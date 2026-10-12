//! -i: an interactive console for one connection with several streams.
//!
//! Lines typed on stdin are sent to the current stream; lines starting with
//! `/` are commands to open, list, switch, finish, reset and stop streams.
//! What the peer sends is printed per line, prefixed with the stream ID.
//! On a terminal, Ctrl-C clears the line and Ctrl-D (on an empty line) quits.

use std::{
    collections::BTreeMap,
    io::{IsTerminal, Write},
    net::SocketAddr,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc,
    },
    time::Duration,
};

use anyhow::Result;
use bytes::Bytes;
use quinn::{Connection, ConnectionError, Endpoint, ReadError, RecvStream, SendStream, VarInt};
use rustyline::{
    CompletionType, Config, Context, Editor, ExternalPrinter, Helper,
    completion::{Completer, Pair},
    error::ReadlineError,
    highlight::Highlighter,
    hint::Hinter,
    history::DefaultHistory,
    validate::Validator,
};
use tokio::{sync::mpsc, task::JoinHandle};

const HELP: &str = "\
commands (any other line is sent to the current stream, \"//x\" sends \"/x\"):
  /open                 open a new bidirectional stream and make it current
  /open-uni             open a new unidirectional (send-only) stream and
                        make it current
  /list, /ls            list streams (* = current)
  /use ID               make stream ID current
  /close [ID]           finish our sending side (FIN)
  /reset [ID] [CODE]    abort our sending side (RESET_STREAM)
  /stop [ID] [CODE]     ask the peer to stop sending (STOP_SENDING)
  /kill [ID] [CODE]     abort both directions now (/reset + /stop)
  /forget [ID]          remove an ended stream from /list (no ID: all
                        ended ones); nothing is sent to the peer
  /migrate [PORT]       client: move the connection to a new local UDP port
                        (random if not given), like switching networks
  /quit                 close the connection now
Tab completes command names and stream IDs.
ID defaults to the current stream, CODE to 0. Stream IDs: 0, 4, 8, .. are
bidirectional streams opened by the client, 1, 5, 9, .. by the server;
2, 6, 10, .. and 3, 7, 11, .. are their unidirectional ones.
Ctrl-C clears the line, Ctrl-D quits after sending FIN on every stream.";

/// Command names (for completion) and their usage.
const COMMANDS: &[(&str, &str)] = &[
    ("open", "/open"),
    ("open-uni", "/open-uni"),
    ("migrate", "/migrate [PORT]"),
    ("list", "/list"),
    ("use", "/use ID"),
    ("close", "/close [ID]"),
    ("reset", "/reset [ID] [CODE]"),
    ("stop", "/stop [ID] [CODE]"),
    ("kill", "/kill [ID] [CODE]"),
    ("forget", "/forget [ID]"),
    ("help", "/help"),
    ("quit", "/quit"),
];

/// Commands whose first argument is a stream ID.
const TAKES_ID: &[&str] = &["use", "close", "reset", "stop", "kill", "forget"];

// ---------------------------------------------------------------- console

/// IDs of the current connection's streams, for completion.
static STREAM_IDS: Mutex<Vec<u64>> = Mutex::new(Vec::new());

/// Tab completion: command names after "/", stream IDs as their first argument.
struct Completion;

impl Completer for Completion {
    type Candidate = Pair;

    fn complete(&self, line: &str, pos: usize, _: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        let before = &line[..pos];
        let Some(cmd) = before.strip_prefix('/').filter(|c| !c.starts_with('/')) else {
            return Ok((pos, Vec::new()));
        };
        let pair = |word: String| Pair { display: word.clone(), replacement: format!("{word} ") };
        let Some((name, args)) = cmd.split_once(' ') else {
            let names = COMMANDS.iter().filter(|c| c.0.starts_with(cmd)).map(|c| pair(c.0.into()));
            return Ok((1, names.collect()));
        };
        let args = args.trim_start();
        if !TAKES_ID.contains(&name) || args.contains(' ') {
            return Ok((pos, Vec::new()));
        }
        let ids = STREAM_IDS.lock().unwrap();
        let ids = ids.iter().map(u64::to_string).filter(|id| id.starts_with(args)).map(pair);
        Ok((pos - args.len(), ids.collect()))
    }
}

impl Hinter for Completion {
    type Hint = String;
}
impl Highlighter for Completion {}
impl Validator for Completion {}
impl Helper for Completion {}

/// The terminal side, shared by all connections (one stdin reader for the
/// whole process, so a server with --keep can serve one client after another).
struct Console {
    /// Prints above the prompt; None when stdin is not a terminal.
    printer: Option<Mutex<Box<dyn ExternalPrinter + Send>>>,
    /// Lines from stdin; closed on EOF (Ctrl-D).
    lines: tokio::sync::Mutex<mpsc::UnboundedReceiver<String>>,
    /// Tells the reader thread a line was handled, so the next prompt shows
    /// its effect (e.g. the stream chosen by /use).
    done: Mutex<std_mpsc::Sender<()>>,
    prompt: Arc<Mutex<String>>,
}

static CONSOLE: OnceLock<Console> = OnceLock::new();
static SAVED_TERMIOS: OnceLock<libc::termios> = OnceLock::new();
/// The prompt is on screen, waiting for input.
static READING: AtomicBool = AtomicBool::new(false);

fn console() -> &'static Console {
    CONSOLE.get_or_init(|| {
        let tty = std::io::stdin().is_terminal();
        if tty {
            // SAFETY: plain libc call on stdin with a zeroed out-parameter.
            unsafe {
                let mut t: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(libc::STDIN_FILENO, &mut t) == 0 {
                    let _ = SAVED_TERMIOS.set(t);
                }
            }
        }
        // Like bash: complete the common prefix, list the candidates on a second Tab.
        let config = Config::builder().completion_type(CompletionType::List).build();
        let mut editor = Editor::<Completion, DefaultHistory>::with_config(config).expect("line editor");
        editor.set_helper(Some(Completion));
        let printer = if tty {
            editor
                .create_external_printer()
                .ok()
                .map(|p| Mutex::new(Box::new(p) as Box<dyn ExternalPrinter + Send>))
        } else {
            None
        };
        let (line_tx, line_rx) = mpsc::unbounded_channel();
        let (done_tx, done_rx) = std_mpsc::channel();
        let prompt = Arc::new(Mutex::new(String::from("qnc> ")));
        let thread_prompt = prompt.clone();
        std::thread::spawn(move || {
            loop {
                let prompt = if tty { thread_prompt.lock().unwrap().clone() } else { String::new() };
                READING.store(tty, Ordering::Relaxed);
                let read = editor.readline(&prompt);
                READING.store(false, Ordering::Relaxed);
                match read {
                    Ok(line) => {
                        if tty && !line.trim().is_empty() {
                            let _ = editor.add_history_entry(line.as_str());
                        }
                        if line_tx.send(line).is_err() || done_rx.recv().is_err() {
                            break;
                        }
                    }
                    // Ctrl-C: rustyline has already discarded the line.
                    Err(ReadlineError::Interrupted) => {}
                    // Ctrl-D, or end of piped input: dropping line_tx closes `lines`.
                    Err(_) => break,
                }
            }
        });
        Console {
            printer,
            lines: tokio::sync::Mutex::new(line_rx),
            done: Mutex::new(done_tx),
            prompt,
        }
    })
}

/// Undo the line editor's raw mode, in case we exit while it is reading.
pub fn restore_terminal() {
    if let Some(t) = SAVED_TERMIOS.get() {
        // SAFETY: restores attributes previously read by tcgetattr.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, t);
        }
    }
    // Exiting under a prompt (e.g. the peer closed the connection): end its
    // line, so the shell prompt does not follow it on the same line.
    if READING.load(Ordering::Relaxed) {
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(b"\n");
        let _ = stdout.flush();
    }
}

/// A status message, above the prompt (or on stderr without a terminal).
fn info(msg: impl std::fmt::Display) {
    match &console().printer {
        Some(p) => {
            let _ = p.lock().unwrap().print(format!("* {msg}\n"));
        }
        None => eprintln!("* {msg}"),
    }
}

/// Data received on stream `id`, one output line per line of input.
fn data(id: u64, bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        out.push_str(&format!("[{id}] {}\n", line.strip_suffix('\n').unwrap_or(line)));
    }
    match &console().printer {
        Some(p) => {
            let _ = p.lock().unwrap().print(out);
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(out.as_bytes());
            let _ = stdout.flush();
        }
    }
}

fn set_prompt(current: Option<u64>) {
    *console().prompt.lock().unwrap() = match current {
        Some(id) => format!("qnc[{id}]> "),
        None => "qnc> ".into(),
    };
}

// ---------------------------------------------------------------- streams

enum SendCmd {
    Data(Bytes),
    Finish,
    Reset(VarInt),
}

struct Stream {
    /// Opened by us (otherwise by the peer).
    local: bool,
    /// Unidirectional: only we send (local) or only the peer does.
    uni: bool,
    send: String,
    recv: String,
    sent: u64,
    recvd: u64,
    /// None once our sending side is finished or over.
    send_tx: Option<mpsc::UnboundedSender<SendCmd>>,
    /// None once the receiving side is over.
    stop_tx: Option<mpsc::UnboundedSender<VarInt>>,
    writer: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct Table {
    streams: BTreeMap<u64, Stream>,
    current: Option<u64>,
}

struct Session {
    conn: Connection,
    /// Client only: its endpoint, for /migrate.
    endpoint: Option<Endpoint>,
    table: Mutex<Table>,
}

type Shared = Arc<Session>;

impl Session {
    fn update(&self, id: u64, f: impl FnOnce(&mut Stream)) {
        if let Some(st) = self.table.lock().unwrap().streams.get_mut(&id) {
            f(st);
        }
    }

    fn set_current(&self, t: &mut Table, id: u64) {
        t.current = Some(id);
        set_prompt(t.current);
    }
}

/// Start the reader and writer tasks of a new stream (a unidirectional one
/// has only one side); it becomes current if there is none yet and we can
/// send on it.
fn register(s: &Shared, send: Option<SendStream>, recv: Option<RecvStream>, local: bool) -> u64 {
    let id: u64 = match (&send, &recv) {
        (Some(send), _) => send.id().into(),
        (None, Some(recv)) => recv.id().into(),
        (None, None) => unreachable!("a stream has at least one side"),
    };
    let can_send = send.is_some();
    let mut t = s.table.lock().unwrap();
    t.streams.insert(
        id,
        Stream {
            local,
            uni: send.is_none() || recv.is_none(),
            send: if send.is_some() { "open" } else { "-" }.into(),
            recv: if recv.is_some() { "open" } else { "-" }.into(),
            sent: 0,
            recvd: 0,
            send_tx: None,
            stop_tx: None,
            writer: None,
        },
    );
    // The tasks wait for the lock we hold, so they see the entry.
    let st = t.streams.get_mut(&id).unwrap();
    if let Some(send) = send {
        let (send_tx, send_rx) = mpsc::unbounded_channel();
        st.send_tx = Some(send_tx);
        st.writer = Some(tokio::spawn(writer(s.clone(), id, send, send_rx, local)));
    }
    if let Some(recv) = recv {
        let (stop_tx, stop_rx) = mpsc::unbounded_channel();
        st.stop_tx = Some(stop_tx);
        tokio::spawn(reader(s.clone(), id, recv, stop_rx));
    }
    STREAM_IDS.lock().unwrap().push(id);
    if t.current.is_none() && can_send {
        s.set_current(&mut t, id);
    }
    id
}

async fn writer(s: Shared, id: u64, mut send: SendStream, mut rx: mpsc::UnboundedReceiver<SendCmd>, announce: bool) {
    // Streams are only announced to the peer once a STREAM frame is sent.
    if announce && let Err(e) = send.write_chunk(Bytes::new()).await {
        s.update(id, |st| st.send = e.to_string());
        return;
    }
    let mut finished = false;
    let state = loop {
        tokio::select! {
            cmd = rx.recv(), if !finished => match cmd {
                Some(SendCmd::Data(data)) => {
                    let n = data.len() as u64;
                    match send.write_chunk(data).await {
                        Ok(()) => s.update(id, |st| st.sent += n),
                        Err(e) => break e.to_string(),
                    }
                }
                Some(SendCmd::Finish) => {
                    let _ = send.finish();
                    finished = true;
                }
                Some(SendCmd::Reset(code)) => {
                    let _ = send.reset(code);
                    break format!("reset by us (code {code})");
                }
                None => return,
            },
            r = send.stopped() => break match r {
                Ok(None) => "FIN sent, all data acknowledged".into(),
                Ok(Some(code)) => {
                    info(format_args!("stream {id}: peer sent STOP_SENDING (code {code}), we reset it"));
                    format!("stopped by peer (code {code})")
                }
                Err(e) => e.to_string(),
            },
        }
    };
    s.update(id, |st| {
        st.send = state;
        st.send_tx = None;
    });
}

async fn reader(s: Shared, id: u64, mut recv: RecvStream, mut stop_rx: mpsc::UnboundedReceiver<VarInt>) {
    let state = loop {
        tokio::select! {
            code = stop_rx.recv() => {
                let Some(code) = code else { return };
                let _ = recv.stop(code);
                break format!("stopped by us (code {code})");
            }
            chunk = recv.read_chunk(64 * 1024, true) => match chunk {
                Ok(Some(chunk)) => {
                    s.update(id, |st| st.recvd += chunk.bytes.len() as u64);
                    data(id, &chunk.bytes);
                }
                Ok(None) => {
                    info(format_args!("stream {id}: peer finished sending (FIN)"));
                    break "FIN received".into();
                }
                Err(ReadError::Reset(code)) => {
                    info(format_args!("stream {id}: peer reset it (RESET_STREAM, code {code})"));
                    break format!("reset by peer (code {code})");
                }
                Err(ReadError::ConnectionLost(_)) => break "connection lost".into(),
                Err(e) => break e.to_string(),
            }
        }
    };
    s.update(id, |st| {
        st.recv = state;
        st.stop_tx = None;
    });
}

async fn accept_streams(s: Shared) {
    loop {
        let (send, recv, kind) = tokio::select! {
            r = s.conn.accept_bi() => match r {
                Ok((send, recv)) => (Some(send), recv, "stream"),
                Err(_) => return,
            },
            r = s.conn.accept_uni() => match r {
                Ok(recv) => (None, recv, "unidirectional stream"),
                Err(_) => return,
            },
        };
        let id = register(&s, send, Some(recv), false);
        info(format_args!("peer opened {kind} {id}"));
    }
}

/// Reports when the peer's address changes: on a server, that is the client
/// migrating (or a NAT rebinding), validated with PATH_CHALLENGE/PATH_RESPONSE.
async fn watch_peer_address(conn: Connection) {
    let mut addr = crate::peer_addr(&conn);
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = crate::peer_addr(&conn);
        if now != addr {
            info(format_args!("peer address changed: {addr} -> {now}"));
            addr = now;
        }
    }
}

// ---------------------------------------------------------------- commands

/// Server: starts the console before the first client arrives.
pub fn waiting(addr: std::net::SocketAddr) {
    set_prompt(None);
    info(format_args!("listening on udp {addr}, waiting for a client; Ctrl-D quits"));
}

/// Server, between connections: handles console input until stdin ends
/// (Ctrl-D) or /quit. Cancel-safe: a line is fully handled once received.
pub async fn idle() {
    let mut lines = console().lines.lock().await;
    while let Some(line) = lines.recv().await {
        let quit = matches!(line.trim(), "/quit" | "/q");
        if !quit && !line.trim().is_empty() {
            info("no connection yet, waiting for a client; Ctrl-D or /quit stops the server");
        }
        let _ = console().done.lock().unwrap().send(());
        if quit {
            return;
        }
    }
}

/// Runs the console on `conn` until it is closed (by either side) or stdin
/// ends. Returns true if stdin ended, so a server should stop accepting.
/// `endpoint`: the client's endpoint (enables /migrate), None on a server.
pub async fn run(conn: &Connection, endpoint: Option<&Endpoint>) -> Result<bool> {
    let s: Shared = Arc::new(Session {
        conn: conn.clone(),
        endpoint: endpoint.cloned(),
        table: Mutex::default(),
    });
    let mut lines = console().lines.lock().await;
    STREAM_IDS.lock().unwrap().clear();
    set_prompt(None);
    info(format_args!("connected to {}; /help for commands, Ctrl-D to quit", crate::peer_addr(conn)));
    // No stream is opened up front: the connection starts empty, /open adds one.
    let accept = tokio::spawn(accept_streams(s.clone()));
    let watch = tokio::spawn(watch_peer_address(conn.clone()));

    let result = loop {
        tokio::select! {
            line = lines.recv() => {
                let Some(line) = line else {
                    finish_all(&s).await;
                    break Ok(true);
                };
                let quit = command(&s, &line).await;
                let _ = console().done.lock().unwrap().send(());
                if quit {
                    break Ok(false);
                }
            }
            reason = conn.closed() => {
                info(format_args!("connection closed: {reason}"));
                break match reason {
                    ConnectionError::ApplicationClosed(_) | ConnectionError::LocallyClosed => Ok(false),
                    e => Err(e.into()),
                };
            }
        }
    };
    accept.abort();
    watch.abort();
    set_prompt(None);
    result
}

/// Ctrl-D: FIN on every stream, then give the peer a moment to acknowledge
/// the data, which closing the connection would discard.
async fn finish_all(s: &Shared) {
    let writers: Vec<_> = {
        let mut t = s.table.lock().unwrap();
        t.streams
            .values_mut()
            .filter_map(|st| {
                if let Some(tx) = st.send_tx.take() {
                    let _ = tx.send(SendCmd::Finish);
                }
                st.writer.take()
            })
            .collect()
    };
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        for w in writers {
            let _ = w.await;
        }
    })
    .await;
}

/// Handles one input line; returns true to close the connection.
async fn command(s: &Shared, line: &str) -> bool {
    let Some(cmd) = line.strip_prefix('/').filter(|c| !c.starts_with('/')) else {
        // "//x" sends "/x"
        send_line(s, line.strip_prefix('/').unwrap_or(line));
        return false;
    };
    let mut words = cmd.split_whitespace();
    let name = match words.next().unwrap_or("") {
        "h" | "?" => "help",
        "ls" => "list",
        "q" => "quit",
        n => n,
    };
    let args: Vec<&str> = words.collect();
    match (name, args.as_slice()) {
        ("help", _) => info(HELP),
        ("open", []) => open(s, false).await,
        ("open-uni", []) => open(s, true).await,
        ("list", []) => list(s),
        ("use", [id]) => match parse_id(s, Some(id)) {
            Ok(id) => {
                let mut t = s.table.lock().unwrap();
                s.set_current(&mut t, id);
            }
            Err(e) => info(e),
        },
        ("close", [] | [_]) => match parse_id(s, args.first()) {
            Ok(id) => close(s, id),
            Err(e) => info(e),
        },
        ("reset" | "stop" | "kill", [] | [_] | [_, _]) => match (parse_id(s, args.first()), parse_code(args.get(1))) {
            (Ok(id), Ok(code)) if name == "reset" => reset(s, id, code),
            (Ok(id), Ok(code)) if name == "stop" => stop(s, id, code),
            (Ok(id), Ok(code)) => kill(s, id, code),
            (Err(e), _) | (_, Err(e)) => info(e),
        },
        ("forget", []) => forget_ended(s),
        ("forget", [id]) => match parse_id(s, Some(id)) {
            Ok(id) => forget(s, id),
            Err(e) => info(e),
        },
        ("migrate", [] | [_]) => migrate(s, args.first()),
        ("quit", []) => return true,
        _ => match COMMANDS.iter().find(|c| c.0 == name) {
            Some((_, usage)) => info(format_args!("usage: {usage}")),
            None => info(format_args!("unknown command: /{name}, see /help")),
        },
    }
    false
}

fn send_line(s: &Shared, line: &str) {
    let t = s.table.lock().unwrap();
    let Some(id) = t.current else {
        info("no stream yet, /open one");
        return;
    };
    let st = &t.streams[&id];
    match &st.send_tx {
        Some(tx) => {
            let _ = tx.send(SendCmd::Data(Bytes::from(format!("{line}\n"))));
        }
        None if st.uni && !st.local => {
            info(format_args!("stream {id} is the peer's unidirectional stream, we cannot send on it"))
        }
        None => info(format_args!("stream {id}: our sending side is closed, /open or /use another")),
    }
}

/// Opens a stream (send-only if `uni`); if the peer's stream limit
/// (MAX_STREAMS) is reached, keeps waiting in the background instead of
/// blocking the console.
async fn open(s: &Shared, uni: bool) {
    let conn = s.conn.clone();
    let mut opening = Box::pin(async move {
        if uni {
            conn.open_uni().await.map(|send| (send, None))
        } else {
            conn.open_bi().await.map(|(send, recv)| (send, Some(recv)))
        }
    });
    let opened = tokio::select! {
        r = &mut opening => r,
        _ = tokio::time::sleep(Duration::from_millis(100)) => {
            info("waiting for the peer to allow another stream (MAX_STREAMS)");
            let s = s.clone();
            tokio::spawn(async move {
                if let Ok((send, recv)) = opening.await {
                    let id = register(&s, Some(send), recv, true);
                    let mut t = s.table.lock().unwrap();
                    s.set_current(&mut t, id);
                    info(format_args!("opened stream {id}"));
                }
            });
            return;
        }
    };
    match opened {
        Ok((send, recv)) => {
            let id = register(s, Some(send), recv, true);
            let mut t = s.table.lock().unwrap();
            s.set_current(&mut t, id);
        }
        Err(e) => info(e),
    }
}

fn list(s: &Shared) {
    let t = s.table.lock().unwrap();
    if t.streams.is_empty() {
        info("no streams");
        return;
    }
    let mut out = format!("{:>5}  {:<4} {:<3} {:>8} {:>8}  {:<32} {}", "id", "by", "dir", "sent", "recvd", "send", "recv");
    for (id, st) in &t.streams {
        let mark = if t.current == Some(*id) { '*' } else { ' ' };
        let by = if st.local { "us" } else { "peer" };
        let dir = if st.uni { "uni" } else { "bi" };
        out.push_str(&format!(
            "\n  {mark}{id:>4}  {by:<4} {dir:<3} {:>8} {:>8}  {:<32} {}",
            st.sent, st.recvd, st.send, st.recv
        ));
    }
    info(out);
}

fn close(s: &Shared, id: u64) {
    let mut t = s.table.lock().unwrap();
    let st = t.streams.get_mut(&id).unwrap();
    match st.send_tx.take() {
        Some(tx) => {
            let _ = tx.send(SendCmd::Finish);
            st.send = "FIN sent".into();
        }
        None => info(format_args!("stream {id}: our sending side is already closed")),
    }
}

fn reset(s: &Shared, id: u64, code: VarInt) {
    let mut t = s.table.lock().unwrap();
    let st = t.streams.get_mut(&id).unwrap();
    match st.send_tx.take() {
        Some(tx) => {
            let _ = tx.send(SendCmd::Reset(code));
        }
        None => info(format_args!("stream {id}: our sending side is already closed")),
    }
}

fn stop(s: &Shared, id: u64, code: VarInt) {
    let mut t = s.table.lock().unwrap();
    let st = t.streams.get_mut(&id).unwrap();
    match st.stop_tx.take() {
        Some(tx) => {
            let _ = tx.send(code);
        }
        None => info(format_args!("stream {id}: receiving is already over")),
    }
}

/// RESET_STREAM and STOP_SENDING at once: abort both directions now.
fn kill(s: &Shared, id: u64, code: VarInt) {
    let mut t = s.table.lock().unwrap();
    let st = t.streams.get_mut(&id).unwrap();
    let send = st.send_tx.take().map(|tx| tx.send(SendCmd::Reset(code)));
    let recv = st.stop_tx.take().map(|tx| tx.send(code));
    if send.is_none() && recv.is_none() {
        info(format_args!("stream {id}: both directions are already over"));
    }
}

/// Both directions are over and their tasks are done.
fn ended(st: &Stream) -> bool {
    st.send_tx.is_none() && st.stop_tx.is_none() && st.writer.as_ref().is_none_or(|w| w.is_finished())
}

/// Drop ended streams from the table; nothing is sent to the peer.
fn remove(t: &mut Table, ids: &[u64]) {
    for id in ids {
        t.streams.remove(id);
    }
    STREAM_IDS.lock().unwrap().retain(|id| !ids.contains(id));
    if t.current.is_some_and(|c| ids.contains(&c)) {
        t.current = None;
        set_prompt(None);
    }
}

fn forget(s: &Shared, id: u64) {
    let mut t = s.table.lock().unwrap();
    if !ended(&t.streams[&id]) {
        info(format_args!("stream {id} is still active, /close or /kill it first"));
        return;
    }
    remove(&mut t, &[id]);
}

fn forget_ended(s: &Shared) {
    let mut t = s.table.lock().unwrap();
    let ids: Vec<u64> = t.streams.iter().filter(|(_, st)| ended(st)).map(|(id, _)| *id).collect();
    remove(&mut t, &ids);
    info(format_args!("forgot {} ended stream(s)", ids.len()));
}

/// Client: switch the endpoint to a new UDP socket. quinn then sends from the
/// new address with a fresh connection ID from the server (if it gave us a
/// spare one), and the server validates the new path before using it.
fn migrate(s: &Shared, port: Option<&&str>) {
    let Some(endpoint) = &s.endpoint else {
        info("only the client can migrate; QUIC servers keep their address");
        return;
    };
    let port: u16 = match port.map(|p| p.parse()) {
        None => 0,
        Some(Ok(p)) => p,
        Some(Err(_)) => return info(format_args!("bad port {:?}", port.unwrap())),
    };
    let result = endpoint.local_addr().map_err(anyhow::Error::from).and_then(|old| {
        let socket = crate::udp_socket(SocketAddr::new(old.ip(), port))?;
        let new = socket.local_addr()?;
        endpoint.rebind(socket)?;
        Ok((old, new))
    });
    match result {
        Ok((old, new)) => info(format_args!("migrated from local {old} to {new}")),
        Err(e) => info(format_args!("migrate failed: {e:#}")),
    }
}

/// A known stream ID, or the current stream if `arg` is None.
fn parse_id(s: &Shared, arg: Option<&&str>) -> Result<u64, String> {
    let t = s.table.lock().unwrap();
    let id = match arg {
        Some(a) => a.parse().map_err(|_| format!("bad stream ID {a:?}"))?,
        None => t.current.ok_or("no current stream")?,
    };
    if !t.streams.contains_key(&id) {
        return Err(format!("no stream {id}, see /list"));
    }
    Ok(id)
}

fn parse_code(arg: Option<&&str>) -> Result<VarInt, String> {
    let Some(a) = arg else { return Ok(VarInt::from_u32(0)) };
    a.parse::<u64>()
        .ok()
        .and_then(|n| VarInt::from_u64(n).ok())
        .ok_or_else(|| format!("bad error code {a:?}"))
}
