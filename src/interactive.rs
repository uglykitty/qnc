//! -i: an interactive console for one connection with several streams.
//!
//! Lines typed on stdin are sent to the current stream; lines starting with
//! `/` are commands to open, list, switch, finish, reset and stop streams.
//! What the peer sends is printed per line, prefixed with the stream ID.
//! On a terminal, Ctrl-C clears the line and Ctrl-D (on an empty line) quits.

use std::{
    collections::BTreeMap,
    io::{IsTerminal, Write},
    sync::{Arc, Mutex, OnceLock, mpsc as std_mpsc},
    time::Duration,
};

use anyhow::Result;
use bytes::Bytes;
use quinn::{Connection, ConnectionError, ReadError, RecvStream, SendStream, VarInt};
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
  /list, /ls            list streams (* = current)
  /use ID               make stream ID current
  /close [ID]           finish our sending side (FIN)
  /reset [ID] [CODE]    abort our sending side (RESET_STREAM)
  /stop [ID] [CODE]     ask the peer to stop sending (STOP_SENDING)
  /kill [ID] [CODE]     abort both directions now (/reset + /stop)
  /forget [ID]          remove an ended stream from /list (no ID: all
                        ended ones); nothing is sent to the peer
  /quit                 close the connection now
Tab completes command names and stream IDs.
ID defaults to the current stream, CODE to 0. Stream IDs: 0, 4, 8, .. are
opened by the client, 1, 5, 9, .. by the server.
Ctrl-C clears the line, Ctrl-D quits after sending FIN on every stream.";

/// Command names (for completion) and their usage.
const COMMANDS: &[(&str, &str)] = &[
    ("open", "/open"),
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
                match editor.readline(&prompt) {
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

/// Start the reader and writer tasks of a new stream; it becomes current if
/// there is none yet.
fn register(s: &Shared, send: SendStream, recv: RecvStream, local: bool) -> u64 {
    let id: u64 = send.id().into();
    let (send_tx, send_rx) = mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = mpsc::unbounded_channel();
    let mut t = s.table.lock().unwrap();
    t.streams.insert(
        id,
        Stream {
            local,
            send: "open".into(),
            recv: "open".into(),
            sent: 0,
            recvd: 0,
            send_tx: Some(send_tx),
            stop_tx: Some(stop_tx),
            writer: None,
        },
    );
    // The tasks wait for the lock we hold, so they see the entry.
    let writer = tokio::spawn(writer(s.clone(), id, send, send_rx, local));
    tokio::spawn(reader(s.clone(), id, recv, stop_rx));
    t.streams.get_mut(&id).unwrap().writer = Some(writer);
    STREAM_IDS.lock().unwrap().push(id);
    if t.current.is_none() {
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
    while let Ok((send, recv)) = s.conn.accept_bi().await {
        let id = register(&s, send, recv, false);
        info(format_args!("peer opened stream {id}"));
    }
}

// ---------------------------------------------------------------- commands

/// Runs the console on `conn` until it is closed (by either side) or stdin
/// ends. Returns true if stdin ended, so a server should stop accepting.
pub async fn run(conn: &Connection) -> Result<bool> {
    let s: Shared = Arc::new(Session { conn: conn.clone(), table: Mutex::default() });
    let mut lines = console().lines.lock().await;
    STREAM_IDS.lock().unwrap().clear();
    set_prompt(None);
    info(format_args!("connected to {}; /help for commands, Ctrl-D to quit", crate::peer_addr(conn)));
    // No stream is opened up front: the connection starts empty, /open adds one.
    let accept = tokio::spawn(accept_streams(s.clone()));

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
        ("open", []) => open(s).await,
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
    match t.streams.get(&id).and_then(|st| st.send_tx.as_ref()) {
        Some(tx) => {
            let _ = tx.send(SendCmd::Data(Bytes::from(format!("{line}\n"))));
        }
        None => info(format_args!("stream {id}: our sending side is closed, /open or /use another")),
    }
}

/// Opens a stream; if the peer's stream limit (MAX_STREAMS) is reached, keeps
/// waiting in the background instead of blocking the console.
async fn open(s: &Shared) {
    let conn = s.conn.clone();
    let mut opening = Box::pin(async move { conn.open_bi().await });
    let opened = tokio::select! {
        r = &mut opening => r,
        _ = tokio::time::sleep(Duration::from_millis(100)) => {
            info("waiting for the peer to allow another stream (MAX_STREAMS)");
            let s = s.clone();
            tokio::spawn(async move {
                if let Ok((send, recv)) = opening.await {
                    let id = register(&s, send, recv, true);
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
            let id = register(s, send, recv, true);
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
    let mut out = format!("{:>5}  {:<4} {:>8} {:>8}  {:<32} {}", "id", "by", "sent", "recvd", "send", "recv");
    for (id, st) in &t.streams {
        let mark = if t.current == Some(*id) { '*' } else { ' ' };
        let by = if st.local { "us" } else { "peer" };
        out.push_str(&format!(
            "\n  {mark}{id:>4}  {by:<4} {:>8} {:>8}  {:<32} {}",
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
