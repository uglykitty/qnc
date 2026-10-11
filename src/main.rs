//! qnc: a netcat-like tool over QUIC.
//!
//!   qnc -l 0.0.0.0:4433 --save-cert cert.pem     # server, self-signed cert
//!   qnc --ca cert.pem localhost 4433             # client, trust that cert
//!   qnc -k localhost 4433                        # client, skip verification
//!
//! Each connection carries one bidirectional stream: stdin is sent to the peer,
//! what the peer sends is written to stdout. With -u, unreliable QUIC DATAGRAM
//! frames (RFC 9221) are used instead, like `nc -u`.
//!
//! For learning/debugging the protocol:
//!   -v .. -vvvv                 increasingly detailed logs (see --help)
//!   --qlog DIR                  one qlog file per connection, view in https://qvis.quictools.info
//!   SSLKEYLOGFILE=keys.txt      TLS secrets, lets Wireshark decrypt captured QUIC packets

use std::{
    io::{IsTerminal, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{ArgAction, Parser};
use quinn::{
    Connection, ConnectionError, ConnectionStats, Endpoint, QlogConfig, QlogStream, ReadError, RecvStream,
    SendDatagramError, SendStream, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    DigitallySignedStruct, KeyLogFile, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime, pem::PemObject},
};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::{
    filter::LevelFilter,
    fmt::{format::Writer, time::FormatTime},
};

static START: LazyLock<Instant> = LazyLock::new(Instant::now);
static VERBOSE: AtomicU8 = AtomicU8::new(0);
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Application error code sent in CONNECTION_CLOSE when we are interrupted.
const CLOSE_INTERRUPTED: u32 = 1;

fn verbose(level: u8) -> bool {
    VERBOSE.load(Ordering::Relaxed) >= level
}

/// `eprintln!` prefixed with the time since start, as seconds.milliseconds.
macro_rules! log {
    ($($arg:tt)*) => {{
        let t = START.elapsed();
        eprintln!("{}.{:03} {}", t.as_secs(), t.subsec_millis(), format_args!($($arg)*));
    }};
}

/// `log!` that only prints at verbosity `level` (number of -v) or higher.
macro_rules! vlog {
    ($level:expr, $($arg:tt)*) => {
        if verbose($level) {
            log!($($arg)*);
        }
    };
}

/// Timestamps for quinn/rustls logs (-vvv), same format as `log!`.
struct Uptime;

impl FormatTime for Uptime {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        let t = START.elapsed();
        write!(w, "{}.{:03}", t.as_secs(), t.subsec_millis())
    }
}

#[derive(Parser)]
#[command(version, about = "netcat-like QUIC client/server")]
struct Args {
    /// Listen mode: bind to this address (e.g. 0.0.0.0:4433 or [::]:4433)
    #[arg(short, long, value_name = "ADDR")]
    listen: Option<SocketAddr>,

    /// Server: keep accepting connections instead of exiting after the first
    #[arg(long, requires = "listen")]
    keep: bool,

    /// Server: echo every stream (or datagram, with -u) back, serving many clients concurrently
    #[arg(long, requires = "listen")]
    echo: bool,

    /// Use unreliable QUIC DATAGRAM frames instead of a stream (like nc -u);
    /// both sides need it
    #[arg(short = 'u', long)]
    datagram: bool,

    /// With -u: after stdin EOF, keep receiving for SECS, then close
    #[arg(short = 'q', value_name = "SECS", default_value_t = 1.0, requires = "datagram")]
    quit_after: f64,

    /// Server: certificate chain (PEM); self-signed if omitted
    #[arg(long, requires_all = ["listen", "key"])]
    cert: Option<PathBuf>,

    /// Server: private key (PEM)
    #[arg(long, requires_all = ["listen", "cert"])]
    key: Option<PathBuf>,

    /// Server: write the generated self-signed certificate here (for client --ca)
    #[arg(long, requires = "listen", conflicts_with = "cert")]
    save_cert: Option<PathBuf>,

    /// Client: trust this CA / certificate (PEM)
    #[arg(long)]
    ca: Option<PathBuf>,

    /// Client: do not verify the server certificate
    #[arg(short = 'k', long)]
    insecure: bool,

    /// Client: TLS server name (defaults to HOST)
    #[arg(long)]
    sni: Option<String>,

    /// ALPN protocol, must match on both sides
    #[arg(long, default_value = "qnc")]
    alpn: String,

    /// Log to stderr; repeat for more: -v events and stats, -vv streams, bytes
    /// and handshake details, -vvv quinn/rustls debug logs, -vvvv packet trace
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    /// Write a qlog trace of every connection into this directory
    #[arg(long, value_name = "DIR")]
    qlog: Option<PathBuf>,

    /// Client: remote host
    host: Option<String>,

    /// Client: remote port
    port: Option<u16>,
}

fn main() -> Result<()> {
    LazyLock::force(&START);
    let args = Args::parse();
    VERBOSE.store(args.verbose, Ordering::Relaxed);
    if args.verbose >= 3 {
        tracing_subscriber::fmt()
            .with_max_level(if args.verbose >= 4 { LevelFilter::TRACE } else { LevelFilter::DEBUG })
            .with_timer(Uptime)
            .with_writer(std::io::stderr)
            .with_ansi(std::io::stderr().is_terminal())
            .init();
    }
    if let Some(path) = std::env::var_os("SSLKEYLOGFILE") {
        vlog!(1, "writing TLS secrets to {} (SSLKEYLOGFILE)", Path::new(&path).display());
    }
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async {
        if let Some(addr) = args.listen {
            server(&args, addr).await
        } else {
            client(&args).await
        }
    });
    // A pending blocking read on stdin would keep the runtime from shutting down.
    rt.shutdown_background();
    if INTERRUPTED.load(Ordering::Relaxed) {
        // Errors from connections we closed ourselves are expected; 130 = 128 + SIGINT.
        std::process::exit(130);
    }
    if let Err(e) = result {
        log!("Error: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// On the first SIGINT/SIGTERM, close every connection of `endpoint` with a
/// CONNECTION_CLOSE frame so peers learn right away instead of waiting for
/// their idle timeout. The normal code path then finishes; a second signal, or
/// a close that takes too long, exits immediately.
fn close_on_signal(endpoint: Endpoint) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut int = signal(SignalKind::interrupt())?;
    let mut term = signal(SignalKind::terminate())?;
    tokio::spawn(async move {
        let name = tokio::select! {
            _ = int.recv() => "SIGINT",
            _ = term.recv() => "SIGTERM",
        };
        INTERRUPTED.store(true, Ordering::Relaxed);
        vlog!(1, "{name}: closing {} connection(s), press Ctrl-C again to quit now", endpoint.open_connections());
        endpoint.close(CLOSE_INTERRUPTED.into(), b"interrupted");
        tokio::select! {
            _ = int.recv() => vlog!(1, "SIGINT again, exiting"),
            _ = term.recv() => vlog!(1, "SIGTERM again, exiting"),
            // Closing waits 3 PTOs at most; this only guards against a hang.
            _ = tokio::time::sleep(Duration::from_secs(3)) => log!("close timed out, exiting"),
        }
        std::process::exit(130);
    });
    Ok(())
}

fn transport(qlog: Option<QlogStream>) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    t.qlog_stream(qlog);
    Arc::new(t)
}

/// `[::ffff:1.2.3.4]:5` -> `1.2.3.4:5`. A dual-stack socket reports IPv4 peers
/// as IPv4-mapped IPv6 addresses.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

fn peer_addr(conn: &Connection) -> SocketAddr {
    canonical(conn.remote_address())
}

/// With --qlog, a qlog stream writing to DIR/<time>-<role>-<peer>.sqlog.
/// `odcid`: the client's original destination connection ID, known up front
/// only on the server; the client's writer learns it from its first event.
fn qlog(args: &Args, role: &'static str, peer: SocketAddr, odcid: Option<&[u8]>) -> Result<Option<QlogStream>> {
    let Some(dir) = &args.qlog else {
        return Ok(None);
    };
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
    let peer_name: String = peer.to_string().chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '_' }).collect();
    let path = dir.join(format!("{}.{:03}-{role}-{peer_name}.sqlog", now.as_secs(), now.subsec_millis()));
    // Unbuffered (one write per record), so the trace is complete even though
    // we exit without dropping everything.
    let file = std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    let writer = QlogFixup {
        file,
        role,
        group_id: odcid.map(hex),
        pending_header: None,
        buf: Vec::new(),
    };
    vlog!(1, "{peer}: writing qlog to {}", path.display());
    let mut config = QlogConfig::default();
    config
        .writer(Box::new(writer))
        .title(Some(format!("qnc {role}, peer {peer}")))
        .start_time(*START);
    Ok(config.into_stream())
}

// ---------------------------------------------------------------- server

async fn server(args: &Args, addr: SocketAddr) -> Result<()> {
    let (certs, key) = match (&args.cert, &args.key) {
        (Some(cert), Some(key)) => (
            CertificateDer::pem_file_iter(cert)
                .with_context(|| format!("reading {}", cert.display()))?
                .collect::<Result<Vec<_>, _>>()?,
            PrivateKeyDer::from_pem_file(key).with_context(|| format!("reading {}", key.display()))?,
        ),
        _ => {
            let c = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            if let Some(path) = &args.save_cert {
                std::fs::write(path, c.cert.pem()).with_context(|| format!("writing {}", path.display()))?;
            }
            let key = PrivatePkcs8KeyDer::from(c.key_pair.serialize_der());
            (vec![c.cert.der().clone()], key.into())
        }
    };

    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![args.alpn.as_bytes().to_vec()];
    tls.key_log = Arc::new(KeyLogFile::new());

    let mut config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    config.transport_config(transport(None));
    let endpoint = Endpoint::server(config.clone(), addr)?;
    close_on_signal(endpoint.clone())?;
    vlog!(1, "listening on udp {}", endpoint.local_addr()?);

    while let Some(incoming) = endpoint.accept().await {
        let peer = canonical(incoming.remote_address());
        vlog!(2, "{peer}: incoming connection attempt, address validated: {}", incoming.remote_address_validated());
        // A per-connection config, so each connection gets its own qlog file.
        let connecting = match qlog(args, "server", peer, Some(&incoming.orig_dst_cid()))? {
            Some(stream) => {
                let mut config = config.clone();
                config.transport_config(transport(Some(stream)));
                incoming.accept_with(Arc::new(config))
            }
            None => incoming.accept(),
        };
        let conn = match async { connecting?.await }.await {
            Ok(c) => c,
            Err(e) => {
                log!("{peer}: handshake failed: {e}");
                continue;
            }
        };
        vlog!(1, "connection from {}", peer_addr(&conn));
        log_handshake(&conn);

        if args.echo {
            tokio::spawn(echo(conn, args.datagram));
            continue;
        }

        let result = if args.datagram {
            datagram_pipe(&conn, linger(args)?).await
        } else {
            match conn.accept_bi().await {
                Ok((send, recv)) => {
                    vlog!(2, "{}: accepted {}", peer_addr(&conn), send.id());
                    pipe(send, recv).await
                }
                Err(e) => Err(e.into()),
            }
        };
        finish(&conn);
        match result {
            Err(e) if !INTERRUPTED.load(Ordering::Relaxed) => log!("{}: {e:#}", peer_addr(&conn)),
            _ => {}
        }
        if !args.keep {
            break;
        }
    }
    endpoint.wait_idle().await;
    Ok(())
}

async fn echo(conn: Connection, datagram: bool) {
    let peer = peer_addr(&conn);
    let reason = if datagram { echo_datagrams(&conn).await } else { echo_streams(&conn).await };
    vlog!(1, "{peer} closed");
    vlog!(2, "{peer}: close reason: {reason}");
    if verbose(1) {
        print_stats(&conn);
    }
}

async fn echo_streams(conn: &Connection) -> ConnectionError {
    let peer = peer_addr(conn);
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(e) => break e,
        };
        vlog!(2, "{peer}: accepted {}", send.id());
        tokio::spawn(async move {
            let n = tokio::io::copy(&mut recv, &mut send).await?;
            send.finish()?;
            let _ = send.stopped().await;
            vlog!(2, "{peer}: {} echoed {n} bytes", send.id());
            anyhow::Ok(())
        });
    }
}

async fn echo_datagrams(conn: &Connection) -> ConnectionError {
    let peer = peer_addr(conn);
    let (mut count, mut bytes) = (0u64, 0u64);
    let reason = loop {
        let data = match conn.read_datagram().await {
            Ok(d) => d,
            Err(e) => break e,
        };
        let len = data.len();
        match conn.send_datagram_wait(data).await {
            Ok(()) => {
                count += 1;
                bytes += len as u64;
                vlog!(2, "{peer}: echoed datagram of {len} bytes");
            }
            Err(SendDatagramError::ConnectionLost(e)) => break e,
            // e.g. the peer accepts smaller datagrams than it sends us
            Err(e) => log!("{peer}: dropping datagram of {len} bytes: {e}"),
        }
    };
    vlog!(2, "{peer}: echoed {count} datagrams, {bytes} bytes");
    reason
}

// ---------------------------------------------------------------- client

async fn client(args: &Args) -> Result<()> {
    let (Some(host), Some(port)) = (&args.host, args.port) else {
        bail!("usage: qnc [options] HOST PORT, or qnc -l ADDR (see --help)");
    };
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port)).await?.collect();
    if addrs.is_empty() {
        bail!("{host}: no address");
    }

    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut tls = if args.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider())))
            .with_no_client_auth()
    } else {
        let Some(ca) = &args.ca else {
            bail!("need --ca FILE to verify the server, or -k to skip verification");
        };
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter(ca).with_context(|| format!("reading {}", ca.display()))? {
            roots.add(cert?)?;
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    tls.alpn_protocols = vec![args.alpn.as_bytes().to_vec()];
    tls.key_log = Arc::new(KeyLogFile::new());

    let config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));

    // Dual-stack socket, so one endpoint can try both IPv6 and IPv4 addresses.
    let any6: SocketAddr = "[::]:0".parse()?;
    let any4: SocketAddr = "0.0.0.0:0".parse()?;
    let endpoint = Endpoint::client(any6).or_else(|_| Endpoint::client(any4))?;
    close_on_signal(endpoint.clone())?;

    // UDP gives no "connection refused", so try each address with a timeout
    // (e.g. "localhost" resolves to ::1 first while the server is on 127.0.0.1).
    let sni = args.sni.as_deref().unwrap_or(host);
    let mut conn = None;
    for &addr in &addrs {
        vlog!(1, "trying {addr}");
        let mut config = config.clone();
        config.transport_config(transport(qlog(args, "client", addr, None)?));
        match tokio::time::timeout(Duration::from_secs(3), endpoint.connect_with(config, addr, sni)?).await {
            Ok(Ok(c)) => {
                conn = Some(c);
                break;
            }
            Ok(Err(e)) if addrs.len() == 1 => return Err(anyhow!(e).context(format!("connecting to {addr}"))),
            Ok(Err(e)) => log!("{addr}: {e}"),
            Err(_) => log!("{addr}: handshake timed out"),
        }
    }
    let conn = conn.ok_or_else(|| anyhow!("could not connect to {host}:{port}"))?;
    let addr = peer_addr(&conn);
    vlog!(1, "connected to {addr} from {}", endpoint.local_addr()?);
    log_handshake(&conn);

    let result = if args.datagram {
        datagram_pipe(&conn, linger(args)?).await
    } else {
        let (send, recv) = conn.open_bi().await?;
        vlog!(2, "{addr}: opened {}", send.id());
        pipe(send, recv).await
    };
    finish(&conn);
    endpoint.wait_idle().await;
    result
}

// ---------------------------------------------------------------- shared

/// stdin -> send, recv -> stdout. Returns once the peer has finished its side;
/// if our stdin hits EOF first, we half-close and keep reading.
async fn pipe(mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    // Streams are only announced to the peer once a STREAM frame is sent, so
    // send an empty one right away; otherwise a server that talks first would
    // never see the stream.
    send.write_chunk(Default::default()).await?;

    let id = send.id();
    let stdin_eof = Arc::new(AtomicBool::new(false));
    let eof = stdin_eof.clone();
    let up = tokio::spawn(async move {
        let n = tokio::io::copy(&mut tokio::io::stdin(), &mut send).await?;
        eof.store(true, Ordering::Relaxed);
        send.finish()?;
        vlog!(2, "{id}: stdin EOF after {n} bytes, sent FIN");
        let _ = send.stopped().await;
        vlog!(2, "{id}: peer acknowledged all our data");
        anyhow::Ok(())
    });

    let mut stdout = tokio::io::stdout();
    let copied = tokio::io::copy(&mut recv, &mut stdout).await;
    stdout.flush().await?;
    match copied {
        Ok(n) => vlog!(2, "{id}: received FIN after {n} bytes"),
        Err(e) => {
            // The peer closing the whole connection (like nc exiting) counts as
            // EOF, and so does our own close on Ctrl-C.
            match e.get_ref().and_then(|e| e.downcast_ref::<ReadError>()) {
                Some(ReadError::ConnectionLost(ConnectionError::ApplicationClosed(c))) => {
                    vlog!(2, "{id}: peer closed the connection: {c}");
                }
                Some(ReadError::ConnectionLost(ConnectionError::LocallyClosed)) => {
                    vlog!(2, "{id}: connection closed locally");
                }
                _ => return Err(e.into()),
            }
        }
    }

    if up.is_finished() {
        up.await??;
    } else {
        if stdin_eof.load(Ordering::Relaxed) {
            vlog!(2, "{id}: not waiting for the peer to acknowledge our data");
        } else {
            vlog!(2, "{id}: receiving is over, ignoring the rest of stdin");
        }
        up.abort();
    }
    Ok(())
}

fn linger(args: &Args) -> Result<Duration> {
    Duration::try_from_secs_f64(args.quit_after).map_err(|e| anyhow!("-q {}: {e}", args.quit_after))
}

/// Datagram mode: every stdin read becomes one DATAGRAM frame (split if it is
/// larger than the peer accepts), every datagram received is written to stdout.
/// Like UDP, datagrams may be lost or reordered and there is no EOF, so after
/// our stdin ends we keep receiving for `linger`, then close the connection.
async fn datagram_pipe(conn: &Connection, linger: Duration) -> Result<()> {
    let peer = peer_addr(conn);
    let Some(max) = conn.max_datagram_size() else {
        bail!("{peer}: peer does not accept QUIC datagrams");
    };
    vlog!(2, "{peer}: datagram mode, max datagram size now {max} bytes");
    // Nothing is queued yet, so this is what "queue empty" looks like.
    let empty_queue_space = conn.datagram_send_buffer_space();

    let up = async {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 64 * 1024];
        let (mut count, mut bytes) = (0u64, 0u64);
        loop {
            let n = stdin.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            // The limit follows the path MTU, which can grow during the connection.
            let max = conn.max_datagram_size().unwrap_or(max);
            for chunk in buf[..n].chunks(max) {
                conn.send_datagram_wait(Bytes::copy_from_slice(chunk)).await?;
                count += 1;
                bytes += chunk.len() as u64;
                vlog!(2, "{peer}: sent datagram of {} bytes", chunk.len());
            }
        }
        // Let the queue drain onto the wire before we start the linger timer.
        while conn.datagram_send_buffer_space() < empty_queue_space {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        vlog!(2, "{peer}: stdin EOF after {count} datagrams, {bytes} bytes");
        anyhow::Ok(())
    };

    let down = async {
        let mut stdout = tokio::io::stdout();
        let (mut count, mut bytes) = (0u64, 0u64);
        let result = loop {
            match conn.read_datagram().await {
                Ok(data) => {
                    count += 1;
                    bytes += data.len() as u64;
                    vlog!(2, "{peer}: received datagram of {} bytes", data.len());
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                }
                Err(ConnectionError::ApplicationClosed(c)) => {
                    vlog!(2, "{peer}: peer closed the connection: {c}");
                    break Ok(());
                }
                Err(ConnectionError::LocallyClosed) => break Ok(()),
                Err(e) => break Err(e.into()),
            }
        };
        vlog!(2, "{peer}: received {count} datagrams, {bytes} bytes");
        result
    };

    tokio::pin!(down);
    tokio::select! {
        r = &mut down => r,
        r = up => {
            r?;
            vlog!(2, "{peer}: receiving for {linger:?} more (-q)");
            tokio::time::timeout(linger, down).await.unwrap_or(Ok(()))
        }
    }
}

fn finish(conn: &Connection) {
    conn.close(0u32.into(), b"bye");
    if verbose(1) {
        print_stats(conn);
    }
}

/// -vv: what the TLS handshake negotiated.
fn log_handshake(conn: &Connection) {
    if !verbose(2) {
        return;
    }
    let (alpn, sni) = conn
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .map(|d| {
            let alpn = d.protocol.map(|p| String::from_utf8_lossy(&p).into_owned());
            (alpn, d.server_name)
        })
        .unwrap_or_default();
    log!(
        "{}: connection id {}, alpn {}, sni {}",
        peer_addr(conn),
        conn.stable_id(),
        alpn.as_deref().unwrap_or("-"),
        sni.as_deref().unwrap_or("-"),
    );
}

fn print_stats(conn: &Connection) {
    let s = conn.stats();
    let peer = peer_addr(conn);
    log!(
        "{}: rtt {:?}, cwnd {} B, sent {} B / {} dgrams, recv {} B / {} dgrams, lost {} pkts",
        peer_addr(conn),
        s.path.rtt,
        s.path.cwnd,
        s.udp_tx.bytes,
        s.udp_tx.datagrams,
        s.udp_rx.bytes,
        s.udp_rx.datagrams,
        s.path.lost_packets,
    );
    if s.frame_tx.datagram + s.frame_rx.datagram > 0 {
        log!("{peer}: DATAGRAM frames sent {}, received {}", s.frame_tx.datagram, s.frame_rx.datagram);
    }
    if verbose(2) {
        log!("{peer}: path {:?}", s.path);
        log!("{peer}: frames sent: {}", frame_counts(&s, true));
        log!("{peer}: frames recv: {}", frame_counts(&s, false));
    }
}

/// Non-zero per-type frame counts, e.g. "STREAM 12, ACK 9, CRYPTO 3".
fn frame_counts(s: &ConnectionStats, sent: bool) -> String {
    let f = if sent { &s.frame_tx } else { &s.frame_rx };
    let counts = [
        ("PING", f.ping),
        ("ACK", f.acks),
        ("ACK_FREQUENCY", f.ack_frequency),
        ("IMMEDIATE_ACK", f.immediate_ack),
        ("CRYPTO", f.crypto),
        ("HANDSHAKE_DONE", f.handshake_done.into()),
        ("NEW_TOKEN", f.new_token),
        ("STREAM", f.stream),
        ("RESET_STREAM", f.reset_stream),
        ("STOP_SENDING", f.stop_sending),
        ("DATAGRAM", f.datagram),
        ("MAX_DATA", f.max_data),
        ("MAX_STREAM_DATA", f.max_stream_data),
        ("MAX_STREAMS_BIDI", f.max_streams_bidi),
        ("MAX_STREAMS_UNI", f.max_streams_uni),
        ("DATA_BLOCKED", f.data_blocked),
        ("STREAM_DATA_BLOCKED", f.stream_data_blocked),
        ("STREAMS_BLOCKED_BIDI", f.streams_blocked_bidi),
        ("STREAMS_BLOCKED_UNI", f.streams_blocked_uni),
        ("NEW_CONNECTION_ID", f.new_connection_id),
        ("RETIRE_CONNECTION_ID", f.retire_connection_id),
        ("PATH_CHALLENGE", f.path_challenge),
        ("PATH_RESPONSE", f.path_response),
        ("CONNECTION_CLOSE", f.connection_close),
    ];
    let parts: Vec<String> = counts.iter().filter(|(_, n)| *n > 0).map(|(name, n)| format!("{name} {n}")).collect();
    if parts.is_empty() { "-".into() } else { parts.join(", ") }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Fixes what quinn gets wrong in its qlog output, on the way to the file:
/// - the trace header says vantage point "unknown" (quinn has no setting for
///   it), so qvis has to guess whether it is a client or server trace;
/// - events are grouped by the peer's *current* connection ID, which differs
///   between the two ends and changes during the handshake. qlog wants the
///   ODCID (the client's first destination CID) on both ends, so the client
///   and server traces of one connection can be matched; it is also put in
///   the header as `common_fields.group_id`;
/// - RTTs of `recovery:metrics_updated` events are in seconds, but qlog (and
///   qvis) use milliseconds.
///
/// Records are JSON-SEQ: RS (0x1e), JSON, LF.
struct QlogFixup {
    file: std::fs::File,
    /// "client" or "server"
    role: &'static str,
    /// ODCID as hex. The client only learns it from its first event (its first
    /// Initial, sent to the ODCID), so it holds the header back until then.
    group_id: Option<String>,
    pending_header: Option<serde_json::Value>,
    buf: Vec<u8>,
}

impl Write for QlogFixup {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        while let Some(end) = self.buf.iter().position(|&b| b == b'\n') {
            let record: Vec<u8> = self.buf.drain(..=end).collect();
            self.record(&record)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl QlogFixup {
    fn record(&mut self, record: &[u8]) -> std::io::Result<()> {
        let json = record.strip_prefix(b"\x1e").unwrap_or(record);
        let Ok(mut event) = serde_json::from_slice::<serde_json::Value>(json) else {
            return self.file.write_all(record);
        };

        if let Some(vp) = event.pointer_mut("/trace/vantage_point") {
            *vp = serde_json::json!({ "name": "qnc", "type": self.role });
            if self.group_id.is_some() {
                return self.write_header(event);
            }
            self.pending_header = Some(event);
            return Ok(());
        }

        if let Some(id) = event.get_mut("group_id") {
            match &self.group_id {
                Some(odcid) => *id = odcid.clone().into(),
                None => self.group_id = id.as_str().map(String::from),
            }
        }
        if let Some(header) = self.pending_header.take() {
            self.write_header(header)?;
        }

        if event["name"] == "recovery:metrics_updated"
            && let Some(data) = event.get_mut("data").and_then(|d| d.as_object_mut())
        {
            for key in ["min_rtt", "smoothed_rtt", "latest_rtt", "rtt_variance"] {
                if let Some(v) = data.get_mut(key)
                    && let Some(secs) = v.as_f64()
                {
                    // f32 seconds -> ms, rounded to µs to drop float noise.
                    *v = ((secs * 1e6).round() / 1e3).into();
                }
            }
        }
        self.write_json(&event)
    }

    fn write_header(&mut self, mut header: serde_json::Value) -> std::io::Result<()> {
        if let (Some(trace), Some(odcid)) = (header.get_mut("trace").and_then(|t| t.as_object_mut()), &self.group_id) {
            trace.insert("common_fields".into(), serde_json::json!({ "group_id": odcid, "ODCID": odcid }));
        }
        self.write_json(&header)
    }

    fn write_json(&mut self, value: &serde_json::Value) -> std::io::Result<()> {
        let mut out = b"\x1e".to_vec();
        serde_json::to_writer(&mut out, value)?;
        out.push(b'\n');
        self.file.write_all(&out)
    }
}

/// Accepts any server certificate (still checks the handshake signatures).
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
