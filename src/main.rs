//! qnc: a netcat-like tool over QUIC.
//!
//!   qnc -l 0.0.0.0:4433 --save-cert cert.pem     # server, self-signed cert
//!   qnc --ca cert.pem localhost 4433             # client, trust that cert
//!   qnc -k localhost 4433                        # client, skip verification
//!
//! Each connection carries one bidirectional stream: stdin is sent to the peer,
//! what the peer sends is written to stdout.
//!
//! For learning/debugging the protocol:
//!   -v .. -vvvv                 increasingly detailed logs (see --help)
//!   --qlog DIR                  one qlog file per connection, view in https://qvis.quictools.info
//!   SSLKEYLOGFILE=keys.txt      TLS secrets, lets Wireshark decrypt captured QUIC packets

use std::{
    io::IsTerminal,
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
    SendStream, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    DigitallySignedStruct, KeyLogFile, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime, pem::PemObject},
};
use tokio::io::AsyncWriteExt;
use tracing_subscriber::{
    filter::LevelFilter,
    fmt::{format::Writer, time::FormatTime},
};

static START: LazyLock<Instant> = LazyLock::new(Instant::now);
static VERBOSE: AtomicU8 = AtomicU8::new(0);

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

    /// Server: echo every stream back, serving many clients concurrently
    #[arg(long, requires = "listen")]
    echo: bool,

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
    if let Err(e) = result {
        log!("Error: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn transport(qlog: Option<QlogStream>) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    t.qlog_stream(qlog);
    Arc::new(t)
}

/// With --qlog, a qlog stream writing to DIR/<time>-<role>-<peer>.sqlog.
fn qlog(args: &Args, role: &str, peer: SocketAddr) -> Result<Option<QlogStream>> {
    let Some(dir) = &args.qlog else {
        return Ok(None);
    };
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
    let peer_name: String = peer.to_string().chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '_' }).collect();
    let path = dir.join(format!("{}.{:03}-{role}-{peer_name}.sqlog", now.as_secs(), now.subsec_millis()));
    // Unbuffered, so the trace is complete even though we exit without dropping everything.
    let file = std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    vlog!(1, "{peer}: writing qlog to {}", path.display());
    let mut config = QlogConfig::default();
    config
        .writer(Box::new(file))
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
    vlog!(1, "listening on udp {}", endpoint.local_addr()?);

    while let Some(incoming) = endpoint.accept().await {
        let peer = incoming.remote_address();
        vlog!(2, "{peer}: incoming connection attempt, address validated: {}", incoming.remote_address_validated());
        // A per-connection config, so each connection gets its own qlog file.
        let connecting = match qlog(args, "server", peer)? {
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
        vlog!(1, "connection from {}", conn.remote_address());
        log_handshake(&conn);

        if args.echo {
            tokio::spawn(echo(conn));
            continue;
        }

        let result = match conn.accept_bi().await {
            Ok((send, recv)) => {
                vlog!(2, "{}: accepted {}", conn.remote_address(), send.id());
                pipe(send, recv).await
            }
            Err(e) => Err(e.into()),
        };
        finish(&conn);
        if let Err(e) = result {
            log!("{}: {e}", conn.remote_address());
        }
        if !args.keep {
            break;
        }
    }
    endpoint.wait_idle().await;
    Ok(())
}

async fn echo(conn: Connection) {
    let peer = conn.remote_address();
    let reason = loop {
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
    };
    vlog!(1, "{peer} closed");
    vlog!(2, "{peer}: close reason: {reason}");
    if verbose(1) {
        print_stats(&conn);
    }
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

    // UDP gives no "connection refused", so try each address with a timeout
    // (e.g. "localhost" resolves to ::1 first while the server is on 127.0.0.1).
    let sni = args.sni.as_deref().unwrap_or(host);
    let mut conn = None;
    for &addr in &addrs {
        vlog!(1, "trying {addr}");
        let mut config = config.clone();
        config.transport_config(transport(qlog(args, "client", addr)?));
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
    let addr = conn.remote_address();
    vlog!(1, "connected to {addr} from {}", endpoint.local_addr()?);
    log_handshake(&conn);

    let (send, recv) = conn.open_bi().await?;
    vlog!(2, "{addr}: opened {}", send.id());
    let result = pipe(send, recv).await;
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
            // The peer closing the whole connection (like nc exiting) counts as EOF.
            let closed = e.get_ref().and_then(|e| e.downcast_ref::<ReadError>()).is_some_and(|e| {
                matches!(e, ReadError::ConnectionLost(ConnectionError::ApplicationClosed(_)))
            });
            if !closed {
                return Err(e.into());
            }
            vlog!(2, "{id}: peer closed the connection");
        }
    }

    if up.is_finished() {
        up.await??;
    } else {
        if stdin_eof.load(Ordering::Relaxed) {
            vlog!(2, "{id}: not waiting for the peer to acknowledge our data");
        } else {
            vlog!(2, "{id}: peer is done, ignoring the rest of stdin");
        }
        up.abort();
    }
    Ok(())
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
        conn.remote_address(),
        conn.stable_id(),
        alpn.as_deref().unwrap_or("-"),
        sni.as_deref().unwrap_or("-"),
    );
}

fn print_stats(conn: &Connection) {
    let s = conn.stats();
    let peer = conn.remote_address();
    log!(
        "{}: rtt {:?}, cwnd {} B, sent {} B / {} dgrams, recv {} B / {} dgrams, lost {} pkts",
        conn.remote_address(),
        s.path.rtt,
        s.path.cwnd,
        s.udp_tx.bytes,
        s.udp_tx.datagrams,
        s.udp_rx.bytes,
        s.udp_rx.datagrams,
        s.path.lost_packets,
    );
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
