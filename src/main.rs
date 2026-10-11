//! qnc: a netcat-like tool over QUIC.
//!
//!   qnc -l 0.0.0.0:4433 --save-cert cert.pem     # server, self-signed cert
//!   qnc --ca cert.pem localhost 4433             # client, trust that cert
//!   qnc -k localhost 4433                        # client, skip verification
//!
//! Each connection carries one bidirectional stream: stdin is sent to the peer,
//! what the peer sends is written to stdout.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use quinn::{
    Connection, ConnectionError, Endpoint, ReadError, RecvStream, SendStream, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime, pem::PemObject},
};
use tokio::io::AsyncWriteExt;

static START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// `eprintln!` prefixed with the time since start, as seconds.milliseconds.
macro_rules! log {
    ($($arg:tt)*) => {{
        let t = START.elapsed();
        eprintln!("{}.{:03} {}", t.as_secs(), t.subsec_millis(), format_args!($($arg)*));
    }};
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

    /// Print connection events and statistics to stderr
    #[arg(short, long)]
    verbose: bool,

    /// Client: remote host
    host: Option<String>,

    /// Client: remote port
    port: Option<u16>,
}

fn main() -> Result<()> {
    LazyLock::force(&START);
    let args = Args::parse();
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

fn transport() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    Arc::new(t)
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

    let mut config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    config.transport_config(transport());
    let endpoint = Endpoint::server(config, addr)?;
    if args.verbose {
        log!("listening on udp {}", endpoint.local_addr()?);
    }

    while let Some(incoming) = endpoint.accept().await {
        let conn = match incoming.await {
            Ok(c) => c,
            Err(e) => {
                log!("handshake failed: {e}");
                continue;
            }
        };
        if args.verbose {
            log!("connection from {}", conn.remote_address());
        }

        if args.echo {
            tokio::spawn(echo(conn, args.verbose));
            continue;
        }

        let result = match conn.accept_bi().await {
            Ok((send, recv)) => pipe(send, recv).await,
            Err(e) => Err(e.into()),
        };
        finish(&conn, args.verbose);
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

async fn echo(conn: Connection, verbose: bool) {
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        tokio::spawn(async move {
            tokio::io::copy(&mut recv, &mut send).await?;
            send.finish()?;
            let _ = send.stopped().await;
            anyhow::Ok(())
        });
    }
    if verbose {
        log!("{} closed", conn.remote_address());
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

    let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    config.transport_config(transport());

    // Dual-stack socket, so one endpoint can try both IPv6 and IPv4 addresses.
    let any6: SocketAddr = "[::]:0".parse()?;
    let any4: SocketAddr = "0.0.0.0:0".parse()?;
    let mut endpoint = Endpoint::client(any6).or_else(|_| Endpoint::client(any4))?;
    endpoint.set_default_client_config(config);

    // UDP gives no "connection refused", so try each address with a timeout
    // (e.g. "localhost" resolves to ::1 first while the server is on 127.0.0.1).
    let sni = args.sni.as_deref().unwrap_or(host);
    let mut conn = None;
    for &addr in &addrs {
        if args.verbose {
            log!("trying {addr}");
        }
        match tokio::time::timeout(Duration::from_secs(3), endpoint.connect(addr, sni)?).await {
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
    if args.verbose {
        log!("connected to {addr} from {}", endpoint.local_addr()?);
    }

    let (send, recv) = conn.open_bi().await?;
    let result = pipe(send, recv).await;
    finish(&conn, args.verbose);
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

    let up = tokio::spawn(async move {
        tokio::io::copy(&mut tokio::io::stdin(), &mut send).await?;
        send.finish()?;
        let _ = send.stopped().await;
        anyhow::Ok(())
    });

    let mut stdout = tokio::io::stdout();
    let copied = tokio::io::copy(&mut recv, &mut stdout).await;
    stdout.flush().await?;
    if let Err(e) = copied {
        // The peer closing the whole connection (like nc exiting) counts as EOF.
        let closed = e.get_ref().and_then(|e| e.downcast_ref::<ReadError>()).is_some_and(|e| {
            matches!(e, ReadError::ConnectionLost(ConnectionError::ApplicationClosed(_)))
        });
        if !closed {
            return Err(e.into());
        }
    }

    if up.is_finished() {
        up.await??;
    } else {
        up.abort();
    }
    Ok(())
}

fn finish(conn: &Connection, verbose: bool) {
    conn.close(0u32.into(), b"bye");
    if verbose {
        print_stats(conn);
    }
}

fn print_stats(conn: &Connection) {
    let s = conn.stats();
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
