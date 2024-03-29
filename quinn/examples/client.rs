//! This example demonstrates an HTTP client that requests files from a server.
//!
//! Checkout the `README.md` for guidance.

use std::{
    fs,
    io::{self, Write},
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Error, Result};
use bytes::Bytes;
use clap::Parser;
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tracing::{error, info};
use url::Url;

mod common;

/// HTTP/0.9 over QUIC client
#[derive(Parser, Debug)]
#[clap(name = "client")]
struct Opt {
    /// Perform NSS-compatible TLS key logging to the file specified in `SSLKEYLOGFILE`.
    #[clap(long = "keylog")]
    keylog: bool,

    urls: Vec<ParsedUrl>,

    /// Override hostname used for certificate verification
    #[clap(long = "host")]
    host: Option<String>,

    /// Custom certificate authority to trust, in DER format
    #[clap(long = "ca")]
    ca: Option<PathBuf>,

    /// Simulate NAT rebinding after connecting
    #[clap(long = "rebind")]
    rebind: bool,

    /// Address to bind on
    #[clap(long = "bind", default_value = "[::]:0")]
    bind: SocketAddr,

    /// Read URLs from standard input
    #[clap(long = "stdin")]
    stdin: bool,
}

fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
    let opt = Opt::parse();
    let code = {
        if let Err(e) = run(opt) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run(options: Opt) -> Result<()> {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca_path) = options.ca.as_ref() {
        roots.add(&rustls::Certificate(fs::read(ca_path)?))?;
    } else {
        let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        match fs::read(dirs.data_local_dir().join("cert.der")) {
            Ok(cert) => {
                roots.add(&rustls::Certificate(cert))?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("local server certificate not found");
            }
            Err(e) => {
                error!("failed to open local server certificate: {}", e);
            }
        }
    }
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    client_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    if options.keylog {
        client_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    let mut endpoint = quinn::Endpoint::client(options.bind)?;
    endpoint.set_default_client_config(client_config);

    for url in &options.urls {
        request(&options, &endpoint, url).await?;
    }

    if options.stdin {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Some(line) = {
            eprint!("> ");
            std::io::stderr().flush()?;
            lines.next_line().await?
        } {
            match line.trim().parse() {
                Ok(url) => request(&options, &endpoint, &url).await?,
                Err(e) => {
                    eprintln!("error parsing url: {}", e);
                    eprintln!();
                }
            }
        }
    }

    // Give the server a fair chance to receive the close packet
    endpoint.wait_idle().await;

    Ok(())
}

async fn request(options: &Opt, endpoint: &quinn::Endpoint, url: &ParsedUrl) -> Result<()> {
    let request = format!("GET {}\r\n", url.url.path());
    let start = Instant::now();
    let rebind = options.rebind;
    let host = options.host.as_deref().unwrap_or(&url.url_host);

    eprintln!("connecting to {host} at {}", url.remote);
    let conn = endpoint
        .connect(url.remote, host)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;
    eprintln!("connected at {:?}", start.elapsed());
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))?;
    if rebind {
        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        let addr = socket.local_addr().unwrap();
        eprintln!("rebinding to {addr}");
        endpoint.rebind(socket).expect("rebind failed");
    }

    send.write_all(request.as_bytes())
        .await
        .map_err(|e| anyhow!("failed to send request: {}", e))?;
    drop(send);

    async fn next_response_chunk(recv: &mut quinn::RecvStream) -> Result<Option<Bytes>> {
        Ok(recv
            .read_chunk(4096, true)
            .await
            .map_err(|e| anyhow!("failed to read response: {}", e))?
            .map(|chunk| chunk.bytes))
    }
    let mut resp = next_response_chunk(&mut recv)
        .await?
        .map(|b| b.to_vec())
        .unwrap_or_default();
    let response_start = Instant::now();
    eprintln!("first response byte at {:?}", response_start - start);
    while let Some(b) = next_response_chunk(&mut recv).await? {
        resp.extend(b);
    }

    let duration = response_start.elapsed();
    eprintln!(
        "response received in {:?} - {} KiB/s",
        duration,
        resp.len() as f32 / (duration_secs(&duration) * 1024.0)
    );
    io::stdout().write_all(&resp).unwrap();
    io::stdout().flush().unwrap();
    conn.close(0u32.into(), b"done");
    eprintln!();

    Ok(())
}

#[derive(Debug, Clone)]
struct ParsedUrl {
    url: Url,
    url_host: String,
    remote: SocketAddr,
}

impl FromStr for ParsedUrl {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let url: Url = s.parse()?;
        let url_host = strip_ipv6_brackets(url.host_str().unwrap()).to_owned();
        let remote = (url_host.as_str(), url.port().unwrap_or(4433))
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;
        Ok(Self {
            url,
            url_host,
            remote,
        })
    }
}

fn strip_ipv6_brackets(host: &str) -> &str {
    // An ipv6 url looks like eg https://[::1]:4433/Cargo.toml, wherein the host [::1] is the
    // ipv6 address ::1 wrapped in brackets, per RFC 2732. This strips those.
    if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}
