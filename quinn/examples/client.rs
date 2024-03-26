//! This example demonstrates an HTTP client that requests files from a server.
//!
//! Checkout the `README.md` for guidance.

use std::{
    fs,
    io::{self, Write},
    net::{ToSocketAddrs, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
    str::FromStr,
};

use anyhow::{anyhow, Result, Error};
use clap::Parser;
use tracing::{error, info};
use url::Url;
use tokio::io::{BufReader, AsyncBufReadExt as _};

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

    /// Attempt to transmit request as 0-RTT data
    #[clap(long = "0rtt")]
    zero_rtt: bool,

    /// Read URLs from standard input
    #[clap(long = "stdin")]
    stdin: bool,

    /// Suppress printing the response.
    #[clap(long = "no-print-response")]
    no_print_response: bool,
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
    if let Some(ref ca_path) = options.ca {
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
    client_crypto.enable_early_data = true;
    client_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    if options.keylog {
        client_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    for url in &options.urls {
        request(&options, &endpoint, url).await?;
    }

    if options.stdin {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Some(line) = {
            print!("> ");
            std::io::stdout().flush()?;
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
    let start = Instant::now();
    let request = format!("GET {}\r\n", url.url.path());
    let rebind = options.rebind;
    let host = options.host.as_deref().unwrap_or(&url.url_host);

    eprintln!("connecting to {host} at {}", url.remote);
    let connecting = endpoint.connect(url.remote, host)?;
    let conn = if options.zero_rtt {
        match connecting.into_0rtt() {
            Ok((conn, zero_rtt_accepted)) => {
                eprintln!("client accepted 0rtt conversion");
                tokio::spawn(async move {
                    if zero_rtt_accepted.await {
                        eprintln!("server accepted 0rtt data at {:?}", start.elapsed());
                    } else {
                        eprintln!("server rejected 0rtt data at {:?}", start.elapsed());
                    }
                });
                conn
            }
            Err(connecting) => {
                eprintln!("client rejected 0rtt conversion");
                connecting.await
                    .map_err(|e| anyhow!("failed to connect: {}", e))?
            }
        }
    } else {
        connecting.await
            .map_err(|e| anyhow!("failed to connect: {}", e))?
    };
    eprintln!("sending request at {:?}", start.elapsed());
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
    //let send_finish = tokio::spawn(send.finish());
    /*tokio::spawn(async move {
        if let Err(e) = send.finish().await {
            eprintln!("failed to shutdown stream: {}", e);
        }
    });*/
    /*
    send.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
        */
    /*let response_start = Instant::now();
    eprintln!("receiving response at {:?}", response_start - start);
    
    let resp = recv
        .read_to_end(usize::max_value())
        .await
        .map_err(|e| anyhow!("failed to read response: {}", e))?;*/
        
    let mut resp = Vec::new();
    //let mut buf = [0; 4096];
    let mut response_start = None;
    loop {
        //tokio::join! {
        //    chunk = recv.read_chunk(4096, true).await => {
        //        let chunk = chunk.map_err(|e|)
        //    }
        //}
        let chunk = recv.read_chunk(4096, true).await
            .map_err(|e| anyhow!("failed to read response: {}", e))?;
        if response_start.is_none() {
            let now = Instant::now();
            eprintln!("first response bytes at {:?}", now - start);
            response_start = Some(now);
        }
        if let Some(chunk) = chunk {
            resp.extend(chunk.bytes);
        } else {
            break;
        }
    }
    let response_start = response_start.unwrap();

    let duration = response_start.elapsed();
    eprintln!(
        "response received in {:?} - {} KiB/s",
        duration,
        resp.len() as f32 / (duration_secs(&duration) * 1024.0)
    );
    if !options.no_print_response {
        io::stdout().write_all(&resp).unwrap();
        io::stdout().flush().unwrap();
    }
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
        Ok(Self { url, url_host, remote })
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
