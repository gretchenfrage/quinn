//! This example demonstrates an HTTP client that requests files from a server.
//!
//! Checkout the `README.md` for guidance.

#[macro_use]
extern crate tracing;

use std::{
    fs,
    io::{self, Write},
    net::ToSocketAddrs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use clap::Parser;
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

    url: Url,

    /// Override hostname used for certificate verification
    #[clap(long = "host")]
    host: Option<String>,

    /// Custom certificate authority to trust, in DER format
    #[clap(long = "ca")]
    ca: Option<PathBuf>,

    /// Simulate NAT rebinding after connecting
    #[clap(long = "rebind")]
    rebind: bool,
}

fn main() {
    logging::init_logging();
    //tracing::subscriber::set_global_default(
    //    tracing_subscriber::FmtSubscriber::builder()
    //        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    //        .finish(),
    //)
    //.unwrap();
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
    let url = options.url;
    let url_host = strip_ipv6_brackets(url.host_str().unwrap());
    let remote = (url_host, url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca_path) = options.ca {
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
    client_crypto.enable_early_data = true;

    let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    let request = format!("GET {}\r\n", url.path());
    let start = Instant::now();
    let rebind = options.rebind;
    let host = options.host.as_deref().unwrap_or(url_host);

    for i in 1..=2 {
        eprintln!("round {}", i);
        eprintln!("connecting to {host} at {remote}");
        let conn = match endpoint.connect(remote, host)?.into_0rtt() {
            Ok((conn, _)) => {
                eprintln!("0-rtt accepted");
                conn
            },
            Err(connecting) => {
                eprintln!("0-rtt rejected");
                connecting.await.map_err(|e| anyhow!("failed to connect: {}", e))?
            },
        };
        /*let conn = endpoint
            .connect(remote, host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;*/
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
        send.finish()
            .await
            .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
        let response_start = Instant::now();
        eprintln!("request sent at {:?}", response_start - start);
        let resp = recv
            .read_to_end(usize::max_value())
            .await
            .map_err(|e| anyhow!("failed to read response: {}", e))?;
        let duration = response_start.elapsed();
        eprintln!(
            "response received in {:?} - {} KiB/s",
            duration,
            resp.len() as f32 / (duration_secs(&duration) * 1024.0)
        );
        io::stdout().write_all(&resp).unwrap();
        io::stdout().flush().unwrap();
        conn.close(0u32.into(), b"done");
        eprintln!("");
    }

    // Give the server a fair chance to receive the close packet
    endpoint.wait_idle().await;

    Ok(())
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


mod logging {
    //! Global logging system.

    use std::{
        fs::File,
        sync::Arc,
        env,
        panic,
    };
    use backtrace::Backtrace;
    use tracing_subscriber::{
        fmt::{
            self,
            time::uptime,
        },
        prelude::*,
        Registry,
        EnvFilter,
    };


    /// Default logging environment filter. Our crates are debug, everything else is warn.
    const DEFAULT_FILTER: &'static str = "warn";

    /// Initializes a `tracing` logging backend which outputs to stdout and also a `log` file. Accepts
    /// ecosystem-standard `RUST_LOG` env filters. Configures some other logging tweaks too.
    pub fn init_logging() {
        // initialize and install logging system
        let format = fmt::format()
            .compact()
            .with_timer(uptime())
            .with_line_number(true);
        let stdout_log = fmt::layer()
            .event_format(format);

        let log_file = File::create("log")
            .expect("unable to create log file");
        let log_file_log = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_line_number(true)
            .with_writer(Arc::new(log_file));

        let mut filter = DEFAULT_FILTER.to_owned();
        if let Ok(env_filter) = env::var(EnvFilter::DEFAULT_ENV) {
            filter.push(',');
            filter.push_str(&env_filter);
        }

        let subscriber = Registry::default()
            .with(EnvFilter::new(filter))
            .with(stdout_log)
            .with(log_file_log);
        tracing::subscriber::set_global_default(subscriber)
            .expect("unable to install log subscriber");

        // make panic messages and backtrace go through logging system
        panic::set_hook(Box::new(|info| {
            error!("{}", info);
            if env::var("RUST_BACKTRACE").map(|val| val == "1").unwrap_or(true) {
                error!("{:?}", Backtrace::new());
            }
        }));
    }

}
