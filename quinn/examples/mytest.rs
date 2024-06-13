
use std::{
    sync::Arc,
    net::ToSocketAddrs as _,
};
use anyhow::Error;
use quinn::*;
use tracing::*;
use tracing_subscriber::prelude::*;


const ACK_FREQUENCY_EXT: bool = true;
const ACK_ELICITING_THRESHOLD: u32 = 0;

#[tokio::main]
async fn main() {
    let t0 = std::time::Instant::now();

    // init logging
    
    let log_fmt = tracing_subscriber::fmt::format()
        .compact()
        //.json()
        //.with_span_list(true)
        //.with_current_span(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_line_number(true);
    let stdout_log = tracing_subscriber::fmt::layer()
        //.fmt_fields(tracing_subscriber::fmt::format::JsonFields::new())
        .event_format(log_fmt);
    let log_filter = tracing_subscriber::EnvFilter::new(
        std::env::var(tracing_subscriber::EnvFilter::DEFAULT_ENV).unwrap_or("info".into())
    );
    let log_subscriber = tracing_subscriber::Registry::default()
        /*.with({
            struct Foo;
            impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Foo {
                fn on_event(&self, e: &tracing::Event, ctx: tracing_subscriber::layer::Context<S>) {
                    struct V;
                    impl tracing::field::Visit for V {
                        fn record_debug(&mut self, f: &tracing::field::Field, d: &dyn std::fmt::Debug) {
                            if f.as_ref() == "message" && format!("{:?}", d) == "writing ACK_ECN frame" {
                                println!("{}", std::backtrace::Backtrace::capture());
                            }
                        }
                    }
                    e.record(&mut V);
                }
            }
            Foo
        })*/
        .with(log_filter)
        .with(stdout_log);
    tracing::subscriber::set_global_default(log_subscriber).expect("unable to install logger");
    
    /*
    use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
    use tracing_subscriber::Registry;
    let formatting_layer = BunyanFormattingLayer::new("tracing_demo".into(), std::io::stdout);
    let subscriber = Registry::default()
        .with(JsonStorageLayer)
        .with(formatting_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();
    */

    // generate keys
    let rcgen_cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(rcgen_cert.key_pair.serialize_der());
    let cert = rustls::pki_types::CertificateDer::from(rcgen_cert.cert);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let certs = vec![cert];

    let mut tasks = tokio::task::JoinSet::new();

    // start server
    let (send_stop_server, mut recv_stop_server) = tokio::sync::oneshot::channel();
    tasks.spawn(log_err(async move {
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key.into())?;
        // make sure to configure this:
        server_crypto.max_early_data_size = u32::MAX;
        let server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_crypto))?;
        let mut transport_config = TransportConfig::default();
        if ACK_FREQUENCY_EXT {
            let mut ack_frequency_config = AckFrequencyConfig::default();
            ack_frequency_config.ack_eliciting_threshold(ACK_ELICITING_THRESHOLD.into());
            transport_config.ack_frequency_config(Some(ack_frequency_config));
        } else {
            transport_config.ack_frequency_config(None);
        }
        let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));
        server_config.transport_config(Arc::new(transport_config));
        let endpoint = Endpoint::server(
            server_config,
            "127.0.0.1:4433".to_socket_addrs().unwrap().next().unwrap(),
        )?;
        for _i in 0.. {
            let incoming = tokio::select! {
                option = endpoint.accept() => match option { Some(incoming) => incoming, None => break },
                result = &mut recv_stop_server => if result.is_ok() { break } else { continue },
            };
            // spawn subtask for connection
            tokio::spawn(log_err(async move {
                info!("received incoming connection attempt, accepting");
                // attempt to accept 0-RTT data
                let conn = match incoming.accept()?.into_0rtt() {
                    Ok((conn, _)) => conn,
                    Err(connecting) => connecting.await?,
                };
                if false {
                    // spawn task that writes a byte down-stream intermittently
                    let conn = conn.clone();
                    tokio::spawn(log_err(async move {
                        let mut stream = conn.open_uni().await?;
                        loop {
                            let sleep = tokio::time::sleep(std::time::Duration::from_millis(333));
                            tokio::pin!(sleep);
                            tokio::select! {
                                () = &mut sleep => (),
                                _e = conn.closed() => break,
                            };
                            info!("writing a ping");
                            stream.write_all(b"ping").await?;
                        }
                        Ok(())
                    }).instrument(info_span!("server_down_stream")));
                }
                loop {
                    let mut stream = match conn.accept_uni().await {
                        Ok(stream) => stream,
                        Err(ConnectionError::ApplicationClosed(_)) => break,
                        Err(e) => Err(e)?,
                    };
                    // spawn subtask for stream
                    tokio::spawn(log_err(async move {
                        info!("received stream open");
                        let msg = stream.read_to_end(1 << 30).await?;
                        info!("received message (stream closed) {:?}", String::from_utf8_lossy(&msg));
                        Ok(())
                    }).instrument(info_span!("server_stream")));
                }
                Ok(())
            }).instrument(info_span!("server_conn"/*, server_conn=%i*/)));
        }
        // shut down server endpoint cleanly
        endpoint.wait_idle().await;
        Ok(())
    }).instrument(info_span!("server")));

    // start client
    async fn send_request(conn: &Connection, msg: &str) -> Result<(), Error> {
        let mut stream = conn.open_uni().await?;
        info!(%msg, "beginning write_all and finish calls");
        for _ in 0..1 {
            stream.write_all(msg.as_bytes()).await?;
        }
        stream.finish()?;
        info!(%msg, "returned write_all and finish calls, beginning stopped call");
        stream.stopped().await?;
        info!(%msg, "returned stopped call");
        Ok(())
    }
    tasks.spawn(log_err(async move {
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // make sure to configure this:
        client_crypto.enable_early_data = true;
        let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_crypto))?;
        let mut transport_config = TransportConfig::default();
        if ACK_FREQUENCY_EXT {
            let mut ack_frequency_config = AckFrequencyConfig::default();
            ack_frequency_config.ack_eliciting_threshold(ACK_ELICITING_THRESHOLD.into());
            transport_config.ack_frequency_config(Some(ack_frequency_config));
        } else {
            transport_config.ack_frequency_config(None);
        }
        let mut client_config = ClientConfig::new(Arc::new(client_crypto));
        client_config.transport_config(Arc::new(transport_config));
        let mut endpoint = Endpoint::client(
            "0.0.0.0:0".to_socket_addrs().unwrap().next().unwrap()
        )?;
        endpoint.set_default_client_config(client_config);
        // twice, so as to allow 0-rtt to work on the second time
        for i in 0..2 {
            async {
                info!(%i, "client connecting");
                let connecting = endpoint.connect(
                    "127.0.0.1:4433".to_socket_addrs().unwrap().next().unwrap(),
                    "localhost",
                )?;
                // attempt to transmit 0-RTT data
                match connecting.into_0rtt() {
                    Ok((conn, zero_rtt_accepted)) => {
                        info!("attempting 0-rtt request");
                        let send_request_0rtt = send_request(&conn, "0-rtt hello world");
                        if true {
                            tokio::spawn({
                                let conn = conn.clone();
                                async move {
                                    loop {
                                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                                        let conn = conn.clone();
                                        tokio::spawn(async move {
                                            let _ = send_request(&conn, "ping").await;
                                        });
                                    }
                                }
                            });
                        }
                        tokio::pin!(send_request_0rtt);
                        tokio::select! {
                            result = &mut send_request_0rtt => result?,
                            accepted = zero_rtt_accepted => {
                                if accepted {
                                    info!("0-rtt accepted");
                                    send_request_0rtt.await?;
                                } else {
                                    info!("0-rtt rejected");
                                    send_request(&conn, "1-rtt hello world (0-rtt was attempted)").await?;
                                }
                            }
                        }
                    }
                    Err(connecting) => {
                        info!("not attempting 0-rtt request");
                        let conn = connecting.await?;
                        send_request(&conn, "1-rtt hello world (0-rtt not attempted)").await?;
                    }
                }
                Ok::<(), Error>(())
            }.instrument(info_span!("client_conn"/*, client_conn=%i*/)).await?;

            if i == 0 {
                tokio::time::sleep_until(tokio::time::Instant::from(t0) + std::time::Duration::from_secs(1)).await;
            }
            println!();
        }
        // tell the server to shut down so this process doesn't idle forever
        let _ = send_stop_server.send(());
        Ok(())
    }).instrument(info_span!("client")));

    while tasks.join_next().await.is_some() {}
}

async fn log_err<F: std::future::IntoFuture<Output=Result<(), Error>>>(task: F) {
    if let Err(e) = task.await {
        error!("{}", e);
    }
}
