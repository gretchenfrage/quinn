
use std::{
    sync::Arc,
    net::ToSocketAddrs as _,
};
use anyhow::Error;
use quinn::*;
use tracing::*;
use tracing_subscriber::prelude::*;


#[tokio::main]
async fn main() {
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
        .with(log_filter)
        .with(stdout_log);
    tracing::subscriber::set_global_default(log_subscriber).expect("unable to install logger");

    // generate keys
    let rcgen_cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::PrivateKey(rcgen_cert.serialize_private_key_der());
    let cert = rustls::Certificate(rcgen_cert.serialize_der().unwrap());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(&cert).unwrap();
    let certs = vec![cert];

    let mut tasks = tokio::task::JoinSet::new();

    // start server
    let (send_stop_server, mut recv_stop_server) = tokio::sync::oneshot::channel();
    tasks.spawn(log_err(async move {
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        // make sure to configure this:
        server_crypto.max_early_data_size = u32::MAX;
        let server_config = ServerConfig::with_crypto(Arc::new(server_crypto));
        let endpoint = Endpoint::server(
            server_config,
            "127.0.0.1:4433".to_socket_addrs().unwrap().next().unwrap(),
        )?;
        loop {
            let incoming = tokio::select! {
                option = endpoint.accept() => match option { Some(incoming) => incoming, None => break },
                result = &mut recv_stop_server => if result.is_ok() { break } else { continue },
            };
            // spawn subtask for connection
            tokio::spawn(log_err(async move {
                // attempt to accept 0-RTT data
                let conn = match incoming.accept()?.into_0rtt() {
                    Ok((conn, _)) => conn,
                    Err(connecting) => connecting.await?,
                };
                loop {
                    let mut stream = match conn.accept_uni().await {
                        Ok(stream) => stream,
                        Err(ConnectionError::ApplicationClosed(_)) => break,
                        Err(e) => Err(e)?,
                    };
                    // spawn subtask for stream
                    tokio::spawn(log_err(async move {
                        let msg = stream.read_to_end(1 << 30).await?;
                        info!(msg=%String::from_utf8_lossy(&msg), "received message");
                        Ok(())
                    }.instrument(info_span!("server stream"))));
                }
                Ok(())
            }.instrument(info_span!("server conn"))));
        }
        // shut down server endpoint cleanly
        endpoint.wait_idle().await;
        Ok(())
    }.instrument(info_span!("server"))));

    // start client
    async fn send_request(conn: &Connection, msg: &str) -> Result<(), Error> {
        let mut stream = conn.open_uni().await?;
        debug!(%msg, "beginning write_all call");
        stream.write_all(msg.as_bytes()).await?;
        debug!(%msg, "returned write_all call, beginning finish call");
        stream.finish().await?;
        debug!(%msg, "returned finish call");
        Ok(())
    }
    tasks.spawn(log_err(async move {
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // make sure to configure this:
        client_crypto.enable_early_data = true;
        let mut endpoint = Endpoint::client(
            "0.0.0.0:0".to_socket_addrs().unwrap().next().unwrap()
        )?;
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(client_crypto)));
        // twice, so as to allow 0-rtt to work on the second time
        for i in 0..2 {
            info!(%i, "client iteration");
            let connecting = endpoint.connect(
                "127.0.0.1:4433".to_socket_addrs().unwrap().next().unwrap(),
                "localhost",
            )?;
            // attempt to transmit 0-RTT data
            match connecting.into_0rtt() {
                Ok((conn, zero_rtt_accepted)) => {
                    debug!("attempting 0-rtt request");
                    let send_request_0rtt = send_request(&conn, "0-rtt hello world");
                    let mut send_request_0rtt_pinned = std::pin::pin!(send_request_0rtt);
                    tokio::select! {
                        result = &mut send_request_0rtt_pinned => result?,
                        accepted = zero_rtt_accepted => {
                            if accepted {
                                debug!("0-rtt accepted");
                                send_request_0rtt_pinned.await?;
                            } else {
                                debug!("0-rtt rejected");
                                send_request(&conn, "1-rtt hello world (0-rtt was attempted)").await?;
                            }
                        }
                    }
                }
                Err(connecting) => {
                    debug!("not attempting 0-rtt request");
                    let conn = connecting.await?;
                    send_request(&conn, "1-rtt hello world (0-rtt not attempted)").await?;
                }
            }
            println!();
        }
        // tell the server to shut down so this process doesn't idle forever
        let _ = send_stop_server.send(());
        Ok(())
    }.instrument(info_span!("client"))));

    while tasks.join_next().await.is_some() {}
}

async fn log_err<F: std::future::IntoFuture<Output=Result<(), Error>>>(task: F) {
    if let Err(e) = task.await {
        error!("{}", e);
    }
}
