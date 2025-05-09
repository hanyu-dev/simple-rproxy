//! Simple-RProxy

#![feature(file_lock)]
#![feature(ip_as_octets)]
#![feature(result_flattening)]
#![feature(slice_as_array)]

mod config;
mod error;
mod metrics;
mod peek;
mod relay;
// mod server;
mod utils;

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::Result;
use mimalloc::MiMalloc;
use tokio::{io::AsyncWriteExt, net::TcpStream, task::JoinHandle, time::sleep};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    utils::init_tracing();

    tracing::info!("{} built at {}", utils::VERSION, utils::BUILD_TIME);

    // init global config from cmdline args or config file
    let initialized = config::Config::try_may_init().await?;

    if !initialized {
        return Ok(());
    }

    // init traffic metric, etc
    metrics::init_metrics().await;

    main_tasks().await
}

async fn main_tasks() -> Result<()> {
    // create relay server.
    run().await?;

    #[cfg(unix)]
    // install signal handler for SIGHUP
    reload_handle().await;

    // wait for termination signal
    termination_handle().await;

    // after termination
    termination_post_tasks().await;

    Ok(())
}

/// [`JoinHandle`] after spawning the server.
static SERVER_HANDLE: Mutex<Option<(JoinHandle<()>, Arc<AtomicBool>)>> = Mutex::new(None);
static FATAL_ERROR_SENDER: AtomicBool = AtomicBool::new(false);

#[inline]
async fn run() -> Result<()> {
    let canceller_tx = Arc::new(AtomicBool::new(false));

    let listener = utils::create_listener()?;
    let canceller_rx = canceller_tx.clone();
    let handler = tokio::spawn(async move {
        let has_error = loop {
            let (incoming, remote_addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    tracing::debug!("Connection aborted.");
                    continue;
                }
                Err(e) => {
                    tracing::error!("Failed to accept: {:#?}", e);
                    break true;
                }
            };

            // Instant when new conn is accepted
            let instant = Instant::now();

            tokio::spawn(conn_handler(incoming, remote_addr, instant));

            if canceller_rx.load(Ordering::Relaxed) {
                break false;
            }
        };

        tracing::error!("Current server loop has exited.");

        if has_error {
            FATAL_ERROR_SENDER.store(true, Ordering::Relaxed);
        }
    });

    let last = SERVER_HANDLE
        .lock()
        .unwrap_or_else(|l| l.into_inner())
        .replace((handler, canceller_tx));

    if let Some((_, last_canceller)) = last {
        last_canceller.store(true, Ordering::Relaxed);
        // Just leave the old handler running, no more new connection will be
        // accepted.
    }

    Ok(())
}

#[tracing::instrument(level = "debug", skip(incoming, instant))]
async fn conn_handler(mut incoming: TcpStream, remote_addr: SocketAddr, instant: Instant) {
    let relay_conn = {
        tracing::debug!(elapsed = ?instant.elapsed(), "Start to peek SNI");

        macro_rules! default_upstream {
            (HTTPS) => {
                default_upstream!({
                    use tokio::io::AsyncWriteExt;

                    if let Err(e) = incoming
                        .write_all(&[0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28])
                        .await
                    {
                        tracing::error!("Write TLS Alert error: {e:?}");
                    };
                })
            };
            ($($block:block)?) => {{
                let default_upstream = config::DEFAULT_UPSTREAM.load();
                match default_upstream.as_ref() {
                    Some(upstream) => upstream.connect().await,
                    None => {
                        $($block)?

                        tracing::trace!(elapsed = ?instant.elapsed(), "Drop connection for now.");

                        return;
                    }
                }
            }};
        }

        let relay_conn = match peek::peek_with_timeout(&mut incoming, None).await {
            Ok(peek::Peeked::Tls {
                host_name: Some(host_name),
                maybe_reality: _,
            }) => {
                let peeked_sni = host_name.as_str();

                tracing::debug!(
                    peeked_sni,
                    elapsed = ?instant.elapsed(),
                    "SNI found"
                );

                match config::TARGET_UPSTREAMS.get(peeked_sni) {
                    Some(upstream) => {
                        tracing::debug!(
                            elapsed = ?instant.elapsed(),
                            upstream = ?upstream.value(),
                            peeked_sni,
                            "Upstream matched."
                        );

                        upstream.connect().await
                    }
                    None => {
                        tracing::debug!(
                            elapsed = ?instant.elapsed(),
                            peeked_sni,
                            "No upstream matched."
                        );

                        default_upstream!(HTTPS)
                    }
                }
            }
            Ok(peek::Peeked::Tls {
                host_name: None,
                maybe_reality: _,
            }) => {
                default_upstream!(HTTPS)
            }
            Ok(peek::Peeked::MaybeHttp) => {
                // TODO: Write error response

                tracing::debug!(elapsed = ?instant.elapsed(), "Maybe HTTP, write 403 rejection");

                let _ = incoming
                    .write_all(
                        b"HTTP/1.1 400 The plain HTTP request was sent to HTTPS port\r\n\r\n",
                    )
                    .await
                    .inspect_err(|e| {
                        tracing::error!("Failed to write HTTP response: {e:?}");
                    });

                tracing::debug!(elapsed = ?instant.elapsed(), "HTTP response sent");

                let _ = incoming.shutdown().await.inspect_err(|e| {
                    tracing::error!("Failed to shutdown: {e:?}");
                });

                return;
            }
            Ok(_peeked) => {
                tracing::debug!(elapsed = ?instant.elapsed(), "Not implemented, reject it");

                return;
            }
            _ => {
                tracing::debug!(elapsed = ?instant.elapsed(), "Unknown connection type or error, shutdown");

                return;
            }
        };

        match relay_conn {
            Ok(relay_conn) => relay_conn,
            Err(e) => {
                tracing::error!("Failed to connect to upstream: {e:?}",);
                return;
            }
        }
    };

    tracing::debug!(elapsed = ?instant.elapsed(), "Upstream connected.");

    match relay_conn.relay_io(incoming, remote_addr).await {
        Ok(traffic) => {
            send_metric!(remote_addr.ip(), traffic);
        }
        Err(e) => {
            match e.downcast_ref::<io::Error>().map(|e| e.kind()) {
                Some(io::ErrorKind::BrokenPipe) => {
                    // Some poor implemented client will do so.
                    tracing::debug!("Connection closed unexpectedly");

                    return;
                }
                Some(io::ErrorKind::ConnectionReset) => {
                    // Some poor implemented client will do so.
                    tracing::debug!("Connection reset by peer");

                    return;
                }
                _ => {}
            }

            tracing::error!("Unexpected error: {e:#?}");
        }
    }
}

#[cfg(unix)]
/// Create a signal handler for SIGHUP to gracefully reload server.
async fn reload_handle() {
    use tokio::signal::unix::{SignalKind, signal};

    tokio::spawn(async move {
        loop {
            signal(SignalKind::hangup())
                .expect("Failed to install signal handler")
                .recv()
                .await;

            tracing::info!("SIGHUP received, reloading config...");

            match config::Config::reload() {
                Ok(true) => {
                    tracing::info!("Config reloaded, restarting server...");

                    if let Err(e) = run().await {
                        tracing::error!("Failed to restart server: {e:?}");
                    }
                }
                Ok(false) => {
                    tracing::info!("Config reloaded.");
                }
                Err(e) => {
                    tracing::error!("Failed to reload config: {e:?}");
                }
            }
        }
    });
}

/// `termination_handle` will force the server to shutdown.
async fn termination_handle() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
        () = async {
            loop {
                sleep(Duration::from_secs(1)).await;

                if FATAL_ERROR_SENDER.load(Ordering::Relaxed) {
                    break;
                }
            }
        } => {},
    }

    tracing::info!("signal received, shutdown");
}

async fn termination_post_tasks() {
    #[cfg(unix)]
    {
        config::PID_FILE.store(None);
    }
}
