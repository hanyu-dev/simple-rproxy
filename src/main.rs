//! Simple-RProxy

#![feature(let_chains)] // Will be stable in Rust 1.85, Rust Edition 2024

mod config;
mod error;
mod peek;
mod proxy_protocol;
mod relay;
mod utils;

use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::Result;
use mimalloc::MiMalloc;
use tokio::task::JoinHandle;
use tracing::Instrument;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    utils::init_tracing();

    tracing::info!("{} built at {}", utils::VERSION, utils::BUILD_TIME);

    // init global config from cmdline args or config file
    let initialized = config::Cli::try_init()?;

    if !initialized {
        return Ok(());
    }

    // create relay server.
    run().await?;

    #[cfg(unix)]
    // install signal handler for SIGHUP
    reload_handle().await;

    // wait for termination signal
    termination_handle().await;

    Ok(())
}

/// [`JoinHandle`] after spawning the server.
static SERVER_HANDLE: Mutex<Option<(JoinHandle<()>, Arc<AtomicBool>)>> = Mutex::new(None);

#[inline]
async fn run() -> Result<()> {
    let canceller_tx = Arc::new(AtomicBool::new(false));

    let listener = utils::create_listener()?;
    let canceller_rx = canceller_tx.clone();
    let handler = tokio::spawn(async move {
        loop {
            let (mut incoming, remote_addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    tracing::debug!("Connection aborted.");
                    continue;
                }
                Err(e) => {
                    tracing::error!("Failed to accept: {:#?}", e);
                    break;
                }
            };

            tokio::spawn(async move {
                let root_span = tracing::debug_span!("conn_handler", remote_addr = ?remote_addr);

                async {
                    let relay_conn = {
                        // SNI is no longer than 256 bytes
                        let mut buf = [0u8; 256];

                        let sni_name = match peek::PeekedTcpStream::new(&mut incoming)
                            .peek_sni(&mut buf)
                            .await
                        {
                            Ok(Some(sni_length)) => {
                                if sni_length != 0 {
                                    #[allow(unsafe_code, reason = "Non-UTF-8 is OK")]
                                    Some(unsafe {
                                        std::str::from_utf8_unchecked(&buf[..sni_length])
                                    })
                                } else {
                                    None
                                }
                            }
                            Ok(None) => {
                                tracing::debug!("Not HTTPS.");

                                if config::HTTPS_ONLY.load(Ordering::Relaxed) {
                                    return;
                                }

                                None
                            }
                            Err(e) => {
                                tracing::error!("Error when peeking SNI: {e:?}");

                                None
                            }
                        };

                        let relay_conn = match sni_name {
                            Some(sni_name) => {
                                tracing::debug!("SNI found: {sni_name}");

                                match config::TARGET_UPSTREAMS.get(sni_name) {
                                    Some(upstream) => {
                                        tracing::debug!(
                                            "Upstream [{}] matched for [{sni_name}]",
                                            upstream.value()
                                        );

                                        upstream.connect().await
                                    }
                                    _ => {
                                        config::DEFAULT_UPSTREAM
                                            .load()
                                            .as_ref()
                                            .unwrap()
                                            .connect()
                                            .await
                                    }
                                }
                            }
                            None => {
                                config::DEFAULT_UPSTREAM
                                    .load()
                                    .as_ref()
                                    .unwrap()
                                    .connect()
                                    .await
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

                    if let Err(e) = relay_conn.relay_io(incoming).await {
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
                .instrument(root_span)
                .await;
            });

            if canceller_rx.load(Ordering::Relaxed) {
                break;
            }
        }

        tracing::info!("Current server loop has exited.");
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

            match config::Cli::reload_config() {
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
    }

    tracing::info!("signal received, shutdown");
}
