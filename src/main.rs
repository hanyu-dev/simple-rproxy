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
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Mutex, atomic::Ordering},
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
    create_server().await?;

    #[cfg(unix)]
    // install signal handler for SIGHUP
    reload_handle().await;

    // wait for termination signal
    termination_handle().await;

    Ok(())
}

/// [`JoinHandle`] after spawning the server.
static SERVER_HANDLE: Mutex<Option<(JoinHandle<()>, utils::ConnCounter)>> = Mutex::new(None);

#[inline]
async fn create_server() -> Result<()> {
    let listener = utils::create_listener()?;

    let conn_counter = utils::ConnCounter::new();
    let handler = {
        let conn_counter = conn_counter.clone();
        tokio::spawn(async move {
            loop {
                let mut incoming = match listener.accept().await {
                    Ok((incoming, addr)) => {
                        tracing::debug!("Connection from [{addr}] accepted");
                        incoming
                    }
                    Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                        tracing::debug!("Conn aborted.");
                        continue;
                    }
                    Err(e) => {
                        tracing::error!("Failed to accept: {:#?}", e);
                        break;
                    }
                };

                let conn_counter = conn_counter.clone();
                tokio::spawn(async move {
                    let span = tracing::debug_span!("conn_handler", remote_addr = ?incoming.peer_addr().unwrap_or_else(|e| {
                            tracing::error!("Failed to get remote addr: {e:?}");
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                        })
                    );

                    conn_counter.conn_established();

                    async {
                        let relay_conn = {
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

                        let _ = relay_conn.relay_io(incoming).await;
                    }
                    .instrument(span)
                    .await
                });
            }
        })
    };

    let last = SERVER_HANDLE
        .lock()
        .unwrap_or_else(|l| l.into_inner())
        .replace((handler, conn_counter));

    if let Some(last) = last {
        tokio::spawn(async move {
            last.0.abort();
            last.1.wait_conn_end(None).await;
        });
    }

    Ok(())
}

#[cfg(unix)]
/// Create a signal handler for SIGHUP to gracefully reload server.
async fn reload_handle() {
    use tokio::signal;

    tokio::spawn(async move {
        loop {
            signal::unix::signal(signal::unix::SignalKind::hangup())
                .expect("failed to install signal handler")
                .recv()
                .await;

            tracing::info!("SIGHUP received, reloading config...");
            let need_restart = config::Cli::reload_config().unwrap_or_else(|e| {
                tracing::error!("Failed to reload config: {e}");
                false
            });

            if need_restart {
                tracing::info!("Gracefully restarting server...");

                if let Err(e) = create_server().await {
                    tracing::error!("Failed to restart server: {e}");
                }
            }
        }
    });
}

/// `shutdown_signal` will inform axum to gracefully shutdown when the process
/// is asked to shutdown.
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

    let last = SERVER_HANDLE
        .lock()
        .unwrap_or_else(|l| l.into_inner())
        .take();

    if let Some(last) = last {
        tokio::spawn(async move {
            last.0.abort();
            last.1.wait_conn_end(None).await;
        });
    }
}
