mod config;
mod peek;
mod relay;
mod utils;

use std::{
    io,
    sync::{Arc, OnceLock},
};

use anyhow::Result;
use arc_swap::ArcSwap;
use mimalloc::MiMalloc;
use tokio::task::JoinHandle;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    utils::init_tracing();
    tracing::info!("{} built at {}", utils::VERSION, utils::BUILD_TIME);

    // init global config from cmdline args or config file
    config::Args::try_init()?;

    // create relay server.
    create_server().await?;

    #[cfg(unix)]
    // install signal handler for SIGHUP
    reload_handle().await;

    // wait for termination signal
    termination_handle().await;

    Ok(())
}

/// [JoinHandle] after spawning the server.
static SERVER_HANDLE: OnceLock<ArcSwap<(JoinHandle<()>, utils::ConnCounter)>> = OnceLock::new();

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
                        tracing::error!("Failed to accept: {}", e);
                        break;
                    }
                };

                let conn_counter = conn_counter.clone();
                tokio::spawn(async move {
                    conn_counter.conn_established();

                    let relay_conn = {
                        let args = get_args!();
                        let upstream = if peek::Peeker::is_target_host(&mut incoming)
                            .await
                            .inspect_err(|e| {
                                tracing::error!("Error when peeking target host: {:?}", e);
                            })
                            .unwrap_or_default()
                        {
                            args.target_upstream.as_ref().unwrap()
                        } else {
                            args.default_upstream.as_ref().unwrap()
                        };

                        match relay::RelayConn::new(upstream).await {
                            Ok(relay_conn) => relay_conn,
                            Err(e) => {
                                tracing::error!(
                                    "Failed to connect to upstream {:?}: {:?}",
                                    upstream,
                                    e
                                );
                                return;
                            }
                        }
                    };

                    let _ = relay_conn.relay_io(incoming).await;
                });
            }
        })
    };

    if let Err(last) = SERVER_HANDLE.set(ArcSwap::from(Arc::new((handler, conn_counter)))) {
        tokio::spawn(async move {
            let last = last.into_inner();
            last.1.wait_conn_end(None).await;
            last.0.abort();
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
            let need_restart = config::Args::reload_config().unwrap_or_else(|e| {
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

/// `shutdown_signal` will inform axum to gracefully shutdown when the process is asked to shutdown.
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
