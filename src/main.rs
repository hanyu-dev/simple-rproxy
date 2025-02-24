//! Simple-RProxy

#![feature(let_chains)] // Will be stable in Rust 1.85, Rust Edition 2024
#![feature(const_vec_string_slice)]

mod config;
mod error;
mod peek;
mod relay;
mod utils;

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use anyhow::Result;
use mimalloc::MiMalloc;
use tokio::{net::TcpStream, task::JoinHandle};

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

    // after termination
    termination_post_tasks().await;

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
            let (incoming, remote_addr) = match listener.accept().await {
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

            // Instant when new conn is accepted
            let instant = Instant::now();

            tokio::spawn(conn_handler(incoming, remote_addr, instant));

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

#[tracing::instrument(level = "debug", skip(incoming, instant))]
async fn conn_handler(mut incoming: TcpStream, remote_addr: SocketAddr, instant: Instant) {
    let relay_conn = {
        tracing::debug!(elapsed = ?instant.elapsed(), "Start to peek SNI");

        let peeked_sni = match peek::TcpStreamPeeker::new(&mut incoming)
            .peek_sni()
            .await
            .unwrap_or_default()
        {
            sni_name @ Some(_) => sni_name,
            None => {
                tracing::debug!("Not HTTPS.");

                if config::HTTPS_ONLY.load(Ordering::Relaxed) {
                    return;
                }

                None
            }
        };

        let relay_conn = match peeked_sni {
            Some(peeked_sni) => {
                let peeked_sni = peeked_sni.as_ref();
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
                            "Upstream matched"
                        );

                        upstream.connect().await
                    }
                    _ => {
                        tracing::debug!(
                            elapsed = ?instant.elapsed(),
                            peeked_sni,
                            "No upstream matched"
                        );

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
                tracing::debug!(elapsed = ?instant.elapsed(), "SNI not found");

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

    tracing::debug!(elapsed = ?instant.elapsed(), "Upstream connected.");

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

async fn termination_post_tasks() {
    #[cfg(unix)]
    {
        config::PID_FILE.store(None);
    }
}
