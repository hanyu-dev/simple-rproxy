mod args;
mod peek;
mod utils;

use std::{net::SocketAddr, sync::LazyLock, time::Duration};

use anyhow::Result;
use clap::Parser;
use mimalloc::MiMalloc;
use tokio::net::{TcpSocket, TcpStream};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

static KEEP_ALIVE_CONF: LazyLock<socket2::TcpKeepalive> = LazyLock::new(|| {
    socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(15))
});

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    tracing::info!("{} built at {}", utils::VERSION, utils::BUILD_TIME);

    let args = args::Args::parse();
    tracing::debug!("\n### Accept args ### \n{:#?}\n######", args);

    peek::Peeker::init(args.target_host);

    let listener = {
        let socket = match args.listen {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };

        // Setting with socket2
        {
            let sock_ref = socket2::SockRef::from(&socket);

            #[cfg(unix)]
            let _ = sock_ref.set_cloexec(true);
            let _ = sock_ref.set_tcp_keepalive(&KEEP_ALIVE_CONF);
            let _ = sock_ref.set_nodelay(true);
            let _ = sock_ref.set_nonblocking(true);
        }

        socket.bind(args.listen)?;
        socket.listen(4096)?
    };

    loop {
        let (mut incoming, addr) = match listener.accept().await {
            Ok(ok) => ok,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => {
                tracing::warn!("Failed to accept: {}", e);
                continue;
            }
            Err(e) => {
                tracing::error!("Failed to accept: {}", e);
                break;
            }
        };

        tracing::debug!("Incoming connection from: {}", addr);

        tokio::spawn(async move {
            let upstream = if peek::Peeker::is_target_host(&mut incoming)
                .await
                .inspect_err(|e| {
                    tracing::error!("Error when peeking target host: {:?}", e);
                })
                .unwrap_or_default()
            {
                args.target_upstream
            } else {
                args.default_upstream
            };

            if let Err(e) = match upstream {
                utils::Upstream::SocketAddr(upstream_addr) => {
                    match TcpStream::connect(upstream_addr).await {
                        Ok(mut dest_stream) => {
                            {
                                let sock_ref = socket2::SockRef::from(&dest_stream);

                                #[cfg(unix)]
                                let _ = sock_ref.set_cloexec(true);
                                let _ = sock_ref.set_tcp_keepalive(&KEEP_ALIVE_CONF);
                                let _ = sock_ref.set_nodelay(true);
                                let _ = sock_ref.set_nonblocking(true);
                            }

                            #[cfg(target_os = "linux")]
                            match realm_io::bidi_zero_copy(&mut incoming, &mut dest_stream).await {
                                Ok(_) => Ok(()),
                                Err(ref e) if e.kind() == ErrorKind::InvalidInput => {
                                    realm_io::bidi_copy(&mut incoming, &mut dest_stream)
                                        .await
                                        .map(|_| ())
                                }
                                Err(e) => Err(e),
                            }
                            #[cfg(not(target_os = "linux"))]
                            realm_io::bidi_copy(&mut incoming, &mut dest_stream)
                                .await
                                .map(|_| ())
                        }
                        Err(e) => Err(e),
                    }
                }
                #[cfg(unix)]
                utils::Upstream::Unix(unix_path) => {
                    match tokio::net::UnixStream::connect(unix_path).await {
                        Ok(mut dest_stream) => {
                            #[cfg(target_os = "linux")]
                            match realm_io::bidi_zero_copy(&mut incoming, &mut dest_stream).await {
                                Ok(_) => Ok(()),
                                Err(ref e) if e.kind() == ErrorKind::InvalidInput => {
                                    realm_io::bidi_copy(&mut incoming, &mut dest_stream)
                                        .await
                                        .map(|_| ())
                                }
                                Err(e) => Err(e),
                            }
                            #[cfg(not(target_os = "linux"))]
                            realm_io::bidi_copy(&mut incoming, &mut dest_stream)
                                .await
                                .map(|_| ())
                        }
                        Err(e) => Err(e),
                    }
                }
                #[cfg(not(unix))]
                utils::Upstream::Unix(_) => {
                    unreachable!("Unix socket is not supported on non-unix platform")
                }
            } {
                tracing::error!("Failed to establish relay connection for {addr}: {}", e);
            }
        });
    }

    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{
        filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
    };

    let fmt_layer = tracing_subscriber::fmt::layer().with_filter(
        EnvFilter::builder()
            .with_default_directive(LevelFilter::DEBUG.into())
            .from_env_lossy(),
    );
    tracing_subscriber::registry().with(fmt_layer).init();
}
