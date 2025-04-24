//! Bridge between the client and upstream

use std::{io, net::SocketAddr};

use anyhow::{Context, Result, anyhow};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{io::AsyncWriteExt, net::TcpStream};

use crate::{
    apply_socket_conf,
    config::ADV_ENABLE_ZERO_COPY,
    utils::{Traffic, proxy_protocol::encode_v2},
};

/// Connected to a destination.
pub(crate) enum RelayConn {
    /// [`TcpStream`]
    Tcp {
        /// Destination stream
        dest: TcpStream,

        /// If set, will connect upstream with PROXY protocol.
        proxy_protocol: bool,
    },

    #[cfg(unix)]
    /// [`UnixStream`]
    Unix {
        /// Destination stream
        dest: UnixStream,

        /// If set, will connect upstream with PROXY protocol.
        proxy_protocol: bool,
    },
}

impl RelayConn {
    #[inline]
    pub(crate) fn apply_socket_conf(self) -> Self {
        match &self {
            Self::Tcp { dest, .. } => {
                apply_socket_conf!(dest);
            }
            #[cfg(unix)]
            Self::Unix { dest, .. } => {
                apply_socket_conf!(dest);
            }
        }

        self
    }

    #[tracing::instrument(level = "debug", skip_all)]
    #[inline]
    /// Perform IO relay between the client and the destination.
    pub async fn relay_io(
        self,
        mut incoming: TcpStream,
        remote_addr: SocketAddr,
    ) -> Result<Traffic> {
        macro_rules! do_relay_io {
            ($incoming:expr, $dest_stream:expr, $proxy_protocol:expr) => {{
                if $proxy_protocol {
                    let (len, buf) = encode_v2(remote_addr, $incoming.local_addr()?)
                        .expect("Socket address, addr family match");

                    $dest_stream
                        .writable()
                        .await
                        .context("Failed to write PROXY Protocol headers: not writable")?;

                    $dest_stream
                        .write_all(&buf[0..len])
                        .await
                        .context("Failed to write PROXY Protocol headers")?;

                    tracing::debug!("PROXY Protocol headers sent, add up to {len} bytes");
                };

                #[cfg(unix)]
                if *ADV_ENABLE_ZERO_COPY {
                    match tokio_splice2::copy_bidirectional(&mut $incoming, &mut $dest_stream).await
                    {
                        Ok((tx, rx)) => {
                            tracing::debug!(
                                "Zero-copy bidirectional io closed, tx: {tx} bytes, rx: {rx} bytes"
                            );

                            return Ok(Traffic {
                                tx: tx as _,
                                rx: rx as _,
                            });
                        }
                        Err(e) => match e.kind() {
                            io::ErrorKind::InvalidInput => {
                                tracing::warn!("Fallback to copy bidirectional with buffer");
                            }
                            _ => {
                                return Err(
                                    anyhow!(e).context("`zero_copy_bidirectional` data failed")
                                );
                            }
                        },
                    }
                }

                tokio::io::copy_bidirectional(&mut $incoming, &mut $dest_stream)
                    .await
                    .map(|(tx, rx)| {
                        tracing::debug!(
                            "Bidirectional io with buffer closed, tx: {tx} bytes, rx: {rx} bytes"
                        );

                        Traffic { tx, rx }
                    })
                    .context("`copy_bidirectional` data failed")
            }};
        }

        match self {
            Self::Tcp {
                mut dest,
                proxy_protocol,
            } => do_relay_io!(incoming, dest, proxy_protocol),
            #[cfg(unix)]
            Self::Unix {
                mut dest,
                proxy_protocol,
            } => do_relay_io!(incoming, dest, proxy_protocol),
        }
    }
}
