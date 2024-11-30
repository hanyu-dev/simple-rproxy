//! Bridge between the client and upstream

use std::{io, sync::atomic::Ordering};

use anyhow::{Context, Result, anyhow};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{io::AsyncWriteExt, net::TcpStream};

use crate::{
    apply_socket_conf, config::USE_PROXY_PROTOCOL, proxy_protocol::encode_proxy_header_v2,
};

/// Connected to a destination.
pub(crate) enum RelayConn {
    /// [`TcpStream`]
    Tcp(TcpStream),

    #[cfg(unix)]
    /// [`UnixStream`](tokio::net::UnixStream)
    Unix(UnixStream),
}

impl RelayConn {
    #[inline]
    pub(crate) fn apply_socket_conf(self) -> Self {
        match &self {
            Self::Tcp(dest_stream) => {
                apply_socket_conf!(dest_stream);
            }
            #[cfg(unix)]
            Self::Unix(dest_stream) => {
                apply_socket_conf!(dest_stream);
            }
        }

        self
    }

    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    #[inline]
    /// Perform IO relay between the client and the destination.
    pub async fn relay_io(self, mut incoming: TcpStream) -> Result<()> {
        macro_rules! do_relay_io {
            ($incoming:expr_2021, $dest_stream:expr_2021) => {{
                if USE_PROXY_PROTOCOL.load(Ordering::Relaxed) {
                    let (len, buf) =
                        encode_proxy_header_v2($incoming.peer_addr()?, $incoming.local_addr()?)
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
                match tokio_splice::zero_copy_bidirectional(&mut $incoming, &mut $dest_stream).await
                {
                    Ok((tx, rx)) => {
                        tracing::debug!(
                            "Zero-copy bidirectional io closed, tx: {tx} bytes, rx: {rx} bytes"
                        );

                        return Ok(());
                    }
                    Err(e) => match e.kind() {
                        io::ErrorKind::BrokenPipe => {
                            tracing::debug!("Connection closed unexpectedly");

                            return Ok(());
                        }
                        io::ErrorKind::InvalidInput => {
                            tracing::warn!("Fallback to copy bidirectional with buffer");
                        }
                        _ => {
                            return Err(anyhow!(e).context("`zero_copy_bidirectional` data failed"));
                        }
                    },
                }

                tokio::io::copy_bidirectional(&mut $incoming, &mut $dest_stream)
                    .await
                    .map(|(tx, rx)| {
                        tracing::debug!(
                            "Bidirectional io with buffer closed, tx: {tx} bytes, rx: {rx} bytes"
                        );
                    })
                    .context("`copy_bidirectional` data failed")
            }};
        }

        match self {
            Self::Tcp(mut dest_stream) => do_relay_io!(incoming, dest_stream),
            #[cfg(unix)]
            Self::Unix(mut dest_stream) => do_relay_io!(incoming, dest_stream),
        }
    }
}
