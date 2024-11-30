//! Bridge between the client and upstream

use std::{io, net::SocketAddr, path::Path, sync::atomic::Ordering};

use anyhow::{anyhow, Context, Result};
use proxy_header::{ProxiedAddress, ProxyHeader};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

use crate::{
    apply_socket_conf,
    config::{Upstream, USE_PROXY_PROTOCOL},
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
    /// Connect to the destination.
    ///
    /// Will apply some socket configurations. See [`apply_socket_conf`].
    pub(crate) async fn new<'c, C>(dest: C) -> io::Result<Self>
    where
        C: Into<ConnTo<&'c str>>,
    {
        match dest.into() {
            ConnTo::SocketAddr(dest) => TcpStream::connect(dest).await.map(Self::Tcp),
            #[cfg(unix)]
            ConnTo::UnixPath(path) => UnixStream::connect(path).await.map(Self::Unix),
            #[cfg(not(unix))]
            ConnTo::UnixPath(_) => unreachable!("Unix socket is not supported on this platform"),
        }
        .map(Self::apply_socket_conf)
    }

    #[inline]
    fn apply_socket_conf(self) -> Self {
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
            ($incoming:expr, $dest_stream:expr) => {{
                if USE_PROXY_PROTOCOL.load(Ordering::Relaxed) {
                    let header = ProxyHeader::with_address(ProxiedAddress::stream(
                        $incoming.peer_addr()?,
                        $incoming.local_addr()?,
                    ));

                    let mut buf = [0u8; 1024];

                    let len = header
                        .encode_to_slice_v2(&mut buf)
                        .context("Failed to encode PROXY Protocol headers")?;

                    loop {
                        $dest_stream
                            .writable()
                            .await
                            .context("Failed to write PROXY Protocol headers: not writable")?;

                        match $dest_stream.try_write(&buf[0..len]) {
                            Ok(writed_len) => {
                                debug_assert_eq!(writed_len, len);
                                break;
                            }
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                            Err(e) => {
                                return Err(anyhow!(e).context(
                                    "Failed to write PROXY Protocol headers: unknown error",
                                ))
                            }
                        }
                    }
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
                            return Err(anyhow!(e).context("`zero_copy_bidirectional` data failed"))
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

pub(crate) enum ConnTo<P: AsRef<Path> = &'static str> {
    /// Connect to a socket address.
    SocketAddr(SocketAddr),

    #[allow(dead_code, reason = "Unix socket is not supported on this platform")]
    /// Connect to a Unix socket path.
    UnixPath(P),
}

impl From<SocketAddr> for ConnTo {
    fn from(addr: SocketAddr) -> Self {
        Self::SocketAddr(addr)
    }
}

#[cfg(unix)]
impl<P: AsRef<Path>> From<P> for ConnTo<P> {
    fn from(path: P) -> Self {
        Self::UnixPath(path)
    }
}

impl<'c> From<&'c Upstream> for ConnTo<&'c str> {
    fn from(upstream: &'c Upstream) -> Self {
        match upstream {
            Upstream::SocketAddr(addr) => Self::SocketAddr(*addr),
            #[cfg(unix)]
            Upstream::Unix(path) => Self::UnixPath(path),
        }
    }
}
