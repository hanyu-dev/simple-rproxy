//! Bridge between the client and upstream

use std::{io, net::SocketAddr, path::Path, sync::atomic::Ordering};

use anyhow::{anyhow, Result};
use proxy_header::{ProxiedAddress, ProxyHeader};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

use crate::{
    apply_socket_conf,
    config::{Upstream, USE_PROXY_PROTOCOL},
};

/// Connected to a destination.
pub enum RelayConn {
    /// [TcpStream]
    Tcp(TcpStream),

    #[cfg(unix)]
    /// [UnixStream](tokio::net::UnixStream)
    Unix(UnixStream),
}

impl RelayConn {
    #[allow(private_bounds)]
    #[inline]
    /// Connect to the destination.
    ///
    /// Will apply some socket configurations. See [apply_socket_conf].
    pub async fn new<'c, C>(dest: C) -> io::Result<Self>
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

    #[inline]
    /// Perform IO relay between the client and the destination.
    pub async fn relay_io(self, mut incoming: TcpStream) -> Result<()> {
        macro_rules! realm_io {
            ($incoming:expr, $dest_stream:expr) => {{
                if USE_PROXY_PROTOCOL.load(Ordering::Relaxed) {
                    let header = ProxyHeader::with_address(ProxiedAddress::stream(
                        incoming.peer_addr()?,
                        incoming.local_addr()?,
                    ));

                    let mut buf = [0u8; 1024];

                    let len = header
                        .encode_to_slice_v2(&mut buf)
                        .map_err(io::Error::other)?;

                    loop {
                        $dest_stream.writable().await?;

                        match $dest_stream.try_write(&buf[0..len]) {
                            Ok(writed_len) => {
                                debug_assert_eq!(writed_len, len);
                                break;
                            }
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                            Err(e) => {
                                return Err(anyhow!(
                                    "Unknown error when try to write PROXY headers"
                                )
                                .context(e))
                            }
                        }
                    }
                };

                #[cfg(target_os = "linux")]
                match realm_io::bidi_zero_copy($incoming, $dest_stream).await {
                    Ok(_) => Ok(()),
                    Err(ref e) if e.kind() == io::ErrorKind::InvalidInput => {
                        realm_io::bidi_copy($incoming, $dest_stream)
                            .await
                            .map(|_| ())
                    }
                    Err(e) => Err(e),
                }
                #[cfg(not(target_os = "linux"))]
                realm_io::bidi_copy($incoming, $dest_stream)
                    .await
                    .map(|_| ())
                    .map_err(|e| anyhow!("Failed to bidi_copy data").context(e))
            }};
        }

        match self {
            Self::Tcp(mut dest_stream) => realm_io!(&mut incoming, &mut dest_stream),
            #[cfg(unix)]
            Self::Unix(mut dest_stream) => realm_io!(&mut incoming, &mut dest_stream),
        }
    }
}

enum ConnTo<P: AsRef<Path> = &'static str> {
    /// Connect to a socket address.
    SocketAddr(SocketAddr),

    #[allow(dead_code)]
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
