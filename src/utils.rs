use std::{
    fmt, io,
    net::SocketAddr,
    sync::{Arc, LazyLock},
    time::Duration,
};

use anyhow::{Context, Result};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tracing_subscriber::fmt::time::ChronoLocal;

use crate::{config, relay::RelayConn};

/// The version of the server.
pub(crate) const VERSION: &str = concat!("v", include_str!(concat!(env!("OUT_DIR"), "/VERSION")));
/// The version of the server.
pub(crate) const BUILD_TIME: &str = include_str!(concat!(env!("OUT_DIR"), "/BUILD_TIME"));

pub(crate) static KEEP_ALIVE_CONF: LazyLock<socket2::TcpKeepalive> = LazyLock::new(|| {
    socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(15))
});

/// Initialize tracing subscriber.
pub(crate) fn init_tracing() {
    use tracing_subscriber::{
        EnvFilter, Layer, filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt,
    };

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_timer(ChronoLocal::rfc_3339())
        .with_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        );
    tracing_subscriber::registry().with(fmt_layer).init();
}

/// Create a listener with the given address.
pub(crate) fn create_listener() -> io::Result<TcpListener> {
    let addr = config::CONFIG
        .load()
        .as_ref()
        .expect("Must have config")
        .listen;

    let socket = match &addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };

    // Setting with socket2
    crate::apply_socket_conf!(&socket);

    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;

    socket.bind(addr)?;

    socket.listen(4096)
}

#[macro_export]
/// Apply socket configurations to the given stream.
///
/// - [socket2::SockRef::set_cloexec](socket2::SockRef::set_cloexec): true
/// - [socket2::SockRef::set_tcp_keepalive](socket2::SockRef::set_tcp_keepalive): 15s interval and 15s timeout
/// - [socket2::SockRef::set_nodelay](socket2::SockRef::set_nodelay): true
/// - [socket2::SockRef::set_nonblocking](socket2::SockRef::set_nonblocking):
///   true
macro_rules! apply_socket_conf {
    ($socket:expr_2021) => {{
        let sock_ref = socket2::SockRef::from($socket);

        #[cfg(unix)]
        let _ = sock_ref.set_cloexec(true);
        let _ = sock_ref.set_tcp_keepalive(&$crate::utils::KEEP_ALIVE_CONF);
        let _ = sock_ref.set_nodelay(true);
        let _ = sock_ref.set_nonblocking(true);
    }};
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Upstream to connect to.
pub(crate) enum Upstream {
    /// Upstream addr to connect to.
    SocketAddr(SocketAddr),

    #[cfg(unix)]
    /// Unix socket path to connect to.
    Unix(String),
}

impl Upstream {
    /// Connect to upstream.
    pub(crate) async fn connect(&self) -> Result<RelayConn> {
        match self {
            Self::SocketAddr(addr) => {
                let stream = TcpStream::connect(addr)
                    .await
                    .context("Connect upstream error")?;
                Ok(RelayConn::Tcp(stream))
            }
            #[cfg(unix)]
            Self::Unix(path) => {
                let stream = UnixStream::connect(path)
                    .await
                    .context("Connect upstream error")?;
                Ok(RelayConn::Unix(stream))
            }
        }
        .map(RelayConn::apply_socket_conf)
    }

    /// Parse string to [Upstream], for [clap].
    pub(crate) fn parse(s: &str) -> Result<Self> {
        #[allow(unused_variables, reason = "cfg")]
        if let Some(unix_path) = s.strip_prefix("unix:") {
            #[cfg(unix)]
            return Ok(Upstream::Unix(unix_path.to_string()));
            #[cfg(not(unix))]
            bail!("Unix socket path is not supported on this platform");
        } else {
            s.parse()
                .map(Upstream::SocketAddr)
                .context("Invalid socket addr")
        }
    }

    pub(crate) fn parse_with_delimiter(s: &str) -> Result<(Arc<str>, Self)> {
        let (sni, upstream) = s
            .split_once(':')
            .context("Invalid upstream delimiter, see help for more details")?;

        Ok((sni.into(), Upstream::parse(upstream)?))
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketAddr(addr) => write!(f, "{}", addr),
            #[cfg(unix)]
            Self::Unix(path) => write!(f, "unix:{}", path),
        }
    }
}

impl serde::Serialize for Upstream {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Upstream::SocketAddr(addr) => addr.to_string().serialize(serializer),
            #[cfg(unix)]
            Upstream::Unix(path) => format!("unix:{}", path).serialize(serializer),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Upstream {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let string = String::deserialize(deserializer)?;

        #[allow(unused_variables, reason = "cfg")]
        if let Some(unix_path) = string.strip_prefix("unix:") {
            #[cfg(unix)]
            return Ok(Upstream::Unix(unix_path.to_string()));
            #[cfg(not(unix))]
            return Err(D::Error::custom(
                "Unix socket path is not supported on this platform",
            ));
        } else {
            match string.parse() {
                Ok(addr) => Ok(Upstream::SocketAddr(addr)),
                Err(_) => Err(D::Error::custom(format!(
                    "Invalid upstream `{string}`. See help for more details"
                ))),
            }
        }
    }
}
