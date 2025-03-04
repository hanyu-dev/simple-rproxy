//! Utilities

pub(crate) mod proxy_protocol;

use std::{
    fmt, io,
    net::SocketAddr,
    str::FromStr,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
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

    #[cfg(feature = "feat-tokio-debug")]
    let console_layer = console_subscriber::spawn();

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_timer(ChronoLocal::rfc_3339())
        .with_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        );

    #[cfg(feature = "feat-tokio-debug")]
    tracing_subscriber::registry()
        .with(console_layer)
        .with(fmt_layer)
        .init();

    #[cfg(not(feature = "feat-tokio-debug"))]
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
    // socket.set_reuseport(true)?;

    socket.bind(addr)?;

    tracing::info!(
        "Listener socket initialized, buffer size is r[{}]/w[{}]",
        socket.recv_buffer_size().unwrap_or_default(),
        socket.send_buffer_size().unwrap_or_default()
    );

    socket.listen(65536)
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
    ($socket:expr) => {{
        let sock_ref = socket2::SockRef::from($socket);

        #[cfg(unix)]
        let _ = sock_ref.set_cloexec(true);
        let _ = sock_ref.set_tcp_keepalive(&$crate::utils::KEEP_ALIVE_CONF);
        let _ = sock_ref.set_nodelay(true);
        let _ = sock_ref.set_nonblocking(true);
        if let Some(ip_tos) = *($crate::config::ADV_IP_TOS) {
            let _ = sock_ref.set_tos(ip_tos);
        }
    }};
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Upstream to connect to.
enum UpstreamAddr {
    /// Upstream addr to connect to.
    SocketAddr(SocketAddr),

    #[cfg(unix)]
    /// Unix socket path to connect to.
    Unix(String),
}

#[derive(Debug, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
/// Upstream configuration.
pub(crate) struct Upstream {
    /// Upstream addr to connect to.
    addr: UpstreamAddr,

    /// Proxy protocol to use.
    pub(crate) proxy_protocol: bool,
}

impl From<SocketAddr> for Upstream {
    fn from(addr: SocketAddr) -> Self {
        Upstream {
            addr: UpstreamAddr::SocketAddr(addr),
            proxy_protocol: false,
        }
    }
}

impl Upstream {
    /// Set proxy protocol to use.
    pub(crate) fn set_proxy_protocol(mut self, proxy_protocol: bool) -> Self {
        self.proxy_protocol = proxy_protocol;
        self
    }

    /// Connect to upstream.
    pub(crate) async fn connect(&self) -> Result<RelayConn> {
        match &self.addr {
            UpstreamAddr::SocketAddr(addr) => {
                let dest = TcpStream::connect(addr)
                    .await
                    .context("Connect upstream error")?;
                Ok(RelayConn::Tcp {
                    dest,
                    proxy_protocol: self.proxy_protocol,
                })
            }
            #[cfg(unix)]
            UpstreamAddr::Unix(path) => {
                let dest = UnixStream::connect(path)
                    .await
                    .context("Connect upstream error")?;
                Ok(RelayConn::Unix {
                    dest,
                    proxy_protocol: self.proxy_protocol,
                })
            }
        }
        .map(RelayConn::apply_socket_conf)
    }

    /// Parse string to [Upstream], for [clap].
    pub(crate) fn parse(arg: &str) -> Result<Self> {
        let (proxy_protocol, addr_string) = arg
            .split_once('@')
            .map(|(proxy_protocol, addr)| (proxy_protocol == "PROXY_PROTOCOL_V2", addr))
            .unwrap_or((false, arg));

        #[allow(unused_variables, reason = "cfg")]
        if let Some(unix_path) = addr_string.strip_prefix("unix:") {
            #[cfg(unix)]
            return Ok(Upstream {
                addr: UpstreamAddr::Unix(unix_path.to_string()),
                proxy_protocol,
            });
            #[cfg(not(unix))]
            bail!("Unix socket path is not supported on this platform");
        } else {
            Ok(Upstream {
                addr: addr_string
                    .parse()
                    .map(UpstreamAddr::SocketAddr)
                    .context("Invalid socket addr")?,
                proxy_protocol,
            })
        }
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.proxy_protocol {
            write!(f, "PROXY_PROTOCOL_V2@")?;
        }
        match &self.addr {
            UpstreamAddr::SocketAddr(addr) => write!(f, "{}", addr),
            #[cfg(unix)]
            UpstreamAddr::Unix(path) => write!(f, "unix:{}", path),
        }
    }
}

impl serde::Serialize for UpstreamAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            UpstreamAddr::SocketAddr(addr) => addr.to_string().serialize(serializer),
            #[cfg(unix)]
            UpstreamAddr::Unix(path) => format!("unix:{}", path).serialize(serializer),
        }
    }
}

impl<'de> serde::Deserialize<'de> for UpstreamAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let string = String::deserialize(deserializer)?;

        #[allow(unused_variables, reason = "cfg")]
        if let Some(unix_path) = string.strip_prefix("unix:") {
            #[cfg(unix)]
            return Ok(UpstreamAddr::Unix(unix_path.to_string()));
            #[cfg(not(unix))]
            return Err(D::Error::custom(
                "Unix socket path is not supported on this platform",
            ));
        } else {
            match string.parse() {
                Ok(addr) => Ok(UpstreamAddr::SocketAddr(addr)),
                Err(_) => Err(D::Error::custom(format!(
                    "Invalid upstream `{string}`. See help for more details"
                ))),
            }
        }
    }
}

#[derive(Debug, Clone)]
/// Upstream argument.
pub(crate) struct UpstreamArg {
    /// SNI part
    pub sni: Arc<str>,

    /// Upstream to connect to.
    pub upstream: Arc<Upstream>,
}

impl FromStr for UpstreamArg {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (sni, upstream) = s
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("Invalid upstream argument"))?;

        if sni.is_empty() {
            bail!("SNI cannot be empty");
        }

        Ok(UpstreamArg {
            sni: sni.into(),
            upstream: Upstream::parse(upstream)?.into(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
/// Traffic
pub(crate) struct Traffic {
    pub tx: u64,
    pub rx: u64,
}

impl Traffic {
    /// Create [`Traffic`] from [`AtomicTraffic`].
    pub(crate) fn from_atomic(traffic: &AtomicTraffic) -> Self {
        Self {
            tx: traffic.tx.load(Ordering::Relaxed),
            rx: traffic.rx.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
/// Traffic
pub(crate) struct AtomicTraffic {
    pub tx: AtomicU64,
    pub rx: AtomicU64,
}

impl AtomicTraffic {
    /// Create a new [`AtomicTraffic`]
    pub(crate) const fn new(traffic: Traffic) -> Self {
        Self {
            tx: AtomicU64::new(traffic.tx),
            rx: AtomicU64::new(traffic.rx),
        }
    }

    /// fetch and add [`AtomicTraffic`]
    pub(crate) fn fetch_add(&self, traffic: Traffic) {
        self.tx.fetch_add(traffic.tx, Ordering::Relaxed);
        self.rx.fetch_add(traffic.rx, Ordering::Relaxed);
    }
}

#[cfg(unix)]
pub(crate) use unix::*;

#[cfg(unix)]
mod unix {
    use std::{
        fs::{self, File},
        io::{Read, Write},
        ops::{Deref, DerefMut},
        path::Path,
        process,
        sync::Arc,
    };

    use anyhow::{Context, Result, anyhow, bail};

    pub(crate) struct PidFile {
        path: Arc<str>,
        instance: File,
    }

    impl Deref for PidFile {
        type Target = File;

        fn deref(&self) -> &Self::Target {
            &self.instance
        }
    }

    impl DerefMut for PidFile {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.instance
        }
    }

    #[cfg(unix)]
    impl PidFile {
        /// Create a new [`PidFile`].
        pub(crate) fn new(path: Arc<str>) -> Result<Option<Arc<Self>>> {
            let instance = match fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(&*path)
            {
                Ok(mut instance) => {
                    if !instance
                        .try_lock()
                        .inspect_err(|e| {
                            tracing::error!(path = &*path, "Locking pid file error: {e:?}");
                        })
                        .unwrap_or_default()
                    {
                        bail!(
                            "Locking pid file failed, a different lock is already held on this \
                             file, maybe there has already been a running instance?"
                        )
                    };

                    let current_process_id = process::id();

                    // Validate the existing PID
                    {
                        let process_id = {
                            let mut buf = String::new();
                            instance
                                .read_to_string(&mut buf)
                                .context("Read PID file error")?;
                            buf.parse::<u32>().unwrap_or_default()
                        };

                        if process_id != current_process_id
                            && Path::new(&format!("/proc/{process_id}/status")).exists()
                        {
                            bail!("There's another instance running, PID is {process_id}")
                        }
                    }

                    instance
                        .set_len(0)
                        .context("Truncate existing file error")?;
                    instance
                        .write_all(current_process_id.to_string().as_bytes())
                        .expect("must success when writting pid file");

                    instance
                }
                Err(e) => {
                    // TODO: which error id OK?
                    bail!(anyhow!("Read file `{path}` error").context(e))
                }
            };

            Ok(Some(Arc::new(Self { path, instance })))
        }
    }

    impl Drop for PidFile {
        fn drop(&mut self) {
            let _ = self.instance.unlock().inspect_err(|e| {
                eprintln!("Drop pid file: unlock error: {e:#?}");
            });
            let _ = fs::remove_file(&*self.path).inspect_err(|e| {
                eprintln!("Drop pid file: delete error: {e:#?}");
            });
        }
    }
}
