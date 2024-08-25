use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, LazyLock,
    },
    time::Duration,
};

use tokio::{
    net::{TcpListener, TcpSocket},
    time::sleep,
};

use crate::get_args;

/// The version of the server.
pub const VERSION: &str = concat!("v", include_str!(concat!(env!("OUT_DIR"), "/VERSION")));
/// The version of the server.
pub const BUILD_TIME: &str = include_str!(concat!(env!("OUT_DIR"), "/BUILD_TIME"));

pub static KEEP_ALIVE_CONF: LazyLock<socket2::TcpKeepalive> = LazyLock::new(|| {
    socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(15))
});

/// Initialize tracing subscriber.
pub fn init_tracing() {
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

/// Create a listener with the given address.
pub fn create_listener() -> io::Result<TcpListener> {
    let addr = {
        let args = get_args!();
        args.listen.unwrap()
    };

    let socket = match &addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };

    // Setting with socket2
    crate::apply_socket_conf!(&socket);

    socket.bind(addr)?;

    socket.listen(4096)
}

#[macro_export]
/// Apply socket configurations to the given stream.
///
/// - [socket2::SockRef::set_cloexec](socket2::SockRef::set_cloexec): true
/// - [socket2::SockRef::set_tcp_keepalive](socket2::SockRef::set_tcp_keepalive): 15s interval and 15s timeout
/// - [socket2::SockRef::set_nodelay](socket2::SockRef::set_nodelay): true
/// - [socket2::SockRef::set_nonblocking](socket2::SockRef::set_nonblocking): true
macro_rules! apply_socket_conf {
    ($socket:expr) => {{
        let sock_ref = socket2::SockRef::from($socket);

        #[cfg(unix)]
        let _ = sock_ref.set_cloexec(true);
        let _ = sock_ref.set_tcp_keepalive(&$crate::utils::KEEP_ALIVE_CONF);
        let _ = sock_ref.set_nodelay(true);
        let _ = sock_ref.set_nonblocking(true);
    }};
}

#[derive(Debug, Clone)]
/// Conn counter
pub struct ConnCounter {
    inner: Arc<AtomicUsize>,
}

impl ConnCounter {
    #[inline]
    /// Create a new [ConnCounter].
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[inline]
    /// Increment the connection counter.
    pub fn conn_established(&self) {
        self.inner.fetch_add(1, Ordering::AcqRel);
    }

    #[inline]
    /// Wait for all connections to be closed or force exit after the given duration.
    ///
    /// Default to wait for 15 sec
    pub async fn wait_conn_end(&self, force: Option<Duration>) {
        tokio::select! {
            biased;
            _ = async {
                while self.inner.load(Ordering::Acquire) > 0 {
                    sleep(Duration::from_millis(300)).await;
                }
            } => {},
            _ = sleep(force.unwrap_or(Duration::from_secs(15))) => {
                tracing::warn!("Gracefully shutdown time limit exceeded");
            }
        }
    }
}

impl Drop for ConnCounter {
    fn drop(&mut self) {
        self.inner.fetch_sub(1, Ordering::AcqRel);
    }
}
