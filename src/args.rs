use std::net::SocketAddr;

use clap::Parser;

use crate::utils::Upstream;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(default_value_t = SocketAddr::from(([0, 0, 0, 0], 443)), short, long)]
    /// Local socket addr to bind to, default to be 0.0.0.0:443
    pub listen: SocketAddr,

    #[arg(long, value_parser = Upstream::parse)]
    /// Default upstream like `nginx` to connect to.
    ///
    /// Notice: Unix socket path is only available on Unix platforms and must be prefixed with `unix:`.
    ///
    /// Example: `--default-upstream unix:/path/to/unix.sock` or `--upstream 0.0.0.0:443"
    pub default_upstream: Upstream,

    #[arg(long, value_delimiter = ',', required = true)]
    /// If any of `target_host`s is detected in incoming TLS stream SNI, the underlying
    /// connection will be forwarded to the corresponding `target_upstream`.
    pub target_host: Vec<String>,

    #[arg(long, value_parser = Upstream::parse)]
    /// Target upstream to connect to when incoming TLS stream's SNI matches any of `target_host`s.
    pub target_upstream: Upstream,
}
