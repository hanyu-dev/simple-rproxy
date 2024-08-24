use std::net::SocketAddr;

use anyhow::Result;

/// The version of the server.
pub static VERSION: &str = concat!("v", include_str!(concat!(env!("OUT_DIR"), "/VERSION")));
/// The version of the server.
pub static BUILD_TIME: &str = include_str!(concat!(env!("OUT_DIR"), "/BUILD_TIME"));

#[derive(Debug, Clone, Copy)]
/// Upstream to connect to.
pub enum Upstream {
    /// Upstream addr to connect to.
    SocketAddr(SocketAddr),

    #[allow(dead_code)]
    /// Unix socket path to connect to.
    Unix(&'static str),
}

impl Upstream {
    /// Parse string to [Upstream].
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(unix_path) = s.strip_prefix("unix:") {
            Ok(Upstream::Unix(Box::leak(
                unix_path.to_string().into_boxed_str(),
            )))
        } else {
            match s.parse() {
                Ok(addr) => Ok(Upstream::SocketAddr(addr)),
                Err(_) => Err("Invalid upstream. See help for more details".to_string()),
            }
        }
    }
}
