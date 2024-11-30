//! Error type

#[derive(Debug, Clone, thiserror::Error)]
/// Error types
pub(crate) enum Error {
    #[error("Invalid TLS client hello: {0}")]
    ClientHello(&'static str),

    #[error("Invalid config: {0}")]
    Config(&'static str),
}
