//! Peek the first few bytes of a TCP stream to determine the protocol.

mod utils;

use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::TcpStream;

use crate::error::Error;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_FIXED_HEADER_LENGTH: usize = 43;
const TLS_HANDSHAKE_EXT_TYPE_SERVER_NAME: u16 = 0x00;

#[tracing::instrument(level = "debug", ret)]
pub(crate) async fn peek_with_timeout(
    incoming: &mut TcpStream,
    timeout: Option<Duration>,
) -> Result<Peeked> {
    tokio::time::timeout(timeout.unwrap_or(DEFAULT_TIMEOUT), peek(incoming))
        .await
        .context(Error::Peek("Timeout"))
        .flatten()
}

#[tracing::instrument(level = "debug", ret)]
async fn peek(incoming: &mut TcpStream) -> Result<Peeked> {
    let mut sniffed_header = [0u8; 12];

    incoming.peek(&mut sniffed_header).await?;

    let tls_client_hello_length = match sniffed_header {
        [
            0x16,
            0x03,
            0x01,
            _,
            _,
            TLS_HANDSHAKE_TYPE_CLIENT_HELLO,
            l_x,
            l_y,
            l_z,
            ..,
        ] => u32::from_be_bytes([0, l_x, l_y, l_z]) as usize + 9,
        [0x16, ..] => {
            tracing::debug!("Invalid TLS packet: {sniffed_header:?}");

            bail!(Error::Peek("Invalid TLS packet"))
        }
        [b'S', b'S', b'H', b'-', ..] => {
            return Ok(Peeked::Ssh);
        }
        [b'P', b'R', b'O', b'X', b'Y', ..] | [13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10] => {
            return Ok(Peeked::Proxy);
        }
        [b'G', b'E', b'T', b' ', ..]
        | [b'P', b'O', b'S', b'T', b' ', ..]
        | [b'P', b'U', b'T', b' ', ..]
        | [b'H', b'E', b'A', b'D', b' ', ..]
        | [b'D', b'E', b'L', b'E', b'T', b'E', b' ', ..]
        | [b'O', b'P', b'T', b'I', b'O', b'N', b'S', b' ', ..]
        | [b'P', b'A', b'T', b'C', b'H', b' ', ..]
        | [b'C', b'O', b'N', b'N', b'E', b'C', b'T', b' ', ..]
        | [b'T', b'R', b'A', b'C', b'E', b' ', ..] => {
            return Ok(Peeked::MaybeHttp);
        }
        _ => return Ok(Peeked::Unknown),
    };

    let mut reader = utils::ReaderExt::new(tls_client_hello_length);

    let mut need_peek_more = true;
    let mut can_peek_more = true;
    let mut peek_more_count = 0;
    let mut target_additional = None;
    let mut state = State::First43Bytes;

    loop {
        if need_peek_more && can_peek_more {
            tracing::debug!(
                ?state,
                need_peek_more,
                can_peek_more,
                peek_more_count,
                ?target_additional,
                "Peeking more data"
            );

            let has_more = reader
                .fill_more_data(
                    incoming,
                    target_additional.unwrap_or_else(|| 256 + peek_more_count * 128),
                )
                .await?;

            peek_more_count += 1;
            can_peek_more = has_more;
        }

        match state {
            State::First43Bytes => {
                if reader.skip(TLS_HANDSHAKE_FIXED_HEADER_LENGTH).is_some() {
                    state = State::SessionID;
                } else if can_peek_more {
                    need_peek_more = true;
                } else {
                    tracing::debug!(
                        ?state,
                        need_peek_more,
                        can_peek_more,
                        peek_more_count,
                        ?target_additional,
                        "Invalid TLS packet: {reader:?}"
                    );

                    bail!(Error::ClientHello("Invalid TLS packet"));
                }
            }
            State::SessionID => {
                if reader.read_payload_u8().is_ok() {
                    state = State::CipherSuites;
                } else if can_peek_more {
                    need_peek_more = true;
                } else {
                    tracing::debug!(
                        ?state,
                        need_peek_more,
                        can_peek_more,
                        peek_more_count,
                        ?target_additional,
                        "Invalid TLS packet: {reader:?}"
                    );

                    bail!(Error::ClientHello("Invalid TLS packet"));
                }
            }
            State::CipherSuites => {
                if reader.read_payload_u16().is_ok() {
                    state = State::Compression;
                } else if can_peek_more {
                    need_peek_more = true;
                } else {
                    tracing::debug!(
                        ?state,
                        need_peek_more,
                        can_peek_more,
                        peek_more_count,
                        ?target_additional,
                        "Invalid TLS packet: {reader:?}"
                    );

                    bail!(Error::ClientHello("Invalid TLS packet"));
                }
            }
            State::Compression => {
                if let Ok(data) = reader.read_payload_u8() {
                    if data != [0x00] {
                        tracing::error!("Invalid compression: {data:x?}");
                        bail!(Error::ClientHello("Invalid compression"))
                    }

                    state = State::ExtensionsLength;
                } else if can_peek_more {
                    need_peek_more = true;
                } else {
                    tracing::debug!(
                        ?state,
                        need_peek_more,
                        can_peek_more,
                        peek_more_count,
                        ?target_additional,
                        "Invalid TLS packet: {reader:?}"
                    );

                    bail!(Error::ClientHello("Invalid TLS packet"));
                }
            }
            State::ExtensionsLength => {
                if let Some(data) = reader.read_u16() {
                    // TODO: Add summary here?

                    // F**king Chromium, the ServerName might be located very far back in the
                    // Extensions.
                    target_additional = Some(data as usize / 4);

                    state = State::Extensions;
                } else if can_peek_more {
                    need_peek_more = true;
                } else {
                    tracing::debug!(
                        ?state,
                        need_peek_more,
                        can_peek_more,
                        peek_more_count,
                        ?target_additional,
                        "Invalid TLS packet: {reader:?}"
                    );

                    bail!(Error::ClientHello("Invalid TLS packet"));
                }
            }
            State::Extensions => {
                let extension_type = if let Some(extension_type) = reader.read_u16() {
                    extension_type
                } else if can_peek_more {
                    need_peek_more = true;
                    continue;
                } else {
                    tracing::debug!(
                        ?state,
                        need_peek_more,
                        can_peek_more,
                        peek_more_count,
                        ?target_additional,
                        "Invalid TLS packet: {reader:?}"
                    );

                    bail!(Error::ClientHello("Invalid TLS packet"));
                };

                if extension_type == TLS_HANDSHAKE_EXT_TYPE_SERVER_NAME {
                    match reader.read_payload_u16() {
                        Ok(data) => {
                            if let &[_, _, 0x00, l_x, l_y, ..] = data {
                                tracing::debug!("Found SNI extension");

                                let len = u16::from_be_bytes([l_x, l_y]) as usize;

                                if let Some(host_name) = data
                                    .get(9..len + 9)
                                    .and_then(|data| String::from_utf8(data.to_vec()).ok())
                                {
                                    tracing::debug!(
                                        "Extension::ServerName found, host_name: {host_name}"
                                    );

                                    return Ok(Peeked::Tls {
                                        host_name: Some(host_name),
                                        maybe_reality: false,
                                    });
                                }
                            }
                        }
                        Err(Some(utils::IncompletePayload { len, payload })) => match payload {
                            &[l_x, l_y, ..] => {
                                target_additional = Some(u16::from_be_bytes([l_x, l_y]) as usize);
                            }
                            _ => target_additional = Some(len),
                        },
                        Err(None) => {
                            target_additional = Some(const { u8::MAX as usize + 7 });
                        }
                    }

                    if can_peek_more {
                        need_peek_more = true;
                    } else {
                        tracing::debug!(
                            ?state,
                            need_peek_more,
                            can_peek_more,
                            peek_more_count,
                            ?target_additional,
                            "Extension::ServerName found, but no more data"
                        );

                        return Ok(Peeked::Tls {
                            host_name: None,
                            maybe_reality: false,
                        });
                    }
                } else {
                    tracing::debug!("Found other extension: {extension_type:x?}");
                    if reader.read_payload_u16().is_ok() {
                        // no-op
                    } else if can_peek_more {
                        need_peek_more = true;
                    } else {
                        tracing::debug!(
                            ?state,
                            need_peek_more,
                            can_peek_more,
                            peek_more_count,
                            ?target_additional,
                            "SNI extension not found, but no more data"
                        );

                        return Ok(Peeked::Tls {
                            host_name: None,
                            maybe_reality: false,
                        });
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    /// First fixed 43 bytes.
    ///
    /// - content type (1 byte)
    /// - version (2 bytes)
    /// - length (2 bytes)
    /// - handshake type (1 byte), must be `ClientHello` (we have checked)
    /// - left length (3 bytes)
    /// - version (2 bytes)
    /// - random (32 bytes)
    First43Bytes,

    /// Session ID (1 + 32 bytes usually)
    SessionID,

    /// Cipher suites (2 + 64 bytes usually?)
    CipherSuites,

    /// Compression (1 + 1 bytes usually)
    Compression,

    /// `ExtensionsLength`, 2 bytes
    ExtensionsLength,

    /// Extension, type (2 bytes) + length (2 bytes) + data (dynamic bytes)
    Extensions,
}

#[derive(Debug, Default, Clone)]
/// The result of the peek operation.
pub(crate) enum Peeked {
    /// TLS initial connection
    Tls {
        /// Optional SNI
        host_name: Option<String>,

        #[allow(dead_code, reason = "not used yet")]
        /// Maybe a REALITY connection
        maybe_reality: bool,
    },

    /// Plain HTTP connection
    MaybeHttp,

    /// SSH connection, connect to current machine?
    Ssh,

    /// PROXY protocol v3?, need further parsing.
    Proxy,

    #[default]
    /// Unknown connection, drop it?
    Unknown,
}
