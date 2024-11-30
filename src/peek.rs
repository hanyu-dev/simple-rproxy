//! Peek TLS Stream

use anyhow::{bail, Result};
use tokio::net::TcpStream;

use crate::{config::TARGET_HOSTS, error::Error};

#[derive(Debug, Clone, Copy)]
/// Peek result
pub(crate) enum PeekResult {
    /// The stream is not a HTTPS stream.
    NotHTTPS,

    /// The stream is a TLS stream but not matched any target hosts.
    NotMatched,

    /// The stream is a TLS stream and matched a target host.
    Matched,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Peeker;

impl Peeker {
    #[inline]
    /// Peek the stream (maybe tls stream) and see if it contains any of the
    /// target hosts.
    pub(crate) async fn is_target_host(stream: &mut TcpStream) -> Result<PeekResult> {
        if Self::try_peek::<1>(stream).await[0] != 0x16 {
            return Ok(PeekResult::NotHTTPS);
        }

        let buf = Self::try_peek::<1024>(stream).await;

        let mut cursor = 43usize;

        // Session ID
        cursor += 1 + buf[cursor] as usize;

        macro_rules! get_bytes {
            ($len:expr) => {
                if let Some(bytes) = buf.get(cursor..cursor + $len) {
                    bytes
                } else {
                    bail!(Error::ClientHello("codec error"));
                }
            };
            ($len:expr, THEN: $prefix:ident => $then:block) => {
                if let Some($prefix) = buf.get(cursor..cursor + $len) {
                    cursor += $len;
                    $then
                } else {
                    bail!(Error::ClientHello("codec error"));
                }
            };
            ($len:expr, ADD: $prefix:ident => $then:block) => {
                if let Some($prefix) = buf.get(cursor..cursor + $len) {
                    let content_len = $then;
                    cursor += content_len + $len;
                    content_len
                } else {
                    bail!(Error::ClientHello("codec error"));
                }
            };
        }

        // Cipher Suites
        get_bytes!(2, ADD: cipher_suites_prefix => {
            u16::from_be_bytes([cipher_suites_prefix[0], cipher_suites_prefix[1]]) as usize
        });

        // Compression Methods
        get_bytes!(2, ADD: compression_methods_prefix => {
            if compression_methods_prefix != [0x01, 0x00] {
                tracing::debug!(
                    "Compression method is not null but {:?}",
                    &buf[cursor..cursor + 1]
                );
                bail!(Error::ClientHello("compression method is not null"));
            }
            0
        });

        // Extensions len marker
        get_bytes!(2, THEN: extensions_len_prefix => {
            u16::from_be_bytes([extensions_len_prefix[0], extensions_len_prefix[1]]) as usize
        });

        let mut retry_count = 0;
        loop {
            let buf = match retry_count {
                0 => &buf,
                1 => &Self::try_peek::<1536>(stream).await[..],
                2 => &Self::try_peek::<2048>(stream).await[..],
                3 => &Self::try_peek::<3072>(stream).await[..],
                4 => &Self::try_peek::<4096>(stream).await[..],
                _ => bail!(Error::ClientHello("too long")),
            };

            let sni = Self::find_server_name(&mut cursor, buf)?;

            if sni.is_some_and(|sni| {
                TARGET_HOSTS
                    .get()
                    .expect("TARGET_HOSTS must be inititalized before usage")
                    .load()
                    .contains(sni)
            }) {
                tracing::debug!(
                    "SNI matched target host {}, {retry_count} peek costed.",
                    sni.unwrap()
                );
                return Ok(PeekResult::Matched);
            } else if sni.is_some() {
                tracing::debug!("SNI not matched: {}.", sni.unwrap());
                return Ok(PeekResult::NotMatched);
            } else {
                tracing::debug!("SNI not found. Peeking more.");
                retry_count += 1;
            }
        }
    }

    #[inline(always)]
    async fn try_peek<const BUF_LEN: usize>(stream: &mut TcpStream) -> [u8; BUF_LEN] {
        let mut buf = [0u8; BUF_LEN];

        if let Err(e) = stream.peek(&mut buf).await {
            tracing::error!("Peek failed: {:?}", e);
        };

        buf
    }

    #[inline]
    fn find_server_name<'a>(cursor: &mut usize, bytes: &'a [u8]) -> Result<Option<&'a str>> {
        while let Some(extension_prefix) = bytes.get(*cursor..*cursor + 4) {
            let extension_length =
                u16::from_be_bytes([extension_prefix[2], extension_prefix[3]]) as usize;

            *cursor += 4;

            if extension_prefix[0..2] == [0x00, 0x00] {
                tracing::debug!("Ext `server_name` found.");

                let server_name =
                    bytes
                        .get(*cursor..*cursor + extension_length)
                        .ok_or_else(|| {
                            tracing::error!("Peeked buf is not sufficient: {:02x?}", bytes);

                            Error::ClientHello("failed to get SNI")
                        })?;

                let server_name = server_name.get(5..).unwrap_or_else(|| {
                    if server_name.is_empty() {
                        tracing::debug!("Empty SNI");
                    } else {
                        tracing::warn!("Invalid SNI: {:02x?}", server_name);
                    }
                    &[]
                });

                #[allow(unsafe_code, reason = "Non-UTF-8 SNI is OK")]
                return Ok(Some(unsafe { std::str::from_utf8_unchecked(server_name) }));
            }

            *cursor += extension_length;
        }

        Ok(None)
    }
}
