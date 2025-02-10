//! `TcpStream` with peek.

use std::ops;

use anyhow::{Context, Result, bail};
use tokio::net::TcpStream;

use crate::error::Error;

#[allow(dead_code, reason = "testing new peeker")]
#[derive(Debug)]
pub(crate) struct PeekedTcpStream<'tcp>(&'tcp mut TcpStream);

impl ops::Deref for PeekedTcpStream<'_> {
    type Target = TcpStream;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl ops::DerefMut for PeekedTcpStream<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

#[allow(dead_code, reason = "testing new peeker")]
impl<'tcp> PeekedTcpStream<'tcp> {
    #[inline]
    pub(crate) const fn new(tcp_stream: &'tcp mut TcpStream) -> Self {
        Self(tcp_stream)
    }

    #[inline]
    /// Peek the inner TCP stream (maybe TLS stream), write SNI to given buffer
    /// and return the peeked SNI' length.
    pub(crate) async fn peek_sni(mut self, sni_buf: &mut [u8; 256]) -> Result<Option<usize>> {
        if self.peek_slice::<1>().await?[0] != 0x16 {
            return Ok(None);
        }

        // ! The typical size of TLS client hello is 252 bytes.
        // !
        // ! However, X25519Kyber768Draft00 relies on the TLS key_share extension,
        // ! causing the size of the TLS Client Hello sent during the TLS
        // ! handshake with the built-in TLS implementation of Go 1.23 to increase
        // ! from the typical 252 bytes to 1476 bytes.
        let buf = self.peek_slice::<256>().await?;

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
                1 => &self.peek_slice::<1536>().await?[..],
                2 => &self.peek_slice::<2048>().await?[..],
                3 => &self.peek_slice::<3072>().await?[..],
                4 => &self.peek_slice::<4096>().await?[..],
                _ => bail!(Error::ClientHello("too long")),
            };

            let mut sni_length = None;

            while sni_length.is_none()
                && let Some(extension_prefix) = buf.get(cursor..cursor + 4)
            {
                let extension_length =
                    u16::from_be_bytes([extension_prefix[2], extension_prefix[3]]) as usize;

                if extension_prefix[0..2] == [0x00, 0x00] {
                    tracing::debug!("Ext `server_name` found at byte cursor {cursor}.");

                    // ! | Server name | bytes of "server name" extension data follows |
                    // ! | 00 00       | XX XX                                         |
                    // ! | bytes of first list entry follows | list entry type |
                    // ! | XX XX                             | 00              |
                    // ! | bytes of hostname follows |
                    // ! | XX XX                     |
                    cursor += 7;

                    sni_length = get_bytes!(2, THEN: hostname_prefix => {
                        Some(u16::from_be_bytes([hostname_prefix[0], hostname_prefix[1]]) as usize)
                    });

                    break;
                }

                cursor += 4;
                cursor += extension_length;
            }

            if let Some(sni_length) = sni_length {
                sni_buf
                    .get_mut(..sni_length)
                    .context(Error::ClientHello("SNI too long"))?
                    .copy_from_slice(&buf[cursor..cursor + sni_length]);

                return Ok(Some(sni_length));
            } else {
                tracing::warn!("SNI not found, try peeking more...");

                retry_count += 1;
            }
        }
    }

    #[inline(always)]
    async fn peek_slice<const BUF_LEN: usize>(&mut self) -> Result<[u8; BUF_LEN]> {
        let mut buf = [0u8; BUF_LEN];

        self.peek(&mut buf)
            .await
            .map(move |_| buf)
            .context(Error::Peek("Peek"))
    }
}
