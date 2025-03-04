//! TLS `ClientHello` peeker
//!
//! - [*] TCP
//! - [ ] UDP(QUIC)

mod utils;

use std::{cmp::min, hint::unreachable_unchecked, pin::Pin};

use anyhow::{Context, Result, bail};
use rustls::{
    CipherSuite, InvalidMessage, ProtocolVersion,
    internal::msgs::{codec::Codec, enums::Compression, handshake},
};
use tokio::net::TcpStream;

use crate::error::Error;

#[derive(Debug)]
pub(crate) struct TcpStreamPeeker<'tcp> {
    inner: &'tcp mut TcpStream,

    // buffer for peeking
    buffer: utils::ReaderExt,

    // stats
    /// Bytes that we have peeked.
    bytes_has_been_peeked: usize,
    /// Maximum bytes that we may peek.
    bytes_in_total: usize,
}

impl<'tcp> TcpStreamPeeker<'tcp> {
    #[inline]
    /// Create a new [`TcpStreamPeeker`];
    pub(crate) const fn new(inner: &'tcp mut TcpStream) -> Self {
        Self {
            inner,
            buffer: utils::ReaderExt::new(),
            bytes_has_been_peeked: 0,
            bytes_in_total: 0,
        }
    }

    #[inline]
    #[tracing::instrument(level = "debug", skip_all, err)]
    /// Peeking more.
    ///
    /// If `reset_reader`, the new reader's cursor will be set to the last one,
    /// or the current one.
    async fn peeking_more(self: Pin<&mut Self>, is_retry: bool) -> Result<()> {
        let this = self.get_mut();

        // check if we have peeked enough data
        if this.bytes_has_been_peeked >= this.bytes_in_total {
            bail!(Error::Peek("No more possible data"))
        }

        let buffer = {
            let target_len = min(this.bytes_has_been_peeked + 256, this.bytes_in_total);
            this.buffer.as_mut_slice(target_len)
        };

        // peek data
        let peeked = this
            .inner
            .peek(buffer)
            .await
            .context(Error::Peek("No more possible data"))?;

        // set data that has peeked.
        {
            if this.bytes_has_been_peeked == peeked {
                bail!(Error::Peek("No more data peeked?"))
            } else {
                this.bytes_has_been_peeked = peeked;
                this.buffer.update_buffer(peeked, is_retry);
            }
        }

        Ok(())
    }

    #[inline]
    #[tracing::instrument(level = "debug")]
    /// Try recover from parsing error.
    ///
    /// If no error is returned, just retry and the reader's cursor has been
    /// reset to the last one.
    async fn try_recover_from_parsing_error(
        self: Pin<&mut Self>,
        field_name: &'static str,
        error: InvalidMessage,
    ) -> Result<()> {
        match &error {
            InvalidMessage::MessageTooShort | InvalidMessage::MissingData(_) => {
                tracing::trace!("Insufficient data, try peeking more");

                self.peeking_more(true).await
            }
            _ => {
                tracing::error!("Unrecoverable error");

                Err(Error::ClientHello("invalid packet").into())
            }
        }
    }

    async fn read<T>(mut self: Pin<&mut Self>, field_name: &'static str) -> Result<T>
    where
        T: for<'a> Codec<'a>,
    {
        match T::read(self.buffer.reader()) {
            Ok(data) => Ok(data),
            Err(e) => {
                self.as_mut()
                    .try_recover_from_parsing_error(field_name, e)
                    .await?;

                Box::pin(self.read(field_name)).await
            }
        }
    }

    #[inline]
    #[tracing::instrument(level = "debug", skip(self), err)]
    /// Peek the inner TCP stream (maybe TLS stream), write SNI to given buffer
    /// and return the peeked SNI.
    pub(crate) async fn peek_sni(mut self) -> Result<PeekedSni<impl AsRef<str> + use<>>> {
        // content type (1 byte) + version (2 bytes) + length (2 bytes) + handshake type
        // (1 byte) + length (3 bytes)
        let mut first_9_bytes_buffer = [0u8; 9];
        self.inner
            .peek(&mut first_9_bytes_buffer)
            .await
            .context(Error::Peek("no first 9 bytes"))?;

        if first_9_bytes_buffer[0] != 0x16 {
            return Ok(PeekedSni::NotHTTPS);
        }

        if first_9_bytes_buffer[5] != 0x01 {
            bail!(Error::Peek("invalid handshake packet: not ClientHello"))
        }

        // version (1 byte) + random (32 bytes) + session id (dynamic, 1 + 32 bytes
        // usually) + cipher suites (dynamic, 1 + 64 bytes usually?) + compression (1 +
        // 1 bytes) + extensions (1 + 1024 bytes?)
        let leftover_bytes_length = u32::from_be_bytes([
            0,
            first_9_bytes_buffer[6],
            first_9_bytes_buffer[7],
            first_9_bytes_buffer[8],
        ]) as usize;

        #[allow(unsafe_code, reason = "tokio::pin")]
        let mut this = unsafe { Pin::new_unchecked(&mut self) };

        // init buffer and cursor
        {
            this.bytes_has_been_peeked = 9;
            this.bytes_in_total = leftover_bytes_length + 9;

            this.as_mut().peeking_more(false).await?;

            this.buffer
                .set_cursor(9)
                .expect("must have over 9 bytes peeked");
        }

        macro_rules! read {
            ($ty:ty) => {{ this.as_mut().read::<$ty>(stringify!($ty)).await? }};
        }

        let _ = read!(ProtocolVersion);
        let _ = read!(handshake::Random);
        let _ = read!(handshake::SessionId);
        let _ = read!(Vec::<CipherSuite>);

        let compressions = read!(Vec::<Compression>);
        if compressions.first() != Some(&Compression::Null) {
            tracing::error!("Invalid compressions: {compressions:x?}");
            bail!(Error::ClientHello("invalid compression"));
        }

        // read extensions
        let _len = read!(u16);
        while this.as_mut().buffer.reader().any_left() {
            let extension = read!(handshake::ClientExtension);
            tracing::trace!("Found extension: {:?}", extension.ext_type());
            // Avoid clone here? Emmm troublesome.
            if let handshake::ClientExtension::ServerName(mut server_names) = extension {
                let idx = server_names
                    .iter()
                    .position(|server_name| {
                        matches!(
                            server_name.get_payload(),
                            handshake::ServerNamePayload::HostName(_)
                        )
                    })
                    .ok_or_else(|| {
                        tracing::error!(
                            "Invalid SNI extension though SNI extension found: {server_names:#?}"
                        );

                        Error::ClientHello("Invalid SNI extension")
                    })?;

                // `swap_remove` is O(1) operation
                return match server_names.swap_remove(idx).into_payload() {
                    handshake::ServerNamePayload::HostName(host_name) => {
                        Ok(PeekedSni::Some(host_name))
                    }
                    _ => {
                        #[allow(unsafe_code, reason = "have checked the item located at the idx")]
                        unsafe {
                            unreachable_unchecked()
                        }
                    }
                };
            }
        }

        Ok(PeekedSni::None)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) enum PeekedSni<T> {
    /// SNI is peeked.
    Some(T),

    #[default]
    /// SNI not found.
    None,

    /// Not HTTPS connection at all.
    NotHTTPS,
}
