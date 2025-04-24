//! Some utils

use std::{cmp::min, hint::unreachable_unchecked};

use anyhow::{Result, bail};
use tokio::net::TcpStream;

use crate::error::Error;

#[derive(Debug)]
/// Wrapper over a slice of bytes that allows reading chunks from
/// with the current position state held using a cursor.
///
/// A new reader for a sub section of the buffer can be created
/// using the `sub` function or a section of a certain length can
/// be obtained using the `take` function
pub(super) struct ReaderExt {
    /// The underlying buffer storing the readers content
    buffer: Vec<u8>,
    /// Stores the current reading position for the buffer
    cursor: usize,
    /// Maximum size of the buffer
    maximum: usize,
}

impl ReaderExt {
    /// Creates a new Reader of the provided `bytes` slice with
    /// the initial cursor position of zero.
    pub(super) const fn new(maximum: usize) -> Self {
        Self {
            buffer: Vec::new(),
            cursor: 0,
            maximum,
        }
    }

    #[tracing::instrument(level = "debug", skip_all, err)]
    /// Peek and fill the buffer.
    pub(super) async fn fill_more_data(
        &mut self,
        stream: &mut TcpStream,
        additional: usize,
    ) -> Result<bool> {
        let current_length = self.buffer.len();

        // check if we have peeked enough data
        if current_length >= self.maximum {
            return Ok(false);
        }

        self.buffer.reserve(additional);

        #[allow(unsafe_code, reason = "will set actual len later")]
        unsafe {
            let target_length = min(current_length + additional, self.maximum);
            self.buffer.set_len(target_length);
        }

        let has_peeked = stream.peek(&mut self.buffer).await?;

        // peek will return the same content as has peeked one
        debug_assert!(has_peeked >= current_length);

        if has_peeked <= current_length {
            bail!(Error::Peek("No more data peeked"))
        } else {
            #[allow(unsafe_code, reason = "set actual len")]
            unsafe {
                self.buffer.set_len(has_peeked);
            }
        }

        Ok(true)
    }

    #[inline]
    /// Read single byte from the buffer and move the cursor if success.
    pub(super) fn read_u8(&mut self) -> Option<u8> {
        let data = self.buffer.get(self.cursor).copied()?;

        self.cursor += 1;

        Some(data)
    }

    #[inline]
    /// Read 2 bytes as u16 from the buffer and move the cursor if success.
    pub(super) fn read_u16(&mut self) -> Option<u16> {
        let data = self
            .buffer
            .get(self.cursor..self.cursor + 2)?
            .as_array::<2>()
            .map(|&b| u16::from_be_bytes(b))
            .unwrap_or_else(|| {
                #[allow(unsafe_code, reason = "must be 2 bytes")]
                unsafe {
                    unreachable_unchecked()
                }
            });

        self.cursor += 2;

        Some(data)
    }

    #[inline]
    /// Read a slice of bytes from the buffer and move the cursor if success.
    /// The length of the slice is read from the first two bytes as a `u8`.
    pub(super) fn read_payload_u8(&mut self) -> Result<&[u8], Option<IncompletePayload<'_>>> {
        let length = self.read_u8().ok_or(None)? as usize;

        let payload = self.buffer.get(self.cursor..self.cursor + length);

        match payload {
            Some(payload) => {
                self.cursor += length;

                Ok(payload)
            }
            None => {
                // Reset the current cursor to the start of the payload (length info)
                self.cursor -= 1;

                Err(Some(IncompletePayload {
                    len: length,
                    payload: self.buffer.get(self.cursor..).unwrap_or(&[]),
                }))
            }
        }
    }

    #[inline]
    /// Read a slice of bytes from the buffer and move the cursor if success.
    /// The length of the slice is read from the first two bytes as a `u16`.
    pub(super) fn read_payload_u16(&mut self) -> Result<&[u8], Option<IncompletePayload<'_>>> {
        let length = self.read_u16().ok_or(None)? as usize;

        let payload = self.buffer.get(self.cursor..self.cursor + length);

        match payload {
            Some(payload) => {
                self.cursor += length;

                Ok(payload)
            }
            None => {
                // Reset the current cursor to the start of the payload (length info)
                self.cursor -= 2;

                Err(Some(IncompletePayload {
                    len: length,
                    payload: self.buffer.get(self.cursor..).unwrap_or(&[]),
                }))
            }
        }
    }

    pub(super) fn skip(&mut self, length: usize) -> Option<()> {
        let new_cursor = self.cursor + length;

        if new_cursor > self.buffer.len() {
            return None;
        }

        self.cursor = new_cursor;

        Some(())
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct IncompletePayload<'a> {
    pub len: usize,
    pub payload: &'a [u8],
}
