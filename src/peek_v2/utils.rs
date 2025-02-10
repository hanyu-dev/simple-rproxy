use std::fmt;

use rustls::internal::msgs::codec::Reader;

pub(super) struct ReaderExt {
    /// Inner buffer
    inner: Vec<u8>,

    /// [`Reader`] for rustls
    reader: Reader<'static>,

    /// Stat: `last_cursor`
    last_cursor: usize,
}

impl fmt::Debug for ReaderExt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReaderExt")
            .field("has_peeked", &self.inner.len())
            .field("current_cursor", &self.reader.used())
            .field("last_cursor", &self.last_cursor)
            .finish()
    }
}

impl ReaderExt {
    #[inline]
    pub(super) const fn new() -> Self {
        Self {
            inner: Vec::new(),
            reader: Reader::init(&[]),
            last_cursor: 0,
        }
    }

    #[inline]
    #[allow(unsafe_code, reason = "callee guaranteed")]
    pub(super) fn set_cursor(&mut self, cursor: usize) -> Option<()> {
        self.reader.take(cursor)?;
        self.last_cursor = cursor;
        Some(())
    }

    #[inline]
    pub(super) fn as_mut_slice(&mut self, target_len: usize) -> &mut [u8] {
        debug_assert!(target_len > 0);

        self.inner.reserve(target_len);

        #[allow(unsafe_code, reason = "callee guaranteed")]
        #[allow(
            clippy::uninit_vec,
            reason = "callee guaranteed: will set actual len later"
        )]
        unsafe {
            self.inner.set_len(target_len);
        }

        self.inner.as_mut_slice()
    }

    #[inline]
    pub(super) fn update_buffer(&mut self, new_len: usize, is_retry: bool) {
        #[allow(unsafe_code, reason = "callee guaranteed")]
        unsafe {
            self.inner.set_len(new_len);
        }

        let cursor = if is_retry {
            self.last_cursor
        } else {
            self.reader.used()
        };

        self.reader = Reader::init(
            #[allow(
                unsafe_code,
                reason = "self.reader will be dropped together with self.inner"
            )]
            unsafe {
                std::slice::from_raw_parts(self.inner.as_ptr(), self.inner.len())
            },
        );

        // set the cursor
        self.reader.take(cursor);
    }

    #[inline]
    pub(super) const fn reader(&mut self) -> &mut Reader<'static> {
        self.last_cursor = self.reader.used();
        &mut self.reader
    }
}

impl Drop for ReaderExt {
    fn drop(&mut self) {
        self.reader = Reader::init(&[]);
    }
}
