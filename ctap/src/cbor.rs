//! Minimal CBOR encoder covering the subset CTAP2 needs.
//!
//! CTAP2 uses canonical CBOR with definite lengths only, integer/text map
//! keys, and no floats/tags. A full CBOR library would be a large fraction
//! of the TCB for functionality we never call, so we hand-roll the dozen
//! header variants actually required. A matching decoder lands in M1
//! together with `makeCredential` request parsing.

use alloc::vec::Vec;

pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Create a writer that already contains `prefix`. Convenient for CTAP2
    /// responses, which are `status_byte || cbor`.
    pub fn with_prefix(prefix: u8) -> Self {
        let mut w = Self::new();
        w.buf.push(prefix);
        w
    }

    fn header(&mut self, major: u8, n: u64) {
        let ib = major << 5;
        if n < 24 {
            self.buf.push(ib | n as u8);
        } else if n <= 0xFF {
            self.buf.push(ib | 24);
            self.buf.push(n as u8);
        } else if n <= 0xFFFF {
            self.buf.push(ib | 25);
            self.buf.extend_from_slice(&(n as u16).to_be_bytes());
        } else if n <= 0xFFFF_FFFF {
            self.buf.push(ib | 26);
            self.buf.extend_from_slice(&(n as u32).to_be_bytes());
        } else {
            self.buf.push(ib | 27);
            self.buf.extend_from_slice(&n.to_be_bytes());
        }
    }

    pub fn unsigned(&mut self, n: u64) {
        self.header(0, n);
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.header(2, b.len() as u64);
        self.buf.extend_from_slice(b);
    }
    pub fn text(&mut self, s: &str) {
        self.header(3, s.len() as u64);
        self.buf.extend_from_slice(s.as_bytes());
    }
    pub fn array(&mut self, len: u64) {
        self.header(4, len);
    }
    pub fn map(&mut self, len: u64) {
        self.header(5, len);
    }
    pub fn bool(&mut self, v: bool) {
        self.buf.push(if v { 0xF5 } else { 0xF4 });
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}
