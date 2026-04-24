//! Minimal CBOR codec covering the subset CTAP2 needs.
//!
//! CTAP2 uses canonical CBOR with definite lengths only, integer/text map
//! keys, and no floats or tags in anything we must interpret. A full CBOR
//! library would be a large fraction of the TCB for functionality we never
//! call, so we hand-roll the dozen header variants actually required.

use alloc::vec::Vec;

// ---------------------------------------------------------------- encoder ---

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
    pub fn int(&mut self, n: i64) {
        if n >= 0 {
            self.header(0, n as u64);
        } else {
            self.header(1, (-1 - n) as u64);
        }
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
    /// Append already-encoded CBOR verbatim. Used to splice a COSE key into
    /// the middle of an `authenticatorData` byte string.
    pub fn raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
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

// ---------------------------------------------------------------- decoder ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Eof,
    TypeMismatch,
    /// Indefinite lengths, reserved additional-info values, or nesting beyond
    /// [`MAX_DEPTH`]. CTAP2 forbids the first two; the third is a DoS guard.
    Unsupported,
    Utf8,
}

/// Nesting limit for [`Reader::skip`]. CTAP2 requests are at most 4 deep.
pub const MAX_DEPTH: u8 = 8;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Eof)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::Eof)?;
        self.pos = end;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn header(&mut self) -> Result<(u8, u64), Error> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1F;
        let val = match ai {
            0..=23 => ai as u64,
            24 => self.byte()? as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            _ => return Err(Error::Unsupported),
        };
        Ok((major, val))
    }

    fn expect(&mut self, want_major: u8) -> Result<u64, Error> {
        let (m, v) = self.header()?;
        if m == want_major {
            Ok(v)
        } else {
            Err(Error::TypeMismatch)
        }
    }

    pub fn unsigned(&mut self) -> Result<u64, Error> {
        self.expect(0)
    }

    pub fn int(&mut self) -> Result<i64, Error> {
        match self.header()? {
            (0, v) => i64::try_from(v).map_err(|_| Error::Unsupported),
            (1, v) => {
                let v = i64::try_from(v).map_err(|_| Error::Unsupported)?;
                Ok(-1 - v)
            }
            _ => Err(Error::TypeMismatch),
        }
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.expect(2)?;
        let n = usize::try_from(n).map_err(|_| Error::Eof)?;
        self.take(n)
    }

    pub fn text(&mut self) -> Result<&'a str, Error> {
        let n = self.expect(3)?;
        let n = usize::try_from(n).map_err(|_| Error::Eof)?;
        core::str::from_utf8(self.take(n)?).map_err(|_| Error::Utf8)
    }

    pub fn array(&mut self) -> Result<u64, Error> {
        self.expect(4)
    }

    pub fn map(&mut self) -> Result<u64, Error> {
        self.expect(5)
    }

    pub fn bool(&mut self) -> Result<bool, Error> {
        match self.header()? {
            (7, 20) => Ok(false),
            (7, 21) => Ok(true),
            _ => Err(Error::TypeMismatch),
        }
    }

    /// Consume one data item without interpreting it.
    pub fn skip(&mut self) -> Result<(), Error> {
        self.skip_n(MAX_DEPTH)
    }

    fn skip_n(&mut self, depth: u8) -> Result<(), Error> {
        if depth == 0 {
            return Err(Error::Unsupported);
        }
        let (m, v) = self.header()?;
        match m {
            0 | 1 | 7 => Ok(()),
            2 | 3 => {
                let n = usize::try_from(v).map_err(|_| Error::Eof)?;
                self.take(n).map(|_| ())
            }
            4 => {
                for _ in 0..v {
                    self.skip_n(depth - 1)?;
                }
                Ok(())
            }
            5 => {
                for _ in 0..v {
                    self.skip_n(depth - 1)?;
                    self.skip_n(depth - 1)?;
                }
                Ok(())
            }
            6 => self.skip_n(depth - 1),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_primitives() {
        let mut w = Writer::new();
        w.map(3);
        w.unsigned(1);
        w.text("hi");
        w.int(-7);
        w.bytes(&[0xAA; 40]);
        w.unsigned(300);
        w.array(2);
        w.bool(true);
        w.bool(false);
        let enc = w.into_vec();

        let mut r = Reader::new(&enc);
        assert_eq!(r.map().unwrap(), 3);
        assert_eq!(r.unsigned().unwrap(), 1);
        assert_eq!(r.text().unwrap(), "hi");
        assert_eq!(r.int().unwrap(), -7);
        assert_eq!(r.bytes().unwrap(), &[0xAA; 40]);
        assert_eq!(r.unsigned().unwrap(), 300);
        assert_eq!(r.array().unwrap(), 2);
        assert!(r.bool().unwrap());
        assert!(!r.bool().unwrap());
    }

    #[test]
    fn skip_handles_nesting_and_bounds() {
        let mut w = Writer::new();
        w.array(2);
        w.map(1);
        w.text("k");
        w.array(1);
        w.int(-1);
        w.unsigned(9);
        let enc = w.into_vec();
        let mut r = Reader::new(&enc);
        r.skip().unwrap();

        // Stack-exhaustion guard: a claimed billion-element array still fails
        // fast on EOF instead of recursing.
        let mut r = Reader::new(&[0x9B, 0, 0, 0, 0, 0xFF, 0, 0, 0]);
        assert_eq!(r.skip(), Err(Error::Eof));
    }
}
