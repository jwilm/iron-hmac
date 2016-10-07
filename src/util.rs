use std::io;
use std::str::from_utf8;

use rustc_serialize::hex::FromHex;
use rustc_serialize::hex::ToHex;

use constant_time_eq::constant_time_eq;

use ::error::{Result};

/// Constant time equality comparison for byte lists
#[inline]
pub fn contant_time_equals(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq(a, b)
}


/// Wrapper around Vec<u8> that implements write.
///
/// It can be consumed at any time to obtain the Vec<u8>. This is needed by the after middleware for
/// reading the response body for HMAC header computation.
pub struct Buffer(Vec<u8>);

impl Buffer {
    /// Create a new buffer
    pub fn new() -> Buffer {
        Buffer(Vec::new())
    }

    /// Take ownership of the wrapped Vec<u8>
    pub fn to_inner(self) -> Vec<u8> {
        self.0
    }
}

impl io::Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serialize a list of bytes into a hex string
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.to_hex()
}

/// Interpret a slice of utf8 bytes as hex values
pub fn from_hex(maybe_utf8_bytes: &[u8]) -> Result<Vec<u8>> {
    let s = try!(from_utf8(maybe_utf8_bytes));
    Ok(try!(s.from_hex()))
}
