use std::io;
use std::str::from_utf8;

use rustc_serialize::hex::FromHex;
use rustc_serialize::hex::ToHex;

use constant_time_eq::constant_time_eq;

use ::error::{Result};

// Vector extension from slice
//
// The implementation here is the extend_from_slice which should be stabilised in rust 1.6
// https://github.com/rust-lang/rust/pull/30187/files#diff-77adadec35cb5b03d4933f83754de940R966
pub fn extend_vec(vec: &mut Vec<u8>, extension: &[u8]) {
    vec.reserve(extension.len());

    for i in 0..extension.len() {
        let len = vec.len();
        // Unsafe code so this can be optimised to a memcpy (or something
        // similarly fast) when T is Copy. LLVM is easily confused, so any
        // extra operations during the loop can prevent this optimisation.
        unsafe {
            ::std::ptr::write(vec.get_unchecked_mut(len), extension.get_unchecked(i).clone());
            vec.set_len(len + 1);
        }
    }
}

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
        extend_vec(&mut self.0, buf);
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
