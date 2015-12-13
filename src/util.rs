use openssl::crypto::hash::Type;
use openssl::crypto::hmac::hmac;

use ::SecretKey;

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

pub fn hmac256(secret: &SecretKey, data: &[u8]) -> Vec<u8> {
    hmac(Type::SHA256, &secret, data)
}
