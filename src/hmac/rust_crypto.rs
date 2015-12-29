use ::SecretKey;
use super::HmacBuilder;

use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha2::Sha256;

pub struct RustCryptoHmac256 {
    inner: ::crypto::hmac::Hmac<::crypto::sha2::Sha256>
}

impl HmacBuilder for RustCryptoHmac256 {
    fn new(secret: &SecretKey) -> RustCryptoHmac256 {
        RustCryptoHmac256 {
            inner: Hmac::new(Sha256::new(), secret)
        }
    }

    // Add more input data
    fn input(&mut self, data: &[u8]) -> &mut RustCryptoHmac256 {
        self.inner.input(data);
        self
    }

    // Return the hmac digest
    fn finalize(mut self) -> Vec<u8> {
        let len = self.inner.output_bytes();
        // Make vec for result
        let mut result = Vec::with_capacity(len);
        for _ in 0..len {
            result.push(0);
        }

        self.inner.raw_result(&mut result[..]);

        result
    }
}
