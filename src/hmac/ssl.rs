use std::io::Write;

use openssl::crypto::hash::Type;
use openssl::crypto::hmac::HMAC;

use super::HmacBuilder;
use ::SecretKey;

pub struct OpensslHmac256 {
    inner: HMAC
}

impl HmacBuilder for OpensslHmac256 {
    fn new(secret: &SecretKey) -> OpensslHmac256 {
        OpensslHmac256 {
            inner: HMAC::new(Type::SHA256, &secret[..])
        }
    }

    // Add more input data
    fn input(&mut self, data: &[u8]) -> &mut OpensslHmac256 {
        self.inner.write_all(data).unwrap();
        self
    }

    // Return the hmac digest
    fn finalize(mut self) -> Vec<u8> {
        self.inner.finish()
    }
}
