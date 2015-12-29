use ::SecretKey;

#[cfg(feature = "hmac-rust-crypto")]
mod rust_crypto;

#[cfg(feature = "hmac-rust-crypto")]
pub type Hmac256 = rust_crypto::RustCryptoHmac256;

#[cfg(feature = "hmac-openssl")]
mod ssl;

#[cfg(feature = "hmac-openssl")]
pub type Hmac256 = ssl::OpensslHmac256;


pub trait HmacBuilder {
    // Create the HMAC builder
    fn new(secret: &SecretKey) -> Self;

    // Add more input data
    fn input(&mut self, data: &[u8]) -> &mut Self;

    // Return the hmac digest
    fn finalize(mut self) -> Vec<u8>;
}

/// Compute an HMAC using SHA-256 hashing
pub fn hmac256(secret: &SecretKey, data: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac256::new(secret);
    hmac.input(data);
    hmac.finalize()
}

