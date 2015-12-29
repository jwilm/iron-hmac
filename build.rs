fn main() {
    let ssl = cfg!(feature = "hmac-openssl");
    let crypto = cfg!(feature = "hmac-rust-crypto");

    if ssl && crypto {
        panic!("`hmac-openssl` and `hmac-rust-crypto` features are mutually exclusive");
    } else if !ssl && !crypto {
        panic!("`hmac-openssl` or `hmac-rust-crypto` feature must be used");
    }
}
