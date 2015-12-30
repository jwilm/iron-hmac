test:
	cargo test
	cargo test --features hmac-openssl --no-default-features
