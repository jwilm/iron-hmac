iron-hmac
=========

HMAC middleware for [iron][]

Authenticates incoming requests by computing the HMAC and performing a
constant-time string comparison with the provided value. An HMAC header is
computed and appended to the outgoing response.

[![Build Status](https://travis-ci.org/jwilm/iron-hmac.svg?branch=master)](https://travis-ci.org/jwilm/iron-hmac)

## Usage

For a complete example, please see the [examples][]. This snippet highlights the
critical pieces of using the hmac middleware.

```rust
extern crate iron_hmac;

// ...

// The bodyparser middleware is required for hmac computation
chain.link_before(Read::<bodyparser::MaxBodyLength>::one(MAX_BODY_LENGTH));

// Build the hmac middleware
let (hmac_before, hmac_after) =
    iron_hmac::Hmac256Authentication::middleware(secret, header_key);

// ...

chain.link_before(hmac_before);

// ...

chain.link_after(hmac_after);
```

[iron]: https://github.com/iron/iron/
[examples]: tree/master/examples
