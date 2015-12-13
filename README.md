iron-hmac
=========

HMAC middleware for the [Iron][] HTTP framework

Authenticates incoming requests by computing the HMAC and performing a
constant-time string comparison with the provided value. An HMAC header is
computed and appended to the outgoing response.

[![Build Status](https://travis-ci.org/jwilm/iron-hmac.svg?branch=master)](https://travis-ci.org/jwilm/iron-hmac)

## Usage

For a complete example, please see the [example][].

[Documentation][]

[Iron]: https://github.com/iron/iron/
[example]: examples/hmac_middleware.rs
[Documentation]: https://jwilm.github.io/iron-hmac/latest/iron_hmac/
