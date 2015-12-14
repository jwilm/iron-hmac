iron-hmac
=========

HMAC middleware for the [Iron][] HTTP framework

[![Build Status](https://travis-ci.org/jwilm/iron-hmac.svg?branch=master)](https://travis-ci.org/jwilm/iron-hmac)
[![Crates.io Version](https://img.shields.io/crates/v/iron-hmac.svg)](https://crates.io/crates/iron-hmac/)

Authenticates incoming requests by computing the HMAC and performing a
constant-time string comparison with the provided value. An HMAC header is
computed and appended to the outgoing response.

## Usage

The best way to get started is by looking at the [example][]. For details,
please see the [documentation][]


[Iron]: https://github.com/iron/iron/
[example]: examples/hmac_middleware.rs
[documentation]: https://jwilm.github.io/iron-hmac/latest/iron_hmac/
