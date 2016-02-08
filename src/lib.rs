//! [Iron] middleware for HMAC authentication
//!
//! This package contains `BeforeMiddleware` for authenticating HTTP requests and `AfterMiddleware`
//! for signing response. The HMAC stragegy is presently hardcoded as follows using an SHA-256 hash.
//!
//! For requests, the expected hmac is
//!
//! ```plain
//! hmac(hmac(request.method) + hmac(request.path) + hmac(request.body))
//! ```
//!
//! The response is signed with an hmac generated with
//!
//! ```plain
//! hmac(response.body)
//! ```
//!
//! Middleware can be obtained with the following calls
//!
//! ```no_run
//! use iron_hmac::Hmac256Authentication;
//!
//! let secret = "<your shared hmac secret here>";
//! let header_name = "x-my-hmac";
//!
//! let (hmac_before, hmac_after) = Hmac256Authentication::middleware(secret, header_name);
//! ```
//!
//! The middleware is linked in the usual way.
//!
//! # Building
//!
//! If you wish to use the openssl backed implementation, set `default-features = false` in addition
//! to adding `features = ["hmac-openssl"]`.
//!
//! [Iron]: https://github.com/iron/iron

#![deny(warnings)]

#[cfg(feature = "hmac-rust-crypto")]
extern crate crypto;

#[cfg(feature = "hmac-openssl")]
extern crate openssl;

extern crate iron;
extern crate url;
extern crate bodyparser;
extern crate persistent;
extern crate rustc_serialize;
extern crate constant_time_eq;
extern crate hyper;

use std::any::Any;
use std::fmt::{self, Debug};
use std::ops::Deref;

use iron::prelude::*;
use iron::response::ResponseBody;
use iron::{BeforeMiddleware, AfterMiddleware};
use url::format::PathFormatter;

use hyper::header::{Header, HeaderFormat};

mod error;
#[macro_use]
mod macros;
mod util;
mod hmac;

use hmac::{Hmac256, hmac256, HmacBuilder};

use error::Result;
use error::Error;

/// Key used for HMAC computation
///
/// SecretKey is a newtype for Vec<u8>, and deref returns a &[u8]. The Vec<u8> representation is
/// necessary since the key length cannot be known at compile time.
#[derive(Debug, Clone)]
pub struct SecretKey(Vec<u8>);

impl SecretKey {
    pub fn new(s: &[u8]) -> SecretKey {
        SecretKey(::std::convert::From::from(s))
    }
}

impl Deref for SecretKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Into<SecretKey> for &'static str {
    fn into(self) -> SecretKey {
        SecretKey::new(self.as_bytes())
    }
}

impl Into<SecretKey> for String {
    fn into(self) -> SecretKey {
        SecretKey::new(&self[..].as_bytes())
    }
}

/// Iron middleware for validation hmac headers on requests and signing responses.
#[derive(Debug, Clone)]
pub struct Hmac256Authentication {
    secret: SecretKey,
    hmac_header_key: String
}

impl Hmac256Authentication {
    /// Build Hmac256Authentication BeforeMiddleware and AfterMiddleware
    ///
    /// The `secret` parameter is used for all HMAC generation. The `hmac_header_key` is used to
    /// lookup the request's HMAC.
    pub fn middleware<K: Into<SecretKey>, S: Into<String>>(secret: K, hmac_header_key: S)
        -> (Hmac256Authentication, Hmac256Authentication) {

        let auth = Hmac256Authentication {
            secret: secret.into(),
            hmac_header_key: hmac_header_key.into()
        };

        (auth.clone(), auth)
    }

    fn compute_request_hmac(&self, req: &mut iron::Request) -> Result<Vec<u8>> {
        let body = match try!(req.get::<bodyparser::Raw>()) {
            Some(body) => body,
            None => "".to_string()
        };

        let method = req.method.as_ref();
        let path = {
            let formatter = PathFormatter { path: &req.url.path };
            formatter.to_string()
        };

        let method_hmac = hmac256(&self.secret, method.as_bytes());
        let path_hmac = hmac256(&self.secret, path.as_bytes());
        let body_hmac = hmac256(&self.secret, body.as_bytes());

        let mut merged_hmac = Hmac256::new(&self.secret);

        merged_hmac.input(&method_hmac[..])
                   .input(&path_hmac[..])
                   .input(&body_hmac[..]);

        Ok(merged_hmac.finalize())
    }

    fn compute_response_hmac(&self, res: &mut iron::Response) -> Result<Vec<u8>> {
        let body: Vec<u8> = match res.body {
            Some(ref mut body) => {
                let mut buf = util::Buffer::new();
                try!(body.write_body(&mut ResponseBody::new(&mut buf)));
                buf.to_inner()
            },
            None => Vec::new()
        };

        let response_hmac = hmac256(&self.secret, &body[..]);

        // Need to reset body now that we've written it
        res.body = Some(Box::new(body));

        Ok(response_hmac)
    }
}

impl BeforeMiddleware for Hmac256Authentication {
    fn before(&self, req: &mut iron::Request) -> IronResult<()> {
        let computed = try!(self.compute_request_hmac(req));
        let supplied = match req.headers.get_raw(&self.hmac_header_key[..]) {
            Some(hmac) => try!(util::from_hex(&hmac[0][..])),
            None => {
                let err = Error::MissingHmacHeader(self.hmac_header_key.clone());
                return Err(::iron::IronError::new(err, ::iron::status::Unauthorized));
            }
        };

        if computed.len() != supplied.len() {
            unauthorized!();
        }

        if util::contant_time_equals(&computed[..], &supplied[..]) {
            Ok(())
        } else {
            unauthorized!()
        }
    }
}

/// Authentication strategy
///
/// This is used primarily for formatting the www-authenticate header on 401 responses.
#[derive(Clone, Debug)]
pub struct HmacDigest;

/// Challenges to be returned in a WWWW-Authenticate response header
pub trait WwwAuthenticateChallenge {
    /// Format the challenge
    ///
    /// Eg, a challenge for basic auth might write `Basic realm="<realm>"`
    fn fmt_challenge(&self, &mut fmt::Formatter) -> fmt::Result;
}

impl WwwAuthenticateChallenge for HmacDigest {
    fn fmt_challenge(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let algo = "hmac(hmac(request.method) + hmac(request.path) + hmac(request.body))";
        let hmac = "HMAC-SHA-256";
        let realm = "iron-hmac";
        write!(f, r#"{} realm="{}", algorithm="{}", hmac="{}"#, "HMACDigest", realm, algo, hmac)
    }
}

/// WWW-Authenticate for returning authentication challenges
#[derive(Clone, Debug)]
pub struct WwwAuthenticate<C: WwwAuthenticateChallenge>(C);

impl<C> Header for WwwAuthenticate<C>
    where C: 'static + Any + Clone + Send + Sync + Debug + WwwAuthenticateChallenge
{
    fn header_name() -> &'static str {
        "WWW-Authenticate"
    }

    /// Parse a WWW-Authenticate header
    ///
    /// Always returns an error since iron-hmac only uses this as a response header
    fn parse_header(_raw: &[Vec<u8>]) -> hyper::Result<WwwAuthenticate<C>> {
        Err(::hyper::Error::Header)
    }
}

impl<C> HeaderFormat for WwwAuthenticate<C>
    where C: 'static + Any + Clone + Send + Sync + Debug + WwwAuthenticateChallenge
{
    fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt_challenge(f)
    }
}


impl AfterMiddleware for Hmac256Authentication {
    fn after(&self, _: &mut iron::Request, mut res: iron::Response) -> IronResult<Response> {
        let hmac = try!(self.compute_response_hmac(&mut res));
        let hmac_hex_encoded = util::to_hex(&hmac[..]).as_bytes().to_vec();
        res.headers.set_raw(self.hmac_header_key.clone(), vec![hmac_hex_encoded]);
        Ok(res)
    }

    fn catch(&self, _: &mut iron::Request, mut err: iron::IronError) -> IronResult<Response> {
        // Attach WWW-Authenticate header for unauthorized response
        if let Some(status) = err.response.status {
            if status == hyper::status::StatusCode::Unauthorized {
                err.response.headers.set(WwwAuthenticate(HmacDigest));
            }
        }
        Err(err)
    }
}
