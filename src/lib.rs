//! Before/After middleware for HMAC
//!
//! Before middleware validates that a request is properly signed. If not, a Forbidden response is
//! sent.
//!
//! After middleware handles signing and adding the appropriate header to the response.
//!

#![deny(warnings)]

extern crate openssl;
extern crate iron;
extern crate url;
extern crate bodyparser;
extern crate persistent;
extern crate rustc_serialize;

use iron::prelude::*;
use iron::response::ResponseBody;
use iron::{BeforeMiddleware, AfterMiddleware};
use openssl::crypto::hash::Type;
use openssl::crypto::hmac::HMAC;
use rustc_serialize::hex::FromHex;
use std::io::Write;
use std::ops::Deref;
use url::format::PathFormatter;

mod error;
#[macro_use]
mod macros;
mod util;

use error::Result;
use error::Error;

/// Key used for HMAC
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
///
/// The algorithm employed is as follows.
///
/// `hmac(secret, hmac(secret, method) + hmac(secret, path) + hmac(secret, body))`
#[derive(Debug, Clone)]
pub struct Hmac256Authentication {
    secret: SecretKey,
    hmac_header_key: String
}

impl Hmac256Authentication {
    /// Build Hmac256Authentication before and after middleware given a secret and header key.
    pub fn middleware<K: Into<SecretKey>, S: Into<String>>(secret: K, hmac_header_key: S)
        -> (Hmac256Authentication, Hmac256Authentication) {

        let auth = Hmac256Authentication {
            secret: secret.into(),
            hmac_header_key: hmac_header_key.into()
        };

        (auth.clone(), auth)
    }
}

impl Hmac256Authentication {
    fn compute_request_hmac(&self, req: &mut iron::Request) -> Result<Vec<u8>> {
        let body = match try!(req.get::<bodyparser::Raw>()) {
            Some(body) => {
                body
            },
            None => {
                "".to_string()
            },
        };

        let method = req.method.as_ref();
        let path = {
            let formatter = PathFormatter { path: &req.url.path };
            formatter.to_string()
        };

        let method_hmac = util::hmac256(&self.secret, method.as_bytes());
        let path_hmac = util::hmac256(&self.secret, path.as_bytes());
        let body_hmac = util::hmac256(&self.secret, body.as_bytes());

        let mut merged_hmac = HMAC::new(Type::SHA256, &self.secret[..]);

        try!(merged_hmac.write_all(&method_hmac[..]));
        try!(merged_hmac.write_all(&path_hmac[..]));
        try!(merged_hmac.write_all(&body_hmac[..]));

        Ok(merged_hmac.finish())
    }

    fn compute_response_hmac(&self, res: &mut iron::Response) -> Result<Vec<u8>> {
        let body: Vec<u8> = match res.body {
            Some(ref mut body) => {
                let mut buf = util::Buffer::new();
                try!(body.write_body(&mut ResponseBody::new(&mut buf)));
                buf.to_inner()
            }, None => {
                Vec::new()
            }
        };

        let response_hmac = util::hmac256(&self.secret, &body[..]);

        // Need to reset body now that we've written it
        res.body = Some(Box::new(body));

        Ok(response_hmac)
    }
}

impl BeforeMiddleware for Hmac256Authentication {
    fn before(&self, req: &mut iron::Request) -> IronResult<()> {
        let computed = try!(self.compute_request_hmac(req));
        let supplied = match req.headers.get_raw(&self.hmac_header_key[..]) {
            Some(hmac) => {
                let s = std::str::from_utf8(&hmac[0][..]).unwrap();
                if s.len() != 64 {
                    forbidden!();
                }
                match s.from_hex() {
                    Ok(hex) => hex,
                    Err(err) => {
                        forbidden!(err)
                    }
                }
            },
            None => {
                let err = Error::MissingHmacHeader(self.hmac_header_key.clone());
                return Err(::iron::IronError::new(err, ::iron::status::Forbidden));
            }
        };

        if computed.len() != supplied.len() {
            forbidden!();
        }

        if util::contant_time_equals(&computed[..], &supplied[..]) {
            Ok(())
        } else {
            forbidden!()
        }
    }
}

impl AfterMiddleware for Hmac256Authentication {
    fn after(&self, _: &mut iron::Request, mut res: iron::Response) -> IronResult<Response> {
        let hmac = try!(self.compute_response_hmac(&mut res));
        let hmac_hex_encoded = util::to_hex(&hmac[..]).as_bytes().to_vec();
        res.headers.set_raw(self.hmac_header_key.clone(), vec![hmac_hex_encoded]);
        Ok(res)
    }
}
