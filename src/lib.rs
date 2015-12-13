//! Before/After middleware for HMAC
//!
//! Before middleware validates that a request is properly signed. If not, a Forbidden response is
//! sent.
//!
//! After middleware handles signing and adding the appropriate header to the response.
//!

extern crate openssl;
extern crate iron;
extern crate url;
extern crate bodyparser;
extern crate persistent;
extern crate rustc_serialize;

use iron::prelude::*;
use iron::response::ResponseBody;
use iron::{BeforeMiddleware, AfterMiddleware, status};
use openssl::crypto::hash::Type;
use openssl::crypto::hmac;
use openssl::crypto::memcmp::eq as eq_constant_time;
use rustc_serialize::hex::FromHex;
use std::error::Error;
use std::fmt::{self, Debug};
use std::io::{self, Write, Read};
use std::ops::Deref;
use url::format::PathFormatter;

mod util;

#[macro_use]
mod macros;

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

#[derive(Debug)]
struct StringError(String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

impl std::error::Error for StringError {
    fn description(&self) -> &str { &*self.0 }
}


impl Hmac256Authentication {

    fn compute_request_hmac(&self, req: &mut iron::Request) -> IronResult<Vec<u8>> {
        let body = match req.get::<bodyparser::Raw>() {
            Ok(Some(body)) => {
                body
            },
            Ok(None) => {
                "".to_string()
            },
            Err(err) => forbidden!()
        };

        let method = req.method.as_ref();
        let path = {
            let formatter = PathFormatter { path: &req.url.path };
            formatter.to_string()
        };

        let method_hmac = util::hmac256(&self.secret, method.as_bytes());
        let path_hmac = util::hmac256(&self.secret, path.as_bytes());
        let body_hmac = util::hmac256(&self.secret, body.as_bytes());

        let mut merged_hmac = hmac::HMAC::new(Type::SHA256, &self.secret[..]);

        merged_hmac.write_all(&method_hmac[..]);
        merged_hmac.write_all(&path_hmac[..]);
        merged_hmac.write_all(&body_hmac[..]);

        Ok(merged_hmac.finish())

    }

    fn compute_response_hmac(&self, res: &mut iron::Response)
        -> IronResult<Vec<u8>> {
        let body: Vec<u8> = match res.body {
            Some(ref mut body) => {
                let mut buf = Buffer::new();
                body.write_body(&mut ResponseBody::new(&mut buf));
                buf.0
            }, None => {
                Vec::new()
            }
        };

        let response_hmac = hmac::hmac(Type::SHA256, &self.secret.0, &body[..]);

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
                    let err = StringError("Incorrect HMAC length".to_string());
                    return Err(iron::IronError::new(err, iron::status::BadRequest));
                }
                match s.from_hex() {
                    Ok(hex) => hex,
                    Err(err) => {
                        println!("s: {}", s);
                        println!("err: {}", err);
                        forbidden!()
                    }
                }
            },
            None => forbidden!()
        };

        if computed.len() != supplied.len() {
            forbidden!();
        }

        if eq_constant_time(&computed[..], &supplied[..]) {
            Ok(())
        } else {
            forbidden!()
        }
    }
}

/// A generic buffer that can be written to
struct Buffer(Vec<u8>);

impl Buffer {
    pub fn new() -> Buffer {
        Buffer(Vec::new())
    }
}

impl io::Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        util::extend_vec(&mut self.0, buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AfterMiddleware for Hmac256Authentication {
    fn after(&self, req: &mut iron::Request, mut res: iron::Response) -> IronResult<Response> {
        let hmac = try!(self.compute_response_hmac(&mut res));
        let hmac_hex_encoded = to_hex!(&hmac[..]).as_bytes().to_vec();
        res.headers.set_raw(self.hmac_header_key.clone(), vec![hmac_hex_encoded]);
        Ok(res)
    }
}
