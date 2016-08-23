extern crate iron_hmac;

extern crate iron;
extern crate bodyparser;
extern crate persistent;

#[macro_use]
extern crate hyper;

use hyper::Client;
use iron::prelude::*;
use iron_hmac::Hmac256Authentication;
use std::io::Read;

/// The header used for our tests
static HMAC_HEADER_NAME: &'static str = "x-hmac";

/// Hyper wrapper for the hmac header
header! { (XHmac, HMAC_HEADER_NAME) => [String] }

/// Ensures that the iron server is closed (and the test thread ends) upon failure. The drop
/// implementation simply calls close on the underlying hyper server.
struct CloseGuard(::iron::Listening);

impl Drop for CloseGuard {
    fn drop(&mut self) {
        self.0.close().unwrap();
    }
}

/// Build a server
///
/// The server (wrapped in CloseGuard) will automatically close when going out of scope. The base
/// url to query against is also returned.
fn build_hmac_hello_world() -> (CloseGuard, String) {
    // Create the hmac middleware
    let (hmac_before, hmac_after) = Hmac256Authentication::middleware("rust :)", "x-hmac");

    let mut chain = Chain::new(|_: &mut Request| {
        Ok(Response::with((iron::status::Ok, "Hello, world!")))
    });

    // Need bodyparser middleware to read body
    chain.link_before(persistent::Read::<bodyparser::MaxBodyLength>::one(1024 * 1024 * 10));

    // Hmac auth middleware
    chain.link_before(hmac_before);
    chain.link_after(hmac_after);

    // Server is now running
    let server = Iron::new(chain).http("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", server.socket);

    (CloseGuard(server), base_url)
}

#[test]
fn missing_hmac_is_forbidden() {
    let (_close_guard, url) = build_hmac_hello_world();

    {
        let client = Client::new();
        let res = client.get(&url[..])
                            .send().unwrap();

        assert_eq!(res.status, hyper::status::StatusCode::Forbidden);
    }
}

#[test]
fn malformed_hmac_is_forbidden() {
    let (_close_guard, url) = build_hmac_hello_world();

    {
        let client = Client::new();
        let res = client.get(&url[..])
                            .header(XHmac("123".to_owned()))
                            .send().unwrap();

        assert_eq!(res.status, hyper::status::StatusCode::Forbidden);
    }
}

#[test]
fn incorrect_hmac_is_forbidden() {
    let (_close_guard, url) = build_hmac_hello_world();

    {
        let client = Client::new();
        let request_hmac = "b1d56c98b74d0da82f1105beee559de64480d7632177a28a4a1331a7d0517362";
        let res = client.get(&url[..])
                            .header(XHmac(request_hmac.to_owned()))
                            .send().unwrap();

        assert_eq!(res.status, hyper::status::StatusCode::Forbidden);
    }
}

#[test]
fn correct_hmac_is_ok() {
    let (_close_guard, url) = build_hmac_hello_world();
    {
        let expected_response_hmac =
            "ccc7dfe24de0375cc49067576b69ba4d68be554c9f86fb3dadfc053ce84f71a0";

        let request_hmac = "fa64feb94f1d649d435ae6dce009ff0767f57c0f20867dde5f8f6712fea3a7be";

        let client = Client::new();
        let mut res = client.get(&url[..])
                            .header(XHmac(request_hmac.to_owned()))
                            .send().unwrap();

        assert_eq!(res.status, hyper::status::StatusCode::Ok);

        let mut body = String::new();
        res.read_to_string(&mut body).unwrap();

        let actual_response_hmac = &res.headers.get_raw("x-hmac").unwrap()[0];

        assert_eq!("Hello, world!", body);

        let actual_hmac = std::str::from_utf8(&actual_response_hmac[..]).unwrap();
        assert_eq!(&actual_hmac[..], &expected_response_hmac[..]);
    }
}
