extern crate bodyparser;
extern crate iron;
extern crate iron_hmac;
extern crate persistent;

use iron::prelude::*;
use iron_hmac::Hmac256Authentication;

fn main() {
    // Create the hmac middleware
    let (hmac_before, hmac_after) = Hmac256Authentication::middleware("rust :)", "x-hmac");

    // All queries return a hello world
    let mut chain = Chain::new(|_: &mut Request| {
        Ok(Response::with((iron::status::Ok, "Hello, world!")))
    });

    // Need bodyparser middleware to read body
    chain.link_before(persistent::Read::<bodyparser::MaxBodyLength>::one(1024 * 1024 * 10));

    // Hmac auth middleware
    chain.link_before(hmac_before);
    chain.link_after(hmac_after);

    // Server is now running
    let server = Iron::new(chain).http("localhost:0").unwrap();
    let host = format!("{}", server.socket);

    println!("listening on {}", host);

    // If you want to query against this, perform a GET request and set the `x-hmac` header to
    // fa64feb94f1d649d435ae6dce009ff0767f57c0f20867dde5f8f6712fea3a7be
    //
    // If you change the body, hmac, or request method, the response should be either forbidden or
    // badrequest.
}
