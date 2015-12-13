use std::fmt;
use std::io;
use iron::{IronError, status};
use std::str::Utf8Error;

use rustc_serialize::hex::FromHexError;

/// Error type for the hmac middleware
#[derive(Debug)]
pub enum Error {
    /// Some sort of io::Error occurred
    IoError(io::Error),
    /// The request's provided HMAC is invalid.
    InvalidHmac,
    /// The HMAC header is missing. The String value contains the expected header name.
    MissingHmacHeader(String),
    /// Error occurred while reading request body
    Bodyparser(::bodyparser::BodyError),
    /// Error interpreting byte sequence as utf8
    Utf8Error(Utf8Error),
    /// Error decoding hex
    DecodingHex(FromHexError),
}

pub type Result<T> = ::std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::MissingHmacHeader(ref key) => write!(f, "Missing Hmac Header (key = {})", key),
            Error::InvalidHmac => write!(f, "Provided HMAC is invalid"),
            Error::IoError(ref err) => write!(f, "IoError({})", err),
            Error::Bodyparser(ref err) => write!(f, "Bodyparser({})", err),
            Error::Utf8Error(ref err) => write!(f, "Utf8Error({})", err),
            Error::DecodingHex(ref err) => write!(f, "DecodingHex({})", err),
        }
    }
}

impl ::std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::MissingHmacHeader(_) => "The expected HMAC header is missing",
            Error::InvalidHmac => "Provided HMAC is invalid",
            Error::IoError(ref err) => err.description(),
            Error::Bodyparser(ref err) => err.description(),
            Error::Utf8Error(ref err) => err.description(),
            Error::DecodingHex(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&::std::error::Error> {
        match *self {
            Error::IoError(ref err) => Some(err),
            Error::Bodyparser(ref err) => Some(err),
            Error::Utf8Error(ref err) => Some(err),
            Error::DecodingHex(ref err) => Some(err),
            _ => None
        }
    }
}

impl From<Error> for IronError {
    fn from(err: Error) -> IronError {
        match err {
            Error::MissingHmacHeader(_) => IronError::new(err, status::BadRequest),
            Error::InvalidHmac => IronError::new(err, status::Forbidden),
            Error::DecodingHex(_) => IronError::new(err, status::Forbidden),
            _ => IronError::new(err, status::InternalServerError)
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<::bodyparser::BodyError> for Error {
    fn from(err: ::bodyparser::BodyError) -> Error {
        Error::Bodyparser(err)
    }
}

impl From<Utf8Error> for Error {
    fn from(err: Utf8Error) -> Error {
        Error::Utf8Error(err)
    }
}

impl From<FromHexError> for Error {
    fn from(err: FromHexError) -> Error {
        Error::DecodingHex(err)
    }
}
