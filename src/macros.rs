/// Return an iron Error with status set to Unauthorized
///
/// The error string indicates that HMAC auth failed
macro_rules! unauthorized {
    () => {{
        let err = ::error::Error::InvalidHmac;
        return Err(::iron::IronError::new(err, ::iron::status::Unauthorized));
    }};

    ($err:expr) => {{
        return Err(::iron::IronError::new($err, ::iron::status::Unauthorized));
    }};
}
