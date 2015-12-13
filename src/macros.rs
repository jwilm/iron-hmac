/// Return an iron Error with status set to Forbidden
///
/// The error string indicates that HMAC auth failed
macro_rules! forbidden {
    () => {{
        let err = ::error::Error::InvalidHmac;
        return Err(::iron::IronError::new(err, ::iron::status::Forbidden));
    }};

    ($err:expr) => {{
        return Err(::iron::IronError::new($err, ::iron::status::Forbidden));
    }};
}
