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

/// Serialize a &[u8] sequence to a hex String
macro_rules! to_hex {
    ($bytes:expr) => {{
        use std::fmt::Write;
        let mut tmp_str = String::new();
        for &byte in $bytes {
            write!(&mut tmp_str, "{:02x}", byte).unwrap();
        }

        tmp_str
    }}
}

/// Serialize a &[u8] sequence and pass it to println with the provided format string.
macro_rules! print_hex {
    ($fmt_str:expr, $bytes:expr) => {{
        println!($fmt_str, to_hex!($bytes));
    }}
}
