use rustls::crypto::{CryptoProvider, aws_lc_rs, ring};

mod acme;
mod rfc;

fn providers() -> [(&'static str, CryptoProvider); 2] {
    [
        ("ring", ring::default_provider()),
        ("aws-lc-rs", aws_lc_rs::default_provider()),
    ]
}
