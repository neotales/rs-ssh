//! Compile-time checks for the explicitly opt-in `test-support` feature.
#![allow(missing_docs)]

#[cfg(feature = "test-support")]
#[test]
fn test_support_exposes_the_rekey_ignorable_hook() {
    use std::io::Cursor;

    type Transport = neotales_ssh::ServerTransport<Cursor<Vec<u8>>>;
    const _: fn(&mut Transport, &[u8]) -> Result<(), neotales_ssh::server::ServerTransportError> =
        Transport::write_rekey_ignorable;
}
