//! Callback-only security-key framing and proposal policy.
use neotales_ssh::{
    Writer,
    client::ClientConfig,
    security_key::{self, SecurityKeyVerifier},
};
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest, Sha256};

fn fixture(algorithm: &str) -> (Vec<u8>, Vec<u8>) {
    let mut key = Writer::new();
    key.write_string(algorithm).unwrap();
    let mut sig = Writer::new();
    sig.write_string(algorithm).unwrap();
    if algorithm == security_key::ED25519 {
        key.write_string(
            ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .as_bytes(),
        )
        .unwrap();
        sig.write_string(&[9; 64]).unwrap();
    } else {
        key.write_string("nistp256").unwrap();
        let private = p256::SecretKey::from_slice(&[7; 32]).unwrap();
        key.write_string(private.public_key().to_sec1_point(false).as_bytes())
            .unwrap();
        let mut parts = Writer::new();
        parts.write_mpint(1_u32).unwrap();
        parts.write_mpint(2_u32).unwrap();
        sig.write_string(parts.as_bytes()).unwrap();
    }
    key.write_string("ssh:test").unwrap();
    sig.write_byte(1);
    sig.write_uint32(42);
    (key.into_bytes(), sig.into_bytes())
}

#[test]
fn security_key_callback_receives_openssh_framing_and_denies_bad_inputs() {
    for algorithm in [security_key::ED25519, security_key::ECDSA] {
        let (key, sig) = fixture(algorithm);
        let verifier = SecurityKeyVerifier::new(move |request| {
            assert_eq!(request.algorithm, algorithm);
            assert_eq!(request.application, b"ssh:test");
            assert_eq!(request.flags, 1);
            assert_eq!(request.counter, 42);
            assert_eq!(request.signed_data[..32], Sha256::digest(b"ssh:test")[..]);
            assert_eq!(request.signed_data[32..37], [1, 0, 0, 0, 42]);
            assert_eq!(request.signed_data[37..], Sha256::digest(b"message")[..]);
            true // Fake verifier: framing test, not hardware/cryptographic evidence.
        });
        verifier.verify(algorithm, &key, &sig, b"message").unwrap();
        let reject = SecurityKeyVerifier::new(|_| false);
        assert!(reject.verify(algorithm, &key, &sig, b"message").is_err());
        let panic = SecurityKeyVerifier::new(|_| panic!("denied"));
        assert!(panic.verify(algorithm, &key, &sig, b"message").is_err());
        for length in 0..sig.len() {
            assert!(
                verifier
                    .verify(algorithm, &key, &sig[..length], b"message")
                    .is_err()
            );
        }
        let mut trailing = sig.clone();
        trailing.push(0);
        assert!(
            verifier
                .verify(algorithm, &key, &trailing, b"message")
                .is_err()
        );
        let mut extensions = sig.clone();
        let index = extensions.len() - 5;
        extensions[index] = 0x81;
        assert!(
            verifier
                .verify(algorithm, &key, &extensions, b"message")
                .is_err()
        );
        let mut trailing_key = key.clone();
        trailing_key.push(0);
        assert!(
            verifier
                .verify(algorithm, &trailing_key, &sig, b"message")
                .is_err()
        );
    }
}

#[test]
fn security_key_proposals_require_explicit_callback() {
    let default = ClientConfig::new();
    for name in [security_key::ED25519, security_key::ECDSA] {
        assert!(
            !default
                .kexinit()
                .server_host_key_algorithms
                .iter()
                .any(|n| n == name)
        );
    }
    let enabled = default
        .clone()
        .with_security_key_verifier(SecurityKeyVerifier::new(|_| false));
    for name in [security_key::ED25519, security_key::ECDSA] {
        assert!(
            enabled
                .kexinit()
                .server_host_key_algorithms
                .iter()
                .any(|n| n == name)
        );
    }
    let mut proposal = default.kexinit().clone();
    proposal.server_host_key_algorithms = vec![security_key::ED25519.to_owned()];
    let result = ClientConfig::with_kexinit(proposal)
        .connect_with_host_keys(std::io::Cursor::new(Vec::new()), |_| Ok::<(), ()>(()));
    assert!(matches!(
        result,
        Err(neotales_ssh::client::HandshakeError::UnsupportedAlgorithm)
    ));
}
