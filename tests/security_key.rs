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

#[test]
fn security_key_userauth_without_verifier_does_not_offer_publickey() {
    let (key, _) = fixture(security_key::ED25519);
    let policy = neotales_ssh::auth::ServerAuthPolicy::new(4)
        .unwrap()
        .with_authorized_key(&key)
        .unwrap();
    assert!(!policy.public_key_enabled());
    assert!(
        policy
            .with_signature_algorithms(&[security_key::ED25519])
            .is_err()
    );
}

#[test]
fn security_key_signing_and_enrollment_callbacks_fail_closed() {
    use security_key::{EnrolledKey, ResidentKeyEnrollment, SecurityKeySigner, Signature};

    for algorithm in [security_key::ED25519, security_key::ECDSA] {
        let (key, expected) = fixture(algorithm);
        let mut reader = neotales_ssh::Reader::new(&expected);
        reader.read_string().unwrap();
        let raw = reader.read_string().unwrap().to_vec();
        let supplied = raw.clone();
        let signer = SecurityKeySigner::new(key.clone(), b"handle".to_vec(), move |request| {
            assert_eq!(request.algorithm, algorithm);
            assert_eq!(request.application, b"ssh:test");
            assert_eq!(request.handle, b"handle");
            assert!(request.signed_data(0x80, 42).is_err());
            let data = request.signed_data(1, 42).unwrap();
            assert_eq!(data[..32], Sha256::digest(b"ssh:test")[..]);
            assert_eq!(data[32..37], [1, 0, 0, 0, 42]);
            assert_eq!(data[37..], Sha256::digest(b"message")[..]);
            Some(Signature {
                bytes: supplied.clone(),
                flags: 1,
                counter: 42,
            })
        })
        .unwrap();
        assert_eq!(signer.sign(b"message").unwrap(), expected);
        for mode in 0..4 {
            let raw = raw.clone();
            let signer = SecurityKeySigner::new(key.clone(), vec![], move |_| match mode {
                0 => None,
                1 => panic!("fake callback failure"),
                2 => Some(Signature {
                    bytes: vec![],
                    flags: 1,
                    counter: 42,
                }),
                _ => Some(Signature {
                    bytes: raw.clone(),
                    flags: 0x80,
                    counter: 42,
                }),
            })
            .unwrap();
            assert!(signer.sign(b"message").is_err());
        }
        assert!(SecurityKeySigner::new(vec![], vec![], |_| panic!("must not sign")).is_err());
        assert!(SecurityKeySigner::new(key.clone(), vec![0; 1025], |_| None).is_err());
        assert!(
            ResidentKeyEnrollment::default()
                .enroll(algorithm, b"ssh:test")
                .is_err()
        );
        assert!(
            ResidentKeyEnrollment::new(|_, _| None)
                .enroll(algorithm, b"ssh:test")
                .is_err()
        );
        assert!(
            ResidentKeyEnrollment::new(|_, _| panic!("denied"))
                .enroll(algorithm, b"ssh:test")
                .is_err()
        );
        let enrollment = ResidentKeyEnrollment::new(move |_, _| {
            Some(EnrolledKey {
                public_key_blob: key.clone(),
                handle: b"handle".to_vec(),
            })
        });
        assert_eq!(
            enrollment.enroll(algorithm, b"ssh:test").unwrap().handle,
            b"handle"
        );
        assert!(enrollment.enroll(algorithm, b"ssh:wrong").is_err());
        assert!(
            enrollment
                .enroll(
                    if algorithm == security_key::ED25519 {
                        security_key::ECDSA
                    } else {
                        security_key::ED25519
                    },
                    b"ssh:test"
                )
                .is_err()
        );
    }
}
