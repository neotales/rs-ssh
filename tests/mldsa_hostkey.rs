//! Draft-08 ML-DSA framing, real FIPS 204 verification and both handshakes.
use ml_dsa::signature::rand_core::{TryCryptoRng, TryRng};
use ml_dsa::{Keypair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signer, Verifier};
use neotales_ssh::{
    ClientConfig, KexInit, Reader, ServerConfig, Writer,
    hostkey::{Ed25519Signer, HostPublicKey},
    mldsa_hostkey::{Algorithm, MldsaPublicKey, MldsaSigner},
};
use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
};

// Real OS entropy for hedged signatures; failures propagate, not an infallible
// adapter or a verification stub. Never used to read a stored credential.
struct TestRng;
impl TryRng for TestRng {
    type Error = std::io::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst).map_err(|_| std::io::Error::other("test entropy unavailable"))
    }
}
impl TryCryptoRng for TestRng {}

fn frame(name: &str, raw: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_string(name).unwrap();
    writer.write_string(raw).unwrap();
    writer.into_bytes()
}

fn exercise<P: MlDsaParams>(algorithm: Algorithm, public_size: usize, signature_size: usize) {
    let mut seed = [7; 32];
    let signer = MldsaSigner::from_seed(algorithm, &mut seed);
    assert_eq!(seed, [0; 32]);
    assert_eq!(format!("{signer:?}"), "MldsaSigner(..)");
    let public_blob = signer.public_key().to_blob().unwrap();
    let mut reader = Reader::new(&public_blob);
    assert_eq!(reader.read_string().unwrap(), algorithm.name().as_bytes());
    let raw_public = reader.read_string().unwrap();
    assert_eq!(raw_public.len(), public_size);
    assert!(reader.is_empty());
    let public = MldsaPublicKey::from_blob(&public_blob).unwrap();
    assert_eq!(public.to_blob().unwrap(), public_blob);
    let message = b"SSH exchange hash: test fixture";
    let signature_blob = signer.sign(message).unwrap();
    assert_eq!(signer.sign(message).unwrap(), signature_blob);
    let mut reader = Reader::new(&signature_blob);
    assert_eq!(reader.read_string().unwrap(), algorithm.name().as_bytes());
    let raw_signature = reader.read_string().unwrap();
    assert_eq!(raw_signature.len(), signature_size);
    assert!(reader.is_empty());
    public.verify(&signature_blob, message).unwrap();

    // Cross-check both directions against the real crate's independent API.
    // Its Signer/Verifier use pure ML-DSA with the empty context (not HashML-DSA).
    let crate_key = ml_dsa::SigningKey::<P>::from_seed(&[7; 32].into());
    let crate_public = crate_key.verifying_key();
    assert_eq!(raw_public, crate_public.encode().as_slice());
    let crate_signature = ml_dsa::Signature::<P>::try_from(raw_signature).unwrap();
    crate_public.verify(message, &crate_signature).unwrap();
    let deterministic = crate_key.try_sign(message).unwrap();
    public
        .verify(
            &frame(algorithm.name(), deterministic.encode().as_slice()),
            message,
        )
        .unwrap();
    let hedged = crate_key
        .expanded_key()
        .sign_randomized(message, &[], &mut TestRng)
        .unwrap();
    assert_ne!(hedged.encode(), deterministic.encode());
    public
        .verify(
            &frame(algorithm.name(), hedged.encode().as_slice()),
            message,
        )
        .unwrap();
    let wrong_context = crate_key
        .expanded_key()
        .sign_deterministic(message, b"not empty")
        .unwrap();
    assert!(
        public
            .verify(
                &frame(algorithm.name(), wrong_context.encode().as_slice()),
                message
            )
            .is_err()
    );

    assert!(public.verify(&signature_blob, b"different hash").is_err());
    let mut damaged = raw_signature.to_vec();
    damaged[0] ^= 1;
    assert!(
        public
            .verify(&frame(algorithm.name(), &damaged), message)
            .is_err()
    );
    for size in [0, signature_size - 1, signature_size + 1] {
        assert!(
            public
                .verify(&frame(algorithm.name(), &vec![0; size]), message)
                .is_err()
        );
    }
    for size in [0, public_size - 1, public_size + 1] {
        assert!(MldsaPublicKey::from_blob(&frame(algorithm.name(), &vec![0; size])).is_err());
    }
    for name in [
        "ssh-mldsa-44",
        "ssh-mldsa-65",
        "ssh-mldsa-87",
        "mldsa-65",
        "ssh-mldsa-65@openssh.com",
    ] {
        if name != algorithm.name() {
            assert!(public.verify(&frame(name, raw_signature), message).is_err());
        }
    }
    let mut trailing = signature_blob.clone();
    trailing.push(0);
    assert!(public.verify(&trailing, message).is_err());
    assert!(
        public
            .verify(&signature_blob[..signature_blob.len() - 1], message)
            .is_err()
    );
    let mut trailing = public_blob.clone();
    trailing.push(0);
    assert!(MldsaPublicKey::from_blob(&trailing).is_err());
    assert!(MldsaPublicKey::from_blob(&public_blob[..public_blob.len() - 1]).is_err());
    let wrong = MldsaSigner::from_seed(algorithm, &mut [8; 32]);
    assert!(wrong.public_key().verify(&signature_blob, message).is_err());
}

#[test]
fn mldsa_all_parameter_sets_sign_verify_deterministic_and_hedged() {
    exercise::<MlDsa44>(Algorithm::MlDsa44, 1312, 2420);
    exercise::<MlDsa65>(Algorithm::MlDsa65, 1952, 3309);
    exercise::<MlDsa87>(Algorithm::MlDsa87, 2592, 4627);
}

#[test]
fn mldsa_is_opt_in_and_does_not_replace_existing_host_algorithms() {
    let client = ClientConfig::new();
    let server = ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32]));
    for proposal in [client.kexinit(), server.kexinit(), &KexInit::new([0; 16])] {
        assert!(
            !proposal
                .server_host_key_algorithms
                .iter()
                .any(|name| name.starts_with("ssh-mldsa"))
        );
    }
    let enabled = client.clone().with_mldsa_host_keys().with_mldsa_host_keys();
    assert_eq!(
        &enabled.kexinit().server_host_key_algorithms
            [..client.kexinit().server_host_key_algorithms.len()],
        client.kexinit().server_host_key_algorithms
    );
    for name in ["ssh-mldsa-44", "ssh-mldsa-65", "ssh-mldsa-87"] {
        assert_eq!(
            enabled
                .kexinit()
                .server_host_key_algorithms
                .iter()
                .filter(|entry| *entry == name)
                .count(),
            1
        );
    }
    let original = server.kexinit().server_host_key_algorithms.clone();
    let enabled =
        server.with_mldsa_host_key(MldsaSigner::from_seed(Algorithm::MlDsa65, &mut [7; 32]));
    assert_eq!(
        &enabled.kexinit().server_host_key_algorithms[..original.len()],
        original
    );
    assert!(
        enabled
            .kexinit()
            .server_host_key_algorithms
            .iter()
            .any(|name| name == "ssh-mldsa-65")
    );
    assert!(
        !enabled
            .kexinit()
            .server_host_key_algorithms
            .iter()
            .any(|name| name == "ssh-mldsa-44" || name == "ssh-mldsa-87")
    );
}

#[test]
fn mldsa65_both_handshakes_trust_and_rekeys() -> Result<(), Box<dyn std::error::Error>> {
    for strict in [false, true] {
        for trusted in [false, true] {
            let signer = MldsaSigner::from_seed(Algorithm::MlDsa65, &mut [7; 32]);
            let expected = signer.public_key().to_blob()?;
            let server = ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32]))
                .with_mldsa_host_key(signer);
            let mut proposal = server.kexinit().clone();
            proposal.server_host_key_algorithms = vec!["ssh-mldsa-65".to_owned()];
            if !strict {
                proposal
                    .kex_algorithms
                    .retain(|name| !name.starts_with("kex-strict-"));
            }
            let server = server.with_kexinit(proposal);
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            let address = listener.local_addr()?;
            let thread = std::thread::spawn(move || -> Result<(), String> {
                let run = || -> Result<(), Box<dyn std::error::Error>> {
                    let (stream, _) = listener.accept()?;
                    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
                    let result = server.accept(stream);
                    if !trusted {
                        assert!(result.is_err());
                        return Ok(());
                    }
                    let mut transport = result?;
                    assert_eq!(transport.host_key_algorithm(), "ssh-mldsa-65");
                    assert_eq!(transport.read_auth_packet()?, [5]);
                    transport.write_payload(&[52])?;
                    assert_eq!(transport.read_auth_packet()?, [5, 1]);
                    transport.write_payload(&[52])?;
                    transport.rekey()?;
                    transport.write_payload(&[52])?;
                    Ok(())
                };
                run().map_err(|error| error.to_string())
            });
            let stream = TcpStream::connect(address)?;
            stream.set_read_timeout(Some(Duration::from_secs(15)))?;
            stream.set_write_timeout(Some(Duration::from_secs(15)))?;
            let result = ClientConfig::new()
                .with_mldsa_host_keys()
                .connect_with_host_keys(stream, |key| {
                    assert!(matches!(key, HostPublicKey::Mldsa(_)));
                    assert_eq!(key.to_blob().unwrap(), expected);
                    if trusted { Ok(()) } else { Err(()) }
                });
            if trusted {
                let mut client = result?;
                let sid = client.session_id().to_vec();
                client.write_payload(&[5])?;
                assert_eq!(client.read_payload()?, [52]);
                client.rekey()?;
                client.write_payload(&[5, 1])?;
                assert_eq!(client.read_payload()?, [52]);
                assert_eq!(client.read_payload()?, [52]);
                assert_eq!(client.session_id(), sid);
            } else {
                assert!(result.is_err());
            }
            thread.join().map_err(|_| "server panicked")??;
        }
    }
    Ok(())
}
