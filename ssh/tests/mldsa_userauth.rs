//! In-memory draft-08 identities and Go-vendor certificates; no live ML-DSA peer.
use neotales_ssh::{
    ClientAuthMethod, ClientConfig, Reader, ServerAuthPolicy, ServerConfig, Writer,
    auth::PublicKeySigner,
    authenticate_client, authenticate_server,
    cert::{self, CertificateError, CertificateType, UserCertificateTrust},
    hostkey::Ed25519Signer,
    mldsa_hostkey::{Algorithm, MldsaSigner},
};
use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn signer(algorithm: Algorithm, seed: u8) -> MldsaSigner {
    MldsaSigner::from_seed(algorithm, &mut [seed; 32])
}

fn certificate(algorithm: Algorithm, mldsa_ca: bool) -> Result<Vec<u8>> {
    let name = match algorithm {
        Algorithm::MlDsa44 => cert::SSH_MLDSA44_CERT_V01,
        Algorithm::MlDsa65 => cert::SSH_MLDSA65_CERT_V01,
        Algorithm::MlDsa87 => cert::SSH_MLDSA87_CERT_V01,
    };
    let subject = signer(algorithm, 1).public_key().to_blob()?;
    let mut key = Reader::new(&subject);
    key.read_string()?;
    let mut principals = Writer::new();
    principals.write_string("alice")?;
    let mut writer = Writer::new();
    writer.write_string(name)?;
    writer.write_string(&[7; 32])?;
    writer.write_string(key.read_string()?)?;
    writer.write_uint64(1);
    writer.write_uint32(CertificateType::User.as_u32());
    writer.write_string("test")?;
    writer.write_string(principals.as_bytes())?;
    writer.write_uint64(100);
    writer.write_uint64(300);
    writer.write_string(b"")?;
    writer.write_string(b"")?;
    writer.write_string(b"")?;
    writer.write_string(&ca_blob(algorithm, mldsa_ca)?)?;
    let signature = if mldsa_ca {
        signer(algorithm, 2).sign(writer.as_bytes())?
    } else {
        Ed25519Signer::from_seed(&mut [2; 32]).sign_exchange_hash(writer.as_bytes())?
    };
    writer.write_string(&signature)?;
    Ok(writer.into_bytes())
}

fn ca_blob(algorithm: Algorithm, mldsa: bool) -> Result<Vec<u8>> {
    Ok(if mldsa {
        signer(algorithm, 2).public_key().to_blob()?
    } else {
        Ed25519Signer::from_seed(&mut [2; 32]).public_key_blob()?
    })
}

#[test]
fn all_parameter_sets_sign_and_verify_user_transcripts() -> Result<()> {
    for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87] {
        let identity = PublicKeySigner::mldsa(signer(algorithm, 1));
        assert_eq!(identity.algorithm(), algorithm.name());
        let public =
            neotales_ssh::mldsa_hostkey::MldsaPublicKey::from_blob(&identity.public_key_blob()?)?;
        let transcript = b"explicit-session-id and RFC 4252 request prefix";
        let signature = signer(algorithm, 1).sign(transcript)?;
        public.verify(&signature, transcript)?;
        assert!(public.verify(&signature, b"different session").is_err());
        assert!(
            signer(algorithm, 2)
                .public_key()
                .verify(&signature, transcript)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn certificates_check_signature_principal_and_explicit_time_for_all_sets() -> Result<()> {
    for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87] {
        for mldsa_ca in [false, true] {
            let blob = certificate(algorithm, mldsa_ca)?;
            let ca = ca_blob(algorithm, mldsa_ca)?;
            let verify = |bytes: &[u8], principal, now| {
                cert::verify_certificate(bytes, CertificateType::User, principal, now, &[], &ca)
            };
            let verified = verify(&blob, "alice", 100)?;
            verify(&blob, "alice", 299)?;
            assert_eq!(
                verified.subject_public_key_blob(),
                signer(algorithm, 1).public_key().to_blob()?
            );
            assert_eq!(
                verify(&blob, "alice", 99),
                Err(CertificateError::NotYetValid)
            );
            assert_eq!(verify(&blob, "alice", 300), Err(CertificateError::Expired));
            assert_eq!(
                verify(&blob, "bob", 200),
                Err(CertificateError::PrincipalMismatch)
            );
            assert_eq!(
                cert::verify_certificate(&blob, CertificateType::Host, "alice", 200, &[], &ca),
                Err(CertificateError::TypeMismatch)
            );
            let untrusted = signer(algorithm, 3).public_key().to_blob()?;
            assert_eq!(
                cert::verify_certificate(
                    &blob,
                    CertificateType::User,
                    "alice",
                    200,
                    &[],
                    &untrusted
                ),
                Err(CertificateError::SignatureKeyMismatch)
            );
            let mut damaged = blob.clone();
            *damaged.last_mut().ok_or("signature missing")? ^= 1;
            assert!(verify(&damaged, "alice", 200).is_err());
            let mut trailing = blob.clone();
            trailing.push(0);
            assert!(verify(&trailing, "alice", 200).is_err());
            PublicKeySigner::mldsa_certificate(signer(algorithm, 1), &blob)?;
            assert!(PublicKeySigner::mldsa_certificate(signer(algorithm, 2), &blob).is_err());
        }
    }
    Ok(())
}

fn authenticate(
    cert: bool,
    opt_in: bool,
    now: u64,
    principal: &'static str,
    extension_info: bool,
) -> Result<bool> {
    let algorithm = Algorithm::MlDsa65;
    let identity = if cert {
        PublicKeySigner::mldsa_certificate(signer(algorithm, 1), &certificate(algorithm, true)?)?
    } else {
        PublicKeySigner::mldsa(signer(algorithm, 1))
    };
    let name = identity.algorithm();
    let blob = identity.public_key_blob()?;
    let ca = ca_blob(algorithm, true)?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let server = std::thread::spawn(move || -> std::result::Result<bool, String> {
        let run = || -> Result<bool> {
            let mut policy = ServerAuthPolicy::new(4)?;
            if cert {
                policy = policy.with_user_certificate_trust(UserCertificateTrust::new(
                    &ca,
                    move || now,
                    move |_, _| Some(principal.to_owned()),
                ));
            } else {
                policy = policy.with_authorized_key(&blob)?;
            }
            if opt_in {
                policy = policy.with_signature_algorithms(&[name])?;
            }
            let (stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut transport =
                ServerConfig::new(Ed25519Signer::from_seed(&mut [3; 32])).accept(stream)?;
            let _result = authenticate_server(&mut transport, &policy);
            Ok(transport.is_authenticated())
        };
        run().map_err(|error| error.to_string())
    });
    let stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let config = if extension_info {
        ClientConfig::new().with_extension_info()
    } else {
        ClientConfig::new()
    };
    let mut client = config.connect(stream, |_| Ok::<(), ()>(()))?;
    let accepted = authenticate_client(
        &mut client,
        "alice",
        &[ClientAuthMethod::public_key(identity)],
        4,
    )
    .is_ok();
    drop(client);
    assert_eq!(server.join().map_err(|_| "server panicked")??, accepted);
    Ok(accepted)
}

#[test]
fn mldsa65_userauth_requires_explicit_server_opt_in() -> Result<()> {
    assert!(authenticate(false, true, 200, "alice", true)?);
    assert!(!authenticate(false, false, 200, "alice", true)?);
    // Without server-sig-algs the server still denies an unsolicited request.
    assert!(!authenticate(false, false, 200, "alice", false)?);
    Ok(())
}

#[test]
fn mldsa65_certificate_userauth_requires_opt_in_and_trust_checks() -> Result<()> {
    assert!(authenticate(true, true, 200, "alice", true)?);
    assert!(!authenticate(true, false, 200, "alice", true)?);
    assert!(!authenticate(true, true, 300, "alice", true)?);
    assert!(!authenticate(true, true, 99, "alice", true)?);
    assert!(!authenticate(true, true, 200, "bob", true)?);
    Ok(())
}
