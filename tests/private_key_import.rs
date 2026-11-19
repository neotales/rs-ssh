//! Caller-owned PKCS#8 identity import; no key files or external commands.
use neotales_ssh::{
    auth::{PublicKeySigner, RsaAuthSigner},
    ecdsa_hostkey::{EcdsaP384Signer, EcdsaP521Signer, EcdsaSigner},
    hostkey::Ed25519Signer,
    private_key::import_pkcs8_der,
};

#[test]
fn pkcs8_imports_ed25519_rsa_and_all_implemented_nist_curves()
-> Result<(), Box<dyn std::error::Error>> {
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;
    use rsa::pkcs8::EncodePrivateKey as _;
    let ed = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let imported = import_pkcs8_der(ed.to_pkcs8_der()?.as_bytes())?;
    assert_eq!(
        imported.public_key_blob()?,
        Ed25519Signer::from_seed(&mut [11; 32]).public_key_blob()?
    );
    let rsa = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024)?;
    let imported = import_pkcs8_der(rsa.to_pkcs8_der()?.as_bytes())?;
    assert_eq!(
        imported.public_key_blob()?,
        RsaAuthSigner::from_private_key(rsa)?.public_key_blob()
    );
    let p256 = p256::SecretKey::from_slice(&[11; 32])?;
    let imported = import_pkcs8_der(p256.to_pkcs8_der()?.as_bytes())?;
    assert_eq!(imported.algorithm(), "ecdsa-sha2-nistp256");
    assert_eq!(
        imported.public_key_blob()?,
        EcdsaSigner::from_private_bytes([11; 32])?.public_key_blob()?
    );
    let p384 = p384::SecretKey::from_slice(&[11; 48])?;
    let imported = import_pkcs8_der(p384.to_pkcs8_der()?.as_bytes())?;
    assert_eq!(imported.algorithm(), "ecdsa-sha2-nistp384");
    assert_eq!(
        imported.public_key_blob()?,
        EcdsaP384Signer::from_private_bytes([11; 48])?.public_key_blob()?
    );
    let mut scalar = [0; 66];
    scalar[65] = 11;
    let p521 = p521::SecretKey::from_slice(&scalar)?;
    let imported = import_pkcs8_der(p521.to_pkcs8_der()?.as_bytes())?;
    assert_eq!(imported.algorithm(), "ecdsa-sha2-nistp521");
    assert_eq!(
        imported.public_key_blob()?,
        EcdsaP521Signer::from_private_bytes(scalar)?.public_key_blob()?
    );
    Ok(())
}

#[test]
fn malformed_import_errors_are_fixed_and_redacted() {
    for input in [b"synthetic-not-a-key".as_slice(), b"", b"\x30\x81\xff"] {
        let error = import_pkcs8_der(input).expect_err("must reject malformed input");
        assert_eq!(format!("{error:?}"), "InvalidKey");
    }
    // Public signers do not expose private values in Debug.
    let signer = PublicKeySigner::ed25519(Ed25519Signer::from_seed(&mut [11; 32]));
    assert!(!format!("{signer:?}").contains("11, 11"));
}
