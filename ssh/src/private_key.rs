//! Explicit in-memory identity import. No files, default paths, or key export.
//!
//! PKCS#8 input here is unencrypted DER. Encrypted OpenSSH binary containers
//! retain the existing bcrypt/AES-256-CTR parser and passphrase-wiping contract.
use crate::auth::{AuthError, PublicKeySigner, RsaAuthSigner};
use crate::ecdsa_hostkey::{EcdsaP384Signer, EcdsaP521Signer, EcdsaSigner};
use crate::hostkey::Ed25519Signer;
use zeroize::{Zeroize, Zeroizing};

/// Maximum PKCS#8 DER input length; checked before decoding private material.
pub const MAX_PRIVATE_KEY_DER: usize = 1024 * 1024;

/// Imports an unencrypted PKCS#8 DER identity for Ed25519, RSA, or NIST
/// P-256/P-384/P-521. No algorithm fallback occurs after a successful decode.
/// The caller owns and must protect/wipe the input buffer; temporary private
/// scalar copies are wiped. The returned signer has redacted Debug output.
///
/// # Errors
/// Returns only `AuthError::InvalidKey` for unsupported, encrypted, oversized,
/// or malformed input. Decoder diagnostics never expose input/key material.
pub fn import_pkcs8_der(bytes: &[u8]) -> Result<PublicKeySigner, AuthError> {
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    use rsa::pkcs8::DecodePrivateKey as _;
    if bytes.is_empty() || bytes.len() > MAX_PRIVATE_KEY_DER {
        return Err(AuthError::InvalidKey);
    }
    if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_der(bytes) {
        let mut seed = Zeroizing::new(key.to_bytes());
        return Ok(PublicKeySigner::ed25519(Ed25519Signer::from_seed(
            &mut seed,
        )));
    }
    if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(bytes) {
        return RsaAuthSigner::from_private_key(key).map(PublicKeySigner::rsa);
    }
    if let Ok(key) = p256::SecretKey::from_pkcs8_der(bytes) {
        let mut scalar = key.to_bytes();
        let signer = EcdsaSigner::from_slice(&scalar).map(PublicKeySigner::ecdsa);
        scalar.zeroize();
        return signer.map_err(|_| AuthError::InvalidKey);
    }
    if let Ok(key) = p384::SecretKey::from_pkcs8_der(bytes) {
        let mut scalar = key.to_bytes();
        let signer = EcdsaP384Signer::from_slice(&scalar).map(PublicKeySigner::ecdsa_p384);
        scalar.zeroize();
        return signer.map_err(|_| AuthError::InvalidKey);
    }
    if let Ok(key) = p521::SecretKey::from_pkcs8_der(bytes) {
        let mut scalar = key.to_bytes();
        let signer = EcdsaP521Signer::from_slice(&scalar).map(PublicKeySigner::ecdsa_p521);
        scalar.zeroize();
        return signer.map_err(|_| AuthError::InvalidKey);
    }
    Err(AuthError::InvalidKey)
}

/// Imports one binary OpenSSH Ed25519, RSA, or P-256 identity into userauth.
/// Unencrypted and bcrypt/AES-256-CTR containers share the existing parser.
/// The mutable passphrase is wiped on success and failure. No disk is read.
///
/// # Errors
/// Returns a redacted invalid-key error for an unsupported container/key,
/// malformed data, or a wrong passphrase. Use `openssh_key` directly if the
/// application needs its finer, still non-sensitive parser error categories.
pub fn import_openssh(bytes: &[u8], passphrase: &mut [u8]) -> Result<PublicKeySigner, AuthError> {
    use crate::openssh_key::OpenSshPrivateKey;
    let key = crate::openssh_key::parse_openssh_private_key(bytes, passphrase)
        .map_err(|_| AuthError::InvalidKey)?;
    match key {
        OpenSshPrivateKey::Ed25519 { mut seed, .. } => Ok(PublicKeySigner::ed25519(
            Ed25519Signer::from_seed(&mut seed),
        )),
        OpenSshPrivateKey::Ecdsa { secret, .. } => EcdsaSigner::from_slice(secret.as_slice())
            .map(PublicKeySigner::ecdsa)
            .map_err(|_| AuthError::InvalidKey),
        OpenSshPrivateKey::Rsa { p, q, e, .. } => RsaAuthSigner::from_p_q(
            rsa::BigUint::from_bytes_be(&p),
            rsa::BigUint::from_bytes_be(&q),
            rsa::BigUint::from_bytes_be(&e),
        )
        .map(PublicKeySigner::rsa),
    }
}
