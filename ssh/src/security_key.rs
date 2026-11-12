//! Callback-only OpenSSH security-key verification; no device or key storage.

use crate::hostkey::HostKeyError;
use neotales_ssh::Reader;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

/// OpenSSH Ed25519 security-key algorithm.
pub const ED25519: &str = "sk-ssh-ed25519@openssh.com";
/// OpenSSH P-256 security-key algorithm.
pub const ECDSA: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

/// Borrowed, structurally checked PROTOCOL.u2f verification request.
/// The callback must cryptographically verify `signature` with `public_key`
/// over `signed_data`, and enforce its application, presence and counter policy.
/// ECDSA signatures contain SSH mpints r/s, not ASN.1 DER.
#[derive(Debug)]
pub struct Verification<'a> {
    /// Exact negotiated algorithm.
    pub algorithm: &'a str,
    /// Ed25519 bytes or uncompressed P-256 SEC1 point.
    pub public_key: &'a [u8],
    /// Application bytes from the public key (not a guessed default).
    pub application: &'a [u8],
    /// Signature bytes without the SSH outer string.
    pub signature: &'a [u8],
    /// Authenticator flags.
    pub flags: u8,
    /// Authenticator counter; replay policy belongs to the callback.
    pub counter: u32,
    /// SHA256(application) || flags || counter || SHA256(message).
    pub signed_data: [u8; 69],
}

type Callback = dyn Fn(&Verification<'_>) -> bool + Send + Sync;

/// Explicit verification capability. False or a panic denies the signature.
#[derive(Clone)]
pub struct SecurityKeyVerifier(Arc<Callback>);

impl fmt::Debug for SecurityKeyVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityKeyVerifier(..)")
    }
}

impl SecurityKeyVerifier {
    /// Installs caller-owned cryptographic verification and authenticator policy.
    pub fn new(callback: impl Fn(&Verification<'_>) -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(callback))
    }

    /// Parses exact OpenSSH framing and invokes the verifier only on valid input.
    /// Unknown extension flags are rejected: no SSH U2F extensions are defined.
    /// No USB device, private key, resident credential, or environment is accessed.
    ///
    /// # Errors
    /// Returns a bounded error on malformed input, denial or callback panic.
    pub fn verify(
        &self,
        algorithm: &str,
        blob: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), HostKeyError> {
        let mut key = Reader::new(blob);
        if !supported(algorithm) || key.read_string()? != algorithm.as_bytes() {
            return Err(HostKeyError::UnsupportedAlgorithm);
        }
        if algorithm == ECDSA && key.read_string()? != b"nistp256" {
            return Err(HostKeyError::InvalidPublicKey);
        }
        let public_key = key.read_string()?;
        if algorithm == ED25519 {
            let bytes =
                <&[u8; 32]>::try_from(public_key).map_err(|_| HostKeyError::InvalidPublicKey)?;
            ed25519_dalek::VerifyingKey::from_bytes(bytes)
                .map_err(|_| HostKeyError::InvalidPublicKey)?;
        } else if public_key.len() != 65
            || public_key[0] != 4
            || p256::PublicKey::from_sec1_bytes(public_key).is_err()
        {
            return Err(HostKeyError::InvalidPublicKey);
        }
        let application = key.read_string()?;
        if !key.is_empty() {
            return Err(HostKeyError::InvalidPublicKey);
        }
        let mut sig = Reader::new(signature);
        if sig.read_string()? != algorithm.as_bytes() {
            return Err(HostKeyError::UnsupportedAlgorithm);
        }
        let signature = sig.read_string()?;
        if algorithm == ED25519 {
            if signature.len() != 64 {
                return Err(HostKeyError::InvalidSignature);
            }
        } else {
            let mut parts = Reader::new(signature);
            for _ in 0..2 {
                let scalar = parts.read_mpint_magnitude()?;
                if scalar.is_empty() || scalar.len() > 32 {
                    return Err(HostKeyError::InvalidSignature);
                }
            }
            if !parts.is_empty() {
                return Err(HostKeyError::InvalidSignature);
            }
        }
        let flags = sig.read_byte()?;
        let counter = sig.read_uint32()?;
        if !sig.is_empty() || flags & !0x05 != 0 {
            return Err(HostKeyError::InvalidSignature);
        }
        let mut signed_data = [0; 69];
        signed_data[..32].copy_from_slice(&Sha256::digest(application));
        signed_data[32] = flags;
        signed_data[33..37].copy_from_slice(&counter.to_be_bytes());
        signed_data[37..].copy_from_slice(&Sha256::digest(message));
        let request = Verification {
            algorithm,
            public_key,
            application,
            signature,
            flags,
            counter,
            signed_data,
        };
        match catch_unwind(AssertUnwindSafe(|| (self.0)(&request))) {
            Ok(true) => Ok(()),
            Ok(false) => Err(HostKeyError::InvalidSignature),
            Err(_) => Err(HostKeyError::VerifierPanicked),
        }
    }
}

pub(crate) fn supported(name: &str) -> bool {
    matches!(name, ED25519 | ECDSA)
}
