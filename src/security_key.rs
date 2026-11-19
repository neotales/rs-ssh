//! Callback-only OpenSSH security-key signing, verification and enrollment.

use crate::hostkey::HostKeyError;
use neotales_ssh::{Reader, Writer};
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
        let (public_key, application) = parse_key(algorithm, blob)?;
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
        let signed_data = signed_preimage(application, message, flags, counter)?;
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

pub(crate) fn parse_key<'a>(
    algorithm: &str,
    blob: &'a [u8],
) -> Result<(&'a [u8], &'a [u8]), HostKeyError> {
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
    Ok((public_key, application))
}

fn signed_preimage(
    application: &[u8],
    message: &[u8],
    flags: u8,
    counter: u32,
) -> Result<[u8; 69], HostKeyError> {
    if flags & !0x05 != 0 {
        return Err(HostKeyError::InvalidSignature);
    }
    let mut bytes = [0; 69];
    bytes[..32].copy_from_slice(&Sha256::digest(application));
    bytes[32] = flags;
    bytes[33..37].copy_from_slice(&counter.to_be_bytes());
    bytes[37..].copy_from_slice(&Sha256::digest(message));
    Ok(bytes)
}

/// Borrowed signing request. The callback owns all signing and counter state.
/// Sign exactly `signed_data(flags, counter)`, not `message` directly.
pub struct Signing<'a> {
    /// Exact SSH algorithm.
    pub algorithm: &'static str,
    /// Exact public key's application.
    pub application: &'a [u8],
    /// Opaque caller-supplied handle, never interpreted or printed.
    pub handle: &'a [u8],
    /// SSH message, hashed by `signed_data`.
    pub message: &'a [u8],
}

impl Signing<'_> {
    /// Builds the PROTOCOL.u2f preimage with caller-selected flags and counter.
    ///
    /// # Errors
    /// Unknown flag bits return `InvalidSignature`.
    pub fn signed_data(&self, flags: u8, counter: u32) -> Result<[u8; 69], HostKeyError> {
        signed_preimage(self.application, self.message, flags, counter)
    }
}

/// Caller-produced signature and the exact metadata it signed.
#[derive(Debug)]
pub struct Signature {
    /// Raw 64-byte Ed25519 signature, or SSH mpints r/s for P-256 (not DER).
    pub bytes: Vec<u8>,
    /// Authenticator flags; only 0x01 and 0x04 are defined.
    pub flags: u8,
    /// Caller-owned replay counter.
    pub counter: u32,
}

type SignCallback = dyn Fn(&Signing<'_>) -> Option<Signature> + Send + Sync;

/// Explicit signing capability containing only public material and a handle.
/// Calls are synchronous and may overlap; callbacks own serialization, signing
/// and replay state. Denial or panic never falls back to another key.
pub struct SecurityKeySigner {
    algorithm: &'static str,
    blob: Vec<u8>,
    handle: Vec<u8>,
    callback: Arc<SignCallback>,
}

impl SecurityKeySigner {
    /// Installs a signer for a structurally valid SK public blob and opaque handle.
    ///
    /// # Errors
    /// Rejects unsupported/malformed keys and handles over 1024 bytes. No I/O.
    pub fn new(
        blob: Vec<u8>,
        handle: Vec<u8>,
        callback: impl Fn(&Signing<'_>) -> Option<Signature> + Send + Sync + 'static,
    ) -> Result<Self, HostKeyError> {
        let mut reader = Reader::new(&blob);
        let algorithm = match reader.read_string()? {
            name if name == ED25519.as_bytes() => ED25519,
            name if name == ECDSA.as_bytes() => ECDSA,
            _ => return Err(HostKeyError::UnsupportedAlgorithm),
        };
        parse_key(algorithm, &blob)?;
        if handle.len() > 1024 {
            return Err(HostKeyError::InvalidPublicKey);
        }
        Ok(Self {
            algorithm,
            blob,
            handle,
            callback: Arc::new(callback),
        })
    }

    /// Exact SSH algorithm for this key.
    #[must_use]
    pub fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    /// Exact validated SSH public-key blob.
    #[must_use]
    pub fn public_key_blob(&self) -> &[u8] {
        &self.blob
    }

    /// Invokes the callback and builds an SSH signature including flags/counter.
    ///
    /// # Errors
    /// Rejects denial, panic or malformed signatures. This does not cryptographically
    /// verify the callback's result or access any private key or device.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, HostKeyError> {
        let (_, application) = parse_key(self.algorithm, &self.blob)?;
        let request = Signing {
            algorithm: self.algorithm,
            application,
            handle: &self.handle,
            message,
        };
        let result = catch_unwind(AssertUnwindSafe(|| (self.callback)(&request)))
            .map_err(|_| HostKeyError::VerifierPanicked)?
            .ok_or(HostKeyError::InvalidSignature)?;
        let mut writer = Writer::new();
        writer.write_string(self.algorithm)?;
        writer.write_string(&result.bytes)?;
        writer.write_byte(result.flags);
        writer.write_uint32(result.counter);
        let blob = writer.into_bytes();
        // Reuse the exact verifier framing checks; this callback checks no crypto.
        SecurityKeyVerifier::new(|_| true).verify(self.algorithm, &self.blob, &blob, message)?;
        Ok(blob)
    }
}

/// Public result of caller-owned resident enrollment. No private key is stored.
pub struct EnrolledKey {
    /// SSH SK public-key blob, including the requested application.
    pub public_key_blob: Vec<u8>,
    /// Opaque handle returned to the caller; never interpreted by the library.
    pub handle: Vec<u8>,
}

type EnrollmentCallback = dyn Fn(&str, &[u8]) -> Option<EnrolledKey> + Send + Sync;

/// Default-deny resident enrollment capability. No request or I/O occurs without
/// an installed callback. Repeated calls are independent enrollment requests;
/// the caller owns their side effects and any deduplication.
#[derive(Default)]
pub struct ResidentKeyEnrollment(Option<Arc<EnrollmentCallback>>);

impl fmt::Debug for Signing<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signing")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SecurityKeySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityKeySigner")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for EnrolledKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrolledKey(..)")
    }
}

impl fmt::Debug for ResidentKeyEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResidentKeyEnrollment")
            .field("enabled", &self.0.is_some())
            .finish()
    }
}

impl ResidentKeyEnrollment {
    /// Installs synchronous caller-owned enrollment; callbacks may overlap.
    pub fn new(
        callback: impl Fn(&str, &[u8]) -> Option<EnrolledKey> + Send + Sync + 'static,
    ) -> Self {
        Self(Some(Arc::new(callback)))
    }

    /// Requests one resident key through the callback, never through a device or
    /// credential file.
    ///
    /// # Errors
    /// Rejects missing callback, denial, panic, mismatched keys,
    /// unsupported algorithms and handles over 1024 bytes. No rollback is promised
    /// if a callback enrolls a key but returns an invalid result.
    pub fn enroll(&self, algorithm: &str, application: &[u8]) -> Result<EnrolledKey, HostKeyError> {
        if !supported(algorithm) {
            return Err(HostKeyError::UnsupportedAlgorithm);
        }
        let callback = self.0.as_ref().ok_or(HostKeyError::UnsupportedAlgorithm)?;
        let key = catch_unwind(AssertUnwindSafe(|| callback(algorithm, application)))
            .map_err(|_| HostKeyError::VerifierPanicked)?
            .ok_or(HostKeyError::InvalidPublicKey)?;
        let (_, actual_application) = parse_key(algorithm, &key.public_key_blob)?;
        if actual_application != application || key.handle.len() > 1024 {
            return Err(HostKeyError::InvalidPublicKey);
        }
        Ok(key)
    }
}

pub(crate) fn supported(name: &str) -> bool {
    matches!(name, ED25519 | ECDSA)
}
