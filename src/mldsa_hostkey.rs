//! Pure ML-DSA host keys from draft-sfluhrer-ssh-mldsa-08 §§3, 4, 7.
//! Both key and signature blobs contain SSH string algorithm, string raw bytes.
//! Signing is deterministic FIPS 204 with empty context, not HashML-DSA.
//! Source: <https://www.ietf.org/archive/id/draft-sfluhrer-ssh-mldsa-08.txt>.

use crate::{Reader, Writer, hostkey::HostKeyError};
use ml_dsa::{Keypair, MlDsa44, MlDsa65, MlDsa87, Signer, Verifier};
use zeroize::Zeroizing;

/// Draft ML-DSA parameter set; never proposed by default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// ML-DSA-44: 1312-byte public key, 2420-byte signature.
    MlDsa44,
    /// ML-DSA-65: 1952-byte public key, 3309-byte signature.
    MlDsa65,
    /// ML-DSA-87: 2592-byte public key, 4627-byte signature.
    MlDsa87,
}

impl Algorithm {
    /// Exact SSH draft-08 identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ssh-mldsa-44",
            Self::MlDsa65 => "ssh-mldsa-65",
            Self::MlDsa87 => "ssh-mldsa-87",
        }
    }

    /// Parses only the three exact draft identifiers.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ssh-mldsa-44" => Some(Self::MlDsa44),
            "ssh-mldsa-65" => Some(Self::MlDsa65),
            "ssh-mldsa-87" => Some(Self::MlDsa87),
            _ => None,
        }
    }

    /// Raw public-key length from draft-08 §3.
    #[must_use]
    pub const fn public_key_length(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Raw signature length from draft-08 §4.
    #[must_use]
    pub const fn signature_length(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
}

/// A length-checked draft ML-DSA public key. Trust is a separate caller decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MldsaPublicKey {
    algorithm: Algorithm,
    raw: Vec<u8>,
}

impl MldsaPublicKey {
    /// Parses the exact bounded public-key framing, rejecting trailing data.
    ///
    /// # Errors
    /// Rejects unknown names, incorrect sizes or malformed SSH strings.
    pub fn from_blob(blob: &[u8]) -> Result<Self, HostKeyError> {
        let mut reader = Reader::new(blob);
        let name = std::str::from_utf8(reader.read_string_with_limit(32)?)
            .map_err(|_| HostKeyError::UnsupportedAlgorithm)?;
        let algorithm = Algorithm::from_name(name).ok_or(HostKeyError::UnsupportedAlgorithm)?;
        let raw = reader.read_string_with_limit(algorithm.public_key_length())?;
        if raw.len() != algorithm.public_key_length() {
            return Err(HostKeyError::InvalidPublicKey);
        }
        if !reader.is_empty() {
            return Err(HostKeyError::TrailingData);
        }
        Ok(Self {
            algorithm,
            raw: raw.to_vec(),
        })
    }

    /// Returns this public key's parameter set.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Encodes the draft's two SSH strings.
    ///
    /// # Errors
    /// Returns an error if bounded wire encoding fails.
    pub fn to_blob(&self) -> Result<Vec<u8>, HostKeyError> {
        frame(self.algorithm, &self.raw)
    }

    /// Verifies pure ML-DSA with empty context using `RustCrypto`, including
    /// deterministic and hedged FIPS 204 signatures. Checks the name and exact
    /// signature length before signature decoding or cryptographic verification.
    ///
    /// # Errors
    /// Denies malformed, cross-algorithm or invalid signatures.
    pub fn verify(&self, signature: &[u8], message: &[u8]) -> Result<(), HostKeyError> {
        let mut reader = Reader::new(signature);
        if reader.read_string_with_limit(32)? != self.algorithm.name().as_bytes() {
            return Err(HostKeyError::UnsupportedAlgorithm);
        }
        let raw = reader.read_string_with_limit(self.algorithm.signature_length())?;
        if raw.len() != self.algorithm.signature_length() {
            return Err(HostKeyError::InvalidSignature);
        }
        if !reader.is_empty() {
            return Err(HostKeyError::TrailingData);
        }
        match self.algorithm {
            Algorithm::MlDsa44 => verify::<MlDsa44>(&self.raw, raw, message),
            Algorithm::MlDsa65 => verify::<MlDsa65>(&self.raw, raw, message),
            Algorithm::MlDsa87 => verify::<MlDsa87>(&self.raw, raw, message),
        }
    }
}

fn verify<P: ml_dsa::MlDsaParams>(
    public: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), HostKeyError> {
    let encoded = ml_dsa::EncodedVerifyingKey::<P>::try_from(public)
        .map_err(|_| HostKeyError::InvalidPublicKey)?;
    let public = ml_dsa::VerifyingKey::<P>::decode(&encoded);
    let signature =
        ml_dsa::Signature::<P>::try_from(signature).map_err(|_| HostKeyError::InvalidSignature)?;
    // Verifier's documented context is empty; it is the pure ML-DSA API.
    public
        .verify(message, &signature)
        .map_err(|_| HostKeyError::InvalidSignature)
}

enum Key {
    MlDsa44(ml_dsa::SigningKey<MlDsa44>),
    MlDsa65(ml_dsa::SigningKey<MlDsa65>),
    MlDsa87(ml_dsa::SigningKey<MlDsa87>),
}

/// Explicit in-memory ML-DSA signer; zeroizes its secret state on drop.
/// No key discovery, file access, or default proposal is introduced.
pub struct MldsaSigner {
    key: Key,
    public: MldsaPublicKey,
}

impl std::fmt::Debug for MldsaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MldsaSigner(..)")
    }
}

impl MldsaSigner {
    /// Derives a key from an explicit 32-byte FIPS 204 seed, wiping the input.
    #[must_use]
    pub fn from_seed(algorithm: Algorithm, seed: &mut [u8; 32]) -> Self {
        use zeroize::Zeroize;
        let seed_copy = Zeroizing::new(ml_dsa::Seed::from(*seed));
        seed.zeroize();
        let (key, raw) = match algorithm {
            Algorithm::MlDsa44 => {
                let key = ml_dsa::SigningKey::<MlDsa44>::from_seed(&seed_copy);
                let raw = key.verifying_key().encode().to_vec();
                (Key::MlDsa44(key), raw)
            }
            Algorithm::MlDsa65 => {
                let key = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed_copy);
                let raw = key.verifying_key().encode().to_vec();
                (Key::MlDsa65(key), raw)
            }
            Algorithm::MlDsa87 => {
                let key = ml_dsa::SigningKey::<MlDsa87>::from_seed(&seed_copy);
                let raw = key.verifying_key().encode().to_vec();
                (Key::MlDsa87(key), raw)
            }
        };
        Self {
            key,
            public: MldsaPublicKey { algorithm, raw },
        }
    }

    /// Returns the signer's public key without exposing secret state.
    #[must_use]
    pub const fn public_key(&self) -> &MldsaPublicKey {
        &self.public
    }

    /// Signs a message (an SSH exchange hash for host-key use) with pure ML-DSA,
    /// deterministic randomness and empty context, then emits draft SSH framing.
    ///
    /// # Errors
    /// Returns a bounded error on signing or wire failure.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, HostKeyError> {
        let raw = match &self.key {
            Key::MlDsa44(key) => key.try_sign(message).map(|sig| sig.encode().to_vec()),
            Key::MlDsa65(key) => key.try_sign(message).map(|sig| sig.encode().to_vec()),
            Key::MlDsa87(key) => key.try_sign(message).map(|sig| sig.encode().to_vec()),
        }
        .map_err(|_| HostKeyError::SigningFailed)?;
        frame(self.public.algorithm, &raw)
    }
}

fn frame(algorithm: Algorithm, raw: &[u8]) -> Result<Vec<u8>, HostKeyError> {
    let mut writer = Writer::new();
    writer.write_string(algorithm.name())?;
    writer.write_string(raw)?;
    Ok(writer.into_bytes())
}
