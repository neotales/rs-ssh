//! OpenSSH sntrup761 + X25519 hybrid with SHA-512 and string-encoded K.
use super::{KexError, SharedSecret};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use p256::elliptic_curve::rand_core::{TryCryptoRng, TryRng};
use sha2::{Digest, Sha512};
use sntrup_kem::sntrup761::{self, Ciphertext, DecapsulationKey, EncapsulationKey};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub(crate) const NAME: &str = "sntrup761x25519-sha512@openssh.com";
pub(crate) const CLIENT_LEN: usize = 1158 + 32;
pub(crate) const SERVER_LEN: usize = 1039 + 32;

// A fresh, explicitly fallible seed per operation. ChaCha state wipes on drop.
// No thread RNG, hidden environment lookup or infallible OS entropy call.
struct Random(chacha20::ChaCha20);
impl Random {
    fn new() -> Result<Self, KexError> {
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| KexError::EntropyFailure)?;
        Ok(Self(chacha20::ChaCha20::new(
            (&*seed).into(),
            (&[0; 12]).into(),
        )))
    }
}
impl TryRng for Random {
    type Error = std::convert::Infallible;
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
        dst.fill(0);
        self.0.apply_keystream(dst);
        Ok(())
    }
}
impl TryCryptoRng for Random {}

fn xsecret() -> Result<StaticSecret, KexError> {
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| KexError::EntropyFailure)?;
    Ok(StaticSecret::from(*seed))
}
fn combine(kem: &[u8], x: &StaticSecret, peer: &[u8]) -> Result<SharedSecret, KexError> {
    let peer = <[u8; 32]>::try_from(peer).map_err(|_| KexError::InvalidPublicKey)?;
    let xshared = x.diffie_hellman(&PublicKey::from(peer));
    if !xshared.was_contributory() {
        return Err(KexError::NonContributorySecret);
    }
    let mut material = Zeroizing::new(Vec::with_capacity(64));
    material.extend_from_slice(kem);
    material.extend_from_slice(xshared.as_bytes());
    let digest = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(&*material)));
    SharedSecret::from_raw_string(&*digest)
}

pub(crate) struct Client {
    key: DecapsulationKey,
    x: StaticSecret,
    pub(crate) public: Vec<u8>,
}
impl Client {
    pub(crate) fn new() -> Result<Self, KexError> {
        let (public, key) = sntrup761::generate_key(&mut Random::new()?);
        let x = xsecret()?;
        let mut value = Vec::with_capacity(CLIENT_LEN);
        value.extend_from_slice(public.as_ref());
        value.extend_from_slice(PublicKey::from(&x).as_bytes());
        Ok(Self {
            key,
            x,
            public: value,
        })
    }
    pub(crate) fn complete(self, peer: &[u8]) -> Result<SharedSecret, KexError> {
        if peer.len() != SERVER_LEN {
            return Err(KexError::InvalidPublicKey);
        }
        let ct = Ciphertext::try_from(&peer[..1039]).map_err(|_| KexError::InvalidPublicKey)?;
        let kem = self.key.decapsulate(&ct);
        combine(kem.as_ref(), &self.x, &peer[1039..])
    }
}

pub(crate) fn respond(peer: &[u8]) -> Result<(Vec<u8>, SharedSecret), KexError> {
    if peer.len() != CLIENT_LEN {
        return Err(KexError::InvalidPublicKey);
    }
    let key = EncapsulationKey::try_from(&peer[..1158]).map_err(|_| KexError::InvalidPublicKey)?;
    let x = xsecret()?;
    // Reject non-contributory X25519 before the more expensive encapsulation.
    let public = <[u8; 32]>::try_from(&peer[1158..]).map_err(|_| KexError::InvalidPublicKey)?;
    if !x
        .diffie_hellman(&PublicKey::from(public))
        .was_contributory()
    {
        return Err(KexError::NonContributorySecret);
    }
    let (ct, kem) = key.encapsulate(&mut Random::new()?);
    let shared = combine(kem.as_ref(), &x, &peer[1158..])?;
    let mut value = Vec::with_capacity(SERVER_LEN);
    value.extend_from_slice(ct.as_ref());
    value.extend_from_slice(PublicKey::from(&x).as_bytes());
    Ok((value, shared))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sntrup_lengths_low_order_and_ciphertext_tampering() {
        for length in [0, CLIENT_LEN - 1, CLIENT_LEN + 1] {
            assert!(respond(&vec![0; length]).is_err());
        }
        let client = Client::new().unwrap();
        let mut public = client.public.clone();
        public[1158..].fill(0);
        assert!(matches!(
            respond(&public),
            Err(KexError::NonContributorySecret)
        ));
        for length in [0, SERVER_LEN - 1, SERVER_LEN + 1] {
            assert!(Client::new().unwrap().complete(&vec![0; length]).is_err());
        }
        let (mut response, server_secret) = respond(&client.public).unwrap();
        response[0] ^= 1;
        // The KEM uses implicit rejection. The resulting different exchange
        // hash makes the real host signature fail, not a stub acceptance.
        let client_secret = client.complete(&response).unwrap();
        assert_ne!(client_secret.as_bytes(), server_secret.as_bytes());
        let client = Client::new().unwrap();
        let (mut response, _) = respond(&client.public).unwrap();
        response[1039..].fill(0);
        assert!(matches!(
            client.complete(&response),
            Err(KexError::NonContributorySecret)
        ));
    }
}
