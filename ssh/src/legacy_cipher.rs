//! Deprecated SSH ciphers. Only reached through explicitly enabled proposals.
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use zeroize::Zeroizing;

use super::{CipherAlgorithm, PacketProtectionError};

#[derive(Clone)]
pub(super) enum LegacyCipher {
    Aes128(aes::Aes128, Zeroizing<[u8; 16]>),
    Aes256(aes::Aes256, Zeroizing<[u8; 16]>),
    Des(des::TdesEde3, Zeroizing<[u8; 8]>),
}

impl LegacyCipher {
    pub(super) fn new(
        algorithm: CipherAlgorithm,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Self, PacketProtectionError> {
        let invalid = || PacketProtectionError::InvalidKeyMaterial;
        Ok(match algorithm {
            CipherAlgorithm::Aes128Cbc => Self::Aes128(
                aes::Aes128::new_from_slice(key).map_err(|_| invalid())?,
                Zeroizing::new(iv.try_into().map_err(|_| invalid())?),
            ),
            CipherAlgorithm::Aes256Cbc => Self::Aes256(
                aes::Aes256::new_from_slice(key).map_err(|_| invalid())?,
                Zeroizing::new(iv.try_into().map_err(|_| invalid())?),
            ),
            CipherAlgorithm::DesCbc => Self::Des(
                des::TdesEde3::new_from_slice(key).map_err(|_| invalid())?,
                Zeroizing::new(iv.try_into().map_err(|_| invalid())?),
            ),
            _ => return Err(invalid()),
        })
    }

    pub(super) fn apply(
        &mut self,
        data: &mut [u8],
        encrypt: bool,
    ) -> Result<(), PacketProtectionError> {
        // SSH CBC chains across packets, with no PKCS#7 padding. The caller
        // speculates on a cloned state until authentication/framing succeeds.
        macro_rules! cbc {
            ($cipher:expr, $iv:expr, $size:expr) => {{
                if data.len() % $size != 0 {
                    return Err(PacketProtectionError::InvalidAlignment);
                }
                for block in data.chunks_exact_mut($size) {
                    let saved = Zeroizing::new(
                        <[u8; $size]>::try_from(&*block)
                            .map_err(|_| PacketProtectionError::InvalidAlignment)?,
                    );
                    if encrypt {
                        for (byte, previous) in block.iter_mut().zip($iv.iter()) {
                            *byte ^= previous;
                        }
                        $cipher.encrypt_block(
                            block
                                .try_into()
                                .map_err(|_| PacketProtectionError::InvalidAlignment)?,
                        );
                        $iv.copy_from_slice(block);
                    } else {
                        $cipher.decrypt_block(
                            block
                                .try_into()
                                .map_err(|_| PacketProtectionError::InvalidAlignment)?,
                        );
                        for (byte, previous) in block.iter_mut().zip($iv.iter()) {
                            *byte ^= previous;
                        }
                        $iv.copy_from_slice(saved.as_slice());
                    }
                }
            }};
        }
        match self {
            Self::Aes128(cipher, iv) => cbc!(cipher, iv, 16),
            Self::Aes256(cipher, iv) => cbc!(cipher, iv, 16),
            Self::Des(cipher, iv) => cbc!(cipher, iv, 8),
        }
        Ok(())
    }
}
