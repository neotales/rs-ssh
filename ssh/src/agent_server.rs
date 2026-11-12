//! Bounded in-process RFC 9987 keyring. No listener, service, or disk access.
//! Keys remain resident while locked: lock is an operation gate, not memory
//! encryption or a defense against an attacker reading this process's memory.
use crate::{
    Reader, Writer,
    agent::{AgentError, MAX_FRAME_SIZE},
    auth::PublicKeySigner,
};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Maximum resident agent identities.
pub const MAX_AGENT_IDENTITIES: usize = 64;
struct Identity {
    signer: PublicKeySigner,
    blob: Vec<u8>,
    comment: Vec<u8>,
}
struct Lock {
    salt: [u8; 32],
    digest: Zeroizing<[u8; 32]>,
}

/// Sequential in-memory agent with default-empty keyring. Unsupported
/// constraints and extension operations fail rather than being ignored.
#[derive(Default)]
pub struct AgentServer {
    identities: Vec<Identity>,
    lock: Option<Lock>,
}
impl std::fmt::Debug for AgentServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentServer")
            .field("identities", &self.identities.len())
            .field("locked", &self.lock.is_some())
            .finish()
    }
}
impl AgentServer {
    /// Reads, processes and answers exactly one length-framed request.
    /// Caller owns transport I/O limits. Private request buffers are wiped.
    /// Protocol denials return message 5, without diagnostic/key bytes.
    ///
    /// # Errors
    /// Returns framing/I/O errors. After an I/O error discard this stream;
    /// partial reads/writes are not resumable and effects may have completed.
    pub fn serve_one<T: Read + Write>(&mut self, stream: &mut T) -> Result<(), AgentError> {
        let mut length = [0; 4];
        stream.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_FRAME_SIZE {
            return Err(AgentError::FrameTooLarge);
        }
        let mut request = Zeroizing::new(vec![0; length]);
        stream.read_exact(&mut request)?;
        let response = self.answer(&request).unwrap_or_else(|_| vec![5]);
        stream.write_all(
            &u32::try_from(response.len())
                .map_err(|_| AgentError::FrameTooLarge)?
                .to_be_bytes(),
        )?;
        stream.write_all(&response)?;
        stream.flush()?;
        Ok(())
    }

    fn answer(&mut self, request: &[u8]) -> Result<Vec<u8>, AgentError> {
        let mut reader = Reader::new(request);
        let message = reader.read_byte()?;
        if self.lock.is_some() && message != 23 {
            return Ok(if message == 11 && reader.is_empty() {
                vec![12, 0, 0, 0, 0]
            } else {
                vec![5]
            });
        }
        match message {
            11 if reader.is_empty() => {
                let mut writer = Writer::new();
                writer.write_byte(12);
                writer.write_uint32(
                    u32::try_from(self.identities.len()).map_err(|_| AgentError::FrameTooLarge)?,
                );
                for identity in &self.identities {
                    writer.write_string(&identity.blob)?;
                    writer.write_string(&identity.comment)?;
                }
                Ok(writer.into_bytes())
            }
            13 => {
                let blob = reader.read_string()?;
                let data = reader.read_string()?;
                let flags = reader.read_uint32()?;
                if !reader.is_empty() {
                    return Err(AgentError::InvalidFrame);
                }
                let identity = self
                    .identities
                    .iter()
                    .find(|identity| identity.blob == blob)
                    .ok_or(AgentError::AgentFailure)?;
                let algorithm = match (identity.signer.algorithm(), flags) {
                    ("rsa-sha2-256", 2) => "rsa-sha2-256",
                    ("rsa-sha2-256", 4) => "rsa-sha2-512",
                    (name, 0) if name != "rsa-sha2-256" => name,
                    _ => return Err(AgentError::AgentFailure),
                };
                let signature = identity
                    .signer
                    .sign_algorithm(data, algorithm)
                    .map_err(|_| AgentError::AgentFailure)?;
                let mut writer = Writer::new();
                writer.write_byte(14);
                writer.write_string(&signature)?;
                Ok(writer.into_bytes())
            }
            17 => {
                let identity = decode_identity(&request[1..])?;
                let old = self
                    .identities
                    .iter()
                    .position(|entry| entry.blob == identity.blob);
                if old.is_none() && self.identities.len() >= MAX_AGENT_IDENTITIES {
                    return Err(AgentError::AgentFailure);
                }
                let size: usize = 5 + self
                    .identities
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| Some(*index) != old)
                    .map(|(_, entry)| entry.blob.len() + entry.comment.len() + 8)
                    .sum::<usize>();
                if size + identity.blob.len() + identity.comment.len() + 8 > MAX_FRAME_SIZE {
                    return Err(AgentError::FrameTooLarge);
                }
                if let Some(index) = old {
                    self.identities[index] = identity;
                } else {
                    self.identities.push(identity);
                }
                Ok(vec![6])
            }
            18 => {
                let blob = reader.read_string()?;
                if !reader.is_empty() {
                    return Err(AgentError::InvalidFrame);
                }
                let index = self
                    .identities
                    .iter()
                    .position(|identity| identity.blob == blob)
                    .ok_or(AgentError::AgentFailure)?;
                self.identities.remove(index);
                Ok(vec![6])
            }
            19 if reader.is_empty() => {
                self.identities.clear();
                Ok(vec![6])
            }
            22 | 23 => self.change_lock(message, &mut reader),
            // Constrained adds (25), extensions (27), and unknown operations
            // are deliberately rejected, including a constraints-free 25.
            _ => Err(AgentError::AgentFailure),
        }
    }

    fn change_lock(&mut self, message: u8, reader: &mut Reader<'_>) -> Result<Vec<u8>, AgentError> {
        let passphrase = reader.read_string_with_limit(1024)?;
        if passphrase.is_empty() || !reader.is_empty() {
            return Err(AgentError::InvalidFrame);
        }
        if message == 22 {
            let mut salt = [0; 32];
            getrandom::fill(&mut salt).map_err(|_| AgentError::AgentFailure)?;
            self.lock = Some(Lock {
                salt,
                digest: Zeroizing::new(lock_digest(&salt, passphrase)),
            });
            Ok(vec![6])
        } else {
            let lock = self.lock.as_ref().ok_or(AgentError::AgentFailure)?;
            let digest = Zeroizing::new(lock_digest(&lock.salt, passphrase));
            if !bool::from(lock.digest.as_slice().ct_eq(digest.as_slice())) {
                return Err(AgentError::AgentFailure);
            }
            self.lock = None;
            Ok(vec![6])
        }
    }
}
fn lock_digest(salt: &[u8], passphrase: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(salt);
    hash.update(passphrase);
    hash.finalize().into()
}

fn decode_identity(record: &[u8]) -> Result<Identity, AgentError> {
    let mut reader = Reader::new(record);
    let algorithm = reader.read_string()?;
    let mut public = Writer::new();
    public.write_string(algorithm)?;
    match algorithm {
        b"ssh-ed25519" => {
            public.write_string(reader.read_string()?)?;
            reader.read_string()?;
        }
        b"ssh-rsa" => {
            let n = reader.read_string()?;
            let e = reader.read_string()?;
            public.write_string(e)?;
            public.write_string(n)?;
            for _ in 0..4 {
                reader.read_string()?;
            }
        }
        b"ecdsa-sha2-nistp256" => {
            public.write_string(reader.read_string()?)?;
            public.write_string(reader.read_string()?)?;
            reader.read_string()?;
        }
        _ => return Err(AgentError::UnsupportedKey),
    }
    let comment = reader.read_string_with_limit(1024)?.to_vec();
    if !reader.is_empty() {
        return Err(AgentError::InvalidFrame);
    }
    // RFC agent identity fields match the corresponding OpenSSH private-key
    // record. Reuse that validated parser rather than create a second one.
    let mut private = Zeroizing::new(vec![0; 8]);
    private.extend_from_slice(record);
    let mut padding = 1_u8;
    while !private.len().is_multiple_of(8) {
        private.push(padding);
        padding += 1;
    }
    let blob = public.into_bytes();
    let mut header = Writer::new();
    header.write_string("none")?;
    header.write_string("none")?;
    header.write_string(b"")?;
    header.write_uint32(1);
    header.write_string(&blob)?;
    let mut container = Zeroizing::new(b"openssh-key-v1\0".to_vec());
    container.extend_from_slice(header.as_bytes());
    container.extend_from_slice(
        &u32::try_from(private.len())
            .map_err(|_| AgentError::FrameTooLarge)?
            .to_be_bytes(),
    );
    container.extend_from_slice(&private);
    let signer = crate::private_key::import_openssh(&container, &mut [])
        .map_err(|_| AgentError::AgentFailure)?;
    Ok(Identity {
        signer,
        blob,
        comment,
    })
}
