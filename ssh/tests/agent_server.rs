//! RFC 9987 operations via `AgentClient` and a scripted in-process byte stream.
use neotales_ssh::{
    Writer,
    agent::AgentClient,
    agent_server::AgentServer,
    hostkey::{Ed25519PublicKey, Ed25519Signer, verify_host_key_signature},
};
use std::io::{self, Cursor, Read, Write};

#[derive(Default)]
struct Loopback {
    server: AgentServer,
    request: Vec<u8>,
    response: Cursor<Vec<u8>>,
}
struct Exchange {
    request: Cursor<Vec<u8>>,
    response: Vec<u8>,
}
impl Read for Exchange {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.request.read(bytes)
    }
}
impl Write for Exchange {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.response.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Write for Loopback {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.request.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Read for Loopback {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.response.position() == self.response.get_ref().len() as u64 {
            let mut exchange = Exchange {
                request: Cursor::new(std::mem::take(&mut self.request)),
                response: Vec::new(),
            };
            self.server
                .serve_one(&mut exchange)
                .map_err(|_| io::Error::other("agent request failed"))?;
            self.response = Cursor::new(exchange.response);
        }
        self.response.read(bytes)
    }
}

fn identity(seed: u8) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::from_seed(&mut [seed; 32]);
    let blob = signer.public_key_blob()?;
    let point = signer.public_key().as_bytes();
    let mut private = vec![seed; 32];
    private.extend_from_slice(point);
    let mut record = Writer::new();
    record.write_string("ssh-ed25519")?;
    record.write_string(point)?;
    record.write_string(&private)?;
    record.write_string("synthetic identity")?;
    Ok((record.into_bytes(), blob))
}

#[test]
fn client_drives_add_list_sign_remove_lock_unlock_and_constraint_denial()
-> Result<(), Box<dyn std::error::Error>> {
    let (record, blob) = identity(41)?;
    let (second, other) = identity(42)?;
    let mut client = AgentClient::new(Loopback::default());
    assert_eq!(client.identities()?.len(), 0);
    client.add_identity(&record)?;
    client.add_identity(&second)?;
    assert_eq!(client.identities()?.len(), 2);
    let proof = client.sign(&blob, b"signed payload")?;
    verify_host_key_signature(
        &Ed25519PublicKey::from_blob(&blob)?,
        &proof,
        b"signed payload",
    )?;
    client.remove_identity(&other)?;
    assert_eq!(client.identities()?.len(), 1);
    client.lock(b"synthetic-lock-passphrase")?;
    assert_eq!(client.identities()?.len(), 0);
    assert!(client.sign(&blob, b"denied").is_err());
    assert!(client.add_identity(&second).is_err());
    let error = client
        .unlock(b"synthetic-wrong-passphrase")
        .expect_err("wrong unlock must fail");
    assert!(!format!("{error:?} {error}").contains("passphrase"));
    assert!(client.sign(&blob, b"still locked").is_err());
    client.unlock(b"synthetic-lock-passphrase")?;
    assert_eq!(client.identities()?.len(), 1);
    assert!(client.add_identity_constrained(&second).is_err());
    let mut constrained = second.clone();
    constrained.extend_from_slice(&[1, 0, 0, 0, 60]);
    assert!(client.add_identity_constrained(&constrained).is_err());
    // A constraint appended to an unconstrained record is malformed too.
    assert!(client.add_identity(&constrained).is_err());
    assert_eq!(client.identities()?.len(), 1);
    client.add_identity(&record)?;
    assert_eq!(client.identities()?.len(), 1);
    client.remove_all()?;
    assert_eq!(client.identities()?.len(), 0);
    assert!(client.sign(&blob, b"removed").is_err());
    Ok(())
}

#[test]
fn added_rsa_and_p256_keys_sign_and_unsupported_flags_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let mut client = AgentClient::new(Loopback::default());
    let rsa = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024)?;
    let mut record = Writer::new();
    record.write_string("ssh-rsa")?;
    for value in [
        rsa.n(),
        rsa.e(),
        rsa.d(),
        &rsa.crt_coefficient().ok_or("missing coefficient")?,
        &rsa.primes()[0],
        &rsa.primes()[1],
    ] {
        let bytes = value.to_bytes_be();
        let mut positive = Vec::new();
        if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
            positive.push(0);
        }
        positive.extend_from_slice(&bytes);
        record.write_mpint(&positive)?;
    }
    record.write_string(b"rsa fixture")?;
    client.add_identity(record.as_bytes())?;
    let rsa_blob = client.identities()?.remove(0).key_blob;
    let rsa_public = neotales_ssh::rsa_hostkey::RsaPublicKey::from_blob(&rsa_blob)?;
    for flags in [2, 4] {
        let proof = client.sign_with_flags(&rsa_blob, b"payload", flags)?;
        neotales_ssh::rsa_hostkey::verify_host_key_signature(&rsa_public, &proof, b"payload")?;
    }
    assert!(client.sign_with_flags(&rsa_blob, b"no SHA-1", 0).is_err());
    let signer = neotales_ssh::ecdsa_hostkey::EcdsaSigner::from_private_bytes([3; 32])?;
    let blob = signer.public_key_blob()?;
    let mut reader = neotales_ssh::Reader::new(&blob);
    reader.read_string()?;
    reader.read_string()?;
    let point = reader.read_string()?;
    let mut record = Writer::new();
    record.write_string("ecdsa-sha2-nistp256")?;
    record.write_string("nistp256")?;
    record.write_string(point)?;
    record.write_mpint([3_u8; 32])?;
    record.write_string(b"p256 fixture")?;
    client.add_identity(record.as_bytes())?;
    let proof = client.sign(&blob, b"payload")?;
    neotales_ssh::ecdsa_hostkey::verify_host_key_signature(
        &neotales_ssh::ecdsa_hostkey::EcdsaPublicKey::from_blob(&blob)?,
        &proof,
        b"payload",
    )?;
    assert!(client.sign_with_flags(&blob, b"bad flags", 4).is_err());
    Ok(())
}
