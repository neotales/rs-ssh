//! Connection-level certificate trust. Run: cargo test -p neotales-ssh.
//! Certificates below are synthetic in-memory fixtures; no issuance API or disk.
use neotales_ssh::{
    ClientAuthMethod, ClientConfig, ServerAuthPolicy, ServerConfig, Writer, authenticate_client,
    authenticate_server, hostkey::Ed25519Signer,
};
use neotales_ssh::{
    auth::PublicKeySigner,
    cert::{CertificateType, SSH_ED25519_CERT_V01, UserCertificateTrust},
    known_hosts::{KnownHosts, encode_base64},
};
use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
};

fn signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&mut [seed; 32])
}

fn fixture(
    role: CertificateType,
    principal: &str,
    expiry: u64,
    option: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut principals = Writer::new();
    principals.write_string(principal)?;
    let mut options = Writer::new();
    if let Some(option) = option {
        options.write_string(option)?;
        let mut data = Writer::new();
        data.write_string("restricted")?;
        options.write_string(data.as_bytes())?;
    }
    let mut writer = Writer::new();
    writer.write_string(SSH_ED25519_CERT_V01)?;
    writer.write_string(&[1_u8; 32])?;
    let blob = signer(31).public_key_blob()?;
    let mut key = neotales_ssh::Reader::new(&blob);
    key.read_string()?;
    writer.write_string(key.read_string()?)?;
    writer.write_uint64(1);
    writer.write_uint32(role.as_u32());
    writer.write_string("fixture")?;
    writer.write_string(principals.as_bytes())?;
    writer.write_uint64(100);
    writer.write_uint64(expiry);
    writer.write_string(options.as_bytes())?;
    writer.write_string(b"")?;
    writer.write_string(b"")?;
    writer.write_string(&signer(32).public_key_blob()?)?;
    let signature = signer(32).sign_exchange_hash(writer.as_bytes())?;
    writer.write_string(&signature)?;
    Ok(writer.into_bytes())
}

fn hosts(ca: u8) -> Result<KnownHosts, Box<dyn std::error::Error>> {
    Ok(KnownHosts::parse(&format!(
        "@cert-authority peer.example ssh-ed25519 {}\n",
        encode_base64(&signer(ca).public_key_blob()?)
    ))?)
}

fn connect_host(
    certificate: &[u8],
    ca: u8,
    principal: &str,
    now: u64,
) -> Result<bool, Box<dyn std::error::Error>> {
    let config = ServerConfig::new(signer(31)).with_host_certificate(certificate)?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<bool, String> {
        let (stream, _) = listener.accept().map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        Ok(config.accept(stream).is_ok())
    });
    let stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let result =
        ClientConfig::new().connect_with_known_hosts(stream, &hosts(ca)?, principal, 22, now);
    let accepted = result.is_ok();
    if let Ok(client) = &result {
        assert_eq!(
            client
                .host_public_key()
                .ok_or("missing certificate")?
                .to_blob()?,
            certificate
        );
    }
    drop(result);
    assert_eq!(server.join().map_err(|_| "server panicked")??, accepted);
    Ok(accepted)
}

#[test]
fn host_certificate_requires_ca_principal_time_signature_and_no_critical_options()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = fixture(CertificateType::Host, "peer.example", 300, None)?;
    assert!(connect_host(&valid, 32, "peer.example", 200)?);
    assert!(!connect_host(&valid, 33, "peer.example", 200)?);
    assert!(!connect_host(&valid, 32, "wrong.example", 200)?);
    assert!(!connect_host(&valid, 32, "peer.example", 99)?);
    assert!(!connect_host(&valid, 32, "peer.example", 300)?);
    let mut damaged = valid;
    *damaged.last_mut().ok_or("missing signature")? ^= 1;
    assert!(!connect_host(&damaged, 32, "peer.example", 200)?);
    for option in ["force-command", "source-address", "unknown-option"] {
        assert!(!connect_host(
            &fixture(CertificateType::Host, "peer.example", 300, Some(option))?,
            32,
            "peer.example",
            200
        )?);
    }
    Ok(())
}

fn authenticate_user(
    certificate: &[u8],
    ca: u8,
    now: u64,
    principal_allowed: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<bool, String> {
        let trust = UserCertificateTrust::new(
            &signer(ca)
                .public_key_blob()
                .map_err(|error| error.to_string())?,
            move || now,
            move |username, _| principal_allowed.then(|| username.to_owned()),
        );
        let policy = ServerAuthPolicy::new(4)
            .map_err(|error| error.to_string())?
            .with_user_certificate_trust(trust);
        let (stream, _) = listener.accept().map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        let mut transport = ServerConfig::new(signer(34))
            .accept(stream)
            .map_err(|error| error.to_string())?;
        let _result = authenticate_server(&mut transport, &policy);
        Ok(transport.is_authenticated())
    });
    let stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut client = ClientConfig::new()
        .with_extension_info()
        .connect(stream, |_| Ok::<(), ()>(()))?;
    let method = ClientAuthMethod::public_key(PublicKeySigner::ed25519_certificate(
        signer(31),
        certificate,
    )?);
    let accepted = authenticate_client(&mut client, "alice", &[method], 4).is_ok();
    drop(client);
    assert_eq!(server.join().map_err(|_| "server panicked")??, accepted);
    Ok(accepted)
}

#[test]
fn user_certificate_requires_ca_principal_time_signature_and_application_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = fixture(CertificateType::User, "alice", 300, None)?;
    assert!(authenticate_user(&valid, 32, 200, true)?);
    assert!(!authenticate_user(&valid, 33, 200, true)?);
    assert!(!authenticate_user(&valid, 32, 300, true)?);
    assert!(!authenticate_user(&valid, 32, 99, true)?);
    assert!(!authenticate_user(&valid, 32, 200, false)?);
    assert!(!authenticate_user(
        &fixture(CertificateType::User, "bob", 300, None)?,
        32,
        200,
        true
    )?);
    let mut damaged = valid;
    *damaged.last_mut().ok_or("missing signature")? ^= 1;
    assert!(!authenticate_user(&damaged, 32, 200, true)?);
    for option in ["force-command", "source-address", "unknown-option"] {
        assert!(!authenticate_user(
            &fixture(CertificateType::User, "alice", 300, Some(option))?,
            32,
            200,
            true
        )?);
    }
    Ok(())
}
