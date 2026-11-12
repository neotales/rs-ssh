//! Host-key selection through both public handshakes, not standalone codecs.
use neotales_ssh::{ClientConfig, KexInit, ServerConfig};
use neotales_ssh::{
    ecdsa_hostkey::{EcdsaP384Signer, EcdsaP521Signer, EcdsaSigner},
    hostkey::Ed25519Signer,
    rsa_hostkey::RsaHostSigner,
};
use std::{
    net::{TcpListener, TcpStream},
    sync::Arc,
    time::Duration,
};

type Fixture = (Arc<ServerConfig>, [Vec<u8>; 4]);

#[test]
fn custom_legacy_proposals_fail_closed_without_config_opt_in() {
    for name in [
        "ssh-rsa",
        "hmac-sha1",
        "hmac-sha1-etm@openssh.com",
        "aes128-cbc",
        "aes256-cbc",
        "3des-cbc",
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group-exchange-sha1",
    ] {
        let mut proposal = KexInit::new([0; 16]);
        if name == "ssh-rsa" {
            proposal.server_host_key_algorithms = vec![name.to_owned()];
        } else if name.starts_with("hmac-") {
            proposal.mac_algorithms_client_to_server = vec![name.to_owned()];
        } else if name.starts_with("diffie-") {
            proposal.kex_algorithms = vec![name.to_owned()];
        } else {
            proposal.encryption_algorithms_server_to_client = vec![name.to_owned()];
        }
        assert!(
            matches!(
                ClientConfig::with_kexinit(proposal.clone())
                    .connect_with_host_keys(std::io::Cursor::new(Vec::new()), |_| Ok::<(), ()>(())),
                Err(neotales_ssh::client::HandshakeError::UnsupportedAlgorithm)
            ),
            "client: {name}"
        );
        assert!(
            matches!(
                ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32]))
                    .with_kexinit(proposal)
                    .accept(std::io::Cursor::new(Vec::new())),
                Err(neotales_ssh::server::HandshakeError::UnsupportedAlgorithm)
            ),
            "server: {name}"
        );
    }
}

#[test]
fn legacy_opt_in_completes_host_signature_packets_and_rekey()
-> Result<(), Box<dyn std::error::Error>> {
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024)?;
    let expected = RsaHostSigner::from_private_key(key.clone())?.public_key_blob()?;
    for (kex, cipher, mac) in [
        ("curve25519-sha256", "aes128-cbc", "hmac-sha1"),
        (
            "diffie-hellman-group1-sha1",
            "aes256-cbc",
            "hmac-sha1-etm@openssh.com",
        ),
        (
            "diffie-hellman-group-exchange-sha1",
            "3des-cbc",
            "hmac-sha1",
        ),
        ("curve25519-sha256", "3des-cbc", "hmac-sha1-etm@openssh.com"),
        ("curve25519-sha256", "aes128-ctr", "hmac-sha1"),
    ] {
        let mut proposal = KexInit::new([0; 16]);
        proposal.kex_algorithms = vec![kex.to_owned()];
        proposal.server_host_key_algorithms = vec!["ssh-rsa".to_owned()];
        proposal.encryption_algorithms_client_to_server = vec![cipher.to_owned()];
        proposal.encryption_algorithms_server_to_client = vec![cipher.to_owned()];
        proposal.mac_algorithms_client_to_server = vec![mac.to_owned()];
        proposal.mac_algorithms_server_to_client = vec![mac.to_owned()];
        let server = ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32]))
            .with_rsa_host_key(RsaHostSigner::from_private_key(key.clone())?)
            .with_legacy_algorithms()
            .with_kexinit(proposal.clone());
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let thread = std::thread::spawn(move || -> Result<(), String> {
            let run = || -> Result<(), Box<dyn std::error::Error>> {
                let (stream, _) = listener.accept()?;
                stream.set_read_timeout(Some(Duration::from_secs(15)))?;
                stream.set_write_timeout(Some(Duration::from_secs(15)))?;
                let mut transport = server.accept(stream)?;
                assert_eq!(transport.host_key_algorithm(), "ssh-rsa");
                assert_eq!(transport.read_auth_packet()?, [5]);
                transport.write_payload(&[52])?;
                // The next read services the client's rekey through the same policy.
                assert_eq!(transport.read_auth_packet()?, [5, 1]);
                transport.write_payload(&[52])?;
                transport.rekey()?;
                transport.write_payload(&[52])?;
                Ok(())
            };
            run().map_err(|error| error.to_string())
        });
        let stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        stream.set_write_timeout(Some(Duration::from_secs(15)))?;
        let mut client = ClientConfig::with_kexinit(proposal)
            .with_legacy_algorithms()
            .connect_with_host_keys(stream, |key| {
                if key.to_blob().is_ok_and(|blob| blob == expected) {
                    Ok(())
                } else {
                    Err(())
                }
            })?;
        client.write_payload(&[5])?;
        assert_eq!(client.read_payload()?, [52]);
        client.rekey()?;
        client.write_payload(&[5, 1])?;
        assert_eq!(client.read_payload()?, [52]);
        assert_eq!(client.read_payload()?, [52]);
        thread.join().map_err(|_| "server panicked")??;
    }
    Ok(())
}

#[test]
fn compression_is_opt_in_and_authentication_activates_both_directions()
-> Result<(), Box<dyn std::error::Error>> {
    use neotales_ssh::auth::{
        ClientAuthMethod, ClientAuthenticator, ServerAuthPolicy, authenticate_server,
    };
    let server = ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32]));
    for proposal in [
        ClientConfig::new().kexinit(),
        server.kexinit(),
        &KexInit::new([0; 16]),
    ] {
        assert_eq!(proposal.compression_algorithms_client_to_server, ["none"]);
        assert_eq!(proposal.compression_algorithms_server_to_client, ["none"]);
    }
    let server = server.with_delayed_compression();
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let payload = b"\x5eauthenticated dictionary traffic".repeat(128);
    let expected = payload.clone();
    let thread = std::thread::spawn(move || -> Result<(), String> {
        let run = || -> Result<(), Box<dyn std::error::Error>> {
            let (stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut transport = server.accept(stream)?;
            let policy = ServerAuthPolicy::new(2)?
                .with_password_callback(|candidate| candidate == "fixture");
            authenticate_server(&mut transport, &policy)?;
            assert!(transport.is_authenticated());
            for _ in 0..2 {
                assert_eq!(transport.read_payload()?, expected);
                transport.write_payload(&expected)?;
            }
            transport.rekey()?;
            assert_eq!(transport.read_payload()?, expected);
            transport.write_payload(&expected)?;
            Ok(())
        };
        run().map_err(|error| error.to_string())
    });
    let stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut transport = ClientConfig::new()
        .with_delayed_compression()
        .connect(stream, |_| Ok::<(), ()>(()))?;
    ClientAuthenticator::new(&mut transport, "fixture", 2)?
        .authenticate(&[ClientAuthMethod::password("fixture")])?;
    for _ in 0..2 {
        transport.write_payload(&payload)?;
        assert_eq!(transport.read_payload()?, payload);
    }
    transport.rekey()?;
    transport.write_payload(&payload)?;
    assert_eq!(transport.read_payload()?, payload);
    thread.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn explicit_zlib_selection_is_rejected_by_both_handshakes() -> Result<(), Box<dyn std::error::Error>>
{
    for compression in ["zlib", "zlib@openssh.com"] {
        let mut proposal = KexInit::new([0; 16]);
        proposal.compression_algorithms_client_to_server = vec![compression.to_owned()];
        proposal.compression_algorithms_server_to_client = vec![compression.to_owned()];
        let server = ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32]))
            .with_kexinit(proposal.clone());
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("loopback accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            matches!(
                server.accept(stream),
                Err(neotales_ssh::server::HandshakeError::UnsupportedAlgorithm)
            )
        });
        let stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        assert!(matches!(
            ClientConfig::with_kexinit(proposal).connect(stream, |_| Ok::<(), ()>(())),
            Err(neotales_ssh::client::HandshakeError::UnsupportedAlgorithm)
        ));
        assert!(thread.join().map_err(|_| "server panicked")?);
    }
    Ok(())
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let ed = Ed25519Signer::from_seed(&mut [7; 32]);
    let rsa = RsaHostSigner::from_private_key(rsa::RsaPrivateKey::new(
        &mut rsa::rand_core::OsRng,
        1024,
    )?)?;
    let ecdsa = EcdsaSigner::from_private_bytes([3; 32])?;
    let expected = [
        ed.public_key_blob()?,
        rsa.public_key_blob()?,
        rsa.public_key_blob()?,
        ecdsa.public_key_blob()?,
    ];
    let config = Arc::new(
        ServerConfig::new(ed)
            .with_rsa_host_key(rsa)
            .with_ecdsa_host_key(ecdsa),
    );
    Ok((config, expected))
}

#[test]
fn every_offered_host_key_selects_the_matching_signer_and_checks_trust()
-> Result<(), Box<dyn std::error::Error>> {
    let (config, expected) = fixture()?;
    for (algorithm, expected) in [
        "ssh-ed25519",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ecdsa-sha2-nistp256",
    ]
    .into_iter()
    .zip(expected)
    {
        for kex in [
            "curve25519-sha256",
            "ecdh-sha2-nistp256",
            "mlkem768x25519-sha256",
        ] {
            for accept in [false, true] {
                let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
                let address = listener.local_addr()?;
                let config = Arc::clone(&config);
                let server = std::thread::spawn(move || -> Result<(), String> {
                    let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .map_err(|e| e.to_string())?;
                    stream
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .map_err(|e| e.to_string())?;
                    let mut server = config.accept(stream).map_err(|e| e.to_string())?;
                    assert_eq!(server.host_key_algorithm(), algorithm);
                    assert_eq!(server.read_auth_packet().map_err(|e| e.to_string())?, [5]);
                    server.write_payload(&[52]).map_err(|e| e.to_string())?;
                    if kex == "mlkem768x25519-sha256" {
                        assert_eq!(
                            server.read_auth_packet().map_err(|e| e.to_string())?,
                            [5, 1]
                        );
                        assert_eq!(server.host_key_algorithm(), algorithm);
                        server.write_payload(&[52]).map_err(|e| e.to_string())?;
                    }
                    Ok(())
                });
                let mut proposal = KexInit::client_defaults([0; 16]);
                proposal.server_host_key_algorithms = vec![algorithm.to_owned()];
                proposal.kex_algorithms =
                    vec![kex.to_owned(), "kex-strict-c-v00@openssh.com".to_owned()];
                let stream = TcpStream::connect(address)?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                let client =
                    ClientConfig::with_kexinit(proposal).connect_with_host_keys(stream, |key| {
                        if accept && key.to_blob().is_ok_and(|blob| blob == expected) {
                            Ok(())
                        } else {
                            Err(())
                        }
                    });
                if accept {
                    let mut client = client?;
                    assert_eq!(
                        client
                            .host_public_key()
                            .ok_or("missing trusted key")?
                            .to_blob()?,
                        expected
                    );
                    client.write_payload(&[5])?;
                    assert_eq!(client.read_payload()?, [52]);
                    if kex == "mlkem768x25519-sha256" {
                        client.rekey()?;
                        client.write_payload(&[5, 1])?;
                        assert_eq!(client.read_payload()?, [52]);
                        assert_eq!(
                            client
                                .host_public_key()
                                .ok_or("missing rekey host key")?
                                .to_blob()?,
                            expected
                        );
                    }
                    assert!(server.join().map_err(|_| "server panicked")?.is_ok());
                } else {
                    assert!(matches!(
                        client,
                        Err(neotales_ssh::client::HandshakeError::HostKey(
                            neotales_ssh::hostkey::HostKeyError::TrustRejected
                        ))
                    ));
                    assert!(server.join().map_err(|_| "server panicked")?.is_err());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn p384_and_p521_host_keys_complete_both_handshakes_after_verified_trust()
-> Result<(), Box<dyn std::error::Error>> {
    for (algorithm, config, expected) in [
        (
            "ecdsa-sha2-nistp384",
            ServerConfig::new(Ed25519Signer::from_seed(&mut [9; 32]))
                .with_ecdsa_p384_host_key(EcdsaP384Signer::from_private_bytes([1; 48])?),
            EcdsaP384Signer::from_private_bytes([1; 48])?.public_key_blob()?,
        ),
        (
            "ecdsa-sha2-nistp521",
            ServerConfig::new(Ed25519Signer::from_seed(&mut [9; 32]))
                .with_ecdsa_p521_host_key(EcdsaP521Signer::from_private_bytes([1; 66])?),
            EcdsaP521Signer::from_private_bytes([1; 66])?.public_key_blob()?,
        ),
    ] {
        let config = Arc::new(config);
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let server = std::thread::spawn(move || -> Result<(), String> {
            let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|e| e.to_string())?;
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(|e| e.to_string())?;
            let mut server = config.accept(stream).map_err(|e| e.to_string())?;
            assert_eq!(server.host_key_algorithm(), algorithm);
            assert_eq!(server.read_auth_packet().map_err(|e| e.to_string())?, [5]);
            server.write_payload(&[52]).map_err(|e| e.to_string())?;
            Ok(())
        });
        let mut proposal = KexInit::client_defaults([0; 16]);
        proposal.server_host_key_algorithms = vec![algorithm.to_owned()];
        let stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut client =
            ClientConfig::with_kexinit(proposal).connect_with_host_keys(stream, |key| {
                if key.to_blob().is_ok_and(|blob| blob == expected) {
                    Ok(())
                } else {
                    Err(())
                }
            })?;
        assert_eq!(
            client
                .host_public_key()
                .ok_or("missing trusted key")?
                .to_blob()?,
            expected
        );
        client.write_payload(&[5])?;
        assert_eq!(client.read_payload()?, [52]);
        assert!(server.join().map_err(|_| "server panicked")?.is_ok());
    }
    Ok(())
}
