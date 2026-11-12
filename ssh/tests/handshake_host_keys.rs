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
fn explicit_zlib_selection_is_rejected_by_both_handshakes() -> Result<(), Box<dyn std::error::Error>>
{
    let mut proposal = KexInit::new([0; 16]);
    proposal.compression_algorithms_client_to_server = vec!["zlib@openssh.com".to_owned()];
    proposal.compression_algorithms_server_to_client = vec!["zlib@openssh.com".to_owned()];
    let server =
        ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32])).with_kexinit(proposal.clone());
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
