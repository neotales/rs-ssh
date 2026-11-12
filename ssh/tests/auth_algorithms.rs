//! Authentication negotiation through both public transports. No external peer.
use neotales_ssh::auth::{
    ClientAuthMethod, PublicKeySigner, RsaAuthSigner, ServerAuthPolicy, authenticate_client,
    authenticate_server,
};
use neotales_ssh::hostkey::Ed25519Signer;
use neotales_ssh::{ClientConfig, KexInit, Reader, ServerConfig};
use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
};

fn round_trip(
    signer: PublicKeySigner,
    algorithms: &'static [&'static str],
    expected: &'static str,
    ext: bool,
    strict: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let blob = signer.public_key_blob()?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<(), String> {
        let policy = ServerAuthPolicy::new(4)
            .and_then(|policy| policy.with_authorized_key(&blob))
            .and_then(|policy| policy.with_signature_algorithms(algorithms))
            .map_err(|e| e.to_string())?
            .with_public_key_verifier(move |algorithm, _, _, signature| {
                algorithm == expected
                    && Reader::new(signature)
                        .read_string()
                        .is_ok_and(|name| name == expected.as_bytes())
            });
        let config = ServerConfig::new(Ed25519Signer::from_seed(&mut [9; 32]));
        let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        let mut transport = config.accept(stream).map_err(|e| e.to_string())?;
        authenticate_server(&mut transport, &policy).map_err(|e| e.to_string())?;
        assert!(transport.is_authenticated());
        Ok(())
    });
    let mut proposal = KexInit::client_defaults([0; 16]);
    if !strict {
        proposal
            .kex_algorithms
            .retain(|name| !name.starts_with("kex-strict-"));
    }
    let config = ClientConfig::with_kexinit(proposal);
    let config = if ext {
        config.with_extension_info()
    } else {
        config
    };
    let stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut transport = config.connect(stream, |_| Ok::<(), ()>(()))?;
    let result = authenticate_client(
        &mut transport,
        "user",
        &[ClientAuthMethod::public_key(signer)],
        4,
    );
    let signature_list = transport
        .server_signature_algorithms()
        .map(<[String]>::to_vec);
    drop(transport);
    let server_result = server.join().map_err(|_| "server panicked")?;
    result?;
    server_result.map_err(|_| "server authentication failed")?;
    if ext {
        assert_eq!(signature_list.ok_or("missing ext-info")?, algorithms);
    } else {
        assert!(signature_list.is_none());
    }
    Ok(())
}

#[test]
fn rsa_uses_sha512_only_when_listed_and_falls_back_to_sha256_without_ext_info()
-> Result<(), Box<dyn std::error::Error>> {
    let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024)?;
    for (ext, strict, algorithms, expected) in [
        (true, true, &["rsa-sha2-512"][..], "rsa-sha2-512"),
        (true, false, &["rsa-sha2-512"][..], "rsa-sha2-512"),
        (
            false,
            true,
            &["rsa-sha2-256", "rsa-sha2-512"][..],
            "rsa-sha2-256",
        ),
    ] {
        round_trip(
            PublicKeySigner::rsa(RsaAuthSigner::from_private_key(private.clone())?),
            algorithms,
            expected,
            ext,
            strict,
        )?;
    }
    Ok(())
}

#[test]
fn every_supported_identity_curve_and_explicit_rsa512_authenticates()
-> Result<(), Box<dyn std::error::Error>> {
    use neotales_ssh::ecdsa_hostkey::{EcdsaP384Signer, EcdsaP521Signer, EcdsaSigner};
    round_trip(
        PublicKeySigner::ecdsa(EcdsaSigner::from_private_bytes([3; 32])?),
        &["ecdsa-sha2-nistp256"],
        "ecdsa-sha2-nistp256",
        true,
        true,
    )?;
    round_trip(
        PublicKeySigner::ecdsa_p384(EcdsaP384Signer::from_private_bytes([3; 48])?),
        &["ecdsa-sha2-nistp384"],
        "ecdsa-sha2-nistp384",
        true,
        true,
    )?;
    let mut scalar = [0; 66];
    scalar[65] = 3;
    round_trip(
        PublicKeySigner::ecdsa_p521(EcdsaP521Signer::from_private_bytes(scalar)?),
        &["ecdsa-sha2-nistp521"],
        "ecdsa-sha2-nistp521",
        true,
        true,
    )?;
    let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024)?;
    round_trip(
        PublicKeySigner::rsa_sha512(RsaAuthSigner::from_private_key(private)?),
        &["rsa-sha2-512"],
        "rsa-sha2-512",
        false,
        true,
    )?;
    Ok(())
}

type Sign = dyn Fn(&[u8], u32) -> std::io::Result<Vec<u8>> + Send;
struct ScriptedAgent {
    request: Vec<u8>,
    response: std::io::Cursor<Vec<u8>>,
    sign: Box<Sign>,
}
impl std::io::Write for ScriptedAgent {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.request.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl std::io::Read for ScriptedAgent {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self.response.get_ref().is_empty() {
            let mut reader = Reader::new(&self.request[4..]);
            let invalid = |_| std::io::Error::other("invalid scripted agent request");
            if reader.read_byte().map_err(invalid)? != 13 {
                return Err(std::io::Error::other("unexpected agent message"));
            }
            let _key = reader.read_string().map_err(invalid)?;
            let data = reader.read_string().map_err(invalid)?;
            let flags = reader.read_uint32().map_err(invalid)?;
            let signature = (self.sign)(data, flags)?;
            let mut body = neotales_ssh::Writer::new();
            body.write_byte(14);
            body.write_string(&signature).map_err(invalid)?;
            let mut frame = neotales_ssh::Writer::new();
            frame.write_string(body.as_bytes()).map_err(invalid)?;
            self.response = std::io::Cursor::new(frame.into_bytes());
        }
        std::io::Read::read(&mut self.response, bytes)
    }
}

fn agent(blob: &[u8], sign: Box<Sign>) -> Result<PublicKeySigner, neotales_ssh::auth::AuthError> {
    let transport = ScriptedAgent {
        request: Vec::new(),
        response: std::io::Cursor::new(Vec::new()),
        sign,
    };
    Ok(PublicKeySigner::agent(
        neotales_ssh::auth::AgentKeySigner::new(neotales_ssh::AgentClient::new(transport), blob)?,
    ))
}

#[test]
fn agents_use_negotiated_rsa_flags_and_all_ecdsa_names_and_reject_mislabeled_proofs()
-> Result<(), Box<dyn std::error::Error>> {
    use neotales_ssh::ecdsa_hostkey::{EcdsaP384Signer, EcdsaP521Signer, EcdsaSigner};
    for mismatch in [false, true] {
        let signer = RsaAuthSigner::from_private_key(rsa::RsaPrivateKey::new(
            &mut rsa::rand_core::OsRng,
            1024,
        )?)?;
        let blob = signer.public_key_blob().to_vec();
        let client = agent(
            &blob,
            Box::new(move |data, flags| {
                assert_eq!(flags, neotales_ssh::agent::SSH_AGENT_RSA_SHA2_512);
                signer
                    .sign_with_algorithm(
                        data,
                        if mismatch {
                            "rsa-sha2-256"
                        } else {
                            "rsa-sha2-512"
                        },
                    )
                    .map_err(|_| std::io::Error::other("scripted signing failed"))
            }),
        )?;
        let result = round_trip(client, &["rsa-sha2-512"], "rsa-sha2-512", true, true);
        if mismatch {
            assert!(result.is_err());
        } else {
            result?;
        }
    }
    let signer = EcdsaSigner::from_private_bytes([4; 32])?;
    let client = agent(
        &signer.public_key_blob()?,
        Box::new(move |data, flags| {
            assert_eq!(flags, 0);
            signer
                .sign_exchange_hash(data)
                .map_err(|_| std::io::Error::other("scripted signing failed"))
        }),
    )?;
    round_trip(
        client,
        &["ecdsa-sha2-nistp256"],
        "ecdsa-sha2-nistp256",
        true,
        true,
    )?;
    let signer = EcdsaP384Signer::from_private_bytes([4; 48])?;
    let client = agent(
        &signer.public_key_blob()?,
        Box::new(move |data, flags| {
            assert_eq!(flags, 0);
            signer
                .sign_exchange_hash(data)
                .map_err(|_| std::io::Error::other("scripted signing failed"))
        }),
    )?;
    round_trip(
        client,
        &["ecdsa-sha2-nistp384"],
        "ecdsa-sha2-nistp384",
        true,
        true,
    )?;
    let mut scalar = [0; 66];
    scalar[65] = 4;
    let signer = EcdsaP521Signer::from_private_bytes(scalar)?;
    let client = agent(
        &signer.public_key_blob()?,
        Box::new(move |data, flags| {
            assert_eq!(flags, 0);
            signer
                .sign_exchange_hash(data)
                .map_err(|_| std::io::Error::other("scripted signing failed"))
        }),
    )?;
    round_trip(
        client,
        &["ecdsa-sha2-nistp521"],
        "ecdsa-sha2-nistp521",
        true,
        true,
    )?;
    Ok(())
}
