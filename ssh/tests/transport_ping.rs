//! OpenSSH transport ping is separate from named connection global requests.
use neotales_ssh::{ClientConfig, Reader, ServerConfig};
use neotales_ssh::{
    hostkey::Ed25519Signer,
    keepalive::{GlobalRequest, TransportPing},
};
use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
};

#[test]
fn both_transports_echo_ping_and_never_treat_a_named_global_request_as_ping()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<(), String> {
        let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        let mut server = ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32]))
            .accept(stream)
            .map_err(|e| e.to_string())?;
        let policy = neotales_ssh::ServerAuthPolicy::new(4)
            .and_then(|policy| {
                policy.with_authorized_key(
                    &Ed25519Signer::from_seed(&mut [49; 32])
                        .public_key_blob()
                        .expect("synthetic public key"),
                )
            })
            .map_err(|e| e.to_string())?;
        neotales_ssh::authenticate_server(&mut server, &policy).map_err(|e| e.to_string())?;
        assert_eq!(server.read_auth_packet().map_err(|e| e.to_string())?, [5]);
        server
            .send_ping(b"server\0ping")
            .map_err(|e| e.to_string())?;
        server.write_payload(&[52]).map_err(|e| e.to_string())?;
        server
            .write_payload(
                &GlobalRequest::ping(b"legacy")
                    .encode()
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        assert_eq!(
            TransportPing::decode(&server.read_auth_packet().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?,
            TransportPing::Pong(b"server\0ping".to_vec())
        );
        Ok(())
    });
    let stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut client = ClientConfig::new().connect(stream, |_| Ok::<(), ()>(()))?;
    // OpenSSH PROTOCOL 1.8: no PONG is generated before authentication.
    client.send_ping(b"ignored before authentication")?;
    neotales_ssh::authenticate_client(
        &mut client,
        "user",
        &[neotales_ssh::ClientAuthMethod::public_key(
            neotales_ssh::auth::PublicKeySigner::ed25519(Ed25519Signer::from_seed(&mut [49; 32])),
        )],
        4,
    )?;
    client.send_ping(b"client\0ping")?;
    client.write_payload(&[5])?;
    let reply = client.read_payload()?;
    let mut reader = Reader::new(&reply);
    assert_eq!(reader.read_byte()?, 193);
    assert_eq!(reader.read_string()?, b"client\0ping");
    assert!(reader.is_empty());
    assert_eq!(client.read_payload()?, [52]);
    let before = client.outbound_sequence();
    let legacy = client.read_payload()?;
    assert_eq!(legacy[0], 80);
    assert!(TransportPing::decode(&legacy).is_err());
    assert_eq!(client.outbound_sequence(), before);
    assert!(server.join().map_err(|_| "server panicked")?.is_ok());
    let request = GlobalRequest::keepalive_with_reply();
    assert!(GlobalRequest::decode(&request.encode()?)?.want_reply());
    assert_eq!(request.reply()?, Some(vec![81]));
    Ok(())
}
