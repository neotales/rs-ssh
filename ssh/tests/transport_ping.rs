//! OpenSSH transport ping is separate from named connection global requests.
use neotales_ssh::{ClientConfig, Reader, ServerConfig};
use neotales_ssh::{
    hostkey::Ed25519Signer,
    keepalive::{GlobalRequest, TransportPing},
};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

struct GatedSocket {
    socket: TcpStream,
    allowance: Arc<AtomicUsize>,
}

impl Read for GatedSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.socket.read(bytes)
    }
}

impl Write for GatedSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let allowed = self.allowance.load(Ordering::SeqCst);
        if allowed == 0 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let count = self.socket.write(&bytes[..bytes.len().min(allowed)])?;
        if allowed != usize::MAX {
            self.allowance.fetch_sub(count, Ordering::SeqCst);
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

#[test]
fn owned_packet_defers_pong_without_losing_inbound_or_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    use neotales_ssh::transport::{OwnedInbound, TransportError};
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let (send, recv) = mpsc::channel();
    let (ready, sent) = mpsc::channel();
    let server = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let (stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut server =
                ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32])).accept(stream)?;
            let policy = neotales_ssh::ServerAuthPolicy::new(4)?
                .with_authorized_key(&Ed25519Signer::from_seed(&mut [49; 32]).public_key_blob()?)?;
            neotales_ssh::authenticate_server(&mut server, &policy)?;
            recv.recv_timeout(Duration::from_secs(5))?;
            server.write_payload(b"\x5ebefore-ping")?;
            server.send_ping(b"deferred")?;
            server.write_payload(b"\x5einbound")?;
            ready.send(())?;
            assert_eq!(server.read_payload()?, b"\x5eoutbound");
            assert_eq!(
                TransportPing::decode(&server.read_payload()?)?,
                TransportPing::Pong(b"deferred".to_vec())
            );
            Ok(())
        },
    );
    let stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let allowance = Arc::new(AtomicUsize::new(usize::MAX));
    let mut client = ClientConfig::new().connect(
        GatedSocket {
            socket: stream,
            allowance: Arc::clone(&allowance),
        },
        |_| Ok::<(), ()>(()),
    )?;
    neotales_ssh::authenticate_client(
        &mut client,
        "user",
        &[neotales_ssh::ClientAuthMethod::public_key(
            neotales_ssh::auth::PublicKeySigner::ed25519(Ed25519Signer::from_seed(&mut [49; 32])),
        )],
        4,
    )?;
    let outbound = client.outbound_sequence();
    let inbound = client.inbound_sequence();
    let id = client.start_owned_packet(b"\x5eoutbound")?;
    allowance.store(1, Ordering::SeqCst);
    assert!(
        matches!(client.drive_owned_packet(&id), Err(TransportError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock)
    );
    send.send(())?;
    sent.recv_timeout(Duration::from_secs(5))?;
    assert!(matches!(
        client.read_while_owned(&id)?,
        OwnedInbound::Payload(bytes) if bytes == b"\x5ebefore-ping"
    ));
    assert!(matches!(
        client.read_while_owned(&id)?,
        OwnedInbound::PongDeferred
    ));
    assert_eq!(client.inbound_sequence(), inbound + 2);
    assert_eq!(client.outbound_sequence(), outbound);
    assert!(matches!(
        client.read_while_owned(&id),
        Err(TransportError::OwnedPacketState)
    ));
    allowance.store(usize::MAX, Ordering::SeqCst);
    client.drive_owned_packet(&id)?;
    assert!(matches!(
        client.write_payload(b"other"),
        Err(TransportError::OwnedPacketState)
    ));
    assert!(client.begin_rekey().is_err());
    allowance.store(1, Ordering::SeqCst);
    assert!(
        matches!(client.drive_deferred_pong(), Err(TransportError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock)
    );
    assert_eq!(client.outbound_sequence(), outbound + 1);
    assert!(matches!(
        client.write_payload(b"other"),
        Err(TransportError::OwnedPacketState)
    ));
    allowance.store(usize::MAX, Ordering::SeqCst);
    client.drive_deferred_pong()?;
    assert_eq!(client.outbound_sequence(), outbound + 2);
    assert_eq!(client.read_payload()?, b"\x5einbound");
    server
        .join()
        .map_err(|_| "server panicked")?
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn peer_rekey_while_owned_terminally_disables_protected_io()
-> Result<(), Box<dyn std::error::Error>> {
    use neotales_ssh::transport::TransportError;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let (send, recv) = mpsc::channel();
    let (sent, ready) = mpsc::channel();
    let server = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let (stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut server =
                ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32])).accept(stream)?;
            let policy = neotales_ssh::ServerAuthPolicy::new(4)?
                .with_authorized_key(&Ed25519Signer::from_seed(&mut [49; 32]).public_key_blob()?)?;
            neotales_ssh::authenticate_server(&mut server, &policy)?;
            recv.recv_timeout(Duration::from_secs(5))?;
            server.write_payload(&[20])?;
            sent.send(())?;
            Ok(())
        },
    );
    let stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let allowance = Arc::new(AtomicUsize::new(usize::MAX));
    let mut client = ClientConfig::new().connect(
        GatedSocket {
            socket: stream,
            allowance: Arc::clone(&allowance),
        },
        |_| Ok::<(), ()>(()),
    )?;
    neotales_ssh::authenticate_client(
        &mut client,
        "user",
        &[neotales_ssh::ClientAuthMethod::public_key(
            neotales_ssh::auth::PublicKeySigner::ed25519(Ed25519Signer::from_seed(&mut [49; 32])),
        )],
        4,
    )?;
    let outbound = client.outbound_sequence();
    let id = client.start_owned_packet(b"\x5eoutbound")?;
    allowance.store(1, Ordering::SeqCst);
    assert!(
        matches!(client.drive_owned_packet(&id), Err(TransportError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock)
    );
    send.send(())?;
    ready.recv_timeout(Duration::from_secs(5))?;
    assert!(matches!(
        client.read_while_owned(&id),
        Err(TransportError::UnexpectedMessage)
    ));
    assert!(!client.is_established());
    assert_eq!(client.outbound_sequence(), outbound);
    assert!(matches!(
        client.drive_owned_packet(&id),
        Err(TransportError::OwnedPacketState)
    ));
    server
        .join()
        .map_err(|_| "server panicked")?
        .map_err(|e| e.to_string())?;
    Ok(())
}

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
