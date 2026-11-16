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
    read_allowance: Arc<AtomicUsize>,
}

impl Read for GatedSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let allowed = self.read_allowance.load(Ordering::SeqCst);
        if allowed == 0 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let length = bytes.len().min(allowed);
        let count = self.socket.read(&mut bytes[..length])?;
        if allowed != usize::MAX {
            self.read_allowance.fetch_sub(count, Ordering::SeqCst);
        }
        Ok(count)
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

/// Peer for `owned_packet_defers_pong_without_losing_inbound_or_sequence`.
///
/// Waits until the client is parked in an owned packet before sending the
/// deferred ping, so the ping and the payload after it queue behind the
/// client's blocked outbound write.
fn serve_deferred_ping(
    listener: &TcpListener,
    proceed: &mpsc::Receiver<()>,
    ping_queued: &mpsc::Sender<()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut server = ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32])).accept(stream)?;
    let policy = neotales_ssh::ServerAuthPolicy::new(4)?
        .with_authorized_key(&Ed25519Signer::from_seed(&mut [49; 32]).public_key_blob()?)?;
    neotales_ssh::authenticate_server(&mut server, &policy)?;
    proceed.recv_timeout(Duration::from_secs(5))?;
    server.write_payload(b"\x5ebefore-ping")?;
    server.send_ping(b"deferred")?;
    server.write_payload(b"\x5einbound")?;
    ping_queued.send(())?;
    assert_eq!(server.read_payload()?, b"\x5eoutbound");
    assert_eq!(
        TransportPing::decode(&server.read_payload()?)?,
        TransportPing::Pong(b"deferred".to_vec())
    );
    Ok(())
}

#[test]
fn owned_packet_defers_pong_without_losing_inbound_or_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    use neotales_ssh::transport::{OwnedInbound, TransportError};
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let (proceed_tx, proceed_rx) = mpsc::channel();
    let (ping_queued_tx, ping_queued_rx) = mpsc::channel();
    let server =
        std::thread::spawn(move || serve_deferred_ping(&listener, &proceed_rx, &ping_queued_tx));
    let stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let allowance = Arc::new(AtomicUsize::new(usize::MAX));
    let read_allowance = Arc::new(AtomicUsize::new(usize::MAX));
    let mut client = ClientConfig::new().connect(
        GatedSocket {
            socket: stream,
            allowance: Arc::clone(&allowance),
            read_allowance: Arc::clone(&read_allowance),
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
    proceed_tx.send(())?;
    ping_queued_rx.recv_timeout(Duration::from_secs(5))?;
    assert!(matches!(
        client.read_while_owned(&id)?,
        OwnedInbound::Payload(bytes) if bytes == b"\x5ebefore-ping"
    ));
    let mut blocked_reads = 0;
    loop {
        read_allowance.store(1, Ordering::SeqCst);
        match client.read_while_owned(&id) {
            Ok(OwnedInbound::PongDeferred) => break,
            Err(TransportError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                blocked_reads += 1;
                assert!(blocked_reads < 256);
                assert_eq!(client.inbound_sequence(), inbound + 1);
                assert_eq!(client.outbound_sequence(), outbound);
            }
            other => panic!("unexpected partial ping result: {other:?}"),
        }
    }
    assert!(blocked_reads > 1);
    read_allowance.store(usize::MAX, Ordering::SeqCst);
    assert_eq!(client.inbound_sequence(), inbound + 2);
    assert_eq!(client.outbound_sequence(), outbound);
    assert!(matches!(
        client.read_while_owned(&id)?,
        OwnedInbound::Payload(bytes) if bytes == b"\x5einbound"
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
    server
        .join()
        .map_err(|_| "server panicked")?
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn malformed_peer_kexinit_while_owned_terminally_disables_protected_io()
-> Result<(), Box<dyn std::error::Error>> {
    use neotales_ssh::transport::TransportError;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let (proceed_tx, proceed_rx) = mpsc::channel();
    let (malformed_kex_tx, malformed_kex_rx) = mpsc::channel();
    let server = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let (stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut server =
                ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32])).accept(stream)?;
            let policy = neotales_ssh::ServerAuthPolicy::new(4)?
                .with_authorized_key(&Ed25519Signer::from_seed(&mut [49; 32]).public_key_blob()?)?;
            neotales_ssh::authenticate_server(&mut server, &policy)?;
            proceed_rx.recv_timeout(Duration::from_secs(5))?;
            server.write_payload(&[20])?;
            malformed_kex_tx.send(())?;
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
            read_allowance: Arc::new(AtomicUsize::new(usize::MAX)),
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
    proceed_tx.send(())?;
    malformed_kex_rx.recv_timeout(Duration::from_secs(5))?;
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

fn exercise_owned_ping_capacity(partial: bool) -> Result<(), Box<dyn std::error::Error>> {
    use neotales_ssh::transport::{OwnedInbound, TransportError};
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let server = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let (socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut server =
                ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32])).accept(socket)?;
            let policy = neotales_ssh::ServerAuthPolicy::new(4)?
                .with_authorized_key(&Ed25519Signer::from_seed(&mut [49; 32]).public_key_blob()?)?;
            neotales_ssh::authenticate_server(&mut server, &policy)?;
            for i in 0..9u8 {
                server.send_ping(&[i])?;
            }
            ready_tx.send(())?;
            assert_eq!(server.read_payload()?, b"\x5eoutbound");
            for i in 0..8u8 {
                assert_eq!(
                    TransportPing::decode(&server.read_payload()?)?,
                    TransportPing::Pong(vec![i])
                );
            }
            done_rx.recv_timeout(Duration::from_secs(5))?;
            Ok(())
        },
    );
    let socket = TcpStream::connect(address)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let allowance = Arc::new(AtomicUsize::new(usize::MAX));
    let read_allowance = Arc::new(AtomicUsize::new(usize::MAX));
    let mut client = ClientConfig::new().connect(
        GatedSocket {
            socket,
            allowance: Arc::clone(&allowance),
            read_allowance: Arc::clone(&read_allowance),
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
    let sequence = client.inbound_sequence();
    let id = client.start_owned_packet(b"\x5eoutbound")?;
    allowance.store(1, Ordering::SeqCst);
    assert!(
        matches!(client.drive_owned_packet(&id), Err(TransportError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock)
    );
    ready_rx.recv_timeout(Duration::from_secs(5))?;
    let count = if partial { 7 } else { 8 };
    for _ in 0..count {
        assert!(matches!(
            client.read_while_owned(&id)?,
            OwnedInbound::PongDeferred
        ));
    }
    if partial {
        read_allowance.store(1, Ordering::SeqCst);
        assert!(
            matches!(client.read_while_owned(&id), Err(TransportError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(client.inbound_sequence(), sequence + 7);
        read_allowance.store(123, Ordering::SeqCst);
        assert!(matches!(
            client.read_while_owned(&id)?,
            OwnedInbound::PongDeferred
        ));
    }
    let remaining = read_allowance.load(Ordering::SeqCst);
    assert!(matches!(
        client.read_while_owned(&id),
        Err(TransportError::OwnedPacketState)
    ));
    assert_eq!(client.inbound_sequence(), sequence + 8);
    assert_eq!(read_allowance.load(Ordering::SeqCst), remaining);
    read_allowance.store(usize::MAX, Ordering::SeqCst);
    allowance.store(usize::MAX, Ordering::SeqCst);
    client.drive_owned_packet(&id)?;
    for _ in 0..8 {
        client.drive_deferred_pong()?;
    }
    let next = client.start_owned_packet(b"\x5enext")?;
    assert!(matches!(
        client.read_while_owned(&next)?,
        OwnedInbound::PongDeferred
    ));
    assert_eq!(client.inbound_sequence(), sequence + 9);
    done_tx.send(())?;
    server
        .join()
        .map_err(|_| "server panicked")?
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn owned_pings_fill_queue_and_keep_wire_order() -> Result<(), Box<dyn std::error::Error>> {
    exercise_owned_ping_capacity(false)
}

#[test]
fn owned_partial_read_reserves_obligation_slot() -> Result<(), Box<dyn std::error::Error>> {
    exercise_owned_ping_capacity(true)
}
