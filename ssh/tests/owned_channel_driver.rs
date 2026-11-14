//! Owned channel admission against a synthetic local SSH peer.
#![allow(missing_docs)]

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

use neotales_ssh::{
    ClientConfig, ServerConfig,
    channel::{ChannelConnection, ChannelEvent, OwnedChannelDriver, OwnedChannelError},
    hostkey::Ed25519Signer,
    transport::TransportError,
};

const FATAL: usize = usize::MAX - 1;

#[derive(Debug)]
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
        if allowed == FATAL {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
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

type TestDriver = OwnedChannelDriver<GatedSocket>;
type Peer = std::thread::JoinHandle<Result<Option<Vec<u8>>, String>>;
type Fixture = (TestDriver, Arc<AtomicUsize>, u32, Peer);

fn setup() -> Result<Fixture, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let (ready, opened) = mpsc::channel();
    let peer = std::thread::spawn(move || -> Result<Option<Vec<u8>>, String> {
        let (socket, _) = listener.accept().map_err(|e| e.to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        let mut transport = ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32]))
            .accept(socket)
            .map_err(|e| e.to_string())?;
        let policy = neotales_ssh::ServerAuthPolicy::new(4)
            .and_then(|p| {
                p.with_authorized_key(
                    &Ed25519Signer::from_seed(&mut [49; 32])
                        .public_key_blob()
                        .expect("synthetic public key"),
                )
            })
            .map_err(|e| e.to_string())?;
        neotales_ssh::authenticate_server(&mut transport, &policy).map_err(|e| e.to_string())?;
        let mut channels = ChannelConnection::new(transport);
        let ChannelEvent::OpenRequest(request) =
            channels.dispatch_one().map_err(|e| e.to_string())?
        else {
            return Err("expected open".into());
        };
        channels
            .confirm_open_with_limits(request.sender_channel(), 7, 17, 128)
            .map_err(|e| e.to_string())?;
        ready.send(()).map_err(|e| e.to_string())?;
        match channels.dispatch_one() {
            Ok(ChannelEvent::Data { channel: 7, data }) => Ok(Some(data)),
            Err(error) => {
                let socket = channels.into_inner().into_inner();
                match socket.peek(&mut [0]) {
                    Ok(0) => Ok(None),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        Ok(None)
                    }
                    other => Err(format!("expected socket closure after {error}: {other:?}")),
                }
            }
            other => Err(format!("unexpected peer event: {other:?}")),
        }
    });
    let socket = TcpStream::connect(address)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let allowance = Arc::new(AtomicUsize::new(usize::MAX));
    let mut transport = ClientConfig::new().connect(
        GatedSocket {
            socket,
            allowance: Arc::clone(&allowance),
        },
        |_| Ok::<(), ()>(()),
    )?;
    neotales_ssh::authenticate_client(
        &mut transport,
        "user",
        &[neotales_ssh::ClientAuthMethod::public_key(
            neotales_ssh::auth::PublicKeySigner::ed25519(Ed25519Signer::from_seed(&mut [49; 32])),
        )],
        4,
    )?;
    let mut channels = ChannelConnection::new(transport);
    channels.open_channel(0, b"session", &[])?;
    opened.recv_timeout(Duration::from_secs(5))?;
    assert!(matches!(channels.dispatch_one()?, ChannelEvent::Opened(0)));
    let sequence = channels.transport().outbound_sequence();
    let driver = OwnedChannelDriver::try_new(channels).map_err(|_| "driver refused")?;
    Ok((driver, allowance, sequence, peer))
}

#[test]
fn admission_reserves_once_and_partial_packet_has_single_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, allowance, sequence, peer) = setup()?;
    let (mut foreign, _, _, foreign_peer) = setup()?;
    let foreign_id = foreign.admit_data(0, b"other")?;
    assert!(matches!(
        driver.admit_data(0, &[0; 18]),
        Err(OwnedChannelError::Channel(_))
    ));
    assert_eq!(driver.channel(0).unwrap().remote_window(), 17);
    assert_eq!(driver.outbound_sequence(), sequence);
    let id = driver.admit_data(0, b"abc")?;
    assert_eq!(driver.channel(0).unwrap().remote_window(), 14);
    assert_eq!(driver.outbound_sequence(), sequence);
    assert!(matches!(
        driver.admit_data(0, b"x"),
        Err(OwnedChannelError::Busy)
    ));
    assert!(matches!(
        driver.drive(&foreign_id),
        Err(OwnedChannelError::Busy)
    ));
    let mut driver = driver.try_into_connection().unwrap_err();
    let mut partials = 0;
    loop {
        allowance.store(1, Ordering::SeqCst);
        match driver.drive(&id) {
            Ok(()) => break,
            Err(OwnedChannelError::Transport(TransportError::Io(error)))
                if error.kind() == io::ErrorKind::WouldBlock =>
            {
                assert_eq!(driver.channel(0).unwrap().remote_window(), 14);
                assert_eq!(driver.outbound_sequence(), sequence);
                partials += 1;
                assert!(partials < 256, "packet did not complete");
            }
            other => panic!("unexpected drive result: {other:?}"),
        }
    }
    assert!(partials > 1);
    assert!(matches!(driver.drive(&id), Err(OwnedChannelError::Busy)));
    let channels = driver
        .try_into_connection()
        .map_err(|_| "busy after completion")?;
    assert_eq!(channels.channel(0).unwrap().remote_window(), 14);
    assert_eq!(channels.transport().outbound_sequence(), sequence + 1);
    assert_eq!(
        peer.join().map_err(|_| "peer panic")??,
        Some(b"abc".to_vec())
    );
    drop(foreign);
    assert_eq!(foreign_peer.join().map_err(|_| "peer panic")??, None);
    Ok(())
}

#[test]
fn dropped_id_and_fatal_partial_write_cannot_release_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut abandoned, allowance, _, abandoned_peer) = setup()?;
    let id = abandoned.admit_data(0, b"abc")?;
    allowance.store(1, Ordering::SeqCst);
    assert!(matches!(
        abandoned.drive(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(e))) if e.kind() == io::ErrorKind::WouldBlock
    ));
    drop(id);
    let abandoned = abandoned.try_into_connection().unwrap_err();
    drop(abandoned);
    assert_eq!(abandoned_peer.join().map_err(|_| "peer panic")??, None);

    let (mut failed, allowance, sequence, peer) = setup()?;
    let id = failed.admit_data(0, b"abc")?;
    allowance.store(1, Ordering::SeqCst);
    assert!(matches!(
        failed.drive(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(e))) if e.kind() == io::ErrorKind::WouldBlock
    ));
    allowance.store(FATAL, Ordering::SeqCst);
    assert!(matches!(
        failed.drive(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(e))) if e.kind() == io::ErrorKind::BrokenPipe
    ));
    assert_eq!(failed.channel(0).unwrap().remote_window(), 14);
    assert_eq!(failed.outbound_sequence(), sequence);
    assert!(matches!(failed.drive(&id), Err(OwnedChannelError::Failed)));
    let failed = failed.try_into_connection().unwrap_err();
    drop(failed);
    assert_eq!(peer.join().map_err(|_| "peer panic")??, None);
    Ok(())
}

#[test]
fn constructor_refuses_a_connection_with_an_existing_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let (driver, _, _, peer) = setup()?;
    let mut connection = driver
        .try_into_connection()
        .map_err(|_| "unexpected busy driver")?;
    let id = connection
        .transport_mut()
        .start_owned_packet(b"\x5eexisting")?;
    let connection = OwnedChannelDriver::try_new(connection).unwrap_err();
    drop(id);
    drop(connection);
    assert_eq!(peer.join().map_err(|_| "peer panic")??, None);

    let (driver, allowance, _, peer) = setup()?;
    let mut connection = driver
        .try_into_connection()
        .map_err(|_| "unexpected busy driver")?;
    allowance.store(1, Ordering::SeqCst);
    assert!(matches!(
        connection.transport_mut().write_payload(b"\x5elegacy"),
        Err(TransportError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock
    ));
    let connection = OwnedChannelDriver::try_new(connection).unwrap_err();
    drop(connection);
    assert_eq!(peer.join().map_err(|_| "peer panic")??, None);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)] // One synchronized trace proves the ordering.
fn partial_window_adjustment_allows_reading_a_queued_peer_adjustment()
-> Result<(), Box<dyn std::error::Error>> {
    use neotales_ssh::channel::{INITIAL_CHANNEL_WINDOW, OwnedChannelInbound};

    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let (opened_tx, opened_rx) = mpsc::channel();
    let (send_tx, send_rx) = mpsc::channel();
    let (sent_tx, sent_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let peer = std::thread::spawn(move || -> Result<(), String> {
        let (socket, _) = listener.accept().map_err(|e| e.to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        let mut transport = ServerConfig::new(Ed25519Signer::from_seed(&mut [8; 32]))
            .accept(socket)
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
        neotales_ssh::authenticate_server(&mut transport, &policy).map_err(|e| e.to_string())?;
        let mut channels = ChannelConnection::new(transport);
        let ChannelEvent::OpenRequest(request) =
            channels.dispatch_one().map_err(|e| e.to_string())?
        else {
            return Err("expected channel open".into());
        };
        channels
            .confirm_open_with_limits(request.sender_channel(), 7, 17, 128)
            .map_err(|e| e.to_string())?;
        opened_tx.send(()).map_err(|e| e.to_string())?;
        send_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        channels
            .increase_local_window(7, 1)
            .map_err(|e| e.to_string())?;
        sent_tx.send(()).map_err(|e| e.to_string())?;
        // Keep the peer from reading the client's partial protected packet
        // until the test has observed the driver's read progress.
        release_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        match channels.dispatch_one().map_err(|e| e.to_string())? {
            ChannelEvent::WindowAdjusted {
                channel: 7,
                available,
            } if available == INITIAL_CHANNEL_WINDOW + 1 => Ok(()),
            event => Err(format!("unexpected peer event: {event:?}")),
        }
    });
    let socket = TcpStream::connect(address)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let allowance = Arc::new(AtomicUsize::new(usize::MAX));
    let mut transport = ClientConfig::new().connect(
        GatedSocket {
            socket,
            allowance: Arc::clone(&allowance),
        },
        |_| Ok::<(), ()>(()),
    )?;
    neotales_ssh::authenticate_client(
        &mut transport,
        "user",
        &[neotales_ssh::ClientAuthMethod::public_key(
            neotales_ssh::auth::PublicKeySigner::ed25519(Ed25519Signer::from_seed(&mut [49; 32])),
        )],
        4,
    )?;
    let mut channels = ChannelConnection::new(transport);
    channels.open_channel(0, b"session", &[])?;
    opened_rx.recv_timeout(Duration::from_secs(5))?;
    assert!(matches!(channels.dispatch_one()?, ChannelEvent::Opened(0)));
    let mut driver = OwnedChannelDriver::try_new(channels).map_err(|_| "driver refused")?;
    let sequence = driver.outbound_sequence();
    let id = driver.admit_window_adjustment(0, 1)?;
    allowance.store(1, Ordering::SeqCst);
    assert_eq!(
        allowance.load(Ordering::SeqCst),
        1,
        "one byte must be allowed"
    );
    assert!(matches!(
        driver.drive_window_adjustment(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert_eq!(
        allowance.load(Ordering::SeqCst),
        0,
        "one-byte allowance must be consumed"
    );
    send_tx.send(())?;
    sent_rx.recv_timeout(Duration::from_secs(5))?;
    assert!(matches!(
        driver.read_while_window_adjustment(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::WindowAdjusted {
            channel: 0,
            available: 18
        })
    ));
    assert_eq!(driver.outbound_sequence(), sequence);
    assert_eq!(driver.channel(0).unwrap().remote_window(), 18);
    assert_eq!(
        driver.channel(0).unwrap().local_window(),
        INITIAL_CHANNEL_WINDOW
    );

    // The peer was deliberately held back; this proves read progress during
    // a partial packet, not that a real TCP connection would deadlock.
    allowance.store(usize::MAX, Ordering::SeqCst);
    assert_eq!(
        driver.drive_window_adjustment(&id)?,
        INITIAL_CHANNEL_WINDOW + 1
    );
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    release_tx.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}
