//! Incremental inbound steps while one owned outbound packet is active.
#![allow(missing_docs)]

use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

use neotales_ssh::{
    ClientConfig, ClientTransport, ServerConfig, ServerTransport,
    channel::{
        ChannelConnection, ChannelError, ChannelEvent, ChannelId, OwnedChannelDriver,
        OwnedChannelError, OwnedChannelInbound, OwnedChannelWriteId,
    },
    hostkey::Ed25519Signer,
    keepalive::{GlobalRequest, TransportPing},
    server::ServerTransportError,
    transport::TransportError,
};

#[derive(Debug)]
struct GatedSocket {
    socket: TcpStream,
    write_allowance: Arc<AtomicUsize>,
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
        let allowed = self.write_allowance.load(Ordering::SeqCst);
        if allowed == usize::MAX - 1 {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        if allowed == 0 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let count = self.socket.write(&bytes[..bytes.len().min(allowed)])?;
        if allowed != usize::MAX {
            self.write_allowance.fetch_sub(count, Ordering::SeqCst);
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

#[derive(Debug)]
enum PeerStep {
    Data(Vec<u8>),
    DataOn(ChannelId, Vec<u8>),
    Window(u32),
    WindowOn(ChannelId, u32),
    Eof,
    EofOn(ChannelId),
    Close,
    CloseOn(ChannelId),
    Ping(Vec<u8>),
    GlobalRequest {
        want_reply: bool,
    },
    Open(u32),
    Request {
        request_type: Vec<u8>,
        want_reply: bool,
    },
    RequestOn(ChannelId),
    Raw(Vec<u8>),
    ExpectData(Vec<u8>),
    ExpectDataOn(ChannelId, Vec<u8>),
    ExpectWindow(u32),
    ExpectEof(ChannelId),
    AcceptSecond,
    CycleCloses(u32),
    ExpectPong(Vec<u8>),
    ExpectGlobalFailure,
    ExpectRequestFailure(ChannelId),
    ExpectOpenFailure(ChannelId, u32),
    ExpectTruncatedPacket,
    ExpectOpened(ChannelId),
    ExpectClose(ChannelId),
    Wait(mpsc::Receiver<()>),
    Finish,
}

type TestDriver = OwnedChannelDriver<GatedSocket>;
type Peer = std::thread::JoinHandle<Result<(), String>>;
type Fixture = (
    TestDriver,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    u32,
    mpsc::Sender<PeerStep>,
    Peer,
);

fn run_peer(
    listener: &TcpListener,
    commands: mpsc::Receiver<PeerStep>,
    ready: &mpsc::Sender<()>,
) -> Result<(), String> {
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
    let ChannelEvent::OpenRequest(request) = channels.dispatch_one().map_err(|e| e.to_string())?
    else {
        return Err("expected open".into());
    };
    channels
        .confirm_open_with_limits(request.sender_channel(), 7, 17, 128)
        .map_err(|e| e.to_string())?;
    ready.send(()).map_err(|e| e.to_string())?;
    for step in commands {
        if !run_step(&mut channels, step)? {
            break;
        }
    }
    Ok(())
}

fn run_step(
    channels: &mut ChannelConnection<ServerTransport<TcpStream>>,
    step: PeerStep,
) -> Result<bool, String> {
    match step {
        PeerStep::Data(data) => {
            channels.write_data(7, &data).map_err(|e| e.to_string())?;
        }
        PeerStep::DataOn(channel, data) => {
            channels
                .write_data(channel, &data)
                .map_err(|e| e.to_string())?;
        }
        PeerStep::Window(bytes) => {
            channels
                .increase_local_window(7, bytes)
                .map_err(|e| e.to_string())?;
        }
        PeerStep::WindowOn(channel, bytes) => {
            channels
                .increase_local_window(channel, bytes)
                .map_err(|e| e.to_string())?;
        }
        PeerStep::Eof => channels.send_eof(7).map_err(|e| e.to_string())?,
        PeerStep::EofOn(channel) => channels.send_eof(channel).map_err(|e| e.to_string())?,
        PeerStep::Close => channels.send_close(7).map_err(|e| e.to_string())?,
        PeerStep::CloseOn(channel) => channels.send_close(channel).map_err(|e| e.to_string())?,
        PeerStep::Ping(data) => send_ping(channels, data)?,
        PeerStep::GlobalRequest { want_reply } => send_global_request(channels, want_reply)?,
        PeerStep::Open(local) => channels
            .open_channel(local, b"session", &[])
            .map_err(|e| e.to_string())?,
        PeerStep::Request {
            request_type,
            want_reply,
        } => channels
            .send_request(7, &request_type, want_reply, b"")
            .map_err(|e| e.to_string())?,
        PeerStep::RequestOn(channel) => channels
            .send_request(channel, b"exec", true, b"")
            .map_err(|e| e.to_string())?,
        PeerStep::Raw(payload) => channels
            .transport_mut()
            .write_payload(&payload)
            .map_err(|e| e.to_string())?,
        PeerStep::ExpectData(expected) => expect_data(channels, 7, &expected)?,
        PeerStep::ExpectDataOn(channel, expected) => expect_data(channels, channel, &expected)?,
        PeerStep::ExpectWindow(expected) => expect_window(channels, expected)?,
        PeerStep::ExpectEof(expected) => expect_eof(channels, expected)?,
        PeerStep::AcceptSecond => accept_second(channels)?,
        PeerStep::CycleCloses(count) => cycle_closes(channels, count)?,
        PeerStep::ExpectPong(expected) => {
            let payload = channels
                .transport_mut()
                .read_payload()
                .map_err(|e| e.to_string())?;
            match TransportPing::decode(&payload).map_err(|e| e.to_string())? {
                TransportPing::Pong(data) if data == expected => {}
                other => return Err(format!("expected client pong, got {other:?}")),
            }
        }
        PeerStep::ExpectGlobalFailure => {
            match channels.dispatch_one().map_err(|e| e.to_string())? {
                ChannelEvent::GlobalRequestFailed { .. } => {}
                other => return Err(format!("expected global failure, got {other:?}")),
            }
        }
        PeerStep::ExpectRequestFailure(expected) => {
            match channels.dispatch_one().map_err(|e| e.to_string())? {
                ChannelEvent::RequestFailed { channel } if channel == expected => {}
                other => return Err(format!("expected channel failure, got {other:?}")),
            }
        }
        PeerStep::ExpectOpenFailure(expected, reason) => {
            expect_open_failure(channels, expected, reason)?;
        }
        PeerStep::ExpectTruncatedPacket => expect_truncated(channels.transport_mut())?,
        PeerStep::ExpectOpened(expected) => {
            match channels.dispatch_one().map_err(|e| e.to_string())? {
                ChannelEvent::Opened(channel) if channel == expected => {}
                other => return Err(format!("expected opened channel, got {other:?}")),
            }
        }
        PeerStep::ExpectClose(expected) => {
            match channels.dispatch_one().map_err(|e| e.to_string())? {
                ChannelEvent::Close { channel } if channel == expected => {}
                other => return Err(format!("expected client close, got {other:?}")),
            }
        }
        PeerStep::Wait(release) => {
            release
                .recv_timeout(Duration::from_secs(5))
                .map_err(|e| e.to_string())?;
        }
        PeerStep::Finish => return Ok(false),
    }
    Ok(true)
}

fn expect_truncated(transport: &mut ServerTransport<TcpStream>) -> Result<(), String> {
    match transport.read_payload() {
        Err(ServerTransportError::Transport(TransportError::Truncated)) => Ok(()),
        Err(ServerTransportError::Transport(TransportError::Io(error)))
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            Err(format!("peer timed out waiting for EOF: {error}"))
        }
        other => Err(format!(
            "expected truncated packet after EOF, got {other:?}"
        )),
    }
}

fn send_global_request(
    channels: &mut ChannelConnection<ServerTransport<TcpStream>>,
    want_reply: bool,
) -> Result<(), String> {
    let request = if want_reply {
        GlobalRequest::keepalive_with_reply()
    } else {
        GlobalRequest::keepalive()
    };
    let payload = request.encode().map_err(|e| e.to_string())?;
    channels
        .transport_mut()
        .write_payload(&payload)
        .map_err(|e| e.to_string())
}

fn send_ping(
    channels: &mut ChannelConnection<ServerTransport<TcpStream>>,
    data: Vec<u8>,
) -> Result<(), String> {
    let payload = TransportPing::Ping(data)
        .encode()
        .map_err(|e| e.to_string())?;
    channels
        .transport_mut()
        .write_payload(&payload)
        .map_err(|e| e.to_string())
}

fn accept_second(
    channels: &mut ChannelConnection<ServerTransport<TcpStream>>,
) -> Result<(), String> {
    let ChannelEvent::OpenRequest(request) = channels.dispatch_one().map_err(|e| e.to_string())?
    else {
        return Err("expected second open".into());
    };
    channels
        .confirm_open_with_limits(request.sender_channel(), 8, 17, 128)
        .map_err(|e| e.to_string())
}

fn cycle_closes(
    channels: &mut ChannelConnection<ServerTransport<TcpStream>>,
    count: u32,
) -> Result<(), String> {
    for index in 0..count {
        let ChannelEvent::OpenRequest(request) =
            channels.dispatch_one().map_err(|e| e.to_string())?
        else {
            return Err("expected cycle open".into());
        };
        let local = index + 100;
        channels
            .confirm_open_with_limits(request.sender_channel(), local, 17, 128)
            .map_err(|e| e.to_string())?;
        channels.send_close(local).map_err(|e| e.to_string())?;
        if !matches!(channels.dispatch_one().map_err(|e| e.to_string())?, ChannelEvent::Close { channel } if channel == local)
        {
            return Err("expected cycle close".into());
        }
    }
    Ok(())
}

fn expect_eof(
    channels: &mut ChannelConnection<ServerTransport<TcpStream>>,
    expected: ChannelId,
) -> Result<(), String> {
    match channels.dispatch_one().map_err(|e| e.to_string())? {
        ChannelEvent::Eof { channel } if channel == expected => Ok(()),
        other => Err(format!("expected channel EOF, got {other:?}")),
    }
}

fn expect_window(
    channels: &mut ChannelConnection<ServerTransport<TcpStream>>,
    expected: u32,
) -> Result<(), String> {
    match channels.dispatch_one().map_err(|e| e.to_string())? {
        ChannelEvent::WindowAdjusted {
            channel: 7,
            available,
        } if available == expected => Ok(()),
        other => Err(format!("expected window adjustment, got {other:?}")),
    }
}

fn expect_data(
    channels: &mut ChannelConnection<ServerTransport<TcpStream>>,
    expected_channel: ChannelId,
    expected: &[u8],
) -> Result<(), String> {
    match channels.dispatch_one().map_err(|e| e.to_string())? {
        ChannelEvent::Data { channel, data } if channel == expected_channel && data == expected => {
            Ok(())
        }
        other => Err(format!("expected channel data, got {other:?}")),
    }
}

fn expect_open_failure(
    channels: &mut ChannelConnection<ServerTransport<TcpStream>>,
    expected: ChannelId,
    reason: u32,
) -> Result<(), String> {
    match channels.dispatch_one().map_err(|e| e.to_string())? {
        ChannelEvent::OpenFailed {
            channel,
            reason: received,
            description,
            language,
        } if channel == expected
            && received == reason
            && description.is_empty()
            && language.is_empty() =>
        {
            Ok(())
        }
        other => Err(format!("expected channel open failure, got {other:?}")),
    }
}

struct Harness {
    connection: ChannelConnection<ClientTransport<GatedSocket>>,
    write_allowance: Arc<AtomicUsize>,
    read_allowance: Arc<AtomicUsize>,
    sequence: u32,
    steps: mpsc::Sender<PeerStep>,
    peer: Peer,
}

fn setup_connection() -> Result<Harness, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let (ready, opened) = mpsc::channel();
    let (steps, commands) = mpsc::channel();
    let peer = std::thread::spawn(move || run_peer(&listener, commands, &ready));
    let socket = TcpStream::connect(address)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let write_allowance = Arc::new(AtomicUsize::new(usize::MAX));
    let read_allowance = Arc::new(AtomicUsize::new(usize::MAX));
    let mut transport = ClientConfig::new().connect(
        GatedSocket {
            socket,
            write_allowance: Arc::clone(&write_allowance),
            read_allowance: Arc::clone(&read_allowance),
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
    Ok(Harness {
        connection: channels,
        write_allowance,
        read_allowance,
        sequence,
        steps,
        peer,
    })
}

fn setup() -> Result<Fixture, Box<dyn std::error::Error>> {
    let Harness {
        connection,
        write_allowance,
        read_allowance,
        sequence,
        steps,
        peer,
    } = setup_connection()?;
    let driver = OwnedChannelDriver::try_new(connection).map_err(|_| "driver refused")?;
    Ok((
        driver,
        write_allowance,
        read_allowance,
        sequence,
        steps,
        peer,
    ))
}

fn setup_two_channels() -> Result<Fixture, Box<dyn std::error::Error>> {
    let Harness {
        mut connection,
        write_allowance,
        read_allowance,
        sequence,
        steps,
        peer,
    } = setup_connection()?;
    steps.send(PeerStep::AcceptSecond)?;
    connection.open_channel(1, b"session", &[])?;
    assert!(matches!(
        connection.dispatch_one()?,
        ChannelEvent::Opened(1)
    ));
    let sequence = sequence + 1;
    let driver = OwnedChannelDriver::try_new(connection).map_err(|_| "driver refused")?;
    Ok((
        driver,
        write_allowance,
        read_allowance,
        sequence,
        steps,
        peer,
    ))
}

/// Admits one data packet and leaves it part-written, as a nonblocking writer
/// does when the socket is not writable.
fn admit_partial(
    driver: &mut TestDriver,
    write_allowance: &AtomicUsize,
) -> Result<OwnedChannelWriteId, Box<dyn std::error::Error>> {
    let id = driver.admit_data(0, b"abc")?;
    write_allowance.store(1, Ordering::SeqCst);
    assert!(matches!(
        driver.drive(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(id)
}

#[test]
fn partial_outbound_interleaves_data_window_and_eof_without_event_loss()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    steps.send(PeerStep::Data(b"one".to_vec()))?;
    steps.send(PeerStep::Data(b"two".to_vec()))?;
    steps.send(PeerStep::Window(10))?;
    steps.send(PeerStep::Eof)?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::Finish)?;

    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data })
            if data == b"one"
    ));
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data })
            if data == b"two"
    ));
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::WindowAdjusted {
            channel: 0,
            available: 24,
        })
    ));
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Eof { channel: 0 })
    ));
    let channel = driver.channel(0).expect("channel state");
    assert_eq!(channel.local_window(), 65_530);
    assert!(channel.remote_eof_received());

    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    let channels = driver
        .try_into_connection()
        .map_err(|_| "release refused")?;
    assert_eq!(channels.transport().outbound_sequence(), sequence + 1);
    assert_eq!(
        channels.channel(0).expect("channel state").local_window(),
        65_530
    );
    drop(channels);
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn idle_read_delivers_data_window_and_eof_once() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, _write, _read, _sequence, steps, peer) = setup()?;
    steps.send(PeerStep::Data(b"idle".to_vec()))?;
    steps.send(PeerStep::Window(3))?;
    steps.send(PeerStep::Eof)?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    assert!(
        matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"idle")
    );
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::WindowAdjusted {
            channel: 0,
            available: 20
        })
    ));
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::Eof { channel: 0 })
    ));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn owned_window_adjustment_retries_and_separates_credits() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    steps.send(PeerStep::Data(b"12345".to_vec()))?;
    steps.send(PeerStep::ExpectWindow(65_533))?;
    steps.send(PeerStep::ExpectWindow(65_536))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(
        matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"12345")
    );
    assert!(matches!(
        driver.admit_window_adjustment(9, 1),
        Err(OwnedChannelError::Channel(ChannelError::UnknownChannel))
    ));
    assert!(matches!(
        driver.admit_window_adjustment(0, 0),
        Err(OwnedChannelError::Channel(
            ChannelError::InvalidWindowAdjustment
        ))
    ));
    assert!(matches!(
        driver.admit_window_adjustment(0, u32::MAX),
        Err(OwnedChannelError::Channel(ChannelError::Window(_)))
    ));
    let id = driver.admit_window_adjustment(0, 2)?;
    let mut blocks = 0;
    loop {
        write.store(1, Ordering::SeqCst);
        match driver.drive_window_adjustment(&id) {
            Ok(updated) => {
                assert_eq!(updated, 65_533);
                break;
            }
            Err(OwnedChannelError::Transport(TransportError::Io(error)))
                if error.kind() == io::ErrorKind::WouldBlock =>
            {
                blocks += 1;
                assert!(blocks < 256);
                assert_eq!(driver.channel(0).unwrap().local_window(), 65_531);
                assert_eq!(driver.outbound_sequence(), sequence);
                assert!(matches!(
                    driver.admit_window_adjustment(0, 3),
                    Err(OwnedChannelError::Busy)
                ));
                assert!(matches!(driver.read_idle(), Err(OwnedChannelError::Busy)));
                assert!(matches!(
                    driver.admit_data(0, b"x"),
                    Err(OwnedChannelError::Busy)
                ));
                driver = driver
                    .try_into_connection()
                    .expect_err("window packet released");
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(blocks > 1);
    assert!(matches!(
        driver.drive_window_adjustment(&id),
        Err(OwnedChannelError::Busy)
    ));
    let next = driver.admit_window_adjustment(0, 3)?;
    assert!(matches!(
        driver.drive_window_adjustment(&id),
        Err(OwnedChannelError::Busy)
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    assert_eq!(driver.drive_window_adjustment(&next)?, 65_536);
    assert_eq!(driver.outbound_sequence(), sequence + 2);
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn owned_eof_retries_one_byte_and_preserves_read_half() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectWindow(65_537))?;
    steps.send(PeerStep::ExpectEof(7))?;
    steps.send(PeerStep::Data(b"response".to_vec()))?;
    steps.send(PeerStep::Eof)?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    let data = driver.admit_data(0, b"abc")?;
    assert!(matches!(driver.admit_eof(0), Err(OwnedChannelError::Busy)));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&data)?;
    let credit = driver.admit_window_adjustment(0, 1)?;
    assert!(matches!(driver.admit_eof(0), Err(OwnedChannelError::Busy)));
    driver.drive_window_adjustment(&credit)?;
    assert!(matches!(
        driver.admit_eof(9),
        Err(OwnedChannelError::Channel(ChannelError::UnknownChannel))
    ));
    let id = driver.admit_eof(0)?;
    let mut blocks = 0;
    loop {
        write.store(1, Ordering::SeqCst);
        match driver.drive_eof(&id) {
            Ok(()) => break,
            Err(OwnedChannelError::Transport(TransportError::Io(error)))
                if error.kind() == io::ErrorKind::WouldBlock =>
            {
                blocks += 1;
                assert!(blocks < 256);
                assert!(!driver.channel(0).unwrap().local_eof_sent());
                assert_eq!(driver.outbound_sequence(), sequence + 2);
                assert!(matches!(driver.read_idle(), Err(OwnedChannelError::Busy)));
                assert!(matches!(
                    driver.admit_data(0, b"x"),
                    Err(OwnedChannelError::Busy)
                ));
                assert!(matches!(
                    driver.admit_window_adjustment(0, 1),
                    Err(OwnedChannelError::Busy)
                ));
                driver = driver
                    .try_into_connection()
                    .expect_err("partial EOF released");
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(blocks > 1);
    assert!(driver.channel(0).unwrap().local_eof_sent());
    assert_eq!(driver.outbound_sequence(), sequence + 3);
    assert!(matches!(
        driver.drive_eof(&id),
        Err(OwnedChannelError::Busy)
    ));
    assert!(matches!(
        driver.admit_eof(0),
        Err(OwnedChannelError::Channel(ChannelError::DataAfterEof))
    ));
    assert!(matches!(
        driver.admit_data(0, b"x"),
        Err(OwnedChannelError::Channel(ChannelError::DataAfterEof))
    ));
    assert!(
        matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"response")
    );
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::Eof { channel: 0 })
    ));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn remote_first_eof_allows_one_local_eof() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    steps.send(PeerStep::Eof)?;
    steps.send(PeerStep::ExpectEof(7))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::Eof { channel: 0 })
    ));
    assert!(driver.channel(0).unwrap().remote_eof_received());
    let id = driver.admit_eof(0)?;
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive_eof(&id)?;
    let state = driver.channel(0).unwrap();
    assert!(state.local_eof_sent() && state.remote_eof_received());
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    assert!(matches!(
        driver.drive_eof(&id),
        Err(OwnedChannelError::Busy)
    ));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn eof_requires_confirmed_peer_channel() -> Result<(), Box<dyn std::error::Error>> {
    let Harness {
        mut connection,
        write_allowance: _,
        read_allowance: _,
        sequence: _,
        steps,
        peer,
    } = setup_connection()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    connection.open_channel(1, b"session", &[])?;
    let mut driver = OwnedChannelDriver::try_new(connection).map_err(|_| "driver refused")?;
    assert!(matches!(
        driver.admit_eof(1),
        Err(OwnedChannelError::Channel(ChannelError::InvalidMessage))
    ));
    assert!(!driver.channel(1).unwrap().local_eof_sent());
    drop(driver);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn foreign_eof_id_does_not_advance_or_commit() -> Result<(), Box<dyn std::error::Error>> {
    let (mut first, write, _read, sequence, steps, peer) = setup()?;
    let (mut second, _write2, _read2, _sequence2, steps2, peer2) = setup()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::ExpectEof(7))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    steps2.send(PeerStep::Wait(wait))?;
    steps2.send(PeerStep::Finish)?;
    let id = first.admit_eof(0)?;
    let foreign = second.admit_eof(0)?;
    write.store(usize::MAX, Ordering::SeqCst);
    assert!(matches!(
        first.read_while_eof(&foreign),
        Err(OwnedChannelError::Busy)
    ));
    assert!(matches!(
        first.drive_eof(&foreign),
        Err(OwnedChannelError::Busy)
    ));
    assert!(!first.channel(0).unwrap().local_eof_sent());
    assert_eq!(first.outbound_sequence(), sequence);
    first.drive_eof(&id)?;
    assert!(matches!(
        first.read_while_eof(&id),
        Err(OwnedChannelError::Busy)
    ));
    drop(first.try_into_connection().map_err(|_| "release refused")?);
    drop(second);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    peer2.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn partial_eof_fatal_and_cancel_leave_state_uncommitted() -> Result<(), Box<dyn std::error::Error>>
{
    for fatal in [false, true] {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        let id = driver.admit_eof(0)?;
        write.store(1, Ordering::SeqCst);
        assert!(matches!(driver.drive_eof(&id),
            Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
        if fatal {
            write.store(usize::MAX - 1, Ordering::SeqCst);
            assert!(matches!(driver.drive_eof(&id),
                Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::BrokenPipe));
            assert!(matches!(
                driver.drive_eof(&id),
                Err(OwnedChannelError::Failed)
            ));
        }
        assert!(!driver.channel(0).unwrap().local_eof_sent());
        assert_eq!(driver.outbound_sequence(), sequence);
        let driver = driver
            .try_into_connection()
            .expect_err("partial EOF released");
        drop(driver);
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)] // One trace checks each bounded reply kind.
fn reads_during_partial_window_preserve_credit_and_queue_one_reply()
-> Result<(), Box<dyn std::error::Error>> {
    for kind in 0..5 {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::Data(b"abc".to_vec()))?;
        steps.send(PeerStep::Window(1))?;
        match kind {
            0 => steps.send(PeerStep::Ping(b"p".to_vec()))?,
            1 => steps.send(PeerStep::GlobalRequest { want_reply: true })?,
            2 => steps.send(PeerStep::Request {
                request_type: b"exec".to_vec(),
                want_reply: true,
            })?,
            3 => steps.send(PeerStep::Open(9))?,
            _ => steps.send(PeerStep::Close)?,
        }
        steps.send(PeerStep::ExpectWindow(65_538))?;
        match kind {
            0 => steps.send(PeerStep::ExpectPong(b"p".to_vec()))?,
            1 => steps.send(PeerStep::ExpectGlobalFailure)?,
            2 => steps.send(PeerStep::ExpectRequestFailure(7))?,
            3 => steps.send(PeerStep::ExpectOpenFailure(9, 1))?,
            _ => steps.send(PeerStep::ExpectClose(7))?,
        }
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        let id = driver.admit_window_adjustment(0, 5)?;
        write.store(1, Ordering::SeqCst);
        assert!(matches!(driver.drive_window_adjustment(&id),
            Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
        assert_eq!(write.load(Ordering::SeqCst), 0);
        assert!(matches!(driver.read_while_window_adjustment(&id)?,
            OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc"));
        assert_eq!(driver.channel(0).unwrap().local_window(), 65_533);
        assert!(matches!(
            driver.read_while_window_adjustment(&id)?,
            OwnedChannelInbound::Event(ChannelEvent::WindowAdjusted {
                channel: 0,
                available: 18
            })
        ));
        let event = driver.read_while_window_adjustment(&id)?;
        match kind {
            0 => assert!(matches!(event, OwnedChannelInbound::PongDeferred)),
            1 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                    want_reply: true,
                    ..
                })
            )),
            2 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Request {
                    channel: 0,
                    want_reply: true,
                    ..
                })
            )),
            3 => assert!(
                matches!(event, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9)
            ),
            _ => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
            )),
        }
        assert!(matches!(
            driver.read_while_window_adjustment(&id),
            Err(OwnedChannelError::Busy)
        ));
        let early = match kind {
            0 => driver.drive_deferred_pong(),
            1 => driver.drive_global_failure(),
            2 => driver.drive_channel_failure(0),
            3 => driver.drive_open_rejection(9, 1),
            _ => driver.drive_close_reply(0),
        };
        assert!(matches!(early, Err(OwnedChannelError::Busy)));
        assert_eq!(driver.outbound_sequence(), sequence);
        driver = driver
            .try_into_connection()
            .expect_err("partial window released");
        write.store(usize::MAX, Ordering::SeqCst);
        assert_eq!(driver.drive_window_adjustment(&id)?, 65_538);
        assert!(matches!(
            driver.drive_window_adjustment(&id),
            Err(OwnedChannelError::Busy)
        ));
        match kind {
            0 => driver.drive_deferred_pong()?,
            1 => driver.drive_global_failure()?,
            2 => driver.drive_channel_failure(0)?,
            3 => driver.drive_open_rejection(9, 1)?,
            _ => driver.drive_close_reply(0)?,
        }
        assert_eq!(driver.outbound_sequence(), sequence + 2);
        drop(
            driver
                .try_into_connection()
                .map_err(|_| "release refused")?,
        );
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)] // One trace checks every bounded reply and close transition.
fn partial_eof_reads_events_and_retains_one_reply() -> Result<(), Box<dyn std::error::Error>> {
    for kind in 0..5 {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::Data(b"abc".to_vec()))?;
        steps.send(PeerStep::Window(1))?;
        match kind {
            0 => steps.send(PeerStep::Ping(b"p".to_vec()))?,
            1 => steps.send(PeerStep::GlobalRequest { want_reply: true })?,
            2 => steps.send(PeerStep::Request {
                request_type: b"exec".to_vec(),
                want_reply: true,
            })?,
            3 => steps.send(PeerStep::Open(9))?,
            _ => steps.send(PeerStep::Close)?,
        }
        steps.send(PeerStep::ExpectEof(7))?;
        match kind {
            0 => steps.send(PeerStep::ExpectPong(b"p".to_vec()))?,
            1 => steps.send(PeerStep::ExpectGlobalFailure)?,
            2 => steps.send(PeerStep::ExpectRequestFailure(7))?,
            3 => steps.send(PeerStep::ExpectOpenFailure(9, 1))?,
            _ => steps.send(PeerStep::ExpectClose(7))?,
        }
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        let id = driver.admit_eof(0)?;
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_eof(&id), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(write.load(Ordering::SeqCst), 0);
        assert!(
            matches!(driver.read_while_eof(&id)?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc")
        );
        assert_eq!(driver.channel(0).unwrap().local_window(), 65_533);
        assert!(matches!(
            driver.read_while_eof(&id)?,
            OwnedChannelInbound::Event(ChannelEvent::WindowAdjusted {
                channel: 0,
                available: 18
            })
        ));
        let event = driver.read_while_eof(&id)?;
        match kind {
            0 => assert!(matches!(event, OwnedChannelInbound::PongDeferred)),
            1 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                    want_reply: true,
                    ..
                })
            )),
            2 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Request {
                    channel: 0,
                    want_reply: true,
                    ..
                })
            )),
            3 => assert!(
                matches!(event, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9)
            ),
            _ => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
            )),
        }
        assert!(matches!(
            driver.read_while_eof(&id),
            Err(OwnedChannelError::Busy)
        ));
        let early = match kind {
            0 => driver.drive_deferred_pong(),
            1 => driver.drive_global_failure(),
            2 => driver.drive_channel_failure(0),
            3 => driver.drive_open_rejection(9, 1),
            _ => driver.drive_close_reply(0),
        };
        assert!(matches!(early, Err(OwnedChannelError::Busy)));
        assert!(!driver.channel(0).unwrap().local_eof_sent());
        if kind == 4 {
            let state = driver.channel(0).unwrap();
            assert!(state.remote_close_received() && !state.local_close_sent());
            assert!(!driver.is_retired_channel(0));
        }
        assert_eq!(driver.outbound_sequence(), sequence);
        driver = driver
            .try_into_connection()
            .expect_err("partial EOF released");
        write.store(usize::MAX, Ordering::SeqCst);
        driver.drive_eof(&id)?;
        assert!(driver.channel(0).unwrap().local_eof_sent());
        if kind == 4 {
            let state = driver.channel(0).unwrap();
            assert!(state.remote_close_received() && !state.local_close_sent());
            assert!(!driver.is_retired_channel(0));
        }
        assert!(matches!(
            driver.drive_eof(&id),
            Err(OwnedChannelError::Busy)
        ));
        match kind {
            0 => driver.drive_deferred_pong()?,
            1 => driver.drive_global_failure()?,
            2 => driver.drive_channel_failure(0)?,
            3 => driver.drive_open_rejection(9, 1)?,
            _ => driver.drive_close_reply(0)?,
        }
        if kind == 4 {
            assert!(driver.channel(0).is_none());
            assert!(driver.is_retired_channel(0));
        }
        assert_eq!(driver.outbound_sequence(), sequence + 2);
        drop(
            driver
                .try_into_connection()
                .map_err(|_| "release refused")?,
        );
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn partial_eof_with_queued_request_fatal_or_cancel_keeps_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    for fatal in [false, true] {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::GlobalRequest { want_reply: true })?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        let id = driver.admit_eof(0)?;
        write.store(1, Ordering::SeqCst);
        assert!(matches!(driver.drive_eof(&id),
            Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
        assert!(matches!(
            driver.read_while_eof(&id)?,
            OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                want_reply: true,
                ..
            })
        ));
        assert!(matches!(
            driver.drive_global_failure(),
            Err(OwnedChannelError::Busy)
        ));
        if fatal {
            write.store(usize::MAX - 1, Ordering::SeqCst);
            assert!(matches!(driver.drive_eof(&id),
                Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::BrokenPipe));
            assert!(matches!(
                driver.drive_global_failure(),
                Err(OwnedChannelError::Failed)
            ));
        }
        assert!(!driver.channel(0).unwrap().local_eof_sent());
        assert_eq!(driver.outbound_sequence(), sequence);
        let driver = driver
            .try_into_connection()
            .expect_err("partial EOF released");
        drop(driver);
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn rekey_during_partial_eof_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Raw(vec![20]))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    let id = driver.admit_eof(0)?;
    write.store(1, Ordering::SeqCst);
    assert!(matches!(driver.drive_eof(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
    assert!(matches!(
        driver.read_while_eof(&id),
        Err(OwnedChannelError::Transport(
            TransportError::UnexpectedMessage
        ))
    ));
    assert!(matches!(
        driver.drive_eof(&id),
        Err(OwnedChannelError::Failed)
    ));
    assert_eq!(driver.outbound_sequence(), sequence);
    assert!(!driver.channel(0).unwrap().local_eof_sent());
    let driver = driver
        .try_into_connection()
        .expect_err("failed driver released");
    drop(driver);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn partial_inbound_during_eof_resumes_after_eof_completes() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut driver, write, read, sequence, steps, peer) = setup()?;
    steps.send(PeerStep::Data(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectEof(7))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    let id = driver.admit_eof(0)?;
    write.store(1, Ordering::SeqCst);
    assert!(matches!(driver.drive_eof(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
    read.store(1, Ordering::SeqCst);
    assert!(matches!(driver.read_while_eof(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive_eof(&id)?;
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    driver = driver
        .try_into_connection()
        .expect_err("partial inbound released");
    read.store(usize::MAX, Ordering::SeqCst);
    assert!(matches!(driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc"));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn partial_global_reply_retains_one_next_obligation() -> Result<(), Box<dyn std::error::Error>> {
    for kind in 0..5 {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::GlobalRequest { want_reply: true })?;
        steps.send(PeerStep::Data(b"abc".to_vec()))?;
        steps.send(PeerStep::Window(1))?;
        match kind {
            0 => steps.send(PeerStep::Ping(b"p".to_vec()))?,
            1 => {
                steps.send(PeerStep::GlobalRequest { want_reply: true })?;
                steps.send(PeerStep::GlobalRequest { want_reply: true })?;
            }
            2 => steps.send(PeerStep::Request {
                request_type: b"exec".to_vec(),
                want_reply: true,
            })?,
            3 => steps.send(PeerStep::Open(9))?,
            _ => steps.send(PeerStep::Close)?,
        }
        steps.send(PeerStep::ExpectGlobalFailure)?;
        match kind {
            0 => steps.send(PeerStep::ExpectPong(b"p".to_vec()))?,
            1 => {
                steps.send(PeerStep::ExpectGlobalFailure)?;
                steps.send(PeerStep::ExpectGlobalFailure)?;
            }
            2 => steps.send(PeerStep::ExpectRequestFailure(7))?,
            3 => steps.send(PeerStep::ExpectOpenFailure(9, 1))?,
            _ => steps.send(PeerStep::ExpectClose(7))?,
        }
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        assert!(matches!(
            driver.read_idle()?,
            OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                want_reply: true,
                ..
            })
        ));
        assert!(matches!(
            driver.read_while_global_failure(),
            Err(OwnedChannelError::Busy)
        ));
        write.store(1, Ordering::SeqCst);
        assert!(matches!(driver.drive_global_failure(),
            Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
        assert_eq!(write.load(Ordering::SeqCst), 0);
        assert!(matches!(driver.read_while_global_failure()?,
            OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc"));
        assert!(matches!(
            driver.read_while_global_failure()?,
            OwnedChannelInbound::Event(ChannelEvent::WindowAdjusted {
                channel: 0,
                available: 18
            })
        ));
        let event = driver.read_while_global_failure()?;
        match kind {
            0 => assert!(matches!(event, OwnedChannelInbound::PongDeferred)),
            1 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                    want_reply: true,
                    ..
                })
            )),
            2 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Request {
                    channel: 0,
                    want_reply: true,
                    ..
                })
            )),
            3 => assert!(
                matches!(event, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9)
            ),
            _ => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
            )),
        }
        assert!(matches!(
            driver.read_while_global_failure(),
            Err(OwnedChannelError::Busy)
        ));
        assert_eq!(driver.outbound_sequence(), sequence);
        driver = driver
            .try_into_connection()
            .expect_err("partial reply released");
        write.store(usize::MAX, Ordering::SeqCst);
        driver.drive_global_failure()?;
        assert_eq!(driver.outbound_sequence(), sequence + 1);
        assert!(matches!(driver.read_idle(), Err(OwnedChannelError::Busy)));
        match kind {
            0 => driver.drive_deferred_pong()?,
            1 => driver.drive_global_failure()?,
            2 => driver.drive_channel_failure(0)?,
            3 => driver.drive_open_rejection(9, 1)?,
            _ => driver.drive_close_reply(0)?,
        }
        assert_eq!(driver.outbound_sequence(), sequence + 2);
        if kind == 1 {
            assert!(matches!(
                driver.read_idle()?,
                OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                    want_reply: true,
                    ..
                })
            ));
            driver.drive_global_failure()?;
            assert_eq!(driver.outbound_sequence(), sequence + 3);
        }
        drop(
            driver
                .try_into_connection()
                .map_err(|_| "release refused")?,
        );
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn fatal_or_cancelled_global_reply_keeps_next_request_unreleased()
-> Result<(), Box<dyn std::error::Error>> {
    for fatal in [false, true] {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::GlobalRequest { want_reply: true })?;
        steps.send(PeerStep::GlobalRequest { want_reply: true })?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        assert!(matches!(
            driver.read_idle()?,
            OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                want_reply: true,
                ..
            })
        ));
        write.store(1, Ordering::SeqCst);
        assert!(matches!(driver.drive_global_failure(),
            Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
        assert_eq!(write.load(Ordering::SeqCst), 0);
        assert!(matches!(
            driver.read_while_global_failure()?,
            OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                want_reply: true,
                ..
            })
        ));
        assert!(matches!(
            driver.read_while_global_failure(),
            Err(OwnedChannelError::Busy)
        ));
        if fatal {
            write.store(usize::MAX - 1, Ordering::SeqCst);
            assert!(matches!(driver.drive_global_failure(),
                Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::BrokenPipe));
            assert!(matches!(
                driver.read_while_global_failure(),
                Err(OwnedChannelError::Failed)
            ));
        }
        assert_eq!(driver.outbound_sequence(), sequence);
        let driver = driver
            .try_into_connection()
            .expect_err("partial reply released");
        drop(driver);
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn partial_inbound_during_global_reply_resumes_after_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, read, sequence, steps, peer) = setup()?;
    steps.send(PeerStep::GlobalRequest { want_reply: true })?;
    steps.send(PeerStep::Data(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectGlobalFailure)?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
            want_reply: true,
            ..
        })
    ));
    write.store(1, Ordering::SeqCst);
    assert!(matches!(driver.drive_global_failure(),
        Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
    read.store(1, Ordering::SeqCst);
    assert!(matches!(driver.read_while_global_failure(),
        Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive_global_failure()?;
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    driver = driver
        .try_into_connection()
        .expect_err("partial inbound released");
    read.store(usize::MAX, Ordering::SeqCst);
    assert!(matches!(driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc"));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn rekey_during_global_reply_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::GlobalRequest { want_reply: true })?;
    steps.send(PeerStep::Raw(vec![20]))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
            want_reply: true,
            ..
        })
    ));
    write.store(1, Ordering::SeqCst);
    assert!(matches!(driver.drive_global_failure(),
        Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
    assert!(matches!(
        driver.read_while_global_failure(),
        Err(OwnedChannelError::Transport(
            TransportError::UnexpectedMessage
        ))
    ));
    assert!(matches!(
        driver.drive_global_failure(),
        Err(OwnedChannelError::Failed)
    ));
    assert_eq!(driver.outbound_sequence(), sequence);
    let driver = driver
        .try_into_connection()
        .expect_err("failed driver released");
    drop(driver);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)] // One protected transcript exercises all next-obligation kinds.
fn partial_channel_failure_retains_one_next_obligation() -> Result<(), Box<dyn std::error::Error>> {
    for kind in 0..5 {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::Request {
            request_type: b"exec".to_vec(),
            want_reply: true,
        })?;
        steps.send(PeerStep::Data(b"abc".to_vec()))?;
        steps.send(PeerStep::Window(1))?;
        match kind {
            0 => steps.send(PeerStep::Ping(b"p".to_vec()))?,
            1 => steps.send(PeerStep::GlobalRequest { want_reply: true })?,
            2 => {
                steps.send(PeerStep::Request {
                    request_type: b"exec".to_vec(),
                    want_reply: true,
                })?;
                steps.send(PeerStep::Request {
                    request_type: b"exec".to_vec(),
                    want_reply: true,
                })?;
            }
            3 => steps.send(PeerStep::Open(9))?,
            _ => steps.send(PeerStep::Close)?,
        }
        steps.send(PeerStep::ExpectRequestFailure(7))?;
        match kind {
            0 => steps.send(PeerStep::ExpectPong(b"p".to_vec()))?,
            1 => steps.send(PeerStep::ExpectGlobalFailure)?,
            2 => {
                steps.send(PeerStep::ExpectRequestFailure(7))?;
                steps.send(PeerStep::ExpectRequestFailure(7))?;
            }
            3 => steps.send(PeerStep::ExpectOpenFailure(9, 1))?,
            _ => steps.send(PeerStep::ExpectClose(7))?,
        }
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        assert!(matches!(
            driver.read_idle()?,
            OwnedChannelInbound::Event(ChannelEvent::Request {
                channel: 0,
                want_reply: true,
                ..
            })
        ));
        assert!(matches!(
            driver.channel_failure_read_id(0),
            Err(OwnedChannelError::Busy)
        ));
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_channel_failure(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(write.load(Ordering::SeqCst), 0);
        assert!(matches!(
            driver.channel_failure_read_id(7),
            Err(OwnedChannelError::Busy)
        ));
        let read_id = driver.channel_failure_read_id(0)?;
        assert!(
            matches!(driver.read_while_channel_failure(&read_id)?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc")
        );
        assert!(matches!(
            driver.read_while_channel_failure(&read_id)?,
            OwnedChannelInbound::Event(ChannelEvent::WindowAdjusted {
                channel: 0,
                available: 18
            })
        ));
        let event = driver.read_while_channel_failure(&read_id)?;
        match kind {
            0 => assert!(matches!(event, OwnedChannelInbound::PongDeferred)),
            1 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                    want_reply: true,
                    ..
                })
            )),
            2 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Request {
                    channel: 0,
                    want_reply: true,
                    ..
                })
            )),
            3 => assert!(
                matches!(event, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9)
            ),
            _ => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
            )),
        }
        assert!(matches!(
            driver.read_while_channel_failure(&read_id),
            Err(OwnedChannelError::Busy)
        ));
        assert_eq!(driver.outbound_sequence(), sequence);
        driver = driver
            .try_into_connection()
            .expect_err("partial reply released");
        write.store(usize::MAX, Ordering::SeqCst);
        driver.drive_channel_failure(0)?;
        assert_eq!(driver.outbound_sequence(), sequence + 1);
        assert!(matches!(driver.read_idle(), Err(OwnedChannelError::Busy)));
        match kind {
            0 => driver.drive_deferred_pong()?,
            1 => driver.drive_global_failure()?,
            2 => {
                write.store(1, Ordering::SeqCst);
                assert!(
                    matches!(driver.drive_channel_failure(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
                );
                let next_id = driver.channel_failure_read_id(0)?;
                assert!(matches!(
                    driver.read_while_channel_failure(&read_id),
                    Err(OwnedChannelError::Busy)
                ));
                write.store(usize::MAX, Ordering::SeqCst);
                driver.drive_channel_failure(0)?;
                assert!(matches!(
                    driver.read_while_channel_failure(&next_id),
                    Err(OwnedChannelError::Busy)
                ));
            }
            3 => driver.drive_open_rejection(9, 1)?,
            _ => driver.drive_close_reply(0)?,
        }
        assert_eq!(driver.outbound_sequence(), sequence + 2);
        if kind == 2 {
            assert!(matches!(
                driver.read_idle()?,
                OwnedChannelInbound::Event(ChannelEvent::Request {
                    channel: 0,
                    want_reply: true,
                    ..
                })
            ));
            driver.drive_channel_failure(0)?;
            assert_eq!(driver.outbound_sequence(), sequence + 3);
        }
        drop(
            driver
                .try_into_connection()
                .map_err(|_| "release refused")?,
        );
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn partial_channel_reply_with_queued_request_fatal_or_cancel()
-> Result<(), Box<dyn std::error::Error>> {
    for fatal in [false, true] {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::Request {
            request_type: b"exec".to_vec(),
            want_reply: true,
        })?;
        steps.send(PeerStep::Request {
            request_type: b"exec".to_vec(),
            want_reply: true,
        })?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        assert!(matches!(
            driver.read_idle()?,
            OwnedChannelInbound::Event(ChannelEvent::Request {
                channel: 0,
                want_reply: true,
                ..
            })
        ));
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_channel_failure(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(write.load(Ordering::SeqCst), 0);
        let read_id = driver.channel_failure_read_id(0)?;
        assert!(matches!(
            driver.read_while_channel_failure(&read_id)?,
            OwnedChannelInbound::Event(ChannelEvent::Request {
                channel: 0,
                want_reply: true,
                ..
            })
        ));
        assert!(matches!(
            driver.read_while_channel_failure(&read_id),
            Err(OwnedChannelError::Busy)
        ));
        if fatal {
            write.store(usize::MAX - 1, Ordering::SeqCst);
            assert!(
                matches!(driver.drive_channel_failure(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::BrokenPipe)
            );
            assert!(matches!(
                driver.read_while_channel_failure(&read_id),
                Err(OwnedChannelError::Failed)
            ));
        }
        assert_eq!(driver.outbound_sequence(), sequence);
        let driver = driver
            .try_into_connection()
            .expect_err("partial reply released");
        drop(driver);
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn rekey_during_channel_failure_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Request {
        request_type: b"exec".to_vec(),
        want_reply: true,
    })?;
    steps.send(PeerStep::Raw(vec![20]))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::Request {
            channel: 0,
            want_reply: true,
            ..
        })
    ));
    write.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.drive_channel_failure(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let read_id = driver.channel_failure_read_id(0)?;
    assert!(matches!(
        driver.read_while_channel_failure(&read_id),
        Err(OwnedChannelError::Transport(
            TransportError::UnexpectedMessage
        ))
    ));
    assert!(matches!(
        driver.drive_channel_failure(0),
        Err(OwnedChannelError::Failed)
    ));
    assert_eq!(driver.outbound_sequence(), sequence);
    let driver = driver
        .try_into_connection()
        .expect_err("failed driver released");
    drop(driver);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn partial_inbound_during_channel_failure_resumes_after_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, read, sequence, steps, peer) = setup()?;
    steps.send(PeerStep::Request {
        request_type: b"exec".to_vec(),
        want_reply: true,
    })?;
    steps.send(PeerStep::Data(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectRequestFailure(7))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::Request {
            channel: 0,
            want_reply: true,
            ..
        })
    ));
    write.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.drive_channel_failure(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let read_id = driver.channel_failure_read_id(0)?;
    read.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.read_while_channel_failure(&read_id), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive_channel_failure(0)?;
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    driver = driver
        .try_into_connection()
        .expect_err("partial inbound released");
    read.store(usize::MAX, Ordering::SeqCst);
    assert!(
        matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc")
    );
    assert!(matches!(
        driver.read_while_channel_failure(&read_id),
        Err(OwnedChannelError::Busy)
    ));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn foreign_channel_failure_read_id_does_not_consume_input() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut first, write1, _read1, _seq1, steps1, peer1) = setup()?;
    let (mut second, write2, _read2, _seq2, steps2, peer2) = setup()?;
    for steps in [&steps1, &steps2] {
        steps.send(PeerStep::Request {
            request_type: b"exec".to_vec(),
            want_reply: true,
        })?;
        steps.send(PeerStep::Data(b"abc".to_vec()))?;
        steps.send(PeerStep::ExpectRequestFailure(7))?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
    }
    for (driver, write) in [(&mut first, &write1), (&mut second, &write2)] {
        assert!(matches!(
            driver.read_idle()?,
            OwnedChannelInbound::Event(ChannelEvent::Request {
                channel: 0,
                want_reply: true,
                ..
            })
        ));
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_channel_failure(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
    }
    let first_id = first.channel_failure_read_id(0)?;
    let foreign = second.channel_failure_read_id(0)?;
    assert!(matches!(
        first.read_while_channel_failure(&foreign),
        Err(OwnedChannelError::Busy)
    ));
    assert!(
        matches!(first.read_while_channel_failure(&first_id)?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc")
    );
    assert!(matches!(
        second.read_while_channel_failure(&first_id),
        Err(OwnedChannelError::Busy)
    ));
    assert!(
        matches!(second.read_while_channel_failure(&foreign)?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc")
    );
    for (driver, write) in [(&mut first, &write1), (&mut second, &write2)] {
        write.store(usize::MAX, Ordering::SeqCst);
        driver.drive_channel_failure(0)?;
    }
    drop(
        first
            .try_into_connection()
            .map_err(|_| "first release refused")?,
    );
    drop(
        second
            .try_into_connection()
            .map_err(|_| "second release refused")?,
    );
    peer1.join().map_err(|_| "peer panic")??;
    peer2.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)] // One transcript checks every next-obligation kind.
fn partial_open_rejection_retains_one_next_obligation() -> Result<(), Box<dyn std::error::Error>> {
    for kind in 0..5 {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::Open(9))?;
        steps.send(PeerStep::Data(b"abc".to_vec()))?;
        steps.send(PeerStep::Window(1))?;
        match kind {
            0 => steps.send(PeerStep::Ping(b"p".to_vec()))?,
            1 => steps.send(PeerStep::GlobalRequest { want_reply: true })?,
            2 => steps.send(PeerStep::Request {
                request_type: b"exec".to_vec(),
                want_reply: true,
            })?,
            3 => {
                steps.send(PeerStep::Open(10))?;
                steps.send(PeerStep::Open(11))?;
            }
            _ => steps.send(PeerStep::Close)?,
        }
        steps.send(PeerStep::ExpectOpenFailure(9, 2))?;
        match kind {
            0 => steps.send(PeerStep::ExpectPong(b"p".to_vec()))?,
            1 => steps.send(PeerStep::ExpectGlobalFailure)?,
            2 => steps.send(PeerStep::ExpectRequestFailure(7))?,
            3 => {
                steps.send(PeerStep::ExpectOpenFailure(10, 1))?;
                steps.send(PeerStep::ExpectOpenFailure(11, 1))?;
                steps.send(PeerStep::Open(9))?;
                steps.send(PeerStep::ExpectOpenFailure(9, 1))?;
            }
            _ => steps.send(PeerStep::ExpectClose(7))?,
        }
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        assert!(
            matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9)
        );
        assert!(matches!(
            driver.open_rejection_read_id(9),
            Err(OwnedChannelError::Busy)
        ));
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_open_rejection(9, 2), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(write.load(Ordering::SeqCst), 0);
        assert!(matches!(
            driver.open_rejection_read_id(10),
            Err(OwnedChannelError::Busy)
        ));
        let read_id = driver.open_rejection_read_id(9)?;
        assert!(
            matches!(driver.read_while_open_rejection(&read_id)?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc")
        );
        assert!(matches!(
            driver.read_while_open_rejection(&read_id)?,
            OwnedChannelInbound::Event(ChannelEvent::WindowAdjusted {
                channel: 0,
                available: 18
            })
        ));
        let event = driver.read_while_open_rejection(&read_id)?;
        match kind {
            0 => assert!(matches!(event, OwnedChannelInbound::PongDeferred)),
            1 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                    want_reply: true,
                    ..
                })
            )),
            2 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Request {
                    channel: 0,
                    want_reply: true,
                    ..
                })
            )),
            3 => assert!(
                matches!(event, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 10)
            ),
            _ => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
            )),
        }
        assert!(matches!(
            driver.read_while_open_rejection(&read_id),
            Err(OwnedChannelError::Busy)
        ));
        assert_eq!(driver.pending_open_count(), if kind == 3 { 2 } else { 1 });
        assert_eq!(driver.outbound_sequence(), sequence);
        driver = driver
            .try_into_connection()
            .expect_err("partial rejection released");
        write.store(usize::MAX, Ordering::SeqCst);
        driver.drive_open_rejection(9, 2)?;
        assert_eq!(driver.pending_open_count(), usize::from(kind == 3));
        assert_eq!(driver.outbound_sequence(), sequence + 1);
        assert!(matches!(
            driver.read_while_open_rejection(&read_id),
            Err(OwnedChannelError::Busy)
        ));
        match kind {
            0 => driver.drive_deferred_pong()?,
            1 => driver.drive_global_failure()?,
            2 => driver.drive_channel_failure(0)?,
            3 => driver.drive_open_rejection(10, 1)?,
            _ => driver.drive_close_reply(0)?,
        }
        assert_eq!(driver.outbound_sequence(), sequence + 2);
        if kind == 3 {
            assert!(
                matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 11)
            );
            driver.drive_open_rejection(11, 1)?;
            assert_eq!(driver.outbound_sequence(), sequence + 3);
            assert!(
                matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9)
            );
            write.store(1, Ordering::SeqCst);
            assert!(
                matches!(driver.drive_open_rejection(9, 1), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
            );
            let next_id = driver.open_rejection_read_id(9)?;
            assert!(matches!(
                driver.read_while_open_rejection(&read_id),
                Err(OwnedChannelError::Busy)
            ));
            write.store(usize::MAX, Ordering::SeqCst);
            driver.drive_open_rejection(9, 1)?;
            assert!(matches!(
                driver.read_while_open_rejection(&next_id),
                Err(OwnedChannelError::Busy)
            ));
            assert_eq!(driver.outbound_sequence(), sequence + 4);
        }
        drop(
            driver
                .try_into_connection()
                .map_err(|_| "release refused")?,
        );
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn foreign_open_rejection_id_does_not_consume_input() -> Result<(), Box<dyn std::error::Error>> {
    let (mut first, write1, _read1, _seq1, steps1, peer1) = setup()?;
    let (mut second, write2, _read2, _seq2, steps2, peer2) = setup()?;
    for steps in [&steps1, &steps2] {
        steps.send(PeerStep::Open(9))?;
        steps.send(PeerStep::Data(b"abc".to_vec()))?;
        steps.send(PeerStep::ExpectOpenFailure(9, 1))?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
    }
    for (driver, write) in [(&mut first, &write1), (&mut second, &write2)] {
        assert!(
            matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9)
        );
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_open_rejection(9, 1), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
    }
    let first_id = first.open_rejection_read_id(9)?;
    let foreign = second.open_rejection_read_id(9)?;
    assert!(matches!(
        first.read_while_open_rejection(&foreign),
        Err(OwnedChannelError::Busy)
    ));
    assert!(
        matches!(first.read_while_open_rejection(&first_id)?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc")
    );
    assert!(matches!(
        second.read_while_open_rejection(&first_id),
        Err(OwnedChannelError::Busy)
    ));
    assert!(
        matches!(second.read_while_open_rejection(&foreign)?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc")
    );
    for (driver, write) in [(&mut first, &write1), (&mut second, &write2)] {
        write.store(usize::MAX, Ordering::SeqCst);
        driver.drive_open_rejection(9, 1)?;
    }
    drop(
        first
            .try_into_connection()
            .map_err(|_| "first release refused")?,
    );
    drop(
        second
            .try_into_connection()
            .map_err(|_| "second release refused")?,
    );
    peer1.join().map_err(|_| "peer panic")??;
    peer2.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn partial_open_rejection_with_queued_request_fatal_or_cancel()
-> Result<(), Box<dyn std::error::Error>> {
    for fatal in [false, true] {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::Open(9))?;
        steps.send(PeerStep::GlobalRequest { want_reply: true })?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        assert!(
            matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9)
        );
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_open_rejection(9, 1), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
        let read_id = driver.open_rejection_read_id(9)?;
        assert!(matches!(
            driver.read_while_open_rejection(&read_id)?,
            OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                want_reply: true,
                ..
            })
        ));
        assert!(matches!(
            driver.read_while_open_rejection(&read_id),
            Err(OwnedChannelError::Busy)
        ));
        if fatal {
            write.store(usize::MAX - 1, Ordering::SeqCst);
            assert!(
                matches!(driver.drive_open_rejection(9, 1), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::BrokenPipe)
            );
            assert!(matches!(
                driver.read_while_open_rejection(&read_id),
                Err(OwnedChannelError::Failed)
            ));
        }
        assert_eq!(driver.pending_open_count(), 1);
        assert_eq!(driver.outbound_sequence(), sequence);
        let driver = driver
            .try_into_connection()
            .expect_err("partial rejection released");
        drop(driver);
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn rekey_during_open_rejection_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Open(9))?;
    steps.send(PeerStep::Raw(vec![20]))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    assert!(
        matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9)
    );
    write.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.drive_open_rejection(9, 1), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let id = driver.open_rejection_read_id(9)?;
    assert!(matches!(
        driver.read_while_open_rejection(&id),
        Err(OwnedChannelError::Transport(
            TransportError::UnexpectedMessage
        ))
    ));
    assert!(matches!(
        driver.drive_open_rejection(9, 1),
        Err(OwnedChannelError::Failed)
    ));
    assert_eq!(driver.outbound_sequence(), sequence);
    assert_eq!(driver.pending_open_count(), 1);
    let driver = driver
        .try_into_connection()
        .expect_err("failed driver released");
    drop(driver);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn partial_inbound_during_open_rejection_resumes_after_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, read, sequence, steps, peer) = setup()?;
    steps.send(PeerStep::Open(9))?;
    steps.send(PeerStep::Data(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectOpenFailure(9, 1))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(
        matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9)
    );
    write.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.drive_open_rejection(9, 1), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let id = driver.open_rejection_read_id(9)?;
    read.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.read_while_open_rejection(&id), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive_open_rejection(9, 1)?;
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    driver = driver
        .try_into_connection()
        .expect_err("partial inbound released");
    read.store(usize::MAX, Ordering::SeqCst);
    assert!(
        matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc")
    );
    assert!(matches!(
        driver.read_while_open_rejection(&id),
        Err(OwnedChannelError::Busy)
    ));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)] // One protected transcript checks all next obligations.
fn partial_close_reply_retains_one_next_obligation() -> Result<(), Box<dyn std::error::Error>> {
    for kind in 0..5 {
        let (mut driver, write, _read, sequence, steps, peer) = setup_two_channels()?;
        steps.send(PeerStep::Close)?;
        steps.send(PeerStep::DataOn(8, b"abc".to_vec()))?;
        steps.send(PeerStep::WindowOn(8, 1))?;
        match kind {
            0 => steps.send(PeerStep::Ping(b"p".to_vec()))?,
            1 => steps.send(PeerStep::GlobalRequest { want_reply: true })?,
            2 => steps.send(PeerStep::RequestOn(8))?,
            3 => steps.send(PeerStep::Open(9))?,
            _ => steps.send(PeerStep::CloseOn(8))?,
        }
        steps.send(PeerStep::ExpectClose(7))?;
        match kind {
            0 => steps.send(PeerStep::ExpectPong(b"p".to_vec()))?,
            1 => steps.send(PeerStep::ExpectGlobalFailure)?,
            2 => steps.send(PeerStep::ExpectRequestFailure(8))?,
            3 => steps.send(PeerStep::ExpectOpenFailure(9, 1))?,
            _ => steps.send(PeerStep::ExpectClose(8))?,
        }
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        assert!(matches!(
            driver.read_idle()?,
            OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
        ));
        assert!(matches!(
            driver.close_reply_read_id(0),
            Err(OwnedChannelError::Busy)
        ));
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_close_reply(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(write.load(Ordering::SeqCst), 0);
        assert!(matches!(
            driver.close_reply_read_id(1),
            Err(OwnedChannelError::Busy)
        ));
        let id = driver.close_reply_read_id(0)?;
        assert!(
            matches!(driver.read_while_close_reply(&id)?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 1, data }) if data == b"abc")
        );
        assert!(matches!(
            driver.read_while_close_reply(&id)?,
            OwnedChannelInbound::Event(ChannelEvent::WindowAdjusted {
                channel: 1,
                available: 18
            })
        ));
        let event = driver.read_while_close_reply(&id)?;
        match kind {
            0 => assert!(matches!(event, OwnedChannelInbound::PongDeferred)),
            1 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                    want_reply: true,
                    ..
                })
            )),
            2 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Request {
                    channel: 1,
                    want_reply: true,
                    ..
                })
            )),
            3 => assert!(
                matches!(event, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9)
            ),
            _ => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Close { channel: 1 })
            )),
        }
        assert!(matches!(
            driver.read_while_close_reply(&id),
            Err(OwnedChannelError::Busy)
        ));
        let state = driver.channel(0).unwrap();
        assert!(state.remote_close_received() && !state.local_close_sent());
        assert!(!driver.is_retired_channel(0));
        assert_eq!(driver.outbound_sequence(), sequence);
        driver = driver
            .try_into_connection()
            .expect_err("partial close released");
        write.store(usize::MAX, Ordering::SeqCst);
        driver.drive_close_reply(0)?;
        assert!(driver.channel(0).is_none());
        assert!(driver.is_retired_channel(0));
        assert_eq!(driver.outbound_sequence(), sequence + 1);
        assert!(matches!(
            driver.read_while_close_reply(&id),
            Err(OwnedChannelError::Busy)
        ));
        match kind {
            0 => driver.drive_deferred_pong()?,
            1 => driver.drive_global_failure()?,
            2 => driver.drive_channel_failure(1)?,
            3 => driver.drive_open_rejection(9, 1)?,
            _ => {
                assert!(!driver.is_retired_channel(1));
                driver.drive_close_reply(1)?;
                assert!(driver.is_retired_channel(1));
            }
        }
        assert_eq!(driver.outbound_sequence(), sequence + 2);
        drop(
            driver
                .try_into_connection()
                .map_err(|_| "release refused")?,
        );
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn same_channel_traffic_after_close_fails_terminally_during_reply()
-> Result<(), Box<dyn std::error::Error>> {
    for payload in [
        vec![97, 0, 0, 0, 0],
        vec![96, 0, 0, 0, 0],
        vec![94, 0, 0, 0, 0, 0, 0, 0, 1, b'x'],
        vec![93, 0, 0, 0, 0, 0, 0, 0, 1],
    ] {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        let (release, wait) = mpsc::channel();
        steps.send(PeerStep::Close)?;
        steps.send(PeerStep::Raw(payload))?;
        steps.send(PeerStep::Wait(wait))?;
        steps.send(PeerStep::Finish)?;
        assert!(matches!(
            driver.read_idle()?,
            OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
        ));
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_close_reply(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
        let id = driver.close_reply_read_id(0)?;
        assert!(matches!(
            driver.read_while_close_reply(&id),
            Err(OwnedChannelError::Channel(_))
        ));
        assert!(matches!(
            driver.drive_close_reply(0),
            Err(OwnedChannelError::Failed)
        ));
        assert!(!driver.is_retired_channel(0));
        assert!(!driver.channel(0).unwrap().local_close_sent());
        assert_eq!(driver.outbound_sequence(), sequence);
        let driver = driver
            .try_into_connection()
            .expect_err("failed close released");
        drop(driver);
        release.send(())?;
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn partial_close_with_queued_request_fatal_or_cancel() -> Result<(), Box<dyn std::error::Error>> {
    for fatal in [false, true] {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::Close)?;
        steps.send(PeerStep::GlobalRequest { want_reply: true })?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        assert!(matches!(
            driver.read_idle()?,
            OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
        ));
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_close_reply(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
        let id = driver.close_reply_read_id(0)?;
        assert!(matches!(
            driver.read_while_close_reply(&id)?,
            OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                want_reply: true,
                ..
            })
        ));
        assert!(matches!(
            driver.read_while_close_reply(&id),
            Err(OwnedChannelError::Busy)
        ));
        if fatal {
            write.store(usize::MAX - 1, Ordering::SeqCst);
            assert!(
                matches!(driver.drive_close_reply(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::BrokenPipe)
            );
            assert!(matches!(
                driver.read_while_close_reply(&id),
                Err(OwnedChannelError::Failed)
            ));
        }
        assert!(!driver.is_retired_channel(0));
        assert!(!driver.channel(0).unwrap().local_close_sent());
        assert_eq!(driver.outbound_sequence(), sequence);
        let driver = driver
            .try_into_connection()
            .expect_err("partial close released");
        drop(driver);
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn rekey_during_close_reply_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Close)?;
    steps.send(PeerStep::Raw(vec![20]))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
    ));
    write.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.drive_close_reply(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let id = driver.close_reply_read_id(0)?;
    assert!(matches!(
        driver.read_while_close_reply(&id),
        Err(OwnedChannelError::Transport(
            TransportError::UnexpectedMessage
        ))
    ));
    assert!(matches!(
        driver.drive_close_reply(0),
        Err(OwnedChannelError::Failed)
    ));
    assert!(!driver.is_retired_channel(0));
    assert_eq!(driver.outbound_sequence(), sequence);
    let driver = driver
        .try_into_connection()
        .expect_err("failed driver released");
    drop(driver);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn partial_inbound_during_close_reply_resumes_after_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, read, sequence, steps, peer) = setup_two_channels()?;
    steps.send(PeerStep::Close)?;
    steps.send(PeerStep::DataOn(8, b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectClose(7))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
    ));
    write.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.drive_close_reply(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let id = driver.close_reply_read_id(0)?;
    read.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.read_while_close_reply(&id), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive_close_reply(0)?;
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    driver = driver
        .try_into_connection()
        .expect_err("partial inbound released");
    read.store(usize::MAX, Ordering::SeqCst);
    assert!(
        matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 1, data }) if data == b"abc")
    );
    assert!(matches!(
        driver.read_while_close_reply(&id),
        Err(OwnedChannelError::Busy)
    ));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn other_channel_eof_is_delivered_while_close_reply_is_partial()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup_two_channels()?;
    steps.send(PeerStep::Close)?;
    steps.send(PeerStep::EofOn(8))?;
    steps.send(PeerStep::ExpectClose(7))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
    ));
    write.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.drive_close_reply(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let id = driver.close_reply_read_id(0)?;
    assert!(matches!(
        driver.read_while_close_reply(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Eof { channel: 1 })
    ));
    assert!(driver.channel(1).unwrap().remote_eof_received());
    assert!(!driver.is_retired_channel(0));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive_close_reply(0)?;
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    assert!(driver.is_retired_channel(0));
    assert!(driver.channel(1).unwrap().remote_eof_received());
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn stale_close_id_cannot_read_after_local_channel_id_reuse()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    steps.send(PeerStep::Close)?;
    steps.send(PeerStep::ExpectClose(7))?;
    let cycles = u32::try_from(neotales_ssh::channel::MAX_REMEMBERED_CLOSED_CHANNELS)?;
    steps.send(PeerStep::CycleCloses(cycles))?;
    steps.send(PeerStep::AcceptSecond)?;
    steps.send(PeerStep::CloseOn(8))?;
    steps.send(PeerStep::GlobalRequest { want_reply: true })?;
    steps.send(PeerStep::ExpectClose(8))?;
    steps.send(PeerStep::ExpectGlobalFailure)?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
    ));
    write.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.drive_close_reply(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let stale = driver.close_reply_read_id(0)?;
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive_close_reply(0)?;
    assert!(driver.is_retired_channel(0));
    let mut connection = driver
        .try_into_connection()
        .map_err(|_| "release refused")?;
    assert!(matches!(
        connection.open_channel(0, b"session", &[]),
        Err(ChannelError::ClosedChannel(0))
    ));
    for channel in 1..=cycles {
        connection.open_channel(channel, b"session", &[])?;
        assert!(
            matches!(connection.dispatch_one()?, ChannelEvent::Opened(opened) if opened == channel)
        );
        connection.send_close(channel)?;
        assert!(
            matches!(connection.dispatch_one()?, ChannelEvent::Close { channel: closed } if closed == channel)
        );
    }
    assert!(
        !connection.is_retired_channel(0),
        "oldest tombstone should be evicted"
    );
    assert_eq!(connection.allocate_channel_id()?, 0);
    connection.open_channel(0, b"session", &[])?;
    assert!(matches!(
        connection.dispatch_one()?,
        ChannelEvent::Opened(0)
    ));
    assert!(!connection.is_retired_channel(0));
    let mut driver = OwnedChannelDriver::try_new(connection).map_err(|_| "driver refused")?;
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
    ));
    write.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.drive_close_reply(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let current = driver.close_reply_read_id(0)?;
    assert!(matches!(
        driver.read_while_close_reply(&stale),
        Err(OwnedChannelError::Busy)
    ));
    assert!(matches!(
        driver.read_while_close_reply(&current)?,
        OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
            want_reply: true,
            ..
        })
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive_close_reply(0)?;
    driver.drive_global_failure()?;
    assert!(driver.is_retired_channel(0));
    assert_eq!(driver.outbound_sequence(), sequence + 4 + 2 * cycles);
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn foreign_close_read_id_does_not_consume_input() -> Result<(), Box<dyn std::error::Error>> {
    let (mut first, write1, _read1, _seq1, steps1, peer1) = setup_two_channels()?;
    let (mut second, write2, _read2, _seq2, steps2, peer2) = setup_two_channels()?;
    for steps in [&steps1, &steps2] {
        steps.send(PeerStep::Close)?;
        steps.send(PeerStep::DataOn(8, b"abc".to_vec()))?;
        steps.send(PeerStep::ExpectClose(7))?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
    }
    for (driver, write) in [(&mut first, &write1), (&mut second, &write2)] {
        assert!(matches!(
            driver.read_idle()?,
            OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
        ));
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_close_reply(0), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
    }
    let first_id = first.close_reply_read_id(0)?;
    let foreign = second.close_reply_read_id(0)?;
    assert!(matches!(
        first.read_while_close_reply(&foreign),
        Err(OwnedChannelError::Busy)
    ));
    assert!(
        matches!(first.read_while_close_reply(&first_id)?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 1, data }) if data == b"abc")
    );
    assert!(matches!(
        second.read_while_close_reply(&first_id),
        Err(OwnedChannelError::Busy)
    ));
    assert!(
        matches!(second.read_while_close_reply(&foreign)?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 1, data }) if data == b"abc")
    );
    for (driver, write) in [(&mut first, &write1), (&mut second, &write2)] {
        write.store(usize::MAX, Ordering::SeqCst);
        driver.drive_close_reply(0)?;
    }
    drop(
        first
            .try_into_connection()
            .map_err(|_| "first release refused")?,
    );
    drop(
        second
            .try_into_connection()
            .map_err(|_| "second release refused")?,
    );
    peer1.join().map_err(|_| "peer panic")??;
    peer2.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)] // One protected transcript checks each next-obligation kind.
fn partial_pong_retains_one_next_obligation() -> Result<(), Box<dyn std::error::Error>> {
    for kind in 0..5 {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::Ping(b"first".to_vec()))?;
        steps.send(PeerStep::Data(b"abc".to_vec()))?;
        steps.send(PeerStep::Window(1))?;
        match kind {
            0 => {
                steps.send(PeerStep::Ping(b"second".to_vec()))?;
                steps.send(PeerStep::Ping(b"third".to_vec()))?;
            }
            1 => steps.send(PeerStep::GlobalRequest { want_reply: true })?,
            2 => steps.send(PeerStep::Request {
                request_type: b"exec".to_vec(),
                want_reply: true,
            })?,
            3 => steps.send(PeerStep::Open(9))?,
            _ => steps.send(PeerStep::Close)?,
        }
        steps.send(PeerStep::ExpectPong(b"first".to_vec()))?;
        match kind {
            0 => {
                steps.send(PeerStep::ExpectPong(b"second".to_vec()))?;
                steps.send(PeerStep::ExpectPong(b"third".to_vec()))?;
            }
            1 => steps.send(PeerStep::ExpectGlobalFailure)?,
            2 => steps.send(PeerStep::ExpectRequestFailure(7))?,
            3 => steps.send(PeerStep::ExpectOpenFailure(9, 1))?,
            _ => steps.send(PeerStep::ExpectClose(7))?,
        }
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        assert!(matches!(
            driver.read_idle()?,
            OwnedChannelInbound::PongDeferred
        ));
        assert!(matches!(
            driver.pong_read_id(),
            Err(OwnedChannelError::Busy)
        ));
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_deferred_pong(), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(write.load(Ordering::SeqCst), 0);
        let id = driver.pong_read_id()?;
        assert!(
            matches!(driver.read_while_pong(&id)?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc")
        );
        assert!(matches!(
            driver.read_while_pong(&id)?,
            OwnedChannelInbound::Event(ChannelEvent::WindowAdjusted {
                channel: 0,
                available: 18
            })
        ));
        let event = driver.read_while_pong(&id)?;
        match kind {
            0 => assert!(matches!(event, OwnedChannelInbound::PongDeferred)),
            1 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                    want_reply: true,
                    ..
                })
            )),
            2 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Request {
                    channel: 0,
                    want_reply: true,
                    ..
                })
            )),
            3 => assert!(
                matches!(event, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9)
            ),
            _ => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
            )),
        }
        assert!(matches!(
            driver.read_while_pong(&id),
            Err(OwnedChannelError::Busy)
        ));
        for _ in 0..32 {
            assert!(matches!(
                driver.read_while_pong(&id),
                Err(OwnedChannelError::Busy)
            ));
        }
        assert_eq!(driver.outbound_sequence(), sequence);
        driver = driver
            .try_into_connection()
            .expect_err("partial PONG released");
        write.store(usize::MAX, Ordering::SeqCst);
        driver.drive_deferred_pong()?;
        assert_eq!(driver.outbound_sequence(), sequence + 1);
        assert!(matches!(
            driver.read_while_pong(&id),
            Err(OwnedChannelError::Busy)
        ));
        match kind {
            0 => {
                write.store(1, Ordering::SeqCst);
                assert!(
                    matches!(driver.drive_deferred_pong(), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
                );
                let next_id = driver.pong_read_id()?;
                assert!(matches!(
                    driver.read_while_pong(&id),
                    Err(OwnedChannelError::Busy)
                ));
                assert!(matches!(
                    driver.read_while_pong(&next_id)?,
                    OwnedChannelInbound::PongDeferred
                ));
                assert!(matches!(
                    driver.read_while_pong(&next_id),
                    Err(OwnedChannelError::Busy)
                ));
                write.store(usize::MAX, Ordering::SeqCst);
                driver.drive_deferred_pong()?;
                driver.drive_deferred_pong()?;
            }
            1 => driver.drive_global_failure()?,
            2 => driver.drive_channel_failure(0)?,
            3 => driver.drive_open_rejection(9, 1)?,
            _ => driver.drive_close_reply(0)?,
        }
        assert_eq!(
            driver.outbound_sequence(),
            sequence + if kind == 0 { 3 } else { 2 }
        );
        drop(
            driver
                .try_into_connection()
                .map_err(|_| "release refused")?,
        );
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn foreign_pong_read_id_does_not_consume_input() -> Result<(), Box<dyn std::error::Error>> {
    let (mut first, write1, _read1, _seq1, steps1, peer1) = setup()?;
    let (mut second, write2, _read2, _seq2, steps2, peer2) = setup()?;
    for steps in [&steps1, &steps2] {
        steps.send(PeerStep::Ping(b"p".to_vec()))?;
        steps.send(PeerStep::Data(b"abc".to_vec()))?;
        steps.send(PeerStep::ExpectPong(b"p".to_vec()))?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
    }
    for (driver, write) in [(&mut first, &write1), (&mut second, &write2)] {
        assert!(matches!(
            driver.read_idle()?,
            OwnedChannelInbound::PongDeferred
        ));
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_deferred_pong(), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
    }
    let first_id = first.pong_read_id()?;
    let foreign = second.pong_read_id()?;
    assert!(matches!(
        first.read_while_pong(&foreign),
        Err(OwnedChannelError::Busy)
    ));
    assert!(
        matches!(first.read_while_pong(&first_id)?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc")
    );
    assert!(matches!(
        second.read_while_pong(&first_id),
        Err(OwnedChannelError::Busy)
    ));
    assert!(
        matches!(second.read_while_pong(&foreign)?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc")
    );
    for (driver, write) in [(&mut first, &write1), (&mut second, &write2)] {
        write.store(usize::MAX, Ordering::SeqCst);
        driver.drive_deferred_pong()?;
    }
    drop(
        first
            .try_into_connection()
            .map_err(|_| "first release refused")?,
    );
    drop(
        second
            .try_into_connection()
            .map_err(|_| "second release refused")?,
    );
    peer1.join().map_err(|_| "peer panic")??;
    peer2.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn partial_pong_with_next_ping_fatal_or_cancel() -> Result<(), Box<dyn std::error::Error>> {
    for fatal in [false, true] {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::Ping(b"first".to_vec()))?;
        steps.send(PeerStep::Ping(b"second".to_vec()))?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        assert!(matches!(
            driver.read_idle()?,
            OwnedChannelInbound::PongDeferred
        ));
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_deferred_pong(), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
        let id = driver.pong_read_id()?;
        assert!(matches!(
            driver.read_while_pong(&id)?,
            OwnedChannelInbound::PongDeferred
        ));
        assert!(matches!(
            driver.read_while_pong(&id),
            Err(OwnedChannelError::Busy)
        ));
        if fatal {
            write.store(usize::MAX - 1, Ordering::SeqCst);
            assert!(
                matches!(driver.drive_deferred_pong(), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::BrokenPipe)
            );
            assert!(matches!(
                driver.read_while_pong(&id),
                Err(OwnedChannelError::Failed)
            ));
        }
        assert_eq!(driver.outbound_sequence(), sequence);
        let driver = driver
            .try_into_connection()
            .expect_err("partial PONG released");
        drop(driver);
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn rekey_during_partial_pong_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Ping(b"p".to_vec()))?;
    steps.send(PeerStep::Raw(vec![20]))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::PongDeferred
    ));
    write.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.drive_deferred_pong(), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let id = driver.pong_read_id()?;
    assert!(matches!(
        driver.read_while_pong(&id),
        Err(OwnedChannelError::Transport(
            TransportError::UnexpectedMessage
        ))
    ));
    assert!(matches!(
        driver.drive_deferred_pong(),
        Err(OwnedChannelError::Failed)
    ));
    assert_eq!(driver.outbound_sequence(), sequence);
    let driver = driver
        .try_into_connection()
        .expect_err("failed driver released");
    drop(driver);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn oversized_nested_ping_length_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Ping(b"p".to_vec()))?;
    steps.send(PeerStep::Raw(vec![192, 255, 255, 255, 255]))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::PongDeferred
    ));
    write.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.drive_deferred_pong(), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let id = driver.pong_read_id()?;
    assert!(matches!(
        driver.read_while_pong(&id),
        Err(OwnedChannelError::Transport(TransportError::InvalidMessage))
    ));
    assert!(matches!(
        driver.drive_deferred_pong(),
        Err(OwnedChannelError::Failed)
    ));
    assert_eq!(driver.outbound_sequence(), sequence);
    let driver = driver
        .try_into_connection()
        .expect_err("failed driver released");
    drop(driver);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn partial_inbound_during_pong_resumes_after_completion() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut driver, write, read, sequence, steps, peer) = setup()?;
    steps.send(PeerStep::Ping(b"p".to_vec()))?;
    steps.send(PeerStep::Data(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectPong(b"p".to_vec()))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::PongDeferred
    ));
    write.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.drive_deferred_pong(), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let id = driver.pong_read_id()?;
    read.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.read_while_pong(&id), Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
    );
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive_deferred_pong()?;
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    driver = driver
        .try_into_connection()
        .expect_err("partial inbound released");
    read.store(usize::MAX, Ordering::SeqCst);
    assert!(
        matches!(driver.read_idle()?, OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc")
    );
    assert!(matches!(
        driver.read_while_pong(&id),
        Err(OwnedChannelError::Busy)
    ));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn foreign_window_id_cannot_advance_packet() -> Result<(), Box<dyn std::error::Error>> {
    let (mut first, first_write, _read, sequence, steps, peer) = setup()?;
    let (mut second, _write2, _read2, _sequence2, steps2, peer2) = setup()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::ExpectWindow(65_537))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    steps2.send(PeerStep::Wait(wait))?;
    steps2.send(PeerStep::Finish)?;
    let id = first.admit_window_adjustment(0, 1)?;
    let foreign = second.admit_window_adjustment(0, 1)?;
    first_write.store(usize::MAX, Ordering::SeqCst);
    assert!(matches!(
        first.read_while_window_adjustment(&foreign),
        Err(OwnedChannelError::Busy)
    ));
    assert!(matches!(
        first.drive_window_adjustment(&foreign),
        Err(OwnedChannelError::Busy)
    ));
    assert_eq!(first.channel(0).unwrap().local_window(), 65_536);
    assert_eq!(first.outbound_sequence(), sequence);
    assert_eq!(first.drive_window_adjustment(&id)?, 65_537);
    assert!(matches!(
        first.read_while_window_adjustment(&id),
        Err(OwnedChannelError::Busy)
    ));
    drop(first.try_into_connection().map_err(|_| "release refused")?);
    drop(second);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    peer2.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn rekey_during_partial_window_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Raw(vec![20]))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    let id = driver.admit_window_adjustment(0, 1)?;
    write.store(1, Ordering::SeqCst);
    assert!(matches!(driver.drive_window_adjustment(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
    assert!(matches!(
        driver.read_while_window_adjustment(&id),
        Err(OwnedChannelError::Transport(
            TransportError::UnexpectedMessage
        ))
    ));
    assert!(matches!(
        driver.drive_window_adjustment(&id),
        Err(OwnedChannelError::Failed)
    ));
    assert_eq!(driver.outbound_sequence(), sequence);
    assert_eq!(driver.channel(0).unwrap().local_window(), 65_536);
    let driver = driver
        .try_into_connection()
        .expect_err("failed driver released");
    drop(driver);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn fatal_window_write_with_queued_request_cannot_release() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    steps.send(PeerStep::GlobalRequest { want_reply: true })?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    let id = driver.admit_window_adjustment(0, 1)?;
    write.store(1, Ordering::SeqCst);
    assert!(matches!(driver.drive_window_adjustment(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
    assert!(matches!(
        driver.read_while_window_adjustment(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
            want_reply: true,
            ..
        })
    ));
    assert!(matches!(
        driver.drive_global_failure(),
        Err(OwnedChannelError::Busy)
    ));
    write.store(usize::MAX - 1, Ordering::SeqCst);
    assert!(matches!(driver.drive_window_adjustment(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::BrokenPipe));
    assert!(matches!(
        driver.drive_global_failure(),
        Err(OwnedChannelError::Failed)
    ));
    assert_eq!(driver.outbound_sequence(), sequence);
    assert_eq!(driver.channel(0).unwrap().local_window(), 65_536);
    let driver = driver
        .try_into_connection()
        .expect_err("failed driver released");
    drop(driver);
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn partial_inbound_during_window_can_resume_after_window_finishes()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, read, sequence, steps, peer) = setup()?;
    steps.send(PeerStep::Data(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectWindow(65_538))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    let id = driver.admit_window_adjustment(0, 5)?;
    write.store(1, Ordering::SeqCst);
    assert!(matches!(driver.drive_window_adjustment(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
    read.store(1, Ordering::SeqCst);
    assert!(matches!(driver.read_while_window_adjustment(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
    write.store(usize::MAX, Ordering::SeqCst);
    assert_eq!(driver.drive_window_adjustment(&id)?, 65_541);
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    driver = driver
        .try_into_connection()
        .expect_err("partial inbound released");
    read.store(usize::MAX, Ordering::SeqCst);
    assert!(matches!(driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"abc"));
    assert_eq!(driver.channel(0).unwrap().local_window(), 65_538);
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn partial_window_adjustment_fatal_and_cancel_leave_credit_uncommitted()
-> Result<(), Box<dyn std::error::Error>> {
    for fatal in [false, true] {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        let id = driver.admit_window_adjustment(0, 1)?;
        write.store(1, Ordering::SeqCst);
        assert!(matches!(driver.drive_window_adjustment(&id),
            Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
        if fatal {
            write.store(usize::MAX - 1, Ordering::SeqCst);
            assert!(matches!(driver.drive_window_adjustment(&id),
                Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::BrokenPipe));
            assert!(matches!(
                driver.drive_window_adjustment(&id),
                Err(OwnedChannelError::Failed)
            ));
        }
        assert_eq!(driver.channel(0).unwrap().local_window(), 65_536);
        assert_eq!(driver.outbound_sequence(), sequence);
        let driver = driver
            .try_into_connection()
            .expect_err("partial adjustment released");
        drop(driver);
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn window_adjustment_accepts_maximum_and_rejects_overflow() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    steps.send(PeerStep::ExpectWindow(u32::MAX))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    let id = driver.admit_window_adjustment(0, u32::MAX - 65_536)?;
    write.store(usize::MAX, Ordering::SeqCst);
    assert_eq!(driver.drive_window_adjustment(&id)?, u32::MAX);
    assert!(matches!(
        driver.admit_window_adjustment(0, 1),
        Err(OwnedChannelError::Channel(ChannelError::Window(_)))
    ));
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn window_adjustment_rejects_locally_closed_channel() -> Result<(), Box<dyn std::error::Error>> {
    let Harness {
        mut connection,
        write_allowance: _write,
        read_allowance: _read,
        sequence: _,
        steps,
        peer,
    } = setup_connection()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::ExpectClose(7))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    connection.send_close(0)?;
    let mut driver = OwnedChannelDriver::try_new(connection).map_err(|_| "driver refused")?;
    assert!(matches!(
        driver.admit_window_adjustment(0, 1),
        Err(OwnedChannelError::Channel(ChannelError::InvalidMessage))
    ));
    assert!(matches!(
        driver.admit_eof(0),
        Err(OwnedChannelError::Channel(ChannelError::InvalidMessage))
    ));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn idle_window_adjustment_unblocks_exhausted_remote_window()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let data = b"abcdefghijklmnopq";
    steps.send(PeerStep::ExpectData(data.to_vec()))?;
    steps.send(PeerStep::Window(3))?;
    steps.send(PeerStep::ExpectData(b"xyz".to_vec()))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    let id = driver.admit_data(0, data)?;
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    assert_eq!(driver.channel(0).unwrap().remote_window(), 0);
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Busy)
    ));
    assert!(matches!(
        driver.read_idle()?,
        OwnedChannelInbound::Event(ChannelEvent::WindowAdjusted {
            channel: 0,
            available: 3
        })
    ));
    let next = driver.admit_data(0, b"xyz")?;
    driver.drive(&next)?;
    assert_eq!(driver.outbound_sequence(), sequence + 2);
    assert_eq!(driver.channel(0).unwrap().remote_window(), 0);
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn idle_obligations_are_delivered_once_and_completed() -> Result<(), Box<dyn std::error::Error>> {
    for kind in 0..5 {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        match kind {
            0 => {
                steps.send(PeerStep::Ping(b"p".to_vec()))?;
                steps.send(PeerStep::ExpectPong(b"p".to_vec()))?;
            }
            1 => {
                steps.send(PeerStep::GlobalRequest { want_reply: true })?;
                steps.send(PeerStep::ExpectGlobalFailure)?;
            }
            2 => {
                steps.send(PeerStep::Request {
                    request_type: b"exec".to_vec(),
                    want_reply: true,
                })?;
                steps.send(PeerStep::ExpectRequestFailure(7))?;
            }
            3 => {
                steps.send(PeerStep::Open(9))?;
                steps.send(PeerStep::ExpectOpenFailure(9, 1))?;
            }
            _ => {
                steps.send(PeerStep::Close)?;
                steps.send(PeerStep::ExpectClose(7))?;
            }
        }
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        let event = driver.read_idle()?;
        match kind {
            0 => assert!(matches!(event, OwnedChannelInbound::PongDeferred)),
            1 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
                    want_reply: true,
                    ..
                })
            )),
            2 => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Request {
                    channel: 0,
                    want_reply: true,
                    ..
                })
            )),
            3 => assert!(
                matches!(event, OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9)
            ),
            _ => assert!(matches!(
                event,
                OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
            )),
        }
        assert!(matches!(driver.read_idle(), Err(OwnedChannelError::Busy)));
        assert!(matches!(
            driver.admit_data(0, b"x"),
            Err(OwnedChannelError::Busy)
        ));
        driver = driver
            .try_into_connection()
            .expect_err("obligation released");
        write.store(1, Ordering::SeqCst);
        let result = match kind {
            0 => driver.drive_deferred_pong(),
            1 => driver.drive_global_failure(),
            2 => driver.drive_channel_failure(0),
            3 => driver.drive_open_rejection(9, 1),
            _ => driver.drive_close_reply(0),
        };
        assert!(
            matches!(result, Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(driver.outbound_sequence(), sequence);
        assert!(matches!(driver.read_idle(), Err(OwnedChannelError::Busy)));
        write.store(usize::MAX, Ordering::SeqCst);
        match kind {
            0 => driver.drive_deferred_pong()?,
            1 => driver.drive_global_failure()?,
            2 => driver.drive_channel_failure(0)?,
            3 => driver.drive_open_rejection(9, 1)?,
            _ => driver.drive_close_reply(0)?,
        }
        assert_eq!(driver.outbound_sequence(), sequence + 1);
        drop(
            driver
                .try_into_connection()
                .map_err(|_| "release refused")?,
        );
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn idle_partial_read_survives_admission_and_cannot_be_released()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, read, _sequence, steps, peer) = setup()?;
    steps.send(PeerStep::Data(b"prefix".to_vec()))?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    read.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.read_idle(), Err(OwnedChannelError::Transport(TransportError::Io(error)))
        if error.kind() == io::ErrorKind::WouldBlock)
    );
    driver = driver
        .try_into_connection()
        .expect_err("partial input released");
    let id = driver.admit_data(0, b"abc")?;
    assert!(matches!(driver.read_idle(), Err(OwnedChannelError::Busy)));
    read.store(usize::MAX, Ordering::SeqCst);
    assert!(matches!(driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data }) if data == b"prefix"));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Busy)
    ));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn idle_peer_rekey_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, _write, _read, _sequence, steps, peer) = setup()?;
    steps.send(PeerStep::Raw(vec![20]))?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_idle(),
        Err(OwnedChannelError::Transport(
            TransportError::UnexpectedMessage
        ))
    ));
    assert!(matches!(driver.read_idle(), Err(OwnedChannelError::Failed)));
    let driver = driver
        .try_into_connection()
        .expect_err("terminal driver released");
    drop(driver);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn idle_would_block_without_bytes_can_release_but_partial_cancellation_cannot()
-> Result<(), Box<dyn std::error::Error>> {
    for partial in [false, true] {
        let (mut driver, _write, read, _sequence, steps, peer) = setup()?;
        if partial {
            steps.send(PeerStep::Data(b"prefix".to_vec()))?;
        }
        let (release, wait) = mpsc::channel();
        steps.send(PeerStep::Wait(wait))?;
        steps.send(PeerStep::Finish)?;
        read.store(usize::from(partial), Ordering::SeqCst);
        assert!(
            matches!(driver.read_idle(), Err(OwnedChannelError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock)
        );
        if partial {
            let driver = driver
                .try_into_connection()
                .expect_err("partial read released");
            drop(driver);
        } else {
            drop(
                driver
                    .try_into_connection()
                    .map_err(|_| "empty read blocked release")?,
            );
        }
        release.send(())?;
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn close_is_surfaced_but_blocks_further_reads_and_release() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut driver, write, _read, _sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Close)?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;

    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
    ));
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Busy)
    ));
    let Err(driver) = driver.try_into_connection() else {
        panic!("released with a close reply owed")
    };
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    drop(driver);
    Ok(())
}

#[test]
fn peer_close_reply_reaps_only_after_last_byte() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    steps.send(PeerStep::Close)?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectClose(7))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
    ));
    assert!(matches!(
        driver.drive_close_reply(0),
        Err(OwnedChannelError::Busy)
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    assert!(matches!(
        driver.drive_close_reply(7),
        Err(OwnedChannelError::Busy)
    ));
    let mut blocks = 0;
    loop {
        write.store(1, Ordering::SeqCst);
        match driver.drive_close_reply(0) {
            Ok(()) => break,
            Err(OwnedChannelError::Transport(TransportError::Io(error)))
                if error.kind() == io::ErrorKind::WouldBlock =>
            {
                blocks += 1;
                assert!(blocks < 256);
                let state = driver.channel(0).expect("not reaped");
                assert!(state.remote_close_received());
                assert!(!state.local_close_sent());
                assert!(!driver.is_retired_channel(0));
                assert_eq!(driver.outbound_sequence(), sequence + 1);
                assert!(matches!(
                    driver.drive_close_reply(7),
                    Err(OwnedChannelError::Busy)
                ));
                assert!(matches!(
                    driver.read_inbound(&id),
                    Err(OwnedChannelError::Busy)
                ));
                assert!(matches!(
                    driver.admit_data(0, b"x"),
                    Err(OwnedChannelError::Busy)
                ));
                driver = driver
                    .try_into_connection()
                    .expect_err("partial close released");
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(blocks > 1);
    assert!(driver.channel(0).is_none());
    assert!(driver.is_retired_channel(0));
    assert_eq!(driver.outbound_sequence(), sequence + 2);
    assert!(matches!(
        driver.drive_close_reply(0),
        Err(OwnedChannelError::Busy)
    ));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn local_first_close_is_reaped_without_duplicate_response() -> Result<(), Box<dyn std::error::Error>>
{
    let Harness {
        mut connection,
        write_allowance: write,
        read_allowance: _read,
        sequence,
        steps,
        peer,
    } = setup_connection()?;
    steps.send(PeerStep::ExpectClose(7))?;
    steps.send(PeerStep::AcceptSecond)?;
    steps.send(PeerStep::Close)?;
    steps.send(PeerStep::ExpectDataOn(8, b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    connection.send_close(0)?;
    connection.open_channel(1, b"session", &[])?;
    assert!(matches!(
        connection.dispatch_one()?,
        ChannelEvent::Opened(1)
    ));
    let mut driver = OwnedChannelDriver::try_new(connection).map_err(|_| "driver refused")?;
    let id = driver.admit_data(1, b"abc")?;
    write.store(1, Ordering::SeqCst);
    assert!(
        matches!(driver.drive(&id), Err(OwnedChannelError::Transport(TransportError::Io(error)))
        if error.kind() == io::ErrorKind::WouldBlock)
    );
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
    ));
    assert!(driver.is_retired_channel(0));
    assert!(driver.channel(0).is_none());
    assert!(matches!(
        driver.drive_close_reply(0),
        Err(OwnedChannelError::Busy)
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    assert_eq!(driver.outbound_sequence(), sequence + 3);
    assert!(matches!(
        driver.drive_close_reply(0),
        Err(OwnedChannelError::Busy)
    ));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn partial_close_fatal_and_cancel_never_reap_or_release() -> Result<(), Box<dyn std::error::Error>>
{
    for fatal in [false, true] {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        let id = admit_partial(&mut driver, &write)?;
        steps.send(PeerStep::Close)?;
        steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        assert!(matches!(
            driver.read_inbound(&id)?,
            OwnedChannelInbound::Event(ChannelEvent::Close { channel: 0 })
        ));
        write.store(usize::MAX, Ordering::SeqCst);
        driver.drive(&id)?;
        write.store(1, Ordering::SeqCst);
        assert!(
            matches!(driver.drive_close_reply(0), Err(OwnedChannelError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock)
        );
        if fatal {
            write.store(usize::MAX - 1, Ordering::SeqCst);
            assert!(
                matches!(driver.drive_close_reply(0), Err(OwnedChannelError::Transport(TransportError::Io(error)))
                if error.kind() == io::ErrorKind::BrokenPipe)
            );
            assert!(matches!(
                driver.drive_close_reply(0),
                Err(OwnedChannelError::Failed)
            ));
        }
        let state = driver.channel(0).expect("channel retained");
        assert!(state.remote_close_received() && !state.local_close_sent());
        assert!(!driver.is_retired_channel(0));
        assert_eq!(driver.outbound_sequence(), sequence + 1);
        let driver = driver
            .try_into_connection()
            .expect_err("partial close released");
        drop(driver);
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn foreign_and_stale_ids_do_not_consume_inbound() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, _sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    let (
        mut foreign,
        _foreign_write,
        _foreign_read,
        _foreign_sequence,
        foreign_steps,
        foreign_peer,
    ) = setup()?;
    let foreign_id = foreign.admit_data(0, b"other")?;
    steps.send(PeerStep::Data(b"queued".to_vec()))?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::Finish)?;

    assert!(matches!(
        driver.read_inbound(&foreign_id),
        Err(OwnedChannelError::Busy)
    ));
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data })
            if data == b"queued"
    ));

    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Busy)
    ));
    let channels = driver
        .try_into_connection()
        .map_err(|_| "release refused")?;
    drop(channels);
    peer.join().map_err(|_| "peer panic")??;

    drop(foreign_id);
    drop(foreign);
    foreign_steps.send(PeerStep::Finish)?;
    foreign_peer.join().map_err(|_| "foreign peer panic")??;
    Ok(())
}

#[test]
fn parse_failure_after_consumed_packet_terminally_fails_driver()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, _sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    // SSH_MSG_CHANNEL_DATA for channel 0 with a nine-byte string and one byte.
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Raw(vec![94, 0, 0, 0, 0, 0, 0, 0, 9, b'x']))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;

    let error = driver.read_inbound(&id).unwrap_err();
    assert!(
        matches!(error, OwnedChannelError::Channel(ChannelError::Wire(_))),
        "{error:?}"
    );
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Failed)
    ));
    assert!(matches!(driver.drive(&id), Err(OwnedChannelError::Failed)));
    let Err(driver) = driver.try_into_connection() else {
        panic!("released after a parse failure")
    };
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    drop(driver);
    Ok(())
}

#[test]
fn channel_protocol_error_after_consumed_packet_fails_channel_and_driver()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, _sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Eof)?;
    // Raw data bypasses the peer's own data-after-EOF guard.
    steps.send(PeerStep::Raw(vec![
        94, 0, 0, 0, 0, 0, 0, 0, 4, b'l', b'a', b't', b'e',
    ]))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;

    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Eof { channel: 0 })
    ));
    let error = driver.read_inbound(&id).unwrap_err();
    assert!(
        matches!(
            error,
            OwnedChannelError::Channel(ChannelError::DataAfterEof)
        ),
        "{error:?}"
    );
    assert!(driver.channel(0).expect("channel state").failed());
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Failed)
    ));
    let Err(driver) = driver.try_into_connection() else {
        panic!("released after a channel protocol error")
    };
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    drop(driver);
    Ok(())
}

#[test]
fn deferred_pong_blocks_reads_until_data_and_pong_are_driven()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    assert!(matches!(
        driver.drive_deferred_pong(),
        Err(OwnedChannelError::Busy)
    ));
    steps.send(PeerStep::Ping(b"p".to_vec()))?;
    steps.send(PeerStep::Data(b"after".to_vec()))?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectPong(b"p".to_vec()))?;
    steps.send(PeerStep::Finish)?;

    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::PongDeferred
    ));
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Busy)
    ));
    assert!(matches!(
        driver.drive_deferred_pong(),
        Err(OwnedChannelError::Busy)
    ));
    let Err(mut driver) = driver.try_into_connection() else {
        panic!("released with a pong owed")
    };

    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Busy)
    ));
    let Err(mut driver) = driver.try_into_connection() else {
        panic!("released with a pong owed")
    };
    write.store(1, Ordering::SeqCst);
    assert!(matches!(
        driver.drive_deferred_pong(),
        Err(OwnedChannelError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock
    ));
    let Err(mut driver) = driver.try_into_connection() else {
        panic!("released after a pong WouldBlock")
    };
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive_deferred_pong()?;
    let mut channels = driver
        .try_into_connection()
        .map_err(|_| "release refused after pong")?;
    assert_eq!(channels.transport().outbound_sequence(), sequence + 2);
    assert!(matches!(
        channels.dispatch_one()?,
        ChannelEvent::Data { channel: 0, data } if data == b"after"
    ));
    drop(channels);
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn global_request_with_reply_is_surfaced_without_reply_and_blocks_release()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, _sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::GlobalRequest { want_reply: true })?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;

    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
            want_reply: true,
            ..
        })
    ));
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Busy)
    ));
    let Err(driver) = driver.try_into_connection() else {
        panic!("released with a global reply owed")
    };
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    drop(driver);
    Ok(())
}

#[test]
fn consumed_global_request_failure_resumes_one_byte_at_a_time()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    steps.send(PeerStep::GlobalRequest { want_reply: true })?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectGlobalFailure)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
            want_reply: true,
            ..
        })
    ));
    assert!(matches!(
        driver.drive_global_failure(),
        Err(OwnedChannelError::Busy)
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    let mut blocks = 0;
    loop {
        write.store(1, Ordering::SeqCst);
        match driver.drive_global_failure() {
            Ok(()) => break,
            Err(OwnedChannelError::Transport(TransportError::Io(error)))
                if error.kind() == io::ErrorKind::WouldBlock =>
            {
                blocks += 1;
                assert!(blocks < 256);
                assert_eq!(driver.outbound_sequence(), sequence + 1);
                assert!(matches!(
                    driver.admit_data(0, b"x"),
                    Err(OwnedChannelError::Busy)
                ));
                assert!(matches!(
                    driver.read_inbound(&id),
                    Err(OwnedChannelError::Busy)
                ));
                driver = driver
                    .try_into_connection()
                    .expect_err("partial reply released");
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(blocks > 1);
    assert_eq!(driver.outbound_sequence(), sequence + 2);
    assert!(matches!(
        driver.drive_global_failure(),
        Err(OwnedChannelError::Busy)
    ));
    assert_eq!(driver.channel(0).unwrap().remote_window(), 14);
    let connection = driver
        .try_into_connection()
        .map_err(|_| "release refused")?;
    drop(connection);
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn global_failure_fatal_write_prevents_release() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::GlobalRequest { want_reply: true })?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
            want_reply: true,
            ..
        })
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    write.store(1, Ordering::SeqCst);
    assert!(matches!(
        driver.drive_global_failure(),
        Err(OwnedChannelError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock
    ));
    write.store(usize::MAX - 1, Ordering::SeqCst);
    assert!(matches!(
        driver.drive_global_failure(),
        Err(OwnedChannelError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::BrokenPipe
    ));
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    assert!(matches!(
        driver.drive_global_failure(),
        Err(OwnedChannelError::Failed)
    ));
    let driver = driver
        .try_into_connection()
        .expect_err("failed driver released");
    drop(driver);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn dropping_driver_during_global_failure_closes_partial_packet()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    steps.send(PeerStep::GlobalRequest { want_reply: true })?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
            want_reply: true,
            ..
        })
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    write.store(1, Ordering::SeqCst);
    assert!(matches!(
        driver.drive_global_failure(),
        Err(OwnedChannelError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    drop(driver);
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn channel_request_with_reply_is_surfaced_and_blocks_release()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, _sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Request {
        request_type: b"exec".to_vec(),
        want_reply: true,
    })?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;

    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Request {
            channel: 0,
            want_reply: true,
            ..
        })
    ));
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Busy)
    ));
    let Err(driver) = driver.try_into_connection() else {
        panic!("released with a channel reply owed")
    };
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    drop(driver);
    Ok(())
}

#[test]
fn channel_failure_retries_one_byte_and_uses_peer_channel_number()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    steps.send(PeerStep::Request {
        request_type: b"exec".to_vec(),
        want_reply: true,
    })?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectRequestFailure(7))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Request {
            channel: 0,
            want_reply: true,
            ..
        })
    ));
    assert!(matches!(
        driver.drive_channel_failure(0),
        Err(OwnedChannelError::Busy)
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    assert!(matches!(
        driver.drive_channel_failure(7),
        Err(OwnedChannelError::Busy)
    ));
    let mut blocks = 0;
    loop {
        write.store(1, Ordering::SeqCst);
        match driver.drive_channel_failure(0) {
            Ok(()) => break,
            Err(OwnedChannelError::Transport(TransportError::Io(error)))
                if error.kind() == io::ErrorKind::WouldBlock =>
            {
                blocks += 1;
                assert!(blocks < 256);
                assert_eq!(driver.outbound_sequence(), sequence + 1);
                assert!(matches!(
                    driver.drive_channel_failure(7),
                    Err(OwnedChannelError::Busy)
                ));
                assert!(matches!(
                    driver.admit_data(0, b"x"),
                    Err(OwnedChannelError::Busy)
                ));
                assert!(matches!(
                    driver.read_inbound(&id),
                    Err(OwnedChannelError::Busy)
                ));
                driver = driver
                    .try_into_connection()
                    .expect_err("partial reply released");
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(blocks > 1);
    assert_eq!(driver.outbound_sequence(), sequence + 2);
    assert_eq!(driver.channel(0).unwrap().remote_window(), 14);
    assert!(matches!(
        driver.drive_channel_failure(0),
        Err(OwnedChannelError::Busy)
    ));
    let connection = driver
        .try_into_connection()
        .map_err(|_| "release refused")?;
    drop(connection);
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn channel_request_without_reply_never_emits_a_failure() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    steps.send(PeerStep::Request {
        request_type: b"exec".to_vec(),
        want_reply: false,
    })?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Request {
            channel: 0,
            want_reply: false,
            ..
        })
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    assert!(matches!(
        driver.drive_channel_failure(0),
        Err(OwnedChannelError::Busy)
    ));
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    let connection = driver
        .try_into_connection()
        .map_err(|_| "release refused")?;
    drop(connection);
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn request_for_unknown_channel_terminally_fails_driver() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, _sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Raw(vec![
        98, 0, 0, 0, 99, 0, 0, 0, 4, b'e', b'x', b'e', b'c', 1,
    ]))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Channel(ChannelError::UnknownChannel))
    ));
    assert!(matches!(
        driver.drive_channel_failure(99),
        Err(OwnedChannelError::Failed)
    ));
    let driver = driver
        .try_into_connection()
        .expect_err("failed driver released");
    drop(driver);
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn channel_failure_fatal_after_partial_write_prevents_release()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    steps.send(PeerStep::Request {
        request_type: b"exec".to_vec(),
        want_reply: true,
    })?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Request {
            channel: 0,
            want_reply: true,
            ..
        })
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    write.store(1, Ordering::SeqCst);
    assert!(matches!(driver.drive_channel_failure(0),
        Err(OwnedChannelError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock));
    write.store(usize::MAX - 1, Ordering::SeqCst);
    assert!(matches!(driver.drive_channel_failure(0),
        Err(OwnedChannelError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::BrokenPipe));
    assert_eq!(driver.outbound_sequence(), sequence + 1);
    assert!(matches!(
        driver.drive_channel_failure(0),
        Err(OwnedChannelError::Failed)
    ));
    let driver = driver
        .try_into_connection()
        .expect_err("failed driver released");
    drop(driver);
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn pong_global_and_channel_replies_follow_their_owned_data()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    steps.send(PeerStep::Ping(b"p".to_vec()))?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectPong(b"p".to_vec()))?;
    steps.send(PeerStep::GlobalRequest { want_reply: true })?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectGlobalFailure)?;
    steps.send(PeerStep::Request {
        request_type: b"exec".to_vec(),
        want_reply: true,
    })?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectRequestFailure(7))?;
    steps.send(PeerStep::Open(9))?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectOpenFailure(9, 1))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;

    let first = admit_partial(&mut driver, &write)?;
    assert!(matches!(
        driver.read_inbound(&first)?,
        OwnedChannelInbound::PongDeferred
    ));
    assert!(matches!(
        driver.drive_channel_failure(0),
        Err(OwnedChannelError::Busy)
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&first)?;
    driver.drive_deferred_pong()?;

    let second = admit_partial(&mut driver, &write)?;
    assert!(matches!(
        driver.read_inbound(&second)?,
        OwnedChannelInbound::Event(ChannelEvent::GlobalRequest {
            want_reply: true,
            ..
        })
    ));
    assert!(matches!(
        driver.drive_channel_failure(0),
        Err(OwnedChannelError::Busy)
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&second)?;
    driver.drive_global_failure()?;

    let third = admit_partial(&mut driver, &write)?;
    assert!(matches!(
        driver.read_inbound(&third)?,
        OwnedChannelInbound::Event(ChannelEvent::Request {
            channel: 0,
            want_reply: true,
            ..
        })
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&third)?;
    driver.drive_channel_failure(0)?;
    let fourth = admit_partial(&mut driver, &write)?;
    assert!(matches!(driver.read_inbound(&fourth)?,
        OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&fourth)?;
    driver.drive_open_rejection(9, 1)?;
    assert_eq!(driver.outbound_sequence(), sequence + 8);
    assert_eq!(driver.channel(0).unwrap().remote_window(), 5);
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn open_request_is_surfaced_and_blocks_release() -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, _sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Open(9))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::Finish)?;

    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request))
            if request.sender_channel() == 9
    ));
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Busy)
    ));
    let Err(driver) = driver.try_into_connection() else {
        panic!("released with an open request owed")
    };
    release.send(())?;
    peer.join().map_err(|_| "peer panic")??;
    drop(driver);
    Ok(())
}

#[test]
fn open_rejection_resumes_each_byte_and_removes_pending_once()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    steps.send(PeerStep::Open(9))?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::ExpectOpenFailure(9, 1))?;
    steps.send(PeerStep::ExpectTruncatedPacket)?;
    steps.send(PeerStep::Finish)?;
    assert!(matches!(driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9));
    assert_eq!(driver.pending_open_count(), 1);
    assert!(matches!(
        driver.drive_open_rejection(9, 1),
        Err(OwnedChannelError::Busy)
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    assert!(matches!(
        driver.drive_open_rejection(8, 1),
        Err(OwnedChannelError::Busy)
    ));
    assert!(matches!(
        driver.drive_open_rejection(9, 0),
        Err(OwnedChannelError::Channel(ChannelError::InvalidMessage))
    ));
    assert!(matches!(
        driver.drive_open_rejection(9, 5),
        Err(OwnedChannelError::Channel(ChannelError::InvalidMessage))
    ));
    let mut blocks = 0;
    loop {
        write.store(1, Ordering::SeqCst);
        match driver.drive_open_rejection(9, 1) {
            Ok(()) => break,
            Err(OwnedChannelError::Transport(TransportError::Io(error)))
                if error.kind() == io::ErrorKind::WouldBlock =>
            {
                blocks += 1;
                assert!(blocks < 256);
                assert_eq!(driver.pending_open_count(), 1);
                assert_eq!(driver.outbound_sequence(), sequence + 1);
                assert!(matches!(
                    driver.drive_open_rejection(9, 2),
                    Err(OwnedChannelError::Busy)
                ));
                assert!(matches!(
                    driver.admit_data(0, b"x"),
                    Err(OwnedChannelError::Busy)
                ));
                assert!(matches!(
                    driver.read_inbound(&id),
                    Err(OwnedChannelError::Busy)
                ));
                driver = driver
                    .try_into_connection()
                    .expect_err("partial rejection released");
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(blocks > 1);
    assert_eq!(driver.pending_open_count(), 0);
    assert_eq!(driver.outbound_sequence(), sequence + 2);
    assert_eq!(driver.channel(0).unwrap().remote_window(), 14);
    assert!(matches!(
        driver.drive_open_rejection(9, 1),
        Err(OwnedChannelError::Busy)
    ));
    drop(
        driver
            .try_into_connection()
            .map_err(|_| "release refused")?,
    );
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn open_rejection_fatal_and_cancel_close_partial_packet() -> Result<(), Box<dyn std::error::Error>>
{
    for fatal in [false, true] {
        let (mut driver, write, _read, sequence, steps, peer) = setup()?;
        let id = admit_partial(&mut driver, &write)?;
        steps.send(PeerStep::Open(9))?;
        steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
        steps.send(PeerStep::ExpectTruncatedPacket)?;
        steps.send(PeerStep::Finish)?;
        assert!(matches!(driver.read_inbound(&id)?,
            OwnedChannelInbound::Event(ChannelEvent::OpenRequest(request)) if request.sender_channel() == 9));
        write.store(usize::MAX, Ordering::SeqCst);
        driver.drive(&id)?;
        write.store(1, Ordering::SeqCst);
        assert!(matches!(driver.drive_open_rejection(9, 1),
            Err(OwnedChannelError::Transport(TransportError::Io(error)))
                if error.kind() == io::ErrorKind::WouldBlock));
        if fatal {
            write.store(usize::MAX - 1, Ordering::SeqCst);
            assert!(matches!(driver.drive_open_rejection(9, 1),
                Err(OwnedChannelError::Transport(TransportError::Io(error)))
                    if error.kind() == io::ErrorKind::BrokenPipe));
            assert!(matches!(
                driver.drive_open_rejection(9, 1),
                Err(OwnedChannelError::Failed)
            ));
        }
        assert_eq!(driver.pending_open_count(), 1);
        assert_eq!(driver.outbound_sequence(), sequence + 1);
        let driver = driver
            .try_into_connection()
            .expect_err("partial rejection released");
        drop(driver);
        peer.join().map_err(|_| "peer panic")??;
    }
    Ok(())
}

#[test]
fn ignored_payload_is_consumed_without_event_and_reading_continues()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, write, _read, _sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    // SSH_MSG_IGNORE with an empty data string.
    steps.send(PeerStep::Raw(vec![2, 0, 0, 0, 0]))?;
    steps.send(PeerStep::Data(b"kept".to_vec()))?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::Finish)?;

    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Consumed
    ));
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data })
            if data == b"kept"
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    let channels = driver
        .try_into_connection()
        .map_err(|_| "release refused")?;
    drop(channels);
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn inbound_would_block_preserves_packet_and_obligations() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut driver, write, read, _sequence, steps, peer) = setup()?;
    let id = admit_partial(&mut driver, &write)?;
    steps.send(PeerStep::Data(b"resume".to_vec()))?;
    steps.send(PeerStep::ExpectData(b"abc".to_vec()))?;
    steps.send(PeerStep::Finish)?;

    read.store(1, Ordering::SeqCst);
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock
    ));
    let Err(mut driver) = driver.try_into_connection() else {
        panic!("released after an inbound WouldBlock")
    };
    assert!(matches!(
        driver.read_inbound(&id),
        Err(OwnedChannelError::Transport(TransportError::Io(error)))
            if error.kind() == io::ErrorKind::WouldBlock
    ));
    read.store(usize::MAX, Ordering::SeqCst);
    assert!(matches!(
        driver.read_inbound(&id)?,
        OwnedChannelInbound::Event(ChannelEvent::Data { channel: 0, data })
            if data == b"resume"
    ));
    write.store(usize::MAX, Ordering::SeqCst);
    driver.drive(&id)?;
    let channels = driver
        .try_into_connection()
        .map_err(|_| "release refused")?;
    drop(channels);
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn try_new_refuses_pending_open_and_retry_succeeds_after_answer()
-> Result<(), Box<dyn std::error::Error>> {
    let Harness {
        mut connection,
        steps,
        peer,
        ..
    } = setup_connection()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Open(9))?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::ExpectOpened(9))?;
    steps.send(PeerStep::Finish)?;

    let event = connection.dispatch_one()?;
    let ChannelEvent::OpenRequest(request) = event else {
        panic!("expected open request, got {event:?}");
    };
    assert_eq!(request.sender_channel(), 9);
    assert_eq!(connection.pending_open_count(), 1);
    let channel_zero = connection.channel(0).expect("channel 0");
    let sequence = connection.transport().outbound_sequence();

    let Err(connection) = OwnedChannelDriver::try_new(connection) else {
        panic!("accepted a connection with a pending open")
    };
    let mut connection = *connection;
    assert_eq!(connection.pending_open_count(), 1);
    assert_eq!(connection.channel(0).expect("channel 0"), channel_zero);
    assert_eq!(connection.transport().outbound_sequence(), sequence);

    connection.confirm_open_with_limits(9, 9, 17, 128)?;
    assert_eq!(connection.pending_open_count(), 0);
    assert!(connection.channel(9).is_some());

    let driver = OwnedChannelDriver::try_new(connection).map_err(|_| "retry refused")?;
    assert!(driver.channel(9).is_some());
    assert_eq!(driver.channel(0).expect("channel 0"), channel_zero);
    release.send(())?;
    drop(driver);
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}

#[test]
fn try_new_refuses_close_reply_and_retry_succeeds_after_close()
-> Result<(), Box<dyn std::error::Error>> {
    let Harness {
        mut connection,
        steps,
        peer,
        ..
    } = setup_connection()?;
    let (release, wait) = mpsc::channel();
    steps.send(PeerStep::Close)?;
    steps.send(PeerStep::Wait(wait))?;
    steps.send(PeerStep::ExpectClose(7))?;
    steps.send(PeerStep::Finish)?;

    assert!(matches!(
        connection.dispatch_one()?,
        ChannelEvent::Close { channel: 0 }
    ));
    let channel_zero = connection.channel(0).expect("channel 0");
    assert!(channel_zero.remote_close_received());
    assert!(!channel_zero.local_close_sent());

    let Err(connection) = OwnedChannelDriver::try_new(connection) else {
        panic!("accepted a connection with an unanswered close")
    };
    let mut connection = *connection;
    assert_eq!(connection.channel(0).expect("channel 0"), channel_zero);
    assert_eq!(connection.channel_count(), 1);

    connection.send_close(0)?;
    assert!(connection.channel(0).is_none());
    assert_eq!(connection.channel_count(), 0);

    let driver = OwnedChannelDriver::try_new(connection).map_err(|_| "retry refused")?;
    release.send(())?;
    drop(driver);
    peer.join().map_err(|_| "peer panic")??;
    Ok(())
}
