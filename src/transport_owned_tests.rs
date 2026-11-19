//! Private reservation/identity branches and exact packet/sequence boundaries.
use super::*;
use crate::cipher::PacketKeyMaterial;
use std::io::Cursor;

#[derive(Debug)]
pub(crate) struct ScriptedIo {
    pub(crate) input: Cursor<Vec<u8>>,
    pub(crate) output: Vec<u8>,
    pub(crate) budget: usize,
    pub(crate) reads: usize,
    pub(crate) writes: usize,
}
impl Read for ScriptedIo {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.input.read(bytes)
    }
}
impl Write for ScriptedIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.budget == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let count = bytes.len().min(self.budget);
        self.output.extend_from_slice(&bytes[..count]);
        self.budget -= count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn transport() -> ClientTransport<ScriptedIo> {
    let (mut transport, _) = ClientTransport::start(
        ScriptedIo {
            input: Cursor::new(b"SSH-2.0-test\r\n".to_vec()),
            output: Vec::new(),
            budget: usize::MAX,
            reads: 0,
            writes: 0,
        },
        "SSH-2.0-test",
    )
    .unwrap();
    transport.established = true;
    transport.authenticated = true;
    let suite = PacketSuite::new("chacha20-poly1305@openssh.com", None).unwrap();
    transport.write_protector = Some(
        PacketProtector::new(suite, PacketKeyMaterial::new(&[0; 8], &[42; 64], None)).unwrap(),
    );
    transport.read_protector = Some(
        PacketProtector::new(suite, PacketKeyMaterial::new(&[0; 8], &[42; 64], None)).unwrap(),
    );
    transport.stream.output.clear();
    transport
}

#[test]
fn private_control_identity_front_and_completion_boundaries() {
    let mut transport = transport();
    let data = transport.start_owned_packet(b"\x5edata").unwrap();
    let first = transport.reserve_owned_control().unwrap();
    let second = transport.reserve_owned_control().unwrap();
    let before = transport.outbound_sequence();
    for id in [&first, &second] {
        assert!(transport.start_owned_control_packet(id, &[82]).is_err());
        assert!(transport.complete_owned_control(id).is_err());
    }
    assert_eq!(transport.stream.output, Vec::<u8>::new());
    transport.drive_owned_packet(&data).unwrap();
    transport.stream.output.clear();
    assert!(
        transport
            .start_owned_control_packet(&second, &[82])
            .is_err()
    );
    let packet = transport.start_owned_control_packet(&first, &[82]).unwrap();
    transport.stream.budget = 1;
    assert!(transport.drive_owned_packet(&packet).is_err());
    assert_eq!(transport.outbound_sequence(), before + 1);
    assert_eq!(transport.owned_obligations.len(), 2);
    assert!(transport.complete_owned_control(&first).is_err());
    assert!(
        transport
            .start_owned_control_packet(&second, &[82])
            .is_err()
    );
    assert!(transport.start_owned_control_packet(&first, &[81]).is_err());
    let prefix = transport.stream.output.clone();
    transport.stream.budget = usize::MAX;
    transport.drive_owned_packet(&packet).unwrap();
    assert!(transport.stream.output.starts_with(&prefix));
    assert_eq!(transport.outbound_sequence(), before + 2);
    assert_eq!(transport.owned_obligations.len(), 2);
    assert!(transport.complete_owned_control(&second).is_err());
    transport.complete_owned_control(&first).unwrap();
    assert!(transport.complete_owned_control(&first).is_err());
    let packet = transport
        .start_owned_control_packet(&second, &[82])
        .unwrap();
    transport.drive_owned_packet(&packet).unwrap();
    transport.complete_owned_control(&second).unwrap();
    assert!(transport.owned_obligations.is_empty());
    assert_eq!(transport.outbound_sequence(), before + 3);
}

#[test]
fn private_mixed_fifo_counts_active_reply_and_blocks_rekey() {
    let mut transport = transport();
    let control = transport.reserve_owned_control().unwrap();
    transport
        .owned_obligations
        .push(Obligation::Pong(vec![193, 0, 0, 0, 0]))
        .unwrap();
    transport.deferred_owned_pong = true;
    for _ in 2..8 {
        transport.reserve_owned_control().unwrap();
    }
    transport.retained_peer_kexinit = Some(vec![20]);
    assert!(transport.advance_retained_peer_rekey().is_err());
    assert!(transport.drive_deferred_pong().is_err());
    assert_eq!(transport.stream.output, Vec::<u8>::new());
    let reads = transport.stream.reads;
    assert!(transport.reserve_owned_control().is_err());
    assert!(transport.read_idle_owned().is_err());
    assert_eq!(transport.stream.reads, reads);
    let packet = transport
        .start_owned_control_packet(&control, &[82])
        .unwrap();
    transport.stream.budget = 1;
    assert!(transport.drive_owned_packet(&packet).is_err());
    assert!(transport.reserve_owned_control().is_err());
    assert_eq!(transport.owned_obligations.len(), 8);
    transport.stream.budget = usize::MAX;
    transport.drive_owned_packet(&packet).unwrap();
    transport.complete_owned_control(&control).unwrap();
    transport.drive_deferred_pong().unwrap();
    // Even with no PONG left, control reservations keep the rekey barrier.
    assert!(!transport.deferred_owned_pong);
    assert!(transport.advance_retained_peer_rekey().is_err());
    assert_eq!(transport.owned_obligations.len(), 6);
    assert_eq!(transport.outbound_sequence(), 2);
}

#[test]
fn private_fatal_front_write_does_not_restore_queue_or_reservation() {
    let mut transport = transport();
    let control = transport.reserve_owned_control().unwrap();
    let packet = transport
        .start_owned_control_packet(&control, &[82])
        .unwrap();
    transport.owned_read_reserved = true;
    transport.write_buffer.abort();
    assert!(transport.drive_owned_packet(&packet).is_err());
    assert!(transport.owned_obligations.is_empty());
    assert!(!transport.owned_read_reserved);
    assert!(transport.complete_owned_control(&control).is_err());
    let bytes = transport.stream.output.len();
    assert!(transport.drive_owned_packet(&packet).is_err());
    assert_eq!(transport.stream.output.len(), bytes);
}

// Exact packet/bounds tests need access to the crate-private reservations.
// Both directions have seven-byte buffers, smaller than a protected packet.
struct TinyEnd {
    input: std::rc::Rc<std::cell::RefCell<VecDeque<u8>>>,
    output: std::rc::Rc<std::cell::RefCell<VecDeque<u8>>>,
    identification: Cursor<Vec<u8>>,
    bounded: bool,
    reads: usize,
    writes: usize,
}
impl Read for TinyEnd {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        if !self.bounded {
            return self.identification.read(bytes);
        }
        let mut input = self.input.borrow_mut();
        if input.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let count = bytes.len().min(input.len());
        for byte in &mut bytes[..count] {
            *byte = input.pop_front().unwrap();
        }
        Ok(count)
    }
}
impl Write for TinyEnd {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if !self.bounded {
            return Ok(bytes.len());
        }
        let mut output = self.output.borrow_mut();
        let count = bytes.len().min(7 - output.len());
        if count == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        output.extend(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn tiny_pair() -> (ClientTransport<TinyEnd>, TinyEnd) {
    let a = std::rc::Rc::new(std::cell::RefCell::new(VecDeque::new()));
    let b = std::rc::Rc::new(std::cell::RefCell::new(VecDeque::new()));
    let endpoint = |input, output| TinyEnd {
        input,
        output,
        identification: Cursor::new(b"SSH-2.0-test\r\n".to_vec()),
        bounded: false,
        reads: 0,
        writes: 0,
    };
    let (mut client, _) = ClientTransport::start(
        endpoint(std::rc::Rc::clone(&a), std::rc::Rc::clone(&b)),
        "SSH-2.0-test",
    )
    .unwrap();
    client.stream.bounded = true;
    client.established = true;
    client.authenticated = true;
    client.read_protector = Some(tiny_protector());
    client.write_protector = Some(tiny_protector());
    let mut peer = endpoint(b, a);
    peer.bounded = true;
    (client, peer)
}
fn tiny_protector() -> PacketProtector {
    PacketProtector::new(
        PacketSuite::new("chacha20-poly1305@openssh.com", None).unwrap(),
        PacketKeyMaterial::new(&[0; 8], &[42; 64], None),
    )
    .unwrap()
}
fn tiny_send(
    client: &mut ClientTransport<TinyEnd>,
    owner: &OwnedPacketId,
    peer: &mut TinyEnd,
    payload: &[u8],
) -> OwnedInbound {
    let mut sender = tiny_protector();
    let packet = sender
        .seal(
            client.inbound_sequence(),
            payload,
            &random_padding(payload.len(), sender.suite()).unwrap(),
        )
        .unwrap();
    let mut written = 0;
    let writes = client.stream.writes;
    for _ in 0..128 {
        if written < packet.len() {
            written += peer.write(&packet[written..]).unwrap();
        }
        let result = client.read_while_owned(owner);
        assert_eq!(client.stream.writes, writes, "the parser wrote a reply");
        match result {
            Ok(inbound) => {
                assert_eq!(written, packet.len());
                return inbound;
            }
            Err(TransportError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {}
            other => panic!("unexpected tiny read: {other:?}"),
        }
    }
    panic!("a bounded tiny packet did not complete");
}
fn tiny_finish(
    mut drive: impl FnMut() -> Result<(), TransportError>,
    peer: &mut TinyEnd,
    transcript: &mut Vec<u8>,
) {
    for _ in 0..128 {
        let result = drive();
        let mut bytes = [0; 7];
        let count = peer.read(&mut bytes).unwrap();
        transcript.extend_from_slice(&bytes[..count]);
        match result {
            Ok(()) => return,
            Err(TransportError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {}
            other => panic!("unexpected tiny write: {other:?}"),
        }
    }
    panic!("a bounded tiny write did not complete");
}
fn tiny_fifo(mixed: bool) {
    let (mut client, mut peer) = tiny_pair();
    let data = client.start_owned_packet(b"\x5edata").unwrap();
    assert!(matches!(client.drive_owned_packet(&data),
        Err(TransportError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock));
    let ping = |bytes: &[u8]| {
        neotales_ssh::keepalive::TransportPing::Ping(bytes.to_vec())
            .encode()
            .unwrap()
    };
    assert!(matches!(
        tiny_send(&mut client, &data, &mut peer, &ping(b"A")),
        OwnedInbound::PongDeferred
    ));
    let control = if mixed {
        assert!(matches!(
            tiny_send(&mut client, &data, &mut peer, &[80, 0, 0, 0, 0, 1]),
            OwnedInbound::Payload(_)
        ));
        Some(client.reserve_owned_control().unwrap())
    } else {
        None
    };
    assert!(matches!(
        tiny_send(&mut client, &data, &mut peer, &ping(b"B")),
        OwnedInbound::PongDeferred
    ));
    assert_eq!(client.outbound_sequence(), 0);
    assert_eq!(client.inbound_sequence(), if mixed { 3 } else { 2 });
    let mut transcript = Vec::new();
    tiny_finish(
        || client.drive_owned_packet(&data),
        &mut peer,
        &mut transcript,
    );
    tiny_finish(|| client.drive_deferred_pong(), &mut peer, &mut transcript);
    if let Some(control) = control {
        assert!(client.drive_deferred_pong().is_err());
        let packet = client.start_owned_control_packet(&control, &[82]).unwrap();
        tiny_finish(
            || client.drive_owned_packet(&packet),
            &mut peer,
            &mut transcript,
        );
        client.complete_owned_control(&control).unwrap();
    }
    tiny_finish(|| client.drive_deferred_pong(), &mut peer, &mut transcript);
    assert!(client.owned_obligations.is_empty());
    let reply = |bytes: &[u8]| {
        neotales_ssh::keepalive::TransportPing::Pong(bytes.to_vec())
            .encode()
            .unwrap()
    };
    let mut expected = vec![b"\x5edata".to_vec(), reply(b"A")];
    if mixed {
        expected.push(vec![82]);
    }
    expected.push(reply(b"B"));
    let mut input = Cursor::new(transcript);
    let mut protector = tiny_protector();
    let mut buffer = ProtectedReadBuffer::default();
    for (sequence, payload) in expected.iter().enumerate() {
        assert_eq!(
            read_protected_packet_buffered(
                &mut input,
                &mut buffer,
                &mut protector,
                u32::try_from(sequence).unwrap()
            )
            .unwrap(),
            *payload
        );
    }
    assert_eq!(
        usize::try_from(input.position()).unwrap(),
        input.get_ref().len()
    );
    assert_eq!(
        client.outbound_sequence(),
        u32::try_from(expected.len()).unwrap()
    );
}

#[test]
fn private_two_tiny_ends_write_two_pongs_once_in_arrival_order() {
    tiny_fifo(false);
}
#[test]
fn private_two_tiny_ends_keep_pong_control_pong_in_arrival_order() {
    tiny_fifo(true);
}
#[test]
fn private_tiny_reserved_eighth_can_release_or_convert_without_draining() {
    let (mut client, mut peer) = tiny_pair();
    let data = client.start_owned_packet(b"\x5edata").unwrap();
    let ping = neotales_ssh::keepalive::TransportPing::Ping(vec![1])
        .encode()
        .unwrap();
    for _ in 0..7 {
        tiny_send(&mut client, &data, &mut peer, &ping);
    }
    // Every packet is split over several seven-byte transfers. Resuming the
    // eighth non-reply releases its reservation without draining any reply.
    assert!(matches!(
        tiny_send(&mut client, &data, &mut peer, &[2, 0, 0, 0, 0]),
        OwnedInbound::Payload(_)
    ));
    assert_eq!(client.owned_obligations.len(), 7);
    assert!(!client.owned_read_reserved);
    tiny_send(&mut client, &data, &mut peer, &ping);
    assert_eq!(client.owned_obligations.len(), 8);
    let reads = client.stream.reads;
    let sequence = client.inbound_sequence();
    peer.write_all(&[1]).unwrap();
    assert!(matches!(
        client.read_while_owned(&data),
        Err(TransportError::OwnedPacketState)
    ));
    assert_eq!(client.stream.reads, reads);
    assert_eq!(client.inbound_sequence(), sequence);
    assert_eq!(peer.output.borrow().len(), 1);
}
