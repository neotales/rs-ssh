//! Private retain-phase branching and exact FIFO/sequence/accounting boundaries.
use super::*;
use crate::cipher::{PacketKeyMaterial, PacketProtector, PacketSuite};
use crate::transport::owned_tests::{ScriptedIo, transport};
use std::io::{self, Cursor};

fn protector() -> PacketProtector {
    PacketProtector::new(
        PacketSuite::new("chacha20-poly1305@openssh.com", None).unwrap(),
        PacketKeyMaterial::new(&[0; 8], &[42; 64], None),
    )
    .unwrap()
}

fn driver(payloads: &[Vec<u8>]) -> OwnedChannelDriver<ScriptedIo> {
    let mut connection = ChannelConnection::new(transport());
    connection.open_channel(0, b"session", &[]).unwrap();
    let mut opened = Writer::new();
    opened.write_byte(91);
    for value in [0, 7, 128, 128] {
        opened.write_uint32(value);
    }
    connection
        .dispatch_decoded_payload(&opened.into_bytes())
        .unwrap();
    connection.transport.stream.output.clear();
    let mut sender = protector();
    let mut bytes = Vec::new();
    for (sequence, payload) in payloads.iter().enumerate() {
        let padding = vec![
            0;
            crate::cipher::PacketAlignment::for_suite(sender.suite())
                .padding_length(payload.len())
                .unwrap()
        ];
        bytes.extend(
            sender
                .seal(u32::try_from(sequence).unwrap(), payload, &padding)
                .unwrap(),
        );
    }
    connection.transport.stream.input = Cursor::new(bytes);
    OwnedChannelDriver::try_new(connection).unwrap()
}

fn ping(data: &[u8]) -> Vec<u8> {
    neotales_ssh::keepalive::TransportPing::Ping(data.to_vec())
        .encode()
        .unwrap()
}
fn request() -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(98);
    writer.write_uint32(0);
    writer.write_string(b"exec").unwrap();
    writer.write_bool(true);
    writer.into_bytes()
}
fn decode_output(driver: &OwnedChannelDriver<ScriptedIo>) -> Vec<Vec<u8>> {
    let mut input = Cursor::new(driver.connection.transport.stream.output.clone());
    let mut protector = protector();
    let mut buffer = crate::transport::ProtectedReadBuffer::default();
    let mut packets = Vec::new();
    while usize::try_from(input.position()).unwrap() < input.get_ref().len() {
        packets.push(
            crate::transport::read_protected_packet_buffered(
                &mut input,
                &mut buffer,
                &mut protector,
                u32::try_from(packets.len()).unwrap() + 1,
            )
            .unwrap(),
        );
    }
    packets
}

#[test]
fn private_fifo_retains_two_distinct_pings_and_mixed_repeated_controls() {
    let mut driver = driver(&[ping(b"A"), request(), ping(b"B"), request()]);
    let id = driver.admit_data(0, b"abc").unwrap();
    let sequence = driver.outbound_sequence();
    driver.connection.transport.stream.budget = 1;
    assert!(driver.drive(&id).is_err());
    for _ in 0..4 {
        let bytes = driver.connection.transport.stream.output.len();
        driver.read_inbound(&id).unwrap();
        assert_eq!(driver.connection.transport.stream.output.len(), bytes);
        assert_eq!(driver.outbound_sequence(), sequence);
    }
    assert_eq!(driver.inbound_sequence(), 4);
    assert_eq!(driver.reply_obligations.len(), 4);
    assert!(matches!(
        driver.drive_channel_failure(0),
        Err(OwnedChannelError::Busy)
    ));
    driver.connection.transport.stream.budget = usize::MAX;
    driver.drive(&id).unwrap();
    // A later control may not overtake the first PONG.
    assert!(matches!(
        driver.drive_channel_failure(0),
        Err(OwnedChannelError::Busy)
    ));
    driver.drive_deferred_pong().unwrap();
    assert!(matches!(
        driver.drive_deferred_pong(),
        Err(OwnedChannelError::Busy)
    ));
    assert!(matches!(
        driver.drive_channel_failure(1),
        Err(OwnedChannelError::Busy)
    ));
    driver.connection.transport.stream.budget = 1;
    assert!(driver.drive_channel_failure(0).is_err());
    assert_eq!(driver.reply_obligations.len(), 3);
    assert!(matches!(
        driver.drive_deferred_pong(),
        Err(OwnedChannelError::Busy)
    ));
    driver.connection.transport.stream.budget = usize::MAX;
    driver.drive_channel_failure(0).unwrap();
    driver.drive_deferred_pong().unwrap();
    driver.drive_channel_failure(0).unwrap();
    assert_eq!(driver.outbound_sequence(), sequence + 5);
    assert!(driver.reply_obligations.is_empty());
    let mut data = Writer::new();
    data.write_byte(94);
    data.write_uint32(7);
    data.write_string(b"abc").unwrap();
    let pong = |bytes: &[u8]| {
        neotales_ssh::keepalive::TransportPing::Pong(bytes.to_vec())
            .encode()
            .unwrap()
    };
    assert_eq!(
        decode_output(&driver),
        vec![
            data.into_bytes(),
            pong(b"A"),
            vec![100, 0, 0, 0, 7],
            pong(b"B"),
            vec![100, 0, 0, 0, 7],
        ]
    );
}

#[test]
fn private_retained_event_blocks_reads_and_is_moved_once_without_credit() {
    let mut data = Writer::new();
    data.write_byte(94);
    data.write_uint32(0);
    data.write_string(b"abc").unwrap();
    let mut driver = driver(&[data.into_bytes(), ping(b"later")]);
    let id = driver.admit_data(0, b"x").unwrap();
    let before = driver.channel(0).unwrap().local_window();
    driver.retain_next_owned(&id.0).unwrap();
    assert_eq!(driver.channel(0).unwrap().local_window(), before - 3);
    let reads = driver.connection.transport.stream.reads;
    assert!(matches!(
        driver.retain_next_owned(&id.0),
        Err(OwnedChannelError::Busy)
    ));
    assert_eq!(driver.connection.transport.stream.reads, reads);
    assert_eq!(driver.inbound_sequence(), 1);
    assert!(matches!(driver.read_inbound(&id).unwrap(),
        OwnedChannelInbound::Event(ChannelEvent::Data { data, .. }) if data == b"abc"));
    assert!(driver.take_retained_event().is_none());
    assert_eq!(driver.connection.transport.stream.reads, reads);
    assert_eq!(driver.channel(0).unwrap().local_window(), before - 3);
    assert!(matches!(
        driver.read_inbound(&id).unwrap(),
        OwnedChannelInbound::PongDeferred
    ));
    assert_eq!(driver.inbound_sequence(), 2);
}

#[test]
fn private_capacity_boundary_counts_active_front_and_reopens_after_completion() {
    let mut driver = driver(&(0..9u8).map(|i| ping(&[i])).collect::<Vec<_>>());
    let id = driver.admit_data(0, b"x").unwrap();
    for _ in 0..8 {
        driver.read_inbound(&id).unwrap();
    }
    let reads = driver.connection.transport.stream.reads;
    for _ in 0..16 {
        assert!(matches!(
            driver.read_inbound(&id),
            Err(OwnedChannelError::Busy)
        ));
    }
    assert_eq!(driver.connection.transport.stream.reads, reads);
    assert_eq!(driver.inbound_sequence(), 8);
    driver.drive(&id).unwrap();
    driver.connection.transport.stream.budget = 1;
    assert!(matches!(driver.drive_deferred_pong(),
        Err(OwnedChannelError::Transport(TransportError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock));
    let pong = driver.pong_read_id().unwrap();
    assert!(matches!(
        driver.read_while_pong(&pong),
        Err(OwnedChannelError::Busy)
    ));
    assert_eq!(driver.connection.transport.stream.reads, reads);
    driver.connection.transport.stream.budget = usize::MAX;
    driver.drive_deferred_pong().unwrap();
    assert!(matches!(
        driver.read_idle().unwrap(),
        OwnedChannelInbound::PongDeferred
    ));
    assert_eq!(driver.inbound_sequence(), 9);
    assert_eq!(driver.reply_obligations.len(), 8);
    for _ in 0..8 {
        driver.drive_deferred_pong().unwrap();
    }
    assert_eq!(decode_output(&driver).len(), 10);
}
