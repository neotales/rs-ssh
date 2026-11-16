//! Private reservation/identity branches and exact packet/sequence boundaries.
use super::*;
use crate::cipher::PacketKeyMaterial;
use std::io::Cursor;

#[derive(Debug)]
struct ScriptedIo {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    budget: usize,
    reads: usize,
}
impl Read for ScriptedIo {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.input.read(bytes)
    }
}
impl Write for ScriptedIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
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

fn transport() -> ClientTransport<ScriptedIo> {
    let (mut transport, _) = ClientTransport::start(
        ScriptedIo {
            input: Cursor::new(b"SSH-2.0-test\r\n".to_vec()),
            output: Vec::new(),
            budget: usize::MAX,
            reads: 0,
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
    assert!(transport.stream.output.is_empty());
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
    assert!(transport.stream.output.is_empty());
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
