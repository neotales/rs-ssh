//! Streamlocal helpers over a byte-only channel transport, with independent wire assertions.
use neotales_ssh::{
    Reader,
    channel::{ChannelConnection, ChannelEvent, ChannelTransport},
    streamlocal::{MAX_STREAMLOCAL_PATH, Operation, StreamlocalPath, StreamlocalPolicy},
};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};
type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;
struct End {
    input: Queue,
    output: Queue,
}
impl ChannelTransport for End {
    fn write_channel_payload(&mut self, data: &[u8]) -> Result<(), ()> {
        self.output.borrow_mut().push_back(data.to_vec());
        Ok(())
    }
    fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
        self.input.borrow_mut().pop_front().ok_or(())
    }
}

#[test]
fn direct_reverse_forward_cancel_and_default_deny() -> Result<(), Box<dyn std::error::Error>> {
    let a = Queue::default();
    let b = Queue::default();
    let mut client = ChannelConnection::new(End {
        input: b.clone(),
        output: a.clone(),
    });
    let mut server = ChannelConnection::new(End {
        input: a.clone(),
        output: b,
    });
    let path = StreamlocalPath::new(b"opaque\xff/socket")?;
    let deny = StreamlocalPolicy::default();
    let allow = StreamlocalPolicy::new(|_, path| path.as_bytes() == b"opaque\xff/socket");
    for operation in [Operation::Direct, Operation::Forwarded] {
        for accepted in [false, true] {
            let local = path.open(&mut client, operation)?;
            let wire = a.borrow().front().cloned().ok_or("missing open")?;
            let mut reader = Reader::new(&wire);
            assert_eq!(reader.read_byte()?, 90);
            let expected = if operation == Operation::Direct {
                b"direct-streamlocal@openssh.com".as_slice()
            } else {
                b"forwarded-streamlocal@openssh.com"
            };
            assert_eq!(reader.read_string()?, expected);
            reader.read_uint32()?;
            reader.read_uint32()?;
            reader.read_uint32()?;
            assert_eq!(reader.read_string()?, path.as_bytes());
            assert_eq!(reader.read_string()?, b"");
            if operation == Operation::Direct {
                assert_eq!(reader.read_uint32()?, 0);
            }
            assert!(reader.is_empty());
            let ChannelEvent::OpenRequest(request) = server.dispatch_one()? else {
                return Err("missing open event".into());
            };
            let policy = if accepted { &allow } else { &deny };
            assert_eq!(
                policy.handle_open(&mut server, &request)?.is_some(),
                accepted
            );
            let reply = client.dispatch_one()?;
            assert!(if accepted {
                matches!(reply, ChannelEvent::Opened(id) if id == local)
            } else {
                matches!(reply, ChannelEvent::OpenFailed { .. })
            });
        }
    }
    for operation in [Operation::Forward, Operation::Cancel] {
        for accepted in [false, true] {
            path.request(&mut client, operation, true)?;
            let ChannelEvent::GlobalRequest {
                request_name,
                want_reply,
                data,
            } = server.dispatch_one()?
            else {
                return Err("missing global".into());
            };
            let expected = if operation == Operation::Forward {
                b"streamlocal-forward@openssh.com".as_slice()
            } else {
                b"cancel-streamlocal-forward@openssh.com"
            };
            assert_eq!(request_name, expected);
            let mut reader = Reader::new(&data);
            assert_eq!(reader.read_string()?, path.as_bytes());
            assert!(reader.is_empty());
            assert_eq!(
                (if accepted { &allow } else { &deny }).handle_global(
                    &mut server,
                    &request_name,
                    want_reply,
                    &data
                )?,
                accepted
            );
            assert!(if accepted {
                matches!(
                    client.dispatch_one()?,
                    ChannelEvent::GlobalRequestSucceeded { .. }
                )
            } else {
                matches!(
                    client.dispatch_one()?,
                    ChannelEvent::GlobalRequestFailed { .. }
                )
            });
        }
    }
    Ok(())
}

#[test]
fn invalid_paths_are_rejected_before_application_policy() -> Result<(), Box<dyn std::error::Error>>
{
    let a = Queue::default();
    let b = Queue::default();
    let mut client = ChannelConnection::new(End {
        input: b.clone(),
        output: a.clone(),
    });
    let mut server = ChannelConnection::new(End {
        input: a,
        output: b,
    });
    let allow = StreamlocalPolicy::new(|_, _| panic!("invalid path reached policy"));
    for invalid in [
        b"".as_slice(),
        b"nul\0path",
        &vec![b'a'; MAX_STREAMLOCAL_PATH + 1],
    ] {
        assert!(StreamlocalPath::new(invalid).is_err());
    }
    // Invalid peer metadata must not reach even an allowing policy.
    client.open_channel(
        999,
        b"direct-streamlocal@openssh.com",
        b"\0\0\0\x03a\0b\0\0\0\0\0\0\0\0",
    )?;
    let ChannelEvent::OpenRequest(request) = server.dispatch_one()? else {
        return Err("missing invalid open".into());
    };
    assert!(allow.handle_open(&mut server, &request).is_err());
    Ok(())
}
