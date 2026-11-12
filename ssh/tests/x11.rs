//! X11 byte-transport framing, policy, bounds, and redaction.
use neotales_ssh::{
    Reader,
    channel::{ChannelConnection, ChannelEvent, ChannelTransport},
    x11::{MAX_X11_COOKIE, MAX_X11_PROTOCOL, X11Open, X11Policy, X11Request},
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
fn explicit_request_and_open_are_default_denied_then_policy_accepted()
-> Result<(), Box<dyn std::error::Error>> {
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
    let session = client.allocate_channel_id()?;
    client.open_channel(session, b"session", &[])?;
    let ChannelEvent::OpenRequest(open) = server.dispatch_one()? else {
        return Err("missing session".into());
    };
    let server_session = server.allocate_channel_id()?;
    server.confirm_open(open.sender_channel(), server_session)?;
    client.dispatch_one()?;
    assert_eq!(a.borrow().len(), 0); // No implicit X11 request.
    let request = X11Request::new(true, b"MIT-MAGIC-COOKIE-1", b"0123456789abcdef", 7)?;
    // RFC 4254 6.3 independent body fixture, not our encoder's round trip.
    assert_eq!(
        request.encode()?,
        b"\x01\0\0\0\x12MIT-MAGIC-COOKIE-1\0\0\0\x100123456789abcdef\0\0\0\x07"
    );
    let deny = X11Policy::default();
    let allow = X11Policy::default()
        .with_request_policy(|_, request| request.single_connection() && request.screen() == 7)
        .with_open_policy(|open| open.originator() == b"origin" && open.port() == 6000);
    for accepted in [false, true] {
        request.send(&mut client, session, true)?;
        let wire = a.borrow().front().cloned().ok_or("missing wire")?;
        let mut reader = Reader::new(&wire);
        assert_eq!(reader.read_byte()?, 98);
        reader.read_uint32()?;
        assert_eq!(reader.read_string()?, b"x11-req");
        assert!(reader.read_boolean()?);
        let ChannelEvent::Request {
            channel,
            request_type,
            want_reply,
            data,
        } = server.dispatch_one()?
        else {
            return Err("missing request".into());
        };
        assert_eq!(request_type, b"x11-req");
        assert_eq!(channel, server_session);
        assert_eq!(
            (if accepted { &allow } else { &deny }).handle_request(
                &mut server,
                channel,
                want_reply,
                &data
            )?,
            accepted
        );
        assert!(if accepted {
            matches!(
                client.dispatch_one()?,
                ChannelEvent::RequestSucceeded { .. }
            )
        } else {
            matches!(client.dispatch_one()?, ChannelEvent::RequestFailed { .. })
        });
    }
    for accepted in [false, true] {
        let local = X11Open::new(b"origin", 6000)?.open(&mut client)?;
        let ChannelEvent::OpenRequest(open) = server.dispatch_one()? else {
            return Err("missing x11 open".into());
        };
        assert_eq!(open.channel_type(), b"x11");
        assert_eq!(open.type_specific_data(), b"\0\0\0\x06origin\0\0\x17\x70");
        let remote = (if accepted { &allow } else { &deny }).handle_open(&mut server, &open)?;
        assert_eq!(remote.is_some(), accepted);
        let reply = client.dispatch_one()?;
        assert!(if accepted {
            matches!(reply, ChannelEvent::Opened(id) if id == local)
        } else {
            matches!(reply, ChannelEvent::OpenFailed { .. })
        });
        if let Some(remote) = remote {
            client.write_data(local, b"opaque display bytes")?;
            assert!(
                matches!(server.dispatch_one()?, ChannelEvent::Data { channel, data } if channel == remote && data == b"opaque display bytes")
            );
        }
    }
    assert!(
        allow
            .handle_request(&mut server, server_session, true, b"\x02")
            .is_err()
    );
    Ok(())
}

#[test]
fn request_bounds_and_redaction_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
    let request = X11Request::new(true, b"MIT-MAGIC-COOKIE-1", b"0123456789abcdef", 7)?;
    assert!(!format!("{request:?}").contains("0123456789abcdef"));
    assert!(!format!("{request:?}").contains("MIT-MAGIC"));
    for length in 0..request.encode()?.len() {
        assert!(X11Request::decode(&request.encode()?[..length]).is_err());
    }
    let mut trailing = request.encode()?;
    trailing.push(0);
    assert!(X11Request::decode(&trailing).is_err());
    assert!(X11Request::new(false, &vec![b'a'; MAX_X11_PROTOCOL + 1], b"", 0).is_err());
    assert!(X11Request::new(false, b"", &vec![b'a'; MAX_X11_COOKIE + 2], 0).is_err());
    assert!(X11Request::new(false, b"", b"not hex", 0).is_err());
    Ok(())
}
