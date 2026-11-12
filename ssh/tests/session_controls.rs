//! Session control wire encodings and default-deny server policy.
use neotales_ssh::channel::ChannelTransport;
use neotales_ssh::session::{SessionControl, SessionDecision, SessionEvent};
use neotales_ssh::{
    ClientSessions, KexInit, NegotiatedAlgorithms, NegotiationError, ServerSessions,
};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;
struct End {
    input: Queue,
    output: Queue,
}
impl ChannelTransport for End {
    fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
        self.output.borrow_mut().push_back(payload.to_vec());
        Ok(())
    }
    fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
        self.input.borrow_mut().pop_front().ok_or(())
    }
}

#[test]
fn controls_use_exact_wire_bytes_and_require_explicit_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let incoming = Queue::default();
    let outgoing = Queue::default();
    let mut client = ClientSessions::new(End {
        input: Rc::clone(&outgoing),
        output: Rc::clone(&incoming),
    });
    let mut server = ServerSessions::with_policy(
        End {
            input: Rc::clone(&incoming),
            output: outgoing,
        },
        |_| SessionDecision::accept(0),
    );
    let session = client.open_session()?;
    let SessionEvent::Opened {
        session: server_session,
    } = server.dispatch_one()?
    else {
        return Err("expected open".into());
    };
    client.dispatch_one()?;
    client.send_break(session, 1234, true)?;
    assert!(matches!(
        server.dispatch_one()?,
        SessionEvent::ControlRequested {
            accepted: false,
            ..
        }
    ));
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::RequestFailed { .. }
    ));
    let calls = Rc::new(Cell::new(0));
    let calls_in_callback = Rc::clone(&calls);
    server.set_control_policy(move |_, _| {
        calls_in_callback.set(calls_in_callback.get() + 1);
        true
    });
    for (control, expected) in [
        (
            SessionControl::Signal(b"TERM".to_vec()),
            b"\0\0\0\x04TERM".to_vec(),
        ),
        (
            SessionControl::WindowChange([80, 24, 640, 480]),
            [80_u32, 24, 640, 480]
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect(),
        ),
        (SessionControl::Break(1234), 1234_u32.to_be_bytes().to_vec()),
    ] {
        match &control {
            SessionControl::Signal(name) => client.send_signal(session, name)?,
            SessionControl::WindowChange(dimensions) => {
                client.window_change(session, *dimensions)?;
            }
            SessionControl::Break(duration) => client.send_break(session, *duration, false)?,
        }
        let valid = incoming
            .borrow()
            .front()
            .cloned()
            .ok_or("missing control")?;
        assert_eq!(
            server.dispatch_one()?,
            SessionEvent::ControlRequested {
                session: server_session,
                control,
                data: expected,
                want_reply: false,
                accepted: true
            }
        );
        let before = calls.get();
        let mut short = valid.clone();
        short.pop();
        incoming.borrow_mut().push_back(short);
        assert!(server.dispatch_one().is_err());
        let mut trailing = valid;
        trailing.push(0);
        incoming.borrow_mut().push_back(trailing);
        assert!(server.dispatch_one().is_err());
        assert_eq!(calls.get(), before);
    }
    assert_eq!(calls.get(), 3);
    Ok(())
}

#[test]
fn downstream_can_name_proposals_and_negotiation_results() -> Result<(), NegotiationError> {
    let proposal = KexInit::new([0; 16]);
    let _: NegotiatedAlgorithms = proposal.negotiate(&proposal)?;
    let _client = neotales_ssh::ClientConfig::with_kexinit(proposal.clone());
    let _server = neotales_ssh::ServerConfig::new(neotales_ssh::hostkey::Ed25519Signer::from_seed(
        &mut [1; 32],
    ))
    .with_kexinit(proposal);
    Ok(())
}

#[test]
fn agent_forwarding_is_explicit_default_denied_and_carries_only_opaque_channel_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let incoming = Queue::default();
    let outgoing = Queue::default();
    let mut client = ClientSessions::new(End {
        input: Rc::clone(&outgoing),
        output: Rc::clone(&incoming),
    });
    let mut server = ServerSessions::with_policy(
        End {
            input: incoming,
            output: outgoing,
        },
        |_| SessionDecision::accept(0),
    );
    let session = client.open_session()?;
    let SessionEvent::Opened {
        session: server_session,
    } = server.dispatch_one()?
    else {
        return Err("expected open".into());
    };
    client.dispatch_one()?;
    assert!(server.open_agent_channel(server_session).is_err());
    server
        .connection_mut()
        .open_channel(900, b"auth-agent@openssh.com", &[])?;
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::OpenRejected { .. }
    ));
    server.connection_mut().dispatch_one()?;
    client.request_agent_forwarding(session, true)?;
    assert!(matches!(
        server.dispatch_one()?,
        SessionEvent::AgentForwardingRequested {
            accepted: false,
            ..
        }
    ));
    assert!(matches!(
        client.dispatch_one()?,
        SessionEvent::RequestFailed { .. }
    ));
    assert!(server.open_agent_channel(server_session).is_err());
    server.set_agent_forwarding_policy(|_| true);
    client.request_agent_forwarding(session, true)?;
    assert!(matches!(
        server.dispatch_one()?,
        SessionEvent::AgentForwardingRequested { accepted: true, .. }
    ));
    client.dispatch_one()?;
    let server_agent = server.open_agent_channel(server_session)?;
    let SessionEvent::AgentChannelOpen { request } = client.dispatch_one()? else {
        return Err("expected agent open".into());
    };
    assert_eq!(request.channel_type(), b"auth-agent@openssh.com");
    assert_eq!(request.type_specific_data(), []);
    let client_agent = client.accept_agent_channel(&request)?;
    server.dispatch_one()?;
    server
        .connection_mut()
        .write_data(server_agent, b"opaque\0agent request")?;
    assert!(
        matches!(client.dispatch_one()?, SessionEvent::Data { session, data } if session == client_agent && data == b"opaque\0agent request")
    );
    client.send_data(client_agent, b"opaque response")?;
    assert!(
        matches!(server.dispatch_one()?, SessionEvent::Data { session, data } if session == server_agent && data == b"opaque response")
    );
    Ok(())
}
