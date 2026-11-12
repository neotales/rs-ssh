//! One-connection RFC 4254 reverse TCP byte tunnel.
//!
//! The caller owns the synchronous SSH dispatcher. Repeatedly call
//! [`TcpTunnel::poll_tcp`] and route dispatched events to
//! [`TcpTunnel::handle_event`]. Only call `dispatch_one` when a complete SSH
//! payload is ready; blocking there while TCP needs service deadlocks a copy.
//! This module never reads the SSH stream, starts threads, or retries a bind.
//! SSH writes retain the transport's synchronous blocking semantics.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};

use crate::channel::{
    ChannelConnection, ChannelError, ChannelEvent, ChannelId, ChannelOpenRequest, ChannelTransport,
};
use crate::tcpip_forward::{
    CANCEL_TCPIP_FORWARD_REQUEST, FORWARDED_TCPIP_CHANNEL_TYPE, ForwardedTcpipTuple,
    TCPIP_FORWARD_REQUEST, TcpipForwardBinding, TcpipForwardError, TcpipForwardResponse,
};

const WINDOW: u32 = 32_768;
const PACKET: u32 = 16_384;

fn channel_error(error: ChannelError) -> io::Error {
    io::Error::other(error)
}
fn protocol_error(error: TcpipForwardError) -> io::Error {
    io::Error::other(error)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// An explicitly bound, one-shot reverse listener. Drop or `cancel` closes it.
/// Authorization belongs to the caller; no address or wildcard is inferred.
#[derive(Debug)]
pub struct ReverseListener {
    listener: Option<TcpListener>,
    binding: TcpipForwardBinding,
    address: SocketAddr,
    requested_port: u16,
}

impl ReverseListener {
    /// Binds exactly the supplied numeric IP address and port, without retries.
    /// Port zero asks the OS for a port. Empty addresses and hostnames are errors.
    ///
    /// # Errors
    /// Returns invalid-input or socket errors; failure leaves no listener.
    pub fn bind(address: &str, port: u16) -> io::Result<Self> {
        let ip = address
            .parse()
            .map_err(|_| invalid("a numeric bind address is required"))?;
        let listener = TcpListener::bind(SocketAddr::new(ip, port))?;
        listener.set_nonblocking(true)?;
        let local = listener.local_addr()?;
        Ok(Self {
            listener: Some(listener),
            binding: TcpipForwardBinding::new(address.as_bytes(), local.port())
                .map_err(protocol_error)?,
            address: local,
            requested_port: port,
        })
    }

    /// Returns the actual bound address, including an OS-allocated port.
    ///
    /// # Errors
    /// Returns `NotConnected` after cancellation or acceptance.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "listener closed"))?;
        Ok(self.address)
    }

    /// Returns exact caller address bytes and the actual listening port.
    #[must_use]
    pub const fn binding(&self) -> &TcpipForwardBinding {
        &self.binding
    }

    /// Closes the listener immediately. Repeated cancellation is harmless.
    pub fn cancel(&mut self) {
        self.listener = None;
    }

    /// Answers a dispatched forwarding request only when it exactly matches
    /// this caller-authorized bind. A port-zero reply carries the real port.
    /// Exact `cancel-tcpip-forward` closes the listener, not an accepted copy;
    /// cancel that separately with `TcpTunnel::cancel`. Returns false for other
    /// events. No request can cause a new bind or widen the supplied address.
    ///
    /// # Errors
    /// Returns malformed-request or SSH write errors. Cancellation is not
    /// rolled back if sending its reply fails.
    pub fn handle_request<T: ChannelTransport>(
        &mut self,
        connection: &mut ChannelConnection<T>,
        event: &ChannelEvent,
    ) -> io::Result<bool> {
        let ChannelEvent::GlobalRequest {
            request_name,
            want_reply,
            data,
        } = event
        else {
            return Ok(false);
        };
        let forward = request_name == TCPIP_FORWARD_REQUEST.as_bytes();
        let cancel = request_name == CANCEL_TCPIP_FORWARD_REQUEST.as_bytes();
        if !forward && !cancel {
            return Ok(false);
        }
        let request = TcpipForwardBinding::decode(data).map_err(protocol_error)?;
        let expected_port = if forward {
            u32::from(self.requested_port)
        } else {
            self.binding.port()
        };
        let accepted = request.bind_address() == self.binding.bind_address()
            && request.port() == expected_port
            && (cancel || self.listener.is_some());
        if accepted && cancel {
            self.cancel();
        }
        if *want_reply {
            let response = if !accepted {
                TcpipForwardResponse::Failure
            } else if forward && self.requested_port == 0 {
                TcpipForwardResponse::AllocatedPort(self.binding.port())
            } else {
                TcpipForwardResponse::Success
            };
            connection
                .transport_mut()
                .write_channel_payload(&response.encode().map_err(protocol_error)?)
                .map_err(|()| channel_error(ChannelError::Transport))?;
        }
        Ok(true)
    }

    /// Accepts at most one socket and opens one `forwarded-tcpip` channel.
    /// Returns `None` when no socket is ready or the listener is closed.
    /// Acceptance closes this one-shot listener, including on an open error.
    ///
    /// # Errors
    /// Returns socket, metadata, channel-limit, or SSH write errors. No retry.
    pub fn poll_accept<T: ChannelTransport>(
        &mut self,
        connection: &mut ChannelConnection<T>,
    ) -> io::Result<Option<TcpTunnel>> {
        let Some(listener) = &self.listener else {
            return Ok(None);
        };
        let (stream, origin) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error),
        };
        self.cancel();
        stream.set_nonblocking(true)?;
        let tuple = ForwardedTcpipTuple::new(
            self.binding.bind_address(),
            self.binding.port(),
            origin.ip().to_string().as_bytes(),
            origin.port(),
        )
        .map_err(protocol_error)?;
        let channel = connection.allocate_channel_id().map_err(channel_error)?;
        connection
            .open_channel_with_limits(
                channel,
                FORWARDED_TCPIP_CHANNEL_TYPE.as_bytes(),
                &tuple.encode().map_err(protocol_error)?,
                WINDOW,
                PACKET,
            )
            .map_err(channel_error)?;
        Ok(Some(TcpTunnel::new(stream, channel)))
    }
}

#[derive(Debug, PartialEq)]
enum Receive {
    Open,
    Eof,
    Shutdown,
}

/// Bounded nonblocking TCP side of one existing SSH channel.
/// Drop closes TCP; use `cancel` to also send SSH CLOSE. No worker survives it.
#[derive(Debug)]
pub struct TcpTunnel {
    stream: Option<TcpStream>,
    channel: ChannelId,
    pending: VecDeque<u8>,
    receive: Receive,
}

impl TcpTunnel {
    fn new(stream: TcpStream, channel: ChannelId) -> Self {
        Self {
            stream: Some(stream),
            channel,
            pending: VecDeque::new(),
            receive: Receive::Open,
        }
    }

    /// Accepts only an exact authorized binding and dials the caller's local
    /// destination (never an address supplied by the SSH peer). Connect blocks
    /// for at most three seconds; copying thereafter is nonblocking on TCP.
    /// The caller must reject the pending open if this method fails.
    ///
    /// # Errors
    /// Returns invalid metadata/binding, dial, or SSH confirmation errors.
    pub fn connect<T: ChannelTransport>(
        connection: &mut ChannelConnection<T>,
        request: &ChannelOpenRequest,
        binding: &TcpipForwardBinding,
        destination: SocketAddr,
    ) -> io::Result<Self> {
        if request.channel_type() != FORWARDED_TCPIP_CHANNEL_TYPE.as_bytes() {
            return Err(invalid("not a forwarded TCP channel"));
        }
        let tuple =
            ForwardedTcpipTuple::decode(request.type_specific_data()).map_err(protocol_error)?;
        if binding.bind_address().is_empty()
            || tuple.connected_address() != binding.bind_address()
            || tuple.connected_port() != binding.port()
        {
            return Err(invalid(
                "forwarded channel does not match authorized binding",
            ));
        }
        let stream = TcpStream::connect_timeout(&destination, std::time::Duration::from_secs(3))?;
        stream.set_nonblocking(true)?;
        let channel = connection.allocate_channel_id().map_err(channel_error)?;
        connection
            .confirm_open_with_limits(request.sender_channel(), channel, WINDOW, PACKET)
            .map_err(channel_error)?;
        Ok(Self::new(stream, channel))
    }

    /// Reports completion after CLOSE or explicit cancellation.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.stream.is_none()
    }

    /// Closes TCP immediately and sends CLOSE if the channel is established.
    /// May discard buffered data. Repeated cancellation is harmless.
    ///
    /// # Errors
    /// Returns an SSH write error after closing TCP (no rollback).
    pub fn cancel<T: ChannelTransport>(
        &mut self,
        connection: &mut ChannelConnection<T>,
    ) -> io::Result<()> {
        self.stream = None;
        self.pending.clear();
        if let Some(state) = connection.channel(self.channel)
            && state.remote_id().is_some()
            && !state.local_close_sent()
        {
            connection.send_close(self.channel).map_err(channel_error)?;
        }
        Ok(())
    }

    /// Routes one already-dispatched event; returns false for unrelated events.
    /// Receive credit is replenished only after bytes reach TCP. Buffering is
    /// bounded by the advertised window. EOF preserves the opposite direction.
    ///
    /// # Errors
    /// Returns socket or SSH errors. The caller must cancel/drop on failure.
    pub fn handle_event<T: ChannelTransport>(
        &mut self,
        connection: &mut ChannelConnection<T>,
        event: &ChannelEvent,
    ) -> io::Result<bool> {
        match event {
            ChannelEvent::Data { channel, data } if *channel == self.channel => {
                if self.pending.len() + data.len() > WINDOW as usize {
                    return Err(invalid("tunnel receive window exceeded"));
                }
                self.pending.extend(data);
            }
            ChannelEvent::Eof { channel } | ChannelEvent::Close { channel }
                if *channel == self.channel =>
            {
                if self.receive == Receive::Open {
                    self.receive = Receive::Eof;
                }
            }
            ChannelEvent::Opened(channel) if *channel == self.channel => {
                if self.is_finished() {
                    self.cancel(connection)?;
                }
            }
            ChannelEvent::WindowAdjusted { channel, .. } if *channel == self.channel => {}
            ChannelEvent::OpenFailed { channel, .. } if *channel == self.channel => {
                self.stream = None;
            }
            _ => return Ok(false),
        }
        self.poll_tcp(connection)?;
        Ok(true)
    }

    /// Advances both TCP directions once without blocking on TCP or reading SSH.
    /// Call regularly, including while no SSH event is ready. Honors the existing
    /// channel window and maximum packet size. SSH writes can still block.
    ///
    /// # Errors
    /// Returns socket or channel errors; partial delivery is possible. Cancel or
    /// drop on error rather than retrying a failed SSH write.
    pub fn poll_tcp<T: ChannelTransport>(
        &mut self,
        connection: &mut ChannelConnection<T>,
    ) -> io::Result<()> {
        let Some(stream) = &mut self.stream else {
            return Ok(());
        };
        if !self.pending.is_empty() {
            match stream.write(self.pending.as_slices().0) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "tunnel TCP write stopped",
                    ));
                }
                Ok(count) => {
                    self.pending.drain(..count);
                    if connection.channel(self.channel).is_some_and(|state| {
                        !state.local_close_sent() && !state.remote_close_received()
                    }) {
                        connection
                            .increase_local_window(
                                self.channel,
                                u32::try_from(count).map_err(|_| invalid("window overflow"))?,
                            )
                            .map_err(channel_error)?;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        if self.pending.is_empty() && self.receive == Receive::Eof {
            match stream.shutdown(Shutdown::Write) {
                Ok(()) => {}
                // Both FINs can complete before the dispatched SSH EOF is
                // serviced. TCP is already shut down in that case.
                Err(error) if error.kind() == io::ErrorKind::NotConnected => {}
                Err(error) => return Err(error),
            }
            self.receive = Receive::Shutdown;
        }
        let Some(state) = connection.channel(self.channel) else {
            if self.pending.is_empty() {
                self.stream = None;
            }
            return Ok(());
        };
        if state.remote_close_received() {
            if self.pending.is_empty() {
                if !state.local_close_sent() {
                    connection.send_close(self.channel).map_err(channel_error)?;
                }
                self.stream = None;
            }
            return Ok(());
        }
        if state.remote_id().is_none() || state.local_close_sent() {
            return Ok(());
        }
        if !state.local_eof_sent() && state.remote_window() > 0 {
            let mut buffer = [0; PACKET as usize];
            let limit = buffer
                .len()
                .min(state.remote_window() as usize)
                .min(state.remote_maximum_packet_size() as usize);
            match stream.read(&mut buffer[..limit]) {
                Ok(0) => connection.send_eof(self.channel).map_err(channel_error)?,
                Ok(count) => {
                    connection
                        .write_data(self.channel, &buffer[..count])
                        .map_err(channel_error)?;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        if self.receive == Receive::Shutdown
            && connection
                .channel(self.channel)
                .is_some_and(|state| state.local_eof_sent())
        {
            connection.send_close(self.channel).map_err(channel_error)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    #[derive(Clone)]
    struct MemoryTransport {
        incoming: Rc<RefCell<VecDeque<Vec<u8>>>>,
        outgoing: Rc<RefCell<VecDeque<Vec<u8>>>>,
    }

    impl ChannelTransport for MemoryTransport {
        fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
            self.outgoing.borrow_mut().push_back(payload.to_vec());
            Ok(())
        }

        fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
            self.incoming.borrow_mut().pop_front().ok_or(())
        }
    }

    #[test]
    fn explicit_bind_cancel_and_drop_release_the_port() -> io::Result<()> {
        assert_eq!(
            ReverseListener::bind("", 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let mut listener = ReverseListener::bind("127.0.0.1", 0)?;
        let address = listener.local_addr()?;
        assert_eq!(
            address.ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_ne!(address.port(), 0);
        assert!(TcpListener::bind(address).is_err());
        listener.cancel();
        listener.cancel();
        let rebound = ReverseListener::bind("127.0.0.1", address.port())?;
        drop(rebound);
        drop(TcpListener::bind(address)?);
        Ok(())
    }

    #[test]
    fn wire_cancel_requires_exact_binding() -> Result<(), Box<dyn std::error::Error>> {
        let queue = Rc::new(RefCell::new(VecDeque::new()));
        let mut connection = ChannelConnection::new(MemoryTransport {
            incoming: queue.clone(),
            outgoing: queue,
        });
        let mut listener = ReverseListener::bind("127.0.0.1", 0)?;
        let address = listener.local_addr()?;
        let event = |host: &[u8]| -> Result<ChannelEvent, TcpipForwardError> {
            Ok(ChannelEvent::GlobalRequest {
                request_name: CANCEL_TCPIP_FORWARD_REQUEST.as_bytes().to_vec(),
                want_reply: true,
                data: TcpipForwardBinding::new(host, address.port())?.encode()?,
            })
        };
        assert!(listener.handle_request(&mut connection, &event(b"0.0.0.0")?)?);
        assert_eq!(listener.local_addr()?, address);
        assert!(matches!(
            connection.dispatch_one()?,
            ChannelEvent::GlobalRequestFailed { .. }
        ));
        assert!(listener.handle_request(&mut connection, &event(b"127.0.0.1")?)?);
        assert!(matches!(
            connection.dispatch_one()?,
            ChannelEvent::GlobalRequestSucceeded { .. }
        ));
        assert!(listener.local_addr().is_err());
        drop(TcpListener::bind(address)?);
        Ok(())
    }

    // Exact byte and window/EOF assertions need control of dispatch ordering;
    // the TCP listener and destination are real loopback sockets, not mocks.
    #[test]
    fn one_byte_each_way() -> Result<(), Box<dyn std::error::Error>> {
        let incoming = Rc::new(RefCell::new(VecDeque::new()));
        let outgoing = Rc::new(RefCell::new(VecDeque::new()));
        let mut server = ChannelConnection::new(MemoryTransport {
            incoming: incoming.clone(),
            outgoing: outgoing.clone(),
        });
        let mut client = ChannelConnection::new(MemoryTransport {
            incoming: outgoing,
            outgoing: incoming,
        });
        let mut listener = ReverseListener::bind("127.0.0.1", 0)?;
        let request =
            crate::tcpip_forward::TcpipForwardGlobalRequest::tcpip_forward(b"127.0.0.1", 0, true)?
                .encode()?;
        client
            .transport_mut()
            .write_channel_payload(&request)
            .map_err(|()| "request write failed")?;
        let event = server.dispatch_one()?;
        assert!(listener.handle_request(&mut server, &event)?);
        assert!(
            matches!(client.dispatch_one()?, ChannelEvent::GlobalRequestSucceeded { data }
            if data == listener.binding().port().to_be_bytes())
        );
        let binding = listener.binding().clone();
        let destination = TcpListener::bind(("127.0.0.1", 0))?;
        let mut origin = TcpStream::connect(listener.local_addr()?)?;
        origin.set_nonblocking(true)?;
        // The originator sends nothing until the destination has spoken. A
        // blocking TCP-read-first pump deadlocks here.
        let mut server_copy = listener.poll_accept(&mut server)?.ok_or("no accept")?;
        let ChannelEvent::OpenRequest(request) = client.dispatch_one()? else {
            return Err("no forwarded open".into());
        };
        let mut client_copy =
            TcpTunnel::connect(&mut client, &request, &binding, destination.local_addr()?)?;
        let (mut local, _) = destination.accept()?;
        local.set_nonblocking(true)?;
        local.write_all(b"s")?;
        local.shutdown(Shutdown::Write)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut received_origin = Vec::new();
        let mut received_local = Vec::new();
        let mut replied = false;
        loop {
            assert!(Instant::now() < deadline, "tunnel stalled");
            server_copy.poll_tcp(&mut server)?;
            client_copy.poll_tcp(&mut client)?;
            while !server.transport().incoming.borrow().is_empty() {
                let event = server.dispatch_one()?;
                assert!(server_copy.handle_event(&mut server, &event)?);
            }
            while !client.transport().incoming.borrow().is_empty() {
                let event = client.dispatch_one()?;
                assert!(client_copy.handle_event(&mut client, &event)?);
            }
            let mut byte = [0];
            match origin.read(&mut byte) {
                Ok(1) => received_origin.push(byte[0]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Ok(_) => {}
                Err(error) => return Err(error.into()),
            }
            if received_origin == b"s" && !replied {
                origin.write_all(b"c")?;
                origin.shutdown(Shutdown::Write)?;
                replied = true;
            }
            match local.read(&mut byte) {
                Ok(1) => received_local.push(byte[0]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Ok(_) => {}
                Err(error) => return Err(error.into()),
            }
            if server_copy.is_finished() && client_copy.is_finished() {
                break;
            }
            std::thread::yield_now();
        }
        assert_eq!(received_origin, b"s");
        assert_eq!(received_local, b"c");
        assert_eq!(server.channel_count(), 0);
        assert_eq!(client.channel_count(), 0);
        Ok(())
    }
}
