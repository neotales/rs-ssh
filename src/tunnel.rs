//! Caller-driven RFC 4254 local and reverse TCP byte tunnels.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use crate::channel::{
    ChannelConnection, ChannelError, ChannelEvent, ChannelId, ChannelOpenRequest, ChannelTransport,
};
use crate::direct_tcpip::{DIRECT_TCPIP_CHANNEL_TYPE, DirectTcpipTuple};
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

/// An explicitly bound reverse listener, accepting one channel per TCP connection.
/// Drop or `cancel` closes the listener and shuts down all its accepted TCP copies.
/// The caller owns returned tunnels and must keep polling/routing them to finish
/// SSH CLOSE (including an open confirmation that arrives after cancellation).
/// Authorization belongs to the caller; no address or wildcard is inferred.
#[derive(Debug)]
pub struct ReverseListener {
    listener: Option<TcpListener>,
    binding: TcpipForwardBinding,
    address: SocketAddr,
    requested_port: u16,
    copies: Vec<Weak<TunnelSocket>>,
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
            copies: Vec::new(),
        })
    }

    /// Returns the actual bound address, including an OS-allocated port.
    ///
    /// # Errors
    /// Returns `NotConnected` after cancellation.
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

    /// Closes the listener and shuts down every accepted TCP copy immediately.
    /// Repeated cancellation is harmless. Poll returned tunnels to send SSH CLOSE.
    pub fn cancel(&mut self) {
        self.listener = None;
        for socket in self.copies.drain(..).filter_map(|copy| copy.upgrade()) {
            socket.cancel();
        }
    }

    /// Answers a dispatched forwarding request only when it exactly matches
    /// this caller-authorized bind. A port-zero reply carries the real port.
    /// Exact `cancel-tcpip-forward` closes the listener and all accepted copies.
    /// Poll returned tunnels to send SSH CLOSE. Returns false for other
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
    /// The listener stays bound for subsequent accepts, including on open errors.
    /// The caller owns the returned copy; listener cancellation also shuts it down.
    ///
    /// # Errors
    /// Returns socket, metadata, channel-limit, or SSH write errors. No retry.
    pub fn poll_accept<T: ChannelTransport>(
        &mut self,
        connection: &mut ChannelConnection<T>,
    ) -> io::Result<Option<TcpTunnel>> {
        let Some((stream, origin)) = self.accept_socket()? else {
            return Ok(None);
        };
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
        Ok(Some(self.track(TcpTunnel::new(stream, channel))))
    }

    fn accept_socket(&self) -> io::Result<Option<(TcpStream, SocketAddr)>> {
        let Some(listener) = &self.listener else {
            return Ok(None);
        };
        match listener.accept() {
            Ok((stream, origin)) => {
                stream.set_nonblocking(true)?;
                Ok(Some((stream, origin)))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn track(&mut self, tunnel: TcpTunnel) -> TcpTunnel {
        // Weak references neither retain finished sockets nor grow across
        // sequential connections. Active count is bounded by SSH channel limits.
        self.copies.retain(|copy| copy.strong_count() != 0);
        self.copies.push(Arc::downgrade(
            tunnel.stream.as_ref().expect("new TCP copy"),
        ));
        tunnel
    }
}

impl Drop for ReverseListener {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// A local (`ssh -L`) listener opening one `direct-tcpip` channel per connection.
/// Only the explicit numeric bind address is used locally. Destination bytes are
/// sent unchanged to the SSH peer; this listener never resolves or dials them.
/// No worker reads SSH: the caller polls accepts and each returned `TcpTunnel`.
/// Drop/cancel closes the listener and shuts down all accepted TCP copies.
#[derive(Debug)]
pub struct LocalListener {
    listener: ReverseListener,
    destination_host: Vec<u8>,
    destination_port: u16,
}

impl LocalListener {
    /// Binds exactly the supplied numeric address (port zero is OS-allocated).
    /// Destination host must be nonempty, at most 255 bytes; port must be nonzero.
    /// Invalid metadata fails before binding. No address inference or retry.
    ///
    /// # Errors
    /// Returns metadata, invalid-input, or socket errors.
    pub fn bind(
        address: &str,
        port: u16,
        destination_host: &[u8],
        destination_port: u16,
    ) -> io::Result<Self> {
        DirectTcpipTuple::new(
            destination_host,
            destination_port,
            address.as_bytes(),
            0_u16,
        )
        .map_err(io::Error::other)?;
        Ok(Self {
            listener: ReverseListener::bind(address, port)?,
            destination_host: destination_host.to_vec(),
            destination_port,
        })
    }

    /// Returns the actual bound address, or `NotConnected` after cancellation.
    ///
    /// # Errors
    /// Returns `NotConnected` if closed.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Closes the listener and shuts down all accepted TCP copies. Idempotent.
    /// Poll returned tunnels to finish SSH CLOSE; this method never writes SSH.
    pub fn cancel(&mut self) {
        self.listener.cancel();
    }

    /// Accepts at most one ready socket and sends one direct-tcpip open with its
    /// real originator address/port. Returns `None` if no socket is ready/closed.
    /// The caller owns the copy and routes dispatched events to it; no data is
    /// read from TCP until SSH confirms the open. A failed open drops that socket
    /// but leaves the listener bound; the operation is not retried.
    ///
    /// # Errors
    /// Returns socket, metadata, channel-limit, or SSH write errors.
    pub fn poll_accept<T: ChannelTransport>(
        &mut self,
        connection: &mut ChannelConnection<T>,
    ) -> io::Result<Option<TcpTunnel>> {
        let Some((stream, origin)) = self.listener.accept_socket()? else {
            return Ok(None);
        };
        let tuple = DirectTcpipTuple::new(
            &self.destination_host,
            self.destination_port,
            origin.ip().to_string().as_bytes(),
            origin.port(),
        )
        .map_err(io::Error::other)?;
        let channel = connection.allocate_channel_id().map_err(channel_error)?;
        connection
            .open_channel_with_limits(
                channel,
                DIRECT_TCPIP_CHANNEL_TYPE.as_bytes(),
                &tuple.encode().map_err(io::Error::other)?,
                WINDOW,
                PACKET,
            )
            .map_err(channel_error)?;
        Ok(Some(self.listener.track(TcpTunnel::new(stream, channel))))
    }
}

#[derive(Debug)]
struct TunnelSocket {
    stream: TcpStream,
    cancelled: AtomicBool,
}

impl TunnelSocket {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
        // Cancellation is best effort at the OS boundary (e.g. both FINs may
        // already have completed). The flag prevents any later copy I/O.
        let _ = self.stream.shutdown(Shutdown::Both);
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
    stream: Option<Arc<TunnelSocket>>,
    channel: ChannelId,
    pending: VecDeque<u8>,
    receive: Receive,
}

impl TcpTunnel {
    fn new(stream: TcpStream, channel: ChannelId) -> Self {
        Self {
            stream: Some(Arc::new(TunnelSocket {
                stream,
                cancelled: AtomicBool::new(false),
            })),
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

    /// Reports TCP completion after CLOSE or explicit/listener cancellation.
    /// Keep routing SSH events after cancellation to close a pending open.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.stream
            .as_ref()
            .is_none_or(|socket| socket.cancelled.load(Ordering::Relaxed))
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
        if self.is_finished() {
            // A cancelled pending open still needs CLOSE after confirmation.
            // Never enqueue late DATA for a socket shut down by its listener.
            self.cancel(connection)?;
            return Ok(matches!(event,
                ChannelEvent::Opened(channel)
                | ChannelEvent::Data { channel, .. }
                | ChannelEvent::Eof { channel }
                | ChannelEvent::Close { channel }
                | ChannelEvent::OpenFailed { channel, .. }
                | ChannelEvent::WindowAdjusted { channel, .. }
                if *channel == self.channel));
        }
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
        let Some(socket) = self
            .stream
            .as_ref()
            .filter(|socket| !socket.cancelled.load(Ordering::Relaxed))
        else {
            self.cancel(connection)?;
            return Ok(());
        };
        let mut stream = &socket.stream;
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

    fn connections() -> (
        ChannelConnection<MemoryTransport>,
        ChannelConnection<MemoryTransport>,
    ) {
        let incoming = Rc::new(RefCell::new(VecDeque::new()));
        let outgoing = Rc::new(RefCell::new(VecDeque::new()));
        (
            ChannelConnection::new(MemoryTransport {
                incoming: incoming.clone(),
                outgoing: outgoing.clone(),
            }),
            ChannelConnection::new(MemoryTransport {
                incoming: outgoing,
                outgoing: incoming,
            }),
        )
    }

    fn pump(
        connection: &mut ChannelConnection<MemoryTransport>,
        copies: &mut [TcpTunnel],
    ) -> Result<(), Box<dyn std::error::Error>> {
        for copy in &mut *copies {
            copy.poll_tcp(connection)?;
        }
        while !connection.transport().incoming.borrow().is_empty() {
            let event = connection.dispatch_one()?;
            let mut handled = 0;
            for copy in &mut *copies {
                handled += usize::from(copy.handle_event(connection, &event)?);
            }
            assert_eq!(handled, 1, "event must belong to exactly one copy");
        }
        Ok(())
    }

    fn read_ready(stream: &mut TcpStream, received: &mut Vec<u8>) -> io::Result<()> {
        let mut buffer = [0; 16];
        match stream.read(&mut buffer) {
            Ok(count) => received.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    // Exact channel routing and dispatch ordering use in-memory SSH payloads;
    // all listening, accepting, copying and cancellation use real loopback TCP.
    #[test]
    fn local_listener_splices_one_byte_each_way() -> Result<(), Box<dyn std::error::Error>> {
        let _serial = crate::test_serial::port_and_spawn();
        let (mut client, mut server) = connections();
        assert!(LocalListener::bind("localhost", 0, b"destination", 80).is_err());
        assert!(LocalListener::bind("", 0, b"destination", 80).is_err());
        assert!(LocalListener::bind("127.0.0.1", 0, b"", 80).is_err());
        assert!(LocalListener::bind("127.0.0.1", 0, b"destination", 0).is_err());
        let mut listener = LocalListener::bind("127.0.0.1", 0, b"destination", 80)?;
        let address = listener.local_addr()?;
        assert!(listener.poll_accept(&mut client)?.is_none());
        assert!(LocalListener::bind("127.0.0.1", address.port(), b"destination", 80).is_err());
        let mut origin = TcpStream::connect(address)?;
        origin.set_nonblocking(true)?;
        let mut copies = [listener.poll_accept(&mut client)?.ok_or("no accept")?];
        origin.write_all(b"l")?;
        copies[0].poll_tcp(&mut client)?;
        let ChannelEvent::OpenRequest(request) = server.dispatch_one()? else {
            return Err("no direct open".into());
        };
        assert_eq!(request.channel_type(), b"direct-tcpip");
        let tuple = DirectTcpipTuple::decode(request.type_specific_data())?;
        assert_eq!(tuple.destination_host(), b"destination");
        assert_eq!(tuple.destination_port(), 80);
        assert_eq!(tuple.originator_address(), b"127.0.0.1");
        assert_eq!(
            tuple.originator_port(),
            u32::from(origin.local_addr()?.port())
        );
        // No bytes are sent before confirmation, even if TCP data is ready.
        assert_eq!(server.transport().incoming.borrow().len(), 0);
        let remote = server.allocate_channel_id()?;
        server.confirm_open_with_limits(request.sender_channel(), remote, WINDOW, PACKET)?;
        server.write_data(remote, b"r")?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut received_origin = Vec::new();
        let mut received_remote = Vec::new();
        while received_origin.is_empty() || received_remote.is_empty() {
            assert!(Instant::now() < deadline, "local tunnel stalled");
            pump(&mut client, &mut copies)?;
            while !server.transport().incoming.borrow().is_empty() {
                match server.dispatch_one()? {
                    ChannelEvent::Data { channel, data } => {
                        assert_eq!(channel, remote);
                        received_remote.extend(data);
                    }
                    ChannelEvent::WindowAdjusted { .. } => {}
                    event => panic!("unexpected event {event:?}"),
                }
            }
            read_ready(&mut origin, &mut received_origin)?;
            std::thread::yield_now();
        }
        assert_eq!(received_origin, b"r");
        assert_eq!(received_remote, b"l");
        drop(listener);
        assert!(TcpStream::connect(address).is_err());
        assert!(copies[0].is_finished());
        pump(&mut client, &mut copies)?;
        assert!(
            matches!(server.dispatch_one()?, ChannelEvent::Close { channel } if channel == remote)
        );
        origin.set_nonblocking(false)?;
        origin.set_read_timeout(Some(Duration::from_secs(3)))?;
        assert_eq!(origin.read(&mut [0])?, 0);
        Ok(())
    }

    #[test]
    fn reverse_two_connections_copy_independently_and_cancel_or_drop_closes_both()
    -> Result<(), Box<dyn std::error::Error>> {
        let _serial = crate::test_serial::port_and_spawn();
        for cancel in [false, true] {
            let (mut server, mut client) = connections();
            let mut listener = ReverseListener::bind("127.0.0.1", 0)?;
            let address = listener.local_addr()?;
            let binding = listener.binding().clone();
            let destination = TcpListener::bind(("127.0.0.1", 0))?;
            let mut origins = Vec::new();
            let mut locals = Vec::new();
            let mut server_copies = Vec::new();
            let mut client_copies = Vec::new();
            for _ in 0..2 {
                let origin = TcpStream::connect(address)?;
                origin.set_nonblocking(true)?;
                origins.push(origin);
                server_copies.push(listener.poll_accept(&mut server)?.ok_or("no accept")?);
                let ChannelEvent::OpenRequest(request) = client.dispatch_one()? else {
                    return Err("no forwarded open".into());
                };
                assert_eq!(request.channel_type(), b"forwarded-tcpip");
                client_copies.push(TcpTunnel::connect(
                    &mut client,
                    &request,
                    &binding,
                    destination.local_addr()?,
                )?);
                let (local, _) = destination.accept()?;
                local.set_nonblocking(true)?;
                locals.push(local);
            }
            assert_ne!(server_copies[0].channel, server_copies[1].channel);
            assert_ne!(client_copies[0].channel, client_copies[1].channel);
            assert_eq!(listener.local_addr()?, address);
            assert!(listener.poll_accept(&mut server)?.is_none());
            // Opposite order in the two directions catches cross-copy routing.
            origins[0].write_all(b"a")?;
            origins[1].write_all(b"b")?;
            locals[1].write_all(b"y")?;
            locals[0].write_all(b"x")?;
            let mut at_origin = [Vec::new(), Vec::new()];
            let mut at_local = [Vec::new(), Vec::new()];
            let deadline = Instant::now() + Duration::from_secs(3);
            while at_origin.iter().chain(&at_local).any(Vec::is_empty) {
                assert!(Instant::now() < deadline, "two reverse copies stalled");
                pump(&mut server, &mut server_copies)?;
                pump(&mut client, &mut client_copies)?;
                for i in 0..2 {
                    read_ready(&mut origins[i], &mut at_origin[i])?;
                    read_ready(&mut locals[i], &mut at_local[i])?;
                }
                std::thread::yield_now();
            }
            assert_eq!(at_origin, [b"x".to_vec(), b"y".to_vec()]);
            assert_eq!(at_local, [b"a".to_vec(), b"b".to_vec()]);
            if cancel {
                let event = ChannelEvent::GlobalRequest {
                    request_name: CANCEL_TCPIP_FORWARD_REQUEST.as_bytes().to_vec(),
                    want_reply: false,
                    data: binding.encode()?,
                };
                assert!(listener.handle_request(&mut server, &event)?);
                listener.cancel(); // repeated cancellation is harmless
            }
            drop(listener);
            assert!(TcpStream::connect(address).is_err());
            assert!(server_copies.iter().all(TcpTunnel::is_finished));
            // Polling, not cancellation/drop, writes SSH CLOSE for both copies.
            pump(&mut server, &mut server_copies)?;
            pump(&mut client, &mut client_copies)?;
            pump(&mut server, &mut server_copies)?;
            assert!(client_copies.iter().all(TcpTunnel::is_finished));
            assert_eq!(server.channel_count(), 0);
            assert_eq!(client.channel_count(), 0);
            for mut stream in origins.into_iter().chain(locals) {
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                assert_eq!(stream.read(&mut [0])?, 0);
            }
        }
        Ok(())
    }

    #[test]
    fn local_cancel_before_confirmation_closes_late_open() -> Result<(), Box<dyn std::error::Error>>
    {
        let _serial = crate::test_serial::port_and_spawn();
        let (mut client, mut server) = connections();
        let mut listener = LocalListener::bind("127.0.0.1", 0, b"destination", 80)?;
        let address = listener.local_addr()?;
        let mut origin = TcpStream::connect(address)?;
        origin.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut copies = [listener.poll_accept(&mut client)?.ok_or("no accept")?];
        listener.cancel();
        listener.cancel();
        assert!(listener.local_addr().is_err());
        assert!(listener.poll_accept(&mut client)?.is_none());
        assert!(TcpStream::connect(address).is_err());
        assert!(copies[0].is_finished());
        assert_eq!(origin.read(&mut [0])?, 0);
        pump(&mut client, &mut copies)?;
        let ChannelEvent::OpenRequest(request) = server.dispatch_one()? else {
            return Err("no direct open".into());
        };
        let remote = server.allocate_channel_id()?;
        server.confirm_open(request.sender_channel(), remote)?;
        pump(&mut client, &mut copies)?;
        assert!(
            matches!(server.dispatch_one()?, ChannelEvent::Close { channel } if channel == remote)
        );
        server.send_close(remote)?;
        pump(&mut client, &mut copies)?;
        assert_eq!(client.channel_count(), 0);
        Ok(())
    }

    #[test]
    fn reverse_listener_accepts_two_connections() -> Result<(), Box<dyn std::error::Error>> {
        let _serial = crate::test_serial::port_and_spawn();
        let queue = Rc::new(RefCell::new(VecDeque::new()));
        let mut connection = ChannelConnection::new(MemoryTransport {
            incoming: queue.clone(),
            outgoing: queue,
        });
        let mut listener = ReverseListener::bind("127.0.0.1", 0)?;
        let address = listener.local_addr()?;
        let _first = TcpStream::connect(address)?;
        let _first_copy = listener
            .poll_accept(&mut connection)?
            .ok_or("no first accept")?;
        assert_eq!(listener.local_addr()?, address);
        let _second = TcpStream::connect(address)?;
        let _second_copy = listener
            .poll_accept(&mut connection)?
            .ok_or("no second accept")?;
        Ok(())
    }

    #[test]
    fn explicit_bind_cancel_and_drop_release_the_port() -> io::Result<()> {
        let _serial = crate::test_serial::port_and_spawn();
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
        let _serial = crate::test_serial::port_and_spawn();
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
        let _serial = crate::test_serial::port_and_spawn();
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
