//! RFC 4254 connection-level channel multiplexing and flow control.
//!
//! [`ChannelConnection`] owns exactly one authenticated packet transport and
//! serializes every channel write through that value. It does not buffer
//! channel data: each call to [`ChannelConnection::dispatch_one`] reads one
//! transport payload, validates it completely, accounts any received window
//! credit, and returns one bounded event to the caller.
//!
//! # Connection-level messages
//!
//! A channel multiplexer is not the only thing on an authenticated
//! connection, and RFC 4254 §4 says so of global requests: "both the client
//! and server MAY send global requests at any time, and the receiver MUST
//! respond appropriately". [`ChannelConnection::dispatch_one`] therefore
//! tolerates the message numbers that are legal at any time on an
//! established connection and routes each one to the treatment RFC 4253 §11
//! and RFC 4254 §4 give it. See [`ChannelConnection::dispatch_one`] for the
//! exact split, because which of the three it is — handled, dropped, or
//! surfaced — is a contract and not an implementation detail.
//!
//! A current OpenSSH server sends `SSH_MSG_GLOBAL_REQUEST`
//! `hostkeys-00@openssh.com` as the very first payload after
//! `SSH_MSG_USERAUTH_SUCCESS`, ahead of anything the client asked for. A
//! multiplexer that treats that as fatal cannot open a channel against a
//! current OpenSSH at all.

use std::collections::VecDeque;
use std::fmt;
use std::io::{Read, Write};

use neotales_ssh::{Error as WireError, MAX_PACKET_CONTENT, MIN_PADDING, Reader, Writer};

use crate::cipher::AES_BLOCK_SIZE;
use crate::client::ClientTransport;
use crate::server::ServerTransport;
use crate::transport::{ObligationId, OwnedInbound, OwnedPacketId, TransportError};

#[cfg(test)]
#[path = "channel_owned_tests.rs"]
mod owned_tests;

/// SSH message number for `SSH_MSG_CHANNEL_OPEN`.
pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
/// SSH message number for `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`.
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
/// SSH message number for `SSH_MSG_CHANNEL_OPEN_FAILURE`.
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
/// SSH message number for `SSH_MSG_CHANNEL_WINDOW_ADJUST`.
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
/// SSH message number for `SSH_MSG_CHANNEL_DATA`.
pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
/// SSH message number for `SSH_MSG_CHANNEL_EXTENDED_DATA`.
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
/// SSH message number for `SSH_MSG_CHANNEL_EOF`.
pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
/// SSH message number for `SSH_MSG_CHANNEL_CLOSE`.
pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
/// SSH message number for `SSH_MSG_CHANNEL_REQUEST`.
pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
/// SSH message number for `SSH_MSG_CHANNEL_SUCCESS`.
pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
/// SSH message number for `SSH_MSG_CHANNEL_FAILURE`.
pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

// The transport-layer and connection-layer message numbers below are the ones
// RFC 4253 §12 and RFC 4254 §9 assign. They are declared here rather than
// imported so that a multiplexer built on this type does not have to reach
// through the handshake's private sequence layer for values this file has to
// recognise on every packet.

/// `SSH_MSG_IGNORE`, RFC 4253 §11.2.
pub const SSH_MSG_IGNORE: u8 = 2;
/// `SSH_MSG_UNIMPLEMENTED`, RFC 4253 §11.4.
pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
/// `SSH_MSG_DEBUG`, RFC 4253 §11.3.
pub const SSH_MSG_DEBUG: u8 = 4;
/// `SSH_MSG_GLOBAL_REQUEST`, RFC 4254 §4.
pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
/// `SSH_MSG_REQUEST_SUCCESS`, RFC 4254 §4.
pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
/// `SSH_MSG_REQUEST_FAILURE`, RFC 4254 §4.
pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;

/// The local receive window advertised by default for every channel.
pub const INITIAL_CHANNEL_WINDOW: u32 = 65_536;
/// The largest channel-data payload advertised by default.
pub const MAX_CHANNEL_PACKET_SIZE: u32 = 32_768;
const MAX_CHANNEL_PADDING_SIZE: usize = AES_BLOCK_SIZE + MIN_PADDING - 1;
const MAX_DEFLATE_OVERHEAD: usize =
    MAX_PACKET_CONTENT / 4_096 + MAX_PACKET_CONTENT / 16_384 + MAX_PACKET_CONTENT / 33_554_432 + 13;
const MAX_CHANNEL_MESSAGE_SIZE: usize =
    MAX_PACKET_CONTENT - MAX_CHANNEL_PADDING_SIZE - MAX_DEFLATE_OVERHEAD;
/// The largest channel-data payload this implementation can safely frame.
///
/// The bound leaves room for extended-data message fields, the largest padding
/// used by supported packet ciphers, and zlib's worst-case expansion at the
/// transport payload limit. The compression allowance is calculated at the
/// full transport limit, leaving two bytes of additional headroom at this cap.
pub const MAX_CHANNEL_DATA_SIZE: usize = MAX_CHANNEL_MESSAGE_SIZE - 13;
/// The maximum number of live or pending channels retained by one connection.
pub const MAX_CHANNELS_PER_CONNECTION: usize = 1_024;
/// The maximum encoded length accepted for a channel type or request name.
pub const MAX_CHANNEL_NAME_LENGTH: usize = 256;

/// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`.
pub const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
/// `SSH_OPEN_CONNECT_FAILED`.
pub const SSH_OPEN_CONNECT_FAILED: u32 = 2;
/// `SSH_OPEN_UNKNOWN_CHANNEL_TYPE`.
pub const SSH_OPEN_UNKNOWN_CHANNEL_TYPE: u32 = 3;
/// `SSH_OPEN_RESOURCE_SHORTAGE`.
pub const SSH_OPEN_RESOURCE_SHORTAGE: u32 = 4;

/// An RFC 4254 channel identifier local to one side of a connection.
pub type ChannelId = u32;

/// A bounded channel-window failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowError {
    /// A complete data write did not fit in the peer's remaining credit.
    Insufficient {
        /// Credit still available to the sender.
        available: u32,
        /// Number of data bytes the caller attempted to write.
        requested: usize,
    },
    /// A window adjustment would exceed the RFC 4254 `uint32` range.
    AdjustmentOverflow {
        /// Current local or remote window before the rejected adjustment.
        current: u32,
        /// Increment in the rejected adjustment.
        increment: u32,
    },
}

impl fmt::Display for WindowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insufficient {
                available,
                requested,
            } => write!(
                formatter,
                "channel data requires {requested} bytes but only {available} bytes of window remain"
            ),
            Self::AdjustmentOverflow { current, increment } => write!(
                formatter,
                "channel window adjustment {current} + {increment} overflows u32"
            ),
        }
    }
}

impl std::error::Error for WindowError {}

/// A bounded channel protocol or transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelError {
    /// An SSH primitive was malformed or truncated.
    Wire(WireError),
    /// The underlying protected transport failed.
    Transport,
    /// A channel packet was structurally invalid for an open channel.
    InvalidMessage,
    /// A channel-open advertisement was invalid.
    InvalidOpen,
    /// A zero window adjustment was supplied.
    InvalidWindowAdjustment,
    /// The requested recipient channel is unknown.
    UnknownChannel,
    /// A local or remote channel identifier is already active.
    DuplicateChannel,
    /// The bounded per-connection channel count was exhausted.
    TooManyChannels,
    /// No unused local channel identifier remains.
    ChannelIdExhausted,
    /// A message type is not valid at this layer or channel state.
    UnexpectedMessage(u8),
    /// Data was received after the peer's EOF.
    DataAfterEof,
    /// Flow-control accounting failed.
    Window(WindowError),
    /// Received data exceeded the recipient's advertised local window.
    WindowExceeded {
        /// Local credit available before this packet.
        available: u32,
        /// Data bytes carried by the rejected packet.
        received: usize,
    },
    /// A data write exceeded the effective maximum data size for that channel.
    PacketTooLarge {
        /// Maximum data bytes permitted in this channel packet.
        maximum: u32,
        /// Data bytes the caller attempted to write.
        requested: usize,
    },
    /// A complete encoded channel message exceeded the transport bound.
    MessageTooLarge,
    /// A channel message named a channel that both sides had already closed.
    ///
    /// RFC 4254 §5.3: "The channel is considered closed for a party when it
    /// has both sent and received `SSH_MSG_CHANNEL_CLOSE`". Once that is true
    /// the channel is gone from the table, and OpenSSH disconnects on a
    /// message for a channel it no longer has — `channel_from_packet_id`
    /// calls `ssh_packet_disconnect(ssh, "%s packet referred to nonexistent
    /// channel %d")`. This error is that condition, reported without the
    /// disconnect so a caller can decide.
    ClosedChannel(ChannelId),
}

impl fmt::Display for ChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "SSH channel wire error: {error}"),
            Self::Transport => formatter.write_str("SSH channel transport failed"),
            Self::InvalidMessage => formatter.write_str("SSH channel message is invalid"),
            Self::InvalidOpen => formatter.write_str("SSH channel-open message is invalid"),
            Self::InvalidWindowAdjustment => {
                formatter.write_str("SSH channel window adjustment must be nonzero")
            }
            Self::UnknownChannel => formatter.write_str("SSH channel identifier is unknown"),
            Self::DuplicateChannel => {
                formatter.write_str("SSH channel identifier is already active")
            }
            Self::TooManyChannels => {
                formatter.write_str("SSH connection channel limit was exhausted")
            }
            Self::ChannelIdExhausted => {
                formatter.write_str("SSH local channel identifiers were exhausted")
            }
            Self::UnexpectedMessage(message) => {
                write!(
                    formatter,
                    "SSH channel received unexpected message {message}"
                )
            }
            Self::DataAfterEof => formatter.write_str("SSH channel data arrived after peer EOF"),
            Self::Window(error) => write!(formatter, "SSH channel window error: {error}"),
            Self::WindowExceeded {
                available,
                received,
            } => write!(
                formatter,
                "SSH channel received {received} bytes with only {available} bytes of local window"
            ),
            Self::PacketTooLarge { maximum, requested } => write!(
                formatter,
                "SSH channel data requires {requested} bytes but the peer maximum is {maximum}"
            ),
            Self::MessageTooLarge => {
                formatter.write_str("SSH channel message exceeds the transport limit")
            }
            Self::ClosedChannel(channel) => write!(
                formatter,
                "SSH channel {channel} was addressed after both sides closed it"
            ),
        }
    }
}

impl std::error::Error for ChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Transport
            | Self::InvalidMessage
            | Self::InvalidOpen
            | Self::InvalidWindowAdjustment
            | Self::UnknownChannel
            | Self::DuplicateChannel
            | Self::TooManyChannels
            | Self::ChannelIdExhausted
            | Self::UnexpectedMessage(_)
            | Self::DataAfterEof
            | Self::Window(_)
            | Self::WindowExceeded { .. }
            | Self::PacketTooLarge { .. }
            | Self::MessageTooLarge
            | Self::ClosedChannel(_) => None,
        }
    }
}

impl From<WireError> for ChannelError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

/// The minimal packet boundary required by a channel multiplexer.
///
/// Client and server protected transports implement this trait. Applications
/// and later channel types can also provide another single serialized writer.
pub trait ChannelTransport {
    /// Writes one complete nonempty SSH payload.
    fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()>;

    /// Reads and consumes one complete SSH payload.
    fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()>;
}

impl<S> ChannelTransport for ClientTransport<S>
where
    S: Read + Write,
{
    fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
        self.write_payload(payload).map_err(|_error| ())
    }

    fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
        self.read_payload().map_err(|_error| ())
    }
}

impl<S> ChannelTransport for ServerTransport<S>
where
    S: Read + Write,
{
    fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
        self.write_payload(payload).map_err(|_error| ())
    }

    fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
        self.read_payload().map_err(|_error| ())
    }
}

/// A validated inbound `SSH_MSG_CHANNEL_OPEN` request.
///
/// Type-specific bytes are kept opaque by the shared channel layer. Session
/// rejects all bytes after the four standard open fields, while a later channel
/// type can decode its own bounded payload without changing packet or window
/// handling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelOpenRequest {
    channel_type: Vec<u8>,
    sender_channel: ChannelId,
    initial_window: u32,
    maximum_packet_size: u32,
    type_specific_data: Vec<u8>,
}

impl ChannelOpenRequest {
    /// Returns the requested channel type.
    #[must_use]
    pub fn channel_type(&self) -> &[u8] {
        &self.channel_type
    }

    /// Returns the sender-selected channel identifier.
    #[must_use]
    pub const fn sender_channel(&self) -> ChannelId {
        self.sender_channel
    }

    /// Returns the peer's advertised receive window.
    #[must_use]
    pub const fn initial_window(&self) -> u32 {
        self.initial_window
    }

    /// Returns the peer's advertised maximum channel-data packet size.
    #[must_use]
    pub const fn maximum_packet_size(&self) -> u32 {
        self.maximum_packet_size
    }

    /// Returns the bounded type-specific open bytes.
    #[must_use]
    pub fn type_specific_data(&self) -> &[u8] {
        &self.type_specific_data
    }
}

/// One completely parsed and routed channel event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelEvent {
    /// A peer requested a new channel.
    OpenRequest(ChannelOpenRequest),
    /// The peer confirmed a locally opened channel.
    Opened(ChannelId),
    /// The peer rejected a locally opened channel.
    OpenFailed {
        /// The local sender channel that was rejected.
        channel: ChannelId,
        /// RFC 4254 numeric rejection reason.
        reason: u32,
        /// Human-readable diagnostic supplied by the peer.
        description: Vec<u8>,
        /// RFC 4250 language tag supplied by the peer.
        language: Vec<u8>,
    },
    /// The peer granted additional credit for data sent to its channel.
    WindowAdjusted {
        /// The recipient channel receiving the adjustment.
        channel: ChannelId,
        /// Newly available remote credit after the adjustment.
        available: u32,
    },
    /// A complete data packet was charged to the local receive window.
    Data {
        /// The recipient channel.
        channel: ChannelId,
        /// The bounded data bytes.
        data: Vec<u8>,
    },
    /// A complete extended-data packet was charged to the local receive window.
    ExtendedData {
        /// The recipient channel.
        channel: ChannelId,
        /// RFC 4254 extended-data type code (1 is `SSH_EXTENDED_DATA_STDERR`).
        data_type_code: u32,
        /// The bounded extended-data bytes.
        data: Vec<u8>,
    },
    /// The peer will send no more data on this channel.
    Eof {
        /// The recipient channel.
        channel: ChannelId,
    },
    /// The peer closed this channel.
    Close {
        /// The recipient channel.
        channel: ChannelId,
    },
    /// A channel request whose type-specific bytes remain application-defined.
    Request {
        /// The recipient channel.
        channel: ChannelId,
        /// SSH request type.
        request_type: Vec<u8>,
        /// Whether the requester asked for SUCCESS or FAILURE.
        want_reply: bool,
        /// Bounded request-specific bytes.
        data: Vec<u8>,
    },
    /// The peer answered a request with `SSH_MSG_CHANNEL_SUCCESS`.
    RequestSucceeded {
        /// The recipient channel.
        channel: ChannelId,
    },
    /// The peer answered a request with `SSH_MSG_CHANNEL_FAILURE`.
    RequestFailed {
        /// The recipient channel.
        channel: ChannelId,
    },
    /// The peer sent an `SSH_MSG_GLOBAL_REQUEST`, RFC 4254 §4.
    ///
    /// A global request is not addressed to a channel and RFC 4254 §4 allows
    /// one "at any time". Which requests are honoured is policy, not channel
    /// multiplexing, so this value is surfaced rather than answered here; see
    /// [`ChannelConnection::send_global_request_success`] and
    /// [`ChannelConnection::send_global_request_failure`] for the reply the
    /// same section requires when `want_reply` is set.
    GlobalRequest {
        /// The request name, in US-ASCII, as the peer spelled it.
        request_name: Vec<u8>,
        /// Whether the peer requires a `SSH_MSG_REQUEST_SUCCESS` or
        /// `SSH_MSG_REQUEST_FAILURE` answer.
        want_reply: bool,
        /// Bounded request-specific data.
        data: Vec<u8>,
    },
    /// The peer answered an outstanding global request with success.
    ///
    /// RFC 4254 §4 requires replies to global requests to arrive in the order
    /// the requests were sent, so the caller pairs these with its own
    /// outstanding-request queue.
    GlobalRequestSucceeded {
        /// Bounded response-specific data, empty when the reply carried none.
        data: Vec<u8>,
    },
    /// The peer answered an outstanding global request with failure.
    GlobalRequestFailed {
        /// Bounded response-specific data, empty when the reply carried none.
        data: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChannelDirection {
    OpenedLocally,
    AcceptedLocally,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct Channel {
    local_id: ChannelId,
    remote_id: Option<ChannelId>,
    direction: ChannelDirection,
    local_window: u32,
    remote_window: u32,
    local_maximum_packet_size: u32,
    remote_maximum_packet_size: u32,
    local_eof_sent: bool,
    remote_eof_received: bool,
    local_close_sent: bool,
    remote_close_received: bool,
    failed: bool,
}

impl Channel {
    fn writable(&self) -> Result<(), ChannelError> {
        if self.failed {
            return Err(ChannelError::InvalidMessage);
        }
        if self.local_eof_sent {
            return Err(ChannelError::DataAfterEof);
        }
        if self.local_close_sent {
            return Err(ChannelError::InvalidMessage);
        }
        Ok(())
    }

    fn active(&self) -> Result<(), ChannelError> {
        if self.failed || self.remote_close_received {
            return Err(ChannelError::InvalidMessage);
        }
        Ok(())
    }
}

/// A public, read-only view of one open channel's flow-control state.
///
/// The view does not own a queue. Incoming data exists only in the
/// [`ChannelEvent`] returned by one dispatcher call.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelState {
    local_id: ChannelId,
    remote_id: Option<ChannelId>,
    local_window: u32,
    remote_window: u32,
    local_maximum_packet_size: u32,
    remote_maximum_packet_size: u32,
    local_eof_sent: bool,
    remote_eof_received: bool,
    local_close_sent: bool,
    remote_close_received: bool,
    failed: bool,
}

impl ChannelState {
    /// Returns the local sender channel identifier.
    #[must_use]
    pub const fn local_id(&self) -> ChannelId {
        self.local_id
    }

    /// Returns the peer sender channel identifier for an established channel.
    #[must_use]
    pub const fn remote_id(&self) -> Option<ChannelId> {
        self.remote_id
    }

    /// Returns the remaining local receive window.
    #[must_use]
    pub const fn local_window(&self) -> u32 {
        self.local_window
    }

    /// Returns the remaining remote receive window.
    #[must_use]
    pub const fn remote_window(&self) -> u32 {
        self.remote_window
    }

    /// Returns the locally advertised maximum data size.
    #[must_use]
    pub const fn local_maximum_packet_size(&self) -> u32 {
        self.local_maximum_packet_size
    }

    /// Returns the peer-advertised maximum data size, capped to this
    /// implementation's transport-safe limit.
    #[must_use]
    pub const fn remote_maximum_packet_size(&self) -> u32 {
        self.remote_maximum_packet_size
    }

    /// Returns whether this side has sent EOF.
    #[must_use]
    pub const fn local_eof_sent(&self) -> bool {
        self.local_eof_sent
    }

    /// Returns whether the peer has sent EOF.
    #[must_use]
    pub const fn remote_eof_received(&self) -> bool {
        self.remote_eof_received
    }

    /// Returns whether this side has sent CLOSE.
    #[must_use]
    pub const fn local_close_sent(&self) -> bool {
        self.local_close_sent
    }

    /// Returns whether the peer has sent CLOSE.
    #[must_use]
    pub const fn remote_close_received(&self) -> bool {
        self.remote_close_received
    }

    /// Returns whether a channel-specific protocol error made the channel unusable.
    #[must_use]
    pub const fn failed(&self) -> bool {
        self.failed
    }
}

/// A bounded, single-reader and serialized-writer channel multiplexer.
///
/// All channel operations borrow the connection mutably. The connection does
/// not run background readers, spawn threads, or buffer data between calls.
#[derive(Debug)]
pub struct ChannelConnection<T> {
    transport: T,
    channels: std::collections::BTreeMap<ChannelId, Channel>,
    incoming: std::collections::BTreeMap<ChannelId, ChannelOpenRequest>,
    /// Bounded tombstones for channels both sides have closed.
    ///
    /// RFC 4254 §5.3 lets a party reuse a channel number once it has both sent
    /// and received `SSH_MSG_CHANNEL_CLOSE`, and OpenSSH reuses the lowest free
    /// slot (`channel_new`: "Try to find a free slot where to put the new
    /// channel"). A peer is therefore entitled to name a number we have just
    /// retired. Remembering the retirement lets the multiplexer say
    /// [`ChannelError::ClosedChannel`] instead of silently routing a straggler
    /// onto whatever channel took the number next; the bound keeps a
    /// misbehaving peer from growing the table without limit.
    closed: std::collections::BTreeMap<ChannelId, u64>,
    /// Monotonic retirement counter used to bound the tombstone map.
    reap_clock: u64,
}

/// Failure of the single-packet owned channel writer.
#[derive(Debug)]
pub enum OwnedChannelError {
    /// A packet is already admitted, a packet identifier is stale or foreign,
    /// or an inbound obligation is outstanding.
    Busy,
    /// A terminal transport or channel failure has made this driver unusable.
    Failed,
    /// Channel validation or flow control rejected the request.
    Channel(ChannelError),
    /// The protected transport rejected or could not drive the packet.
    Transport(TransportError),
}

impl fmt::Display for OwnedChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => {
                formatter.write_str("the owned channel driver is busy with a packet or obligation")
            }
            Self::Failed => formatter.write_str("the owned channel driver has failed"),
            Self::Channel(error) => write!(formatter, "SSH channel error: {error}"),
            Self::Transport(error) => write!(formatter, "SSH transport error: {error}"),
        }
    }
}

impl std::error::Error for OwnedChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Channel(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Busy | Self::Failed => None,
        }
    }
}

/// Opaque identity of one packet admitted by an [`OwnedChannelDriver`].
#[derive(Clone, Debug)]
pub struct OwnedChannelWriteId(OwnedPacketId);

/// Opaque identity of one admitted outbound window adjustment.
#[derive(Clone, Debug)]
pub struct OwnedWindowAdjustmentId(OwnedPacketId);

/// Opaque identity of an admitted outbound channel EOF.
#[derive(Clone, Debug)]
pub struct OwnedChannelEofId(OwnedPacketId);

/// Opaque identity for reading behind one active channel-failure reply.
#[derive(Clone, Debug)]
pub struct OwnedChannelFailureReadId {
    channel: ChannelId,
    packet: OwnedPacketId,
}

/// Opaque identity for reading behind one active open rejection.
#[derive(Clone, Debug)]
pub struct OwnedOpenRejectionReadId {
    remote: ChannelId,
    packet: OwnedPacketId,
}

/// Opaque identity for reading behind one active peer-close reply.
#[derive(Clone, Debug)]
pub struct OwnedCloseReplyReadId {
    channel: ChannelId,
    packet: OwnedPacketId,
}

/// Opaque identity for reading behind one active deferred PONG.
#[derive(Clone, Debug)]
pub struct OwnedPongReadId(OwnedPacketId);

#[derive(Debug)]
struct WindowAdjustment {
    channel: ChannelId,
    increment: u32,
}

#[derive(Debug)]
enum GlobalFailure {
    Queued,
    Writing(OwnedPacketId),
}

#[derive(Debug)]
enum ReplyKind {
    Pong,
    GlobalFailure(GlobalFailure),
    ChannelFailure(ChannelFailure),
    OpenRejection(OpenRejection),
    CloseReply(CloseReply),
}

#[derive(Debug)]
struct ReplyObligation {
    id: ObligationId,
    reply: ReplyKind,
}

#[derive(Debug)]
struct ChannelFailure {
    channel: ChannelId,
    remote: ChannelId,
    packet: Option<OwnedPacketId>,
}

#[derive(Debug)]
struct OpenRejection {
    remote: ChannelId,
    packet: Option<(u32, OwnedPacketId)>,
}

#[derive(Debug)]
struct CloseReply {
    channel: ChannelId,
    remote: ChannelId,
    packet: Option<OwnedPacketId>,
}

/// One bounded result from [`OwnedChannelDriver::read_inbound`],
/// [`OwnedChannelDriver::read_idle`], or
/// [`OwnedChannelDriver::read_while_window_adjustment`], or
/// [`OwnedChannelDriver::read_while_eof`], or
/// [`OwnedChannelDriver::read_while_global_failure`], or
/// [`OwnedChannelDriver::read_while_channel_failure`], or
/// [`OwnedChannelDriver::read_while_open_rejection`], or
/// [`OwnedChannelDriver::read_while_close_reply`], or
/// [`OwnedChannelDriver::read_while_pong`].
#[derive(Debug)]
pub enum OwnedChannelInbound {
    /// One complete channel event was decoded and delivered unchanged.
    ///
    /// The driver never automatically answers a request, sends a close, or
    /// adjusts a window. When any read step surfaces a `Request` or `GlobalRequest` that asked for
    /// a reply, a channel `OpenRequest`, or a `Close` this side has not already
    /// sent, the obligation blocks further reads and release. Global and
    /// channel requests have explicit failure reply paths; open requests can be
    /// rejected and a peer close can be answered explicitly. If the event
    /// arrives during a window adjustment, EOF, global failure, channel
    /// failure, open rejection, close reply or PONG, that packet must complete before the reply
    /// can be driven.
    Event(ChannelEvent),
    /// One authenticated payload was consumed and carried no channel event.
    ///
    /// This is the result for the RFC 4253 §11 messages the legacy dispatcher
    /// also drops: `SSH_MSG_IGNORE`, `SSH_MSG_DEBUG` and
    /// `SSH_MSG_UNIMPLEMENTED`.
    Consumed,
    /// An inbound transport ping was consumed and its pong is owed.
    ///
    /// No further inbound read is permitted until any admitted data packet or
    /// window adjustment, EOF, active failure, open rejection, close reply or PONG completes and
    /// [`OwnedChannelDriver::drive_deferred_pong`]
    /// writes the pong. The connection cannot be released while the pong is owed.
    PongDeferred,
    /// A peer-initiated rekey was retained or advanced by this step.
    ///
    /// The peer KEXINIT was authenticated with its inbound sequence number
    /// committed exactly once. No channel event was produced and no application
    /// payload may be admitted or released until the rekey completes. Finish any
    /// active outbound packet, then call [`OwnedChannelDriver::read_idle`] to
    /// advance the exchange. A `WouldBlock` from that call is retryable.
    PeerRekey,
}

/// Owns a channel connection while admitting and driving one data packet.
///
/// No mutable reference to the connection or transport is exposed. Admission
/// reserves remote window immediately; it does not mean the peer received the
/// bytes. Dropping the ID does not cancel or roll back the packet: retain a
/// copy to finish it, or drop the driver and its transport. A failed or busy
/// driver cannot release its connection. Dropping the driver drops its stream,
/// although other independently held stream handles may remain open.
///
/// [`Self::read_inbound`] adds one opt-in inbound step while the admitted
/// packet is active; [`Self::read_idle`] does the same without an admitted
/// packet. It is deliberately not a full-duplex scheduler: it does
/// not loop, does not automatically answer requests or peer closes,
/// and retains a peer KEXINIT for a later bounded rekey. The admitted data
/// packet can be driven with
/// [`Self::drive`] unless the driver fails; a deferred pong can then be written
/// with [`Self::drive_deferred_pong`]. Release is allowed only when no other
/// obligation or failure remains. [`Self::drive_global_failure`] answers one
/// consumed global request; [`Self::drive_channel_failure`] refuses a channel
/// request. [`Self::drive_open_rejection`] rejects an inbound open and
/// [`Self::drive_close_reply`] answers a peer close. [`Self::try_new`] refuses
/// a connection that already has a pending open or unanswered peer close, so those pre-existing obligations
/// stay answerable through the legacy API. A global or channel request that was
/// already delivered to the caller is that caller's to answer and is not
/// visible to the constructor.
/// The legacy [`ChannelConnection`] and [`ChannelTransport`] APIs are unchanged.
///
/// Read-behind provides bounded backpressure, not guaranteed full-duplex
/// progress. There is no retained inbound event slot: each returned event
/// belongs to the caller. A caller with room for only one undelivered event
/// cannot reach a later control packet behind it until that event is drained.
///
/// If a reply is owed behind a partially written data, window adjustment, or
/// EOF packet, or a peer rekey is retained behind a partially written packet,
/// further reads stop and the original writer must resume that packet. A reply
/// already being written can admit one later reply obligation, which is
/// ordered after it; once that next obligation is present, reads stop again.
/// This mechanism does not admit a second reply behind a data packet while the
/// first reply is merely owed. Callers must wait for readiness, not spin, and
/// be prepared to discard the connection if progress cannot resume.
///
/// The wrapped connection's mutable transport cannot be reached through the
/// driver:
///
/// ```compile_fail
/// use std::io::{Read, Write};
/// use neotales_ssh::channel::OwnedChannelDriver;
///
/// fn bypass<S: Read + Write>(driver: &mut OwnedChannelDriver<S>) {
///     let _transport = driver.transport_mut();
/// }
/// ```
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct OwnedChannelDriver<S> {
    connection: Box<ChannelConnection<ClientTransport<S>>>,
    pending: bool,
    failed: bool,
    /// Metadata mirrors the transport FIFO, including its active front.
    reply_obligations: VecDeque<ReplyObligation>,
    /// Parsed and accounted once, moved to the caller before another read.
    retained_event: Option<ChannelEvent>,
    /// One admitted window adjustment; local credit is committed on completion.
    window_adjustment: Option<WindowAdjustment>,
    /// Channel whose admitted EOF is awaiting packet completion.
    pending_eof: Option<ChannelId>,
}

impl<S: Read + Write> OwnedChannelDriver<S> {
    /// Takes exclusive ownership only of an authenticated, idle transport with
    /// no pending inbound open and no unanswered peer close.
    ///
    /// A connection that already holds a pending open request, or a peer close
    /// this side has not answered, is refused. The unmodified connection is
    /// returned so the caller can answer that obligation with the legacy
    /// channel API and retry. These are the only pre-existing control
    /// obligations checked here. A global or channel request whose
    /// `want_reply` was already delivered to the caller is not visible to this
    /// constructor; the caller owns that reply and must send it before handing
    /// the connection over. A transport that is busy for another reason,
    /// including a deferred pong or a partial packet, is also refused; finish
    /// that transport work through the transport API and retry. The driver has
    /// no reply path for a pre-existing open or an unanswered close, so
    /// accepting either would leave the caller unable to answer or release it.
    pub fn try_new(
        connection: ChannelConnection<ClientTransport<S>>,
    ) -> Result<Self, Box<ChannelConnection<ClientTransport<S>>>> {
        let transport = &connection.transport;
        let control_owed = connection.pending_open_count() != 0
            || connection
                .channels()
                .any(|channel| channel.remote_close_received() && !channel.local_close_sent());
        if !transport.can_start_owned_channel_driver() || control_owed {
            return Err(Box::new(connection));
        }
        Ok(Self {
            connection: Box::new(connection),
            pending: false,
            failed: false,
            reply_obligations: VecDeque::new(),
            retained_event: None,
            window_adjustment: None,
            pending_eof: None,
        })
    }

    /// Returns a copy of the named channel's state.
    #[must_use]
    pub fn channel(&self, channel: ChannelId) -> Option<ChannelState> {
        self.connection.channel(channel)
    }

    /// Returns whether a tombstone for this local channel ID is currently remembered.
    ///
    /// Tombstones have bounded retention and an ID can be reused. Therefore,
    /// `false` does not prove that the ID was never retired.
    #[must_use]
    pub fn is_retired_channel(&self, channel: ChannelId) -> bool {
        self.connection.is_retired_channel(channel)
    }

    /// Returns the number of peer opens awaiting a response.
    #[must_use]
    pub fn pending_open_count(&self) -> usize {
        self.connection.pending_open_count()
    }

    /// Returns the protected transport's committed outbound sequence.
    #[must_use]
    pub fn outbound_sequence(&self) -> u32 {
        self.connection.transport.outbound_sequence()
    }

    /// Returns the protected transport's committed inbound sequence.
    #[must_use]
    pub fn inbound_sequence(&self) -> u32 {
        self.connection.transport.inbound_sequence()
    }

    /// Returns whether a peer-initiated rekey is retained or in progress.
    ///
    /// While this is true, channel-data admission, window adjustments, EOF,
    /// replies, further owned reads, and release are refused. Finish the active
    /// packet and call [`Self::read_idle`] to advance the exchange.
    #[must_use]
    pub fn rekey_active(&self) -> bool {
        self.connection.transport.rekey_active()
    }

    /// Admits one bounded channel-data packet and reserves its remote credit.
    ///
    /// # Errors
    ///
    /// Returns busy, failed, channel validation, flow-control or transport
    /// errors. Rejected admission does not consume remote credit. Admission is
    /// also busy while an adjustment, EOF, inbound pong or control reply is owed;
    /// see [`Self::read_inbound`].
    pub fn admit_data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
    ) -> Result<OwnedChannelWriteId, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if self.pending
            || !self.reply_obligations.is_empty()
            || self.window_adjustment.is_some()
            || self.pending_eof.is_some()
            || self.connection.transport.rekey_active()
        {
            return Err(OwnedChannelError::Busy);
        }
        let connection = &mut *self.connection;
        let state = connection
            .channels
            .get_mut(&channel)
            .ok_or(OwnedChannelError::Channel(ChannelError::UnknownChannel))?;
        state.writable().map_err(OwnedChannelError::Channel)?;
        let remote = state
            .remote_id
            .ok_or(OwnedChannelError::Channel(ChannelError::InvalidMessage))?;
        let maximum = usize::try_from(state.remote_maximum_packet_size)
            .unwrap_or(usize::MAX)
            .min(MAX_CHANNEL_DATA_SIZE);
        if data.len() > maximum {
            return Err(OwnedChannelError::Channel(ChannelError::PacketTooLarge {
                maximum: u32::try_from(maximum).unwrap_or(u32::MAX),
                requested: data.len(),
            }));
        }
        let length = u32::try_from(data.len())
            .map_err(|_| OwnedChannelError::Channel(ChannelError::MessageTooLarge))?;
        if length > state.remote_window {
            return Err(OwnedChannelError::Channel(ChannelError::Window(
                WindowError::Insufficient {
                    available: state.remote_window,
                    requested: data.len(),
                },
            )));
        }
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_DATA);
        writer.write_uint32(remote);
        writer
            .write_string(data)
            .map_err(|error| OwnedChannelError::Channel(ChannelError::Wire(error)))?;
        let id = match connection
            .transport
            .start_owned_packet(&writer.into_bytes())
        {
            Ok(id) => id,
            Err(error) => {
                if !connection.transport.is_established() {
                    self.failed = true;
                }
                return Err(OwnedChannelError::Transport(error));
            }
        };
        state.remote_window -= length;
        self.pending = true;
        Ok(OwnedChannelWriteId(id))
    }

    /// Drives the admitted packet without retaining caller-provided bytes.
    ///
    /// `WouldBlock` preserves the packet and reserved credit. Completion is
    /// reported exactly once; stale or foreign IDs do not change the driver.
    /// Any other write error makes the driver terminal.
    ///
    /// The driver does not expose its socket. Obtain a separate readiness
    /// handle from the same socket **before** handing that socket to the SSH
    /// transport. Wait for writable readiness after `WouldBlock`; do not spin.
    /// A cloned handle can keep the underlying socket open after the driver is
    /// dropped, so close that handle too on failure or cancellation.
    ///
    /// This example's `prepare` must authenticate and confirm the named channel
    /// using the socket it receives. `wait_writable` must actually wait for
    /// writable readiness without retaining another socket handle:
    ///
    /// ```no_run
    /// use std::{io, net::TcpStream};
    /// use neotales_ssh::{
    ///     ClientTransport,
    ///     channel::{ChannelConnection, ChannelId, OwnedChannelDriver, OwnedChannelError},
    ///     transport::TransportError,
    /// };
    ///
    /// fn send_one(
    ///     socket: TcpStream,
    ///     prepare: impl FnOnce(TcpStream)
    ///         -> Result<ChannelConnection<ClientTransport<TcpStream>>, Box<dyn std::error::Error>>,
    ///     channel: ChannelId,
    ///     data: &[u8],
    ///     mut wait_writable: impl FnMut(&TcpStream) -> io::Result<()>,
    /// ) -> Result<OwnedChannelDriver<TcpStream>, Box<dyn std::error::Error>> {
    ///     // Clone before prepare moves the socket into the SSH transport.
    ///     let readiness = socket.try_clone()?;
    ///     let connection = prepare(socket)?;
    ///     // Both handles refer to the same socket; switch only after the
    ///     // synchronous handshake, authentication and channel confirmation.
    ///     readiness.set_nonblocking(true)?;
    ///     let mut driver = OwnedChannelDriver::try_new(connection)
    ///         .map_err(|_| io::Error::other("SSH transport is not idle"))?;
    ///     let id = driver.admit_data(channel, data)?;
    ///     loop {
    ///         match driver.drive(&id) {
    ///             Ok(()) => return Ok(driver),
    ///             Err(OwnedChannelError::Transport(TransportError::Io(error)))
    ///                 if error.kind() == io::ErrorKind::WouldBlock =>
    ///             {
    ///                 wait_writable(&readiness)?;
    ///             }
    ///             // Returning drops both driver and readiness, including after
    ///             // a fatal transport error or a readiness-wait failure.
    ///             Err(error) => return Err(error.into()),
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns busy for a wrong ID, a retryable transport `WouldBlock`, or a
    /// terminal transport error.
    pub fn drive(&mut self, id: &OwnedChannelWriteId) -> Result<(), OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if !self.pending {
            return Err(OwnedChannelError::Busy);
        }
        match self.connection.transport.drive_owned_packet(&id.0) {
            Ok(()) => {
                self.pending = false;
                Ok(())
            }
            Err(TransportError::OwnedPacketState) => Err(OwnedChannelError::Busy),
            Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                Err(OwnedChannelError::Transport(TransportError::Io(error)))
            }
            Err(error) => {
                self.failed = true;
                Err(OwnedChannelError::Transport(error))
            }
        }
    }

    /// Admits one bounded local-window adjustment without yet granting credit.
    ///
    /// The increment is sealed into one protected packet. Local window is
    /// updated only by successful [`Self::drive_window_adjustment`]. The
    /// [`Self::read_while_window_adjustment`] step may receive one packet at a
    /// time; new admissions and release are blocked until completion. The caller
    /// must retain this ID or drop the driver; dropping an ID does not cancel
    /// the packet. Additional consumed credit remains the caller's separate
    /// responsibility and must be admitted as a later adjustment.
    ///
    /// # Errors
    ///
    /// Returns busy or failed, a channel validation/window overflow error, or
    /// a transport error. Rejected admission does not change the window.
    pub fn admit_window_adjustment(
        &mut self,
        channel: ChannelId,
        increment: u32,
    ) -> Result<OwnedWindowAdjustmentId, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if self.pending
            || !self.reply_obligations.is_empty()
            || self.window_adjustment.is_some()
            || self.pending_eof.is_some()
            || self.connection.transport.rekey_active()
        {
            return Err(OwnedChannelError::Busy);
        }
        if increment == 0 {
            return Err(OwnedChannelError::Channel(
                ChannelError::InvalidWindowAdjustment,
            ));
        }
        let state = self
            .connection
            .channels
            .get(&channel)
            .ok_or(OwnedChannelError::Channel(ChannelError::UnknownChannel))?;
        state.active().map_err(OwnedChannelError::Channel)?;
        if state.local_close_sent {
            return Err(OwnedChannelError::Channel(ChannelError::InvalidMessage));
        }
        let remote = state
            .remote_id
            .ok_or(OwnedChannelError::Channel(ChannelError::InvalidMessage))?;
        state
            .local_window
            .checked_add(increment)
            .ok_or(OwnedChannelError::Channel(ChannelError::Window(
                WindowError::AdjustmentOverflow {
                    current: state.local_window,
                    increment,
                },
            )))?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_WINDOW_ADJUST);
        writer.write_uint32(remote);
        writer.write_uint32(increment);
        let id = match self
            .connection
            .transport
            .start_owned_packet(&writer.into_bytes())
        {
            Ok(id) => id,
            Err(error) => {
                if !self.connection.transport.is_established() {
                    self.failed = true;
                }
                return Err(OwnedChannelError::Transport(error));
            }
        };
        self.window_adjustment = Some(WindowAdjustment { channel, increment });
        Ok(OwnedWindowAdjustmentId(id))
    }

    /// Drives the exact admitted adjustment and returns the updated local window.
    ///
    /// `WouldBlock` retains the packet and leaves credit unchanged. Completion
    /// updates credit exactly once; stale or foreign IDs return busy without
    /// changes. Other write errors make the driver terminal. On cancellation
    /// drop the driver and any independently held readiness socket handles.
    ///
    /// # Errors
    ///
    /// Returns busy for a stale or foreign ID, failed after a terminal error,
    /// or a transport error, including retryable `WouldBlock`.
    pub fn drive_window_adjustment(
        &mut self,
        id: &OwnedWindowAdjustmentId,
    ) -> Result<u32, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        let Some(adjustment) = self.window_adjustment.as_ref() else {
            return Err(OwnedChannelError::Busy);
        };
        let (channel, increment) = (adjustment.channel, adjustment.increment);
        match self.connection.transport.drive_owned_packet(&id.0) {
            Ok(()) => {
                let Some(state) = self.connection.channels.get_mut(&channel) else {
                    self.failed = true;
                    return Err(OwnedChannelError::Channel(ChannelError::UnknownChannel));
                };
                let Some(updated) = state.local_window.checked_add(increment) else {
                    self.failed = true;
                    return Err(OwnedChannelError::Channel(ChannelError::Window(
                        WindowError::AdjustmentOverflow {
                            current: state.local_window,
                            increment,
                        },
                    )));
                };
                state.local_window = updated;
                self.window_adjustment = None;
                Ok(updated)
            }
            Err(TransportError::OwnedPacketState) => Err(OwnedChannelError::Busy),
            Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                Err(OwnedChannelError::Transport(TransportError::Io(error)))
            }
            Err(error) => {
                self.failed = true;
                Err(OwnedChannelError::Transport(error))
            }
        }
    }

    /// Reads one packet while the identified outbound window adjustment is active.
    ///
    /// It uses the same bounded event and reply handling as [`Self::read_inbound`].
    /// A reply-requiring event or PING is retained behind the active packet;
    /// further reads stop until that obligation is answered. The adjustment
    /// must finish before any such reply can be driven. Inbound data reduces
    /// local window immediately; the admitted increment is added to the
    /// then-current window only when its protected write completes.
    ///
    /// `WouldBlock` preserves partial input and the outbound packet. Retain the
    /// ID and resume, or drop the driver and all separate socket handles.
    /// Terminal protocol or I/O errors fail the driver. A peer KEXINIT is
    /// retained and advanced with [`Self::read_idle`] after this packet
    /// completes. Use [`Self::read_while_eof`] for an active EOF and
    /// [`Self::read_while_global_failure`], [`Self::read_while_channel_failure`],
    /// [`Self::read_while_open_rejection`], [`Self::read_while_close_reply`],
    /// or [`Self::read_while_pong`] for those active replies.
    ///
    /// # Errors
    ///
    /// Returns busy for a stale or foreign ID or an owed reply, failed after a
    /// terminal error, or a channel or transport error.
    pub fn read_while_window_adjustment(
        &mut self,
        id: &OwnedWindowAdjustmentId,
    ) -> Result<OwnedChannelInbound, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if self.window_adjustment.is_none() {
            return Err(OwnedChannelError::Busy);
        }
        self.read_behind_reply(&id.0)
    }

    /// Admits one outbound channel EOF without yet changing channel state.
    ///
    /// Earlier data and control work must be completed first. Other admissions
    /// and release are blocked until [`Self::drive_eof`] completes the packet.
    /// [`Self::read_while_eof`] may read one packet per step while it is active.
    /// After completion the read half remains usable until peer closure. The ID
    /// must be retained; dropping it does not cancel the EOF.
    ///
    /// # Errors
    ///
    /// Returns busy or failed, a channel state error, or a transport error.
    pub fn admit_eof(
        &mut self,
        channel: ChannelId,
    ) -> Result<OwnedChannelEofId, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if self.pending
            || !self.reply_obligations.is_empty()
            || self.window_adjustment.is_some()
            || self.pending_eof.is_some()
            || self.connection.transport.rekey_active()
        {
            return Err(OwnedChannelError::Busy);
        }
        let state = self
            .connection
            .channels
            .get(&channel)
            .ok_or(OwnedChannelError::Channel(ChannelError::UnknownChannel))?;
        state.active().map_err(OwnedChannelError::Channel)?;
        state.writable().map_err(OwnedChannelError::Channel)?;
        let remote = state
            .remote_id
            .ok_or(OwnedChannelError::Channel(ChannelError::InvalidMessage))?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_EOF);
        writer.write_uint32(remote);
        let id = match self
            .connection
            .transport
            .start_owned_packet(&writer.into_bytes())
        {
            Ok(id) => id,
            Err(error) => {
                if !self.connection.transport.is_established() {
                    self.failed = true;
                }
                return Err(OwnedChannelError::Transport(error));
            }
        };
        self.pending_eof = Some(channel);
        Ok(OwnedChannelEofId(id))
    }

    /// Completes the exact EOF admitted by [`Self::admit_eof`].
    ///
    /// `WouldBlock` preserves the packet and leaves local EOF unset; wait for
    /// writability before retrying. A successful completion sets local EOF
    /// exactly once; stale or foreign IDs are busy. If cancellation or a
    /// retryable `WouldBlock` interrupts the operation, retain the same ID and
    /// resume, or discard the driver and all independently held socket handles.
    /// Other write errors make the driver terminal and require discarding it
    /// and those handles. In either case the peer's observed outcome may be
    /// unknown; do not send a replacement EOF on that connection.
    ///
    /// # Errors
    ///
    /// Returns busy for a stale or foreign ID, failed after a terminal error,
    /// or a transport error, including retryable `WouldBlock`.
    pub fn drive_eof(&mut self, id: &OwnedChannelEofId) -> Result<(), OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        let Some(channel) = self.pending_eof else {
            return Err(OwnedChannelError::Busy);
        };
        match self.connection.transport.drive_owned_packet(&id.0) {
            Ok(()) => {
                let Some(state) = self.connection.channels.get_mut(&channel) else {
                    self.failed = true;
                    return Err(OwnedChannelError::Channel(ChannelError::UnknownChannel));
                };
                state.local_eof_sent = true;
                self.pending_eof = None;
                Ok(())
            }
            Err(TransportError::OwnedPacketState) => Err(OwnedChannelError::Busy),
            Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                Err(OwnedChannelError::Transport(TransportError::Io(error)))
            }
            Err(error) => {
                self.failed = true;
                Err(OwnedChannelError::Transport(error))
            }
        }
    }

    /// Reads one authenticated packet while the identified outbound EOF is active.
    ///
    /// Events use the same bounded handling as [`Self::read_inbound`]. One
    /// reply-requiring event or PING is retained behind the EOF; further reads
    /// stop until the EOF and that reply complete. In particular, a peer CLOSE
    /// is delivered and retained even if it arrives while EOF is partial. The
    /// EOF completes before the corresponding CLOSE reply and its local state
    /// is set only when its own packet completes.
    ///
    /// `WouldBlock` retains partial input and the outbound EOF. Retain the ID
    /// and retry after readiness, or drop the driver and any separately held
    /// socket handles. Terminal errors fail the driver. A peer KEXINIT is
    /// retained for [`Self::read_idle`]. [`Self::read_while_global_failure`] and
    /// [`Self::read_while_channel_failure`], [`Self::read_while_open_rejection`]
    /// [`Self::read_while_close_reply`] and [`Self::read_while_pong`] cover
    /// those active replies.
    ///
    /// # Errors
    ///
    /// Returns busy for a stale or foreign ID or an owed reply, failed after a
    /// terminal error, or a channel or transport error.
    pub fn read_while_eof(
        &mut self,
        id: &OwnedChannelEofId,
    ) -> Result<OwnedChannelInbound, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if self.pending_eof.is_none() {
            return Err(OwnedChannelError::Busy);
        }
        self.read_behind_reply(&id.0)
    }

    /// Consumes exactly one inbound packet while the admitted data packet is active.
    ///
    /// This is the opt-in incremental read step for a caller that must keep an
    /// outbound packet partially written. It performs one authenticated
    /// transport read and, for an ordinary payload, exactly one call to the
    /// private decoded-payload dispatcher. It never loops and never answers a
    /// message, so one packet produces at most one event and no event is
    /// consumed after an event has been produced.
    ///
    /// The driver refuses the read while an inbound obligation is outstanding:
    ///
    /// * a pong deferred by an inbound transport ping blocks reads until the
    ///   admitted data packet completes and [`Self::drive_deferred_pong`]
    ///   writes the pong;
    /// * a channel open the peer is waiting to be confirmed or refused, a peer
    ///   close this side has not already answered, or a channel request or
    ///   global request whose `want_reply` is set is surfaced as an event and
    ///   also blocks further reads and release.
    ///
    /// A deferred pong, global failure, channel failure, open rejection and
    /// peer close reply have driver completion paths. This is not a general
    /// scheduler for control replies or a client-initiated rekey. A peer
    /// KEXINIT is retained as [`OwnedChannelInbound::PeerRekey`] and advanced
    /// by [`Self::read_idle`] after the active packet completes. A data event
    /// that exhausts the local window is not a reply obligation; admit a window
    /// adjustment when the writer is available if the peer should continue.
    ///
    /// `WouldBlock` preserves the partial inbound packet, the admitted outbound
    /// packet, and every obligation. A stale or foreign identifier returns
    /// [`OwnedChannelError::Busy`] without reading. A channel parse or protocol
    /// error after the packet has been consumed makes the driver terminal,
    /// because that packet cannot be replayed.
    ///
    /// # Errors
    ///
    /// Returns failed, busy, a channel error after a consumed payload, or a
    /// transport error. A transport `WouldBlock` is returned as
    /// [`OwnedChannelError::Transport`] and is retryable.
    pub fn read_inbound(
        &mut self,
        id: &OwnedChannelWriteId,
    ) -> Result<OwnedChannelInbound, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if !self.pending {
            return Err(OwnedChannelError::Busy);
        }
        self.read_behind_reply(&id.0)
    }

    /// Reads at most one authenticated packet without an active data write.
    ///
    /// Events and reply obligations are handled exactly as in
    /// [`Self::read_inbound`]. While any reply is owed, another read, data
    /// admission and release are refused. A PING retains a pong for
    /// [`Self::drive_deferred_pong`].
    ///
    /// A peer `SSH_MSG_KEXINIT` is authenticated and retained as
    /// [`OwnedChannelInbound::PeerRekey`]. Its sequence number is committed
    /// once and application payloads are refused until the rekey completes.
    /// Finish any active outbound packet, then call this method again: it
    /// advances the retained exchange and returns `PeerRekey` for each step.
    /// Extension messages, rekey messages other than KEXINIT, and unsupported
    /// proposals still fail the driver closed.
    ///
    /// `WouldBlock` retains any partial protected packet. A partial packet
    /// prevents release until another read completes it, or the driver is
    /// dropped. A subsequent data admission may be read through
    /// [`Self::read_inbound`], which resumes that same partial packet. Waiting
    /// for socket readiness after `WouldBlock` is the caller's responsibility.
    /// Dropping the driver drops its stream; separately held handles may keep
    /// the underlying socket open.
    ///
    /// # Errors
    ///
    /// Returns busy for an active data write, window adjustment, EOF or obligation,
    /// failed after a terminal error, a channel error for a consumed invalid
    /// packet, or a transport error. `WouldBlock` is retryable.
    pub fn read_idle(&mut self) -> Result<OwnedChannelInbound, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if let Some(event) = self.take_retained_event() {
            return Ok(OwnedChannelInbound::Event(event));
        }
        if self.pending || self.window_adjustment.is_some() || self.pending_eof.is_some() {
            return Err(OwnedChannelError::Busy);
        }
        if self.connection.transport.rekey_active() {
            if !self.reply_obligations.is_empty() {
                return Err(OwnedChannelError::Busy);
            }
            return self.advance_peer_rekey();
        }
        let result = self.connection.transport.read_idle_owned();
        self.handle_owned_inbound(result)
    }

    fn advance_peer_rekey(&mut self) -> Result<OwnedChannelInbound, OwnedChannelError> {
        match self.connection.transport.advance_retained_peer_rekey() {
            Ok(true) => Ok(OwnedChannelInbound::PeerRekey),
            Ok(false) | Err(TransportError::OwnedPacketState) => Err(OwnedChannelError::Busy),
            Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                Err(OwnedChannelError::Transport(TransportError::Io(error)))
            }
            Err(error) => {
                self.failed = true;
                Err(OwnedChannelError::Transport(error))
            }
        }
    }

    fn handle_owned_inbound(
        &mut self,
        result: Result<OwnedInbound, TransportError>,
    ) -> Result<OwnedChannelInbound, OwnedChannelError> {
        let inbound = self.retain_owned_inbound(result)?;
        Ok(self
            .take_retained_event()
            .map_or(inbound, OwnedChannelInbound::Event))
    }

    fn take_retained_event(&mut self) -> Option<ChannelEvent> {
        self.retained_event.take()
    }

    fn retain_owned_inbound(
        &mut self,
        result: Result<OwnedInbound, TransportError>,
    ) -> Result<OwnedChannelInbound, OwnedChannelError> {
        if self.retained_event.is_some() {
            return Err(OwnedChannelError::Busy);
        }
        match result {
            Ok(OwnedInbound::Payload(payload)) => {
                match self.connection.dispatch_decoded_payload(&payload) {
                    Ok(Some(event)) => {
                        if let Err(error) = self.queue_event_control(&event) {
                            self.failed = true;
                            self.retained_event = None;
                            return Err(error);
                        }
                        self.retained_event = Some(event);
                        Ok(OwnedChannelInbound::Consumed)
                    }
                    Ok(None) => Ok(OwnedChannelInbound::Consumed),
                    Err(error) => {
                        self.failed = true;
                        Err(OwnedChannelError::Channel(error))
                    }
                }
            }
            Ok(OwnedInbound::PongDeferred) => {
                let Some(id) = self.connection.transport.last_owned_obligation_id() else {
                    self.failed = true;
                    return Err(OwnedChannelError::Transport(TransportError::InvalidMessage));
                };
                self.reply_obligations.push_back(ReplyObligation {
                    id,
                    reply: ReplyKind::Pong,
                });
                Ok(OwnedChannelInbound::PongDeferred)
            }
            Ok(OwnedInbound::PeerKexInitRetained) => Ok(OwnedChannelInbound::PeerRekey),
            Err(TransportError::OwnedPacketState) => {
                if self.connection.transport.rekey_active() {
                    Ok(OwnedChannelInbound::PeerRekey)
                } else {
                    Err(OwnedChannelError::Busy)
                }
            }
            Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                Err(OwnedChannelError::Transport(TransportError::Io(error)))
            }
            Err(error) => {
                self.failed = true;
                Err(OwnedChannelError::Transport(error))
            }
        }
    }

    /// Reads one authenticated packet behind a partially written global failure.
    ///
    /// This step is available only once the global failure packet has been
    /// admitted by [`Self::drive_global_failure`]. The active packet remains
    /// the sole protected writer. A PING or reply-requiring event occupies one
    /// separate bounded next-obligation slot, after which further reads are
    /// busy. Complete the active global failure first, then drive the deferred
    /// pong or reply using its corresponding method. Inbound data and window
    /// events are delivered one at a time without queuing.
    ///
    /// A partial read and the active packet survive `WouldBlock`. On
    /// cancellation retain the driver or drop it and its separate socket
    /// handles. Terminal I/O or protocol errors fail the driver. A peer KEXINIT is
    /// retained for [`Self::read_idle`]. [`Self::read_while_channel_failure`] and
    /// [`Self::read_while_open_rejection`], [`Self::read_while_close_reply`]
    /// and [`Self::read_while_pong`] cover those active replies.
    ///
    /// # Errors
    ///
    /// Returns busy if the packet is not writing or the next slot is occupied,
    /// failed after a terminal error, or a channel or transport error.
    pub fn read_while_global_failure(&mut self) -> Result<OwnedChannelInbound, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        let Some(ReplyObligation {
            reply: ReplyKind::GlobalFailure(GlobalFailure::Writing(id)),
            ..
        }) = self.reply_obligations.front()
        else {
            return Err(OwnedChannelError::Busy);
        };
        let id = id.clone();
        self.read_behind_reply(&id)
    }

    /// Returns the identity of an active channel-failure reply.
    ///
    /// `channel` is the local channel from the request event. This succeeds
    /// only after [`Self::drive_channel_failure`] has admitted the packet. The
    /// ID cannot be reused for a later reply on the same channel.
    ///
    /// # Errors
    ///
    /// Returns busy for a wrong channel or no active packet, or failed after a
    /// terminal error.
    pub fn channel_failure_read_id(
        &self,
        channel: ChannelId,
    ) -> Result<OwnedChannelFailureReadId, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        let Some(ReplyObligation {
            reply: ReplyKind::ChannelFailure(failure),
            ..
        }) = self.reply_obligations.front()
        else {
            return Err(OwnedChannelError::Busy);
        };
        if failure.channel != channel {
            return Err(OwnedChannelError::Busy);
        }
        let Some(packet) = failure.packet.clone() else {
            return Err(OwnedChannelError::Busy);
        };
        Ok(OwnedChannelFailureReadId { channel, packet })
    }

    /// Reads one authenticated packet behind a partially written channel failure.
    ///
    /// `id` comes from [`Self::channel_failure_read_id`] and identifies the
    /// packet's retained owner. One PING or reply-requiring event can be
    /// retained behind it; further reads then return busy. Complete the active
    /// channel failure before driving the promoted reply or PONG.
    ///
    /// `WouldBlock` retains partial input. On cancellation keep the driver or
    /// drop it and separately held socket handles. Fatal I/O or protocol errors
    /// fail the driver. A peer KEXINIT is retained for [`Self::read_idle`].
    /// Reads during other reply ciphertext remain unsupported except for
    /// [`Self::read_while_global_failure`]
    /// [`Self::read_while_open_rejection`], [`Self::read_while_close_reply`],
    /// and [`Self::read_while_pong`].
    ///
    /// # Errors
    ///
    /// Returns busy for a stale or foreign ID, no active packet or a full next
    /// slot, failed after a terminal error, or a channel or transport error.
    pub fn read_while_channel_failure(
        &mut self,
        id: &OwnedChannelFailureReadId,
    ) -> Result<OwnedChannelInbound, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        let Some(ReplyObligation {
            reply: ReplyKind::ChannelFailure(failure),
            ..
        }) = self.reply_obligations.front()
        else {
            return Err(OwnedChannelError::Busy);
        };
        if failure.channel != id.channel || failure.packet.is_none() {
            return Err(OwnedChannelError::Busy);
        }
        self.read_behind_reply(&id.packet)
    }

    /// Returns the identity of an active rejection for the peer's sender ID.
    ///
    /// This succeeds only after [`Self::drive_open_rejection`] has admitted the
    /// packet. The returned identity cannot be reused for a later rejection,
    /// even when the peer reuses the same sender ID.
    ///
    /// # Errors
    ///
    /// Returns busy for a wrong sender ID or no active packet, or failed after
    /// a terminal error.
    pub fn open_rejection_read_id(
        &self,
        remote: ChannelId,
    ) -> Result<OwnedOpenRejectionReadId, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        let Some(ReplyObligation {
            reply: ReplyKind::OpenRejection(rejection),
            ..
        }) = self.reply_obligations.front()
        else {
            return Err(OwnedChannelError::Busy);
        };
        if rejection.remote != remote {
            return Err(OwnedChannelError::Busy);
        }
        let Some((_, packet)) = rejection.packet.as_ref() else {
            return Err(OwnedChannelError::Busy);
        };
        Ok(OwnedOpenRejectionReadId {
            remote,
            packet: packet.clone(),
        })
    }

    /// Reads one packet behind the identified partially written open rejection.
    ///
    /// The active rejection remains the only protected writer. A PING or
    /// reply-requiring event occupies one separate next-obligation slot; no
    /// more reads are permitted while that slot is full. Finish the active
    /// rejection before driving its promoted reply or PONG. The active pending
    /// open is removed only after its full rejection is written.
    ///
    /// A partial read and active packet survive `WouldBlock`. On cancellation,
    /// retain the driver or drop it and separately held socket handles. Fatal
    /// I/O or protocol errors fail the driver. A peer KEXINIT is retained for
    /// [`Self::read_idle`]. Reads during global, channel, close and PONG
    /// replies have their own bounded read steps.
    ///
    /// # Errors
    ///
    /// Returns busy for a stale or foreign ID, no active packet or a full next
    /// slot, failed after a terminal error, or a channel or transport error.
    pub fn read_while_open_rejection(
        &mut self,
        id: &OwnedOpenRejectionReadId,
    ) -> Result<OwnedChannelInbound, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        let Some(ReplyObligation {
            reply: ReplyKind::OpenRejection(rejection),
            ..
        }) = self.reply_obligations.front()
        else {
            return Err(OwnedChannelError::Busy);
        };
        if rejection.remote != id.remote || rejection.packet.is_none() {
            return Err(OwnedChannelError::Busy);
        }
        self.read_behind_reply(&id.packet)
    }

    /// Returns the identity of an active close reply for a local channel.
    ///
    /// This succeeds only after [`Self::drive_close_reply`] has admitted the
    /// packet. The identity cannot be reused for a later reply, even when the
    /// local channel ID is reused.
    ///
    /// # Errors
    ///
    /// Returns busy for a wrong channel or no active packet, or failed after a
    /// terminal error.
    pub fn close_reply_read_id(
        &self,
        channel: ChannelId,
    ) -> Result<OwnedCloseReplyReadId, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        let Some(ReplyObligation {
            reply: ReplyKind::CloseReply(reply),
            ..
        }) = self.reply_obligations.front()
        else {
            return Err(OwnedChannelError::Busy);
        };
        if reply.channel != channel {
            return Err(OwnedChannelError::Busy);
        }
        let Some(packet) = reply.packet.clone() else {
            return Err(OwnedChannelError::Busy);
        };
        Ok(OwnedCloseReplyReadId { channel, packet })
    }

    /// Reads one packet behind the identified partially written close reply.
    ///
    /// The active close remains the sole protected writer. A PING or
    /// reply-requiring event occupies one separate bounded next-obligation slot;
    /// further reads return busy while it is full. Finish the active close
    /// before driving the promoted reply or PONG. The active channel is marked
    /// locally closed and retired only after its complete reply is written.
    /// Invalid events, including a duplicate close for the active channel,
    /// fail the driver rather than being silently discarded.
    ///
    /// `WouldBlock` retains partial input and the active packet. On
    /// cancellation retain the driver or drop it and separately held socket
    /// handles. Fatal I/O or protocol errors fail the driver. A peer KEXINIT is
    /// retained for [`Self::read_idle`]. [`Self::read_while_pong`] covers
    /// active PONG ciphertext.
    ///
    /// # Errors
    ///
    /// Returns busy for a stale or foreign ID, no active packet or a full next
    /// slot, failed after a terminal error, or a channel or transport error.
    pub fn read_while_close_reply(
        &mut self,
        id: &OwnedCloseReplyReadId,
    ) -> Result<OwnedChannelInbound, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        let Some(ReplyObligation {
            reply: ReplyKind::CloseReply(reply),
            ..
        }) = self.reply_obligations.front()
        else {
            return Err(OwnedChannelError::Busy);
        };
        if reply.channel != id.channel || reply.packet.is_none() {
            return Err(OwnedChannelError::Busy);
        }
        self.read_behind_reply(&id.packet)
    }

    fn read_behind_reply(
        &mut self,
        id: &OwnedPacketId,
    ) -> Result<OwnedChannelInbound, OwnedChannelError> {
        if !self.connection.transport.owns_packet(id) {
            return Err(OwnedChannelError::Busy);
        }
        if let Some(event) = self.take_retained_event() {
            return Ok(OwnedChannelInbound::Event(event));
        }
        let inbound = self.retain_next_owned(id)?;
        Ok(self
            .take_retained_event()
            .map_or(inbound, OwnedChannelInbound::Event))
    }

    fn retain_next_owned(
        &mut self,
        id: &OwnedPacketId,
    ) -> Result<OwnedChannelInbound, OwnedChannelError> {
        if self.retained_event.is_some() {
            return Err(OwnedChannelError::Busy);
        }
        let result = self.connection.transport.read_while_owned(id);
        self.retain_owned_inbound(result)
    }

    /// Returns the identity of the actively written deferred PONG.
    ///
    /// This is available after [`Self::drive_deferred_pong`] returns
    /// `WouldBlock`. It cannot be reused for a later PONG.
    ///
    /// # Errors
    ///
    /// Returns busy when no PONG is actively writing, or failed after a
    /// terminal error.
    pub fn pong_read_id(&self) -> Result<OwnedPongReadId, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if !matches!(
            self.reply_obligations.front().map(|entry| &entry.reply),
            Some(ReplyKind::Pong)
        ) {
            return Err(OwnedChannelError::Busy);
        }
        self.connection
            .transport
            .deferred_pong_read_id()
            .map(OwnedPongReadId)
            .ok_or(OwnedChannelError::Busy)
    }

    /// Reads one authenticated packet behind the identified partial PONG.
    ///
    /// The active PONG remains the sole protected writer. At most one later
    /// PING or reply-requiring event is retained separately; further reads are
    /// busy until the active PONG and that subsequent obligation complete.
    /// The two PONGs retain their exact payloads and wire order.
    ///
    /// `WouldBlock` retains partial input and the active packet. On
    /// cancellation retain the driver or drop it and separately held socket
    /// handles. Fatal I/O or protocol errors fail the driver. A peer KEXINIT is
    /// retained for [`Self::read_idle`].
    ///
    /// # Errors
    ///
    /// Returns busy for a stale or foreign ID, no active PONG or a full next
    /// slot, failed after a terminal error, or a channel or transport error.
    pub fn read_while_pong(
        &mut self,
        id: &OwnedPongReadId,
    ) -> Result<OwnedChannelInbound, OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if !matches!(
            self.reply_obligations.front().map(|entry| &entry.reply),
            Some(ReplyKind::Pong)
        ) {
            return Err(OwnedChannelError::Busy);
        }
        let result = self.connection.transport.read_while_deferred_pong(&id.0);
        self.handle_behind_reply(result)
    }

    fn handle_behind_reply(
        &mut self,
        result: Result<OwnedInbound, TransportError>,
    ) -> Result<OwnedChannelInbound, OwnedChannelError> {
        self.handle_owned_inbound(result)
    }

    fn queue_event_control(&mut self, event: &ChannelEvent) -> Result<(), OwnedChannelError> {
        if !self.event_owes_control(event) {
            return Ok(());
        }
        let reply = match event {
            ChannelEvent::GlobalRequest { .. } => ReplyKind::GlobalFailure(GlobalFailure::Queued),
            ChannelEvent::Request { channel, .. } => ReplyKind::ChannelFailure(ChannelFailure {
                channel: *channel,
                remote: self
                    .connection
                    .remote_channel(*channel)
                    .map_err(OwnedChannelError::Channel)?,
                packet: None,
            }),
            ChannelEvent::OpenRequest(request) => ReplyKind::OpenRejection(OpenRejection {
                remote: request.sender_channel(),
                packet: None,
            }),
            ChannelEvent::Close { channel } => ReplyKind::CloseReply(CloseReply {
                channel: *channel,
                remote: self
                    .connection
                    .remote_channel(*channel)
                    .map_err(OwnedChannelError::Channel)?,
                packet: None,
            }),
            _ => unreachable!("event_owes_control selects only reply-requiring events"),
        };
        let id = self
            .connection
            .transport
            .reserve_owned_control()
            .map_err(OwnedChannelError::Transport)?;
        self.reply_obligations
            .push_back(ReplyObligation { id, reply });
        Ok(())
    }

    fn complete_control(&mut self) -> Result<(), OwnedChannelError> {
        let front = self
            .reply_obligations
            .front()
            .expect("completed reply has a front");
        if let Err(error) = self.connection.transport.complete_owned_control(&front.id) {
            self.failed = true;
            return Err(OwnedChannelError::Transport(error));
        }
        self.reply_obligations.pop_front();
        Ok(())
    }

    /// Refuses a consumed global request that asked for a reply.
    ///
    /// Any admitted data, window adjustment or EOF and deferred pong must
    /// complete first. The
    /// reply occupies at most one protected packet and is retained across
    /// `WouldBlock`. Once it starts, [`Self::read_while_global_failure`] may
    /// read with one bounded next obligation; new data and release remain
    /// blocked until the reply completes. Dropping the driver discards the
    /// connection, not just the obligation. A non-retryable transport error
    /// makes the driver terminal.
    ///
    /// # Errors
    ///
    /// Returns busy when no global failure is owed or earlier work remains,
    /// failed after a terminal error, or a transport error.
    pub fn drive_global_failure(&mut self) -> Result<(), OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if self.pending || self.window_adjustment.is_some() || self.pending_eof.is_some() {
            return Err(OwnedChannelError::Busy);
        }
        let Some(ReplyObligation {
            id: obligation,
            reply: ReplyKind::GlobalFailure(failure),
        }) = self.reply_obligations.front_mut()
        else {
            return Err(OwnedChannelError::Busy);
        };
        if matches!(failure, GlobalFailure::Queued) {
            match self
                .connection
                .transport
                .start_owned_control_packet(obligation, &[SSH_MSG_REQUEST_FAILURE])
            {
                Ok(id) => *failure = GlobalFailure::Writing(id),
                Err(error) => {
                    self.failed = true;
                    return Err(OwnedChannelError::Transport(error));
                }
            }
        }
        let GlobalFailure::Writing(id) = failure else {
            unreachable!("global failure was admitted");
        };
        match self.connection.transport.drive_owned_packet(id) {
            Ok(()) => self.complete_control(),
            Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                Err(OwnedChannelError::Transport(TransportError::Io(error)))
            }
            Err(error) => {
                self.failed = true;
                Err(OwnedChannelError::Transport(error))
            }
        }
    }

    /// Refuses one consumed channel request that asked for a reply.
    ///
    /// `channel` is the local channel from the delivered event. A wrong
    /// channel is rejected without changing the obligation. Data, a window
    /// adjustment, EOF, a deferred pong and any global failure must complete
    /// first. The protected reply is
    /// retained across `WouldBlock`; [`Self::read_while_channel_failure`] may
    /// read with one bounded next obligation once the reply starts. Admission
    /// and release remain blocked until completion. Dropping the driver
    /// discards its connection.
    ///
    /// # Errors
    ///
    /// Returns busy for a wrong channel, missing obligation or earlier work,
    /// failed after a terminal error, or a transport error.
    pub fn drive_channel_failure(&mut self, channel: ChannelId) -> Result<(), OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if self.pending || self.window_adjustment.is_some() || self.pending_eof.is_some() {
            return Err(OwnedChannelError::Busy);
        }
        let Some(ReplyObligation {
            id: obligation,
            reply: ReplyKind::ChannelFailure(failure),
        }) = self.reply_obligations.front_mut()
        else {
            return Err(OwnedChannelError::Busy);
        };
        if failure.channel != channel {
            return Err(OwnedChannelError::Busy);
        }
        if failure.packet.is_none() {
            let mut writer = Writer::new();
            writer.write_byte(SSH_MSG_CHANNEL_FAILURE);
            writer.write_uint32(failure.remote);
            match self
                .connection
                .transport
                .start_owned_control_packet(obligation, &writer.into_bytes())
            {
                Ok(id) => failure.packet = Some(id),
                Err(error) => {
                    self.failed = true;
                    return Err(OwnedChannelError::Transport(error));
                }
            }
        }
        let Some(id) = failure.packet.as_ref() else {
            self.failed = true;
            return Err(OwnedChannelError::Transport(TransportError::InvalidMessage));
        };
        match self.connection.transport.drive_owned_packet(id) {
            Ok(()) => self.complete_control(),
            Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                Err(OwnedChannelError::Transport(TransportError::Io(error)))
            }
            Err(error) => {
                self.failed = true;
                Err(OwnedChannelError::Transport(error))
            }
        }
    }

    /// Rejects the delivered peer open identified by its sender channel.
    ///
    /// `reason` must be one of the four RFC 4254 `SSH_OPEN_*` reason constants.
    /// The description and language are empty SSH strings. After the first
    /// successful admission, retries must use the same reason. A wrong ID or
    /// changed reason is busy; an invalid reason is rejected without consuming
    /// the obligation. Earlier data, deferred pong and control replies must
    /// complete first. Once the reply starts, [`Self::read_while_open_rejection`]
    /// may read with one bounded next obligation. Data admission and release
    /// remain blocked until the entire rejection is written and its pending
    /// open is removed.
    ///
    /// Dropping the driver discards its transport, not just the rejection;
    /// a fatal transport error leaves the driver terminal.
    ///
    /// # Errors
    ///
    /// Returns busy for a wrong ID, changed reason, missing obligation or
    /// earlier work, a channel error for an invalid reason, failed after a
    /// terminal error, or a transport error.
    pub fn drive_open_rejection(
        &mut self,
        remote: ChannelId,
        reason: u32,
    ) -> Result<(), OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if self.pending || self.window_adjustment.is_some() || self.pending_eof.is_some() {
            return Err(OwnedChannelError::Busy);
        }
        let Some(ReplyObligation {
            id: obligation,
            reply: ReplyKind::OpenRejection(rejection),
        }) = self.reply_obligations.front_mut()
        else {
            return Err(OwnedChannelError::Busy);
        };
        if rejection.remote != remote {
            return Err(OwnedChannelError::Busy);
        }
        if !(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED..=SSH_OPEN_RESOURCE_SHORTAGE).contains(&reason) {
            return Err(OwnedChannelError::Channel(ChannelError::InvalidMessage));
        }
        if rejection
            .packet
            .as_ref()
            .is_some_and(|(prior, _)| *prior != reason)
        {
            return Err(OwnedChannelError::Busy);
        }
        if rejection.packet.is_none() {
            let mut writer = Writer::new();
            writer.write_byte(SSH_MSG_CHANNEL_OPEN_FAILURE);
            writer.write_uint32(remote);
            writer.write_uint32(reason);
            writer.write_uint32(0);
            writer.write_uint32(0);
            match self
                .connection
                .transport
                .start_owned_control_packet(obligation, &writer.into_bytes())
            {
                Ok(id) => rejection.packet = Some((reason, id)),
                Err(error) => {
                    self.failed = true;
                    return Err(OwnedChannelError::Transport(error));
                }
            }
        }
        let Some((_, id)) = rejection.packet.as_ref() else {
            self.failed = true;
            return Err(OwnedChannelError::Transport(TransportError::InvalidMessage));
        };
        match self.connection.transport.drive_owned_packet(id) {
            Ok(()) => {
                if self.connection.incoming.remove(&remote).is_none() {
                    self.failed = true;
                    return Err(OwnedChannelError::Channel(ChannelError::UnknownChannel));
                }
                self.complete_control()
            }
            Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                Err(OwnedChannelError::Transport(TransportError::Io(error)))
            }
            Err(error) => {
                self.failed = true;
                Err(OwnedChannelError::Transport(error))
            }
        }
    }

    /// Answers a peer close with one retained `SSH_MSG_CHANNEL_CLOSE`.
    ///
    /// `channel` is the local ID delivered with the close event. A wrong ID,
    /// or a close already answered locally, returns busy without changes.
    /// Earlier data and obligations must complete first. On `WouldBlock`, the
    /// same protected packet remains owned; [`Self::read_while_close_reply`]
    /// may read with one bounded next obligation. Admission and release remain
    /// blocked until the entire reply is written and the channel is marked
    /// locally closed and retired. Dropping the driver discards its transport.
    ///
    /// # Errors
    ///
    /// Returns busy for a wrong ID, absent obligation or earlier work, failed
    /// after a terminal error, or a transport error.
    pub fn drive_close_reply(&mut self, channel: ChannelId) -> Result<(), OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if self.pending || self.window_adjustment.is_some() || self.pending_eof.is_some() {
            return Err(OwnedChannelError::Busy);
        }
        let Some(ReplyObligation {
            id: obligation,
            reply: ReplyKind::CloseReply(reply),
        }) = self.reply_obligations.front_mut()
        else {
            return Err(OwnedChannelError::Busy);
        };
        if reply.channel != channel {
            return Err(OwnedChannelError::Busy);
        }
        if reply.packet.is_none() {
            let mut writer = Writer::new();
            writer.write_byte(SSH_MSG_CHANNEL_CLOSE);
            writer.write_uint32(reply.remote);
            match self
                .connection
                .transport
                .start_owned_control_packet(obligation, &writer.into_bytes())
            {
                Ok(id) => reply.packet = Some(id),
                Err(error) => {
                    self.failed = true;
                    return Err(OwnedChannelError::Transport(error));
                }
            }
        }
        let Some(id) = reply.packet.as_ref() else {
            self.failed = true;
            return Err(OwnedChannelError::Transport(TransportError::InvalidMessage));
        };
        match self.connection.transport.drive_owned_packet(id) {
            Ok(()) => {
                let Some(state) = self.connection.channels.get_mut(&channel) else {
                    self.failed = true;
                    return Err(OwnedChannelError::Channel(ChannelError::UnknownChannel));
                };
                if state.local_close_sent || !state.remote_close_received {
                    self.failed = true;
                    return Err(OwnedChannelError::Channel(ChannelError::InvalidMessage));
                }
                state.local_close_sent = true;
                self.connection.reap_if_fully_closed(channel);
                self.complete_control()
            }
            Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                Err(OwnedChannelError::Transport(TransportError::Io(error)))
            }
            Err(error) => {
                self.failed = true;
                Err(OwnedChannelError::Transport(error))
            }
        }
    }

    /// Writes a pong deferred by [`Self::read_inbound`], [`Self::read_idle`],
    /// [`Self::read_while_window_adjustment`], [`Self::read_while_eof`], or
    /// [`Self::read_while_global_failure`], [`Self::read_while_channel_failure`],
    /// [`Self::read_while_open_rejection`], [`Self::read_while_close_reply`],
    /// or [`Self::read_while_pong`].
    ///
    /// Any admitted data packet, window adjustment, EOF or active global or
    /// channel failure, open rejection or close reply must complete first.
    /// `WouldBlock` preserves the pong and is retryable; once partially
    /// written, [`Self::pong_read_id`] and [`Self::read_while_pong`] permit a
    /// bounded inbound step. The active PONG completes before the one next
    /// PONG or reply is promoted. Any other write failure makes the driver
    /// terminal. A pong is owed only after
    /// [`OwnedChannelInbound::PongDeferred`], and the connection cannot be
    /// released until this succeeds. Global and channel requests have their own
    /// completion paths; an inbound open can be rejected and a peer close
    /// answered after earlier work.
    ///
    /// # Errors
    ///
    /// Returns busy when no pong is owed or an earlier packet is still active,
    /// or a transport error.
    pub fn drive_deferred_pong(&mut self) -> Result<(), OwnedChannelError> {
        if self.failed {
            return Err(OwnedChannelError::Failed);
        }
        if self.pending
            || self.window_adjustment.is_some()
            || self.pending_eof.is_some()
            || !matches!(
                self.reply_obligations.front().map(|entry| &entry.reply),
                Some(ReplyKind::Pong)
            )
        {
            return Err(OwnedChannelError::Busy);
        }
        match self.connection.transport.drive_deferred_pong() {
            Ok(()) => {
                self.reply_obligations.pop_front();
                Ok(())
            }
            Err(TransportError::OwnedPacketState) => Err(OwnedChannelError::Busy),
            Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                Err(OwnedChannelError::Transport(TransportError::Io(error)))
            }
            Err(error) => {
                self.failed = true;
                Err(OwnedChannelError::Transport(error))
            }
        }
    }

    /// Returns whether an inbound event requires a reply.
    fn event_owes_control(&self, event: &ChannelEvent) -> bool {
        match event {
            ChannelEvent::OpenRequest(_) => true,
            ChannelEvent::Close { channel } => self
                .connection
                .channel(*channel)
                .is_some_and(|state| state.remote_close_received() && !state.local_close_sent()),
            ChannelEvent::Request { want_reply, .. }
            | ChannelEvent::GlobalRequest { want_reply, .. } => *want_reply,
            _ => false,
        }
    }

    /// Releases the connection only when no admitted packet, partial inbound
    /// packet, obligation, or failure is outstanding. On refusal, returns the
    /// still-owning driver.
    ///
    /// An admitted data packet can be driven with [`Self::drive`], an admitted
    /// window adjustment with [`Self::drive_window_adjustment`], and an EOF
    /// with [`Self::drive_eof`], unless the driver fails. Any obligation
    /// received behind one of those packets is answered after that packet
    /// completes.
    ///
    /// If [`Self::read_while_global_failure`] or
    /// [`Self::read_while_channel_failure`], [`Self::read_while_open_rejection`],
    /// [`Self::read_while_close_reply`], or [`Self::read_while_pong`] receives a PING or a reply-requiring
    /// event, it retains at most one next
    /// obligation. Complete the active reply first; only then drive the promoted
    /// pong or reply. Further reads are blocked while that next slot is occupied.
    ///
    /// Drive a deferred pong with [`Self::drive_deferred_pong`], a global
    /// failure with [`Self::drive_global_failure`], a channel failure with
    /// [`Self::drive_channel_failure`], an open rejection with
    /// [`Self::drive_open_rejection`], or a peer-close reply with
    /// [`Self::drive_close_reply`]. Release is allowed only after all
    /// outstanding obligations complete and no failure remains.
    ///
    /// A failed driver must be dropped along with its transport. Pre-existing
    /// opens and unanswered closes are refused by
    /// [`Self::try_new`] before the driver takes ownership; a global or channel
    /// request already delivered to the caller is that caller's to answer and is
    /// not tracked by either method.
    #[allow(clippy::result_large_err)] // Returning the bounded owner preserves its public recovery API.
    pub fn try_into_connection(self) -> Result<ChannelConnection<ClientTransport<S>>, Self> {
        let transport = &self.connection.transport;
        let close_owed = self
            .connection
            .channels()
            .any(|channel| channel.remote_close_received() && !channel.local_close_sent());
        if self.pending
            || self.failed
            || self.window_adjustment.is_some()
            || self.pending_eof.is_some()
            || !self.reply_obligations.is_empty()
            || self.retained_event.is_some()
            || self.connection.pending_open_count() != 0
            || close_owed
            || transport.deferred_owned_pong
            || transport.owned_packet.is_some()
            || transport.write_buffer.is_pending()
            || transport.has_partial_protected_read()
            || transport.rekey_active()
        {
            return Err(self);
        }
        Ok(*self.connection)
    }
}

/// How many retired local channel identifiers are remembered.
///
/// Far above any legitimate multiplexing depth, and small enough that the
/// tombstone map is not a growth vector.
pub const MAX_REMEMBERED_CLOSED_CHANNELS: usize = 1_024;

impl<T> ChannelConnection<T> {
    /// Wraps one already authenticated transport.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            channels: std::collections::BTreeMap::new(),
            incoming: std::collections::BTreeMap::new(),
            closed: std::collections::BTreeMap::new(),
            reap_clock: 0,
        }
    }

    /// Returns a read-only reference to the owned transport.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns the sole mutable transport reference.
    ///
    /// Normal channel users should prefer the typed methods on this value. This
    /// accessor remains available to channel-type extensions that need to
    /// exchange a bounded protocol packet on the same serialized transport.
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Returns one open channel's current state.
    #[must_use]
    pub fn channel(&self, channel: ChannelId) -> Option<ChannelState> {
        self.channels.get(&channel).map(Channel::state)
    }

    /// Iterates over copies of all locally addressed channel states in identifier order.
    pub fn channels(&self) -> impl Iterator<Item = ChannelState> {
        self.channels.values().map(Channel::state)
    }

    /// Returns the number of locally addressed open channels.
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Returns the number of received opens awaiting confirmation or rejection.
    #[must_use]
    pub fn pending_open_count(&self) -> usize {
        self.incoming.len()
    }

    /// Returns the number of retired channel identifiers still remembered.
    ///
    /// A non-zero value means at least one channel on this connection has
    /// reached the point RFC 4254 §5.3 calls closed and been dropped from
    /// [`Self::channel`]. It is the observable half of "a closed channel is
    /// dropped", which is otherwise only visible as a freed identifier.
    #[must_use]
    pub fn closed_channel_count(&self) -> usize {
        self.closed.len()
    }

    /// Returns whether one local identifier was retired and not yet reused.
    #[must_use]
    pub fn is_retired_channel(&self, channel: ChannelId) -> bool {
        self.closed.contains_key(&channel)
    }

    /// Returns the always-zero number of buffered data bytes.
    ///
    /// This explicit invariant makes backpressure behavior observable without
    /// retaining payload copies between dispatch calls.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub const fn buffered_data_bytes(&self) -> usize {
        0
    }

    /// Consumes the multiplexer and returns its transport.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.transport
    }
}

impl<T> ChannelConnection<T>
where
    T: ChannelTransport,
{
    /// Allocates the lowest local channel identifier that is free to use.
    ///
    /// An identifier is free when no live channel holds it *and* it is not
    /// still remembered as closed. Skipping the second case is what keeps a
    /// straggler distinguishable: a peer that sends `SSH_MSG_CHANNEL_DATA` for
    /// a channel it has already closed would otherwise have that data delivered
    /// into whichever channel was given the number next. RFC 4254 §5.3 permits
    /// reuse — "the party may then reuse the channel number" — but permits it,
    /// it does not require it, and skipping a bounded window of retired
    /// identifiers costs at most [`MAX_REMEMBERED_CLOSED_CHANNELS`] extra
    /// identifiers while removing the only way a dropped channel's bytes can be
    /// misrouted. OpenSSH does reuse freely, which is why it relies on
    /// `ssh_packet_disconnect` for a message it cannot attribute; this
    /// multiplexer reports the condition instead.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::ChannelIdExhausted`] after every `u32` identifier
    /// has been used.
    pub fn allocate_channel_id(&self) -> Result<ChannelId, ChannelError> {
        for candidate in 0..=u32::MAX {
            if !self.channels.contains_key(&candidate) && !self.closed.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(ChannelError::ChannelIdExhausted)
    }

    /// Sends a channel open with this implementation's standard local limits.
    ///
    /// `type_specific_data` is appended as raw SSH channel-open type-specific
    /// data; it is not wrapped in another string.
    ///
    /// # Errors
    ///
    /// Returns a validation or transport error without registering a channel
    /// when the open cannot be written completely.
    pub fn open_channel(
        &mut self,
        sender_channel: ChannelId,
        channel_type: &[u8],
        type_specific_data: &[u8],
    ) -> Result<(), ChannelError> {
        self.open_channel_with_limits(
            sender_channel,
            channel_type,
            type_specific_data,
            INITIAL_CHANNEL_WINDOW,
            MAX_CHANNEL_PACKET_SIZE,
        )
    }

    /// Sends a channel open with explicit local receive limits.
    ///
    /// `maximum_packet_size` must not exceed [`MAX_CHANNEL_DATA_SIZE`], which
    /// reserves space for channel framing, packet padding, and compression.
    ///
    /// # Errors
    ///
    /// Returns a validation, limit, or transport error. No channel is
    /// registered unless the complete open packet is written.
    pub fn open_channel_with_limits(
        &mut self,
        sender_channel: ChannelId,
        channel_type: &[u8],
        type_specific_data: &[u8],
        initial_window: u32,
        maximum_packet_size: u32,
    ) -> Result<(), ChannelError> {
        validate_channel_name(channel_type)?;
        validate_local_limits(initial_window, maximum_packet_size)?;
        validate_type_specific_size(type_specific_data, maximum_packet_size)?;
        self.ensure_capacity(sender_channel, None)?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_OPEN);
        writer.write_string(channel_type)?;
        writer.write_uint32(sender_channel);
        writer.write_uint32(initial_window);
        writer.write_uint32(maximum_packet_size);
        let mut payload = writer.into_bytes();
        payload.extend_from_slice(type_specific_data);
        if payload.len() > MAX_CHANNEL_MESSAGE_SIZE {
            return Err(ChannelError::MessageTooLarge);
        }
        self.transport
            .write_channel_payload(&payload)
            .map_err(|_error| ChannelError::Transport)?;
        self.channels.insert(
            sender_channel,
            Channel {
                local_id: sender_channel,
                remote_id: None,
                direction: ChannelDirection::OpenedLocally,
                local_window: initial_window,
                remote_window: 0,
                local_maximum_packet_size: maximum_packet_size,
                remote_maximum_packet_size: 0,
                local_eof_sent: false,
                remote_eof_received: false,
                local_close_sent: false,
                remote_close_received: false,
                failed: false,
            },
        );
        Ok(())
    }

    /// Confirms a pending peer open with this implementation's standard limits.
    ///
    /// # Errors
    ///
    /// Returns an unknown, duplicate, invalid-limit, or transport error. The
    /// pending request remains reserved when packet writing fails.
    pub fn confirm_open(
        &mut self,
        remote_channel: ChannelId,
        local_channel: ChannelId,
    ) -> Result<(), ChannelError> {
        self.confirm_open_with_limits(
            remote_channel,
            local_channel,
            INITIAL_CHANNEL_WINDOW,
            MAX_CHANNEL_PACKET_SIZE,
        )
    }

    /// Confirms a pending peer open with explicit local receive limits.
    ///
    /// `maximum_packet_size` must not exceed [`MAX_CHANNEL_DATA_SIZE`], which
    /// reserves space for channel framing, packet padding, and compression.
    ///
    /// # Errors
    ///
    /// Returns an unknown, duplicate, invalid-limit, or transport error. The
    /// pending request remains reserved when packet writing fails.
    pub fn confirm_open_with_limits(
        &mut self,
        remote_channel: ChannelId,
        local_channel: ChannelId,
        initial_window: u32,
        maximum_packet_size: u32,
    ) -> Result<(), ChannelError> {
        validate_local_limits(initial_window, maximum_packet_size)?;
        self.incoming
            .get(&remote_channel)
            .ok_or(ChannelError::UnknownChannel)?;
        self.ensure_capacity(local_channel, Some(remote_channel))?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        writer.write_uint32(remote_channel);
        writer.write_uint32(local_channel);
        writer.write_uint32(initial_window);
        writer.write_uint32(maximum_packet_size);
        self.transport
            .write_channel_payload(&writer.into_bytes())
            .map_err(|_error| ChannelError::Transport)?;
        let pending = self
            .incoming
            .remove(&remote_channel)
            .ok_or(ChannelError::UnknownChannel)?;
        self.channels.insert(
            local_channel,
            Channel {
                local_id: local_channel,
                remote_id: Some(remote_channel),
                direction: ChannelDirection::AcceptedLocally,
                local_window: initial_window,
                remote_window: pending.initial_window,
                local_maximum_packet_size: maximum_packet_size,
                remote_maximum_packet_size: effective_remote_maximum_packet_size(
                    pending.maximum_packet_size,
                ),
                local_eof_sent: false,
                remote_eof_received: false,
                local_close_sent: false,
                remote_close_received: false,
                failed: false,
            },
        );
        Ok(())
    }

    /// Rejects and removes one pending peer channel open.
    ///
    /// # Errors
    ///
    /// Returns an unknown request, invalid description, or transport error. A
    /// transport failure leaves the request pending.
    pub fn reject_open(
        &mut self,
        remote_channel: ChannelId,
        reason: u32,
        description: &[u8],
        language: &[u8],
    ) -> Result<(), ChannelError> {
        if !self.incoming.contains_key(&remote_channel) {
            return Err(ChannelError::UnknownChannel);
        }
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_OPEN_FAILURE);
        writer.write_uint32(remote_channel);
        writer.write_uint32(reason);
        writer.write_string_with_limit(description, MAX_CHANNEL_PACKET_SIZE as usize)?;
        writer.write_string_with_limit(language, MAX_CHANNEL_PACKET_SIZE as usize)?;
        self.transport
            .write_channel_payload(&writer.into_bytes())
            .map_err(|_error| ChannelError::Transport)?;
        self.incoming
            .remove(&remote_channel)
            .ok_or(ChannelError::UnknownChannel)?;
        Ok(())
    }

    /// Reads and routes exactly one complete SSH payload.
    ///
    /// Channel payloads are parsed completely before any window or lifecycle
    /// field is changed. No event is returned for malformed or unknown-channel
    /// input.
    ///
    /// # What this layer tolerates
    ///
    /// An authenticated connection carries more than channels, and the
    /// multiplexing layer has to be the place that knows the difference. The
    /// message numbers treated as connection-level rather than as a defect are
    /// exactly the six that are legal at any time on an established
    /// connection, and each gets the treatment its own section requires:
    ///
    /// * `SSH_MSG_IGNORE` (2), `SSH_MSG_DEBUG` (4) and `SSH_MSG_UNIMPLEMENTED`
    ///   (3) are parsed, bounded, and dropped without producing an event.
    ///   RFC 4253 §11.2 says implementations "MUST understand (and ignore)"
    ///   the first at any time, §11.3 allows them to ignore the second, and
    ///   §11.4 says the third "MUST be otherwise ignored". A caller never
    ///   sees them, so no caller's `match` has to carry a variant the RFC
    ///   permits it to ignore. Malformed framing is still an error, because
    ///   "ignore" describes the message, not a licence to skip validation.
    /// * `SSH_MSG_GLOBAL_REQUEST` (80), `SSH_MSG_REQUEST_SUCCESS` (81) and
    ///   `SSH_MSG_REQUEST_FAILURE` (82) are surfaced as
    ///   [`ChannelEvent::GlobalRequest`], and the two replies as
    ///   [`ChannelEvent::GlobalRequestSucceeded`] or
    ///   [`ChannelEvent::GlobalRequestFailed`]. They are surfaced rather than
    ///   dropped because RFC 4254 §4 requires an answer when "want reply" is
    ///   true, and because whether a request is honoured is a policy decision
    ///   that belongs above the multiplexer — which is also why they are not
    ///   answered here. Use [`Self::send_global_request_success`] and
    ///   [`Self::send_global_request_failure`] to reply.
    ///
    /// Every other message number is still
    /// [`ChannelError::UnexpectedMessage`], and that includes message numbers
    /// this layer *does* own. A `SSH_MSG_CHANNEL_*` it failed to honour, a
    /// transport-layer number, and a user-authentication number are all
    /// errors. Silently discarding a channel message would be a worse defect
    /// than the one this replaces: a client that drops `SSH_MSG_CHANNEL_DATA`
    /// loses data with no signal, where a client that fails says so.
    ///
    /// This is not hypothetical for the tolerated set. A current OpenSSH
    /// server sends `hostkeys-00@openssh.com` as a global request as the first
    /// payload after `SSH_MSG_USERAUTH_SUCCESS` — `sshd` calls
    /// `notify_hostkeys(ssh)` from `do_authenticated`'s caller, immediately
    /// before the session starts — and follows it with `SSH_MSG_DEBUG`.
    /// Neither is a channel message, and both arrive before any channel
    /// exists.
    ///
    /// # Errors
    ///
    /// Returns a transport, wire, unknown-channel, state, flow-control, or
    /// unexpected-message error. A channel-specific violation marks that
    /// channel failed without delivering an event.
    pub fn dispatch_one(&mut self) -> Result<ChannelEvent, ChannelError> {
        // A discarded connection-level message produces no event, so the loop
        // continues to the next payload rather than returning early. This is
        // what makes `SSH_MSG_IGNORE` transparent to every caller instead of a
        // variant each of them has to handle.
        loop {
            if let Some(event) = self.dispatch_payload()? {
                return Ok(event);
            }
        }
    }

    /// Reads one payload and returns its event, or `None` when it carried none.
    ///
    /// This is the legacy read adapter: exactly one transport read, then
    /// exactly one call to [`Self::dispatch_decoded_payload`]. Routing lives in
    /// the helper so it does not depend on how the payload arrived.
    fn dispatch_payload(&mut self) -> Result<Option<ChannelEvent>, ChannelError> {
        let payload = self
            .transport
            .read_channel_payload()
            .map_err(|_error| ChannelError::Transport)?;
        self.dispatch_decoded_payload(&payload)
    }

    /// Parses and routes one already-read payload.
    ///
    /// The payload is parsed completely before any channel state is mutated.
    /// Returns `None` only for a connection-level message that carries no
    /// event.
    fn dispatch_decoded_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<Option<ChannelEvent>, ChannelError> {
        let message = parse_message(payload)?;
        let event = match message {
            ParsedMessage::Open(request) => self.apply_open(request),
            ParsedMessage::Confirmation {
                channel,
                remote_channel,
                remote_window,
                remote_maximum_packet_size,
            } => self.apply_confirmation(
                channel,
                remote_channel,
                remote_window,
                remote_maximum_packet_size,
            ),
            ParsedMessage::OpenFailure {
                channel,
                reason,
                description,
                language,
            } => self.apply_open_failure(channel, reason, description, language),
            ParsedMessage::WindowAdjustment { channel, bytes } => {
                self.apply_window_adjustment(channel, bytes)
            }
            ParsedMessage::Data { channel, data } => self.apply_data(channel, data),
            ParsedMessage::ExtendedData {
                channel,
                data_type_code,
                data,
            } => self.apply_extended_data(channel, data_type_code, data),
            ParsedMessage::Eof { channel } => self.apply_eof(channel),
            ParsedMessage::Close { channel } => self.apply_close(channel),
            ParsedMessage::Request {
                channel,
                request_type,
                want_reply,
                data,
            } => self.apply_request(channel, request_type, want_reply, data),
            ParsedMessage::Reply { channel, success } => {
                let invalid = self
                    .channels
                    .get(&channel)
                    .ok_or_else(|| self.unknown_channel(channel))?
                    .active()
                    .is_err();
                if invalid {
                    return Err(self.fail_channel(channel, ChannelError::InvalidMessage));
                }
                Ok(if success {
                    ChannelEvent::RequestSucceeded { channel }
                } else {
                    ChannelEvent::RequestFailed { channel }
                })
            }
            ParsedMessage::GlobalRequest {
                request_name,
                want_reply,
                data,
            } => Ok(ChannelEvent::GlobalRequest {
                request_name,
                want_reply,
                data,
            }),
            ParsedMessage::GlobalReply { success, data } => Ok(if success {
                ChannelEvent::GlobalRequestSucceeded { data }
            } else {
                ChannelEvent::GlobalRequestFailed { data }
            }),
            // No event: `dispatch_one` reads the next payload instead.
            ParsedMessage::Discarded => return Ok(None),
        }?;
        Ok(Some(event))
    }

    /// Sends `SSH_MSG_REQUEST_SUCCESS` for an earlier global request.
    ///
    /// RFC 4254 §4 requires this whenever the peer set "want reply", and
    /// requires replies to be sent in the order their requests were.
    ///
    /// # Errors
    ///
    /// Returns a wire or transport error.
    pub fn send_global_request_success(&mut self) -> Result<(), ChannelError> {
        self.write_global_reply(SSH_MSG_REQUEST_SUCCESS)
    }

    /// Sends `SSH_MSG_REQUEST_FAILURE` for an earlier global request.
    ///
    /// RFC 4254 §4: "If the recipient does not recognize or support the
    /// request, it simply responds with `SSH_MSG_REQUEST_FAILURE`."
    ///
    /// # Errors
    ///
    /// Returns a wire or transport error.
    pub fn send_global_request_failure(&mut self) -> Result<(), ChannelError> {
        self.write_global_reply(SSH_MSG_REQUEST_FAILURE)
    }

    /// Answers a global request this connection has no policy for.
    ///
    /// RFC 4254 §4 requires an answer whenever the peer set "want reply", and
    /// names the answer for a request the recipient does not support:
    /// `SSH_MSG_REQUEST_FAILURE`. OpenSSH does the same for every request type
    /// it does not recognise — `client_input_global_request` leaves `success`
    /// at zero and replies failure when `want_reply` is set, and its
    /// `server_input_global_request` does the same.
    ///
    /// A request with `want_reply` clear is answered with nothing, because the
    /// RFC only obliges a reply when one was asked for.
    ///
    /// # Errors
    ///
    /// Returns a transport error.
    pub fn refuse_global_request(&mut self, want_reply: bool) -> Result<(), ChannelError> {
        if want_reply {
            self.send_global_request_failure()?;
        }
        Ok(())
    }

    /// Reads payloads until one yields a channel event, or none is left.
    ///
    /// This is the dispatch loop for a layer built on this multiplexer that
    /// has no global-request policy of its own — a session or direct-tcpip
    /// endpoint, say. Such a layer has nothing to do with a connection-level
    /// request, so it cannot surface one in a channel-scoped event, and it must
    /// not fail on one either: a current OpenSSH server sends
    /// `hostkeys-00@openssh.com` before any channel exists. So the request is
    /// answered per RFC 4254 §4 and reading continues.
    ///
    /// `None` means the next call has to read from the transport again, which
    /// is also what happens when only ignorable messages arrived.
    ///
    /// # Errors
    ///
    /// Returns a transport, wire, channel-state, flow-control, or
    /// unexpected-message error.
    pub fn dispatch_channel_event(&mut self) -> Result<Option<ChannelEvent>, ChannelError> {
        loop {
            match self.dispatch_payload()? {
                Some(ChannelEvent::GlobalRequest { want_reply, .. }) => {
                    self.refuse_global_request(want_reply)?;
                }
                // An ignorable RFC 4253 §11 message carries no event, so keep
                // reading rather than reporting an empty dispatch.
                Some(
                    ChannelEvent::GlobalRequestSucceeded { .. }
                    | ChannelEvent::GlobalRequestFailed { .. },
                )
                | None => {}
                other => return Ok(other),
            }
        }
    }

    fn write_global_reply(&mut self, message: u8) -> Result<(), ChannelError> {
        if message != SSH_MSG_REQUEST_SUCCESS && message != SSH_MSG_REQUEST_FAILURE {
            return Err(ChannelError::InvalidMessage);
        }
        self.transport
            .write_channel_payload(&[message])
            .map_err(|_error| ChannelError::Transport)
    }

    /// Writes one complete channel-data packet without buffering it.
    ///
    /// The remote window and maximum packet are validated before any write.
    /// Remote credit is committed only after the transport accepts the packet.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::PacketTooLarge`] or
    /// [`WindowError::Insufficient`] without sending anything when the payload
    /// does not fit. State and transport errors are returned unchanged.
    pub fn write_data(&mut self, channel: ChannelId, data: &[u8]) -> Result<usize, ChannelError> {
        self.write_data_packet(channel, None, data)
    }

    /// Writes one complete extended-data packet without buffering it.
    ///
    /// Extended data shares the channel's receive window and packet-size limits
    /// with ordinary data; the type code is metadata and is not charged as
    /// payload bytes.
    ///
    /// # Errors
    ///
    /// Returns the same channel, state, packet-size, window, or transport
    /// errors as [`Self::write_data`].
    pub fn write_extended_data(
        &mut self,
        channel: ChannelId,
        data_type_code: u32,
        data: &[u8],
    ) -> Result<usize, ChannelError> {
        self.write_data_packet(channel, Some(data_type_code), data)
    }

    fn write_data_packet(
        &mut self,
        channel: ChannelId,
        data_type_code: Option<u32>,
        data: &[u8],
    ) -> Result<usize, ChannelError> {
        let (remote_channel, remote_maximum, remote_window) = {
            let state = self
                .channels
                .get(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            state.writable()?;
            (
                state.remote_id.ok_or(ChannelError::InvalidMessage)?,
                state.remote_maximum_packet_size,
                state.remote_window,
            )
        };
        let requested = data.len();
        let maximum = usize::try_from(remote_maximum)
            .unwrap_or(usize::MAX)
            .min(MAX_CHANNEL_DATA_SIZE);
        if requested > maximum {
            return Err(ChannelError::PacketTooLarge {
                maximum: u32::try_from(maximum).map_err(|_error| ChannelError::MessageTooLarge)?,
                requested,
            });
        }
        let data_length =
            u32::try_from(requested).map_err(|_error| ChannelError::MessageTooLarge)?;
        if data_length > remote_window {
            return Err(ChannelError::Window(WindowError::Insufficient {
                available: remote_window,
                requested,
            }));
        }
        let mut writer = Writer::new();
        writer.write_byte(if data_type_code.is_some() {
            SSH_MSG_CHANNEL_EXTENDED_DATA
        } else {
            SSH_MSG_CHANNEL_DATA
        });
        writer.write_uint32(remote_channel);
        if let Some(data_type_code) = data_type_code {
            writer.write_uint32(data_type_code);
        }
        writer.write_string(data)?;
        self.transport
            .write_channel_payload(&writer.into_bytes())
            .map_err(|_error| ChannelError::Transport)?;
        if let Some(state) = self.channels.get_mut(&channel) {
            state.remote_window -= data_length;
        }
        Ok(requested)
    }

    /// Sends a bounded channel request with type-specific bytes appended raw.
    ///
    /// # Errors
    ///
    /// Returns a name, channel-state, packet-size, wire, or transport error.
    pub fn send_request(
        &mut self,
        channel: ChannelId,
        request_type: &[u8],
        want_reply: bool,
        data: &[u8],
    ) -> Result<(), ChannelError> {
        validate_channel_name(request_type)?;
        let remote_channel = self.remote_channel(channel)?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_REQUEST);
        writer.write_uint32(remote_channel);
        writer.write_string(request_type)?;
        writer.write_boolean(want_reply);
        let mut payload = writer.into_bytes();
        payload.extend_from_slice(data);
        self.write_control(channel, &payload)
    }

    /// Sends `SSH_MSG_CHANNEL_SUCCESS` for an earlier request.
    ///
    /// # Errors
    ///
    /// Returns an unknown, closed, or transport error.
    pub fn send_request_success(&mut self, channel: ChannelId) -> Result<(), ChannelError> {
        let remote_channel = self.remote_channel(channel)?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_SUCCESS);
        writer.write_uint32(remote_channel);
        self.write_control(channel, &writer.into_bytes())
    }

    /// Sends `SSH_MSG_CHANNEL_FAILURE` for an earlier request.
    ///
    /// # Errors
    ///
    /// Returns an unknown, closed, or transport error.
    pub fn send_request_failure(&mut self, channel: ChannelId) -> Result<(), ChannelError> {
        let remote_channel = self.remote_channel(channel)?;
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_FAILURE);
        writer.write_uint32(remote_channel);
        self.write_control(channel, &writer.into_bytes())
    }

    /// Grants the peer more local receive credit with `WINDOW_ADJUST`.
    ///
    /// Local credit changes only after the complete packet is written.
    ///
    /// # Errors
    ///
    /// Returns a zero increment, [`WindowError::AdjustmentOverflow`], channel
    /// state, or transport error without changing the local window.
    pub fn increase_local_window(
        &mut self,
        channel: ChannelId,
        bytes: u32,
    ) -> Result<u32, ChannelError> {
        if bytes == 0 {
            return Err(ChannelError::InvalidWindowAdjustment);
        }
        let (remote_channel, updated) = {
            let state = self
                .channels
                .get(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            state.active()?;
            if state.local_close_sent {
                return Err(ChannelError::InvalidMessage);
            }
            let remote_channel = state.remote_id.ok_or(ChannelError::InvalidMessage)?;
            let updated = state
                .local_window
                .checked_add(bytes)
                .ok_or(ChannelError::Window(WindowError::AdjustmentOverflow {
                    current: state.local_window,
                    increment: bytes,
                }))?;
            (remote_channel, updated)
        };
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_WINDOW_ADJUST);
        writer.write_uint32(remote_channel);
        writer.write_uint32(bytes);
        self.transport
            .write_channel_payload(&writer.into_bytes())
            .map_err(|_error| ChannelError::Transport)?;
        if let Some(state) = self.channels.get_mut(&channel) {
            state.local_window = updated;
        }
        Ok(updated)
    }

    /// Sends one half-close EOF marker.
    ///
    /// # Errors
    ///
    /// Returns an unknown channel, repeated EOF, data-after-EOF state, or
    /// transport error.
    pub fn send_eof(&mut self, channel: ChannelId) -> Result<(), ChannelError> {
        let remote_channel = self.remote_channel(channel)?;
        {
            let state = self
                .channels
                .get(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            state.writable()?;
        }
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_EOF);
        writer.write_uint32(remote_channel);
        self.transport
            .write_channel_payload(&writer.into_bytes())
            .map_err(|_error| ChannelError::Transport)?;
        if let Some(state) = self.channels.get_mut(&channel) {
            state.local_eof_sent = true;
        }
        Ok(())
    }

    /// Sends one channel CLOSE marker.
    ///
    /// A channel marked failed by a protocol error can still be closed, but
    /// cannot send any further data, request, EOF, or window adjustment.
    ///
    /// When the peer has already closed its side, this call completes the
    /// RFC 4254 §5.3 handshake and the channel is dropped from the connection
    /// before this method returns. Re-issuing any per-channel method for it
    /// afterwards returns [`ChannelError::UnknownChannel`]; querying
    /// [`Self::channel`] returns `None`.
    ///
    /// # Errors
    ///
    /// Returns an unknown channel, repeated CLOSE, or transport error.
    pub fn send_close(&mut self, channel: ChannelId) -> Result<(), ChannelError> {
        let remote_channel = self.remote_channel(channel)?;
        {
            let state = self
                .channels
                .get(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            if state.local_close_sent {
                return Err(ChannelError::InvalidMessage);
            }
        }
        let mut writer = Writer::new();
        writer.write_byte(SSH_MSG_CHANNEL_CLOSE);
        writer.write_uint32(remote_channel);
        self.transport
            .write_channel_payload(&writer.into_bytes())
            .map_err(|_error| ChannelError::Transport)?;
        if let Some(state) = self.channels.get_mut(&channel) {
            state.local_close_sent = true;
        }
        self.reap_if_fully_closed(channel);
        Ok(())
    }

    fn remote_channel(&self, channel: ChannelId) -> Result<ChannelId, ChannelError> {
        self.channels
            .get(&channel)
            .ok_or(ChannelError::UnknownChannel)?
            .remote_id
            .ok_or(ChannelError::InvalidMessage)
    }

    /// Records a channel both sides have closed, RFC 4254 §5.3.
    ///
    /// The channel leaves `channels` — that is the whole of the fix — and its
    /// identifier is remembered in `closed` so that a straggler naming it is
    /// reported as [`ChannelError::ClosedChannel`] instead of being routed onto
    /// whichever channel is allocated the number next.
    fn retire_channel(&mut self, channel: ChannelId) {
        self.channels.remove(&channel);
        self.closed.insert(channel, self.reap_clock);
        self.reap_clock = self.reap_clock.wrapping_add(1);
        while self.closed.len() > MAX_REMEMBERED_CLOSED_CHANNELS {
            let Some(oldest) = self
                .closed
                .iter()
                .min_by_key(|(_identifier, retired_at)| *retired_at)
                .map(|(identifier, _retired_at)| *identifier)
            else {
                break;
            };
            self.closed.remove(&oldest);
        }
    }

    /// Reaps one channel if it has crossed the RFC 4254 §5.3 close boundary.
    ///
    /// The boundary is *both* directions, not either. A peer may send
    /// `SSH_MSG_CHANNEL_CLOSE` without having sent or received
    /// `SSH_MSG_CHANNEL_EOF` — the same section says so explicitly — and
    /// `SSH_MSG_CHANNEL_DATA` for a channel can still be in flight when the
    /// local `CLOSE` goes out. Reaping on the local close alone would drop
    /// that data on the floor; RFC 4254 §5.3 asks the opposite, that "all data
    /// sent before this message be delivered to the actual destination".
    fn reap_if_fully_closed(&mut self, channel: ChannelId) {
        let fully_closed = self
            .channels
            .get(&channel)
            .is_some_and(|state| state.local_close_sent && state.remote_close_received);
        if fully_closed {
            self.retire_channel(channel);
        }
    }

    /// Distinguishes a never-seen channel from one both sides have closed.
    fn unknown_channel(&self, channel: ChannelId) -> ChannelError {
        if self.closed.contains_key(&channel) {
            ChannelError::ClosedChannel(channel)
        } else {
            ChannelError::UnknownChannel
        }
    }

    /// Fails before a mutable borrow is taken, for the `get_mut` apply paths.
    fn require_live(&self, channel: ChannelId) -> Result<(), ChannelError> {
        if self.channels.contains_key(&channel) {
            Ok(())
        } else {
            Err(self.unknown_channel(channel))
        }
    }

    fn ensure_capacity(
        &self,
        local_channel: ChannelId,
        remote_channel: Option<ChannelId>,
    ) -> Result<(), ChannelError> {
        if self.channels.contains_key(&local_channel) {
            return Err(ChannelError::DuplicateChannel);
        }
        if self.closed.contains_key(&local_channel) {
            return Err(ChannelError::ClosedChannel(local_channel));
        }
        let replacing_pending =
            remote_channel.is_some_and(|remote| self.incoming.contains_key(&remote));
        let occupied_after = self
            .channels
            .len()
            .saturating_add(self.incoming.len())
            .saturating_sub(usize::from(replacing_pending));
        if occupied_after >= MAX_CHANNELS_PER_CONNECTION {
            return Err(ChannelError::TooManyChannels);
        }
        if let Some(remote) = remote_channel {
            let open_channel_uses_remote = self
                .channels
                .values()
                .any(|channel| channel.remote_id == Some(remote));
            if open_channel_uses_remote {
                return Err(ChannelError::DuplicateChannel);
            }
        }
        Ok(())
    }

    fn remote_channel_in_use(&self, remote: ChannelId) -> bool {
        self.incoming.contains_key(&remote)
            || self
                .channels
                .values()
                .any(|channel| channel.remote_id == Some(remote))
    }

    fn write_control(&mut self, channel: ChannelId, payload: &[u8]) -> Result<(), ChannelError> {
        if payload.len() > MAX_CHANNEL_MESSAGE_SIZE {
            return Err(ChannelError::MessageTooLarge);
        }
        {
            let state = self
                .channels
                .get(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            state.writable()?;
        }
        self.transport
            .write_channel_payload(payload)
            .map_err(|_error| ChannelError::Transport)
    }

    fn apply_open(&mut self, request: ChannelOpenRequest) -> Result<ChannelEvent, ChannelError> {
        if self.channels.len().saturating_add(self.incoming.len()) >= MAX_CHANNELS_PER_CONNECTION {
            return Err(ChannelError::TooManyChannels);
        }
        if self.remote_channel_in_use(request.sender_channel) {
            return Err(ChannelError::DuplicateChannel);
        }
        self.incoming
            .insert(request.sender_channel, request.clone());
        Ok(ChannelEvent::OpenRequest(request))
    }

    /// Applies an inbound `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`.
    ///
    /// The duplicate-remote-identifier guard is scoped to *live* channels and
    /// to opens this side is still holding, which is what makes identifier
    /// reuse work. RFC 4254 §5.3 allows reuse once a party has both sent and
    /// received `SSH_MSG_CHANNEL_CLOSE`, and OpenSSH allocates the lowest free
    /// slot on the connection, so the second session on a connection is
    /// confirmed with the same remote identifier the first one used. A refusal
    /// here is a real protocol error only while the identifier is genuinely
    /// held by another open channel.
    fn apply_confirmation(
        &mut self,
        channel: ChannelId,
        remote_channel: ChannelId,
        remote_window: u32,
        remote_maximum_packet_size: u32,
    ) -> Result<ChannelEvent, ChannelError> {
        if remote_maximum_packet_size == 0
            || remote_maximum_packet_size as usize > MAX_PACKET_CONTENT
        {
            return Err(self.fail_channel(channel, ChannelError::InvalidOpen));
        }
        if self.remote_channel_in_use(remote_channel) {
            return Err(self.fail_channel(channel, ChannelError::DuplicateChannel));
        }
        self.require_live(channel)?;
        let state = self
            .channels
            .get_mut(&channel)
            .ok_or(ChannelError::UnknownChannel)?;
        if state.direction != ChannelDirection::OpenedLocally
            || state.remote_id.is_some()
            || state.failed
            || state.local_close_sent
        {
            return Err(self.fail_channel(channel, ChannelError::InvalidMessage));
        }
        state.remote_id = Some(remote_channel);
        state.remote_window = remote_window;
        state.remote_maximum_packet_size =
            effective_remote_maximum_packet_size(remote_maximum_packet_size);
        Ok(ChannelEvent::Opened(channel))
    }

    fn apply_open_failure(
        &mut self,
        channel: ChannelId,
        reason: u32,
        description: Vec<u8>,
        language: Vec<u8>,
    ) -> Result<ChannelEvent, ChannelError> {
        let state = self
            .channels
            .get(&channel)
            .ok_or_else(|| self.unknown_channel(channel))?;
        if state.direction != ChannelDirection::OpenedLocally
            || state.remote_id.is_some()
            || state.failed
        {
            return Err(self.fail_channel(channel, ChannelError::InvalidMessage));
        }
        self.channels.remove(&channel);
        Ok(ChannelEvent::OpenFailed {
            channel,
            reason,
            description,
            language,
        })
    }

    fn apply_window_adjustment(
        &mut self,
        channel: ChannelId,
        bytes: u32,
    ) -> Result<ChannelEvent, ChannelError> {
        if bytes == 0 {
            return Err(self.fail_channel(channel, ChannelError::InvalidWindowAdjustment));
        }
        let result = {
            let state = self
                .channels
                .get_mut(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            if state.active().is_err() {
                Err(ChannelError::InvalidMessage)
            } else {
                let current = state.remote_window;
                match current.checked_add(bytes) {
                    Some(available) => {
                        state.remote_window = available;
                        Ok(available)
                    }
                    None => Err(ChannelError::Window(WindowError::AdjustmentOverflow {
                        current,
                        increment: bytes,
                    })),
                }
            }
        };
        let available = result.map_err(|error| self.fail_channel(channel, error))?;
        Ok(ChannelEvent::WindowAdjusted { channel, available })
    }

    fn apply_data(
        &mut self,
        channel: ChannelId,
        data: Vec<u8>,
    ) -> Result<ChannelEvent, ChannelError> {
        self.account_received_data(channel, &data)?;
        Ok(ChannelEvent::Data { channel, data })
    }

    fn apply_extended_data(
        &mut self,
        channel: ChannelId,
        data_type_code: u32,
        data: Vec<u8>,
    ) -> Result<ChannelEvent, ChannelError> {
        self.account_received_data(channel, &data)?;
        Ok(ChannelEvent::ExtendedData {
            channel,
            data_type_code,
            data,
        })
    }

    fn account_received_data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
    ) -> Result<(), ChannelError> {
        self.require_live(channel)?;
        let result = {
            let state = self
                .channels
                .get_mut(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            if state.active().is_err() {
                Err(ChannelError::InvalidMessage)
            } else if state.remote_eof_received {
                Err(ChannelError::DataAfterEof)
            } else if data.len() > state.local_maximum_packet_size as usize {
                Err(ChannelError::PacketTooLarge {
                    maximum: state.local_maximum_packet_size,
                    requested: data.len(),
                })
            } else {
                let length =
                    u32::try_from(data.len()).map_err(|_error| ChannelError::MessageTooLarge)?;
                if length > state.local_window {
                    Err(ChannelError::WindowExceeded {
                        available: state.local_window,
                        received: data.len(),
                    })
                } else {
                    state.local_window -= length;
                    Ok(())
                }
            }
        };
        result.map_err(|error| self.fail_channel(channel, error))
    }

    fn apply_eof(&mut self, channel: ChannelId) -> Result<ChannelEvent, ChannelError> {
        self.require_live(channel)?;
        let invalid = {
            let state = self
                .channels
                .get_mut(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            state.active().is_err() || state.remote_eof_received
        };
        if invalid {
            return Err(self.fail_channel(channel, ChannelError::InvalidMessage));
        }
        if let Some(state) = self.channels.get_mut(&channel) {
            state.remote_eof_received = true;
        }
        Ok(ChannelEvent::Eof { channel })
    }

    /// Applies an inbound `SSH_MSG_CHANNEL_CLOSE`.
    ///
    /// RFC 4254 §5.3: "Upon receiving this message, a party MUST send back an
    /// `SSH_MSG_CHANNEL_CLOSE` unless it has already sent this message for the
    /// channel." Reaching the local close earlier is the case where that
    /// MUST does not apply, and it is also the case where the channel crosses
    /// the section's closed boundary and is dropped.
    fn apply_close(&mut self, channel: ChannelId) -> Result<ChannelEvent, ChannelError> {
        self.require_live(channel)?;
        let invalid = {
            let state = self
                .channels
                .get_mut(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            state.failed || state.remote_close_received
        };
        if invalid {
            return Err(self.fail_channel(channel, ChannelError::InvalidMessage));
        }
        if let Some(state) = self.channels.get_mut(&channel) {
            state.remote_close_received = true;
        }
        // The event is built from values captured before the reap, so a caller
        // still learns that the channel closed even though the entry is gone
        // by the time this returns.
        self.reap_if_fully_closed(channel);
        Ok(ChannelEvent::Close { channel })
    }

    /// Applies an inbound `SSH_MSG_CHANNEL_REQUEST`.
    ///
    /// RFC 4254 §6.10 defines exactly two channel requests that a peer sends
    /// after its `SSH_MSG_CHANNEL_EOF`: `exit-status` and `exit-signal`.
    /// `exit-signal` optionally carries a core dump as part of its payload.
    /// Every other request is refused once `remote_eof_received` is set.
    fn apply_request(
        &mut self,
        channel: ChannelId,
        request_type: Vec<u8>,
        want_reply: bool,
        data: Vec<u8>,
    ) -> Result<ChannelEvent, ChannelError> {
        self.require_live(channel)?;
        let result = {
            let state = self
                .channels
                .get_mut(&channel)
                .ok_or(ChannelError::UnknownChannel)?;
            if state.active().is_err()
                || (state.remote_eof_received && !is_request_allowed_after_eof(&request_type))
            {
                Err(ChannelError::InvalidMessage)
            } else if data.len() > state.local_maximum_packet_size as usize {
                Err(ChannelError::PacketTooLarge {
                    maximum: state.local_maximum_packet_size,
                    requested: data.len(),
                })
            } else {
                Ok(())
            }
        };
        result.map_err(|error| self.fail_channel(channel, error))?;
        Ok(ChannelEvent::Request {
            channel,
            request_type,
            want_reply,
            data,
        })
    }

    fn fail_channel(&mut self, channel: ChannelId, error: ChannelError) -> ChannelError {
        if let Some(state) = self.channels.get_mut(&channel) {
            state.failed = true;
        }
        error
    }
}

impl Channel {
    fn state(&self) -> ChannelState {
        ChannelState {
            local_id: self.local_id,
            remote_id: self.remote_id,
            local_window: self.local_window,
            remote_window: self.remote_window,
            local_maximum_packet_size: self.local_maximum_packet_size,
            remote_maximum_packet_size: self.remote_maximum_packet_size,
            local_eof_sent: self.local_eof_sent,
            remote_eof_received: self.remote_eof_received,
            local_close_sent: self.local_close_sent,
            remote_close_received: self.remote_close_received,
            failed: self.failed,
        }
    }
}

enum ParsedMessage {
    Open(ChannelOpenRequest),
    Confirmation {
        channel: ChannelId,
        remote_channel: ChannelId,
        remote_window: u32,
        remote_maximum_packet_size: u32,
    },
    OpenFailure {
        channel: ChannelId,
        reason: u32,
        description: Vec<u8>,
        language: Vec<u8>,
    },
    WindowAdjustment {
        channel: ChannelId,
        bytes: u32,
    },
    Data {
        channel: ChannelId,
        data: Vec<u8>,
    },
    ExtendedData {
        channel: ChannelId,
        data_type_code: u32,
        data: Vec<u8>,
    },
    Eof {
        channel: ChannelId,
    },
    Close {
        channel: ChannelId,
    },
    Request {
        channel: ChannelId,
        request_type: Vec<u8>,
        want_reply: bool,
        data: Vec<u8>,
    },
    Reply {
        channel: ChannelId,
        success: bool,
    },
    /// A connection-level message with no channel event to deliver.
    ///
    /// RFC 4253 §11.2, §11.3 and §11.4 all say the same thing about
    /// `SSH_MSG_IGNORE`, `SSH_MSG_DEBUG` and `SSH_MSG_UNIMPLEMENTED`: the
    /// receiver must understand them and must otherwise ignore them. The
    /// payload was still parsed and bounded, so a malformed one is an error
    /// and a well-formed one is dropped without a caller ever seeing it.
    Discarded,
    /// A global request, RFC 4254 §4.
    GlobalRequest {
        /// The request name, in US-ASCII, as the peer spelled it.
        request_name: Vec<u8>,
        /// Whether the peer requires a reply.
        want_reply: bool,
        /// Bounded request-specific data.
        data: Vec<u8>,
    },
    /// A global-request reply, RFC 4254 §4.
    GlobalReply {
        /// Whether the reply was success or failure.
        success: bool,
        /// Bounded response-specific data.
        data: Vec<u8>,
    },
}

#[allow(clippy::too_many_lines)]
fn parse_message(payload: &[u8]) -> Result<ParsedMessage, ChannelError> {
    let message = payload
        .first()
        .copied()
        .ok_or(ChannelError::InvalidMessage)?;
    let mut reader = Reader::new(&payload[1..]);
    match message {
        SSH_MSG_CHANNEL_OPEN => {
            let channel_type = reader
                .read_string_with_limit(MAX_CHANNEL_NAME_LENGTH)?
                .to_vec();
            if channel_type.is_empty() {
                return Err(ChannelError::InvalidOpen);
            }
            let sender_channel = reader.read_uint32()?;
            let initial_window = reader.read_uint32()?;
            let maximum_packet_size = reader.read_uint32()?;
            if maximum_packet_size == 0 || maximum_packet_size as usize > MAX_PACKET_CONTENT {
                return Err(ChannelError::InvalidOpen);
            }
            validate_type_specific_size(reader.remaining(), maximum_packet_size)?;
            Ok(ParsedMessage::Open(ChannelOpenRequest {
                channel_type,
                sender_channel,
                initial_window,
                maximum_packet_size,
                type_specific_data: reader.remaining().to_vec(),
            }))
        }
        SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
            let channel = reader.read_uint32()?;
            let remote_channel = reader.read_uint32()?;
            let remote_window = reader.read_uint32()?;
            let remote_maximum_packet_size = reader.read_uint32()?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::Confirmation {
                channel,
                remote_channel,
                remote_window,
                remote_maximum_packet_size,
            })
        }
        SSH_MSG_CHANNEL_OPEN_FAILURE => {
            let channel = reader.read_uint32()?;
            let reason = reader.read_uint32()?;
            let description = reader
                .read_string_with_limit(MAX_CHANNEL_PACKET_SIZE as usize)?
                .to_vec();
            let language = reader
                .read_string_with_limit(MAX_CHANNEL_PACKET_SIZE as usize)?
                .to_vec();
            ensure_finished(&reader)?;
            Ok(ParsedMessage::OpenFailure {
                channel,
                reason,
                description,
                language,
            })
        }
        SSH_MSG_CHANNEL_WINDOW_ADJUST => {
            let channel = reader.read_uint32()?;
            let bytes = reader.read_uint32()?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::WindowAdjustment { channel, bytes })
        }
        SSH_MSG_CHANNEL_DATA => {
            let channel = reader.read_uint32()?;
            let data = reader.read_string_with_limit(MAX_PACKET_CONTENT)?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::Data {
                channel,
                data: data.to_vec(),
            })
        }
        SSH_MSG_CHANNEL_EXTENDED_DATA => {
            let channel = reader.read_uint32()?;
            let data_type_code = reader.read_uint32()?;
            let data = reader.read_string_with_limit(MAX_PACKET_CONTENT)?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::ExtendedData {
                channel,
                data_type_code,
                data: data.to_vec(),
            })
        }
        SSH_MSG_CHANNEL_EOF => {
            let channel = reader.read_uint32()?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::Eof { channel })
        }
        SSH_MSG_CHANNEL_CLOSE => {
            let channel = reader.read_uint32()?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::Close { channel })
        }
        SSH_MSG_CHANNEL_REQUEST => {
            let channel = reader.read_uint32()?;
            let request_type = reader
                .read_string_with_limit(MAX_CHANNEL_NAME_LENGTH)?
                .to_vec();
            if request_type.is_empty() {
                return Err(ChannelError::InvalidMessage);
            }
            let want_reply = reader.read_boolean()?;
            if reader.remaining().len() > MAX_PACKET_CONTENT {
                return Err(ChannelError::MessageTooLarge);
            }
            Ok(ParsedMessage::Request {
                channel,
                request_type,
                want_reply,
                data: reader.remaining().to_vec(),
            })
        }
        SSH_MSG_CHANNEL_SUCCESS | SSH_MSG_CHANNEL_FAILURE => {
            let channel = reader.read_uint32()?;
            ensure_finished(&reader)?;
            Ok(ParsedMessage::Reply {
                channel,
                success: message == SSH_MSG_CHANNEL_SUCCESS,
            })
        }
        _ => parse_connection_level(message, &mut reader),
    }
}

/// Parses every message that is legal on an established connection but is not
/// addressed to a channel.
///
/// The three RFC 4253 §11 messages are validated for framing and then
/// discarded, and the three RFC 4254 §4 messages are decoded into variants
/// the caller can match. Anything outside those six numbers is
/// [`ChannelError::UnexpectedMessage`], which keeps a message this layer
/// exists to route — a `SSH_MSG_CHANNEL_*` it did not honour, or a transport
/// or user-authentication number that has no business here — an error rather
/// than something silently swallowed.
fn parse_connection_level(
    message: u8,
    reader: &mut Reader<'_>,
) -> Result<ParsedMessage, ChannelError> {
    match message {
        // RFC 4253 §11.2: "All implementations MUST understand (and ignore)
        // this message at any time (after receiving the identification
        // string)." It is padding a peer sends for traffic-analysis reasons, so
        // it is the one message here that must not reach a caller's match.
        SSH_MSG_IGNORE => {
            let _data = reader.read_string_with_limit(MAX_PACKET_CONTENT)?;
            Ok(ParsedMessage::Discarded)
        }
        // RFC 4253 §11.4: "Such messages MUST be otherwise ignored." The
        // reference is to a message number we sent, which a channel layer
        // cannot act on; the sequence number is read to prove the framing and
        // then discarded, because the transport owns the sequence space.
        SSH_MSG_UNIMPLEMENTED => {
            let _sequence = reader.read_uint32()?;
            ensure_finished(reader)?;
            Ok(ParsedMessage::Discarded)
        }
        // RFC 4253 §11.3: "All implementations MUST understand this message,
        // but they are allowed to ignore it." The payload is bounded and
        // dropped; surfacing it would add a variant every caller's match has
        // to carry for a message the RFC explicitly permits ignoring.
        SSH_MSG_DEBUG => {
            let _always_display = reader.read_boolean()?;
            let _message = reader.read_string_with_limit(MAX_CHANNEL_PACKET_SIZE as usize)?;
            let _language = reader.read_string_with_limit(MAX_CHANNEL_PACKET_SIZE as usize)?;
            Ok(ParsedMessage::Discarded)
        }
        // RFC 4254 §4: a global request affects the whole connection and
        // "both the client and server MAY send global requests at any time".
        // Whether to honour it is policy, so it is surfaced rather than
        // answered here.
        SSH_MSG_GLOBAL_REQUEST => {
            // The name is bounded but not otherwise constrained here. OpenSSH
            // reads a cstring, compares it against the requests it knows, and
            // reports "unsupported request" for anything else including the
            // empty name; refusing an empty name here would be stricter than
            // the peer this layer has to interoperate with, and a peer is
            // entitled to ask about a request that does not exist.
            let request_name = reader
                .read_string_with_limit(MAX_CHANNEL_NAME_LENGTH)?
                .to_vec();
            let want_reply = reader.read_boolean()?;
            Ok(ParsedMessage::GlobalRequest {
                request_name,
                want_reply,
                data: reader.remaining().to_vec(),
            })
        }
        // RFC 4254 §4: "byte SSH_MSG_REQUEST_SUCCESS .... response specific
        // data". The data is opaque and bounded; callers pair the reply with
        // their own outstanding-request queue, which §4 requires to be
        // in-order.
        SSH_MSG_REQUEST_SUCCESS => Ok(ParsedMessage::GlobalReply {
            success: true,
            data: reader.remaining().to_vec(),
        }),
        SSH_MSG_REQUEST_FAILURE => Ok(ParsedMessage::GlobalReply {
            success: false,
            data: reader.remaining().to_vec(),
        }),
        _ => Err(ChannelError::UnexpectedMessage(message)),
    }
}

fn ensure_finished(reader: &Reader<'_>) -> Result<(), ChannelError> {
    if reader.is_empty() {
        Ok(())
    } else {
        Err(ChannelError::InvalidMessage)
    }
}

fn validate_channel_name(name: &[u8]) -> Result<(), ChannelError> {
    if name.is_empty() || name.len() > MAX_CHANNEL_NAME_LENGTH {
        Err(ChannelError::InvalidOpen)
    } else {
        Ok(())
    }
}

fn effective_remote_maximum_packet_size(advertised: u32) -> u32 {
    advertised.min(u32::try_from(MAX_CHANNEL_DATA_SIZE).unwrap_or(u32::MAX))
}

fn validate_local_limits(
    initial_window: u32,
    maximum_packet_size: u32,
) -> Result<(), ChannelError> {
    if initial_window == 0
        || maximum_packet_size == 0
        || maximum_packet_size as usize > MAX_CHANNEL_DATA_SIZE
    {
        Err(ChannelError::InvalidOpen)
    } else {
        Ok(())
    }
}

fn validate_type_specific_size(data: &[u8], maximum_packet_size: u32) -> Result<(), ChannelError> {
    if data.len() > maximum_packet_size as usize || data.len() > MAX_PACKET_CONTENT {
        Err(ChannelError::InvalidOpen)
    } else {
        Ok(())
    }
}

/// The RFC 4254 §6.10 `exit-status` channel request name.
const EXIT_STATUS_REQUEST: &[u8] = b"exit-status";
/// The RFC 4254 §6.10 `exit-signal` channel request name.
const EXIT_SIGNAL_REQUEST: &[u8] = b"exit-signal";

/// Returns whether RFC 4254 §6.10 defines this channel request as arriving
/// after the peer's `SSH_MSG_CHANNEL_EOF`.
///
/// `exit-status` and `exit-signal` are the only two. `exit-signal` optionally
/// carries a core dump, which is part of its payload rather than a separate
/// request.
fn is_request_allowed_after_eof(request_type: &[u8]) -> bool {
    request_type == EXIT_STATUS_REQUEST || request_type == EXIT_SIGNAL_REQUEST
}
