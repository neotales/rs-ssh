//! RFC 4254 section 6.3 X11 framing, with independent default-deny policy.
//!
//! Use these helpers with `ChannelConnection` request/open events. No display,
//! socket, cookie generation, or process environment is consulted. Applications
//! own the grant lifecycle, including single-connection enforcement and cookie
//! replacement. A granted request does not implicitly grant a channel open.
use crate::channel::{
    ChannelConnection, ChannelError, ChannelId, ChannelOpenRequest, ChannelTransport,
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
};
use crate::{Error, Reader, Writer};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Maximum X11 authentication protocol length.
pub const MAX_X11_PROTOCOL: usize = 256;
/// Maximum encoded authentication cookie length.
pub const MAX_X11_COOKIE: usize = 4096;
/// Maximum opaque originator address length.
pub const MAX_X11_ORIGINATOR: usize = 256;

/// Caller-supplied X11 forwarding request. Debug never prints protocol or cookie.
#[derive(Clone, Eq, PartialEq)]
pub struct X11Request {
    single_connection: bool,
    protocol: Vec<u8>,
    cookie: Vec<u8>,
    screen: u32,
}

impl std::fmt::Debug for X11Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X11Request")
            .field("single_connection", &self.single_connection)
            .field("screen", &self.screen)
            .finish_non_exhaustive()
    }
}

impl X11Request {
    /// Copies bounded protocol and hexadecimal cookie strings. Empty values
    /// are permitted by the codec; authorization belongs to application policy.
    ///
    /// # Errors
    /// Rejects oversized strings, NUL, or a non-hexadecimal/odd-length cookie.
    pub fn new(
        single_connection: bool,
        protocol: &[u8],
        cookie: &[u8],
        screen: u32,
    ) -> Result<Self, Error> {
        if protocol.len() > MAX_X11_PROTOCOL || cookie.len() > MAX_X11_COOKIE {
            return Err(Error::LimitExceeded);
        }
        if protocol.contains(&0)
            || !cookie.len().is_multiple_of(2)
            || !cookie.iter().all(u8::is_ascii_hexdigit)
        {
            return Err(Error::InvalidPacket);
        }
        Ok(Self {
            single_connection,
            protocol: protocol.to_vec(),
            cookie: cookie.to_vec(),
            screen,
        })
    }

    /// Whether the caller asks to permit only one connection.
    #[must_use]
    pub const fn single_connection(&self) -> bool {
        self.single_connection
    }
    /// Borrows the protocol bytes. Treat them as sensitive; do not log.
    #[must_use]
    pub fn protocol(&self) -> &[u8] {
        &self.protocol
    }
    /// Borrows the encoded cookie. The library never logs this value.
    #[must_use]
    pub fn cookie(&self) -> &[u8] {
        &self.cookie
    }
    /// Returns the requested screen number.
    #[must_use]
    pub const fn screen(&self) -> u32 {
        self.screen
    }

    /// Encodes only the type-specific `x11-req` data, without channel framing.
    ///
    /// # Errors
    /// Returns a wire encoding error.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::new();
        writer.write_boolean(self.single_connection);
        writer.write_string(&self.protocol)?;
        writer.write_string(&self.cookie)?;
        writer.write_uint32(self.screen);
        Ok(writer.into_bytes())
    }

    /// Decodes exactly one bounded request body before copying its strings.
    ///
    /// # Errors
    /// Rejects truncation, invalid booleans/strings, oversize, and trailing data.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(data);
        let single = reader.read_boolean()?;
        let protocol = reader.read_string_with_limit(MAX_X11_PROTOCOL)?;
        let cookie = reader.read_string_with_limit(MAX_X11_COOKIE)?;
        let screen = reader.read_uint32()?;
        if !reader.is_empty() {
            return Err(Error::InvalidPacket);
        }
        Self::new(single, protocol, cookie, screen)
    }

    /// Explicitly sends `x11-req` on a session. Nothing requests X11 by default.
    ///
    /// # Errors
    /// Returns a wire, channel-state, or transport error.
    pub fn send<T: ChannelTransport>(
        &self,
        channels: &mut ChannelConnection<T>,
        session: ChannelId,
        want_reply: bool,
    ) -> Result<(), ChannelError> {
        channels.send_request(session, b"x11-req", want_reply, &self.encode()?)
    }
}

/// X11 channel originator metadata, not a local display destination.
#[derive(Clone, Eq, PartialEq)]
pub struct X11Open {
    originator: Vec<u8>,
    port: u32,
}
impl std::fmt::Debug for X11Open {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X11Open")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}
impl X11Open {
    /// Validates opaque originator bytes and a TCP port, without resolving them.
    ///
    /// # Errors
    /// Rejects oversized/NUL-containing addresses or ports above 65535.
    pub fn new(originator: &[u8], port: u32) -> Result<Self, Error> {
        if originator.len() > MAX_X11_ORIGINATOR {
            return Err(Error::LimitExceeded);
        }
        if originator.contains(&0) || port > u32::from(u16::MAX) {
            return Err(Error::InvalidPacket);
        }
        Ok(Self {
            originator: originator.to_vec(),
            port,
        })
    }
    /// Borrows the unnormalized originator address.
    #[must_use]
    pub fn originator(&self) -> &[u8] {
        &self.originator
    }
    /// Returns the originator TCP port.
    #[must_use]
    pub const fn port(&self) -> u32 {
        self.port
    }
    /// Decodes exactly the X11 channel type-specific data.
    ///
    /// # Errors
    /// Rejects truncation, oversize, invalid metadata, and trailing data.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(data);
        let address = reader.read_string_with_limit(MAX_X11_ORIGINATOR)?;
        let port = reader.read_uint32()?;
        if !reader.is_empty() {
            return Err(Error::InvalidPacket);
        }
        Self::new(address, port)
    }
    /// Sends an explicit X11 channel open. No display is opened.
    ///
    /// # Errors
    /// Returns wire, channel-allocation, or transport errors.
    pub fn open<T: ChannelTransport>(
        &self,
        channels: &mut ChannelConnection<T>,
    ) -> Result<ChannelId, ChannelError> {
        let mut writer = Writer::new();
        writer.write_string(&self.originator)?;
        writer.write_uint32(self.port);
        let id = channels.allocate_channel_id()?;
        channels.open_channel(id, b"x11", writer.as_bytes())?;
        Ok(id)
    }
}

type RequestPolicy = dyn Fn(ChannelId, &X11Request) -> bool;
type OpenPolicy = dyn Fn(&X11Open) -> bool;
/// Separate explicit request and channel-open policy. Both default to deny;
/// panics deny. Applications must bind these decisions to authorized sessions.
#[derive(Default)]
pub struct X11Policy {
    request: Option<Box<RequestPolicy>>,
    open: Option<Box<OpenPolicy>>,
}
impl std::fmt::Debug for X11Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X11Policy")
            .field("request_configured", &self.request.is_some())
            .field("open_configured", &self.open.is_some())
            .finish()
    }
}
impl X11Policy {
    /// Installs request permission without implicitly accepting channel opens.
    #[must_use]
    pub fn with_request_policy(
        mut self,
        policy: impl Fn(ChannelId, &X11Request) -> bool + 'static,
    ) -> Self {
        self.request = Some(Box::new(policy));
        self
    }
    /// Installs channel-open permission without implicitly accepting requests.
    #[must_use]
    pub fn with_open_policy(mut self, policy: impl Fn(&X11Open) -> bool + 'static) -> Self {
        self.open = Some(Box::new(policy));
        self
    }
    /// Handles data from a channel request event named `x11-req`. The caller
    /// must check that name and the session lifecycle before invoking this.
    /// Returns the policy result and sends a reply only when requested.
    ///
    /// # Errors
    /// Invalid requests never reach policy. Returns decode/channel/I/O errors.
    pub fn handle_request<T: ChannelTransport>(
        &self,
        channels: &mut ChannelConnection<T>,
        session: ChannelId,
        want_reply: bool,
        data: &[u8],
    ) -> Result<bool, ChannelError> {
        let request = X11Request::decode(data)?;
        let accepted = self.request.as_ref().is_some_and(|policy| {
            catch_unwind(AssertUnwindSafe(|| policy(session, &request))).unwrap_or(false)
        });
        if want_reply {
            if accepted {
                channels.send_request_success(session)?;
            } else {
                channels.send_request_failure(session)?;
            }
        }
        Ok(accepted)
    }
    /// Validates an `x11` open, asks policy, then confirms or denies it. Returns
    /// a local channel id only when accepted. Subsequent traffic is opaque.
    ///
    /// # Errors
    /// Invalid metadata never reaches policy. Returns decode/channel/I/O errors.
    pub fn handle_open<T: ChannelTransport>(
        &self,
        channels: &mut ChannelConnection<T>,
        request: &ChannelOpenRequest,
    ) -> Result<Option<ChannelId>, ChannelError> {
        if request.channel_type() != b"x11" {
            return Err(ChannelError::InvalidOpen);
        }
        let metadata = X11Open::decode(request.type_specific_data())?;
        let accepted = self.open.as_ref().is_some_and(|policy| {
            catch_unwind(AssertUnwindSafe(|| policy(&metadata))).unwrap_or(false)
        });
        if !accepted {
            channels.reject_open(
                request.sender_channel(),
                SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                b"X11 denied",
                b"",
            )?;
            return Ok(None);
        }
        let id = channels.allocate_channel_id()?;
        channels.confirm_open(request.sender_channel(), id)?;
        Ok(Some(id))
    }
}
