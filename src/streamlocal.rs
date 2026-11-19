//! OpenSSH PROTOCOL 2.4 streamlocal framing and explicit application policy.
//!
//! These helpers share the channel multiplexer. They never open, reserve, or
//! listen on a socket. The application owns any endpoint and binding lifecycle.
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::channel::{
    ChannelConnection, ChannelError, ChannelId, ChannelOpenRequest, ChannelTransport,
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
};
use crate::{Error, Reader, Writer};

/// Maximum opaque streamlocal path length in bytes.
pub const MAX_STREAMLOCAL_PATH: usize = 4096;
/// Direct streamlocal channel name.
pub const DIRECT_STREAMLOCAL: &[u8] = b"direct-streamlocal@openssh.com";
/// Reverse streamlocal channel name.
pub const FORWARDED_STREAMLOCAL: &[u8] = b"forwarded-streamlocal@openssh.com";
/// Reverse binding request name.
pub const STREAMLOCAL_FORWARD: &[u8] = b"streamlocal-forward@openssh.com";
/// Reverse binding cancellation name.
pub const CANCEL_STREAMLOCAL_FORWARD: &[u8] = b"cancel-streamlocal-forward@openssh.com";

/// Operation submitted to explicit policy. Validation does not authorize it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Open a direct opaque channel.
    Direct,
    /// Accept a reverse opaque channel.
    Forwarded,
    /// Application must reserve a reverse endpoint before accepting.
    Forward,
    /// Application must cancel the named reverse endpoint before accepting.
    Cancel,
}

/// Validated opaque path; no UTF-8, normalization, or filesystem access.
#[derive(Clone, Eq, PartialEq)]
pub struct StreamlocalPath(Vec<u8>);

impl std::fmt::Debug for StreamlocalPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamlocalPath")
            .field("length", &self.0.len())
            .finish()
    }
}

impl StreamlocalPath {
    /// Copies a nonempty path after validating its bound and absence of NUL.
    ///
    /// # Errors
    /// Rejects empty, NUL-containing, or oversized paths without copying them.
    pub fn new(path: &[u8]) -> Result<Self, Error> {
        if path.len() > MAX_STREAMLOCAL_PATH {
            return Err(Error::LimitExceeded);
        }
        if path.is_empty() || path.contains(&0) {
            return Err(Error::InvalidPacket);
        }
        Ok(Self(path.to_vec()))
    }

    /// Borrows the unchanged opaque path bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Opens a direct or reverse channel with empty reserved fields.
    ///
    /// # Errors
    /// Rejects non-channel operations and channel allocation or transport errors.
    pub fn open<T: ChannelTransport>(
        &self,
        channels: &mut ChannelConnection<T>,
        operation: Operation,
    ) -> Result<ChannelId, ChannelError> {
        let name = match operation {
            Operation::Direct => DIRECT_STREAMLOCAL,
            Operation::Forwarded => FORWARDED_STREAMLOCAL,
            _ => return Err(ChannelError::InvalidOpen),
        };
        let mut writer = Writer::new();
        writer.write_string(&self.0)?;
        writer.write_string(b"")?;
        if operation == Operation::Direct {
            writer.write_uint32(0);
        }
        let id = channels.allocate_channel_id()?;
        channels.open_channel(id, name, writer.as_bytes())?;
        Ok(id)
    }

    /// Sends a reverse binding request or cancel. Nothing is sent by default.
    ///
    /// # Errors
    /// Rejects non-global operations and wire or transport errors.
    pub fn request<T: ChannelTransport>(
        &self,
        channels: &mut ChannelConnection<T>,
        operation: Operation,
        want_reply: bool,
    ) -> Result<(), ChannelError> {
        let name = match operation {
            Operation::Forward => STREAMLOCAL_FORWARD,
            Operation::Cancel => CANCEL_STREAMLOCAL_FORWARD,
            _ => return Err(ChannelError::InvalidMessage),
        };
        let mut writer = Writer::new();
        writer.write_byte(80);
        writer.write_string(name)?;
        writer.write_boolean(want_reply);
        writer.write_string(&self.0)?;
        channels
            .transport_mut()
            .write_channel_payload(writer.as_bytes())
            .map_err(|()| ChannelError::Transport)
    }
}

/// Default-deny streamlocal policy. Panicking callbacks deny. The application
/// must apply its own per-user binding rules and endpoint lifecycle; allowing
/// `Forward` alone does not authorize a later `Forwarded` open.
#[derive(Default)]
pub struct StreamlocalPolicy {
    callback: Option<Box<Allow>>,
}
type Allow = dyn Fn(Operation, &StreamlocalPath) -> bool;

impl std::fmt::Debug for StreamlocalPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamlocalPolicy")
            .field("configured", &self.callback.is_some())
            .finish()
    }
}

impl StreamlocalPolicy {
    /// Installs explicit permission. No endpoints are opened by this policy.
    #[must_use]
    pub fn new(callback: impl Fn(Operation, &StreamlocalPath) -> bool + 'static) -> Self {
        Self {
            callback: Some(Box::new(callback)),
        }
    }

    fn allows(&self, operation: Operation, path: &StreamlocalPath) -> bool {
        self.callback.as_ref().is_some_and(|callback| {
            catch_unwind(AssertUnwindSafe(|| callback(operation, path))).unwrap_or(false)
        })
    }

    /// Validates a received streamlocal open, asks policy, then confirms or
    /// rejects it. Returns the local id only when accepted. Reserved fields
    /// are parsed but ignored as required by OpenSSH PROTOCOL 2.4.
    ///
    /// # Errors
    /// Rejects malformed metadata before invoking policy, or channel/I/O errors.
    pub fn handle_open<T: ChannelTransport>(
        &self,
        channels: &mut ChannelConnection<T>,
        request: &ChannelOpenRequest,
    ) -> Result<Option<ChannelId>, ChannelError> {
        let operation = match request.channel_type() {
            DIRECT_STREAMLOCAL => Operation::Direct,
            FORWARDED_STREAMLOCAL => Operation::Forwarded,
            _ => return Err(ChannelError::InvalidOpen),
        };
        let mut reader = Reader::new(request.type_specific_data());
        let path = StreamlocalPath::new(reader.read_string_with_limit(MAX_STREAMLOCAL_PATH)?)?;
        reader.read_string_with_limit(MAX_STREAMLOCAL_PATH)?;
        if operation == Operation::Direct {
            reader.read_uint32()?;
        }
        if !reader.is_empty() {
            return Err(ChannelError::InvalidOpen);
        }
        if !self.allows(operation, &path) {
            channels.reject_open(
                request.sender_channel(),
                SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                b"streamlocal denied",
                b"",
            )?;
            return Ok(None);
        }
        let id = channels.allocate_channel_id()?;
        channels.confirm_open(request.sender_channel(), id)?;
        Ok(Some(id))
    }

    /// Handles a decoded global-request event's name and data. The callback
    /// must complete any binding/cancel effect before returning true. Replies
    /// follow `want_reply`; no binding state or socket is hidden in this helper.
    ///
    /// # Errors
    /// Rejects unknown names, invalid paths, trailing data, and transport errors.
    pub fn handle_global<T: ChannelTransport>(
        &self,
        channels: &mut ChannelConnection<T>,
        name: &[u8],
        want_reply: bool,
        data: &[u8],
    ) -> Result<bool, ChannelError> {
        let operation = match name {
            STREAMLOCAL_FORWARD => Operation::Forward,
            CANCEL_STREAMLOCAL_FORWARD => Operation::Cancel,
            _ => return Err(ChannelError::InvalidMessage),
        };
        let mut reader = Reader::new(data);
        let path = StreamlocalPath::new(reader.read_string_with_limit(MAX_STREAMLOCAL_PATH)?)?;
        if !reader.is_empty() {
            return Err(ChannelError::InvalidMessage);
        }
        let allowed = self.allows(operation, &path);
        if want_reply {
            if allowed {
                channels.send_global_request_success()?;
            } else {
                channels.send_global_request_failure()?;
            }
        }
        Ok(allowed)
    }
}
