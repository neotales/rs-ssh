//! Thin common-case adapters. All underlying protocol APIs remain public.
//!
//! Callers supply authenticated transports, byte streams, trust and server policy.
//! These helpers never read SSH configuration, start a process, or add peer trust.

use std::io::{self, Read, Write};

use crate::channel::{ChannelId, ChannelTransport};
use crate::hostkey::Ed25519PublicKey;
use crate::proxy::{self, JumpHost, ProxyClient, ProxyError, ProxyTarget};
use crate::scp::{self, ScpError, ScpFile};
use crate::session::{SessionDecision, SessionError, SessionEvent, SessionRequest};
use crate::{
    ClientAuthMethod, ClientConfig, ClientSessions, ServerConfig, ServerSessions, ServerTransport,
};

/// Opens a session and executes the exact command bytes, returning stdout and exit status.
///
/// Use a dedicated, authenticated session endpoint: this pumps its single reader,
/// discards stderr (returning its window credit), and has no output-size limit.
/// Stops at exit-status; the caller still owns the endpoint and drains EOF/CLOSE.
/// Configure transport deadlines externally. Repeating this executes again.
///
/// # Errors
/// Returns session/transport errors, request rejection, or `UnexpectedMessage`
/// if the peer closes or reports an exit signal without an exit status.
pub fn run_command<T: ChannelTransport>(
    sessions: &mut ClientSessions<T>,
    command: &[u8],
) -> Result<(Vec<u8>, u32), SessionError> {
    let session = open_session(sessions)?;
    sessions.request_exec(session, command, true)?;
    let mut stdout = Vec::new();
    loop {
        match sessions.dispatch_one()? {
            SessionEvent::Data {
                session: received,
                data,
            } if received == session => {
                return_credit(sessions, session, data.len())?;
                stdout.extend_from_slice(&data);
            }
            SessionEvent::ExtendedData {
                session: received,
                data,
                ..
            } if received == session => {
                return_credit(sessions, session, data.len())?;
            }
            SessionEvent::ExitStatus {
                session: received,
                status,
            } if received == session => {
                return Ok((stdout, status));
            }
            SessionEvent::RequestFailed { session: received } if received == session => {
                return Err(SessionError::RequestRejected);
            }
            SessionEvent::Close { .. } | SessionEvent::ExitSignal { .. } => {
                return Err(SessionError::UnexpectedMessage);
            }
            SessionEvent::RequestSucceeded { session: received }
            | SessionEvent::WindowAdjusted {
                session: received, ..
            }
            | SessionEvent::Eof { session: received }
                if received == session => {}
            _ => return Err(SessionError::UnexpectedMessage),
        }
    }
}

fn return_credit<T: ChannelTransport>(
    sessions: &mut ClientSessions<T>,
    session: ChannelId,
    bytes: usize,
) -> Result<(), SessionError> {
    if bytes != 0 {
        let credit = u32::try_from(bytes).map_err(|_| SessionError::InvalidRequest)?;
        sessions.increase_local_window(session, credit)?;
    }
    Ok(())
}

fn open_session<T: ChannelTransport>(
    sessions: &mut ClientSessions<T>,
) -> Result<ChannelId, SessionError> {
    let session = sessions.open_session()?;
    match sessions.dispatch_one()? {
        SessionEvent::Opened { session: opened } if opened == session => Ok(session),
        SessionEvent::OpenRejected { .. } => Err(SessionError::RequestRejected),
        _ => Err(SessionError::UnexpectedMessage),
    }
}

/// Executes script bytes as the exec command, without selecting an interpreter.
/// Has the same ownership, buffering and repeat semantics as [`run_command`].
///
/// # Errors
/// Returns the same errors as [`run_command`].
pub fn run_script<T: ChannelTransport>(
    sessions: &mut ClientSessions<T>,
    script: &[u8],
) -> Result<(Vec<u8>, u32), SessionError> {
    run_command(sessions, script)
}

/// Uploads one in-memory file on an already established SCP byte stream.
/// Calls `progress` once with the full payload length after successful transfer:
/// the underlying [`scp::upload`] writes the body as one buffer. No wire/header
/// bytes are counted. The caller opens/execs SCP and closes its channel.
/// A failed transfer can leave a partial remote file; retrying can overwrite it.
///
/// # Errors
/// Returns the same errors as [`scp::upload`].
pub fn copy_up<S: Read + Write>(
    stream: &mut S,
    path: impl AsRef<[u8]>,
    data: &[u8],
    progress: impl Fn(u64),
) -> Result<(), ScpError> {
    scp::upload(stream, path, data, None)?;
    progress(data.len() as u64);
    Ok(())
}

/// Downloads one in-memory file from an established SCP byte stream.
/// Calls `progress` once with the full payload length after successful transfer,
/// since [`scp::download`] reads the complete body. Headers are not counted.
/// The caller sends the SCP exec request and owns channel cleanup.
///
/// # Errors
/// Returns the same errors as [`scp::download`].
pub fn copy_down<S: Read + Write>(
    stream: &mut S,
    progress: impl Fn(u64),
) -> Result<ScpFile, ScpError> {
    let file = scp::download(stream)?;
    progress(file.data.len() as u64);
    Ok(file)
}

/// Opens a session and sends `request_sftp` with a reply requested.
/// Returns the channel ID, not an `SftpClient`: there is no session byte-stream
/// adapter here. The caller drives `dispatch_one`, checks request success, and
/// joins `Data`/`send_data` to its SFTP byte path, returning window credit and
/// closing the channel. Do not hand the raw SSH transport to `SftpClient`.
/// Use a dedicated endpoint while opening; unrelated events are rejected.
///
/// # Errors
/// Returns session open, request encoding or transport errors.
pub fn sftp_session<T: ChannelTransport>(
    sessions: &mut ClientSessions<T>,
) -> Result<ChannelId, SessionError> {
    let session = open_session(sessions)?;
    sessions.request_sftp(session, true)?;
    Ok(session)
}

/// Completes the server handshake and installs a required session policy.
/// Does not authenticate users or start a process. Before dispatching channels,
/// authenticate through the transport accessible via `connection_mut()`.
/// The caller owns the returned endpoint and drives all I/O and cleanup.
///
/// # Errors
/// Returns the same handshake errors as [`ServerConfig::connect`].
pub fn serve<S, F>(
    config: &ServerConfig,
    stream: S,
    policy: F,
) -> Result<ServerSessions<ServerTransport<S>>, crate::server::HandshakeError>
where
    S: Read + Write,
    F: for<'request> Fn(SessionRequest<'request>) -> SessionDecision + 'static,
{
    Ok(ServerSessions::with_policy(config.connect(stream)?, policy))
}

/// Connects through exactly one extra hop using [`proxy::connect`].
/// `hop` is one `ProxyJump` entry, not a list. The required trust callback is
/// cloned for each hop. No `ProxyCommand` is accepted or executed. Destination
/// routing fields come from `destination`; its proxy settings are ignored.
/// The returned client owns both transports; dropping it releases both.
///
/// # Errors
/// Returns route validation, dial, handshake, authentication or channel errors.
pub fn jump<'stream, S, D, A, T, E>(
    config: &ClientConfig,
    destination: &ProxyTarget<'_>,
    hop: &str,
    destination_auth: &[ClientAuthMethod],
    dial: D,
    jump_auth: A,
    trust_host_key: T,
) -> Result<ProxyClient<'stream>, ProxyError>
where
    S: Read + Write + 'stream,
    D: FnMut(&str, u16) -> io::Result<S>,
    A: FnMut(&JumpHost) -> Option<Vec<ClientAuthMethod>>,
    T: Fn(&Ed25519PublicKey) -> Result<(), E> + Clone,
{
    if proxy::parse_jump_list(hop)?.len() != 1 {
        return Err(ProxyError::InvalidJumpHost);
    }
    let target = ProxyTarget::new(
        destination.host(),
        destination.port(),
        destination.user(),
        Some(hop),
        None,
    );
    proxy::connect(
        config,
        &target,
        destination_auth,
        dial,
        None,
        jump_auth,
        trust_host_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Writer;
    use crate::channel::{INITIAL_CHANNEL_WINDOW, MAX_CHANNEL_PACKET_SIZE};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::io::Cursor;

    // Public-contract fixtures: scripted protocol peers avoid a network/server.
    struct Peer {
        incoming: VecDeque<Vec<u8>>,
        outgoing: Vec<Vec<u8>>,
    }

    impl ChannelTransport for Peer {
        fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
            self.incoming.pop_front().ok_or(())
        }

        fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
            self.outgoing.push(payload.to_vec());
            Ok(())
        }
    }

    fn peer() -> Result<Peer, Box<dyn std::error::Error>> {
        let mut opened = Writer::new();
        opened.write_byte(91);
        opened.write_uint32(0);
        opened.write_uint32(42);
        opened.write_uint32(INITIAL_CHANNEL_WINDOW);
        opened.write_uint32(MAX_CHANNEL_PACKET_SIZE);
        let mut data = Writer::new();
        data.write_byte(94);
        data.write_uint32(0);
        data.write_string(b"hello\0")?;
        let mut status = Writer::new();
        status.write_byte(98);
        status.write_uint32(0);
        status.write_string(b"exit-status")?;
        status.write_boolean(false);
        status.write_uint32(23);
        Ok(Peer {
            incoming: [
                opened.into_bytes(),
                vec![99, 0, 0, 0, 0],
                data.into_bytes(),
                status.into_bytes(),
            ]
            .into(),
            outgoing: Vec::new(),
        })
    }

    #[test]
    fn run_command_and_script_preserve_exec_bytes_and_return_status()
    -> Result<(), Box<dyn std::error::Error>> {
        for script in [false, true] {
            let mut sessions = ClientSessions::new(peer()?);
            let command = b"printf 'a'\n# opaque\0\xff";
            let result = if script {
                run_script(&mut sessions, command)?
            } else {
                run_command(&mut sessions, command)?
            };
            assert_eq!(result, (b"hello\0".to_vec(), 23));
            let peer = sessions.into_inner();
            let mut expected = Writer::new();
            expected.write_byte(98);
            expected.write_uint32(42);
            expected.write_string(b"exec")?;
            expected.write_boolean(true);
            expected.write_string(command)?;
            assert_eq!(peer.outgoing[1], expected.into_bytes());
        }
        Ok(())
    }

    #[test]
    fn run_command_reports_missing_status_and_rejection() -> Result<(), Box<dyn std::error::Error>>
    {
        for (reply, expected) in [
            (100, SessionError::RequestRejected),
            (97, SessionError::UnexpectedMessage),
        ] {
            let mut peer = peer()?;
            peer.incoming.truncate(1);
            peer.incoming.push_back(vec![reply, 0, 0, 0, 0]);
            assert_eq!(
                run_command(&mut ClientSessions::new(peer), b"x"),
                Err(expected)
            );
        }
        Ok(())
    }

    struct ScpPeer {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for ScpPeer {
        fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
            self.input.read(data)
        }
    }

    impl Write for ScpPeer {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn copy_progress_counts_only_the_single_file_body() -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = ScpPeer {
            input: Cursor::new(vec![0, 0, 0]),
            output: Vec::new(),
        };
        let counts = RefCell::new(Vec::new());
        copy_up(&mut stream, "file", b"abc", |count| {
            counts.borrow_mut().push(count);
        })?;
        assert_eq!(*counts.borrow(), [3]);
        assert_eq!(stream.output, b"C0644 3 file\nabc\0");
        stream.input = Cursor::new(b"C0644 3 file\nabc\0".to_vec());
        let file = copy_down(&mut stream, |count| counts.borrow_mut().push(count))?;
        assert_eq!(file.data, b"abc");
        assert_eq!(*counts.borrow(), [3, 3]);
        Ok(())
    }
}
