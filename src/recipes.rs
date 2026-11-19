//! Thin common-case adapters. All underlying protocol APIs remain public.
//!
//! These helpers never start a process or add peer trust.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::rc::Rc;

use crate::channel::{ChannelId, ChannelTransport};
use crate::hostkey::Ed25519PublicKey;
use crate::proxy::{self, JumpHost, ProxyClient, ProxyError, ProxyTarget};
use crate::scp::{self, ScpError, ScpFile};
use crate::session::{SessionDecision, SessionError, SessionEvent, SessionRequest};
use crate::{
    ClientAuthMethod, ClientConfig, ClientSessions, ServerConfig, ServerSessions, ServerTransport,
};

/// An authenticated connection for sequential common-case operations.
/// No background reader is started; operations may block on the peer.
pub struct SshClient<T: ChannelTransport = crate::ClientTransport<TcpStream>> {
    sessions: ClientSessions<T>,
}

impl<T: ChannelTransport> std::fmt::Debug for SshClient<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SshClient").finish_non_exhaustive()
    }
}

/// Error returned by the convenience client.
pub type ClientError = Box<dyn std::error::Error>;

/// Configuration for a convenience client. Clones share explicitly supplied
/// authentication methods, but independently own their configuration.
#[derive(Clone, Debug, Default)]
pub struct SshClientBuilder {
    host: Option<String>,
    username: Option<String>,
    port: Option<u16>,
    methods: Vec<AuthChoice>,
    pin: Option<Vec<u8>>,
    known_hosts: Option<String>,
    known_hosts_path: Option<std::path::PathBuf>,
}

#[derive(Clone, Debug)]
enum AuthChoice {
    Method(Rc<ClientAuthMethod>),
    Agent,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn parse_destination(value: &str) -> Result<(Option<&str>, &str, u16), ClientError> {
    let (user, address) = match value.split_once('@') {
        Some((user, address)) => (Some(user), address),
        None => (None, value),
    };
    if user == Some("") || address.is_empty() || address.contains('@') {
        return Err(invalid("username and host required").into());
    }
    let (host, port) = if let Some(rest) = address.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| invalid("invalid IPv6 host"))?;
        host.parse::<std::net::Ipv6Addr>()
            .map_err(|_| invalid("invalid IPv6 host"))?;
        let port = if tail.is_empty() {
            22
        } else {
            tail.strip_prefix(':')
                .ok_or_else(|| invalid("invalid port"))?
                .parse::<u16>()
                .map_err(|_| invalid("invalid port"))?
        };
        (host, port)
    } else if let Some((host, port)) = address.split_once(':') {
        (
            host,
            port.parse::<u16>().map_err(|_| invalid("invalid port"))?,
        )
    } else {
        (address, 22)
    };
    if host.is_empty() || port == 0 || host.contains(['[', ']']) {
        return Err(invalid("invalid host or port").into());
    }
    Ok((user, host, port))
}

fn default_username() -> Result<String, ClientError> {
    let names: &[&str] = if cfg!(windows) {
        &["USERNAME"]
    } else {
        &["USER", "LOGNAME"]
    };
    names
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|value| !value.is_empty())
        .ok_or_else(|| invalid("current process username unavailable; specify user@host").into())
}

impl SshClientBuilder {
    /// Sets the destination host.
    #[must_use]
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }
    /// Sets the login name.
    #[must_use]
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }
    /// Sets the destination port (default 22).
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }
    /// Appends an explicit authentication method.
    #[must_use]
    pub fn method(mut self, method: ClientAuthMethod) -> Self {
        self.methods.push(AuthChoice::Method(Rc::new(method)));
        self
    }

    /// Appends authentication methods in iteration order.
    #[must_use]
    pub fn methods(mut self, methods: impl IntoIterator<Item = ClientAuthMethod>) -> Self {
        self.methods
            .extend(methods.into_iter().map(|m| AuthChoice::Method(Rc::new(m))));
        self
    }

    /// Appends a password method whose value is redacted and zeroized.
    #[must_use]
    pub fn password(self, secret: impl Into<String>) -> Self {
        self.method(ClientAuthMethod::password(secret))
    }

    /// Reads one unencrypted OpenSSH or PKCS#8 DER identity.
    ///
    /// # Errors
    /// Returns an I/O or invalid-key error.
    pub fn identity_file(self, path: impl AsRef<std::path::Path>) -> Result<Self, ClientError> {
        self.import_identity(path.as_ref(), &mut [])
    }

    /// Reads one encrypted OpenSSH identity, wiping the passphrase copy.
    ///
    /// # Errors
    /// Returns an I/O or invalid-key error, including for a wrong passphrase.
    pub fn identity_file_with_passphrase(
        self,
        path: impl AsRef<std::path::Path>,
        passphrase: impl AsRef<[u8]>,
    ) -> Result<Self, ClientError> {
        let mut passphrase = zeroize::Zeroizing::new(passphrase.as_ref().to_vec());
        self.import_identity(path.as_ref(), &mut passphrase)
    }

    fn import_identity(
        self,
        path: &std::path::Path,
        passphrase: &mut [u8],
    ) -> Result<Self, ClientError> {
        let bytes = zeroize::Zeroizing::new(std::fs::read(path)?);
        let decoded = if bytes.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----") {
            let text = std::str::from_utf8(&bytes).map_err(|_| invalid("invalid OpenSSH key"))?;
            let body = text
                .strip_prefix("-----BEGIN OPENSSH PRIVATE KEY-----")
                .and_then(|s| s.trim().strip_suffix("-----END OPENSSH PRIVATE KEY-----"))
                .ok_or_else(|| invalid("invalid OpenSSH key"))?;
            let encoded = zeroize::Zeroizing::new(
                body.chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect::<String>(),
            );
            Some(zeroize::Zeroizing::new(
                crate::known_hosts::decode_base64(&encoded)
                    .map_err(|_| invalid("invalid OpenSSH key"))?,
            ))
        } else {
            None
        };
        let key = decoded
            .as_deref()
            .map_or(bytes.as_slice(), |v| v.as_slice());
        let signer = if key.starts_with(b"openssh-key-v1\0") || decoded.is_some() {
            crate::private_key::import_openssh(key, passphrase)?
        } else {
            crate::private_key::import_pkcs8_der(key)?
        };
        Ok(self.method(ClientAuthMethod::public_key(signer)))
    }

    /// Enables or disables default-agent authentication without removing other methods.
    /// If the agent is unavailable, explicitly supplied methods remain usable.
    #[must_use]
    pub fn agent(mut self, enabled: bool) -> Self {
        if enabled {
            if !self.methods.iter().any(|m| matches!(m, AuthChoice::Agent)) {
                self.methods.push(AuthChoice::Agent);
            }
        } else {
            self.methods.retain(|m| !matches!(m, AuthChoice::Agent));
        }
        self
    }
    /// Pins an SSH-format Ed25519 host key; takes precedence over known hosts.
    #[must_use]
    pub fn pin(mut self, blob: impl AsRef<[u8]>) -> Self {
        self.pin = Some(blob.as_ref().to_vec());
        self
    }
    /// Sets known-hosts document text.
    #[must_use]
    pub fn known_hosts(mut self, text: impl Into<String>) -> Self {
        self.known_hosts = Some(text.into());
        self.known_hosts_path = None;
        self
    }
    /// Sets a known-hosts document path, read only during build.
    #[must_use]
    pub fn known_hosts_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.known_hosts_path = Some(path.into());
        self.known_hosts = None;
        self
    }

    /// Connects and authenticates. No unknown host key is accepted.
    ///
    /// # Errors
    /// Returns validation, agent, trust, network, handshake or authentication errors.
    pub fn build(self) -> Result<SshClient, ClientError> {
        let host = self
            .host
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid("host required"))?;
        let username = self
            .username
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid("username required"))?;
        let port = self.port.unwrap_or(22);
        if port == 0 {
            return Err(invalid("invalid port").into());
        }
        if self.methods.is_empty() {
            return Err(invalid("authentication methods required").into());
        }
        let mut resolved = Vec::new();
        let has_explicit = self
            .methods
            .iter()
            .any(|m| matches!(m, AuthChoice::Method(_)));
        for choice in &self.methods {
            match choice {
                AuthChoice::Method(method) => resolved.push(Rc::clone(method)),
                AuthChoice::Agent => match default_agent_methods() {
                    Ok(methods) => resolved.extend(methods.into_iter().map(Rc::new)),
                    Err(_) if has_explicit => {}
                    Err(error) => return Err(error),
                },
            }
        }
        let pin = self
            .pin
            .as_deref()
            .map(Ed25519PublicKey::from_blob)
            .transpose()?;
        let known_hosts = if pin.is_some() {
            None
        } else {
            let text = if let Some(text) = self.known_hosts {
                text
            } else if let Some(path) = self.known_hosts_path {
                std::fs::read_to_string(path).map_err(|_| {
                    io::Error::other("known_hosts unavailable; builder pin required")
                })?
            } else {
                return Err(invalid("known_hosts or builder pin required").into());
            };
            Some(crate::KnownHosts::parse(&text)?)
        };
        let stream = TcpStream::connect((host, port))?;
        let config = ClientConfig::new();
        let mut transport = if let Some(pin) = pin {
            config.connect(stream, |key| if *key == pin { Ok(()) } else { Err(()) })?
        } else {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            config.connect_with_known_hosts(stream, known_hosts.as_ref().ok_or_else(|| invalid("builder pin required"))?, host, port, now)
                .map_err(|error| io::Error::other(format!("host verification failed or handshake failed ({error}); builder pin required if host is not trusted")))?
        };
        // Public-key authentication consumes one attempt for the query and one
        // for the signed request, including for the last agent identity.
        let mut authenticator = crate::auth::ClientAuthenticator::new(
            &mut transport,
            username,
            resolved.len().saturating_mul(2),
        )?;
        authenticator.authenticate_refs(resolved.iter().map(Rc::as_ref))?;
        Ok(SshClient {
            sessions: ClientSessions::new(transport),
        })
    }
}

#[cfg(unix)]
fn default_agent_methods() -> Result<Vec<ClientAuthMethod>, ClientError> {
    let path = std::env::var_os("SSH_AUTH_SOCK")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| io::Error::other("SSH agent unavailable: SSH_AUTH_SOCK is not set"))?;
    let client = crate::agent::connect_unix(path)
        .map_err(|e| io::Error::other(format!("SSH agent unavailable: {e}")))?;
    agent_methods(client, std::os::unix::net::UnixStream::try_clone)
}

#[cfg(windows)]
fn default_agent_methods() -> Result<Vec<ClientAuthMethod>, ClientError> {
    let client = crate::agent::connect_pipe(r"\\.\pipe\openssh-ssh-agent")
        .map_err(|e| io::Error::other(format!("SSH agent unavailable: {e}")))?;
    agent_methods(client, std::fs::File::try_clone)
}

#[cfg(not(any(unix, windows)))]
fn default_agent_methods() -> Result<Vec<ClientAuthMethod>, ClientError> {
    Err(io::Error::other("SSH agent unavailable on this platform").into())
}

#[cfg(any(unix, windows))]
fn agent_methods<T: Read + Write + Send + 'static>(
    mut client: crate::agent::AgentClient<T>,
    clone_stream: impl Fn(&T) -> io::Result<T>,
) -> Result<Vec<ClientAuthMethod>, ClientError> {
    let identities = client
        .identities()
        .map_err(|e| io::Error::other(format!("SSH agent unavailable: {e}")))?;
    let stream = client.into_inner();
    let mut methods = Vec::new();
    for identity in identities {
        let client = crate::agent::AgentClient::new(clone_stream(&stream)?);
        if let Ok(signer) = crate::AgentKeySigner::new(client, &identity.key_blob) {
            methods.push(ClientAuthMethod::agent(signer));
        }
    }
    if methods.is_empty() {
        return Err(io::Error::other("SSH agent has no supported identities").into());
    }
    Ok(methods)
}

impl SshClient<crate::ClientTransport<TcpStream>> {
    /// Opens a destination using the current process user when omitted, the
    /// default agent, and the existing known-hosts file.
    ///
    /// # Errors
    /// Rejects invalid destinations, unavailable agents, unknown hosts and connection failures.
    pub fn open(destination: &str) -> Result<Self, ClientError> {
        let (username, host, port) = parse_destination(destination)?;
        let username = match username {
            Some(username) => username.to_owned(),
            None => default_username()?,
        };
        let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .ok_or_else(|| io::Error::other("known_hosts unavailable; builder pin required"))?;
        Self::builder()
            .username(username)
            .host(host)
            .port(port)
            .agent(true)
            .known_hosts_path(
                std::path::PathBuf::from(home)
                    .join(".ssh")
                    .join("known_hosts"),
            )
            .build()
    }

    /// Creates an independently cloneable client configuration.
    #[must_use]
    pub fn builder() -> SshClientBuilder {
        SshClientBuilder::default()
    }

    /// Dials and authenticates with a required SSH-format Ed25519 key blob.
    /// `None` selects port 22. No configuration or credentials are loaded.
    /// The pin is checked only after the server signature has been verified.
    ///
    /// # Errors
    /// Rejects empty methods, invalid pins, dial, handshake and authentication failures.
    pub fn open_pinned(
        host: &str,
        port: Option<u16>,
        username: &str,
        methods: &[ClientAuthMethod],
        pinned_ed25519_blob: &[u8],
    ) -> Result<Self, ClientError> {
        if methods.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "authentication methods required",
            )
            .into());
        }
        let pin = Ed25519PublicKey::from_blob(pinned_ed25519_blob)?;
        let stream = TcpStream::connect((host, port.unwrap_or(22)))?;
        let mut transport = ClientConfig::new()
            .connect(stream, |key| if *key == pin { Ok(()) } else { Err(()) })?;
        crate::authenticate_client(
            &mut transport,
            username,
            methods,
            methods.len().saturating_mul(2),
        )?;
        Ok(Self {
            sessions: ClientSessions::new(transport),
        })
    }
}

impl<T: ChannelTransport> SshClient<T> {
    /// Opens a session channel borrowing this connection.
    ///
    /// # Errors
    /// Returns session or transport errors.
    pub fn session(&mut self) -> Result<SshSession<'_, T>, SessionError> {
        let session = open_session(&mut self.sessions)?;
        Ok(SshSession {
            sessions: &mut self.sessions,
            session,
            closed: false,
        })
    }

    /// Executes command bytes, discarding stderr, and returns buffered stdout and status.
    ///
    /// # Errors
    /// Returns session, request or transport errors.
    pub fn exec(&mut self, command: &[u8]) -> Result<(Vec<u8>, u32), SessionError> {
        self.session()?.exec(command)
    }

    /// Executes the exact script bytes without selecting an interpreter.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::exec`].
    pub fn script(&mut self, bytes: &[u8]) -> Result<(Vec<u8>, u32), SessionError> {
        self.exec(bytes)
    }

    /// Uploads one in-memory file and reports payload bytes after success.
    /// Failure may leave a partial remote file; retrying may overwrite it.
    ///
    /// # Errors
    /// Returns channel, SCP or transport errors.
    pub fn upload(
        &mut self,
        path: impl AsRef<[u8]>,
        bytes: &[u8],
        progress: impl Fn(u64),
    ) -> Result<(), ClientError> {
        let session = open_session(&mut self.sessions)?;
        self.sessions.request_scp_upload(session, &path, true)?;
        accepted(&mut self.sessions, session)?;
        let mut stream = SessionStream::new(&mut self.sessions, session);
        copy_up(&mut stream, path, bytes, progress)?;
        stream.finish()?;
        Ok(())
    }

    /// Downloads one in-memory file and reports payload bytes after success.
    ///
    /// # Errors
    /// Returns channel, SCP or transport errors.
    pub fn download(
        &mut self,
        path: impl AsRef<[u8]>,
        progress: impl Fn(u64),
    ) -> Result<Vec<u8>, ClientError> {
        let session = open_session(&mut self.sessions)?;
        self.sessions.request_scp_download(session, path, true)?;
        accepted(&mut self.sessions, session)?;
        let mut stream = SessionStream::new(&mut self.sessions, session);
        let data = copy_down(&mut stream, progress)?.data;
        stream.finish()?;
        Ok(data)
    }

    /// Opens an SFTP subsystem borrowing this client until the returned client is dropped.
    ///
    /// # Errors
    /// Returns channel, subsystem or SFTP negotiation errors.
    pub fn sftp(&mut self) -> Result<crate::sftp::SftpClient<SessionStream<'_, T>>, ClientError> {
        let session = sftp_session(&mut self.sessions)?;
        accepted(&mut self.sessions, session)?;
        Ok(crate::sftp::SftpClient::connect(SessionStream::new(
            &mut self.sessions,
            session,
        ))?)
    }
}

/// A single session channel borrowing an authenticated client.
/// Dropping an unused session closes it and may block on the peer.
pub struct SshSession<'a, T: ChannelTransport = crate::ClientTransport<TcpStream>> {
    sessions: &'a mut ClientSessions<T>,
    session: ChannelId,
    closed: bool,
}

impl<T: ChannelTransport> std::fmt::Debug for SshSession<'_, T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SshSession").finish_non_exhaustive()
    }
}

impl<T: ChannelTransport> SshSession<'_, T> {
    /// Executes one command and closes the session, returning stdout and status.
    ///
    /// # Errors
    /// Returns session, request or transport errors.
    pub fn exec(mut self, command: &[u8]) -> Result<(Vec<u8>, u32), SessionError> {
        let session = self.session;
        self.sessions.request_exec(session, command, true)?;
        let mut output = Vec::new();
        let status = loop {
            match self.sessions.dispatch_one()? {
                SessionEvent::Data { session: id, data } if id == session => {
                    return_credit(self.sessions, session, data.len())?;
                    output.extend(data);
                }
                SessionEvent::ExtendedData {
                    session: id, data, ..
                } if id == session => {
                    return_credit(self.sessions, session, data.len())?;
                }
                SessionEvent::ExitStatus {
                    session: id,
                    status,
                } if id == session => break status,
                SessionEvent::RequestSucceeded { session: id }
                | SessionEvent::WindowAdjusted { session: id, .. }
                | SessionEvent::Eof { session: id }
                    if id == session => {}
                SessionEvent::RequestFailed { session: id } if id == session => {
                    return Err(SessionError::RequestRejected);
                }
                _ => return Err(SessionError::UnexpectedMessage),
            }
        };
        self.closed = true;
        close_session(self.sessions, session)?;
        Ok((output, status))
    }
}

impl<T: ChannelTransport> Drop for SshSession<'_, T> {
    fn drop(&mut self) {
        if !self.closed {
            let _ = close_session(self.sessions, self.session);
        }
    }
}

fn accepted<T: ChannelTransport>(
    sessions: &mut ClientSessions<T>,
    session: ChannelId,
) -> Result<(), SessionError> {
    match sessions.dispatch_one()? {
        SessionEvent::RequestSucceeded { session: received } if session == received => Ok(()),
        SessionEvent::RequestFailed { session: received } if session == received => {
            Err(SessionError::RequestRejected)
        }
        _ => Err(SessionError::UnexpectedMessage),
    }
}

/// A session-channel byte stream borrowed from a convenience client.
pub struct SessionStream<'a, T: ChannelTransport> {
    sessions: &'a mut ClientSessions<T>,
    session: ChannelId,
    incoming: VecDeque<u8>,
    eof: bool,
    finished: bool,
}

impl<T: ChannelTransport> std::fmt::Debug for SessionStream<'_, T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionStream")
            .finish_non_exhaustive()
    }
}

impl<'a, T: ChannelTransport> SessionStream<'a, T> {
    fn new(sessions: &'a mut ClientSessions<T>, session: ChannelId) -> Self {
        Self {
            sessions,
            session,
            incoming: VecDeque::new(),
            eof: false,
            finished: false,
        }
    }

    fn finish(&mut self) -> Result<(), SessionError> {
        self.finished = true;
        close_session(self.sessions, self.session)
    }

    fn dispatch(&mut self) -> io::Result<()> {
        match self.sessions.dispatch_one().map_err(io::Error::other)? {
            SessionEvent::Data { session, data } if session == self.session => {
                self.incoming.extend(data);
            }
            SessionEvent::ExtendedData { session, data, .. } if session == self.session => {
                return_credit(self.sessions, session, data.len()).map_err(io::Error::other)?;
            }
            SessionEvent::WindowAdjusted { session, .. } if session == self.session => {}
            SessionEvent::Eof { session } | SessionEvent::Close { session }
                if session == self.session =>
            {
                self.eof = true;
            }
            SessionEvent::ExitStatus { session, .. } if session == self.session => {}
            _ => return Err(io::Error::other(SessionError::UnexpectedMessage)),
        }
        Ok(())
    }
}

impl<T: ChannelTransport> Drop for SessionStream<'_, T> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish();
        }
    }
}

fn close_session<T: ChannelTransport>(
    sessions: &mut ClientSessions<T>,
    session: ChannelId,
) -> Result<(), SessionError> {
    sessions.send_close(session)?;
    loop {
        match sessions.dispatch_one()? {
            SessionEvent::Close { session: id } if id == session => return Ok(()),
            SessionEvent::Data { session: id, data }
            | SessionEvent::ExtendedData {
                session: id, data, ..
            } if id == session => return_credit(sessions, session, data.len())?,
            SessionEvent::ExitStatus { session: id, .. }
            | SessionEvent::Eof { session: id }
            | SessionEvent::WindowAdjusted { session: id, .. }
                if id == session => {}
            _ => return Err(SessionError::UnexpectedMessage),
        }
    }
}

impl<T: ChannelTransport> Read for SessionStream<'_, T> {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if target.is_empty() {
            return Ok(0);
        }
        while self.incoming.is_empty() {
            if self.eof {
                return Ok(0);
            }
            self.dispatch()?;
        }
        let count = target.len().min(self.incoming.len());
        return_credit(self.sessions, self.session, count).map_err(io::Error::other)?;
        for byte in &mut target[..count] {
            *byte = self
                .incoming
                .pop_front()
                .ok_or_else(|| io::Error::other("missing channel byte"))?;
        }
        Ok(count)
    }
}

impl<T: ChannelTransport> Write for SessionStream<'_, T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let state = self
                .sessions
                .connection()
                .channel(self.session)
                .ok_or_else(|| io::Error::other(SessionError::UnexpectedMessage))?;
            let count = bytes
                .len()
                .min(state.remote_window() as usize)
                .min(state.remote_maximum_packet_size() as usize)
                .min(crate::channel::MAX_CHANNEL_DATA_SIZE);
            if count > 0 {
                return self
                    .sessions
                    .send_data(self.session, &bytes[..count])
                    .map_err(io::Error::other);
            }
            if self.eof || state.remote_maximum_packet_size() == 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
            }
            self.dispatch()?;
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

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

    #[test]
    fn destination_parsing() -> Result<(), ClientError> {
        assert_eq!(parse_destination("example.org")?, (None, "example.org", 22));
        assert_eq!(
            parse_destination("example.org:2222")?,
            (None, "example.org", 2222)
        );
        assert_eq!(parse_destination("user@host")?, (Some("user"), "host", 22));
        assert_eq!(
            parse_destination("user@host:22")?,
            (Some("user"), "host", 22)
        );
        assert_eq!(
            parse_destination("user@example.org:2222")?,
            (Some("user"), "example.org", 2222)
        );
        assert_eq!(parse_destination("[::1]")?, (None, "::1", 22));
        assert_eq!(parse_destination("[::1]:2222")?, (None, "::1", 2222));
        assert_eq!(
            parse_destination("user@[::1]:2222")?,
            (Some("user"), "::1", 2222)
        );
        for value in [
            "",
            "@host",
            "user@",
            "host@",
            ":22",
            "host:bad",
            "user@host:no",
            "user@host:0",
            "user@::1",
        ] {
            assert!(parse_destination(value).is_err(), "{value}");
        }
        Ok(())
    }

    #[test]
    fn builder_clone_is_independent() {
        let original = SshClient::builder()
            .host("example.org")
            .username("user")
            .port(22)
            .pin(b"key");
        let changed = original.clone().port(2222);
        assert_eq!(original.port, Some(22));
        assert_eq!(changed.port, Some(2222));
        assert_eq!(original.pin, changed.pin);
        assert_eq!(original.host, changed.host);
    }

    #[test]
    fn builder_password_is_redacted_and_clone_appends_independently() {
        let original = SshClient::builder().password("test-secret").agent(true);
        let changed = original.clone().password("other-secret");
        assert_eq!(original.methods.len(), 2);
        assert_eq!(changed.methods.len(), 3);
        assert!(
            matches!(&original.methods[0], AuthChoice::Method(m) if matches!(m.as_ref(), ClientAuthMethod::Password(_)))
        );
        assert!(matches!(&original.methods[1], AuthChoice::Agent));
        assert!(!format!("{changed:?}").contains("secret"));
    }

    #[test]
    fn identity_file_missing_fails() {
        let path = std::env::temp_dir()
            .join(format!("neotales-missing-{}", std::process::id()))
            .join("identity");
        let result = SshClient::builder().identity_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn agent_order_and_explicit_methods_are_preserved() {
        let builder = SshClient::builder()
            .agent(true)
            .password("a")
            .agent(true)
            .method(ClientAuthMethod::None)
            .methods(vec![ClientAuthMethod::password("b")]);
        assert!(matches!(builder.methods[0], AuthChoice::Agent));
        assert!(
            matches!(&builder.methods[1], AuthChoice::Method(m) if matches!(m.as_ref(), ClientAuthMethod::Password(_)))
        );
        assert!(
            matches!(&builder.methods[2], AuthChoice::Method(m) if matches!(m.as_ref(), ClientAuthMethod::None))
        );
        assert_eq!(builder.methods.len(), 4);
        assert_eq!(builder.agent(false).methods.len(), 3);
    }

    #[test]
    fn pinned_builder_authenticates_public_key() -> Result<(), ClientError> {
        let _serial = crate::test_serial::port_and_spawn();
        let host_signer = crate::hostkey::Ed25519Signer::from_seed(&mut [7; 32]);
        let pin = host_signer.public_key().to_blob()?;
        let user_signer = crate::hostkey::Ed25519Signer::from_seed(&mut [8; 32]);
        let user_key = user_signer.public_key().to_blob()?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let server = std::thread::spawn(move || -> Result<(), String> {
            let run = || -> Result<(), ClientError> {
                let (stream, _) = listener.accept()?;
                stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
                let mut transport = ServerConfig::new(host_signer).accept(stream)?;
                let policy = crate::ServerAuthPolicy::new(4)?.with_authorized_key(&user_key)?;
                crate::authenticate_server(&mut transport, &policy)?;
                Ok(())
            };
            run().map_err(|error| error.to_string())
        });
        let method =
            ClientAuthMethod::public_key(crate::auth::PublicKeySigner::Ed25519(user_signer));
        let client = SshClient::builder()
            .host("127.0.0.1")
            .port(port)
            .username("user")
            .methods(vec![method])
            .pin(pin)
            .build();
        assert!(client.is_ok(), "{client:?}");
        assert_eq!(
            server
                .join()
                .map_err(|_| io::Error::other("server panicked"))?,
            Ok(())
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn current_user_defaults() -> Result<(), ClientError> {
        const CHILD: &str = "NEOTALES_SSH_USER_TEST_CHILD";
        if let Ok(expected) = std::env::var(CHILD) {
            if expected == "missing" {
                assert!(
                    default_username()
                        .unwrap_err()
                        .to_string()
                        .contains("username unavailable")
                );
            } else {
                assert_eq!(default_username()?, expected);
            }
            return Ok(());
        }
        let _serial = crate::test_serial::port_and_spawn();
        for (user, logname, expected) in [
            ("first", "second", "first"),
            ("", "second", "second"),
            ("", "", "missing"),
        ] {
            let status = std::process::Command::new(std::env::current_exe()?)
                .arg("--exact")
                .arg("recipes_impl::tests::current_user_defaults")
                .env("USER", user)
                .env("LOGNAME", logname)
                .env(CHILD, expected)
                .status()?;
            assert!(status.success());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn string_open_without_agent_does_not_dial() -> Result<(), ClientError> {
        const CHILD: &str = "NEOTALES_SSH_NO_AGENT_CHILD";
        if let Some(port) = std::env::var_os(CHILD) {
            let error =
                SshClient::open(&format!("127.0.0.1:{}", port.to_string_lossy())).unwrap_err();
            assert!(error.to_string().contains("agent unavailable"), "{error}");
            return Ok(());
        }
        let _serial = crate::test_serial::port_and_spawn();
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let status = std::process::Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("recipes_impl::tests::string_open_without_agent_does_not_dial")
            .env_remove("SSH_AUTH_SOCK")
            .env("USER", "test-user")
            .env(CHILD, listener.local_addr()?.port().to_string())
            .status()?;
        assert!(status.success());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        Ok(())
    }

    #[test]
    fn owned_client_rejects_empty_auth_before_dial() {
        assert!(SshClient::open_pinned("invalid.invalid", None, "user", &[], b"").is_err());
    }

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
    fn client_and_session_exec_close_the_channel() -> Result<(), Box<dyn std::error::Error>> {
        for explicit_session in [false, true] {
            let mut peer = peer()?;
            peer.incoming.push_back(vec![97, 0, 0, 0, 0]);
            let mut client = SshClient {
                sessions: ClientSessions::new(peer),
            };
            let result = if explicit_session {
                client.session()?.exec(b"hello")?
            } else {
                client.exec(b"hello")?
            };
            assert_eq!(result, (b"hello\0".to_vec(), 23));
            let peer = client.sessions.into_inner();
            assert_eq!(peer.outgoing.last(), Some(&vec![97, 0, 0, 0, 42]));
        }
        Ok(())
    }

    // A full authenticated SSH peer is an unreasonable fixture for this adapter.
    #[test]
    fn owned_client_scp_round_trip_over_scripted_channels() -> Result<(), Box<dyn std::error::Error>>
    {
        fn scripted(data: &[u8]) -> Result<Peer, Box<dyn std::error::Error>> {
            let mut peer = peer()?;
            peer.incoming.truncate(2);
            let mut packet = Writer::new();
            packet.write_byte(94);
            packet.write_uint32(0);
            packet.write_string(data)?;
            peer.incoming.push_back(packet.into_bytes());
            peer.incoming.push_back(vec![97, 0, 0, 0, 0]);
            Ok(peer)
        }
        let counts = RefCell::new(Vec::new());
        let mut upload = SshClient {
            sessions: ClientSessions::new(scripted(&[0, 0, 0])?),
        };
        upload.upload("file", b"abc", |n| counts.borrow_mut().push(n))?;
        let peer = upload.sessions.into_inner();
        let wire = peer.outgoing.concat();
        assert!(
            wire.windows(b"C0644 3 file\n".len())
                .any(|part| part == b"C0644 3 file\n")
        );
        assert!(wire.windows(3).any(|part| part == b"abc"));
        let mut download = SshClient {
            sessions: ClientSessions::new(scripted(b"C0644 3 file\nabc\0")?),
        };
        assert_eq!(
            download.download("file", |n| counts.borrow_mut().push(n))?,
            b"abc"
        );
        assert_eq!(*counts.borrow(), [3, 3]);
        Ok(())
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
