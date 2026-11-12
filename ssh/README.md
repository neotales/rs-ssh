# neotales-ssh

SSH-2 building blocks meant to be forked and patched. `recipes` covers common
paths; every low-level API and policy hook remains public. Helpers do not read
`~/.ssh`, execute local commands, or accept a host key by default.

## Command and script

`recipes::run_command` opens a session, sends the exact `request_exec` bytes,
and pumps `ClientSessions::dispatch_one` until exit-status. `run_script` uses
the same path: the script **is** the command, with no interpreter selected.
Both return `(stdout_bytes, status)`, discard stderr, and buffer stdout without
a size limit. Use a dedicated endpoint; drain EOF/CLOSE afterward through the
low-level API. Set socket deadlines in the application.

```rust,no_run
use neotales_ssh::{ClientConfig, ClientSessions, ClientAuthMethod, authenticate_client};
use neotales_ssh::{hostkey::Ed25519PublicKey, recipes};
use std::net::TcpStream;

fn execute(expected: Ed25519PublicKey, methods: &[ClientAuthMethod])
    -> Result<(), Box<dyn std::error::Error>>
{
    let stream = TcpStream::connect(("example.org", 22))?;
    let mut transport = ClientConfig::new().connect(stream, move |key| {
        if key == &expected { Ok(()) } else { Err("host key mismatch") }
    })?;
    authenticate_client(&mut transport, "user", methods, 3)?;
    let mut sessions = ClientSessions::new(transport);
    let (stdout, status) = recipes::run_command(&mut sessions, b"printf hello")?;
    assert_eq!(status, 0);
    assert_eq!(stdout, b"hello");
    // On a separate endpoint, or after draining the previous channel:
    // recipes::run_script(&mut sessions, b"printf one\nprintf two\n")?;
    Ok(())
}
```

```rust,no_run
use neotales_ssh::{ClientSessions, channel::ChannelTransport, recipes};
fn script<T: ChannelTransport>(sessions: &mut ClientSessions<T>)
    -> Result<(), neotales_ssh::session::SessionError>
{
    let (stdout, status) = recipes::run_script(sessions, b"printf one\nprintf two\n")?;
    assert_eq!((stdout.as_slice(), status), (b"onetwo".as_slice(), 0));
    Ok(())
}
```

`ClientConfig::connect` verifies Ed25519 signatures before asking the required
trust callback. `connect_with_host_keys` supplies trust for other host-key types.
Pins and authentication methods above are application inputs, not loaded files.

## One extra hop

`recipes::jump` wraps `proxy::connect`, requiring exactly one `ProxyJump` entry.
The trust callback is cloned per hop, including the destination. Supply explicit
authentication for both. No `ProxyCommand` is accepted or executed by this helper.

```rust,no_run
use neotales_ssh::{ClientConfig, ClientAuthMethod, hostkey::Ed25519PublicKey, recipes};
use neotales_ssh::proxy::{ProxyClient, ProxyTarget};
use std::net::TcpStream;

fn through_jump(pins: Vec<Ed25519PublicKey>, methods: &[ClientAuthMethod],
    hop_methods: Vec<ClientAuthMethod>) -> Result<ProxyClient<'static>, Box<dyn std::error::Error>>
{
    let target = ProxyTarget::new("destination.example", 22, "user", None, None);
    let mut hop_methods = Some(hop_methods);
    Ok(recipes::jump(&ClientConfig::new(), &target, "user@jump.example:22", methods,
        |host, port| TcpStream::connect((host, port)),
        move |_| hop_methods.take(),
        move |key| if pins.contains(key) { Ok(()) } else { Err("host key mismatch") },
    )?)
}
```

The lower-level `proxy::connect` also supports multiple hops and an explicit
caller-supplied `ProxyCommand` byte-stream opener. It does not execute a command
implicitly. `spawn_proxy_command` is a separate, explicit process-launch hook.

## Local and reverse TCP tunnels

```rust,no_run
use neotales_ssh::tunnel::{LocalListener, ReverseListener};
// ssh -L: the destination is sent to the peer, not resolved/dialed locally.
let local = LocalListener::bind("127.0.0.1", 0, b"destination.example", 80)?;
assert_ne!(local.local_addr()?.port(), 0);
// ssh -R: explicitly authorize this numeric reverse bind.
let mut listener = ReverseListener::bind("127.0.0.1", 0)?;
let bound = listener.local_addr()?;
assert_ne!(bound.port(), 0);
// Application handles requests and accepts through handle_request/poll_accept.
listener.cancel();
drop(local);
# Ok::<(), std::io::Error>(())
```

Both listeners bind only the supplied numeric address, without retries. Each
`poll_accept` accepts at most one ready connection and returns its own `TcpTunnel`:
`LocalListener` opens `direct-tcpip`; `ReverseListener` opens `forwarded-tcpip`.
They remain bound for subsequent connections. Keep and service all returned
copies independently. For reverse forwarding, use `TcpTunnel::connect` on the
other SSH endpoint to dial the explicitly authorized local destination.

This is not a background forwarding service: drive `poll_accept`, reverse
`handle_request`, and each copy's `poll_tcp` / `handle_event` yourself. Dispatch
SSH only when a complete payload is ready; TCP polls do not read SSH, and SSH
writes can still block. Drop/cancel closes the listener and shuts down all its
accepted TCP copies. Continue routing/polling copies to finish SSH CLOSE,
including confirmations arriving after cancellation. EOF preserves half-close.
See `tcpip_forward` for SSH forward requests and `direct_tcpip` for socket-free
local-forward metadata and policy.

## One-file SCP upload and download

`recipes::copy_up` calls `scp::upload`; `copy_down` calls `scp::download`.
Both operate on an **already established SCP byte stream**, not raw SSH packets.
Open a channel and send `ClientSessions::request_scp_upload` or
`request_scp_download`, check acceptance, and bridge its `Data`/`send_data` path to
the byte stream. The caller owns that adapter and channel cleanup.

The required `Fn(u64)` callback gets payload bytes, not headers. The existing
SCP functions transfer the whole in-memory body, so these helpers report the
full length once, after success. There is no hidden progress type.

```rust,no_run
use neotales_ssh::recipes;
use std::io::{Read, Write};

fn transfer<S: Read + Write>(upload_stream: &mut S, download_stream: &mut S)
    -> Result<(), neotales_ssh::scp::ScpError>
{
    recipes::copy_up(upload_stream, "report.txt", b"report", |bytes| {
        println!("uploaded {bytes} bytes");
    })?;
    let file = recipes::copy_down(download_stream, |bytes| {
        println!("downloaded {bytes} bytes");
    })?;
    assert_eq!(file.data, b"report");
    Ok(())
}
```

For explicit modes, timestamps or reusable endpoints use `ScpClient`,
`scp::upload_with_mode`, and `scp::upload_with_time`. Directory transfers use
`scp::upload_directory` / `download_directory` with an in-memory tree.

Disk access is explicit: on Linux, `scp::RootedScpServer::new(stream, root)`
pins a caller-supplied, canonicalized directory. `receive_file(path)` accepts
one upload into that exact path (never the peer's basename); `send_file(path)`
sends one disk file. Neither spawns a process. Directory copy stays in-memory.
Modes/timestamps are validated but not applied; failures can leave partial files.

## SFTP session

`recipes::sftp_session` opens a channel and sends `request_sftp`. It returns a
channel ID, **not** an `SftpClient`: there is no built-in session-channel byte
adapter/multiplexer. The caller still drives the channel, checks request
success, returns window credit, and closes it. `SftpClient::connect` needs the
adapted subsystem byte stream; never pass it the raw SSH transport.

```rust,no_run
use neotales_ssh::{ClientSessions, channel::ChannelTransport, recipes};
use neotales_ssh::session::SessionEvent;
fn subsystem<T: ChannelTransport>(sessions: &mut ClientSessions<T>)
    -> Result<(), neotales_ssh::session::SessionError>
{
    let channel = recipes::sftp_session(sessions)?;
    match sessions.dispatch_one()? {
        SessionEvent::RequestSucceeded { session } if session == channel => {
            // Now bridge this channel's Data/send_data to SftpClient::connect.
            Ok(())
        }
        _ => Err(neotales_ssh::session::SessionError::RequestRejected),
    }
}
```

The low-level names are `ClientSessions::open_session`, `request_subsystem`,
`request_sftp`, `dispatch_one`, `send_data`, and `increase_local_window`.
`SftpServer` stays memory-backed and never accesses disk. The explicit Linux
adapter `sftp::RootedSftpServer::new(stream, root)` supports SFTP v3 OPEN, READ,
WRITE and CLOSE through `SftpClient`. Missing files return a failure status.
Each read/write is bounded by the existing 16 MiB SFTP frame cap (including
framing overhead); SCP disk I/O is streamed in smaller bounded chunks.

Both rooted adapters require Linux `openat2` (Linux 5.6+, permitted by the host's
security policy), with no less-safe fallback. Their APIs compile on other targets,
but constructors return `RootedTransferError::UnsupportedPlatform` without
accessing the filesystem. Paths are relative to the supplied
root; absolute paths must be beneath its canonical path. `..`, symlinks escaping
the root, and special files are rejected. Relative in-root symlinks work;
absolute symlinks are conservatively rejected. Descriptor-relative resolution
prevents symlink-swap escapes. No implicit host root or home directory is used.
The caller controls the root's contents and lifetime; hard links and mounts
already placed inside the root are not a separate sandbox boundary. Open handles
pin files even if their names are later replaced. Do not move open files out of
the root if continued access is unwanted. Writes are not transactional.

## Server

`recipes::serve` is `ServerConfig::connect` plus
`ServerSessions::with_policy`. Policy is required; no shell, child process or
`sshd` starts. User authentication remains explicit before channel dispatch.

```rust,no_run
use neotales_ssh::{ServerConfig, ServerAuthPolicy, authenticate_server, recipes};
use neotales_ssh::hostkey::Ed25519Signer;
use neotales_ssh::session::SessionDecision;
use std::net::TcpListener;

fn server(signer: Ed25519Signer, auth_policy: &ServerAuthPolicy)
    -> Result<(), Box<dyn std::error::Error>>
{
    let listener = TcpListener::bind(("127.0.0.1", 2222))?;
    let (stream, _) = listener.accept()?;
    let config = ServerConfig::new(signer);
    let mut sessions = recipes::serve(&config, stream, |_request| {
        SessionDecision::reject() // Replace with application policy, never a host shell.
    })?;
    authenticate_server(sessions.connection_mut().transport_mut(), auth_policy)?;
    let event = sessions.dispatch_one()?;
    // Application interprets events and sends data/status/EOF/CLOSE explicitly.
    drop(event);
    Ok(())
}
```

## TLS, algorithms, and security keys

This crate does **not speak TLS**. For an expired or untrusted TLS server
certificate in the Docker library, see
`neotales_docker::TlsServerTrust::AllowExpiredOrUntrusted` and
`DockerClient::connect_https_with_trust`. That override is explicit and is not
the default; it is unrelated to SSH host-key trust.

`KexInit` and `with_legacy_algorithms` remain public. RC4/arcfour is rejected,
including with legacy opt-in. Security keys sign and verify **only through
caller callbacks** (`security_key`); callback-based signers are provided, but
there is no USB/device access.

## Fork, patch, verify

Start at `src/recipes.rs` for orchestration, `session.rs` / `channel.rs` for
dispatch, `client/` and `server/` for handshakes, `auth.rs` for authentication,
and `scp.rs` / `sftp.rs` for transfer codecs. Keep low-level hooks public and
test trust and wire behavior, not only paired codec round-trips. See
[`docs/compatibility.md`](docs/compatibility.md) for verified interoperability
and exclusions. README Rust examples are included in the crate's doctests.

From the Cargo workspace `rs/lib`:

```sh
cargo test -p neotales-ssh --lib recipes --offline
cargo test -p neotales-ssh --doc --offline
cargo clippy -p neotales-ssh --all-targets --all-features --offline -- -D warnings
```

Opt-in interoperability tests require `NEOTALES_SSH_E2E=1`; the checks above
do not require or enable them.
