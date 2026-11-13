# neotales-ssh

SSH-2 building blocks meant to be forked and patched. `SshClient` covers common
paths; every low-level API and policy hook remains public. Helpers do not execute
local commands or accept a host key by default.

`SshClient::open` takes a destination string. No user means the current process
user, no port means 22, authentication tries the default `ssh-agent`, and an
unknown host key is rejected.

## Opening a connection

The builder is for anything the destination string cannot express: an explicit
pin, or a port you set per copy.

```rust,no_run
use neotales_ssh::SshClient;
fn example() -> Result<(), Box<dyn std::error::Error>> {
    let _client = SshClient::open("example.org")?;
    Ok(())
}
```

Password and host pin:

```rust,no_run
use neotales_ssh::SshClient;
fn example(pin: &[u8], password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _client = SshClient::builder().host("example.org").username("user").pin(pin).password(password).build()?;
    Ok(())
}
```

Identity file:

```rust,no_run
use neotales_ssh::SshClient;
use std::path::Path;
fn example(pin: &[u8], path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let _client = SshClient::builder().host("example.org").username("user").pin(pin).identity_file(path)?.build()?;
    Ok(())
}
```

Encrypted identity file:

```rust,no_run
use neotales_ssh::SshClient;
use std::path::Path;
fn example(pin: &[u8], path: &Path, passphrase: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _client = SshClient::builder().host("example.org").username("user").pin(pin).identity_file_with_passphrase(path, passphrase)?.build()?;
    Ok(())
}
```

OpenSSH identity parsing accepts RSA component magnitudes up to 8192 bits
(1024 bytes) each, including the modulus, exponents, coefficient and primes.
Larger components are rejected as invalid key data before RSA integer
conversion and validation; this applies to plaintext and encrypted containers.

Clone and change only the port:

```rust,no_run
use neotales_ssh::SshClient;
fn example(pin: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let builder = SshClient::builder().host("example.org").username("user").agent(true).pin(pin);
    let alternate_port = builder.clone().port(2222);
    let _client = alternate_port.build()?;
    Ok(())
}
```

## Command

```rust,no_run
use neotales_ssh::SshClient;

fn example() -> Result<(), Box<dyn std::error::Error>> {
    // example.org is port 22 and the current user.
    // user@example.org:2222 sets both.
    let mut ssh = SshClient::open("user@example.org:2222")?;
    let (stdout, status) = ssh.exec(b"printf hello")?;
    assert_eq!((stdout.as_slice(), status), (b"hello".as_slice(), 0));
    Ok(())
}
```

Output is buffered and stderr is discarded; `status` is the remote exit code. Set
network deadlines at the lower level when you need them.

## Script

```rust,no_run
use neotales_ssh::SshClient;

fn example() -> Result<(), Box<dyn std::error::Error>> {
    let mut ssh = SshClient::open("user@example.org:2222")?;
    let (stdout, status) = ssh.script(b"printf one\nprintf two\n")?;
    assert_eq!((stdout.as_slice(), status), (b"onetwo".as_slice(), 0));
    Ok(())
}
```

The bytes are sent as an exact command string: no interpreter is selected and no
local shell runs.

## Upload

```rust,no_run
use neotales_ssh::SshClient;

fn example() -> Result<(), Box<dyn std::error::Error>> {
    let mut ssh = SshClient::open("user@example.org:2222")?;
    ssh.upload("report.txt", b"report", |bytes| println!("uploaded {bytes}"))?;
    Ok(())
}
```

Progress counts payload bytes only, and a failed upload may leave a partial
remote file.

## Download

```rust,no_run
use neotales_ssh::SshClient;

fn example() -> Result<(), Box<dyn std::error::Error>> {
    let mut ssh = SshClient::open("user@example.org:2222")?;
    let bytes = ssh.download("report.txt", |bytes| println!("downloaded {bytes}"))?;
    assert_eq!(bytes, b"report");
    Ok(())
}
```

The file is held in memory; the whole payload arrives before the call returns.

## SFTP

```rust,no_run
use neotales_ssh::{sftp, SshClient};

fn example() -> Result<(), Box<dyn std::error::Error>> {
    let mut ssh = SshClient::open("user@example.org:2222")?;
    let mut sftp = ssh.sftp()?;
    let handle = sftp.open(
        "report.txt",
        sftp::SSH_FXF_READ | sftp::SSH_FXF_WRITE | sftp::SSH_FXF_CREAT,
    )?;
    sftp.write(&handle, 0, b"report")?;
    let data = sftp.read(&handle, 0, 6_u32)?;
    sftp.close(&handle)?;
    let _ = data;
    Ok(())
}
```

The returned client borrows the connection, and one client cannot hold an SFTP
client and a session at the same time. Use `SshClient::session` for one channel
you drive yourself:

```rust,no_run
use neotales_ssh::SshClient;

fn example() -> Result<(), Box<dyn std::error::Error>> {
    let mut ssh = SshClient::open("user@example.org:2222")?;
    // The session borrows the connection; exec consumes it and closes the channel.
    let (stdout, status) = ssh.session()?.exec(b"printf hello")?;
    let _ = (stdout, status);
    Ok(())
}
```

`ClientSessions` and `dispatch_one` remain public. Other host-key types and
known-hosts documents remain available through the low-level `ClientConfig` APIs.

## One extra hop

Use `proxy::connect` for explicit proxy routes and trust callbacks. It supports
multiple hops and a caller-supplied `ProxyCommand` byte-stream opener; it does
not execute a command implicitly. `spawn_proxy_command` is a separate,
explicit process-launch hook.

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

## Server

Combine `ServerConfig::connect` with
`ServerSessions::with_policy`. Policy is required; no shell, child process or
`sshd` starts. User authentication remains explicit before channel dispatch.

```rust,no_run
use neotales_ssh::{ServerConfig, ServerAuthPolicy, ServerSessions, authenticate_server};
use neotales_ssh::hostkey::Ed25519Signer;
use neotales_ssh::session::SessionDecision;
use std::net::TcpListener;

fn server(signer: Ed25519Signer, auth_policy: &ServerAuthPolicy)
    -> Result<(), Box<dyn std::error::Error>>
{
    let listener = TcpListener::bind(("127.0.0.1", 2222))?;
    let (stream, _) = listener.accept()?;
    let config = ServerConfig::new(signer);
    let mut sessions = ServerSessions::with_policy(config.connect(stream)?, |_request| {
        SessionDecision::reject() // Replace with application policy, never a host shell.
    });
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

Start at `SshClient` for orchestration, `session.rs` / `channel.rs` for
dispatch, `client/` and `server/` for handshakes, `auth.rs` for authentication,
and `scp.rs` / `sftp.rs` for transfer codecs. Keep low-level hooks public and
test trust and wire behavior, not only paired codec round-trips. See
[`docs/compatibility.md`](docs/compatibility.md) for verified interoperability
and exclusions. README Rust examples are included in the crate's doctests.

From the Cargo workspace `rs/lib`:

```sh
cargo test -p neotales-ssh --lib --offline
cargo test -p neotales-ssh --doc --offline
cargo clippy -p neotales-ssh --all-targets --all-features --offline -- -D warnings
```

Opt-in interoperability tests require `NEOTALES_SSH_E2E=1`; the checks above do
not require or enable them.
