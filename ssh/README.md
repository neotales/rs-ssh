# neotales-ssh

SSH-2 building blocks meant to be forked and patched. `recipes` covers common
paths; every low-level API and policy hook remains public. Helpers do not read
`~/.ssh`, execute local commands, or accept a host key by default.

Each call requires a username, authentication methods, and a trusted Ed25519 SSH
public-key blob supplied by the application. `None` selects port 22. Signature
verification precedes the pin check; no host key is accepted by default. The
script is sent as exact command bytes, without selecting an interpreter. Output
is buffered; stderr is discarded. Upload progress counts payload bytes only and
failed uploads may leave partial files. Set appropriate network deadlines at the
lower level when needed.

## Command

```rust,no_run
use neotales_ssh::{ClientAuthMethod, recipes::Client};
fn example(methods: &[ClientAuthMethod], pin: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::open("example.org", None, "user", methods, pin)?;
    let (stdout, status) = client.exec(b"printf hello")?;
    assert_eq!((stdout.as_slice(), status), (b"hello".as_slice(), 0));
    Ok(())
}
```

## Script

```rust,no_run
use neotales_ssh::{ClientAuthMethod, recipes::Client};
fn example(methods: &[ClientAuthMethod], pin: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::open("example.org", None, "user", methods, pin)?;
    let (stdout, status) = client.script(b"printf one\nprintf two\n")?;
    assert_eq!((stdout.as_slice(), status), (b"onetwo".as_slice(), 0));
    Ok(())
}
```

## Upload

```rust,no_run
use neotales_ssh::{ClientAuthMethod, recipes::Client};
fn example(methods: &[ClientAuthMethod], pin: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::open("example.org", None, "user", methods, pin)?;
    client.upload("report.txt", b"report", |bytes| println!("uploaded {bytes}"))?;
    Ok(())
}
```

## Download

```rust,no_run
use neotales_ssh::{ClientAuthMethod, recipes::Client};
fn example(methods: &[ClientAuthMethod], pin: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::open("example.org", None, "user", methods, pin)?;
    let bytes = client.download("report.txt", |bytes| println!("downloaded {bytes}"))?;
    assert_eq!(bytes, b"report");
    Ok(())
}
```

## SFTP

```rust,no_run
use neotales_ssh::{ClientAuthMethod, recipes::Client};
fn example(methods: &[ClientAuthMethod], pin: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::open("example.org", None, "user", methods, pin)?;
    let mut sftp = client.sftp()?;
    let handle = sftp.open("report.txt", neotales_ssh::sftp::SSH_FXF_READ | neotales_ssh::sftp::SSH_FXF_WRITE | neotales_ssh::sftp::SSH_FXF_CREAT)?;
    sftp.write(&handle, 0, b"report")?;
    let data = sftp.read(&handle, 0, 6_u32)?;
    sftp.close(&handle)?;
    let _ = data;
    Ok(())
}
```

`ClientSessions`, `dispatch_one`, and the channel types remain public hooks for
custom protocols and policies. Other host-key types and known-hosts documents
remain available through the low-level `ClientConfig` APIs.

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
