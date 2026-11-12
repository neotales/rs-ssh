# neotales-ssh

`neotales-ssh` is an SSH-2 protocol library for developers who want full control
and may need to fork and patch it. It is not a sealed SSH client. Low-level
protocol hooks stay public so callers can choose policy and build their own
integration. The library does not read `~/.ssh`, shell out, or provide default
peer trust.

See [`docs/compatibility.md`](docs/compatibility.md) for verified
interoperability claims and exclusions. This crate does not start an SSH server,
host shell, or background service.

## Client transport and trust

The callback is mandatory: there is no accept-any default. `connect` handles
Ed25519 host keys; the callback runs only after the key's signature has been
verified. Use `connect_with_host_keys` to decide trust for other host-key types.
The callback is where the application supplies its trust policy.

```rust,no_run
use neotales_ssh::ClientConfig;
use std::net::TcpStream;

let stream = TcpStream::connect(("example.org", 22))?;
let transport = ClientConfig::new().connect(stream, |key| {
    // Check the verified key against application policy.
    trust_ed25519_key(key)
})?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The network example is illustrative; `trust_ed25519_key` represents the
caller's own policy, not a crate helper. The crate does not speak TLS. SSH's
equivalent peer-trust decision is the required host-key callback, called after
signature verification; there is no TLS API here.

## Server and sessions

`ServerConfig::connect(stream)` builds a server protocol endpoint. Install
session policy with `ServerSessions::with_policy`; the library does not launch
a host shell or `sshd` for you. Client-side channels are managed through
`ClientSessions` or the `session` module: open a session, then request exec,
shell, subsystem, or SFTP as appropriate. `request_exec` takes command bytes;
a script is an exec request containing the script bytes, not an implicit
interpreter invocation.

## Proxies and forwarding

`proxy::connect` takes a `ClientConfig`, `ProxyTarget`, dial callback, separate
jump-host and destination authentication, and a host-key trust callback cloned
for each hop. `ProxyCommand` is not executed unless the caller explicitly uses
`spawn_proxy_command` as the opener; that function starts an executable, not a
shell.

`tunnel::ReverseListener::bind(address, port)` binds only the numeric address
provided by the caller. `TcpTunnel` is caller-driven through `poll_tcp` and
`handle_event`; `direct_tcpip` describes local-forward metadata. These are
building blocks, not a multi-connection forwarding product or background
thread.

## File transfer

SCP provides `scp::upload`, `scp::download`, and `ScpClient`; the directory
helpers `upload_directory` and `download_directory` operate on an in-memory
tree. Progress is not a library type: count bytes in the caller around the
transfer, for example by wrapping the input/output stream.

SFTP uses `SftpClient::connect` over a byte stream supplied by the caller, then
`write` and `read` operations. The in-process SFTP server is memory-backed; it
does not expose the host filesystem.

## Algorithms and security keys

`KexInit` is public, and `with_legacy_algorithms` is an explicit opt-in.
RC4/arcfour is rejected even with that option. Security-key support currently
means callback-based verification; signer and USB-device support are not
provided.

## Build and test

From the repository root:

```sh
cargo test -p neotales-ssh
```

Long-running interoperability tests require `NEOTALES_SSH_E2E=1` and are not
part of `cargo test -p neotales-ssh`. The crate uses Rust and the dependencies
declared in its `Cargo.toml`.
