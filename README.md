# neotales-ssh

SSH-2 protocol implementation with wire codecs, key exchange, authentication, transport, and host-key handling.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-ssh)

<!-- badges: crates.io, docs.rs, CI. Add once the first version exists. -->

## Install 📦

```sh
cargo add neotales-ssh
```

## What you can do 🔧

**Connect.** `SshClient::builder()` needs a host, a username, at least one authentication method, and a host-key pin or known-hosts text. `build()` dials the host and authenticates. An unknown host key is refused.

```rust,no_run
use neotales_ssh::SshClient;

let _client = SshClient::builder()
    .host("ssh.example.com")
    .username("deploy")
    .password("secret")
    .known_hosts("ssh.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample")
    .build()
    .expect("connect");
```

**Use the SSH agent.** `.agent(true)` offers every identity the running agent holds, without naming a key file.

```rust,no_run
use neotales_ssh::SshClient;

let _client = SshClient::builder()
    .host("ssh.example.com")
    .username("deploy")
    .agent(true)
    .known_hosts("ssh.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample")
    .build()
    .expect("connect with the agent");
```

**Authenticate with a password.** `.password("secret")` adds one password method; the value is redacted from `Debug` and zeroized on drop.

```rust,no_run
use neotales_ssh::SshClient;

let _client = SshClient::builder()
    .host("ssh.example.com")
    .username("deploy")
    .password("secret")
    .known_hosts("ssh.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample")
    .build()
    .expect("connect with a password");
```

**Authenticate with an identity file.** `.identity_file("id_ed25519")` reads one unencrypted OpenSSH or PKCS#8 DER key. `identity_file_with_passphrase` reads an encrypted OpenSSH key and wipes the passphrase copy.

```rust,no_run
use neotales_ssh::SshClient;

let _client = SshClient::builder()
    .host("ssh.example.com")
    .username("deploy")
    .identity_file("id_ed25519")
    .expect("read the identity")
    .known_hosts("ssh.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample")
    .build()
    .expect("connect with the identity");
```

**Run a command.** `exec` returns the buffered stdout and the exit status. Stderr is discarded.

```rust,no_run
use neotales_ssh::SshClient;

let mut client = SshClient::builder()
    .host("ssh.example.com")
    .username("deploy")
    .password("secret")
    .known_hosts("ssh.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample")
    .build()
    .expect("connect");

let (stdout, status) = client.exec(b"uname -a").expect("exec");
println!("{}", String::from_utf8_lossy(&stdout));
assert_eq!(status, 0);
```

**Use an interactive shell.** `shell` opens a session, sends the `shell` request, waits for the server to accept it, and returns a `SessionStream` to `read` and `write`. It is a shell channel, not a terminal: no PTY is requested.

```rust,no_run
use std::io::{Read, Write};

use neotales_ssh::SshClient;

let mut client = SshClient::builder()
    .host("ssh.example.com")
    .username("deploy")
    .password("secret")
    .known_hosts("ssh.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample")
    .build()
    .expect("connect");

let mut shell = client.shell().expect("shell");
shell.write_all(b"uname -a\n").expect("write");
let mut buffer = [0u8; 1024];
let read = shell.read(&mut buffer).expect("read");
println!("{}", String::from_utf8_lossy(&buffer[..read]));
```

**Upload and download over SCP.** `upload` and `download` move one in-memory file. The progress callback receives the payload length after a successful transfer.

```rust,no_run
use neotales_ssh::SshClient;

let mut client = SshClient::builder()
    .host("ssh.example.com")
    .username("deploy")
    .password("secret")
    .known_hosts("ssh.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample")
    .build()
    .expect("connect");

client
    .upload("notes.txt", b"hello\n", |_| {})
    .expect("upload");
let data = client.download("notes.txt", |_| {}).expect("download");
assert_eq!(data, b"hello\n");
```

**Upload and download over SFTP.** `client.sftp()` starts the subsystem and negotiates version 3. Open with `SftpOpenFlags`, then `read` or `write` at an offset and `close` the handle.

```rust,no_run
use neotales_ssh::SshClient;
use neotales_ssh::sftp::{SftpOpenFlags, SftpReadResult};

let mut client = SshClient::builder()
    .host("ssh.example.com")
    .username("deploy")
    .password("secret")
    .known_hosts("ssh.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample")
    .build()
    .expect("connect");

let mut sftp = client.sftp().expect("sftp");

let handle = sftp
    .open(
        "notes.txt",
        SftpOpenFlags::WRITE | SftpOpenFlags::CREAT | SftpOpenFlags::TRUNC,
    )
    .expect("open for writing");
sftp.write(&handle, 0, b"hello\n").expect("write");
sftp.close(&handle).expect("close");

let handle = sftp
    .open("notes.txt", SftpOpenFlags::READ)
    .expect("open for reading");
let mut data = Vec::new();
let mut offset = 0u64;
loop {
    match sftp.read(&handle, offset, 4096).expect("read") {
        SftpReadResult::Data(chunk) => {
            if chunk.is_empty() {
                break;
            }
            offset += chunk.len() as u64;
            data.extend_from_slice(&chunk);
        }
        SftpReadResult::Eof => break,
    }
}
sftp.close(&handle).expect("close");
assert_eq!(data, b"hello\n");
```

**Serve an SSH connection.** The crate opens no listener and authenticates no user. The `recipes::serve` helper only performs the handshake and installs a session policy, so this sample binds, accepts, authenticates, and installs the policy explicitly.

```rust,no_run
use neotales_ssh::hostkey::Ed25519Signer;
use neotales_ssh::session::{SessionDecision, SessionRequest};
use neotales_ssh::{ServerAuthPolicy, ServerConfig, ServerSessions, authenticate_server};

let listener = std::net::TcpListener::bind("127.0.0.1:2222").expect("bind");
let (stream, _) = listener.accept().expect("accept");

let config = ServerConfig::new(Ed25519Signer::from_seed(&mut [7; 32]));
let mut transport = config.accept(stream).expect("handshake");

let policy = ServerAuthPolicy::new(4)
    .expect("policy")
    .with_password_verifier(|password: &str| password == "secret");
authenticate_server(&mut transport, &policy).expect("authenticate");

let _server = ServerSessions::with_policy(transport, |request| match request {
    SessionRequest::Exec { .. } | SessionRequest::Shell => SessionDecision::accept(0),
    SessionRequest::Subsystem { .. } => SessionDecision::reject(),
});
```

**Work with SSH wire values.** `encode_string` writes the SSH length prefix and bytes; `decode_string` reads that format back.

```rust,no_run
use neotales_ssh::{decode_string, encode_string};

let encoded = encode_string(b"hello").expect("encode");
assert_eq!(decode_string(&encoded).expect("decode"), b"hello");
```

## Licence 📜

[MIT](LICENSE.md)
