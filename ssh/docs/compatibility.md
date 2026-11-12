# SSH compatibility

This document describes interoperability evidence for `neotales-ssh`. A crate
test passing against its own fixtures is not evidence that another SSH
implementation accepts its output.

## Verified interoperability

These results were recorded in rust-libraries at 765e715; this repository's pipeline does not run those ignored lanes.

The live OpenSSH tests start the platform's system `sshd` and exercise this
crate as the SSH client. They cover protected packet exchange, channel behavior,
and public-key authentication. The current recorded results are:

| Platform | OpenSSH peer | Live lanes |
| --- | --- | ---: |
| Linux x86_64 | OpenSSH 10.5p1 | 16 |
| macOS 13.7.8 x86_64 | OpenSSH 9.0p1 | 16 |
| Windows Server 2025 x86_64 | Windows OpenSSH | 13 applicable |

The Windows count excludes three Unix-agent lanes. Those historical results
do not cover the subsequently added explicit Windows named-pipe connector.
Windows identity coverage includes direct ECDSA-key authentication.
Current Windows discovery checks the in-box `%SystemRoot%\System32\OpenSSH`
location and the Win32-OpenSSH `%ProgramFiles%\OpenSSH` installation. Native
Windows tests confirm discovery and pass the 13 applicable live lanes.

An intermittent macOS identity failure was traced to a valid ECDSA scalar
encoded as a canonical short positive mpint. The parser now left-pads it to the
fixed scalar width, and a deterministic regression fixture covers the encoding.
After the fix, the full macOS live suite passed and 20/20 parallel identity
stress runs passed.

The five packet/handshake lanes include AES-GCM, AES-CTR with encrypt-then-MAC,
ChaCha20-Poly1305, and the ML-KEM hybrid key exchange. Seven live channel lanes
exercise real channel traffic. Identity lanes exercise ECDSA and Ed25519 keys,
and on Unix, real `ssh-agent` authentication.

## Protocol coverage that is not a live OpenSSH claim

Both handshakes support `ssh-ed25519`, `rsa-sha2-256`, `rsa-sha2-512`, and
ECDSA P-256/P-384/P-521 host keys. SHA-1 `ssh-rsa` is not offered.
`ServerConfig::with_rsa_host_key` and the ECDSA host-key builders add signing
keys beside the primary Ed25519 key. The server filters proposals to available
keys and signs with the negotiated algorithm. Use
`ClientConfig::connect_with_host_keys` for an algorithm-aware trust callback.
The original `connect` callback remains Ed25519-only and rejects other types.

Signal, window-change, and break controls have client send methods and typed
server events with their exact payload bytes. A server control-policy callback
must explicitly accept them. The library never signals a process or resizes a
host PTY. Malformed controls do not reach that callback.

`SendEnv` and `SetEnv` are applied by `EnvironmentPlan` and sent as RFC 4254
`env` requests. `subsystem`, including the `sftp` name, and the `scp -t` /
`scp -f` exec requests are covered by in-process session tests. Those tests do
not start `sshd`. SCP remains single-file. SFTP version 3 supports an
in-process server over a caller-supplied byte stream and memory map. It is not
a host filesystem server.

### Additional in-process protocol coverage

These features have scripted-peer or byte-transport tests, not new live-peer
interoperability evidence:

- `ClientConfig::with_extension_info()` opts into `ext-info-c`. The server
  sends requested ext-info before its authentication service reply and advertises
  `ServerAuthPolicy`'s accepted signatures. RSA auth honors `server-sig-algs`
  for SHA-256/SHA-512, retaining PKCS#1 DigestInfo. Missing ext-info keeps the
  signer's explicit/default algorithm. Advertisement is not enabled by default
  because that changes existing packet-count behavior.
- Public-key authentication supports RSA SHA-512 and NIST P-256/P-384/P-521,
  including agent-backed identities. This does not widen the handshake's
  host-key proposal. RSA agent flags default to SHA-256; negotiation can select
  SHA-512. SHA-1 signatures remain rejected.
- `TransportPing` is message 192/193. Both authenticated transports answer
  pings with the same bytes; pre-authentication pings do not generate a reply.
  The legacy global request named `ping@openssh.com` is distinct.
  `GlobalRequest::keepalive_with_reply()` requests a response without a timer.
- RFC 4254 §7.1 reverse TCP forwarding has a one-connection byte tunnel in
  `tunnel`: `ReverseListener` binds only a caller-supplied numeric address and
  port (empty addresses are errors), and `TcpTunnel` dials the caller-supplied
  local destination and copies both ways through the existing channel window.
  Drop/cancel closes the listener; no bind retry or implicit wildcard exists.
  The caller polls nonblocking TCP and routes events from its synchronous SSH
  dispatcher only when a complete payload is ready; there is no background SSH
  reader. EOF half-closes the copy, while cancellation closes it immediately.
  Port-zero allocation metadata alone is not this byte tunnel. Port zero in
  `ReverseListener` really binds an OS-selected port and replies with that port;
  protocol-only types in `tcpip_forward` still open no sockets.
- `ResolvedConfig::to_kexinit()` applies implemented-only exact algorithm lists.
  Unknown names, duplicates, and OpenSSH list modifiers error. Include remains
  rejected and ProxyCommand remains inert text.
- SCP's `RemoteShell::PowerShell` preserves Windows backslashes and doubles
  literal quotes. POSIX quoting remains the default; neither detects a shell.
  SCP directory records remain rejected.
- Agent forwarding requires an explicit session request and separate default-deny
  server policy. The client application must confirm offered agent channels.
  Traffic is opaque; no local agent or process environment is accessed.
- SFTP gates `posix_rename`, `hardlink`, `fsync`, `statvfs`, and `limits` on
  advertised extension versions. Set `SymlinkOrder::OpenSsh` for a known OpenSSH
  peer; the byte-stream client cannot infer the SSH identification. Draft order
  remains available. `begin_stat`/`finish_stat` pipeline at most 16 requests,
  match out-of-order replies by id, and cap retained responses at 16 MiB.
  Synchronous operations cannot overlap a pending STAT batch. Metadata caps stay.
- `streamlocal` and `x11` provide wire-only helpers on `ChannelConnection`, with
  explicit independent policies that default to deny. Applications dispatch
  generic request/open events to these helpers and own endpoint/grant lifecycles.
  Streamlocal paths are bounded opaque bytes without NUL. X11 protocol and cookie
  strings are bounded and redacted in Debug. No socket or display is opened.

### Authentication and identity continuation

Task 0010 replaces the obsolete stop-on-failure test: ordinary failure permits
a later caller-listed method only when the server's remaining-method list also
permits it. `ClientAuthenticator::partial_success()` exposes the last failure's
flag without treating it as authentication success. Keyboard-interactive accepts
multiple rounds through the normal transports (up to 32); empty prompt text and
oversized prompts are rejected. A zero-prompt challenge remains permitted by
RFC 4256. `ClientAuthMethod::None` is explicit, and `with_none_policy` is the only
way for the server to grant it. The default denies.

Ed25519 host and user certificates now have connection-level trust integration.
`ServerConfig::with_host_certificate` associates a certificate with the primary
subject key; `ClientConfig::connect_with_known_hosts` verifies the host's CA
marker, principal, explicit Unix timestamp, and CA signature. User certificates
use `PublicKeySigner::ed25519_certificate` and explicit `UserCertificateTrust`
CA, clock, and application account/principal policy. All critical options,
including source-address and force-command, are rejected rather than ignored.
Wrong-role, expired, not-yet-valid, wrong-principal, wrong-CA, and damaged
certificates fail closed. Certificate algorithms beyond Ed25519 remain outside
the handshake/userauth path even though the standalone parser can verify them.
Default raw-host-key proposals are unchanged. There is no issuance or prompt.

`private_key::import_pkcs8_der` imports unencrypted PKCS#8 DER for Ed25519, RSA,
P-256, P-384, and P-521. `private_key::import_openssh` adapts the existing binary
OpenSSH parser to userauth signers for Ed25519, RSA, and P-256, including encrypted
bcrypt/AES-256-CTR containers. Passphrases are wiped and errors are redacted.
These APIs do not decode PEM armor, decrypt PKCS#8, read a default path, or export
keys. Larger-curve OpenSSH containers remain unsupported; use PKCS#8 DER.

### Agent service, pipe, and GSSAPI-MIC continuation

`agent_server::AgentServer` implements an in-process RFC 9987 keyring on a
caller-owned byte stream. `AgentClient` can add, remove, remove-all, lock and
unlock identities in addition to list/sign. Add records support Ed25519, RSA,
and P-256. At most 64 identities and a 1 MiB enumeration response are retained.
Locked agents return no identities and refuse signing and mutations. Wrong
unlock passphrases leave the lock intact; unsupported constraints and extensions
are denied. Lock gates operations, not memory access: keys remain resident and
are not encrypted by lock. No service, listener, or key-file discovery is added.

`agent::connect_pipe` opens only a caller-supplied local Windows pipe path in
the `\\.\pipe\` namespace, without an environment lookup, guessed name, or
hidden retry. Non-Windows returns UnsupportedPlatform without filesystem access.
Unix connectors are unchanged. Protocol tests use scripted streams; the
Windows-only open test names an explicit fixture and skips when it is absent.
This continuation ran on Linux; no Windows build or native pipe run is claimed.

`ClientAuthMethod::gssapi` and `ServerAuthPolicy::with_gssapi_mic_mechanism`
require an explicit `GssapiMicMechanism`. The application supplies a fresh
context and peer-identity authorization per connection. Token-only callbacks
neither enable nor advertise the method. Message 66 must verify the MIC over
the first session identifier, message 50, username, service and method after
token acceptance; message 63 never authenticates. Mechanism failures are normal
method failures and can fall back. Fake-mechanism tests cover all bound fields
and failure behavior. No Kerberos, SSPI, KDC, delegation or GSS KEX is bundled.

### KEX breadth continuation (0007)

Both handshakes now complete `ecdh-sha2-nistp384` with SHA-384 and
`ecdh-sha2-nistp521` with SHA-512 for both the exchange hash and RFC 4253 key
expansion. Their first session identifiers retain all 48/64 digest bytes.
The existing Curve25519, P-256, group16, and ML-KEM hash paths are unchanged.

`diffie-hellman-group-exchange-sha256` uses RFC 4419 messages 34/31/32/33.
Its hash includes the requested min/preferred/max, the prime, generator, both
ephemeral values, and the shared secret. The client requests exactly 4096 bits.
The server accepts ordered requests bounded within 2048..8192 that include
4096, but selects only the published RFC 3526 group16 safe prime with generator
2. The client accepts only that exact approved safe-prime/generator pair;
other groups (even other safe primes) are rejected before key generation or
agreement. This is a deliberately narrow allowlist, not arbitrary DH group
validation or generation. Oversized wire mpints are capped before allocation.

All three names were added to supported/default catalogs only after both public
handshake tests passed. Existing choices and their preference order remain ahead
of the new names. Strict/non-strict tests cover protected traffic and exact GEX
message order; independent fixed fixtures cover transcript hashes and multi-block
key expansion. No SHA-1 group exchange, group1, CBC, 3DES, RC4, HMAC-SHA1, or
sntrup was added. Post-establishment rekey supports curve25519-sha256,
ecdh-sha2-nistp256/384/521, diffie-hellman-group16-sha512,
diffie-hellman-group-exchange-sha256 and mlkem768x25519-sha256. Rekey retains
the initial algorithm and first exchange hash as the session identifier, and
uses that algorithm's initial-handshake hash and key derivation. Other names
remain rejected and failed exchanges are terminal. In-process tests cover
repeated rekeys and protected traffic; no new live-peer evidence is claimed.

## Not verified or not claimed

- Default proposals, including both handshake builders, offer only `none`.
  `ClientConfig::with_delayed_compression` and
  `ServerConfig::with_delayed_compression` explicitly offer and permit
  `zlib@openssh.com`. Merely overriding KEXINIT does not opt in. Authentication
  packets, including USERAUTH_SUCCESS, remain uncompressed; subsequent packets
  use one continuous zlib context per direction, reset at that direction's
  NEWKEYS boundary. Legacy immediate `zlib` remains unsupported, even with opt-in.
  The standalone `compress_payload` / `decompress_payload` helpers handle finished
  streams, not SSH packet streams. Live OpenSSH compression interoperability is
  not verified here.

- **Reverse interoperability is not verified.** There is no current live test
  demonstrating a system OpenSSH client connecting to this crate's server.
- The historical Windows Unix-agent lanes remain inapplicable; the new Windows
  pipe connector has no recorded native interoperability result here.
- These results are hand-verified on the listed machines, not a passing current
  Gitea three-platform CI matrix. See the repository's
  [`support matrix`](../../docs/support-matrix.md) for CI status and provenance.
- Other SSH implementations and versions are not implied by these OpenSSH runs.

## Running the live tests

The ordinary package test run keeps external-tool tests ignored. With `sshd`,
`ssh-keygen`, and (on Unix) `ssh-agent` and `ssh-add` installed, run:

```sh
NEOTALES_SSH_E2E=1 cargo test -p neotales-ssh -- --ignored
```

Long and live lanes also check this runtime gate, even with `--all-features`
or `--include-ignored`. Missing OpenSSH tools or Docker skip the live lane.
The fast tool-discovery tests remain in the normal run. A skip is not evidence
of interoperability. The loopback transfer lifecycle lane is opt-in too.

## Separate real-peer package

The new `neotales-ssh-e2e` package contains two peers with identical handshake,
pinned host-key trust, and public-key authentication cases. One uses a
digest-pinned OpenSSH image through testcontainers; the other starts native
Unix OpenSSH when its tools are installed. See [`../e2e/README.md`](../../e2e/README.md)
for the exact image digest and fixture lifecycle.

```sh
# Normal library tests; does not compile testcontainers or run real peers.
cargo test -p neotales-ssh
# Opt-in real peers, separate from the existing ignored lanes.
NEOTALES_SSH_E2E=1 cargo test -p neotales-ssh-e2e
```

Testing the e2e package without the runtime gate skips all peer bodies.
Missing Docker skips locally. The dispatch-only `rs-ssh-e2e` workflow runs
`docker info` first, so a missing daemon fails that dedicated job. The ordinary
SSH unit workflow is unchanged.
