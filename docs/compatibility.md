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

### Callback security keys and sntrup (2026-11-12)

`ClientConfig::with_security_key_verifier(SecurityKeyVerifier::new(...))` opts
into `sk-ssh-ed25519@openssh.com` and
`sk-ecdsa-sha2-nistp256@openssh.com` host verification. Without it neither is
advertised, and explicit proposals and peer signatures are rejected. The
separate host-trust callback remains mandatory. `security_key::Verification`
contains the public key, application, SSH signature blob, flags, counter, and
PROTOCOL.u2f preimage `SHA256(application) || flags || counter || SHA256(message)`.
The verifier must perform cryptographic verification and application/presence/
counter policy; false or panic denies. Unknown flags/extensions and trailing or
truncated framing fail before callback invocation. Rekey pins the public blob
and retains this verifier.

`SecurityKeySigner::new(public_blob, handle, callback)` installs an explicit
signing capability. Its callback chooses flags/counter, signs the library-built
`Signing::signed_data(flags, counter)` PROTOCOL.u2f preimage, and returns
`Signature` (raw Ed25519 bytes or SSH P-256 r/s mpints, not DER). The library
validates framing and builds the SSH signature blob with those exact flags and
counter; it neither generates signatures nor stores a private key. Callback
denial, panic, malformed signatures and unknown flags fail closed.

`ClientAuthMethod::public_key(PublicKeySigner::SecurityKey(signer))` uses this
capability for user authentication. The server requires both an explicitly
authorized public blob and `ServerAuthPolicy::with_security_key_verifier(...)`;
the existing verifier owns crypto and application/presence/counter policy.
Without the respective callbacks the client cannot construct the signer and the
server neither offers SK-only publickey authentication nor accepts SK queries
or signatures. Server signature-algorithm advertisements are opt-in as well.
SHA-1 `ssh-rsa` userauth rejection and RSA SHA-2 behavior are unchanged.

`ResidentKeyEnrollment::new(callback).enroll(algorithm, application)` delegates
one resident-key enrollment request entirely to the caller and returns a
validated public blob plus opaque handle. The default has no callback and
rejects without sending any enrollment request. Application/algorithm mismatch,
malformed keys, denial and panic are rejected. No credential file is read.
Offline tests use fake callbacks to sign, authenticate and enroll both SK key
types, and cover missing callbacks and denial. These are in-process callback
contracts, not evidence of a device, resident hardware, USB access or live
OpenSSH interoperability.

Both handshakes support `sntrup761x25519-sha512@openssh.com` through explicit
KEXINIT selection, with unchanged default proposals. Strict/non-strict loopback
tests cover 1190-byte client values, 1071-byte server values, a 64-byte session
identifier and protected traffic. SHA-512 hashes the concatenated KEM and raw
X25519 secrets, encoded as an SSH string (not mpint); transcript and key expansion
also use SHA-512. The exact pure-Rust `sntrup-kem =0.1.0-rc.0` dependency uses
`force-scalar`; no C, assembly or cc build script was added. Length/low-order/
tamper tests also run offline. This is not a live OpenSSH interoperability claim.

### Opt-in ML-DSA keys and user authentication (draft-08)

The caller confirmed the identifiers and sizes from
[draft-sfluhrer-ssh-mldsa-08 §§3, 4, 7](https://www.ietf.org/archive/id/draft-sfluhrer-ssh-mldsa-08.txt):

| Algorithm | Raw public key | Raw signature |
| --- | ---: | ---: |
| `ssh-mldsa-44` | 1312 bytes | 2420 bytes |
| `ssh-mldsa-65` | 1952 bytes | 3309 bytes |
| `ssh-mldsa-87` | 2592 bytes | 4627 bytes |

Both public keys and signatures use `string algorithm, string raw bytes`.
`mldsa_hostkey::MldsaSigner` uses the exact pure-Rust `ml-dsa =0.1.2` crate,
deterministic pure ML-DSA with an empty FIPS 204 context, not HashML-DSA.
The verifier accepts both deterministic and hedged signatures; it checks the
exact algorithm and signature length before decoding or crypto verification.
Seeds supplied to `from_seed` are wiped, and secret key state zeroizes on drop.
No C, assembly, cc build script, key discovery, or private-key file import is added.

`PublicKeySigner::mldsa` also signs RFC 4252 user-authentication transcripts.
The server must explicitly include the draft key name using
`ServerAuthPolicy::with_signature_algorithms` and authorize the public key.
Defaults do not advertise or accept ML-DSA user authentication.

`PublicKeySigner::mldsa_certificate` carries an existing user certificate.
Certificate identifiers are the existing Go x/crypto v0.59.0 vendor names
`ssh-mldsa-44-cert-v01@golang.org`, `ssh-mldsa-65-cert-v01@golang.org`, and
`ssh-mldsa-87-cert-v01@golang.org` from
[Go certs.go](https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.59.0:ssh/certs.go),
not names specified by draft-08. Framing follows the OpenSSH certificate layout
with one string containing the raw ML-DSA subject key. Existing Ed25519 framing
is unchanged. The parser/verifier supports all three subject and CA parameter
sets, including Ed25519 CAs for ML-DSA subjects. CA signatures cover the raw
certificate prefix with pure ML-DSA and empty context when the CA is ML-DSA.
User certificates require explicit CA/principal policy via
`UserCertificateTrust` and explicit inclusion of the vendor certificate name
in `with_signature_algorithms`. Time is supplied by the caller as Unix seconds;
the inclusive start and exclusive expiry, principal, CA signature, and critical
options are checked. No system clock is read by certificate verification.

Offline `mldsa_userauth` tests exercise signing/verification for 44/65/87,
protected client/server 65 user authentication, default denial with and without
server-sig-algs, and certificate authentication with expired/not-yet-valid and
wrong-principal rejection. This is not a live OpenSSH ML-DSA interoperability claim.

Defaults remain unchanged. `ClientConfig::with_mldsa_host_keys()` explicitly
appends the three names; an explicit KEXINIT can select them too.
`ServerConfig::with_mldsa_host_key` adds one explicit signer and its matching
name alongside existing host keys. Use `connect_with_host_keys` for application
trust; the Ed25519-only `connect` API is unchanged. Tests exercise real crate
sign/verify for all three parameter sets, wrong context/key/message/name/size,
and both handshakes selecting `ssh-mldsa-65` in strict and non-strict mode,
protected traffic, trust denial, and client/server-initiated rekeys. This is
in-process evidence, not a live OpenSSH or Go interoperability claim. ML-DSA
user authentication and certificates use the separate opt-in APIs above.

Both handshakes support `ssh-ed25519`, `rsa-sha2-256`, `rsa-sha2-512`, and
ECDSA P-256/P-384/P-521 host keys. SHA-1 `ssh-rsa` is not offered by default.
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
not start `sshd`. SCP supports bounded in-memory directory records alongside
single-file transfers, with at most 8 directory levels and 64 file/directory
records including the root; directory transfers do not access host directories.
SFTP version 3 supports an in-process server over a caller-supplied byte stream
and memory map. This remains the default and never touches disk.

Filesystem access is an explicit adapter: `sftp::RootedSftpServer`
implements v3 OPEN/READ/WRITE/CLOSE; `scp::RootedScpServer` receives or sends one
file without spawning a process. Each requires a caller-supplied root directory,
canonicalized and pinned at construction. There is no implicit host root or home.
Relative paths resolve beneath that root; absolute paths must start beneath its
canonical path. `..`, escaping symlinks, and special files are rejected. Relative
in-root symlinks are allowed; absolute symlinks are conservatively rejected.
Linux `openat2` (5.6+, allowed by host policy) enforces confinement during path
resolution, including symlink swaps; there is no unsafe fallback on older hosts.
On other platforms, the adapter rejects all symlinks and reparse points and
checks canonical paths before opening. These checks are not atomic: callers must
prevent concurrent modification of the root and its directories; otherwise a
path swap can escape the root. They are not a sandbox against an active attacker.
Existing hard links/mounts inside the root and externally moving open files are
the caller's responsibility, not an additional sandbox guarantee.

SFTP missing-file OPEN replies carry `SSH_FX_NO_SUCH_FILE`; reads and writes are
bounded by the existing 16 MiB packet cap including overhead. SCP keeps its
64 MiB file limit and uses bounded streaming disk I/O. Upload destinations are
caller-selected, not peer-selected; mode/time metadata is validated, not applied.
I/O failure can leave partial files. Rooted adapter tests use byte pipes, not
live-peer interoperability tests; directory copy remains in-memory.

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
- RFC 4254 TCP forwarding has caller-driven byte tunnels in `tunnel`.
  `LocalListener` (`ssh -L`) and `ReverseListener` (`ssh -R`) bind only a
  caller-supplied numeric address and port (empty addresses/hostnames are errors).
  Each accepted connection opens its own `direct-tcpip` or `forwarded-tcpip`
  channel and returns an independent `TcpTunnel`; the listener remains bound
  for further connections. Local forwarding sends the explicit destination
  bytes to the peer without local DNS/dialing. For reverse forwarding,
  `TcpTunnel::connect` dials the caller-supplied local destination. Both copy
  directions honor the existing channel window.
  Drop/cancel closes the listener and shuts down all its accepted TCP copies;
  continue polling/routing copies to finish SSH CLOSE, including late open
  confirmations. No bind retry or implicit wildcard exists.
  The caller polls nonblocking TCP and routes events from its synchronous SSH
  dispatcher only when a complete payload is ready; there is no background SSH
  reader. EOF half-closes the copy, while cancellation closes it immediately.
  Port-zero allocation metadata alone is not this byte tunnel. Port zero in
  `ReverseListener` really binds an OS-selected port and replies with that port;
  protocol-only types in `tcpip_forward` and `direct_tcpip` still open no sockets.
  Loopback tests cover a local byte each way and two simultaneous reverse
  connections with distinct bytes, including cancel/drop cleanup; these are
  not new live-OpenSSH interoperability claims.
- `ResolvedConfig::to_kexinit()` applies implemented-only exact algorithm lists.
  Unknown names, duplicates, and OpenSSH list modifiers error. Plain parsing
  does not read Include files; the explicit loader does. Default connect does
  not execute ProxyCommand; explicit process-spawning helpers are available.
- SCP's `RemoteShell::PowerShell` preserves Windows backslashes and doubles
  literal quotes. POSIX quoting remains the default; neither detects a shell.
  SCP directory records (`D`/`E`) support bounded in-memory directory transfers;
  no host directory is opened.
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
key expansion. Post-establishment rekey supports curve25519-sha256,
ecdh-sha2-nistp256/384/521, diffie-hellman-group16-sha512,
diffie-hellman-group-exchange-sha256 and mlkem768x25519-sha256. Rekey retains
the initial algorithm and first exchange hash as the session identifier, and
uses that algorithm's initial-handshake hash and key derivation. Other names
remain rejected and failed exchanges are terminal. In-process tests cover
repeated rekeys and protected traffic; no new live-peer evidence is claimed.

### Deprecated algorithms: explicit opt-in only

`ClientConfig::with_legacy_algorithms()` and
`ServerConfig::with_legacy_algorithms()` explicitly enable these deprecated names:

- `ssh-rsa` (RSA PKCS#1 v1.5 SHA-1 host signatures; requires an RSA host key)
- `hmac-sha1` and `hmac-sha1-etm@openssh.com`
- `aes128-cbc`, `aes256-cbc`, and `3des-cbc`
- `diffie-hellman-group1-sha1` (RFC 4253 1024-bit MODP group, generator 2)
- `diffie-hellman-group-exchange-sha1` (only the same approved 4096-bit
  group16 prime and generator 2 used by SHA-256 group exchange)

Defaults and supported-by-default catalogs still exclude every name above.
Merely overriding KEXINIT does not opt in: both configs reject a custom legacy
proposal without the method call. Opt-in appends legacy names after existing
choices; callers can supply a custom proposal to choose their order. The same
policy-bound proposals govern subsequent rekeys. RSA SHA-2 remains unchanged;
`server-sig-algs` preference never selects SHA-1 for authentication.

CBC uses continuous chaining across SSH packets with SSH padding, not PKCS#7.
RC4 cipher names (`arcfour`, `arcfour128`, and `arcfour256`) are rejected,
including behind `with_legacy_algorithms()`. RFC 8758 deprecates RC4. The
remaining opt-in algorithms are cryptographically obsolete; use them only for
unavoidable legacy compatibility.
Packet fixtures use independent OpenSSL cipher and Python HMAC-SHA1 outputs;
loopback tests cover SHA-1 RSA host signatures, protected traffic, and client-
and server-initiated rekeys. This is not new live OpenSSH interoperability evidence.
No C library or new lockfile crate was added. sntrup, security keys, and ML-DSA
are outside this change.

## Not verified or not claimed

- Default proposals, including both handshake builders, offer only `none`.
  `ClientConfig::with_delayed_compression` and
  `ServerConfig::with_delayed_compression` explicitly offer and permit
  `zlib@openssh.com`. Merely overriding KEXINIT does not opt in. Authentication
  packets, including USERAUTH_SUCCESS, remain uncompressed; subsequent packets
  use one continuous zlib context per direction, reset at that direction's
  NEWKEYS boundary. RFC 4253 immediate `zlib` has a separate explicit opt-in,
  `with_immediate_compression`, and compresses authentication packets from
  NEWKEYS using continuous per-direction streams, reset at rekey. Delayed
  compression does not imply this opt-in; defaults still offer only `none`.
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


## SSH configuration side effects

Plain configuration parsing remains filesystem-free. Include files are read only when the caller explicitly uses the supplied loader; the directory loader confines canonicalized paths to its caller-provided root and limits expansion to depth 8 and 16 files. Ordinary connect does not execute ProxyCommand. A caller may explicitly invoke `proxy::spawn_proxy_command` for an already-resolved command; it starts the executable directly, without a default shell path.

`proxy::spawn_proxy_command_shell` is a separate explicit helper requiring a caller-supplied POSIX-compatible shell path. It passes the resolved command intact as one `-c` argument, preserving quoted spaces through one shell. Callers must trust the command and shell-quote substituted values. Neither parsing nor default connect invokes it.
