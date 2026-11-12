# SSH remediation handoff

## 2026-11-12: callback security keys, sntrup, and opt-in ML-DSA

1. Added callback-only security-key host verification and opt-in client proposals.
   PROTOCOL.u2f public application and signature flags/counter are parsed exactly;
   callbacks receive the constructed signed preimage and own cryptographic and
   authenticator policy. Fake-callback tests are not a hardware claim. Absent
   callbacks reject explicit proposals and peer signatures. Rekey retains the
   verifier and pins the original public blob. No security-key signer, userauth
   integration, resident-key enrollment, USB access or credential access is added.
2. Both handshakes completed sntrup761x25519-sha512@openssh.com in strict and
   non-strict tests with protected traffic before adding it to supported catalogs.
   Default proposals are unchanged; select it with explicit KEXINIT. The exact
   dependency is sntrup-kem =0.1.0-rc.0, force-scalar: build=false, Rust sources,
   no C/assembly/cc build script. Its newly locked rand_chacha 0.10.0 dependency
   is Rust-only too. sntrup761 0.4.0 was rejected because its manifest enables
   sha2 0.10's asm feature on x86/ARM. The selected crate was fetched successfully;
   tests contain no fetch. OpenSSH kexsntrup761x25519.c confirms string-encoded
   SHA512(KEM-secret || raw-X25519-secret); transcript and KDF use SHA-512.
3. **ML-DSA source blocker resolved by the caller's draft-08 confirmation.**
   Sections 3, 4 and 7 of
   https://www.ietf.org/archive/id/draft-sfluhrer-ssh-mldsa-08.txt specify
   `ssh-mldsa-44` (1312/2420 public/signature bytes), `ssh-mldsa-65`
   (1952/3309), and `ssh-mldsa-87` (2592/4627). All three now sign and verify
   through pinned pure-Rust `ml-dsa =0.1.2`, with real deterministic and hedged
   crate signatures and empty FIPS 204 context. Exact signature sizes are checked
   before cryptographic verification. Keys/signatures use two SSH strings;
   wrong name, size, context, key, message, damage and trailing data fail closed.
   Both handshakes select 65, exchange protected traffic, deny untrusted keys,
   and complete both directions of rekey in strict/non-strict tests. Client and
   server have explicit opt-in builders, defaults are unchanged, and existing
   host keys remain available. No ML-DSA userauth or certificates are claimed.
   Fetch succeeded; ml-dsa has build=false, forbids unsafe Rust, and contains no
   C or assembly. Its dependencies were already locked; no cc build script or
   native library was added. Its zeroize feature wipes retained key state.

No existing KEX name was removed. No commit, push, atlas edit or E2E gate.

ML-DSA continuation verification from `rs/lib` (offline after successful fetch):

- `cargo test -p neotales-ssh --test mldsa_hostkey --offline`
  — 3 passed, zero failures.
- `cargo test -p neotales-ssh --all-targets --all-features --offline`
  — 644 passed, 19 ignored, zero failures across 59 test binaries.
- `cargo clippy -p neotales-ssh --all-targets --all-features --offline -- -D warnings`
  — passed without warnings.

Previous security-key/sntrup verification (before ML-DSA):

- `cargo test -p neotales-ssh --lib --test security_key --test kex_breadth --offline`
  — 34 passed, zero failures. Includes fake-callback framing/default-denial,
  peer denial without a verifier, both sntrup handshakes, malformed/low-order/
  tampered values, and independent Python SHA-512 transcript/KDF fixtures.
- `cargo test -p neotales-ssh --all-targets --all-features --offline`
  — 641 passed, 19 ignored, zero failures across 58 test binaries.
- `cargo clippy -p neotales-ssh --all-targets --all-features --offline -- -D warnings`
  — passed without warnings.

The first all-target clippy run exposed integration tests compiling source
modules by path without the new security-key sibling. All nine such harnesses
now include that sibling with their local HostKeyError type; no production
type or error conversion was weakened. Edited Rust files were formatted with
`rustfmt --edition 2024`. The pre-existing `des` lockfile correction is retained.

## Latest continuation: agent server, explicit pipe, GSSAPI MIC

All four requested task files were read. Completed in this continuation:
**0024, 0023, 0011**. **0007 is still unfinished**, as detailed below; this is
not a claim that all four tasks are closed.

### 0024: in-process agent

`agent_server::AgentServer` processes one bounded length-framed request at a
time on a caller-owned Read+Write stream. `AgentClient` now sends add, constrained
add, remove, remove-all, lock and unlock in addition to list/sign. Adds accept
RFC private-identity records for Ed25519, RSA and P-256 and reuse the existing
validated OpenSSH private-record parser. RSA signatures use SHA-256 or SHA-512
only; unsupported signing flags fail. Resident keys are capped at 64 and the
enumeration response at 1 MiB. Private request/container buffers are wiped.

Lock hides enumeration and denies signing/mutations. Only an exact, constant-time
comparison of the salted passphrase digest unlocks it. Empty/oversized lock
passphrases are rejected. Keys remain resident: lock is a protocol gate, not
encryption against process-memory access. Wrong unlock attempts and unsupported
constraints produce generic message 5 without input/key bytes. Constrained-add
message 25 and extension message 27 are rejected, never silently downgraded.
Tests use AgentClient through a scripted byte stream and cover the full keyring
lifecycle, all three supported add algorithms, RSA SHA-2 flags, lock denial,
wrong unlock persistence, replacement, and constrained-add denial.

### 0023: explicit Windows pipe

`agent::connect_pipe` accepts only an explicit nonempty local Windows
`\\.\pipe\` path and returns AgentClient<File>. It performs no process-environment
lookup, default-name selection, hidden retry, or regular-file fallback. The
non-Windows implementation returns UnsupportedPlatform without opening the path;
connect_unix remains unchanged. Protocol tests run on scripted streams. The
Windows-only open test names an explicit synthetic fixture and skips only if
that pipe is absent. This host has only the Linux Rust target installed: **no
Windows build or native pipe execution was performed**. Callers own blocking-I/O
policy; std File has no portable timeout setters.

### 0011: integrity-capable GSSAPI authentication

Diagnosis: token acceptance and message 63 previously crossed the server's
authentication boundary without proving the SSH session/user binding. The new
GssapiMicMechanism trait requires explicit MIC production/verification. Client
GSSAPI is an opt-in ClientAuthMethod variant; server policy must install a
MIC-capable context. Legacy token-only callbacks neither advertise nor enable
the method. The caller supplies a fresh context and peer authorization policy
per connection; no Kerberos/SSPI/KDC or GSS KEX is bundled.

The server verifies message 66 only after token-context acceptance. MIC input
is RFC 4462's SSH string first-session-id, byte 50, username, service, and method.
Message 63 is a denial, even after accepted tokens. MIC/token/mechanism failures
discard pending state and return normal authentication failure, allowing later
listed methods. A panic is denial. Only a verified MIC can produce message 52
and mark the transport authenticated. A fake context tests successful auth,
session/user/service/method mismatches, token and MIC-production failures,
password fallback, token-only policy denial, and message-63 denial.

### 0035 reusable seal input

`PacketProtector` keeps one scratch allocation for the plaintext it copies
before framing. A later seal reuses that capacity instead of allocating another
payload-sized `Vec`. Failure and success both wipe that copy and record the
existing `SealInput` witness. The clear packet is still the buffer handed back
as ciphertext. That is the returned packet, not a discarded copy.

### 0007 landed after the blocker note

The note below described the required design. `src/kex/modern.rs` now implements
it, and both handshakes use it. `cargo test -p neotales-ssh --all-targets
--all-features --offline` from `rs/lib` passed on 2026-11-11, including
`tests/kex_breadth.rs`. P-384 uses SHA-384. P-521 uses SHA-512. Group exchange
uses messages 34/31/32/33 and rejects a group other than the approved 4096-bit
safe prime before key generation. SHA-1 group exchange, group1, and sntrup are
not advertised.

The earlier inspection, kept so the constraint is not rediscovered:

### 0007 design constraint

- `kex/mod.rs::compute_exchange_hash`, KexCompletion, SessionIdTracker and the
  common derive_key validators fix the baseline exchange/session hashes to
  32 bytes and SHA-256. RFC 5656 P-384 requires SHA-384 and P-521 requires
  SHA-512, including matching RFC 4253 key expansion. Merely adding elliptic
  curve mechanisms or advertising their names would produce wrong keys.
- Group16 has a separate SHA-512 context/completion/derivation path. Its fixed
  prime/agreement implementation is not a validated arbitrary-group engine.
- RFC 4419 group exchange requires bounded request/group/init/reply stages
  (34/31/32/33), validation of group size and safe parameters **before use**,
  an exchange hash including requested min/preferred/max and group parameters,
  and staged handshake/sequence handling. The existing generic path expects
  the two-message 30/31 exchange. It must not be relabeled as group exchange.

Next work must generalize hash-width/derivation contracts or add a fully separate
correctly hashed path, integrate the extra group stages, then prove all three
names through both handshakes and reject out-of-bound groups before expensive
group use. No unsupported new name or stub was advertised. No failed or partial
KEX implementation was left in the tree; there is no failing test hidden here.

### Verification

Commands ran from `rs/lib`:

- `cargo test -p neotales-ssh --all-targets --all-features` — **536 passed,
  19 ignored, zero failures**.
- `cargo test -p neotales-ssh` — **537 passed including the doctest,
  19 ignored, zero failures**.
- `cargo clippy -p neotales-ssh --all-targets --all-features -- -D warnings`
  — **passed without warnings**.
- `git diff --check` — passed; edited Rust files were formatted with rustfmt.

Final logs: `ssh-pass6-{all,default,clippy}.log` in the session temporary
directory. No NEOTALES_SSH_E2E, ignored lane, Windows/native pipe, or real GSS
mechanism was run. Streaming zlib was not added. There were no additional
findings outside the task list in this continuation; earlier findings remain
below. Existing uncommitted work was preserved. No commits, pushes, credentials
reads, or atlas edits were made.

## Previous continuation: auth negotiation, certificate trust, identity import

The task contract now explicitly supersedes tests of obsolete behavior. This
section supersedes the previous pass's 0010 blocker and its statement that 0006
was not started. No previous security finding below is removed.

Completed in this continuation:

- **0010:** The old `partial_success_false_stops_before_the_second_method`
  test was renamed and changed to require fallback, with a comment explaining
  the RFC/task contract. It reproduced `AuthenticationFailed` before the fix.
  The client now follows the server's remaining-method list after ordinary or
  partial failure. `partial_success()` exposes the distinction; false and true
  cases remain separately tested. Keyboard-interactive routes response 61
  through the normal transports and can repeat, bounded at 32 challenges.
  Empty prompt text and oversized prompts fail before invoking the responder;
  RFC 4256 zero-prompt challenges remain legal. Explicit `ClientAuthMethod::None`
  can succeed only under `with_none_policy`; default and account denial tests
  remain negative. Unsolicited method responses cannot authenticate. Message 61
  is shared with GSSAPI tokens, so dispatch uses the pending exchange context.
- **0006:** Ed25519 host/user certificate integration is opt-in. The host signer
  configuration verifies the certificate's role and matching subject key. The
  client `connect_with_known_hosts` path validates the host CA marker, concrete
  principal, explicit timestamp, and CA signature. `UserCertificateTrust`
  supplies a public CA, time provider, and application account/principal policy.
  Proof-of-possession is verified separately against the subject key over the
  SSH session transcript. All critical options are rejected, including unknown
  options, source-address, and force-command; none are silently allowed. Tests
  cover both sides, expired/not-yet-valid, wrong principal/CA, damaged signature,
  application denial, and critical options. Integration currently supports
  Ed25519 certificates only; the broader standalone certificate parser remains.
  Raw-host-key defaults are unchanged. No issuance or prompt was introduced.
- **0009:** `private_key::import_pkcs8_der` imports unencrypted PKCS#8 DER for
  Ed25519, RSA, P-256, P-384, and P-521. `import_openssh` returns userauth signers
  from the existing binary OpenSSH parser. Tests cover encrypted/unencrypted
  OpenSSH Ed25519, RSA, and P-256, all five PKCS#8 algorithms, wrong passphrases,
  passphrase wiping, and fixed/redacted errors. DER input is bounded at 1 MiB;
  temporary scalar copies are wiped. PEM armor and encrypted PKCS#8 are not
  implemented (the task permits PKCS#8 or PEM). Larger-curve OpenSSH containers
  remain unsupported; their private keys import through PKCS#8 DER. No default
  identity path, disk access, PPK, or export API was added.

Diagnosis: ordinary failure was being treated as a terminal connection result,
keyboard-interactive was pinned to a single request/response pair at both the
transport and authenticator layers, and none had no explicit policy route.
The correction changes the state machines and their old-behavior test rather
than retaining an incorrect hard-stop contract. Certificate parsing alone did
not establish connection trust; the added handshake/userauth paths require
trust checks and subject-key proof rather than treating a CA blob match as
authentication. PKCS#8 decoding is kept separate from OpenSSH container parsing.

Verified from `rs/lib`:

- `cargo test -p neotales-ssh --all-targets --all-features` — **528 passed,
  19 ignored, zero failures**.
- `cargo test -p neotales-ssh` — **529 passed including the doctest,
  19 ignored, zero failures**.
- `cargo clippy -p neotales-ssh --all-targets --all-features -- -D warnings`
  — **passed without warnings**.
- `git diff --check` — passed. Edited Rust files were formatted with
  `rustfmt --edition 2024`.

Logs: `ssh-auth10-before.log`, `ssh-auth10.log`, `ssh-certificate-trust.log`,
`ssh-import.log`, and final `ssh-pass5-{all,default,clippy}.log` in the session
temporary directory. No NEOTALES_SSH_E2E or ignored lane was run. No new
cross-platform or live-peer claim is made.

Still open, not implemented in this continuation: **0024, 0023, 0007, 0011**
(agent server, Windows pipe connector, KEX breadth, and GSSAPI MIC). Their task
files were read. Streaming zlib was not added. No credentials were read, atlas
was not edited, and nothing was committed or pushed. Pre-existing uncommitted
work was preserved. No additional finding outside the task list was identified
in this continuation; the earlier x509 finding remains recorded below.

## Previous pass: auth and forwarding tasks (historical)

### Final outcome

Implemented and verified against the requested Done-when lists: 0012, 0008,
0022, 0018, 0017, 0016, 0020, 0015, 0019, and 0021. Qualifications are explicit:
ext-info advertisement is opt-in, OpenSSH SFTP symlink order must be selected
by an application that knows its SSH peer, and pipelining is STAT-specific.
0010 remains blocked as detailed below. Optional 0006 was read but not started;
host/user certificate trust integration is not claimed.

Diagnosis: the ext-info codec and its round-trip tests agreed on an incorrect
nested name-list length. The independent RFC 8308 fixture reproduced
`LimitExceeded`; extension values now contain raw comma-separated names.
The transport consumes requested initial ext-info before authentication and
the server advertises its authentication signature policy. RSA signing and
verification retain DigestInfo for both SHA-2 algorithms. The auth path and
agent flags now cover RSA SHA-512 and all three implemented NIST curves;
mismatched signature algorithm labels are rejected.

The remaining changes add authenticated-only transport ping replies; explicit
port-zero policy plus application allocation; implemented-only config proposal
lists; explicit POSIX/PowerShell SCP quoting; default-deny agent forwarding;
version-gated SFTP extension methods; and default-deny streamlocal/X11 helpers.
No host-key proposal was widened by the authentication changes.

Streamlocal and X11 are wire-only APIs on `ChannelConnection`, not automatic
`ServerSessions` routing. Applications dispatch generic request/open events to
the helpers and own binding/grant lifecycle. `StreamlocalPolicy` independently
authorizes direct, reverse, bind, and cancel operations. `X11Policy` independently
authorizes requests and opens. Paths are opaque and bounded, reserved streamlocal
fields are parsed and ignored, and X11 Debug output redacts protocol/cookie.
No socket, display, local agent connection, or process environment is accessed.

SFTP extensions require the exact advertised revision (statvfs 2, the other
four 1). Unadvertised requests write nothing. `SymlinkOrder::Draft` remains the
default; `OpenSsh` selects target-then-link order without guessing from VERSION.
`begin_stat`/`finish_stat` permit 16 outstanding requests, match ids out of order,
and retain at most 16 MiB of buffered replies. Unknown/duplicate peer ids disable
the pipeline. Synchronous operations cannot overlap a pending batch. Existing
metadata item/byte caps remain intact.

Final commands ran from `rs/lib`:

- `cargo test -p neotales-ssh --all-targets --all-features` — passed:
  518 passed, 19 ignored, zero failures across 50 test binaries.
- `cargo clippy -p neotales-ssh --all-targets --all-features -- -D warnings`
  — passed without warnings.
- `cargo test -p neotales-ssh --doc` — one doctest passed.
- Edited Rust sources/tests were formatted with `rustfmt --edition 2024`.

Final test and lint logs are `ssh-pass4-all.log`, `ssh-pass4-clippy.log`, and
`ssh-pass4-doc.log` under the session temporary directory. Focused streamlocal
and X11 byte-transport tests also passed. No NEOTALES_SSH_E2E lane was run.
This pass adds no live-peer or cross-platform interoperability claim. Existing
uncommitted work was preserved; no commits, pushes, atlas edits, or credential
reads were made.

### Reverted slices and remaining auth work

Automatic `ext-info-c` advertisement was attempted and reverted. It changed
`ed25519_authentication_reuses_the_transport_for_application_data` from three
server packets to four. The existing sequence assertion failed. The explicit
`ClientConfig::with_extension_info` path retains the feature without changing
the default packet-count contract. Both strict and non-strict SHA-512-only
negotiation and missing ext-info fallback have passing focused tests.

0010 is blocked by an existing test that requires the behavior the task removes.
`cargo test -p neotales-ssh --test userauth partial_success_false_stops_before_the_second_method`
failed after allowing ordinary method fallback. Authentication succeeded with
the later listed method; the test required failure. The fallback slice was
reverted as requested. The test was not rewritten. Keyboard-interactive repeat
and none-success changes were not started. Closing 0010 requires permission to
replace the old stop-on-failure expectation with the task's fallback contract.

## Finding outside the SSH task list

`crypto/x509/src/ssh_cert.rs::verify_rsa` verified RSA SHA-2 SSH certificate
signatures with `Pkcs1v15Sign::new_unprefixed`. SHA-256 and SHA-512 signatures
require their PKCS#1 DigestInfo prefixes. The certificate verifier rejected
correctly prefixed signatures after the SSH signer was fixed. Both branches
were corrected. The x509 manifest explicitly enables RSA SHA-2 support.
This is an x509 finding. It is **not covered by SSH task 0027**. The SSH
certificate integration test reproduced it. The x509 suite passed after the fix.

## Current status after continuation

Completed from the first pass: 0027, 0025, 0026, 0033, 0038, 0029, 0036,
0037, 0030, 0031, and 0032. The long-test filter remains installed.

Completed in the continuation: 0034, the safe in-place sealing slice of 0035,
0005, 0013, 0014, and the separate real-peer lane in 0003.

0028 uses the permitted default-off fallback. No streaming lifecycle was added.
The continuation found two additional proposal builders:
`src/client/handshake.rs::supported_client_kexinit` and
`src/server/handshake.rs::supported_server_kexinit` still offered zlib after the
first pass changed the generic constructor. Both now offer only `none`.
The supported catalog excludes zlib. Both handshakes reject explicit zlib
selection before key exchange. Standalone packet-zlib primitives remain, but
cannot be negotiated by the handshakes. Streaming zlib remains deferred.
No native zlib dependency was added.

### AES keyed-state reuse and packet allocations

`src/cipher.rs::CtrState` owns expanded AES key state for its entire key epoch.
Each speculative CTR cursor borrows that key on the stack. No key schedule or
boxed stream is constructed per packet. Length probes and failed opens do not
commit the cursor. GCM keeps a keyed AES-GCM instance per direction and borrows
it for each operation. Rekey constructs replacement state and drops the old
state. RustCrypto zeroize features are enabled for the cached state and scratch.
No SIMD, assembly, native CPU flags, or C library was introduced.

`src/chacha_cipher.rs::seal_in_place` encrypts in the caller's Vec and appends
its tag. The common protector path reserves tag space before adding plaintext,
so it hands on the same allocation without another full-packet copy. Short and
maximum-size packets preserve their buffer pointer and round-trip. Errors wipe
and clear the in-place buffer. If an external caller lacks tag capacity, the
exceptional growth path wipes the replaced plaintext allocation before release.
The immutable-slice seal adapter copies input once. ChaCha seal/open no longer
copy their successful result out of a Zeroizing Vec; they transfer ownership.

Remaining copies: `PacketProtector::seal` retains its intermediate payload copy.
Open adapters still copy immutable ciphertext and extract a caller-owned payload.
Those adapters cannot mutate the caller's borrowed buffer. This pass does not
claim an allocation-free packet path or an in-place transport receive API.

An attempted removal of the uncompressed intermediate payload copy was reverted.
It changed `a_seal_that_fails_midway_wipes_the_plaintext_it_built` from a Wiped
witness to no witness because that allocation no longer existed. The slice was
restored to preserve the existing failure test, as requested. No failure or
rekey assertion was removed. The successful ChaCha-seal witness now checks
HandedOn ciphertext instead of a discarded clear packet. It still checks that
the retained intermediate payload copy was wiped.

### Host keys and public configuration

`ClientConfig::connect_with_host_keys` requires algorithm-aware application
trust after signature verification. It supports Ed25519, RSA SHA-256/512, and
ECDSA P-256. The old `connect` callback remains Ed25519-only and rejects other
types. `ServerConfig` can retain additional RSA and ECDSA keys beside its primary
Ed25519 key. It filters the actual proposal to configured keys, selects the
negotiated signer, and signs with the exact negotiated signature algorithm.
RSA's `ssh-rsa` key blob never authorizes a SHA-1 signature. Rekey pins the same
host key and signature algorithm. P-384 and P-521 are not offered.

The public handshake test covers four host algorithms, three key exchanges,
trust acceptance and rejection, protected application exchange, and hybrid
rekey for all four host algorithms. A prior negative test used RSA as an
unreachable algorithm. Its peer now offers SHA-1 `ssh-rsa` instead, preserving
the negative negotiation test while testing the newly supported RSA paths
positively in the new matrix.

KexInit, NegotiatedAlgorithms, and NegotiationError are re-exported from the
crate root. The doctest mirror exposes the same names. A downstream-style test
constructs and passes a named proposal to both configs. Private catalogs remain
private.

### Session controls

ClientSessions sends signal, window-change, and break with the RFC wire fields.
ServerSessions decodes them before calling an optional explicit control policy.
No control policy means deny. Events retain decoded controls and exact payload
bytes. The library never sends a host signal or resizes a PTY. Tests cover each
client method, default denial and a requested failure reply, explicit acceptance,
and truncated/trailing input that leaves the callback count unchanged.

### Separate real-peer package

`ssh/e2e` is the unpublished workspace member `neotales-ssh-e2e`.
It pins testcontainers to `=0.28.0`. The image is
`lscr.io/linuxserver/openssh-server` at OCI index digest
`sha256:161e0b670b31d9539ca1718bc5943e981779331b4e1c9d32e8929d7652a1f22f`.
The image and digest are recorded in its test and README.
The native and testcontainers peers execute the same handshake, pinned-trust
acceptance/rejection, and authorized/unauthorized public-key authentication cases.
Both real peers ran successfully in this continuation. No old ignored lane ran.

All peer bodies return early without NEOTALES_SSH_E2E=1. Docker absence skips
locally. Missing sshd or ssh-keygen skips the native Unix fixture. The native
fixture compiles out and skips on non-Unix platforms. Windows and macOS were
not executed here. The manual-only monorepo `rs-ssh-e2e` workflow requires
`docker info` to succeed before testing. Its exported-prefix mirror is
`.github/workflows/ssh-e2e.yml` under rs/lib. Neither existing unit workflow was
changed. The library dependency graph contains no testcontainers dependency.

## Continuation verification

Commands ran from rs/lib. Final results:

- `cargo test -p neotales-ssh --all-targets --all-features`: 503 passed,
  19 ignored, zero failures. Existing packet, failure, tamper, and rekey tests pass.
- `cargo test -p neotales-ssh`: 504 passed including the doctest, 19 ignored.
- `cargo clippy -p neotales-ssh --all-targets --all-features -- -D warnings`:
  passed without warnings.
- `RUSTDOCFLAGS="-D warnings" cargo doc -p neotales-ssh --no-deps`: passed.
- `cargo test -p neotales-ssh-e2e`: two tests returned successfully with peer
  bodies gated off; total test duration was 0.00 seconds.
- `NEOTALES_SSH_E2E=1 cargo test -p neotales-ssh-e2e -- --nocapture`: both real
  peers passed, no skip messages, zero failures.
- `cargo clippy -p neotales-ssh-e2e --all-targets -- -D warnings`: passed.
- `cargo fmt -p neotales-ssh -p neotales-ssh-e2e -- --check`: passed.
- `cargo tree -p neotales-ssh --edges normal,build,dev`: no testcontainers entry.
- `git diff --check`: passed.

The full gates were preceded by focused packet/cipher, client rekey, server
transport, session control, and host-key matrix runs. Their test bodies passed.
The optional streaming-zlib implementation was not attempted. Existing packet
copy adapters are retained as described above. No commit or push was made.

## First-pass diagnosis and changes (historical)

- 0027: the local signer and verifier shared the same bare-digest error.
  Both host algorithms and both authentication paths now use hash-specific
  DigestInfo padding. A RustCrypto-generated signature verifies without this
  crate's signer. RustCrypto independently checks this crate's output.
  The regression also rejects bare-digest signatures for both host algorithms.
  The separate x509 finding is recorded above and is not covered by task 0027.
- 0025: failed authentication did not invalidate either transport.
  The client and server now discard both protectors, pending buffers, and rekey
  state on protected framing/integrity errors. Short reads and WouldBlock retain
  resumable state. The server transport suite drives both endpoints through
  tampered tags and corrupted lengths for ChaCha, both AES key sizes, GCM,
  encrypt-and-MAC, and encrypt-then-MAC. Later reads and writes leave stream
  queues untouched. Existing split-read/write tests still pass.
- 0026: `src/session.rs::ServerSessions::dispatch_one` acknowledges peer-first
  CLOSE directly through the channel layer before removing session state.
  The test drives 1,025 pending and 1,025 accepted sessions without EOF or exit
  status. Every close produces a reply and frees channel capacity.
- 0033: `src/sftp.rs::parse_data_response` borrows the DATA string, checks its
  requested length and frame cap, then copies. An oversized result is rejected.
- 0038: `src/agent.rs::sign_with_flags` checks the input lengths plus all 13
  framing bytes before constructing Writer. At-cap requests work. One byte over
  returns FrameTooLarge without a read or write.
- 0029: SFTP VERSION extensions are capped at 128, extended attribute pairs at
  256 per block, and directory entries at 1,024. A NAME response has a shared
  4,096-item entry/extended-attribute budget. Counts are checked before growing
  collections. Empty pairs, tiny entries, and aggregate-budget exhaustion are
  covered. The 16 MiB frame cap is unchanged.
- 0036: `src/session.rs::EnvironmentPlan::from_send_and_set` retains the supplied
  generic wrappers without copying their names or values. Only selected,
  validated assignments acquire owned bytes. Removal/re-addition and SetEnv
  precedence remain unchanged.
- 0037: `src/session.rs::ServerOptionalState` retains accepted environment names
  only. Existing duplicate rejection still works.
- 0030: `src/chacha_cipher.rs::ChaChaCipher` documents uniqueness across raw
  seal/open, clones, retries, and rekey. The stateful PacketProtector rejects
  repeated or decreasing ChaCha seal sequences after success. Rekey clears
  this check for fresh keys. Raw explicit-sequence callers own uniqueness.
- 0031: server-owned auth packets and encoded keyboard answers wipe on drop.
  Stored and temporary answer lists use Zeroizing, including partially decoded
  lists on errors. The response encoder reserves before adding answers.
  The discarded ChaCha clear packet wipes on both success and error.
  Compressed input passed to decompression is wrapped too. Public codec outputs
  remain caller-owned; their documentation assigns wiping to that caller.
  Wipe witnesses inspect still-live allocations inside Drop, not freed memory.
- 0032: shared-secret mpint encoding no longer routes through the copying
  general mpint encoder. Transcript/hash buffers use Zeroizing. Group16
  exponent, shared integer, and serialized shared magnitude use Zeroizing.
  SharedSecret's existing redacted Debug and wiping destructor remain intact.

## Test filtering

The existing OpenSSH lanes remain ignored. Each checks `NEOTALES_SSH_E2E=1`
before resource creation and skips on missing tools. Linux channel lanes also
skip when Docker is unavailable. Long group16 exchange/handshake tests and the
loopback transfer lifecycle test are ignored and runtime-gated. Fast unit,
codec, in-memory protocol, and OpenSSH discovery tests remain in the normal run.
`--all-features` does not bypass these gates.

The opt-in command is documented in `docs/compatibility.md`:

```sh
NEOTALES_SSH_E2E=1 cargo test -p neotales-ssh -- --ignored
```

No ignored lane was run. The first pass did not add testcontainers or a CI job;
the separate continuation package and dispatch-only workflows are described above.

## First-pass verification (historical)

All commands ran from the `rs/lib` Cargo workspace.

- `cargo test -p neotales-ssh --test rsa_hostkey digestinfo -- --exact digestinfo_signatures_interoperate_and_bare_digests_are_rejected`
  failed with InvalidSignature before the RSA fix.
- `cargo test -p neotales-ssh --test rsa_hostkey --test userauth`
  passed: 7 RSA and 28 auth tests after the fix.
- `cargo test -p neotales-ssh --test server_transport all_supported_kex_and_packet_suites_round_trip_through_the_server`
  failed on the still-established server before terminalization.
- `cargo test -p neotales-ssh --test server_transport --test client_transport`
  passed: 18 tests in each binary after terminalization.
- `cargo test -p neotales-ssh --test channel_lifetime server_sessions_acknowledge_peer_close_and_reuse_capacity`
  failed with an empty CLOSE reply list before the session fix.
- `cargo test -p neotales-ssh --test channel_lifetime --test session_channel`
  passed: 10 channel-lifetime and 39 session tests.
- `cargo test -p neotales-ssh --test kexinit p0_names_are_present_once_and_compression_is_only_none`
  failed because the old default still advertised zlib.
- `cargo test -p neotales-ssh --test kexinit --test sftp --test agent`
  passed after the default and bounds changes. Final SFTP coverage also includes
  the added metadata-budget case.
- `cargo test -p neotales-ssh --test environment --test userauth --test client_transport --test packet_protection`
  passed after the environment, nonce, and auth-wipe changes.
- `cargo test -p neotales-ssh --test kex --test dh_group16`
  passed: 20 KEX tests and 3 fast group16 tests; 2 long tests ignored.
- The first full test run failed in the RSA certificate test. This reproduced
  the dependency's matching bare-digest verifier defect. It passed after the
  certificate verifier correction.
- Final `cargo test -p neotales-ssh --all-targets --all-features`
  passed: 498 tests, 19 ignored, zero failures. No e2e bodies ran.
- Final `cargo test -p neotales-ssh`
  passed: 499 tests including the doctest, 19 ignored, zero failures.
- `cargo test -p neotales-x509`
  passed: 32 tests including the doctest, zero failures.
- Final `cargo clippy -p neotales-ssh --all-targets --all-features -- -D warnings`
  passed without warnings.
- Edited Rust files were formatted with `rustfmt --edition 2024`.

No cross-platform build was run. No Unix-only production API was introduced.
No library process spawning or process-environment reads were introduced.
The worktree already contained uncommitted changes when this pass began.
Those changes were preserved. Nothing was committed or pushed.
# Current status — 2026-11-12

Recorded tasks 0003 and 0005–0038 are implemented on branch `plab-rs-ssh`.
Later work added P-384/P-521 host keys, delayed zlib, non-ML-KEM rekey, an
`ssh -R` byte tunnel, a memory SFTP server, in-memory recursive SCP, explicit
Include and explicit ProxyCommand spawn. Deprecated SHA-1, group1, CBC, 3DES,
RC4 and HMAC-SHA1 require explicit legacy opt-in. The committed sntrup hybrid
completes both handshakes via explicit KEXINIT. Security-key host verification
requires an explicit verification callback; it is not a device/resident-key
implementation. ML-DSA-44/65/87 host keys now have opt-in real signing and
verification, with both handshakes tested for 65. Default proposals are unchanged.
These continuations do not claim new live-peer interoperability; details and
verification are recorded at the top of this file and in compatibility.md.

The earlier gap lists are historical findings from the pre-implementation review,
not current status.
