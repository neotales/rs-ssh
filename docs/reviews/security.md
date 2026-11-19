# SSH security, performance, and allocation review

## Scope

Reviewed on 2026-11-11. This is an independent source review of the current
uncommitted `rs/lib/ssh/ssh` tree. It includes the session, environment, agent,
SCP, and SFTP work. It does not reuse the previous review.

Paths below are relative to this crate. Findings name the source functions or
types inspected. Line numbers are navigation aids, not stable identifiers.
This document records work for later remediation. No implementation was changed.

The main paths read were packet framing and protection, client and server
handshakes, authentication, key exchange, host-key handling, channel and session
lifecycle, agent framing, SCP, and SFTP. Selected tests were read to check what
their assertions establish. This was not an exhaustive review of every module
or every test.

The review uses `code-ergonomics.md`, especially Performance, Resource cleanup,
Trust boundaries and wire formats, and Documentation at the point of use.
It also uses `testing.md`: a test name is not evidence of its claimed property.
These are atlas standards. No formatting or lint findings are included.

All findings are source-derived. None is a demonstrated exploit or a measured
speed result. Medium findings need correction before relying on the affected
security or protocol contract. Low findings are bounded allocation or performance
work. No high-severity exploit was established; that is not a security clearance.

## Findings

| id | severity | kind | location | summary |
| --- | --- | --- | --- | --- |
| F01 | medium | security | `src/transport.rs::ProtectedReadBuffer::open_packet`; client/server protected reads | A failed authentication does not make the transport terminal. |
| F02 | medium | security | `src/session.rs::ServerSessions::{dispatch_one,send_close}` | Peer-first CLOSE strands a channel behind the session API. |
| F03 | medium | security | `src/rsa_hostkey.rs::RsaHostSigner::sign_with_typed_algorithm`; `src/auth.rs::RsaAuthSigner::sign` | RSA SHA-2 uses unprefixed padding over a bare digest. |
| F04 | medium | security | `src/compression.rs::{compress_payload,decompress_payload}`; handshake protector installation | Delayed compression starts too early and uses independent finished streams. |
| F05 | medium | security | `src/sftp.rs::{parse_version,decode_attributes,parse_name_response}` | Valid-size frames can expand into very large metadata collections. |
| F06 | medium | security | `src/chacha_cipher.rs::ChaChaCipher::seal` | The public low-level API omits the nonce-uniqueness safety contract. |
| F07 | medium | security | `src/auth.rs::ServerAuthenticator::step`; keyboard-interactive paths; `src/cipher.rs::open_chacha` | Internal plaintext copies escape the existing wipe discipline. |
| F08 | medium | security | `src/kex/mod.rs::{SharedSecret::from_raw,compute_exchange_hash}`; `src/kex/dh_group16.rs` | Secret-bearing encoding and hash temporaries use ordinary vectors. |
| F09 | low | allocation | `src/sftp.rs::parse_data_response` | The requested read length is checked after copying the response data. |
| F10 | low | performance | `src/cipher.rs::{new_ctr_stream,encrypt_gcm,decrypt_gcm}` | Packet operations rebuild keyed AES state; CTR also allocates boxes. |
| F11 | low | allocation | `src/cipher.rs::PacketProtector::seal`; `src/chacha_cipher.rs::ChaChaCipher::{seal,open}` | Packet paths make avoidable full-size copies. |
| F12 | low | allocation | `src/session.rs::EnvironmentPlan::from_send_and_set` | Supplied values are copied before byte bounds and selection. |
| F13 | low | allocation | `src/session.rs::ServerOptionalState`; `ServerSessions::handle_request` | Duplicate detection retains environment values it never uses. |
| F14 | low | allocation | `src/agent.rs::AgentClient::sign_with_flags` | The combined outbound frame limit is checked after serialization. |

### F01 — Authentication failure leaves a reusable transport

`ProtectedReadBuffer::open_packet` clears the received frame on an opening
error (`src/transport.rs:485`). `ClientTransport::read_protected_packet`
propagates that error without clearing `established` or discarding the protectors
(`src/transport.rs:930`). Outside rekey, `ServerTransport::read_dispatch_payload`
does the same (`src/server/handshake.rs:1497`).

The bad packet returns no plaintext. That part is correct. The connection can
still be used for subsequent reads and writes, however. Stream consumption has
already occurred, while the packet sequence and cipher position have not been
committed. Retrying an integrity failure is not a safe recovery contract.

Basis: `code-ergonomics.md` §§ Repetition and partial failure, Documentation at
the point of use, and Trust boundaries and wire formats.

**Remediation:** Make integrity and unrecoverable framing failures terminal at
the transport boundary. Preserve resumable `WouldBlock` behavior. Discard pending
state and keys, and reject later protocol I/O. Document that transition on the
public read methods.

**Proof needed:** After tampering, assert that both later reads and writes fail
without touching the stream. Cover both endpoints and each suite. The tampering
tests at `tests/client_transport.rs:402` and `:433` check the immediate error and
unchanged sequence only. The latter's “fails closed” name overstates those
assertions. This is the specific `testing.md` warning about names and assertions.

### F02 — Peer-first session close cannot be acknowledged

`ServerSessions::dispatch_one` removes `sessions` and `optional` entries as soon
as it receives `ChannelEvent::Close` (`src/session.rs:2333`). Its `send_close`
then requires that missing session entry and returns `RequestRequired`
(`src/session.rs:2516`).

The underlying `ChannelConnection::apply_close` marks only the remote side
closed. It does not send the reply. Retirement requires both sides to close
(`src/channel.rs:1403,1752`). An accepted peer-first close therefore leaves a
channel slot occupied when handled through `ServerSessions`. Repetition can
consume the connection's 1,024-channel ceiling. This is bounded per connection,
not an unbounded global leak. An application can work around it through the
lower-level connection, but the session API should not require that escape.

Basis: RFC 4254 §5.3, also quoted by `apply_close`; `code-ergonomics.md`
§ Resource cleanup.

**Remediation:** Complete the close reply before discarding the required state,
or retain a closing state until acknowledgment succeeds. A reply to peer CLOSE
must not require a locally generated exit status or EOF first.

**Proof needed:** Drive peer-first CLOSE through `ServerSessions`, including a
pending session and an accepted command. Assert the reply and channel retirement.
Repeat beyond the concurrency ceiling. The peer-first test at
`tests/channel_lifetime.rs:279` exercises `ChannelConnection`, not this wrapper.

### F03 — RSA SHA-2 omits DigestInfo

`RsaHostSigner::sign_with_typed_algorithm` hashes the message and calls
`Pkcs1v15Sign::new_unprefixed()` on the bare digest
(`src/rsa_hostkey.rs:510`). `verify_host_key_signature` selects the same padding.
`RsaAuthSigner::sign` and `verify_public_key` repeat the construction in
`src/auth.rs:395,3313`.

The requested encoding omits the SHA algorithm's DER DigestInfo prefix.
SSH `rsa-sha2-256` and `rsa-sha2-512` require RSASSA-PKCS1-v1_5 with the selected
hash, not unprefixed digest padding. Matching local signers and verifiers hide
the mismatch. This is a cryptographic wire-format defect, not evidence of a
signature forgery.

Basis: RFC 8332 §3 and RFC 8017 §9.2; `code-ergonomics.md` § Trust boundaries and
wire formats.

**Remediation:** Use the upstream hash-specific PKCS#1 v1.5 signing and verifying
mode on all four paths. Resolve any digest/OID trait-version mismatch explicitly.
Do not retain the raw mode merely to make the dependency types compile.

**Proof needed:** Use independently generated SHA-256 and SHA-512 signatures.
Check both signing and verification, and reject the old unprefixed encoding.
`tests/rsa_hostkey.rs::fixed_key_signs_and_verifies_both_sha2_algorithms` verifies
the crate's signatures with the crate's verifier. It does not distinguish these
encodings. No external interoperability check was run for this review.

### F04 — OpenSSH compression has the wrong lifecycle

`compress_payload` creates a new `ZlibEncoder` and finishes it for every payload.
`decompress_payload` creates a fresh decoder and requires `StreamEnd`
(`src/compression.rs:83,106`). SSH zlib uses a continuing stream between reset
boundaries, not one finished zlib file per packet.

There is a second lifecycle error. The handshake protector factories install
the negotiated compression directly (`src/client/handshake.rs:1223,1235` and
`src/server/handshake.rs:872`). `PacketProtector::seal` and
`decompress_if_selected` apply it immediately. `ServerTransport::mark_authenticated`
only changes a boolean (`src/server/handshake.rs:1071`). The advertised
`zlib@openssh.com` mode must remain inactive until authentication succeeds.

This breaks the negotiated wire contract and exposes decompression work before
user authentication. The output cap is useful, but does not repair either state
transition. The source shows repeated codec setup; its CPU cost was not measured.

Basis: RFC 4253 §6.2 and the delayed-compression contract of `zlib@openssh.com`;
`code-ergonomics.md` §§ State and mutation and Trust boundaries and wire formats.

**Remediation:** The smallest safe interim change is to stop offering this mode.
To support it, keep per-direction streaming state, activate it at the proper
authentication boundary, and reset it at the protocol's key-change boundary.
Keep bounded incremental output. Do not replace this with a mandatory native
zlib dependency.

**Proof needed:** Check uncompressed authentication packets, the activation
boundary, multiple packets sharing a dictionary, and rekey. Use an independent
stream fixture. `tests/compression.rs::zlib_round_trips_and_rejects_trailing_data`
checks a whole-stream round trip, not SSH stream lifetime.

### F05 — SFTP metadata amplifies bounded input

`parse_version` retains every extension pair, including empty pairs
(`src/sftp.rs:2686`). Each pair needs only eight wire bytes. A frame near the
16 MiB limit can therefore request roughly two million `SftpExtension` values.
With two three-word vectors per entry on a 64-bit target, entry storage alone
is roughly 96 MiB, before the frame and spare vector capacity. This is a layout
estimate, not an allocation measurement.

`decode_attributes` permits extended-attribute counts up to remaining bytes
divided by eight. `parse_name_response` uses remaining bytes divided by twelve
for directory entries (`src/sftp.rs:2792,2866`). These checks reject impossible
counts. They do not set a practical decoded-object budget. A hostile SFTP peer
can cause substantial memory and allocator work with a permitted-size frame.

Basis: `code-ergonomics.md` § Trust boundaries and wire formats, especially
bounding collection sizes rather than only encoded lengths.

**Remediation:** Add explicit extension, attribute, and directory-entry limits.
Apply an aggregate decoded-memory or item budget across nested attributes.
Validate before growing collections. Use fallible reservation where a bounded
request can still fail allocation.

**Proof needed:** Feed many empty extension pairs, tiny valid directory entries,
and nested extended attributes through the client API. Measure peak allocation
and show rejection before the item budget is exceeded. The oversized-prefix test
at `tests/sftp.rs:115` does not cover these valid-size frames.

### F06 — Standalone ChaCha requires an unstated safety precondition

`ChaChaCipher` is public, cloneable, and stateless. `seal(&self, sequence_number,
packet)` derives the nonce from that supplied sequence
(`src/chacha_cipher.rs:120,178,414`). Its method documentation describes framing
and lengths, but not the requirement never to encrypt different packets with
the same sequence under the same direction key.

Reusing that pair repeats the ChaCha keystream and Poly1305 one-time key.
The transport's sequence management does not protect a caller of this standalone
API. Saying that the type does not advance the sequence is not enough to explain
safe retry, cloning, rekey, and directional use.

Basis: `code-ergonomics.md` §§ Documentation at the point of use and Signatures
that carry the contract. This is the explicit agent-usability failure: the
signature and method comment do not give a new caller enough information to use
the primitive safely.

**Remediation:** Mark this as a low-level escape hatch. Document per-key nonce
uniqueness on `seal`, distinct direction keys, no wrap/reset under an unchanged
key, and the fact that clones share the same nonce domain. Show retries resending
cached ciphertext rather than sealing changed data. Direct ordinary callers to
the stateful transport; a guarded sender can be added if standalone sending is
intended as a common API.

**Proof needed:** Keep an executable usage example and sequence-exhaustion tests
for the guarded path. No nonce collision was observed in the transport path.

### F07 — Receive and keyboard-interactive plaintext is not wiped

`ServerAuthenticator::step` owns the decrypted authentication packet in an
ordinary vector (`src/auth.rs:2131`). Password bytes in that packet are freed
without the outbound path's `PlaintextBytes` protection.

`KeyboardInteractiveResponse` stores and clones ordinary strings.
`decode_keyboard_interactive_response` allocates ordinary response strings, and
`ClientAuthenticator::authenticate_keyboard_interactive` holds both the answers
and encoded reply without a wipe guard (`src/auth.rs:1252,1403,3091`). The encoder
can also grow its writer after it already contains earlier answers.

There is another internal copy on receive. `ChaChaCipher::open` returns a normal
vector copied from its zeroizing buffer (`src/chacha_cipher.rs:355`).
`cipher.rs::open_chacha` copies out the payload, then drops that full clear packet
without wiping it (`src/cipher.rs:1240`). Even callers that wipe the returned
payload cannot remove this discarded copy.

These are memory-remanence issues. They do not imply disclosure over the wire or
through the redacted Debug implementations.

Basis: `code-ergonomics.md` § Resource cleanup; the secret-buffer lifetime
contract already implemented by `cipher.rs::PlaintextBytes`.

**Remediation:** Guard library-owned receive packets and response strings from
construction through every return path. Pre-size secret-bearing encodings so
growth does not free earlier secret copies. Guard the intermediate ChaCha clear
packet immediately, or pass ownership through a protected internal buffer type.
Document responsibility for caller-owned buffers separately.

**Proof needed:** Add live-buffer wipe witnesses for success, parse failure,
callback rejection, and I/O failure. Do not inspect freed memory. The tests at
`tests/packet_protection.rs:914,1006` prove specific outbound buffer wipes, not
these inbound or keyboard-interactive lifetimes.

### F08 — KEX wrappers do not cover all secret copies

`SharedSecret::from_raw` builds an ordinary `positive` vector and passes it into
`encode_mpint` (`src/kex/mod.rs:425`). `Writer::write_mpint_with_limit` creates
ordinary input and canonicalized vectors while producing another encoded copy
(`src/wire.rs:567`). Wiping the final `SharedSecret` does not wipe those copies.

`compute_exchange_hash` appends the shared secret to an ordinary transcript
vector and hashes it (`src/kex/mod.rs:722`).
`compute_group16_exchange_hash` does the same
(`src/kex/dh_group16.rs:996`). `DhGroup16::agree_impl` also produces an ordinary
`shared.to_bytes_be()` temporary (`src/kex/dh_group16.rs:417`).

That group16 function converts the private exponent into `BigUint` before
`modpow`. The byte-owner wipe test does not establish the lifetime or timing
properties of these arithmetic copies. Dependency destructors and constant-time
behavior were not inspected and are not claimed here.

Basis: `code-ergonomics.md` § Resource cleanup; the crate's existing
`SharedSecret` and ephemeral-owner wipe contract.

**Remediation:** Encode secret mpints directly into pre-sized protected storage,
or guard every intermediate in that path. Feed public transcript framing and the
secret separately into the hash to avoid a combined secret-bearing allocation.
Guard the group16 byte temporary. Audit the resolved big-integer backend before
claiming complete zeroization or constant-time secret exponentiation.

**Proof needed:** Extend wipe witnesses beyond owner destructors to these
temporaries. `tests/kex.rs::the_group16_exponent_destructor_wipes_every_byte_before_releasing_it`
checks the stored byte exponent, not the `BigUint` or serialized shared result.

### F09 — SFTP rejects oversized DATA after copying it

`parse_data_response` calls the allocating `read_string` with the global packet
limit, then compares `data.len()` with `expected_length`
(`src/sftp.rs:2767`). A tiny requested read can cause a near-16 MiB frame and a
second near-16 MiB data vector before rejection. The outer frame is bounded;
the needless second copy is the finding.

Basis: `code-ergonomics.md` §§ Performance and Trust boundaries and wire formats.

**Remediation:** Read a borrowed string bounded by `expected_length`, validate
trailing data, then copy once. A later request-aware framing design could also
reduce the first allocation, but is not needed for this fix.

**Proof needed:** Request one byte and return a much larger, globally valid DATA
packet. Assert rejection before allocating a data-sized output vector.

### F10 — AES state is rebuilt for each packet operation

`new_ctr_stream` constructs a new AES-CTR cipher and boxes it on each call
(`src/cipher.rs:1611`). `apply_ctr` uses that helper; the encrypted-length receive
path performs additional CTR work before opening the full packet.
`encrypt_gcm` and `decrypt_gcm` construct keyed GCM objects for every packet
(`src/cipher.rs:1745,1784`).

The repeated setup and CTR boxes are visible in source. Their throughput impact
is unmeasured. They can obscure gains from an accelerated block-cipher backend,
especially for small packets.

Basis: `code-ergonomics.md` § Performance. This is a should-fix measurement target,
not a reason to replace clear code with unmeasured custom cryptography.

**Remediation:** Benchmark first. If material, retain keyed cipher objects for
the key epoch and replace them only at rekey. Avoid per-operation boxes. Preserve
transactional counter updates on failed opens and the special length-probe
behavior; do not advance the live stream merely to inspect a length.

**Proof needed:** Compare small-packet latency, bulk throughput, and allocations
before and after. Keep counter exhaustion, partial I/O, tampering, and rekey
tests load-bearing.

### F11 — Packet protection copies more than ownership requires

With compression disabled, `PacketProtector::seal` first copies payload and
padding (`src/cipher.rs:826`). `build_clear_packet` copies them again. It is also
the later point that validates their combined length. An invalid direct internal
call therefore copies before rejection.

ChaCha sealing then copies the full clear packet into another buffer and copies
the ciphertext again for return (`src/chacha_cipher.rs:210,225`). Opening copies
into a zeroizing clear buffer, copies that for return, and copies out the payload
in `cipher.rs::open_chacha`. These are full-buffer operations, not tiny metadata
allocations. The plaintext lifetime defect is covered separately by F07.

Basis: `code-ergonomics.md` § Performance.

**Remediation:** Borrow the uncompressed inputs, validate before copying, and
build one correctly sized protected buffer. Add an internal in-place or
ownership-taking ChaCha path. Hand ciphertext ownership onward without cloning.
Keep plaintext guards on every fallible path. Do not remove the tag-capacity
reservation that avoids reallocating a clear packet.

**Proof needed:** Count allocations and copied bytes across suites, with and
without compression. Preserve the existing outbound wipe witnesses. Do not impose
an allocation assertion that requires keeping an unnecessary copy alive.

### F12 — Environment planning copies invalid inputs before filtering

`EnvironmentPlan::from_send_and_set` copies every supplied name and value into
`supplied` before validating byte lengths or matching `SendEnv`
(`src/session.rs:1060`). The 1,024-entry ceiling limits count, not bytes. A single
large invalid or unselected caller value is still cloned.

This is caller-driven allocation, not a remote environment-request bypass.
The documented behavior already permits skipping invalid supplied entries.

Basis: `code-ergonomics.md` §§ Defensive coding and Performance.

**Remediation:** Validate borrowed names and values before cloning. Retain only
bounded candidates needed for pattern evaluation. Continue counting consumed
inputs, including invalid entries, so filtering does not remove the existing
input-count bound. Preserve ordered removal and `SetEnv` override semantics.

**Proof needed:** Supply oversized invalid and unselected values. Assert they
are not copied. Keep the ordering and invalid-entry behavior covered by
`tests/environment.rs`; its current examples do not measure allocation.

### F13 — Server duplicate detection retains unused environment values

`ServerOptionalState.environment` stores `(name, value)` vectors.
`ServerSessions::handle_request` clones both after accepting an environment
request (`src/session.rs:2078,2682`). `environment_allowed` later inspects only
the names (`src/session.rs:2833`). The event already transfers the value to the
application.

The extra value survives until peer CLOSE or endpoint destruction. Policy names
and request sizes bound it; it is not an unbounded list. It still needlessly
multiplies retained bytes across concurrent sessions.

Basis: `code-ergonomics.md` §§ Performance and Resource cleanup.

**Remediation:** Retain only accepted names for duplicate detection. Keep exact
allowlist matching, the count ceiling, and session cleanup unchanged.

**Proof needed:** Accept multiple bounded values and show that only names remain
in duplicate-tracking state. Verify duplicate rejection and both close orderings.

### F14 — Agent outbound length validation comes after construction

`AgentClient::sign_with_flags` serializes the key blob and data into a `Writer`
before `send_frame` applies the 1 MiB total limit (`src/agent.rs:245,275`).
Each string can pass its own bound while the combined request cannot fit.
The payload length is `13 + key_blob.len() + data.len()`.

Inbound `read_frame` correctly validates its prefix before body allocation.
This finding is limited to wasted outbound construction.

Basis: `code-ergonomics.md` §§ Defensive coding and Performance.

**Remediation:** Compute the total with checked arithmetic and reject it before
creating the writer. Reserve the validated size once.

**Proof needed:** Test two individually valid fields whose combined size exceeds
the frame cap. Assert no request write and no combined-size allocation. The
inbound-prefix test at `tests/agent.rs:135` does not exercise this path.

## Crypto speed

The crate already delegates its main primitives to RustCrypto and dalek crates.
That is the right portability boundary. `Cargo.toml` inherits most versions and
features with `workspace = true`. It directly requests `sha2 = "0.11"` and adds
`arithmetic` for the P-curves and `sha2` for RSA. This does not establish resolved
versions, feature unification, backend selection, or emitted instructions.
The workspace manifest, lockfile, and dependency implementations were outside
scope. No accelerator is declared enabled or disabled on that incomplete evidence.

| primitive | inspected call path | portable acceleration action |
| --- | --- | --- |
| AES-GCM | `cipher.rs::{encrypt_gcm,decrypt_gcm}` use `aes_gcm` | Verify the resolved AES and GHASH backends. Prefer upstream AES instructions and carry-less multiplication where supported, with runtime selection and software fallback. Address repeated keyed setup in F10 before assuming the primitive is the bottleneck. |
| AES-CTR | `cipher.rs::new_ctr_stream` uses `ctr::Ctr128BE<aes::Aes128/Aes256>` | Reuse upstream AES acceleration. CTR does not need GHASH. Measure the per-call construction, boxes, and length probe separately. Never require AES instructions for all binaries. |
| ChaCha20-Poly1305 | `chacha_cipher.rs::{new_stream,compute_tag}` use `ChaCha20Legacy` and `poly1305` | Check the resolved crates' available SIMD backends and dispatch. Remove F11's copies before writing intrinsics. Preserve the OpenSSH two-key, 64-bit-nonce construction; an IETF AEAD substitution is not wire-compatible. |
| SHA-2 | `kex/mod.rs::compute_exchange_hash`, group16 hashing, and RSA digest paths use `sha2` | Use upstream architecture-specific SHA implementations where that release supports them, with portable fallback. Streaming the transcript avoids F08's combined allocation. No assembly or target feature flag is prescribed without checking the resolved version. |
| Curve25519 | `kex/curve25519.rs::Curve25519::agree` and hybrid KEX use `x25519-dalek` | Verify the resolved dalek backend and its supported runtime or build selection. Keep its portable implementation available. Do not force an x86 vector backend onto ARM or assume backend selection from the wrapper's name. |
| P-256 | `kex/ecdh_p256.rs::EcdhP256::agree` multiplies the validated point with `p256` arithmetic | Keep upstream constant-time arithmetic. Check what optimized backend the resolved release actually supports. AES/SHA instructions do not imply faster curve multiplication. Do not replace it with mandatory OpenSSL, platform APIs, or custom SIMD. |
| RSA | `rsa_hostkey.rs::RsaHostSigner::sign_with_typed_algorithm` and `auth.rs::RsaAuthSigner::sign` | Correct F03 first. Measure private operations separately from hashing and public verification. Use upstream portable arithmetic and safe precomputation if supported. The call sites supply no RNG; audit the resolved signing API and select its blinded private operation with a CSPRNG where provided. No timing attack or blinding guarantee was verified. |
| ML-KEM | `kex/mlkem768_x25519.rs::{ClientEphemeral::complete,ServerKex::accept_init}` use `ml_kem` | Benchmark the complete hybrid exchange as well as encapsulation and decapsulation. Audit the resolved release for upstream NTT and hash acceleration; do not invent a SIMD feature. Prefer an existing optimized backend with portable fallback if available. Keep exact wire lengths and decapsulation semantics unchanged. |

The default must keep working on Linux, Windows, and macOS, with future
Android and iOS targets in mind. No mandatory C library, OS crypto API, global
`target-cpu=native`, or unconditional CPU instruction requirement is recommended.
This follows `code-ergonomics.md` § Performance: prefer available acceleration,
but retain the portable fallback. Availability and speed still need verification.

## Allocation

The main allocation risks are different and should be measured separately:

- **Peer-controlled expansion:** F05's decoded SFTP object count matters more
  than its bounded wire size. F09 adds an avoidable large data copy before error.
- **Per-packet churn:** F10 and F11 repeat setup, boxes, and full-packet copies.
  Measure short interactive packets and large transfers independently.
- **Secret lifetime:** F07 and F08 concern discarded copies, not just peak heap
  size. Replacing a guarded vector with an ordinary reusable buffer is not a fix.
- **Retention and early rejection:** F12 through F14 can be improved without
  changing wire behavior. F02 needs lifecycle repair, not merely a larger cap.

`SftpClient` and SCP currently return owned data. Ownership alone is not a defect.
The SCP file cap is 64 MiB, so a single-file download can legitimately allocate
that much. Streaming is a possible future API, not an alleged missing bound.

No allocator instrumentation was run. The SFTP and agent oversized-prefix tests
inspect stream consumption, not allocator calls. Source ordering supports their
pre-allocation checks, but those assertions would not detect every allocation
regression. Future allocation tests should reject a mutation that moves the
allocation ahead of the guard, as required by `testing.md`.

## Left alone

- `wire.rs::Reader` checks field lengths before returning borrowed slices or
  copying values. No blanket rewrite of that parser is warranted.
- Agent inbound frames are capped at 1 MiB before allocation. SFTP inbound
  frames are capped at 16 MiB. Packet content is capped at 1 MiB. These are real
  bounds, though they do not settle F05 or F09.
- SCP bounds its header line at 8 KiB and file body at 64 MiB before reserving
  the body. The crate supplies protocol and command handling, not an audited
  filesystem sandbox.
- ChaCha verifies Poly1305 with a constant-time comparison before decrypting.
  HMAC uses the upstream verification API. These source properties do not prove
  that every dependency operation is constant-time.
- AES-GCM checks overflow of the trailing 64-bit invocation counter. Transport
  sequence checks refuse exhaustion rather than silently wrapping. F06 concerns
  standalone callers, not an observed transport nonce reuse.
- X25519 checks contribution, P-256 decodes and validates curve points, and the
  ML-KEM hybrid enforces exact 1,216-byte client and 1,120-byte server blobs.
  The hybrid server validates the encapsulation key before use.
- Initial host-key verification precedes the application's trust callback.
  Rekey pins the host key. `known_hosts` gives revocation precedence and does
  not treat a CA marker as ordinary host-key trust.
- Outbound password construction and the protected-write retry buffer already
  use wipe-owning storage. F07 does not claim those paths are unprotected.
- Channel live/pending state and tombstones are capped. The general two-sided
  channel retirement rule is correct. F02 is the session-wrapper mismatch.
- `EnvironmentPlan` takes an explicit environment rather than reading process
  state. Server environment acceptance remains policy-controlled. F12 and F13
  are copy and retention findings, not evidence of allowlist bypass.
- `openssh_key.rs` delegates encrypted-key derivation and round validation to
  the excluded x509 dependency and maps its invalid-rounds error. No unbounded
  bcrypt-cost finding is asserted without reviewing that dependency.
- README and `docs/compatibility.md` distinguish recorded live results from the
  current ignored lanes. Those historical results were not rerun or independently
  certified here.

### Coverage limits

No other crate, application, Docker SSH implementation, or x509 implementation
was inspected. No credential store, environment file, or key fixture body was
opened. Shared standards and repository instructions were read as review policy.

This was not a dependency audit, compiler-code-generation audit, constant-time
analysis, fuzz campaign, or complete API/specification review. Exact dependency
features, portable acceleration availability, allocator peaks, exploitability,
and cross-platform behavior remain unchecked. Source-derived defects above do
not depend on claiming those checks passed.

### Verification

Source and selected test assertions were inspected with file reads and targeted
searches. `git status --short --untracked-files=all -- rs/lib/ssh/ssh` was run and
showed the existing uncommitted work and untracked review documents. That is a
working-tree inventory, not a correctness test.

An inline `python3 -` document check passed. It checked the required sections,
table header, 14 unique finding rows and subsections, 14 remediation and proof
blocks, and absence of frontmatter. It did not test the Rust implementation.

No `cargo test`, `cargo check`, lint, benchmark, allocation profiler, mutation
test, cross-platform build, or live network test was run. Proposed proofs in
the findings are future work, not passing results from this review.
