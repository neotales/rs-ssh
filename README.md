# neotales-ssh

SSH-2 protocol implementation with wire codecs, key exchange, authentication, transport, and host-key handling.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-ssh)

**Negotiate keys, leave trust policy to the application.** `neotales-ssh` handles the wire exchange, while your application decides which host keys to trust.

<!-- badges: crates.io, docs.rs, CI. Add once the first version exists. -->

## Install 📦

```sh
cargo add neotales-ssh
```

## What you can do 🔧

**Encode SSH wire strings.** `encode_string` writes the SSH length prefix and bytes. `decode_string` reads that format and returns the payload.

```rust
use neotales_ssh::{decode_string, encode_string};

let encoded = encode_string(&b"hello".as_slice())?;
assert_eq!(decode_string(&encoded)?, b"hello");
# Ok::<(), neotales_ssh::Error>(())
```

**Exchange key proposals.** `KexInit` represents the algorithm lists in an SSH key-exchange proposal. `negotiate` returns the common algorithms or `NegotiationError::NoCommonAlgorithm`.

**Authenticate and protect packets.** `authenticate_client` and `authenticate_server` run user authentication over their respective transports. `ClientTransport` and `ServerTransport` handle protected SSH packets and rekeying.

**Check host keys.** `HostPublicKey` represents public host keys, and `KnownHosts` reads known-hosts data. `SshClientBuilder::pin` lets a client require a host key supplied by the caller.

The crate provides protocol building blocks and client helpers; applications choose host-key trust policy and server session policy.

## Licence 📜

[MIT](LICENSE.md)

## Test 🧪

The crate uses Rust 1.100 and RustCrypto dependencies. Run its library and doctests offline from this repository:

```sh
cargo test --lib --offline
cargo test --doc --offline
```
