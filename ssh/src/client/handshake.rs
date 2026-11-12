//! Client-side SSH identification, negotiation, and initial key exchange.

use std::fmt;
use std::io::{Read, Write};

use crate::cipher::{PacketKeyMaterial, PacketProtectionError, PacketProtector, PacketSuite};
use crate::hostkey::{Ed25519PublicKey, HostKeyError, HostPublicKey, verify_algorithm_host_key};
use crate::kex::dh_group16::{Group16ClientKex, Group16KexContext};
use crate::kex::mlkem768_x25519::ClientKex as MlKemClientKex;
use crate::kex::{
    Curve25519, DerivationLengths, DhGroup16, EcdhP256, ExchangeHashInput, KexContext, KexError,
    KeyExchange, compute_exchange_hash, derive_keys,
};
use crate::msg::kexinit::{
    AES128_CTR, AES128_GCM_OPENSSH, AES256_CTR, AES256_GCM_OPENSSH, COMPRESSION_NONE,
    CURVE25519_SHA256, CURVE25519_SHA256_LIBSSH, ECDH_SHA2_NISTP256, HMAC_SHA2_256,
    HMAC_SHA2_256_ETM_OPENSSH, HMAC_SHA2_512, HMAC_SHA2_512_ETM_OPENSSH,
    KEX_DIFFIE_HELLMAN_GROUP16_SHA512, KEX_MLKEM768X25519_SHA256, KEX_STRICT_C_V00_OPENSSH,
    KexInit, NegotiationError, SSH_MSG_KEXINIT, SUPPORTED_HOST_KEY_ALGORITHMS,
    SUPPORTED_MAC_ALGORITHMS, kex_guess_matches,
};
use crate::sequence::{
    Direction, PacketDisposition, PacketObservation, RekeyPhase, SSH_MSG_DEBUG, SSH_MSG_DISCONNECT,
    SSH_MSG_IGNORE, SSH_MSG_KEX_METHOD_FIRST, SSH_MSG_KEX_METHOD_LAST, SSH_MSG_NEWKEYS,
    SSH_MSG_UNIMPLEMENTED, SequenceError,
};
use crate::transport::{ClientRekeyState, ClientTransport, RekeyProtection, TransportError};
use neotales_ssh::compression::CompressionAlgorithm;

/// The exact client identification software string, without its CR LF.
pub const CLIENT_IDENTIFICATION: &str = "SSH-2.0-neotales-ssh_0.1";

const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;
const AES128_KEY_LENGTH: usize = 16;
const AES256_KEY_LENGTH: usize = 32;
const CHACHA_KEY_LENGTH: usize = 64;
const CHACHA20_POLY1305_OPENSSH_NAME: &str =
    neotales_ssh::chacha_cipher::CHACHA20_POLY1305_OPENSSH_NAME;
const CTR_IV_LENGTH: usize = 16;
const GCM_IV_LENGTH: usize = 12;
const CHACHA_IV_LENGTH: usize = 8;
const SHA256_INTEGRITY_LENGTH: usize = 32;
const SHA512_INTEGRITY_LENGTH: usize = 64;

/// A safe client-handshake failure that contains no attacker-controlled data.
#[derive(Debug)]
pub enum HandshakeError {
    /// Identification, framing, I/O, protection, or sequence handling failed.
    Transport(TransportError),
    /// One required algorithm category had no mutually supported name.
    Negotiation,
    /// A selected name is outside this client's implemented mechanism set.
    UnsupportedAlgorithm,
    /// KEX proposal validation, message decoding, agreement, or derivation failed.
    Kex(KexError),
    /// Host-key parsing, signature verification, or application trust failed.
    HostKey(HostKeyError),
    /// A fresh KEXINIT cookie could not be obtained from the operating system.
    EntropyFailure,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "SSH client transport error: {error}"),
            Self::Negotiation => {
                formatter.write_str("SSH client proposals have no common algorithm")
            }
            Self::UnsupportedAlgorithm => {
                formatter.write_str("SSH client selected an unsupported algorithm")
            }
            Self::Kex(error) => write!(formatter, "SSH client key-exchange error: {error}"),
            Self::HostKey(error) => write!(formatter, "SSH client host-key error: {error}"),
            Self::EntropyFailure => {
                formatter.write_str("SSH client random-number generation failed")
            }
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Kex(error) => Some(error),
            Self::HostKey(error) => Some(error),
            Self::Negotiation | Self::UnsupportedAlgorithm | Self::EntropyFailure => None,
        }
    }
}

impl From<TransportError> for HandshakeError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<SequenceError> for HandshakeError {
    fn from(error: SequenceError) -> Self {
        Self::Transport(error.into())
    }
}

impl From<KexError> for HandshakeError {
    fn from(error: KexError) -> Self {
        Self::Kex(error)
    }
}

impl From<neotales_ssh::Error> for HandshakeError {
    fn from(error: neotales_ssh::Error) -> Self {
        Self::Kex(KexError::Wire(error))
    }
}

impl From<HostKeyError> for HandshakeError {
    fn from(error: HostKeyError) -> Self {
        Self::HostKey(error)
    }
}

impl From<PacketProtectionError> for HandshakeError {
    fn from(error: PacketProtectionError) -> Self {
        Self::Transport(TransportError::PacketProtection(error))
    }
}

impl From<HandshakeError> for TransportError {
    fn from(error: HandshakeError) -> Self {
        match error {
            HandshakeError::Transport(error) => error,
            HandshakeError::Negotiation | HandshakeError::UnsupportedAlgorithm => {
                Self::UnexpectedMessage
            }
            HandshakeError::Kex(_) | HandshakeError::HostKey(_) => Self::InvalidMessage,
            HandshakeError::EntropyFailure => Self::EntropyFailure,
        }
    }
}

impl From<NegotiationError> for HandshakeError {
    fn from(_error: NegotiationError) -> Self {
        Self::Negotiation
    }
}

/// Reusable client proposal and connection policy.
///
/// The default proposal advertises the implemented ephemeral ECDH mechanisms,
/// group 16 DH, Ed25519, RSA SHA-2, NIST P-256 host keys, all implemented packet
/// suites, the strict-KEX marker, and only `none` compression. A fresh random
/// cookie is generated for each connection. Use [`Self::connect_with_host_keys`]
/// for an algorithm-aware callback; [`Self::connect`] retains the Ed25519-only
/// callback contract and rejects other key types.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    security_key_verifier: Option<crate::security_key::SecurityKeyVerifier>,
    legacy_algorithms: bool,
    kexinit: KexInit,
    delayed_compression: bool,
    immediate_compression: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientConfig {
    /// Creates the supported client proposal with a placeholder cookie.
    #[must_use]
    pub fn new() -> Self {
        Self {
            kexinit: supported_client_kexinit([0; 16]),
            security_key_verifier: None,
            legacy_algorithms: false,
            delayed_compression: false,
            immediate_compression: false,
        }
    }

    /// Replaces the client proposal while retaining the caller's KEXINIT cookie.
    ///
    /// The connection replaces the cookie with fresh random bytes before the
    /// proposal is encoded. Unsupported selected algorithms and nonzero
    /// reserved fields are rejected rather than removed from either side's
    /// transcript. Guessed first-KEX packets are not offered by this client.
    #[must_use]
    pub fn with_kexinit(kexinit: KexInit) -> Self {
        Self {
            kexinit,
            security_key_verifier: None,
            legacy_algorithms: false,
            delayed_compression: false,
            immediate_compression: false,
        }
    }

    /// Offers security-key host algorithms only with explicit verification.
    /// The callback owns cryptographic verification and presence/counter policy;
    /// the separate host trust callback still must approve the resulting key.
    /// No device access or hardware-provenance claim is made.
    #[must_use]
    pub fn with_security_key_verifier(
        mut self,
        verifier: crate::security_key::SecurityKeyVerifier,
    ) -> Self {
        self.security_key_verifier = Some(verifier);
        for name in [crate::security_key::ED25519, crate::security_key::ECDSA] {
            if !self
                .kexinit
                .server_host_key_algorithms
                .iter()
                .any(|offered| offered == name)
            {
                self.kexinit
                    .server_host_key_algorithms
                    .push(name.to_owned());
            }
        }
        self
    }

    /// Explicitly offers pure ML-DSA-44/65/87 draft host keys after existing choices.
    /// Defaults exclude these names. A custom KEXINIT can also opt in directly.
    /// Use `connect_with_host_keys` to supply application trust for these keys.
    #[must_use]
    pub fn with_mldsa_host_keys(mut self) -> Self {
        for name in ["ssh-mldsa-44", "ssh-mldsa-65", "ssh-mldsa-87"] {
            if !self
                .kexinit
                .server_host_key_algorithms
                .iter()
                .any(|entry| entry == name)
            {
                self.kexinit
                    .server_host_key_algorithms
                    .push(name.to_owned());
            }
        }
        self
    }

    /// Enables deprecated SHA-1, CBC, 3DES, RC4, and group1 algorithms.
    /// Appends them after modern choices; never use this for untrusted legacy peers.
    /// Custom proposals containing these names are rejected without this call.
    #[must_use]
    pub fn with_legacy_algorithms(mut self) -> Self {
        self.legacy_algorithms = true;
        crate::msg::kexinit::enable_legacy_algorithms(&mut self.kexinit);
        self
    }

    /// Offers and permits `zlib@openssh.com`, activated only after authentication.
    /// Default configurations offer only `none`. Does not enable immediate `zlib`.
    #[must_use]
    pub fn with_delayed_compression(mut self) -> Self {
        self.delayed_compression = true;
        if !self
            .kexinit
            .compression_algorithms_client_to_server
            .iter()
            .any(|name| name == "zlib@openssh.com")
        {
            self.kexinit
                .compression_algorithms_client_to_server
                .insert(0, "zlib@openssh.com".to_owned());
        }
        self.kexinit.compression_algorithms_server_to_client =
            self.kexinit.compression_algorithms_client_to_server.clone();
        self
    }

    /// Offers and permits RFC 4253 `zlib` from NEWKEYS, including authentication.
    /// Not enabled by default or by `with_delayed_compression`. Streams reset at rekey.
    #[must_use]
    pub fn with_immediate_compression(mut self) -> Self {
        self.immediate_compression = true;
        if !self
            .kexinit
            .compression_algorithms_client_to_server
            .iter()
            .any(|name| name == "zlib")
        {
            self.kexinit
                .compression_algorithms_client_to_server
                .insert(0, "zlib".to_owned());
        }
        self.kexinit.compression_algorithms_server_to_client =
            self.kexinit.compression_algorithms_client_to_server.clone();
        self
    }

    /// Requests RFC 8308 signature negotiation by advertising `ext-info-c`.
    /// The server's list is recorded before client public-key authentication.
    #[must_use]
    pub fn with_extension_info(mut self) -> Self {
        if !self
            .kexinit
            .kex_algorithms
            .iter()
            .any(|name| name == "ext-info-c")
        {
            self.kexinit.kex_algorithms.push("ext-info-c".to_owned());
        }
        self
    }

    /// Returns the configured proposal before per-connection cookie generation.
    #[must_use]
    pub const fn kexinit(&self) -> &KexInit {
        &self.kexinit
    }

    /// Performs the complete synchronous client handshake over `stream`.
    ///
    /// The callback is mandatory and is invoked only after strict Ed25519
    /// signature verification succeeds. A callback error or panic rejects the
    /// host key before NEWKEYS is sent.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`HandshakeError`] for identification, I/O, proposal,
    /// key-exchange, host-key, derivation, protection, or sequence failures.
    #[allow(clippy::too_many_lines)]
    pub fn connect<S, F, E>(
        &self,
        stream: S,
        trust_callback: F,
    ) -> Result<ClientTransport<S>, HandshakeError>
    where
        S: std::io::Read + std::io::Write,
        F: FnOnce(&Ed25519PublicKey) -> Result<(), E>,
    {
        self.connect_with_host_keys(stream, |key| match key {
            HostPublicKey::Ed25519(key) => trust_callback(key).map_err(|_| ()),
            _ => Err(()),
        })
    }

    /// Connects with a mandatory trust callback for every supported host key.
    /// The callback runs only after signature verification and before NEWKEYS.
    ///
    /// # Errors
    /// Returns the same handshake and trust errors as [`Self::connect`].
    #[allow(clippy::too_many_lines)]
    pub fn connect_with_host_keys<S, F, E>(
        &self,
        stream: S,
        trust_callback: F,
    ) -> Result<ClientTransport<S>, HandshakeError>
    where
        S: Read + Write,
        F: FnOnce(&HostPublicKey) -> Result<(), E>,
    {
        if !self.legacy_algorithms && crate::msg::kexinit::has_legacy_algorithms(&self.kexinit) {
            return Err(HandshakeError::UnsupportedAlgorithm);
        }
        let mut client_kexinit = self.kexinit.clone();
        if self.security_key_verifier.is_none()
            && client_kexinit
                .server_host_key_algorithms
                .iter()
                .any(|name| crate::security_key::supported(name))
        {
            return Err(HandshakeError::UnsupportedAlgorithm);
        }
        if client_kexinit.reserved != 0 || client_kexinit.first_kex_packet_follows {
            return Err(HandshakeError::Kex(KexError::InvalidProposal));
        }
        getrandom::fill(&mut client_kexinit.cookie)
            .map_err(|_error| HandshakeError::EntropyFailure)?;
        let (mut transport, peer_version) = ClientTransport::start(stream, CLIENT_IDENTIFICATION)?;
        transport.ext_info = if client_kexinit
            .kex_algorithms
            .iter()
            .any(|name| name == "ext-info-c")
        {
            crate::transport::ExtensionState::Awaiting
        } else {
            crate::transport::ExtensionState::Disabled
        };
        transport.configure_rekey_proposal(self.kexinit.clone());
        transport.compression_policy = crate::transport::CompressionPolicy {
            delayed: self.delayed_compression,
            immediate: self.immediate_compression,
        };
        let client_payload = client_kexinit.encode()?;

        transport.write_handshake_packet(&client_payload, SSH_MSG_KEXINIT)?;
        let pending_server_kexinit = transport.receive_handshake_packet()?;
        let server_kexinit = KexInit::decode(&pending_server_kexinit.payload)?;
        if server_kexinit.reserved != 0 {
            return Err(HandshakeError::Kex(KexError::InvalidProposal));
        }
        let algorithms = client_kexinit.negotiate(&server_kexinit)?;
        let server_guess_is_correct = !server_kexinit.first_kex_packet_follows
            || kex_guess_matches(&server_kexinit, &algorithms);
        transport.configure_initial_algorithm(algorithms.kex.clone());
        let protection = ProtectionPlan::from_algorithms(
            &algorithms,
            self.delayed_compression,
            self.immediate_compression,
        )?;
        let strict_kex = client_kexinit.strict_kex_enabled(&server_kexinit);
        transport.configure_strict_kex(strict_kex)?;
        transport.accept_handshake_packet(
            &pending_server_kexinit,
            SSH_MSG_KEXINIT,
            Some(server_kexinit.first_kex_packet_follows),
        )?;

        if crate::kex::modern::supported(&algorithms.kex) {
            use crate::kex::modern;
            let gex = modern::is_gex(&algorithms.kex);
            if gex {
                transport.sequence.configure_group_exchange()?;
            }
            let context = modern::Context::new(
                CLIENT_IDENTIFICATION,
                &peer_version,
                &client_kexinit.encode()?,
                &server_kexinit.encode()?,
                &algorithms.kex,
            )?;
            let mut client = modern::Client::new(context)?;
            let first = client.first()?;
            transport.write_handshake_packet(&first, first[0])?;
            let mut pending = transport.receive_handshake_packet()?;
            if !server_guess_is_correct {
                transport.discard_guessed_handshake_packet(&pending)?;
                pending = transport.receive_handshake_packet()?;
            }
            if gex {
                let init = client.accept_group(&pending.payload)?;
                transport.accept_handshake_packet(&pending, 31, None)?;
                transport.write_handshake_packet(&init, 32)?;
                pending = transport.receive_handshake_packet()?;
            }
            let completion = client.complete(&pending.payload)?;
            let verified = verify_algorithm_host_key(
                &algorithms.host_key,
                &completion.host,
                &completion.signature,
                &completion.hash,
                self.security_key_verifier.as_ref(),
                trust_callback,
            )?;
            transport.accept_handshake_packet(&pending, if gex { 33 } else { 31 }, None)?;
            let derived = modern::derive(
                &algorithms.kex,
                &completion.shared,
                &completion.hash,
                &completion.hash,
                protection.lengths,
            )?;
            let write = protection.write_protector(&derived)?;
            let read = protection.read_protector(&derived)?;
            transport.write_handshake_packet(&[SSH_MSG_NEWKEYS], SSH_MSG_NEWKEYS)?;
            let newkeys = transport.receive_handshake_packet()?;
            if newkeys.payload != [SSH_MSG_NEWKEYS] {
                return Err(TransportError::InvalidMessage.into());
            }
            transport.accept_handshake_packet(&newkeys, SSH_MSG_NEWKEYS, None)?;
            transport.finish_handshake(completion.hash, verified, write, read)?;
            return Ok(transport);
        }

        if algorithms.kex == KEX_DIFFIE_HELLMAN_GROUP16_SHA512 {
            let context = Group16KexContext::new(
                CLIENT_IDENTIFICATION,
                &peer_version,
                client_kexinit.encode()?,
                server_kexinit.encode()?,
            )?;
            let mut mechanism = Group16ClientKex::new(DhGroup16::new(), context)?;
            let init_message = mechanism.init_message()?;
            transport.write_handshake_packet(&init_message, SSH_MSG_KEX_ECDH_INIT)?;
            let pending_reply = transport.receive_handshake_packet()?;
            let pending_reply = if server_guess_is_correct {
                pending_reply
            } else {
                transport.discard_guessed_handshake_packet(&pending_reply)?;
                transport.receive_handshake_packet()?
            };
            let completion = mechanism.complete(&pending_reply.payload)?;
            let verified_host_key = verify_algorithm_host_key(
                &algorithms.host_key,
                completion.host_key_blob(),
                completion
                    .signature_blob()
                    .ok_or(KexError::InvalidFieldLength)?,
                completion.exchange_hash(),
                self.security_key_verifier.as_ref(),
                trust_callback,
            )?;
            transport.accept_handshake_packet(&pending_reply, SSH_MSG_KEX_ECDH_REPLY, None)?;
            let derived = crate::kex::dh_group16::derive_keys_sha512(
                completion.shared_secret(),
                completion.exchange_hash(),
                completion.session_id(),
                protection.lengths,
            )?;
            let write_protector = protection.write_protector(&derived)?;
            let read_protector = protection.read_protector(&derived)?;
            transport.write_handshake_packet(&[SSH_MSG_NEWKEYS], SSH_MSG_NEWKEYS)?;
            let pending_server_newkeys = transport.receive_handshake_packet()?;
            if pending_server_newkeys.payload != [SSH_MSG_NEWKEYS] {
                return Err(TransportError::InvalidMessage.into());
            }
            transport.accept_handshake_packet(&pending_server_newkeys, SSH_MSG_NEWKEYS, None)?;
            transport.finish_handshake(
                completion.exchange_hash().to_vec(),
                verified_host_key,
                write_protector,
                read_protector,
            )?;
            return Ok(transport);
        }

        if algorithms.kex == KEX_MLKEM768X25519_SHA256 {
            let context = KexContext::new(
                CLIENT_IDENTIFICATION,
                &peer_version,
                client_kexinit.encode()?,
                server_kexinit.encode()?,
                &algorithms.kex,
            )?;
            let client = MlKemClientKex::generate()?;
            let init_message = client.init_message()?;
            transport.write_handshake_packet(&init_message, SSH_MSG_KEX_ECDH_INIT)?;
            let pending_reply = transport.receive_handshake_packet()?;
            let pending_reply = if server_guess_is_correct {
                pending_reply
            } else {
                transport.discard_guessed_handshake_packet(&pending_reply)?;
                transport.receive_handshake_packet()?
            };
            let completion = client.complete(&context, &pending_reply.payload)?;
            let verified_host_key = verify_algorithm_host_key(
                &algorithms.host_key,
                &completion.host_key_blob,
                &completion.signature_blob,
                &completion.exchange_hash,
                self.security_key_verifier.as_ref(),
                trust_callback,
            )?;
            transport.accept_handshake_packet(&pending_reply, SSH_MSG_KEX_ECDH_REPLY, None)?;
            let derived = derive_keys(
                &completion.shared_secret,
                &completion.exchange_hash,
                &completion.session_id,
                protection.lengths,
            )?;
            let write_protector = protection.write_protector(&derived)?;
            let read_protector = protection.read_protector(&derived)?;
            transport.write_handshake_packet(&[SSH_MSG_NEWKEYS], SSH_MSG_NEWKEYS)?;
            let pending_server_newkeys = transport.receive_handshake_packet()?;
            if pending_server_newkeys.payload != [SSH_MSG_NEWKEYS] {
                return Err(TransportError::InvalidMessage.into());
            }
            transport.accept_handshake_packet(&pending_server_newkeys, SSH_MSG_NEWKEYS, None)?;
            transport.finish_handshake(
                completion.session_id.to_vec(),
                verified_host_key,
                write_protector,
                read_protector,
            )?;
            return Ok(transport);
        }

        let context = KexContext::new(
            CLIENT_IDENTIFICATION,
            &peer_version,
            client_kexinit.encode()?,
            server_kexinit.encode()?,
            &algorithms.kex,
        )?;
        let mechanism = mechanism_for(&algorithms.kex)?;
        let ephemeral = mechanism.generate_ephemeral()?;
        let client_public_key = mechanism.public_key(&ephemeral)?;
        let init_message = mechanism.encode_init_message(&ephemeral)?;
        transport.write_handshake_packet(&init_message, SSH_MSG_KEX_ECDH_INIT)?;

        let pending_reply = transport.receive_handshake_packet()?;
        let pending_reply = if server_guess_is_correct {
            pending_reply
        } else {
            transport.discard_guessed_handshake_packet(&pending_reply)?;
            transport.receive_handshake_packet()?
        };
        let reply = mechanism.decode_reply_message(&pending_reply.payload)?;
        let server_public_key = reply
            .server_public_key()
            .ok_or(KexError::InvalidFieldLength)?;
        let shared_secret = mechanism.agree(ephemeral, server_public_key)?;
        let exchange_input = ExchangeHashInput::new(
            reply.host_key_blob(),
            &client_public_key,
            server_public_key,
            shared_secret.clone(),
        )?;
        let exchange_hash = compute_exchange_hash(&context, &exchange_input)?;
        let verified_host_key = verify_algorithm_host_key(
            &algorithms.host_key,
            reply.host_key_blob(),
            reply.signature_blob(),
            &exchange_hash,
            self.security_key_verifier.as_ref(),
            trust_callback,
        )?;
        transport.accept_handshake_packet(&pending_reply, SSH_MSG_KEX_ECDH_REPLY, None)?;

        let derived = derive_keys(
            &shared_secret,
            &exchange_hash,
            &exchange_hash,
            protection.lengths,
        )?;
        let write_protector = protection.write_protector(&derived)?;
        let read_protector = protection.read_protector(&derived)?;

        transport.write_handshake_packet(&[SSH_MSG_NEWKEYS], SSH_MSG_NEWKEYS)?;
        let pending_server_newkeys = transport.receive_handshake_packet()?;
        if pending_server_newkeys.payload != [SSH_MSG_NEWKEYS] {
            return Err(TransportError::InvalidMessage.into());
        }
        transport.accept_handshake_packet(&pending_server_newkeys, SSH_MSG_NEWKEYS, None)?;
        transport.finish_handshake(
            exchange_hash.to_vec(),
            verified_host_key,
            write_protector,
            read_protector,
        )?;
        Ok(transport)
    }

    /// Connects using `known_hosts` raw-key or CA trust, with explicit Unix time
    /// for certificate validation. Offers Ed25519 certificates before raw keys.
    /// Host principal, validity and CA signature must match. All critical
    /// options are rejected. Unknown hosts/CAs never prompt or mutate the store.
    ///
    /// # Errors
    /// Returns handshake, certificate trust, or protected transport errors.
    pub fn connect_with_known_hosts<S: Read + Write>(
        &self,
        stream: S,
        hosts: &neotales_ssh::known_hosts::KnownHosts,
        host: &str,
        port: u16,
        now: u64,
    ) -> Result<ClientTransport<S>, HandshakeError> {
        let mut config = self.clone();
        config
            .kexinit
            .server_host_key_algorithms
            .insert(0, neotales_ssh::cert::SSH_ED25519_CERT_V01.to_owned());
        config.connect_with_host_keys(stream, |key| -> Result<(), ()> {
            if let HostPublicKey::Certificate(blob) = key {
                neotales_ssh::cert::verify_host_certificate(blob, hosts, host, port, now)
                    .map(|_| ())
                    .map_err(|_| ())
            } else {
                let blob = key.to_blob().map_err(|_| ())?;
                if hosts.check(host, port, &blob)
                    == neotales_ssh::known_hosts::KnownHostsStatus::Trusted
                {
                    Ok(())
                } else {
                    Err(())
                }
            }
        })
    }
}

/// Runs the SSH client handshake with the supported default proposal.
///
/// The trust callback runs only after the peer host key has been verified;
/// returning `Err` rejects that key.
///
/// This example uses an empty stream to demonstrate that a peer which sends no
/// banner fails before the callback runs; it does not complete a handshake.
///
/// ```
/// use neotales_ssh::client::connect;
///
/// let result = connect(std::io::Cursor::new(Vec::<u8>::new()), |_host_key| {
///     Err::<(), &'static str>("reject host key")
/// });
/// assert!(result.is_err());
/// ```
///
/// # Errors
///
/// Returns the same errors as [`ClientConfig::connect`].
pub fn connect<S, F, E>(stream: S, trust_callback: F) -> Result<ClientTransport<S>, HandshakeError>
where
    S: std::io::Read + std::io::Write,
    F: FnOnce(&Ed25519PublicKey) -> Result<(), E>,
{
    ClientConfig::new().connect(stream, trust_callback)
}

impl<S> ClientTransport<S>
where
    S: Read + Write,
{
    /// Starts a client-initiated post-establishment rekey and sends its
    /// protected KEXINIT.
    ///
    /// The caller can drive the exchange incrementally with
    /// [`Self::advance_rekey`], or use [`Self::rekey`] for a blocking stream.
    /// Uses the initial exchange's algorithm: Curve25519, NIST P-256/P-384/P-521,
    /// group16-SHA512, group-exchange-SHA256 or ML-KEM768/X25519. The original
    /// session identifier remains the derivation input for every rekey.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`HandshakeError`] for an unestablished transport,
    /// an active/reentrant cycle, an unsupported proposal, or a failure while
    /// sending KEXINIT. Non-WouldBlock failures terminally disable the
    /// transport.
    pub fn begin_rekey(&mut self) -> Result<(), HandshakeError> {
        if !self.established {
            return Err(TransportError::NotEstablished.into());
        }
        if self.rekey.is_some() {
            if self.write_buffer.pending_message_type() == Some(SSH_MSG_KEXINIT)
                && self.sequence.rekey_outbound_phase() == RekeyPhase::KexInit
            {
                let Some(payload) = self.write_buffer.pending_payload() else {
                    self.abort_rekey();
                    return Err(TransportError::InvalidMessage.into());
                };
                return match self.write_rekey_packet(&payload, SSH_MSG_KEXINIT) {
                    Ok(()) => Ok(()),
                    Err(error) if is_would_block(&error) => Err(error),
                    Err(error) => {
                        self.abort_rekey();
                        Err(error)
                    }
                };
            }
            let error = self
                .sequence
                .begin_rekey()
                .err()
                .unwrap_or(SequenceError::InvalidState);
            self.abort_rekey();
            return Err(error.into());
        }
        if self.sequence.rekey_active() {
            let error = self
                .sequence
                .begin_rekey()
                .err()
                .unwrap_or(SequenceError::InvalidState);
            self.abort_rekey();
            return Err(error.into());
        }

        if !self
            .initial_algorithm
            .as_deref()
            .is_some_and(crate::kex::rekey::supported)
        {
            return Err(HandshakeError::UnsupportedAlgorithm);
        }
        let template = self
            .rekey_proposal
            .clone()
            .ok_or(TransportError::InvalidMessage)?;
        if !matches!(self.session_id.len(), 20 | 32 | 48 | 64) {
            return Err(HandshakeError::Kex(KexError::InvalidSessionId));
        }
        let local_kexinit = rekey_kexinit(
            &template,
            self.initial_algorithm
                .as_deref()
                .ok_or(HandshakeError::UnsupportedAlgorithm)?,
        )?;
        let local_kexinit_payload = local_kexinit.encode()?;
        if let Err(error) = self.sequence.begin_rekey() {
            self.abort_rekey();
            return Err(error.into());
        }
        self.rekey = Some(ClientRekeyState {
            local_kexinit,
            local_kexinit_payload,
            peer_kexinit: None,
            peer_kexinit_payload: None,
            peer_guessed: false,
            peer_guess_is_correct: true,
            protection: None,
            client_kex: None,
            method_payload: None,
            group_received: false,
            derived: None,
            client_method_sent: false,
            write_newkeys_sent: false,
        });
        let Some(state) = self.rekey.as_ref() else {
            self.abort_rekey();
            return Err(TransportError::InvalidMessage.into());
        };
        let local_payload = state.local_kexinit_payload.clone();
        match self.write_rekey_packet(&local_payload, SSH_MSG_KEXINIT) {
            Ok(()) => Ok(()),
            Err(error) if is_would_block(&error) => Err(error),
            Err(error) => {
                self.abort_rekey();
                Err(error)
            }
        }
    }

    /// Handles a peer-originated KEXINIT received by [`ClientTransport::read_payload`].
    ///
    /// The local KEXINIT is sent with the old keys, then the peer proposal is
    /// validated and the client method is emitted. The caller must continue
    /// driving [`Self::advance_rekey`] until the exchange completes.
    pub(crate) fn dispatch_peer_rekey(
        &mut self,
        payload: &[u8],
        sequence: u32,
    ) -> Result<(), TransportError> {
        if payload.first() != Some(&SSH_MSG_KEXINIT) {
            return Err(TransportError::UnexpectedMessage);
        }
        let begin = match self.begin_rekey() {
            Ok(()) => Ok(()),
            Err(error) if is_would_block(&error) => Ok(()),
            Err(error) => Err(error),
        };
        let result = begin.and_then(|()| {
            self.accept_peer_kexinit(payload, sequence)
                .and_then(|()| self.send_client_method())
        });
        match result {
            Ok(()) => Ok(()),
            Err(error) if is_would_block(&error) => Err(error.into()),
            Err(error) => {
                self.abort_rekey();
                Err(error.into())
            }
        }
    }

    /// Advances an active rekey by one protected inbound protocol packet.
    ///
    /// `Ok(false)` means that no rekey is active. Protected-packet bytes are
    /// retained by the transport, so a staged caller may retry after
    /// `WouldBlock` at any packet boundary or in the middle of a packet.
    /// Malformed packets, invalid ordering, cryptographic failures, and
    /// non-WouldBlock I/O errors terminally fail the rekey and disable
    /// protected I/O.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`HandshakeError`] for a transport, sequence,
    /// proposal, host-key, or packet-protection failure.
    pub fn advance_rekey(&mut self) -> Result<bool, HandshakeError> {
        if !self.established {
            return Err(TransportError::NotEstablished.into());
        }
        if self.rekey.is_none() {
            return Ok(false);
        }
        let result = self.advance_rekey_inner();
        match result {
            Ok(progress) => Ok(progress),
            Err(error) if is_would_block(&error) => Err(error),
            Err(error) => {
                self.abort_rekey();
                Err(error)
            }
        }
    }

    /// Performs one complete client-initiated post-establishment rekey.
    ///
    /// This is the blocking convenience form of [`Self::begin_rekey`] and
    /// [`Self::advance_rekey`]. KEXINIT, KEX method messages, and NEWKEYS use
    /// the old keys; the new write keys are installed after local NEWKEYS and
    /// the new read keys after peer NEWKEYS. The original session identifier
    /// is retained for key derivation.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`HandshakeError`] and terminally disables the
    /// transport for malformed proposals, unsupported/non-hybrid negotiation,
    /// host-key/signature failure, invalid ordering, I/O, or protection errors.
    pub fn rekey(&mut self) -> Result<(), HandshakeError> {
        self.begin_rekey()?;
        while self.rekey.is_some() {
            self.advance_rekey()?;
        }
        Ok(())
    }

    /// Alias for [`Self::begin_rekey`] using the state-machine naming.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::begin_rekey`].
    pub fn start_rekey(&mut self) -> Result<(), HandshakeError> {
        self.begin_rekey()
    }

    /// Alias for [`Self::rekey`] for callers that want the blocking operation.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::rekey`].
    pub fn perform_rekey(&mut self) -> Result<(), HandshakeError> {
        self.rekey()
    }

    fn resume_pending_rekey_write(&mut self) -> Result<bool, HandshakeError> {
        if !self.write_buffer.is_pending() {
            return Ok(false);
        }
        let Some(message_type) = self.write_buffer.pending_message_type() else {
            return Err(TransportError::InvalidMessage.into());
        };
        // The payload is fetched inside the arm that needs it rather than
        // before the match. Only a rekey message can be resumed here, so
        // copying the entry out on the way to rejecting it would hand a
        // `Vec<u8>` of whatever was pending — an authentication request whose
        // write blocked part-way, say — to a path that drops it un-wiped.
        match message_type {
            SSH_MSG_KEXINIT => {
                let payload = self
                    .write_buffer
                    .pending_payload()
                    .ok_or(TransportError::InvalidMessage)?;
                self.write_rekey_packet(&payload, SSH_MSG_KEXINIT)?;
            }
            SSH_MSG_KEX_METHOD_FIRST..=SSH_MSG_KEX_METHOD_LAST => {
                self.send_client_method()?;
            }
            SSH_MSG_NEWKEYS => {
                self.send_client_newkeys()?;
            }
            _ => return Err(TransportError::InvalidMessage.into()),
        }
        Ok(true)
    }

    fn advance_rekey_inner(&mut self) -> Result<bool, HandshakeError> {
        if self.resume_pending_rekey_write()? {
            return Ok(true);
        }
        if self
            .rekey
            .as_ref()
            .is_some_and(|state| state.peer_kexinit.is_some() && !state.client_method_sent)
        {
            self.send_client_method()?;
            return Ok(true);
        }
        if self
            .rekey
            .as_ref()
            .is_some_and(|state| state.derived.is_some() && !state.write_newkeys_sent)
        {
            self.send_client_newkeys()?;
            return Ok(true);
        }

        let (payload, sequence) = self.read_rekey_packet()?;
        let message_type = payload
            .first()
            .copied()
            .ok_or(TransportError::InvalidMessage)?;
        match message_type {
            SSH_MSG_KEXINIT => {
                self.accept_peer_kexinit(&payload, sequence)?;
                self.send_client_method()?;
            }
            SSH_MSG_KEX_METHOD_FIRST..=SSH_MSG_KEX_METHOD_LAST => {
                self.accept_peer_kex_method(&payload, sequence)?;
            }
            SSH_MSG_NEWKEYS => self.accept_peer_newkeys(&payload, sequence)?,
            _ => return Err(TransportError::UnexpectedMessage.into()),
        }
        Ok(true)
    }

    fn accept_peer_kexinit(&mut self, payload: &[u8], sequence: u32) -> Result<(), HandshakeError> {
        let local_kexinit = self
            .rekey
            .as_ref()
            .ok_or(TransportError::RekeyInProgress)?
            .local_kexinit
            .clone();
        let peer_kexinit = KexInit::decode(payload)?;
        if peer_kexinit.reserved != 0 {
            return Err(HandshakeError::Kex(KexError::InvalidProposal));
        }
        let algorithms = local_kexinit.negotiate(&peer_kexinit)?;
        let peer_guess_is_correct =
            !peer_kexinit.first_kex_packet_follows || kex_guess_matches(&peer_kexinit, &algorithms);
        if !crate::kex::rekey::supported(&algorithms.kex) {
            return Err(HandshakeError::UnsupportedAlgorithm);
        }
        let protection = rekey_protection(ProtectionPlan::from_algorithms(
            &algorithms,
            self.compression_policy.delayed,
            self.compression_policy.immediate,
        )?);
        self.accept_rekey_kexinit(sequence)?;
        if crate::kex::modern::is_gex(&algorithms.kex) {
            self.sequence.configure_rekey_group_exchange()?;
        }
        let client = crate::kex::rekey::Client::new(&crate::kex::rekey::Transcript {
            client_version: &self.client_version,
            server_version: &self.peer_version,
            client_init: &local_kexinit.encode()?,
            server_init: payload,
            algorithm: &algorithms.kex,
        })?;
        let state = self.rekey.as_mut().ok_or(TransportError::RekeyInProgress)?;
        if state.peer_kexinit.is_some() {
            return Err(TransportError::UnexpectedMessage.into());
        }
        state.peer_kexinit = Some(peer_kexinit);
        state.peer_kexinit_payload = Some(payload.to_vec());
        state.peer_guessed = state
            .peer_kexinit
            .as_ref()
            .is_some_and(|kexinit| kexinit.first_kex_packet_follows);
        state.peer_guess_is_correct = peer_guess_is_correct;
        state.protection = Some(protection);
        state.method_payload = Some(client.init_message()?);
        state.client_kex = Some(client);
        Ok(())
    }

    fn send_client_method(&mut self) -> Result<(), HandshakeError> {
        if self
            .rekey
            .as_ref()
            .is_some_and(|state| state.client_method_sent)
        {
            return Ok(());
        }
        if self.write_buffer.pending_message_type() == Some(SSH_MSG_KEXINIT) {
            let payload = self
                .write_buffer
                .pending_payload()
                .ok_or(TransportError::InvalidMessage)?;
            self.write_rekey_packet(&payload, SSH_MSG_KEXINIT)?;
        }
        let init_message = if self
            .write_buffer
            .pending_message_type()
            .is_some_and(|message| (30..=49).contains(&message))
        {
            self.write_buffer
                .pending_payload()
                .ok_or(TransportError::InvalidMessage)?
        } else {
            let state = self.rekey.as_mut().ok_or(TransportError::RekeyInProgress)?;
            if state.client_method_sent {
                return Ok(());
            }
            state
                .method_payload
                .as_ref()
                .ok_or(TransportError::RekeyInProgress)?
                .clone()
        };
        self.write_rekey_packet(&init_message, init_message[0])?;
        self.rekey
            .as_mut()
            .ok_or(TransportError::RekeyInProgress)?
            .client_method_sent = true;
        Ok(())
    }

    fn accept_peer_kex_method(
        &mut self,
        payload: &[u8],
        sequence: u32,
    ) -> Result<(), HandshakeError> {
        let discard_guess = self
            .rekey
            .as_ref()
            .is_some_and(|state| state.peer_guessed && !state.peer_guess_is_correct);
        if discard_guess {
            let disposition = self.sequence.observe_rekey_observation(
                Direction::Inbound,
                PacketObservation::guessed(payload[0]),
            )?;
            if disposition != PacketDisposition::Ignorable {
                return Err(TransportError::UnexpectedMessage.into());
            }
            self.sequence.commit_inbound()?;
            self.rekey
                .as_mut()
                .ok_or(TransportError::RekeyInProgress)?
                .peer_guessed = false;
            return Ok(());
        }
        let (algorithm, protection, group_received) = {
            let state = self.rekey.as_ref().ok_or(TransportError::RekeyInProgress)?;
            if !state.client_method_sent {
                return Err(TransportError::UnexpectedMessage.into());
            }
            (
                state.local_kexinit.kex_algorithms[0].clone(),
                state.protection.ok_or(TransportError::RekeyInProgress)?,
                state.group_received,
            )
        };
        if crate::kex::modern::is_gex(&algorithm) && !group_received {
            let state = self.rekey.as_mut().ok_or(TransportError::RekeyInProgress)?;
            let init = state
                .client_kex
                .as_mut()
                .ok_or(TransportError::RekeyInProgress)?
                .accept_group(payload)?;
            state.group_received = true;
            state.method_payload = Some(init);
            state.client_method_sent = false;
            state.peer_guessed = false;
            self.accept_rekey_kex_method(Direction::Inbound, 31, sequence)?;
            self.send_client_method()?;
            return Ok(());
        }
        let client = self
            .rekey
            .as_mut()
            .and_then(|state| state.client_kex.take())
            .ok_or(TransportError::RekeyInProgress)?;
        let completion = client.complete(payload)?;
        self.verify_rekey_host_key(&completion.host, &completion.signature, &completion.hash)?;
        self.accept_rekey_kex_method(Direction::Inbound, payload[0], sequence)?;
        let derived = completion.derive(&algorithm, &self.session_id, protection.lengths)?;
        let state = self.rekey.as_mut().ok_or(TransportError::RekeyInProgress)?;
        state.derived = Some(derived);
        state.peer_guessed = false;
        Ok(())
    }

    fn send_client_newkeys(&mut self) -> Result<(), HandshakeError> {
        let (write_material, protection) = {
            let state = self.rekey.as_ref().ok_or(TransportError::RekeyInProgress)?;
            if state.write_newkeys_sent {
                return Ok(());
            }
            let protection = state.protection.ok_or(TransportError::RekeyInProgress)?;
            // The material is built here, inside the borrow of the rekey state,
            // so the one copy of these bytes is the `PacketKeyMaterial` the
            // protector takes. It used to be a `DerivedKeys` clone that was then
            // copied again by `rekey_write_material` and dropped unwiped.
            (
                rekey_write_material(
                    protection,
                    state
                        .derived
                        .as_ref()
                        .ok_or(TransportError::RekeyInProgress)?,
                )?,
                protection,
            )
        };
        self.write_rekey_packet(&[SSH_MSG_NEWKEYS], SSH_MSG_NEWKEYS)?;
        if self.write_buffer.is_pending() {
            return Err(TransportError::InvalidMessage.into());
        }
        self.write_protector
            .as_mut()
            .ok_or(TransportError::NotEstablished)?
            .rekey_with_compression(
                protection.write_suite,
                write_material,
                protection.write_compression,
            )?;
        self.rekey
            .as_mut()
            .ok_or(TransportError::RekeyInProgress)?
            .write_newkeys_sent = true;
        Ok(())
    }

    fn accept_peer_newkeys(&mut self, payload: &[u8], sequence: u32) -> Result<(), HandshakeError> {
        if payload != [SSH_MSG_NEWKEYS] {
            return Err(TransportError::InvalidMessage.into());
        }
        if self.write_buffer.is_pending() {
            return Err(TransportError::InvalidMessage.into());
        }
        let (read_material, protection) = {
            let state = self.rekey.as_ref().ok_or(TransportError::RekeyInProgress)?;
            if !state.write_newkeys_sent {
                return Err(TransportError::UnexpectedMessage.into());
            }
            let protection = state.protection.ok_or(TransportError::RekeyInProgress)?;
            // As in `send_client_newkeys`: the read material is built here so the
            // rekey state keeps the only other copy, and this function's copy is
            // the wiping one the protector owns.
            (
                rekey_read_material(
                    protection,
                    state
                        .derived
                        .as_ref()
                        .ok_or(TransportError::RekeyInProgress)?,
                )?,
                protection,
            )
        };
        self.accept_rekey_newkeys(Direction::Inbound, sequence)?;
        self.read_protector
            .as_mut()
            .ok_or(TransportError::NotEstablished)?
            .rekey_with_compression(
                protection.read_suite,
                read_material,
                protection.read_compression,
            )?;
        self.sequence.complete_rekey_exchange()?;
        self.rekey = None;
        self.established = true;
        Ok(())
    }

    fn read_rekey_packet(&mut self) -> Result<(Vec<u8>, u32), HandshakeError> {
        loop {
            let (payload, sequence) = self.read_protected_packet()?;
            let message_type = payload
                .first()
                .copied()
                .ok_or(TransportError::InvalidMessage)?;
            match message_type {
                SSH_MSG_IGNORE | SSH_MSG_DEBUG | SSH_MSG_UNIMPLEMENTED => {
                    let disposition = self.sequence.observe_rekey_inbound(message_type)?;
                    if disposition != PacketDisposition::Ignorable {
                        return Err(TransportError::UnexpectedMessage.into());
                    }
                    self.commit_rekey_direction(Direction::Inbound, sequence)?;
                }
                SSH_MSG_DISCONNECT => return Err(TransportError::PeerDisconnected.into()),
                SSH_MSG_KEXINIT
                | SSH_MSG_NEWKEYS
                | SSH_MSG_KEX_METHOD_FIRST..=SSH_MSG_KEX_METHOD_LAST => {
                    return Ok((payload, sequence));
                }
                _ => return Ok((payload, sequence)),
            }
        }
    }

    fn write_rekey_packet(
        &mut self,
        payload: &[u8],
        message_type: u8,
    ) -> Result<(), HandshakeError> {
        if payload.first() != Some(&message_type) {
            return Err(TransportError::UnexpectedMessage.into());
        }
        let expected = match message_type {
            SSH_MSG_KEXINIT => PacketDisposition::KexInit,
            SSH_MSG_NEWKEYS => PacketDisposition::NewKeys,
            SSH_MSG_KEX_METHOD_FIRST..=SSH_MSG_KEX_METHOD_LAST => PacketDisposition::KexMethod,
            _ => return Err(TransportError::UnexpectedMessage.into()),
        };
        self.sequence.classify_rekey_outbound(message_type)?;
        let sequence = self.write_protected_rekey_packet(payload, message_type)?;
        let disposition = self.sequence.observe_rekey_outbound(message_type)?;
        if disposition != expected {
            return Err(TransportError::UnexpectedMessage.into());
        }
        self.commit_rekey_direction(Direction::Outbound, sequence)?;
        self.write_buffer.acknowledge(sequence)?;
        Ok(())
    }

    fn accept_rekey_kexinit(&mut self, sequence: u32) -> Result<(), HandshakeError> {
        let disposition = self
            .sequence
            .observe_rekey_kexinit(Direction::Inbound, false)?;
        if disposition != PacketDisposition::KexInit {
            return Err(TransportError::UnexpectedMessage.into());
        }
        self.commit_rekey_direction(Direction::Inbound, sequence)
    }

    fn accept_rekey_kex_method(
        &mut self,
        direction: Direction,
        message_type: u8,
        sequence: u32,
    ) -> Result<(), HandshakeError> {
        let disposition = self
            .sequence
            .observe_rekey_kex_method(direction, message_type)?;
        if disposition != PacketDisposition::KexMethod {
            return Err(TransportError::UnexpectedMessage.into());
        }
        self.commit_rekey_direction(direction, sequence)
    }

    fn accept_rekey_newkeys(
        &mut self,
        direction: Direction,
        sequence: u32,
    ) -> Result<(), HandshakeError> {
        let disposition = self.sequence.observe_rekey_newkeys(direction)?;
        if disposition != PacketDisposition::NewKeys {
            return Err(TransportError::UnexpectedMessage.into());
        }
        self.commit_rekey_direction(direction, sequence)
    }

    fn commit_rekey_direction(
        &mut self,
        direction: Direction,
        expected_sequence: u32,
    ) -> Result<(), HandshakeError> {
        let committed = match direction {
            Direction::Inbound => self.sequence.commit_inbound()?,
            Direction::Outbound => self.sequence.commit_outbound()?,
        };
        if committed != expected_sequence {
            return Err(TransportError::InvalidMessage.into());
        }
        Ok(())
    }

    fn verify_rekey_host_key(
        &self,
        host_key_blob: &[u8],
        signature_blob: &[u8],
        exchange_hash: &[u8],
    ) -> Result<(), HandshakeError> {
        let trusted = self
            .verified_server_host_key
            .as_ref()
            .ok_or(TransportError::NotEstablished)?;
        if host_key_blob != trusted.key.to_blob()? {
            return Err(HandshakeError::Kex(KexError::HostKeyMismatch));
        }
        verify_algorithm_host_key(
            &trusted.algorithm,
            host_key_blob,
            signature_blob,
            exchange_hash,
            trusted.security_key_verifier.as_ref(),
            |_| Ok::<(), ()>(()),
        )?;
        Ok(())
    }

    fn abort_rekey(&mut self) {
        self.rekey = None;
        self.write_buffer.abort();
        self.established = false;
        if !self.sequence.rekey_is_terminal() {
            let _ = self.sequence.fail_rekey();
        }
    }
}

fn rekey_protection(plan: ProtectionPlan) -> RekeyProtection {
    RekeyProtection {
        write_suite: plan.write_suite,
        read_suite: plan.read_suite,
        write_compression: plan.write_compression,
        read_compression: plan.read_compression,
        lengths: plan.lengths,
    }
}

fn rekey_write_material(
    protection: RekeyProtection,
    keys: &crate::kex::DerivedKeys,
) -> Result<PacketKeyMaterial, HandshakeError> {
    material_for(
        protection.write_suite,
        &keys.iv_client_to_server,
        &keys.encryption_key_client_to_server,
        Some(&keys.integrity_key_client_to_server),
    )
}

fn rekey_read_material(
    protection: RekeyProtection,
    keys: &crate::kex::DerivedKeys,
) -> Result<PacketKeyMaterial, HandshakeError> {
    material_for(
        protection.read_suite,
        &keys.iv_server_to_client,
        &keys.encryption_key_server_to_client,
        Some(&keys.integrity_key_server_to_client),
    )
}

fn is_would_block(error: &HandshakeError) -> bool {
    matches!(
        error,
        HandshakeError::Transport(TransportError::Io(error))
            if error.kind() == std::io::ErrorKind::WouldBlock
    )
}

fn rekey_kexinit(template: &KexInit, algorithm: &str) -> Result<KexInit, HandshakeError> {
    if template.reserved != 0 || template.first_kex_packet_follows {
        return Err(HandshakeError::Kex(KexError::InvalidProposal));
    }
    if !template.kex_algorithms.iter().any(|name| name == algorithm) {
        return Err(HandshakeError::UnsupportedAlgorithm);
    }
    let mut proposal = template.clone();
    proposal.kex_algorithms = vec![algorithm.to_owned()];
    proposal.first_kex_packet_follows = false;
    proposal.reserved = 0;
    getrandom::fill(&mut proposal.cookie).map_err(|_error| HandshakeError::EntropyFailure)?;
    Ok(proposal)
}

#[derive(Clone, Copy)]
struct ProtectionPlan {
    write_suite: PacketSuite,
    read_suite: PacketSuite,
    write_compression: CompressionAlgorithm,
    read_compression: CompressionAlgorithm,
    lengths: DerivationLengths,
}

impl ProtectionPlan {
    fn from_algorithms(
        algorithms: &crate::msg::kexinit::NegotiatedAlgorithms,
        delayed_compression: bool,
        immediate_compression: bool,
    ) -> Result<Self, HandshakeError> {
        if !SUPPORTED_HOST_KEY_ALGORITHMS.contains(&algorithms.host_key.as_str())
            && algorithms.host_key != "ssh-rsa"
            && !crate::security_key::supported(&algorithms.host_key)
        {
            return Err(HandshakeError::UnsupportedAlgorithm);
        }
        if [
            &algorithms.compression_client_to_server,
            &algorithms.compression_server_to_client,
        ]
        .iter()
        .any(|name| match name.as_str() {
            "none" => false,
            "zlib@openssh.com" => !delayed_compression,
            "zlib" => !immediate_compression,
            _ => true,
        }) {
            return Err(HandshakeError::UnsupportedAlgorithm);
        }
        let write_compression =
            CompressionAlgorithm::from_name(&algorithms.compression_client_to_server)
                .ok_or(HandshakeError::UnsupportedAlgorithm)?;
        let read_compression =
            CompressionAlgorithm::from_name(&algorithms.compression_server_to_client)
                .ok_or(HandshakeError::UnsupportedAlgorithm)?;
        if (!is_chacha_cipher(&algorithms.cipher_client_to_server)
            && !SUPPORTED_MAC_ALGORITHMS.contains(&algorithms.mac_client_to_server.as_str())
            && !crate::msg::kexinit::LEGACY_MACS
                .contains(&algorithms.mac_client_to_server.as_str()))
            || (!is_chacha_cipher(&algorithms.cipher_server_to_client)
                && !SUPPORTED_MAC_ALGORITHMS.contains(&algorithms.mac_server_to_client.as_str())
                && !crate::msg::kexinit::LEGACY_MACS
                    .contains(&algorithms.mac_server_to_client.as_str()))
        {
            return Err(HandshakeError::UnsupportedAlgorithm);
        }

        let write_suite = suite_for(
            &algorithms.cipher_client_to_server,
            &algorithms.mac_client_to_server,
        )?;
        let read_suite = suite_for(
            &algorithms.cipher_server_to_client,
            &algorithms.mac_server_to_client,
        )?;
        let write_iv = iv_length(write_suite);
        let read_iv = iv_length(read_suite);
        let write_key = encryption_key_length(write_suite)?;
        let read_key = encryption_key_length(read_suite)?;
        let write_integrity = integrity_key_length(write_suite);
        let read_integrity = integrity_key_length(read_suite);
        Ok(Self {
            write_suite,
            read_suite,
            write_compression,
            read_compression,
            lengths: DerivationLengths {
                a: write_iv,
                b: read_iv,
                c: write_key,
                d: read_key,
                e: write_integrity,
                f: read_integrity,
            },
        })
    }

    fn write_material(
        &self,
        keys: &crate::kex::DerivedKeys,
    ) -> Result<PacketKeyMaterial, HandshakeError> {
        material_for(
            self.write_suite,
            &keys.iv_client_to_server,
            &keys.encryption_key_client_to_server,
            Some(&keys.integrity_key_client_to_server),
        )
    }

    fn read_material(
        &self,
        keys: &crate::kex::DerivedKeys,
    ) -> Result<PacketKeyMaterial, HandshakeError> {
        material_for(
            self.read_suite,
            &keys.iv_server_to_client,
            &keys.encryption_key_server_to_client,
            Some(&keys.integrity_key_server_to_client),
        )
    }

    fn write_protector(
        &self,
        keys: &crate::kex::DerivedKeys,
    ) -> Result<PacketProtector, HandshakeError> {
        let material = self.write_material(keys)?;
        Ok(PacketProtector::new_with_delayed_compression(
            self.write_suite,
            material,
            self.write_compression,
        )?)
    }

    fn read_protector(
        &self,
        keys: &crate::kex::DerivedKeys,
    ) -> Result<PacketProtector, HandshakeError> {
        let material = self.read_material(keys)?;
        Ok(PacketProtector::new_with_delayed_compression(
            self.read_suite,
            material,
            self.read_compression,
        )?)
    }
}

fn supported_client_kexinit(cookie: [u8; 16]) -> KexInit {
    KexInit::from_lists(
        cookie,
        vec![
            KEX_MLKEM768X25519_SHA256.to_owned(),
            CURVE25519_SHA256.to_owned(),
            CURVE25519_SHA256_LIBSSH.to_owned(),
            ECDH_SHA2_NISTP256.to_owned(),
            KEX_DIFFIE_HELLMAN_GROUP16_SHA512.to_owned(),
            crate::kex::modern::P384.to_owned(),
            crate::kex::modern::P521.to_owned(),
            crate::kex::modern::GEX.to_owned(),
            KEX_STRICT_C_V00_OPENSSH.to_owned(),
        ],
        crate::msg::kexinit::DEFAULT_HOST_KEY_ALGORITHMS
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        vec![
            CHACHA20_POLY1305_OPENSSH_NAME.to_owned(),
            AES128_CTR.to_owned(),
            AES256_CTR.to_owned(),
            AES128_GCM_OPENSSH.to_owned(),
            AES256_GCM_OPENSSH.to_owned(),
        ],
        vec![
            CHACHA20_POLY1305_OPENSSH_NAME.to_owned(),
            AES128_CTR.to_owned(),
            AES256_CTR.to_owned(),
            AES128_GCM_OPENSSH.to_owned(),
            AES256_GCM_OPENSSH.to_owned(),
        ],
        vec![
            HMAC_SHA2_256.to_owned(),
            HMAC_SHA2_512.to_owned(),
            HMAC_SHA2_256_ETM_OPENSSH.to_owned(),
            HMAC_SHA2_512_ETM_OPENSSH.to_owned(),
        ],
        vec![
            HMAC_SHA2_256.to_owned(),
            HMAC_SHA2_512.to_owned(),
            HMAC_SHA2_256_ETM_OPENSSH.to_owned(),
            HMAC_SHA2_512_ETM_OPENSSH.to_owned(),
        ],
        vec![COMPRESSION_NONE.to_owned()],
        vec![COMPRESSION_NONE.to_owned()],
        Vec::new(),
        Vec::new(),
        false,
        0,
    )
}

fn mechanism_for(name: &str) -> Result<Box<dyn KeyExchange>, HandshakeError> {
    match name {
        CURVE25519_SHA256 => Ok(Box::new(Curve25519::standard())),
        CURVE25519_SHA256_LIBSSH => Ok(Box::new(Curve25519::libssh())),
        ECDH_SHA2_NISTP256 => Ok(Box::new(EcdhP256::new())),
        KEX_DIFFIE_HELLMAN_GROUP16_SHA512 => Ok(Box::new(DhGroup16::new())),
        _ => Err(HandshakeError::UnsupportedAlgorithm),
    }
}

fn is_chacha_cipher(cipher: &str) -> bool {
    cipher == CHACHA20_POLY1305_OPENSSH_NAME
}

fn suite_for(cipher: &str, mac: &str) -> Result<PacketSuite, HandshakeError> {
    if matches!(
        cipher,
        AES128_GCM_OPENSSH | AES256_GCM_OPENSSH | CHACHA20_POLY1305_OPENSSH_NAME
    ) {
        // OpenSSH authenticated-encryption suites still require a mutually
        // negotiated MAC name-list, but do not derive or consume E/F keys.
        return Ok(PacketSuite::new(cipher, None)?);
    }
    // Initial proposals were policy-gated; rekeys retain that exact local template.
    Ok(PacketSuite::new_with_legacy(cipher, Some(mac), true)?)
}

fn iv_length(suite: PacketSuite) -> usize {
    match suite.encryption_name() {
        // OpenSSH derives no IV for ChaCha; the protector receives two zero
        // words through the existing key-material API instead.
        CHACHA20_POLY1305_OPENSSH_NAME => 0,
        "3des-cbc" => 8,
        _ if suite.integrity_name().is_none() => GCM_IV_LENGTH,
        _ => CTR_IV_LENGTH,
    }
}

fn encryption_key_length(suite: PacketSuite) -> Result<usize, HandshakeError> {
    match suite.encryption_name() {
        AES128_CTR | AES128_GCM_OPENSSH | "aes128-cbc" => Ok(AES128_KEY_LENGTH),
        AES256_CTR | AES256_GCM_OPENSSH | "aes256-cbc" => Ok(AES256_KEY_LENGTH),
        "3des-cbc" => Ok(24),
        CHACHA20_POLY1305_OPENSSH_NAME => Ok(CHACHA_KEY_LENGTH),
        _ => Err(HandshakeError::UnsupportedAlgorithm),
    }
}

fn integrity_key_length(suite: PacketSuite) -> usize {
    match suite.integrity_name() {
        None => 0,
        Some("hmac-sha1" | "hmac-sha1-etm@openssh.com") => 20,
        Some(name) if name.contains("sha2-512") => SHA512_INTEGRITY_LENGTH,
        Some(_) => SHA256_INTEGRITY_LENGTH,
    }
}

fn material_for(
    suite: PacketSuite,
    iv: &[u8],
    encryption_key: &[u8],
    integrity_key: Option<&[u8]>,
) -> Result<PacketKeyMaterial, HandshakeError> {
    if suite.encryption_name() == CHACHA20_POLY1305_OPENSSH_NAME {
        return Ok(PacketKeyMaterial::new(
            &[0; CHACHA_IV_LENGTH],
            encryption_key,
            None,
        ));
    }
    if suite.integrity_name().is_none() {
        Ok(PacketKeyMaterial::gcm(iv, encryption_key))
    } else {
        let integrity_key = integrity_key
            .filter(|key| !key.is_empty())
            .ok_or(HandshakeError::UnsupportedAlgorithm)?;
        Ok(PacketKeyMaterial::hmac(iv, encryption_key, integrity_key))
    }
}
