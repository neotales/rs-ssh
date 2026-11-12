//! Rekey dispatch reuses the initial exchange's codecs, hashes and KDFs.
use super::{
    Curve25519, DerivationLengths, DerivedKeys, DhGroup16, EcdhP256, EphemeralKey,
    ExchangeHashInput, KexContext, KexError, KeyExchange, ServerKex, SharedSecret,
    compute_exchange_hash, derive_keys, dh_group16,
    dh_group16::{Group16ClientKex, Group16KexContext},
    mlkem768_x25519, modern,
};
use neotales_ssh::Reader;

pub(crate) fn supported(name: &str) -> bool {
    matches!(
        name,
        "curve25519-sha256"
            | "ecdh-sha2-nistp256"
            | "diffie-hellman-group16-sha512"
            | "mlkem768x25519-sha256"
    ) || modern::supported(name)
}

pub(crate) struct Transcript<'a> {
    pub(crate) client_version: &'a str,
    pub(crate) server_version: &'a str,
    pub(crate) client_init: &'a [u8],
    pub(crate) server_init: &'a [u8],
    pub(crate) algorithm: &'a str,
}
impl Transcript<'_> {
    fn baseline(&self) -> Result<KexContext, KexError> {
        KexContext::new(
            self.client_version,
            self.server_version,
            self.client_init,
            self.server_init,
            self.algorithm,
        )
    }
    fn group16(&self) -> Result<Group16KexContext, KexError> {
        Group16KexContext::new(
            self.client_version,
            self.server_version,
            self.client_init,
            self.server_init,
        )
    }
    fn modern(&self) -> Result<modern::Context, KexError> {
        modern::Context::new(
            self.client_version,
            self.server_version,
            self.client_init,
            self.server_init,
            self.algorithm,
        )
    }
}

pub(crate) enum Client {
    Hybrid(mlkem768_x25519::ClientKex, KexContext),
    Group16(Group16ClientKex),
    Modern(modern::Client),
    Baseline {
        mechanism: Box<dyn KeyExchange>,
        context: KexContext,
        secret: EphemeralKey,
        public: Vec<u8>,
    },
}
pub(crate) struct Completion {
    pub(crate) hash: Vec<u8>,
    pub(crate) shared: SharedSecret,
    pub(crate) host: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}
impl Completion {
    pub(crate) fn derive(
        &self,
        algorithm: &str,
        sid: &[u8],
        lengths: DerivationLengths,
    ) -> Result<DerivedKeys, KexError> {
        if modern::supported(algorithm) {
            modern::derive(algorithm, &self.shared, &self.hash, sid, lengths)
        } else if algorithm == "diffie-hellman-group16-sha512" {
            dh_group16::derive_keys_sha512(&self.shared, &self.hash, sid, lengths)
        } else {
            derive_keys(&self.shared, &self.hash, sid, lengths)
        }
    }
}
impl Client {
    pub(crate) fn new(t: &Transcript<'_>) -> Result<Self, KexError> {
        Ok(match t.algorithm {
            "mlkem768x25519-sha256" => {
                Self::Hybrid(mlkem768_x25519::ClientKex::generate()?, t.baseline()?)
            }
            "diffie-hellman-group16-sha512" => {
                Self::Group16(Group16ClientKex::new(DhGroup16::new(), t.group16()?)?)
            }
            name if modern::supported(name) => Self::Modern(modern::Client::new(t.modern()?)?),
            name => {
                let mechanism: Box<dyn KeyExchange> = match name {
                    "curve25519-sha256" => Box::new(Curve25519::standard()),
                    "ecdh-sha2-nistp256" => Box::new(EcdhP256::new()),
                    _ => return Err(KexError::AlgorithmMismatch),
                };
                let secret = mechanism.generate_ephemeral()?;
                let public = mechanism.public_key(&secret)?;
                Self::Baseline {
                    mechanism,
                    context: t.baseline()?,
                    secret,
                    public,
                }
            }
        })
    }
    pub(crate) fn init_message(&self) -> Result<Vec<u8>, KexError> {
        match self {
            Self::Hybrid(client, _) => client.init_message(),
            Self::Group16(client) => client.init_message(),
            Self::Modern(client) => client.first(),
            Self::Baseline {
                mechanism, secret, ..
            } => mechanism.encode_init_message(secret),
        }
    }
    pub(crate) fn accept_group(&mut self, payload: &[u8]) -> Result<Vec<u8>, KexError> {
        match self {
            Self::Modern(client) => client.accept_group(payload),
            _ => Err(KexError::InvalidState),
        }
    }
    pub(crate) fn complete(self, payload: &[u8]) -> Result<Completion, KexError> {
        Ok(match self {
            Self::Hybrid(client, context) => {
                let c = client.complete(&context, payload)?;
                Completion {
                    hash: c.exchange_hash.to_vec(),
                    shared: c.shared_secret,
                    host: c.host_key_blob,
                    signature: c.signature_blob,
                }
            }
            Self::Group16(mut client) => {
                let c = client.complete(payload)?;
                // The host blob is encoded before the DH public value.
                let mut reader = Reader::new(payload);
                reader.read_byte()?;
                Completion {
                    hash: c.exchange_hash().to_vec(),
                    shared: c.shared_secret().clone(),
                    host: reader.read_string()?.to_vec(),
                    signature: c
                        .signature_blob()
                        .ok_or(KexError::InvalidFieldLength)?
                        .to_vec(),
                }
            }
            Self::Modern(client) => {
                let c = client.complete(payload)?;
                Completion {
                    hash: c.hash,
                    shared: c.shared,
                    host: c.host,
                    signature: c.signature,
                }
            }
            Self::Baseline {
                mechanism,
                context,
                secret,
                public,
            } => {
                let reply = mechanism.decode_reply_message(payload)?;
                let peer = reply
                    .server_public_key()
                    .ok_or(KexError::InvalidFieldLength)?;
                let shared = mechanism.agree(secret, peer)?;
                let input =
                    ExchangeHashInput::new(reply.host_key_blob(), &public, peer, shared.clone())?;
                Completion {
                    hash: compute_exchange_hash(&context, &input)?.to_vec(),
                    shared,
                    host: reply.host_key_blob().to_vec(),
                    signature: reply.signature_blob().to_vec(),
                }
            }
        })
    }
}

pub(crate) enum ServerStep {
    Group(Vec<u8>),
    Ready {
        reply: Vec<u8>,
        derived: DerivedKeys,
    },
}
#[allow(clippy::too_many_arguments)] // Explicit transcript and key-derivation inputs.
pub(crate) fn server_step<E: From<KexError>>(
    t: &Transcript<'_>,
    modern_server: &mut Option<modern::Server>,
    host: &[u8],
    payload: &[u8],
    sid: &[u8],
    lengths: DerivationLengths,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<ServerStep, E> {
    if modern::supported(t.algorithm) {
        if modern_server.is_none() {
            *modern_server = Some(modern::Server::new(t.modern()?, host, false));
        }
        return match modern_server
            .as_mut()
            .ok_or(KexError::InvalidState)?
            .accept(payload)?
        {
            modern::ServerStep::Group(group) => Ok(ServerStep::Group(group)),
            modern::ServerStep::Ready(prepared) => {
                let c = &prepared.completion;
                let derived = modern::derive(t.algorithm, &c.shared, &c.hash, sid, lengths)?;
                Ok(ServerStep::Ready {
                    reply: prepared.reply(&sign(&c.hash)?)?,
                    derived,
                })
            }
        };
    }
    if t.algorithm == "mlkem768x25519-sha256" {
        let mut server = mlkem768_x25519::ServerKex::new(t.baseline()?, host)?;
        let p = server.accept_init(payload)?;
        let derived = derive_keys(p.shared_secret(), p.exchange_hash(), sid, lengths)?;
        return Ok(ServerStep::Ready {
            reply: p.reply_message(&sign(p.exchange_hash())?)?,
            derived,
        });
    }
    if t.algorithm == "diffie-hellman-group16-sha512" {
        let mut server = dh_group16::Group16ServerKex::new(DhGroup16::new(), t.group16()?, host)?;
        server.accept_init(payload)?;
        let c = server.prepare_exchange()?;
        let derived =
            dh_group16::derive_keys_sha512(c.shared_secret(), c.exchange_hash(), sid, lengths)?;
        let signature = sign(c.exchange_hash())?;
        return Ok(ServerStep::Ready {
            reply: server.reply_message(&signature)?,
            derived,
        });
    }
    match t.algorithm {
        "curve25519-sha256" => {
            baseline(Curve25519::standard(), t, host, payload, sid, lengths, sign)
        }
        "ecdh-sha2-nistp256" => baseline(EcdhP256::new(), t, host, payload, sid, lengths, sign),
        _ => Err(KexError::AlgorithmMismatch.into()),
    }
}

fn baseline<A: KeyExchange, E: From<KexError>>(
    mechanism: A,
    t: &Transcript<'_>,
    host: &[u8],
    payload: &[u8],
    sid: &[u8],
    lengths: DerivationLengths,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<ServerStep, E> {
    let mut server = ServerKex::new(mechanism, t.baseline()?, host)?;
    server.accept_init(payload)?;
    let c = server.prepare_exchange()?;
    let derived = derive_keys(c.shared_secret(), c.exchange_hash(), sid, lengths)?;
    let signature = sign(c.exchange_hash())?;
    Ok(ServerStep::Ready {
        reply: server.reply_message(&signature)?,
        derived,
    })
}
