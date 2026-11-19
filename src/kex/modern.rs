//! RFC 5656 large-curve ECDH and bounded RFC 4419 group exchange.
//! Kept separate from the baseline fixed-SHA-256 completion contract.
use super::{
    DerivationLengths, DerivedKeys, EphemeralKey, KexError, SharedSecret, dh_group16::DhGroup16,
};
use crate::msg::kexinit::KexInit;
use neotales_ssh::{Reader, Writer};
use p384::elliptic_curve::{point::AffineCoordinates, sec1::ToSec1Point};
use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

pub(crate) const P384: &str = "ecdh-sha2-nistp384";
pub(crate) const P521: &str = "ecdh-sha2-nistp521";
pub(crate) const GEX: &str = "diffie-hellman-group-exchange-sha256";
pub(crate) const GEX_SHA1: &str = "diffie-hellman-group-exchange-sha1";
pub(crate) const GROUP1: &str = "diffie-hellman-group1-sha1";

pub(crate) fn is_gex(name: &str) -> bool {
    matches!(name, GEX | GEX_SHA1)
}
// A deliberately narrow safe-prime policy, not arbitrary untrusted DH groups.
const GROUP_BITS: u32 = 4096;
const REQUEST: [u32; 3] = [4096, 4096, 4096];

pub(crate) fn supported(name: &str) -> bool {
    matches!(
        name,
        P384 | P521 | GEX | GEX_SHA1 | GROUP1 | super::sntrup::NAME
    )
}

#[derive(Debug)]
pub(crate) struct Context {
    algorithm: String,
    prefix: Vec<u8>,
}
impl Context {
    pub(crate) fn new(
        vc: &str,
        vs: &str,
        ic: &[u8],
        is: &[u8],
        algorithm: &str,
    ) -> Result<Self, KexError> {
        if !supported(algorithm)
            || KexInit::decode(ic)?
                .negotiate(&KexInit::decode(is)?)
                .map_err(|_| KexError::InvalidProposal)?
                .kex
                != algorithm
        {
            return Err(KexError::ProposalMismatch);
        }
        let mut writer = Writer::new();
        for field in [vc.as_bytes(), vs.as_bytes(), ic, is] {
            writer.write_string(field)?;
        }
        Ok(Self {
            algorithm: algorithm.to_owned(),
            prefix: writer.into_bytes(),
        })
    }

    fn exchange_hash(
        &self,
        host: &[u8],
        client: &[u8],
        server: &[u8],
        shared: &SharedSecret,
        bounds: Option<[u32; 3]>,
    ) -> Result<Vec<u8>, KexError> {
        let mut writer = Writer::new();
        writer.write_string(host)?;
        if let Some(bounds) = bounds {
            for value in bounds {
                writer.write_uint32(value);
            }
            positive(&mut writer, &DhGroup16::new().prime_bytes()?)?;
            positive(&mut writer, &[2])?;
            positive(&mut writer, client)?;
            positive(&mut writer, server)?;
        } else if self.algorithm == GROUP1 {
            positive(&mut writer, client)?;
            positive(&mut writer, server)?;
        } else {
            writer.write_string(client)?;
            writer.write_string(server)?;
        }
        let mut input = Zeroizing::new(self.prefix.clone());
        input.extend_from_slice(writer.as_bytes());
        input.extend_from_slice(shared.as_bytes());
        Ok(hash(&self.algorithm, &input))
    }
}

enum Secret {
    Sntrup(super::sntrup::Client),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
    Dh(EphemeralKey),
    Group1(EphemeralKey),
}
impl Secret {
    fn generate(algorithm: &str) -> Result<Self, KexError> {
        if algorithm == super::sntrup::NAME {
            return super::sntrup::Client::new().map(Self::Sntrup);
        }
        if algorithm == GROUP1 {
            return DhGroup16::new().generate_private().map(Self::Group1);
        }
        if is_gex(algorithm) {
            return DhGroup16::new().generate_private().map(Self::Dh);
        }
        for _ in 0..128 {
            let mut raw = Zeroizing::new(vec![0; if algorithm == P384 { 48 } else { 66 }]);
            getrandom::fill(&mut raw).map_err(|_| KexError::EntropyFailure)?;
            if algorithm == P384 {
                if let Ok(key) = p384::SecretKey::from_slice(&raw) {
                    return Ok(Self::P384(key));
                }
            } else if algorithm == P521 {
                raw[0] &= 1;
                if let Ok(key) = p521::SecretKey::from_slice(&raw) {
                    return Ok(Self::P521(key));
                }
            } else {
                return Err(KexError::AlgorithmMismatch);
            }
        }
        Err(KexError::EntropyFailure)
    }
    fn public(&self) -> Result<Vec<u8>, KexError> {
        match self {
            Self::Sntrup(client) => Ok(client.public.clone()),
            Self::P384(key) => Ok(key.public_key().to_sec1_point(false).to_bytes().to_vec()),
            Self::P521(key) => Ok(key.public_key().to_sec1_point(false).to_bytes().to_vec()),
            Self::Dh(key) => DhGroup16::new().public_key(key),
            Self::Group1(key) => DhGroup16::group1_public(key),
        }
    }
    fn agree(self, peer: &[u8]) -> Result<SharedSecret, KexError> {
        // Only uncompressed canonical points are admitted. SecretKey and the
        // temporary scalar copies wipe on drop. Invalid points never multiply.
        macro_rules! curve {
            ($key:expr, $curve:ident, $length:expr) => {{
                if peer.len() != $length || peer[0] != 4 {
                    return Err(KexError::InvalidPublicKey);
                }
                let peer = $curve::PublicKey::from_sec1_bytes(peer)
                    .map_err(|_| KexError::InvalidPublicKey)?;
                let scalar = Zeroizing::new($key.to_nonzero_scalar());
                let point = Zeroizing::new((peer.to_projective() * scalar.as_ref()).to_affine());
                if bool::from(point.is_identity()) {
                    return Err(KexError::NonContributorySecret);
                }
                let x = Zeroizing::new(point.x());
                SharedSecret::from_raw(x.as_slice())
            }};
        }
        match self {
            Self::Sntrup(client) => client.complete(peer),
            Self::P384(key) => curve!(key, p384, 97),
            Self::P521(key) => curve!(key, p521, 133),
            Self::Dh(key) => DhGroup16::new().agree(key, peer),
            Self::Group1(key) => DhGroup16::group1_agree(key, peer),
        }
    }
}

pub(crate) struct Client {
    context: Context,
    secret: Option<Secret>,
    public: Vec<u8>,
    bounds: Option<[u32; 3]>,
}
pub(crate) struct Completion {
    pub(crate) hash: Vec<u8>,
    pub(crate) shared: SharedSecret,
    pub(crate) host: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}
impl Client {
    pub(crate) fn new(context: Context) -> Result<Self, KexError> {
        let secret = if is_gex(&context.algorithm) {
            None
        } else {
            Some(Secret::generate(&context.algorithm)?)
        };
        let public = secret
            .as_ref()
            .map(Secret::public)
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            context,
            secret,
            public,
            bounds: None,
        })
    }
    pub(crate) fn first(&self) -> Result<Vec<u8>, KexError> {
        let mut writer = Writer::new();
        if is_gex(&self.context.algorithm) {
            writer.write_byte(34);
            for value in REQUEST {
                writer.write_uint32(value);
            }
        } else {
            writer.write_byte(30);
            if self.context.algorithm == GROUP1 {
                positive(&mut writer, &self.public)?;
            } else {
                writer.write_string(&self.public)?;
            }
        }
        Ok(writer.into_bytes())
    }
    pub(crate) fn accept_group(&mut self, packet: &[u8]) -> Result<Vec<u8>, KexError> {
        if !is_gex(&self.context.algorithm) || self.secret.is_some() {
            return Err(KexError::InvalidState);
        }
        let mut reader = Reader::new(packet);
        if reader.read_byte()? != 31 {
            return Err(KexError::InvalidMessageType);
        }
        let p = magnitude(&mut reader)?;
        let g = magnitude(&mut reader)?;
        if !reader.is_empty() {
            return Err(KexError::TrailingData);
        }
        validate_group(p, g, REQUEST)?;
        // Neither key generation (g^x) nor agreement runs before group checks.
        let secret = Secret::generate(GEX)?;
        self.public = secret.public()?;
        self.secret = Some(secret);
        self.bounds = Some(REQUEST);
        let mut writer = Writer::new();
        writer.write_byte(32);
        positive(&mut writer, &self.public)?;
        Ok(writer.into_bytes())
    }
    pub(crate) fn complete(mut self, packet: &[u8]) -> Result<Completion, KexError> {
        let mut reader = Reader::new(packet);
        let expected = if is_gex(&self.context.algorithm) {
            33
        } else {
            31
        };
        if reader.read_byte()? != expected {
            return Err(KexError::InvalidMessageType);
        }
        let host = reader.read_string()?.to_vec();
        let peer = if expected == 33 || self.context.algorithm == GROUP1 {
            magnitude(&mut reader)?
        } else {
            reader.read_string_with_limit(if self.context.algorithm == super::sntrup::NAME {
                super::sntrup::SERVER_LEN
            } else {
                133
            })?
        };
        let signature = reader.read_string()?.to_vec();
        if !reader.is_empty() {
            return Err(KexError::TrailingData);
        }
        let shared = self
            .secret
            .take()
            .ok_or(KexError::InvalidState)?
            .agree(peer)?;
        let hash = self
            .context
            .exchange_hash(&host, &self.public, peer, &shared, self.bounds)?;
        Ok(Completion {
            hash,
            shared,
            host,
            signature,
        })
    }
}

pub(crate) struct Server {
    context: Context,
    host: Vec<u8>,
    bounds: Option<[u32; 3]>,
    pub(crate) discard_guess: bool,
    finished: bool,
}
pub(crate) enum ServerStep {
    Group(Vec<u8>),
    Ready(Prepared),
}
pub(crate) struct Prepared {
    pub(crate) completion: Completion,
    public: Vec<u8>,
    gex: bool,
    group1: bool,
}
impl Prepared {
    pub(crate) fn reply(&self, signature: &[u8]) -> Result<Vec<u8>, KexError> {
        let mut writer = Writer::new();
        writer.write_byte(if self.gex { 33 } else { 31 });
        writer.write_string(&self.completion.host)?;
        if self.gex || self.group1 {
            positive(&mut writer, &self.public)?;
        } else {
            writer.write_string(&self.public)?;
        }
        writer.write_string(signature)?;
        Ok(writer.into_bytes())
    }
}
impl Server {
    pub(crate) fn new(context: Context, host: &[u8], discard_guess: bool) -> Self {
        Self {
            context,
            host: host.to_vec(),
            bounds: None,
            discard_guess,
            finished: false,
        }
    }
    pub(crate) fn accept(&mut self, packet: &[u8]) -> Result<ServerStep, KexError> {
        if self.finished {
            return Err(KexError::InvalidState);
        }
        let mut reader = Reader::new(packet);
        let message = reader.read_byte()?;
        let gex = is_gex(&self.context.algorithm);
        if gex && self.bounds.is_none() {
            if message != 34 {
                return Err(KexError::InvalidMessageType);
            }
            let bounds = [
                reader.read_uint32()?,
                reader.read_uint32()?,
                reader.read_uint32()?,
            ];
            if !reader.is_empty() {
                return Err(KexError::TrailingData);
            }
            validate_bounds(bounds)?;
            let mut writer = Writer::new();
            writer.write_byte(31);
            positive(&mut writer, &DhGroup16::new().prime_bytes()?)?;
            positive(&mut writer, &[2])?;
            self.bounds = Some(bounds);
            return Ok(ServerStep::Group(writer.into_bytes()));
        }
        if message != if gex { 32 } else { 30 } {
            return Err(KexError::InvalidMessageType);
        }
        let client = if gex || self.context.algorithm == GROUP1 {
            magnitude(&mut reader)?
        } else {
            reader.read_string_with_limit(if self.context.algorithm == super::sntrup::NAME {
                super::sntrup::CLIENT_LEN
            } else {
                133
            })?
        };
        if !reader.is_empty() {
            return Err(KexError::TrailingData);
        }
        let (public, shared) = if self.context.algorithm == super::sntrup::NAME {
            super::sntrup::respond(client)?
        } else {
            let secret = Secret::generate(&self.context.algorithm)?;
            let public = secret.public()?;
            (public, secret.agree(client)?)
        };
        let hash = self
            .context
            .exchange_hash(&self.host, client, &public, &shared, self.bounds)?;
        self.finished = true;
        Ok(ServerStep::Ready(Prepared {
            completion: Completion {
                hash,
                shared,
                host: self.host.clone(),
                signature: Vec::new(),
            },
            public,
            gex,
            group1: self.context.algorithm == GROUP1,
        }))
    }
}

fn validate_bounds([min, preferred, max]: [u32; 3]) -> Result<(), KexError> {
    if min < 2048
        || max > 8192
        || min > preferred
        || preferred > max
        || min > GROUP_BITS
        || max < GROUP_BITS
    {
        return Err(KexError::InvalidPublicKey);
    }
    Ok(())
}
fn validate_group(p: &[u8], g: &[u8], bounds: [u32; 3]) -> Result<(), KexError> {
    validate_bounds(bounds)?;
    // RFC 3526 section 5's published safe prime and subgroup generator are the
    // entire allowlist. Equality is a stronger check than probable primality:
    // arbitrary same-size primes/composites and other generators are refused.
    // Length/bit bounds are checked before constructing any peer-controlled
    // BigUint or running modpow. The reference prime is a trusted constant.
    if p.len() != 512 || p[0] & 0x80 == 0 || g != [2] || p != DhGroup16::new().prime_bytes()? {
        return Err(KexError::InvalidPublicKey);
    }
    Ok(())
}
fn magnitude<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], KexError> {
    let value = reader.read_mpint_with_limit(513)?;
    if value.is_empty() || value[0] & 0x80 != 0 {
        return Err(KexError::InvalidPublicKey);
    }
    Ok(if value[0] == 0 { &value[1..] } else { value })
}
fn positive(writer: &mut Writer, value: &[u8]) -> Result<(), KexError> {
    let mut signed = Vec::with_capacity(value.len() + 1);
    if value.first().is_some_and(|v| v & 0x80 != 0) {
        signed.push(0);
    }
    signed.extend_from_slice(value);
    writer.write_mpint(signed)?;
    Ok(())
}
fn hash(algorithm: &str, input: &[u8]) -> Vec<u8> {
    match algorithm {
        GROUP1 | GEX_SHA1 => sha1::Sha1::digest(input).to_vec(),
        P384 => Sha384::digest(input).to_vec(),
        P521 | super::sntrup::NAME => Sha512::digest(input).to_vec(),
        _ => Sha256::digest(input).to_vec(),
    }
}
pub(crate) fn derive(
    algorithm: &str,
    shared: &SharedSecret,
    h: &[u8],
    sid: &[u8],
    lengths: DerivationLengths,
) -> Result<DerivedKeys, KexError> {
    let width = match algorithm {
        P384 => 48,
        P521 | super::sntrup::NAME => 64,
        GEX => 32,
        GROUP1 | GEX_SHA1 => 20,
        _ => return Err(KexError::AlgorithmMismatch),
    };
    if h.len() != width {
        return Err(KexError::InvalidExchangeHash);
    }
    if !matches!(sid.len(), 20 | 32 | 48 | 64) {
        return Err(KexError::InvalidSessionId);
    }
    let key = |letter: u8, length: usize| -> Result<Zeroizing<Vec<u8>>, KexError> {
        if length > super::MAX_DERIVED_KEY_LENGTH {
            return Err(KexError::DerivedKeyLimitExceeded);
        }
        let capacity = length.div_ceil(width) * width;
        let mut input = Zeroizing::new(Vec::with_capacity(
            shared.as_bytes().len() + h.len() + capacity.max(sid.len() + 1),
        ));
        input.extend_from_slice(shared.as_bytes());
        input.extend_from_slice(h);
        let prefix = input.len();
        input.push(letter);
        input.extend_from_slice(sid);
        let mut output = Zeroizing::new(Vec::with_capacity(capacity));
        while output.len() < length {
            let block = Zeroizing::new(hash(algorithm, &input));
            output.extend_from_slice(&block);
            input.truncate(prefix);
            input.extend_from_slice(&output);
        }
        output.truncate(length);
        Ok(output)
    };
    Ok(DerivedKeys {
        iv_client_to_server: key(b'A', lengths.a)?,
        iv_server_to_client: key(b'B', lengths.b)?,
        encryption_key_client_to_server: key(b'C', lengths.c)?,
        encryption_key_server_to_client: key(b'D', lengths.d)?,
        integrity_key_client_to_server: key(b'E', lengths.e)?,
        integrity_key_server_to_client: key(b'F', lengths.f)?,
    })
}

#[cfg(test)]
mod tests {
    // Critical codec/hash tests: fixed RFC-layout fixtures independently
    // calculated with Python hashlib, not our other endpoint's implementation.
    use super::*;
    fn decode_hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    fn context(algorithm: &str) -> Context {
        Context {
            algorithm: algorithm.to_owned(),
            prefix: b"\0\0\0\x02vc\0\0\0\x02vs\0\0\0\x02\x14c\0\0\0\x02\x14s".to_vec(),
        }
    }
    #[test]
    fn sntrup_string_secret_transcript_and_expansion_match_python_sha512() {
        // Independent Python hashlib/struct fixture: SHA512(bytes(range(64))),
        // then SSH strings vc/vs/IC/IS/host/client/server/K. The high bit of K
        // is set deliberately: an mpint encoding would add a zero and fail.
        let material: Vec<u8> = (0..64).collect();
        let shared = SharedSecret::from_raw_string(&Sha512::digest(&material)).unwrap();
        assert_eq!(
            shared.as_bytes(),
            decode_hex(
                "00000040ee4320ebaf3fdb4f2c832b137200c08e235e0fa7bbd0eb1740c7063ba8a0d151da77e003398e1714a955d475b05e3e950b639503b452ec185de4229bc4873949"
            )
        );
        let h = context(super::super::sntrup::NAME)
            .exchange_hash(b"host", b"client", b"server", &shared, None)
            .unwrap();
        assert_eq!(
            h,
            decode_hex(
                "838475f3a920d5c9177c92efdf5b74efbd925381225f583b345f7c73f1f961137296b2074f09062c5990f2a5563bb9942176c80527ae1310cf8f80a5d6064d2a"
            )
        );
        let lengths = DerivationLengths {
            a: 100,
            b: 0,
            c: 0,
            d: 0,
            e: 0,
            f: 0,
        };
        let keys = derive(super::super::sntrup::NAME, &shared, &h, &h, lengths).unwrap();
        assert_eq!(
            *keys.iv_client_to_server,
            decode_hex(
                "62dcbe92406dc4ee8ee65ee790c407be730e7768d2de4ea7951cb6218dae8a738a89e4562f423815110df32897105df38bafb4cfdf8ef21e1d122957337184996ca6cc36fb763fb836674962440efebfce60cfdedabb380356fa4427079da29a1b4f5857"
            )
        );
    }
    #[test]
    fn rfc_hash_and_multiblock_expansion_match_independent_fixtures() {
        let fixtures = [
            (
                P384,
                "a79faf55bcf9b418a8207906af69fa9b20b84a60ecb41570c335c0eec970b4221e049e2a040de3740960e308229af314",
                "ff200673239b195427f6676bf2e51d67173e0fb1029192b8822de4b5e3c94ae250cf4a839f1402f5ece5440faad85cf244ce9c29899091f6536722ee53dc93a6cb2fb6c301918f489e631cbe18e8075fefd24a03e605020a5508332cb901754487266b80",
            ),
            (
                P521,
                "42c9fdf1932b6dcb0daab5bcb2567b2a9abcc98fe1ab17bcf5184f697cab7e05b7a523f0b45c3e912c6e3efdabf6ea16bab8792d2bfc3ba987e22e3195a601d3",
                "1877f2587789fb7ae8266b8defe2ea3cfbd9e4f72028ef6cbe1b68185b01f865d349144d54951b715884d232ab44c5fc029e6ab44e12f6f3887e6dc32157a6968b2611af2396fa07411427cd1047cfed9fe1c349d3c9b5774458f3c81b185bff1827a06d",
            ),
            (
                GEX,
                "41e64f83dca59987206aecd3d1bcb581c94c711cfaf2ec09c3d4b1d42896c352",
                "c07d0c483bdf2195b6df2e9745542d7657d9142a3314e5a1841809067e8034962ca5f921cd865e1009cb3d4ec88e9ab0c0d888774d3cf3e2900481d38b199588b6cd9b59b8ff21c34158810652e871a512accdb860b04603b22e8f6c38240403ad065eb0",
            ),
            (
                GEX_SHA1,
                "b309a7d04df197b17872d348f149de133238e6bd",
                "d669912d7dea4d7d99dd94b60de2a43447bac320479074539e977e404b110fe1b4138eb39a32b5b5ee824f49d5a6869cea9a5c39f2ddc2bea964ba9282d8892c27e308f6a5e7685db2b247e4ee1247f9cf4bfa043203f2db5271898c40d0de9c6a4dcf25",
            ),
            (
                GROUP1,
                "112de0fae3a5220b5c31a014407ae80ba658d5f1",
                "96fb9715c3df8ff234ac7a72ca8fbc3f2d2536976cc99ccfe51fd8377977a5bdab7c4ff8ad1afd3ef209fefe9277f2b3901c00b44d3ccf0e0f50196a2c9dcdc54254e8e0a92cc43e594441f016a788d7b0b5abb4db4b80987c8f8a8a4648feefcb56a7f6",
            ),
        ];
        for (algorithm, expected_h, expected_a) in fixtures {
            let shared = SharedSecret::from_raw(&[0x80, 1]).unwrap();
            let (client, server, bounds) = if is_gex(algorithm) {
                (
                    b"\x03".as_slice(),
                    b"\x04".as_slice(),
                    Some([2048, 4096, 8192]),
                )
            } else if algorithm == GROUP1 {
                (b"\x03".as_slice(), b"\x04".as_slice(), None)
            } else {
                (b"client".as_slice(), b"server".as_slice(), None)
            };
            let h = context(algorithm)
                .exchange_hash(b"host", client, server, &shared, bounds)
                .unwrap();
            assert_eq!(h, decode_hex(expected_h));
            let lengths = DerivationLengths {
                a: 100,
                b: 0,
                c: 0,
                d: 0,
                e: 0,
                f: 0,
            };
            let keys = derive(algorithm, &shared, &h, &h, lengths).unwrap();
            assert_eq!(*keys.iv_client_to_server, decode_hex(expected_a));
            if algorithm != GEX {
                assert!(derive(algorithm, &shared, &[0; 32], &h, lengths).is_err());
            }
            if let Some(mut bounds) = bounds {
                bounds[1] += 1;
                assert_ne!(
                    context(algorithm)
                        .exchange_hash(b"host", client, server, &shared, Some(bounds))
                        .unwrap(),
                    h
                );
            }
        }
    }

    #[test]
    fn group1_modular_arithmetic_matches_python_pow_fixture() {
        // Critical crypto boundary: Python pow(base, exponent, RFC4253_prime),
        // not a second invocation of this implementation, is the oracle.
        let private = || {
            DhGroup16::new()
                .from_private_bytes(std::array::from_fn(|i| u8::try_from(i).unwrap()))
                .unwrap()
        };
        assert_eq!(
            DhGroup16::group1_public(&private()).unwrap(),
            decode_hex(
                "0bd459e79b6c61d44a5b4a8093094433af58dd6760aea0c719dcfede25b8afb54772843d5fac44a9fed1a58f8cfa8396b8839a068acfe36001d0f2a61a015f8cb5f7511d3142010f107ebe8de54fcf363a817219e6b561cbf074d155285bdc98f00dda4ceaa736e5fcdf8b437f7d0d8d3f6b6c2eb6fa891b749f10c9ce27cc3a"
            )
        );
        let peer = decode_hex(
            "cc8e15e6a9f146e9efceeeec6c98f5fb3fd3a24ae507715971e7de646ab51f41ac9beddf465da9a8f1a12bb34dae0f25f9f9fc543946085ce35934d47b587b4f82e2c6c5781bd958abec87db04ea7562de6cec84ac2ea6af3cacc37fcd60ce9d31ee597c95668523bbee2d67a051934c5e3f24daa0c154f3bb8e6ce2ddfab438",
        );
        let shared = DhGroup16::group1_agree(private(), &peer).unwrap();
        let expected = decode_hex(
            "0000008039567faad8444a2dd3fa320e85d651839c6051aec89e4ad974e8db49d32ac7be42dc8cd10a5f3ee7e895601c2b231df9d483b46aa6300610282d973bca80732b684eab9ae2b21dce8547005284b317978646e49fea012d13c72c9f1a1ab2e2f2482f505d6ac49554d85f5e82ddcdb707d1e6ae58466cc9a5bec519fa8e1c3c86",
        );
        assert_eq!(shared.as_bytes(), expected);
        for peer in [vec![], vec![0], vec![1], vec![0xff; 129], vec![0xff; 128]] {
            assert!(DhGroup16::group1_agree(private(), &peer).is_err());
        }
    }

    #[test]
    fn group_bounds_safe_prime_and_generator_reject_before_key_generation() {
        let prime = DhGroup16::new().prime_bytes().unwrap();
        let mut wrong = prime.clone();
        wrong[511] ^= 2;
        for (p, g) in [
            (vec![0xff; 1024], vec![2]),
            (vec![0xff; 256], vec![2]),
            (wrong, vec![2]),
            (prime.clone(), vec![1]),
            (prime.clone(), vec![5]),
        ] {
            let mut packet = Writer::new();
            packet.write_byte(31);
            positive(&mut packet, &p).unwrap();
            positive(&mut packet, &g).unwrap();
            for algorithm in [GEX, GEX_SHA1] {
                let mut client = Client::new(context(algorithm)).unwrap();
                assert!(client.accept_group(packet.as_bytes()).is_err());
                assert!(client.secret.is_none());
                assert_eq!(client.public, []);
            }
        }
        validate_group(&prime, &[2], REQUEST).unwrap();
        for bounds in [
            [1024, 4096, 8192],
            [4096, 4096, 16384],
            [2048, 2048, 2048],
            [8192, 8192, 8192],
            [4096, 2048, 8192],
        ] {
            let mut server = Server::new(context(GEX), b"host", false);
            let mut packet = Writer::new();
            packet.write_byte(34);
            for value in bounds {
                packet.write_uint32(value);
            }
            assert!(server.accept(packet.as_bytes()).is_err());
            assert!(server.bounds.is_none());
        }
        // Correct group permits generation; an out-of-order init never does.
        let mut client = Client::new(context(GEX)).unwrap();
        assert!(client.complete(&[33]).is_err());
        client = Client::new(context(GEX)).unwrap();
        let mut packet = Writer::new();
        packet.write_byte(31);
        positive(&mut packet, &prime).unwrap();
        positive(&mut packet, &[2]).unwrap();
        assert_eq!(client.accept_group(packet.as_bytes()).unwrap()[0], 32);
        assert!(client.secret.is_some());
    }
}
