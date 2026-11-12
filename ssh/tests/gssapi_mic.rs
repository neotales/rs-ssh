//! Fake GSS context only: no KDC, credentials, Kerberos or SSPI.
use neotales_ssh::gssapi::{
    GssapiError, GssapiMechanismResult as Step, GssapiMicMechanism, GssapiToken,
    GssapiTokenMechanism, GssapiUserAuthRequest, mic_input,
};
use neotales_ssh::{
    ClientAuthMethod, ClientConfig, ServerAuthPolicy, ServerConfig, Writer, authenticate_client,
    authenticate_server, hostkey::Ed25519Signer,
};
use sha2::{Digest, Sha256};
use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
};
struct Fake {
    server: bool,
    mode: u8,
}
impl GssapiTokenMechanism for Fake {
    fn mechanism(&self) -> &[u8] {
        b"fake-integrity-context"
    }
    fn exchange(&self, token: &[u8]) -> Step {
        if self.mode == 5 {
            return Step::Fail;
        }
        match (self.server, token) {
            (false, b"") => Step::continue_with(b"client-token"),
            (true, b"client-token") => Step::accept_with_token(b"server-token"),
            (false, b"server-token") => Step::Accept,
            _ => Step::Fail,
        }
    }
}
impl GssapiMicMechanism for Fake {
    fn get_mic(&self, data: &[u8]) -> Result<Vec<u8>, GssapiError> {
        if self.mode == 6 {
            return Err(GssapiError::CallbackRejected);
        }
        let mut input = data.to_vec();
        match self.mode {
            1 => input[4] ^= 1, // Different session id.
            2 => {
                let index = input
                    .windows(8)
                    .position(|bytes| bytes == b"mic-user")
                    .ok_or(GssapiError::InvalidMessage)?;
                input[index] ^= 1;
            }
            3 => {
                let index = input
                    .windows(14)
                    .position(|bytes| bytes == b"ssh-connection")
                    .ok_or(GssapiError::InvalidMessage)?;
                input[index] ^= 1;
            }
            4 => {
                let index = input
                    .windows(15)
                    .position(|bytes| bytes == b"gssapi-with-mic")
                    .ok_or(GssapiError::InvalidMessage)?;
                input[index] ^= 1;
            }
            _ => {}
        }
        Ok(Sha256::digest(input).to_vec())
    }
    fn verify_mic(&self, data: &[u8], mic: &[u8]) -> Result<(), GssapiError> {
        if Sha256::digest(data).as_slice() == mic {
            Ok(())
        } else {
            Err(GssapiError::CallbackRejected)
        }
    }
}
type Pair = (
    neotales_ssh::ClientTransport<TcpStream>,
    std::thread::JoinHandle<Result<bool, String>>,
);
fn pair(server_mode: u8, fallback: bool) -> Result<Pair, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let thread = std::thread::spawn(move || -> Result<bool, String> {
        let policy = ServerAuthPolicy::new(8).map_err(|error| error.to_string())?;
        let policy = if server_mode == 6 {
            policy.with_gssapi_token_callback(b"fake-integrity-context", |_| Step::Accept)
        } else {
            policy.with_gssapi_mic_mechanism(Fake {
                server: true,
                mode: server_mode,
            })
        };
        let policy = if fallback {
            policy.with_password_callback(|password| password == "synthetic-fallback")
        } else {
            policy
        };
        let (stream, _) = listener.accept().map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        let mut server = ServerConfig::new(Ed25519Signer::from_seed(&mut [83; 32]))
            .accept(stream)
            .map_err(|error| error.to_string())?;
        let _result = authenticate_server(&mut server, &policy);
        Ok(server.is_authenticated())
    });
    let stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let client = ClientConfig::new().connect(stream, |_| Ok::<(), ()>(()))?;
    Ok((client, thread))
}

#[test]
fn mic_is_required_and_binds_session_user_service_and_method()
-> Result<(), Box<dyn std::error::Error>> {
    for mode in 0..5 {
        let (mut client, server) = pair(0, false)?;
        let result = authenticate_client(
            &mut client,
            "mic-user",
            &[ClientAuthMethod::gssapi(Fake {
                server: false,
                mode,
            })],
            8,
        );
        assert_eq!(result.is_ok(), mode == 0);
        if let Ok(result) = result {
            assert_eq!(result.method(), neotales_ssh::auth::AuthMethodKind::Gssapi);
        }
        drop(client);
        assert_eq!(server.join().map_err(|_| "server panicked")??, mode == 0);
    }
    assert_eq!(
        mic_input(b"sid", b"user")?,
        b"\0\0\0\x03sid\x32\0\0\0\x04user\0\0\0\x0essh-connection\0\0\0\x0fgssapi-with-mic"
    );
    Ok(())
}

#[test]
fn mechanism_failure_is_a_normal_method_failure_and_can_fall_back()
-> Result<(), Box<dyn std::error::Error>> {
    for (client_mode, server_mode) in [(5, 0), (0, 5), (1, 0), (6, 0)] {
        let (mut client, server) = pair(server_mode, true)?;
        let result = authenticate_client(
            &mut client,
            "mic-user",
            &[
                ClientAuthMethod::gssapi(Fake {
                    server: false,
                    mode: client_mode,
                }),
                ClientAuthMethod::password("synthetic-fallback"),
            ],
            8,
        )?;
        assert_eq!(
            result.method(),
            neotales_ssh::auth::AuthMethodKind::Password
        );
        drop(client);
        assert!(server.join().map_err(|_| "server panicked")??);
    }
    Ok(())
}

#[test]
fn token_only_server_configuration_neither_offers_nor_authenticates_gssapi()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut client, server) = pair(6, false)?;
    let result = authenticate_client(
        &mut client,
        "mic-user",
        &[ClientAuthMethod::gssapi(Fake {
            server: false,
            mode: 0,
        })],
        8,
    );
    assert!(result.is_err());
    drop(client);
    assert!(!server.join().map_err(|_| "server panicked")??);
    let (mut client, server) = pair(6, false)?;
    let mut request = Writer::new();
    request.write_byte(5);
    request.write_string("ssh-userauth")?;
    client.write_payload(request.as_bytes())?;
    client.read_payload()?;
    let mut request = Writer::new();
    request.write_byte(50);
    for field in ["mic-user", "ssh-connection", "none"] {
        request.write_string(field)?;
    }
    client.write_payload(request.as_bytes())?;
    let failure = client.read_payload()?;
    let mut reader = neotales_ssh::Reader::new(&failure);
    assert_eq!(reader.read_byte()?, 51);
    assert!(
        !reader
            .read_name_list()?
            .iter()
            .any(|method| method == "gssapi-with-mic")
    );
    drop(client);
    assert!(!server.join().map_err(|_| "server panicked")??);
    Ok(())
}

#[test]
fn message_63_after_accepted_tokens_never_authenticates() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut client, server) = pair(0, false)?;
    let mut service = Writer::new();
    service.write_byte(5);
    service.write_string("ssh-userauth")?;
    client.write_payload(service.as_bytes())?;
    assert_eq!(client.read_payload()?[0], 6);
    client.write_payload(
        &GssapiUserAuthRequest::try_new(b"mic-user", [b"fake-integrity-context"])?.encode()?,
    )?;
    assert_eq!(client.read_payload()?[0], 60);
    client.write_payload(&GssapiToken::new(b"client-token").encode()?)?;
    assert_eq!(client.read_payload()?[0], 61);
    client.write_payload(&[63])?;
    assert_eq!(client.read_payload()?[0], 51);
    drop(client);
    assert!(!server.join().map_err(|_| "server panicked")??);
    Ok(())
}
