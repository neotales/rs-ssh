//! Task 0010 / RFC 4252 and 4256 authentication state-machine contracts.
use neotales_ssh::auth::{
    AuthMethodKind, KeyboardInteractiveChallenge, KeyboardInteractivePrompt,
    KeyboardInteractiveServerDecision as Decision, MAX_KEYBOARD_INTERACTIVE_STRING,
};
use neotales_ssh::{
    ClientAuthMethod, ClientConfig, ServerAuthPolicy, ServerConfig, authenticate_client,
    authenticate_server, hostkey::Ed25519Signer,
};
use std::{
    cell::Cell,
    net::{TcpListener, TcpStream},
    time::Duration,
};

fn connected() -> Result<Connected, Box<dyn std::error::Error>> {
    connect_with_policy(|| {
        let round = Cell::new(0);
        Ok(
            ServerAuthPolicy::new(8)?.with_keyboard_interactive_callback(move |_, responses| {
                match round.replace(round.get() + 1) {
                    0 => Decision::Challenge(challenge("first")),
                    1 if responses == ["first answer"] => Decision::Challenge(challenge("second")),
                    2 if responses == ["second answer"] => Decision::Accept,
                    _ => Decision::Reject,
                }
            }),
        )
    })
}
fn challenge(text: &str) -> KeyboardInteractiveChallenge {
    KeyboardInteractiveChallenge::new(
        "login",
        "answer",
        [KeyboardInteractivePrompt::new(text, false)],
    )
}
type Connected = (
    neotales_ssh::ClientTransport<TcpStream>,
    std::thread::JoinHandle<Result<bool, String>>,
);
fn connect_with_policy(
    factory: impl FnOnce() -> Result<ServerAuthPolicy, neotales_ssh::auth::AuthError> + Send + 'static,
) -> Result<Connected, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let thread = std::thread::spawn(move || {
        let policy = factory().map_err(|error| error.to_string())?;
        let (stream, _) = listener.accept().map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        let mut server = ServerConfig::new(Ed25519Signer::from_seed(&mut [77; 32]))
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
fn keyboard_interactive_runs_two_rounds_through_the_normal_transports()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut client, server) = connected()?;
    let method =
        ClientAuthMethod::keyboard_interactive(|prompts: &[KeyboardInteractivePrompt]| {
            assert_eq!(prompts.len(), 1);
            vec![format!("{} answer", prompts[0].text())]
        });
    let result = authenticate_client(&mut client, "user", &[method], 8)?;
    assert_eq!(result.method(), AuthMethodKind::KeyboardInteractive);
    drop(client);
    assert!(server.join().map_err(|_| "server panicked")??);
    Ok(())
}

#[test]
fn none_requires_explicit_per_account_permission() -> Result<(), Box<dyn std::error::Error>> {
    for (configured, username, accepted) in [
        (false, "guest", false),
        (true, "other", false),
        (true, "guest", true),
    ] {
        let (mut client, server) = connect_with_policy(move || {
            let policy = ServerAuthPolicy::new(4)?;
            Ok(if configured {
                policy.with_none_policy(|name| name == "guest")
            } else {
                policy
            })
        })?;
        let result = authenticate_client(&mut client, username, &[ClientAuthMethod::None], 4);
        assert_eq!(result.is_ok(), accepted);
        if let Ok(result) = result {
            assert_eq!(result.method(), AuthMethodKind::None);
        }
        drop(client);
        assert_eq!(server.join().map_err(|_| "server panicked")??, accepted);
    }
    Ok(())
}

#[test]
fn fallback_skips_methods_not_in_the_servers_remaining_list()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut client, server) = connect_with_policy(|| {
        Ok(ServerAuthPolicy::new(4)?
            .with_password_callback(|password| password == "synthetic-password"))
    })?;
    let mut authenticator = neotales_ssh::auth::ClientAuthenticator::new(&mut client, "user", 4)?;
    let result = authenticator.authenticate(&[
        ClientAuthMethod::None,
        ClientAuthMethod::public_key(neotales_ssh::auth::PublicKeySigner::ed25519(
            Ed25519Signer::from_seed(&mut [79; 32]),
        )),
        ClientAuthMethod::password("synthetic-password"),
    ])?;
    assert_eq!(result.method(), AuthMethodKind::Password);
    assert_eq!(authenticator.attempts(), 2);
    assert!(!authenticator.partial_success());
    drop(client);
    assert!(server.join().map_err(|_| "server panicked")??);
    Ok(())
}

#[test]
fn endlessly_repeated_keyboard_challenges_are_bounded_without_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut client, server) = connect_with_policy(|| {
        Ok(ServerAuthPolicy::new(2)?
            .with_keyboard_interactive_callback(|_, _| Decision::Challenge(challenge("repeat"))))
    })?;
    let rounds = std::rc::Rc::new(Cell::new(0));
    let callback_rounds = rounds.clone();
    let method =
        ClientAuthMethod::keyboard_interactive(move |_: &[KeyboardInteractivePrompt]| {
            callback_rounds.set(callback_rounds.get() + 1);
            vec!["synthetic-response".to_owned()]
        });
    assert!(authenticate_client(&mut client, "user", &[method], 64).is_err());
    assert_eq!(
        rounds.get(),
        neotales_ssh::auth::MAX_KEYBOARD_INTERACTIVE_ROUNDS
    );
    drop(client);
    assert!(!server.join().map_err(|_| "server panicked")??);
    Ok(())
}

#[test]
fn empty_and_oversized_prompts_never_reach_a_responder() -> Result<(), Box<dyn std::error::Error>> {
    for text in [
        String::new(),
        "a".repeat(MAX_KEYBOARD_INTERACTIVE_STRING + 1),
    ] {
        assert!(challenge(&text).validate().is_err());
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let thread = std::thread::spawn(move || -> Result<(), String> {
            let (stream, _) = listener.accept().map_err(|error| error.to_string())?;
            let mut server = ServerConfig::new(Ed25519Signer::from_seed(&mut [78; 32]))
                .accept(stream)
                .map_err(|error| error.to_string())?;
            server
                .read_auth_packet()
                .map_err(|error| error.to_string())?;
            let mut accept = neotales_ssh::Writer::new();
            accept.write_byte(6);
            accept
                .write_string("ssh-userauth")
                .map_err(|error| error.to_string())?;
            server
                .write_auth_packet(accept.as_bytes())
                .map_err(|error| error.to_string())?;
            server
                .read_auth_packet()
                .map_err(|error| error.to_string())?;
            let mut request = neotales_ssh::Writer::new();
            request.write_byte(60);
            for value in ["login", "answer", ""] {
                request
                    .write_string(value)
                    .map_err(|error| error.to_string())?;
            }
            request.write_uint32(1);
            request
                .write_string(&text)
                .map_err(|error| error.to_string())?;
            request.write_boolean(false);
            server
                .write_auth_packet(request.as_bytes())
                .map_err(|error| error.to_string())?;
            Ok(())
        });
        let stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut client = ClientConfig::new().connect(stream, |_| Ok::<(), ()>(()))?;
        let called = std::rc::Rc::new(Cell::new(false));
        let called_in_callback = called.clone();
        let method =
            ClientAuthMethod::keyboard_interactive(move |_: &[KeyboardInteractivePrompt]| {
                called_in_callback.set(true);
                vec![String::new()]
            });
        assert!(authenticate_client(&mut client, "user", &[method], 4).is_err());
        assert!(!called.get());
        drop(client);
        thread.join().map_err(|_| "server panicked")??;
    }
    Ok(())
}
