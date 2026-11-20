//! The same handshake, pinned-trust, and public-key-authentication cases against
//! native OpenSSH and a digest-pinned testcontainers peer. Never a fake peer.
use base64::{Engine, engine::general_purpose::STANDARD};
use neotales_ssh::{
    ClientConfig,
    auth::{AuthMethodKind, ClientAuthMethod, PublicKeySigner, authenticate_client},
    hostkey::{Ed25519PublicKey, Ed25519Signer},
};
use std::{
    net::{SocketAddr, TcpStream},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use testcontainers::{
    GenericImage, ImageExt,
    core::{ExecCommand, IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

type Error = Box<dyn std::error::Error + Send + Sync>;
const IMAGE: &str = "lscr.io/linuxserver/openssh-server";
// OCI index inspected with `docker buildx imagetools inspect` on 2026-11-11.
const IMAGE_TAG: &str =
    "latest@sha256:161e0b670b31d9539ca1718bc5943e981779331b4e1c9d32e8929d7652a1f22f";

fn enabled() -> bool {
    if std::env::var("NEOTALES_SSH_E2E").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipping SSH e2e: set NEOTALES_SSH_E2E=1");
    false
}

fn identity(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&mut [seed; 32])
}

fn authorized_key() -> Result<String, Error> {
    Ok(format!(
        "ssh-ed25519 {} ssh-e2e\n",
        STANDARD.encode(identity(49).public_key_blob()?)
    ))
}

fn public_key(text: &[u8]) -> Result<Ed25519PublicKey, Error> {
    let text = std::str::from_utf8(text)?;
    let encoded = text
        .split_whitespace()
        .nth(1)
        .ok_or("missing host public key")?;
    Ok(Ed25519PublicKey::from_blob(&STANDARD.decode(encoded)?)?)
}

fn connect(address: SocketAddr) -> Result<TcpStream, Error> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let stream = loop {
        match TcpStream::connect_timeout(&address, Duration::from_secs(1)) {
            Ok(stream) => break stream,
            Err(error) if Instant::now() >= deadline => return Err(error.into()),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    Ok(stream)
}

fn cases(address: SocketAddr, expected: Ed25519PublicKey, username: &str) -> Result<(), Error> {
    let rejected = ClientConfig::new().connect(connect(address)?, |_| Err::<(), ()>(()));
    assert!(matches!(
        rejected,
        Err(neotales_ssh::client::HandshakeError::HostKey(
            neotales_ssh::hostkey::HostKeyError::TrustRejected
        ))
    ));
    for (seed, authorized) in [(49, true), (50, false)] {
        let mut trusted = false;
        let mut transport = ClientConfig::new().connect(connect(address)?, |key| {
            trusted = *key == expected;
            if trusted { Ok(()) } else { Err(()) }
        })?;
        assert!(trusted);
        assert!(transport.is_established());
        let method = ClientAuthMethod::public_key(PublicKeySigner::ed25519(identity(seed)));
        let result = authenticate_client(&mut transport, username, &[method], 4);
        if authorized {
            assert_eq!(result?.method(), AuthMethodKind::PublicKey);
        } else {
            assert!(result.is_err());
        }
    }
    Ok(())
}

#[tokio::test]
async fn testcontainers_openssh() -> Result<(), Error> {
    if !enabled() {
        return Ok(());
    }
    if !Command::new("docker")
        .arg("info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        eprintln!("skipping Docker SSH peer: Docker is unavailable");
        return Ok(());
    }
    let container = GenericImage::new(IMAGE, IMAGE_TAG)
        .with_exposed_port(2222.tcp())
        .with_wait_for(WaitFor::seconds(1))
        .with_env_var("USER_NAME", "ssh-e2e")
        .with_env_var("PUBLIC_KEY", authorized_key()?.trim())
        .with_env_var("PASSWORD_ACCESS", "false")
        .with_env_var("SUDO_ACCESS", "false")
        .start()
        .await?;
    let port = container.get_host_port_ipv4(2222.tcp()).await?;
    let address = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    // Wait for the real listener before retrieving its independently trusted
    // public key through Docker's exec API. Never read a private key.
    drop(connect(address)?);
    let mut output = container
        .exec(ExecCommand::new([
            "cat",
            "/config/ssh_host_keys/ssh_host_ed25519_key.pub",
        ]))
        .await?;
    let expected = public_key(&output.stdout_to_vec().await?)?;
    cases(address, expected, "ssh-e2e")?;
    Ok(())
}

#[cfg(unix)]
fn program(name: &str) -> Option<std::path::PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .chain([
            std::path::PathBuf::from("/usr/sbin"),
            std::path::PathBuf::from("/usr/bin"),
            std::path::PathBuf::from("/usr/local/sbin"),
        ])
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

#[cfg(unix)]
struct Native(std::process::Child);
#[cfg(unix)]
impl Drop for Native {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// The native fixture runs a real `sshd`, which only exists on Unix. Splitting
// the test per platform keeps the Unix body able to fail: on any other target
// it has nothing to do, and a `Result` that is always `Ok` is a lie.
#[cfg(unix)]
#[test]
fn native_openssh() -> Result<(), Error> {
    if !enabled() {
        return Ok(());
    }
    let (Some(sshd), Some(keygen)) = (program("sshd"), program("ssh-keygen")) else {
        eprintln!("skipping native SSH peer: sshd or ssh-keygen is missing");
        return Ok(());
    };
    let directory = tempfile::tempdir()?;
    let host = directory.path().join("host");
    let status = Command::new(keygen)
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("fixture host-key generation failed".into());
    }
    let expected = public_key(&std::fs::read(host.with_extension("pub"))?)?;
    let authorized = directory.path().join("authorized_keys");
    std::fs::write(&authorized, authorized_key()?)?;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    drop(listener);
    let config = directory.path().join("sshd_config");
    std::fs::write(
        &config,
        format!(
            "Port {}\nListenAddress 127.0.0.1\nHostKey \"{}\"\nAuthorizedKeysFile \"{}\"\nPidFile \"{}\"\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nUsePAM no\n",
            address.port(),
            host.display(),
            authorized.display(),
            directory.path().join("pid").display()
        ),
    )?;
    let username = Command::new("id").arg("-un").output()?;
    if !username.status.success() {
        return Err("could not identify native fixture user".into());
    }
    let username = std::str::from_utf8(&username.stdout)?.trim();
    let _server = Native(
        Command::new(sshd)
            .args(["-D", "-e", "-f"])
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    cases(address, expected, username)
}

#[cfg(not(unix))]
#[test]
fn native_openssh() {
    eprintln!("skipping native SSH peer: the native fixture requires Unix");
}
