//! Both public handshakes, protected traffic, hash widths and RFC 4419 stages.
use neotales_ssh::{ClientConfig, ServerConfig, hostkey::Ed25519Signer};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    time::Duration,
};
struct Trace {
    stream: TcpStream,
    output: Arc<Mutex<Vec<u8>>>,
}
impl Read for Trace {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.read(bytes)
    }
}
impl Write for Trace {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.stream.write(bytes)?;
        self.output
            .lock()
            .map_err(|_| io::Error::other("trace poisoned"))?
            .extend_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
fn messages(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut offset = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or("missing identification")?
        + 1;
    let mut result = Vec::new();
    while offset + 6 <= bytes.len() {
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into()?) as usize;
        let message = bytes[offset + 5];
        result.push(message);
        if message == 21 {
            return Ok(result);
        }
        offset += length + 4;
    }
    Err("missing NEWKEYS".into())
}

#[test]
fn new_and_baseline_exchanges_complete_with_correct_session_widths_and_stages()
-> Result<(), Box<dyn std::error::Error>> {
    for (name, width) in [
        ("curve25519-sha256", 32),
        ("curve25519-sha256@libssh.org", 32),
        ("ecdh-sha2-nistp256", 32),
        ("diffie-hellman-group16-sha512", 64),
        ("mlkem768x25519-sha256", 32),
        ("sntrup761x25519-sha512@openssh.com", 64),
        ("ecdh-sha2-nistp384", 48),
        ("ecdh-sha2-nistp521", 64),
        ("diffie-hellman-group-exchange-sha256", 32),
    ] {
        for strict in [false, true] {
            let config = ServerConfig::new(Ed25519Signer::from_seed(&mut [91; 32]));
            let mut server_proposal = config.kexinit().clone();
            server_proposal.kex_algorithms.retain(|entry| entry != name);
            server_proposal.kex_algorithms.insert(0, name.to_owned());
            let mut client_proposal = ClientConfig::new().kexinit().clone();
            client_proposal.kex_algorithms.retain(|entry| entry != name);
            client_proposal.kex_algorithms.insert(0, name.to_owned());
            // Keep all existing mechanisms available; preference selects this
            // test's new exchange without creating a single-algorithm default.
            for proposal in [&mut server_proposal, &mut client_proposal] {
                if !strict {
                    proposal
                        .kex_algorithms
                        .retain(|name| !name.starts_with("kex-strict-"));
                }
                proposal.encryption_algorithms_client_to_server = vec!["aes256-ctr".to_owned()];
                proposal.encryption_algorithms_server_to_client = vec!["aes256-ctr".to_owned()];
                proposal.mac_algorithms_client_to_server = vec!["hmac-sha2-512".to_owned()];
                proposal.mac_algorithms_server_to_client = vec!["hmac-sha2-512".to_owned()];
            }
            let config = config.with_kexinit(server_proposal);
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            let address = listener.local_addr()?;
            let server_trace = Arc::new(Mutex::new(Vec::new()));
            let thread_trace = server_trace.clone();
            let server = std::thread::spawn(move || -> Result<Vec<u8>, String> {
                let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .map_err(|e| e.to_string())?;
                let mut transport = config
                    .accept(Trace {
                        stream,
                        output: thread_trace,
                    })
                    .map_err(|e| e.to_string())?;
                let sid = transport.session_id().to_vec();
                if transport.read_auth_packet().map_err(|e| e.to_string())? != b"\x05probe" {
                    return Err("bad protected request".to_owned());
                }
                let mut reply = vec![6];
                reply.extend_from_slice(&sid);
                transport.write_payload(&reply).map_err(|e| e.to_string())?;
                Ok(sid)
            });
            let stream = TcpStream::connect(address)?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            let client_trace = Arc::new(Mutex::new(Vec::new()));
            let mut client = ClientConfig::with_kexinit(client_proposal).connect(
                Trace {
                    stream,
                    output: client_trace.clone(),
                },
                |_| Ok::<(), ()>(()),
            )?;
            let sid = client.session_id().to_vec();
            assert_eq!(sid.len(), width);
            client.write_payload(b"\x05probe")?;
            assert_eq!(&client.read_payload()?[1..], sid);
            assert_eq!(server.join().map_err(|_| "server panicked")??, sid);
            let (client_expected, server_expected) =
                if name == "diffie-hellman-group-exchange-sha256" {
                    (vec![20, 34, 32, 21], vec![20, 31, 33, 21])
                } else {
                    (vec![20, 30, 21], vec![20, 31, 21])
                };
            assert_eq!(
                messages(&client_trace.lock().map_err(|_| "trace poisoned")?)?,
                client_expected
            );
            assert_eq!(
                messages(&server_trace.lock().map_err(|_| "trace poisoned")?)?,
                server_expected
            );
        }
    }
    Ok(())
}

#[test]
fn defaults_retain_existing_choices_and_advertise_only_modern_names_once() {
    let client = ClientConfig::new();
    let server = ServerConfig::new(Ed25519Signer::from_seed(&mut [92; 32]));
    for proposal in [client.kexinit(), server.kexinit()] {
        for name in [
            "curve25519-sha256",
            "ecdh-sha2-nistp256",
            "diffie-hellman-group16-sha512",
            "mlkem768x25519-sha256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256",
        ] {
            assert_eq!(
                proposal
                    .kex_algorithms
                    .iter()
                    .filter(|entry| *entry == name)
                    .count(),
                1
            );
        }
        for name in [
            "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group1-sha1",
            "sntrup761x25519-sha512@openssh.com",
        ] {
            assert!(!proposal.kex_algorithms.iter().any(|entry| entry == name));
        }
        for names in [
            &proposal.encryption_algorithms_client_to_server,
            &proposal.encryption_algorithms_server_to_client,
        ] {
            assert!(
                !names
                    .iter()
                    .any(|name| name.contains("cbc") || name.contains("3des"))
            );
        }
        for names in [
            &proposal.mac_algorithms_client_to_server,
            &proposal.mac_algorithms_server_to_client,
        ] {
            assert!(!names.iter().any(|name| name.contains("sha1")));
        }
    }
}
