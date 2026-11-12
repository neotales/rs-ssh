//! Explicit platform connector behavior; protocol runs on scripted byte streams.
#[cfg(not(windows))]
#[test]
fn a_non_windows_host_does_not_open_a_pipe_as_a_file() {
    assert!(matches!(
        neotales_ssh::agent::connect_pipe(r"\\.\pipe\synthetic-test-agent"),
        Err(neotales_ssh::agent::AgentError::UnsupportedPlatform)
    ));
}

#[cfg(windows)]
#[test]
fn opens_only_an_explicit_test_pipe_and_skips_if_absent() -> Result<(), Box<dyn std::error::Error>>
{
    // This deliberately names a test fixture, never the user's default agent.
    match neotales_ssh::agent::connect_pipe(r"\\.\pipe\neotales-ssh-test-agent") {
        Ok(_client) => Ok(()),
        Err(neotales_ssh::agent::AgentError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            eprintln!("skipped: explicit test pipe is absent");
            Ok(())
        }
        Err(error) => Err(Box::new(error)),
    }
}

#[test]
fn pipe_protocol_is_independent_of_the_connector() -> Result<(), Box<dyn std::error::Error>> {
    struct Script {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl std::io::Read for Script {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.input, bytes)
        }
    }
    impl std::io::Write for Script {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let stream = Script {
        input: std::io::Cursor::new(vec![0, 0, 0, 5, 12, 0, 0, 0, 0]),
        output: Vec::new(),
    };
    let mut client = neotales_ssh::agent::AgentClient::new(stream);
    assert_eq!(client.identities()?.len(), 0);
    assert_eq!(client.into_inner().output, [0, 0, 0, 1, 11]);
    Ok(())
}
