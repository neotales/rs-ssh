// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[test]
fn remote_shell_policy_preserves_windows_paths_and_quotes_without_posix_escaping()
-> Result<(), Box<dyn std::error::Error>> {
    use neotales_ssh::scp::{
        RemoteShell, download_command_with_shell, upload_command, upload_command_with_shell,
    };
    let path = br"C:\Program Files\O'Brien";
    assert_eq!(
        upload_command_with_shell(path, RemoteShell::PowerShell)?,
        "scp -t -- 'C:\\Program Files\\O''Brien'"
    );
    assert_eq!(
        download_command_with_shell(path, RemoteShell::PowerShell)?,
        "scp -f -- 'C:\\Program Files\\O''Brien'"
    );
    assert_ne!(
        upload_command(path)?,
        upload_command_with_shell(path, RemoteShell::PowerShell)?
    );
    for invalid in [b"a\0b".as_slice(), b"a\rb", b"a\nb"] {
        for shell in [RemoteShell::Posix, RemoteShell::PowerShell] {
            assert!(upload_command_with_shell(invalid, shell).is_err());
            assert!(download_command_with_shell(invalid, shell).is_err());
        }
    }
    Ok(())
}

use neotales_ssh::scp;

use std::error::Error;
use std::io::{self, Cursor, Read, Write};

use scp::{
    MAX_SCP_FILE_SIZE, ScpDirectoryEntry, ScpError, ScpFile, download, download_command,
    download_directory, upload, upload_command, upload_directory,
};

struct ScriptedStream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    read_lengths: Vec<usize>,
}

impl ScriptedStream {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(input),
            output: Vec::new(),
            read_lengths: Vec::new(),
        }
    }
}

impl Read for ScriptedStream {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.read_lengths.push(target.len());
        self.input.read(target)
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn upload_sends_time_file_header_body_and_trailer_in_order() -> Result<(), Box<dyn Error>> {
    let mut stream = ScriptedStream::new(vec![0, 0, 0, 0]);

    upload(
        &mut stream,
        "remote/file.bin",
        b"payload",
        Some(1_700_000_000),
    )?;

    assert_eq!(
        stream.output,
        b"T1700000000 0 1700000000 0\nC0644 7 file.bin\npayload\0"
    );
    Ok(())
}

#[test]
fn download_accepts_optional_time_and_returns_body_and_seconds() -> Result<(), Box<dyn Error>> {
    let input = b"T1700000000 123 1700000001 456\nC0644 7 file.bin\npayload\0".to_vec();
    let mut stream = ScriptedStream::new(input);

    let file: ScpFile = download(&mut stream)?;

    assert_eq!(file.data, b"payload");
    assert_eq!(file.mtime, Some(1_700_000_000));
    assert_eq!(file.atime, Some(1_700_000_001));
    assert_eq!(file.basename, b"file.bin");
    assert_eq!(stream.output, vec![0, 0, 0, 0]);
    Ok(())
}

#[test]
fn a_directory_header_is_rejected_without_reading_a_body() {
    let mut stream = ScriptedStream::new(b"D0755 0 directory\n".to_vec());

    let error = download(&mut stream).expect_err("directory records are unsupported");

    assert!(matches!(error, ScpError::DirectoryRecord));
    assert_eq!(stream.output, vec![0]);
    assert!(stream.read_lengths.iter().all(|length| *length == 1));
}

#[test]
fn in_memory_directory_upload_download_preserves_file_names_and_bytes() -> Result<(), Box<dyn Error>>
{
    let entries = vec![
        ScpDirectoryEntry {
            path: b"one.txt".to_vec(),
            data: b"first".to_vec(),
        },
        ScpDirectoryEntry {
            path: b"two.txt".to_vec(),
            data: b"second".to_vec(),
        },
    ];
    // Initial readiness, D, two acknowledgements per C, then E.
    let mut sender = ScriptedStream::new(vec![0; 7]);
    upload_directory(&mut sender, b"tree", &entries)?;
    assert_eq!(sender.input.position(), 7);
    assert_eq!(
        sender.output,
        b"D0755 0 tree\nC0644 5 one.txt\nfirst\0C0644 6 two.txt\nsecond\0E\n"
    );

    let mut receiver = ScriptedStream::new(sender.output);
    let result = download_directory(&mut receiver)?;
    assert_eq!(result.basename, b"tree");
    assert_eq!(result.entries, entries);
    assert_eq!(receiver.output, vec![0; 7]);
    Ok(())
}

#[test]
fn directory_transport_exchanges_acknowledgements_without_scripted_peer()
-> Result<(), Box<dyn Error>> {
    // A bounded, in-memory duplex transport. Reads time out so a framing
    // regression fails rather than leaving the suite blocked on an extra ACK.
    struct MemoryStream {
        input: std::sync::mpsc::Receiver<u8>,
        output: std::sync::mpsc::SyncSender<u8>,
    }
    impl Read for MemoryStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let Some(first) = bytes.first_mut() else {
                return Ok(0);
            };
            *first = self
                .input
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            Ok(1)
        }
    }
    impl Write for MemoryStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            for byte in bytes {
                self.output
                    .send(*byte)
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (a_tx, a_rx) = std::sync::mpsc::sync_channel(1024);
    let (b_tx, b_rx) = std::sync::mpsc::sync_channel(1024);
    let mut sender = MemoryStream {
        input: a_rx,
        output: b_tx,
    };
    let mut receiver = MemoryStream {
        input: b_rx,
        output: a_tx,
    };
    let entries = vec![
        ScpDirectoryEntry {
            path: b"nested/one".to_vec(),
            data: vec![0, 1, 255],
        },
        ScpDirectoryEntry {
            path: b"two".to_vec(),
            data: b"second".to_vec(),
        },
    ];
    let directory = std::thread::scope(|scope| {
        let sending = scope.spawn(|| upload_directory(&mut sender, b"tree", &entries));
        let result = download_directory(&mut receiver);
        sending.join().expect("in-memory sender must not panic")?;
        result
    })?;
    assert_eq!(directory.basename, b"tree");
    assert_eq!(directory.entries, entries);
    Ok(())
}

#[test]
fn directory_paths_reject_escape_and_collisions_before_upload_io() {
    for paths in [
        vec![b"../outside".as_slice()],
        vec![b"/absolute".as_slice()],
        vec![b"dir/../../outside".as_slice()],
        vec![b"dir//file".as_slice()],
        vec![b"dir/./file".as_slice()],
        vec![b"C:outside".as_slice()],
        vec![br"dir\outside".as_slice()],
        vec![b"same".as_slice(), b"same"],
        vec![b"dir".as_slice(), b"dir/file"],
        vec![b"dir/file".as_slice(), b"dir"],
    ] {
        let entries: Vec<_> = paths
            .into_iter()
            .map(|path| ScpDirectoryEntry {
                path: path.to_vec(),
                data: Vec::new(),
            })
            .collect();
        let mut stream = ScriptedStream::new(Vec::new());
        assert!(upload_directory(&mut stream, b"tree", &entries).is_err());
        assert_eq!(stream.output, []);
        assert_eq!(stream.read_lengths, []);
    }
}

#[test]
fn directory_download_rejects_escape_collisions_and_bad_records() {
    for wire in [
        b"D0755 0 ..\n".as_slice(),
        b"D0755 0 tree\nD0755 0 ..\n",
        b"D0755 0 tree\nC0644 0 ../outside\n",
        b"D0755 0 tree\nC0644 0 C:outside\n",
        b"D0755 0 tree\nC0644 0 same\n\0C0644 0 same\n",
        b"D0755 0 tree\nC0644 0 dir\n\0D0755 0 dir\n",
        b"D0755 0 tree\nD0755 0 dir\nE\nC0644 0 dir\n",
        b"D0755 1 tree\n",
        b"D0755 0 tree\nE extra\n",
        b"D0755 0 tree\nC0644 1 file\nx!",
        b"D0755 0 tree\nD0755 0 child\nE\n", // Missing root E.
    ] {
        assert!(download_directory(&mut ScriptedStream::new(wire.to_vec())).is_err());
    }
}

#[test]
fn directory_depth_and_total_record_limits_apply_in_both_directions() -> Result<(), Box<dyn Error>>
{
    // Root plus seven child directories: exactly eight D levels.
    let path = b"a/b/c/d/e/f/g/file";
    let entries = vec![ScpDirectoryEntry {
        path: path.to_vec(),
        data: vec![0, 255],
    }];
    let mut sender = ScriptedStream::new(vec![0; 19]);
    upload_directory(&mut sender, b"r", &entries)?;
    let result = download_directory(&mut ScriptedStream::new(sender.output))?;
    assert_eq!(result.entries, entries);
    let too_deep = vec![ScpDirectoryEntry {
        path: b"a/b/c/d/e/f/g/h/file".to_vec(),
        data: Vec::new(),
    }];
    assert!(upload_directory(&mut ScriptedStream::new(Vec::new()), b"r", &too_deep).is_err());
    let mut deep_wire = b"D0700 0 r\n".to_vec();
    for _ in 0..8 {
        deep_wire.extend_from_slice(b"D0700 0 d\n");
    }
    assert!(download_directory(&mut ScriptedStream::new(deep_wire)).is_err());

    // The root is a record too, leaving room for 63 files.
    let mut entries: Vec<_> = (0..63)
        .map(|i| ScpDirectoryEntry {
            path: format!("file{i:02}").into_bytes(),
            data: Vec::new(),
        })
        .collect();
    let mut sender = ScriptedStream::new(vec![0; 129]);
    upload_directory(&mut sender, b"r", &entries)?;
    assert_eq!(
        download_directory(&mut ScriptedStream::new(sender.output))?.entries,
        entries
    );
    entries.push(ScpDirectoryEntry {
        path: b"extra".to_vec(),
        data: Vec::new(),
    });
    assert!(upload_directory(&mut ScriptedStream::new(Vec::new()), b"r", &entries).is_err());
    // Empty directories must consume the count as well as files.
    let mut wire = b"D0700 0 r\n".to_vec();
    for i in 0..64 {
        wire.extend_from_slice(format!("D0700 0 d{i}\nE\n").as_bytes());
    }
    wire.extend_from_slice(b"E\n");
    assert!(download_directory(&mut ScriptedStream::new(wire)).is_err());
    Ok(())
}

#[test]
fn commands_quote_paths_and_reject_control_bytes() -> Result<(), Box<dyn Error>> {
    assert_eq!(upload_command("file.bin")?, "scp -t -- 'file.bin'");
    assert_eq!(download_command("-remote")?, "scp -f -- '-remote'");
    assert_eq!(upload_command("a'b.bin")?, "scp -t -- 'a'\\''b.bin'");
    assert!(matches!(upload_command(""), Err(ScpError::InvalidPath)));
    assert!(matches!(
        upload_command(&b"bad\0path"[..]),
        Err(ScpError::InvalidPath)
    ));
    assert!(matches!(
        download_command(&b"bad\rpath"[..]),
        Err(ScpError::InvalidPath)
    ));
    assert!(matches!(
        download_command(&b"bad\npath"[..]),
        Err(ScpError::InvalidPath)
    ));
    Ok(())
}

#[test]
fn an_oversized_file_header_is_rejected_before_body_allocation() {
    let header = format!("C0644 {} file.bin\n", MAX_SCP_FILE_SIZE + 1);
    let mut stream = ScriptedStream::new(header.into_bytes());

    let error = download(&mut stream).expect_err("oversized body must fail");

    assert!(matches!(error, ScpError::FileTooLarge));
    assert_eq!(stream.output, vec![0]);
}

#[test]
fn peer_warning_text_is_not_retained_in_error_formatting() {
    let warning = b"warning contains /secret/path and file bytes";
    let mut input = vec![1];
    input.extend_from_slice(warning);
    input.push(b'\n');
    let mut stream = ScriptedStream::new(input);

    let error = download(&mut stream).expect_err("peer warning must fail");

    assert!(matches!(error, ScpError::PeerError));
    assert!(!format!("{error}").contains("secret"));
    assert!(!format!("{error:?}").contains("secret"));
    assert!(!format!("{error}").contains("file bytes"));
    assert!(!format!("{error:?}").contains("file bytes"));
}

#[test]
fn malformed_time_and_basename_headers_are_rejected() {
    let mut invalid_time = ScriptedStream::new(b"T1 1000000 1 0\nC0644 0 file\n\0".to_vec());
    assert!(matches!(
        download(&mut invalid_time),
        Err(ScpError::InvalidTime)
    ));

    let mut invalid_name = ScriptedStream::new(b"C0644 0 ../escape\n\0".to_vec());
    assert!(matches!(
        download(&mut invalid_name),
        Err(ScpError::InvalidBasename)
    ));
}

#[test]
fn the_module_does_not_contain_process_or_socket_operations() {
    let source = include_str!("../src/scp.rs");
    assert!(!source.contains("std::process"));
    assert!(!source.contains("std::net"));
    assert!(!source.contains("TcpStream"));
    assert!(!source.contains("UnixStream"));
    assert!(!source.contains("Command"));
}
