#![allow(missing_docs)]

#[test]
fn rooted_disk_round_trip_and_escape() {
    use neotales_ssh::sftp::{RootedSftpServer, SftpClient, SftpOpenFlags};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret"), b"outside").unwrap();
    #[cfg(unix)]
    let link = std::os::unix::fs::symlink(outside.path(), root.path().join("escape"));
    #[cfg(windows)]
    let link = std::os::windows::fs::symlink_dir(outside.path(), root.path().join("escape"));
    #[cfg(not(any(unix, windows)))]
    let link: std::io::Result<()> = Err(std::io::ErrorKind::Unsupported.into());
    if let Err(error) = &link {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
            ),
            "symlink creation failed: {error}"
        );
        eprintln!("skipping symlink escape assertion: {error}");
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    for stream in [&client, &server] {
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
    }
    let mut server = RootedSftpServer::new(server, root.path()).unwrap();
    let requests = if link.is_ok() { 7 } else { 6 };
    let worker = std::thread::spawn(move || {
        for _ in 0..requests {
            server.serve_one().unwrap();
        }
    });
    let mut client = SftpClient::connect(client).unwrap();
    let handle = client
        .open(
            "one",
            SftpOpenFlags::READ | SftpOpenFlags::WRITE | SftpOpenFlags::CREAT,
        )
        .unwrap();
    client.write(&handle, 0, b"disk bytes").unwrap();
    assert_eq!(
        client.read(&handle, 0, 32).unwrap().as_slice(),
        b"disk bytes"
    );
    client.close(&handle).unwrap();
    assert!(client.open("../secret", SftpOpenFlags::READ).is_err());
    if link.is_ok() {
        assert!(client.open("escape/secret", SftpOpenFlags::READ).is_err());
    }
    worker.join().unwrap();
    assert_eq!(
        std::fs::read(root.path().join("one")).unwrap(),
        b"disk bytes"
    );
}

#[cfg(target_os = "linux")]
mod linux {

    use neotales_ssh::sftp::{RootedSftpServer, SftpClient, SftpOpenFlags, SftpReadResult};
    use std::os::unix::net::UnixStream;

    use neotales_ssh::scp::{self, RootedScpServer};
    use neotales_ssh::sftp::{self, MAX_SFTP_PACKET_SIZE, SftpError};
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::time::Duration;

    fn pipe() -> (UnixStream, UnixStream) {
        let (client, server) = UnixStream::pair().unwrap();
        for stream in [&client, &server] {
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
        }
        (client, server)
    }

    #[test]
    fn rooted_sftp_reads_and_writes_disk() {
        let root = tempfile::tempdir().unwrap();
        let (client, server) = pipe();
        let mut server = RootedSftpServer::new(server, root.path()).unwrap();
        let worker = std::thread::spawn(move || {
            for _ in 0..6 {
                server.serve_one().unwrap();
            }
        });
        let mut client = SftpClient::connect(client).unwrap();
        let handle = client
            .open(
                "one",
                SftpOpenFlags::READ | SftpOpenFlags::WRITE | SftpOpenFlags::CREAT,
            )
            .unwrap();
        client.write(&handle, 0, b"disk bytes").unwrap();
        assert_eq!(
            client.read(&handle, 0, 64).unwrap(),
            SftpReadResult::Data(b"disk bytes".to_vec())
        );
        client.close(&handle).unwrap();
        assert_eq!(
            client
                .open("missing", SftpOpenFlags::READ)
                .unwrap_err()
                .status_code(),
            Some(2)
        );
        worker.join().unwrap();
        assert_eq!(
            std::fs::read(root.path().join("one")).unwrap(),
            b"disk bytes"
        );
    }

    #[test]
    fn rooted_sftp_confines_paths_and_open_handles() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"outside").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("absent"), root.path().join("dangling"))
            .unwrap();
        std::fs::write(root.path().join("inside"), b"inside").unwrap();
        std::os::unix::fs::symlink("inside", root.path().join("link")).unwrap();
        let (client, server) = pipe();
        let mut server = RootedSftpServer::new(server, root.path().join(".")).unwrap();
        let worker = std::thread::spawn(move || {
            for _ in 0..13 {
                server.serve_one().unwrap();
            }
        });
        let mut client = SftpClient::connect(client).unwrap();
        for path in [
            b"../secret".as_slice(),
            b"inside/../inside",
            b"escape/secret",
            b"dangling",
            outside.path().join("secret").as_os_str().as_bytes(),
        ] {
            assert_eq!(
                client
                    .open(
                        path,
                        SftpOpenFlags::WRITE | SftpOpenFlags::CREAT | SftpOpenFlags::TRUNC
                    )
                    .unwrap_err()
                    .status_code(),
                Some(3)
            );
        }
        let absolute = root.path().canonicalize().unwrap().join("inside");
        let handle = client
            .open(absolute.as_os_str().as_bytes(), SftpOpenFlags::READ)
            .unwrap();
        assert_eq!(client.read(&handle, 0, 16).unwrap().as_slice(), b"inside");
        client.close(&handle).unwrap();
        let handle = client
            .open("link", SftpOpenFlags::READ | SftpOpenFlags::WRITE)
            .unwrap();
        std::fs::remove_file(root.path().join("link")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), root.path().join("link"))
            .unwrap();
        client.write(&handle, 0, b"pinned").unwrap();
        assert_eq!(client.read(&handle, 0, 16).unwrap().as_slice(), b"pinned");
        client.close(&handle).unwrap();
        worker.join().unwrap();
        assert_eq!(
            std::fs::read(outside.path().join("secret")).unwrap(),
            b"outside"
        );
        assert!(!outside.path().join("absent").exists());
    }

    #[test]
    fn rooted_sftp_bounds_untrusted_read_and_write_frames() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("one"), b"data").unwrap();
        let (client, server) = pipe();
        let mut server = RootedSftpServer::new(server, root.path()).unwrap();
        let worker = std::thread::spawn(move || {
            for _ in 0..3 {
                server.serve_one().unwrap();
            }
            assert!(matches!(server.serve_one(), Err(SftpError::FrameTooLarge)));
        });
        let mut client = SftpClient::connect(client).unwrap();
        let handle = client
            .open("one", SftpOpenFlags::READ | SftpOpenFlags::WRITE)
            .unwrap();
        let mut raw = client.into_inner();
        let mut request = neotales_ssh::Writer::new();
        request.write_byte(sftp::SSH_FXP_READ);
        request.write_uint32(99);
        request.write_string(handle.as_bytes()).unwrap();
        request.write_uint64(0);
        request.write_uint32(u32::MAX);
        sftp::write_packet(&mut raw, request.as_bytes()).unwrap();
        let response = sftp::read_packet(&mut raw).unwrap();
        assert_eq!(response[0], sftp::SSH_FXP_STATUS);
        assert_eq!(
            u32::from_be_bytes(response[5..9].try_into().unwrap()),
            sftp::SSH_FX_FAILURE
        );
        raw.write_all(
            &u32::try_from(MAX_SFTP_PACKET_SIZE + 1)
                .unwrap()
                .to_be_bytes(),
        )
        .unwrap();
        worker.join().unwrap();
        assert_eq!(std::fs::read(root.path().join("one")).unwrap(), b"data");
    }

    #[test]
    fn rooted_scp_upload_and_download_use_explicit_disk_root() {
        let root = tempfile::tempdir().unwrap();
        let data = vec![0x5a; 150_000];
        let (mut client, server) = pipe();
        let mut server = RootedScpServer::new(server, root.path()).unwrap();
        let worker = std::thread::spawn(move || server.receive_file("stored"));
        scp::upload(&mut client, "untrusted-name", &data, Some(1)).unwrap();
        worker.join().unwrap().unwrap();
        assert_eq!(std::fs::read(root.path().join("stored")).unwrap(), data);
        assert!(!root.path().join("untrusted-name").exists());
        let (mut client, server) = pipe();
        let mut server = RootedScpServer::new(server, root.path()).unwrap();
        let worker = std::thread::spawn(move || server.send_file("stored"));
        let downloaded = scp::download(&mut client).unwrap();
        worker.join().unwrap().unwrap();
        assert_eq!(downloaded.basename, b"stored");
        assert_eq!(downloaded.data, data);
    }

    #[test]
    fn rooted_scp_rejects_missing_files_and_escape_paths() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"outside").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
        for path in ["missing", "../secret", "escape/secret"] {
            let (mut client, server) = pipe();
            let mut server = RootedScpServer::new(server, root.path()).unwrap();
            let path = path.to_owned();
            let worker = std::thread::spawn(move || server.send_file(path));
            assert!(scp::download(&mut client).is_err());
            assert!(worker.join().unwrap().is_err());
        }
        for path in [
            b"../secret".as_slice(),
            b"escape/secret",
            outside.path().join("secret").as_os_str().as_bytes(),
        ] {
            let (mut client, server) = pipe();
            let mut server = RootedScpServer::new(server, root.path()).unwrap();
            let path = path.to_vec();
            let worker = std::thread::spawn(move || server.receive_file(path));
            assert!(scp::upload(&mut client, "name", b"overwrite", None).is_err());
            assert!(worker.join().unwrap().is_err());
        }
        assert_eq!(
            std::fs::read(outside.path().join("secret")).unwrap(),
            b"outside"
        );
    }
}
