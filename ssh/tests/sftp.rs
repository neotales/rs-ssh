// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

use neotales_ssh::sftp;

use std::error::Error;
use std::io::{self, Cursor, Read, Write};

use neotales_ssh::Writer;
use sftp::{
    MAX_SFTP_PACKET_SIZE, SFTP_VERSION, SSH_FX_EOF, SSH_FX_FAILURE, SSH_FXP_ATTRS, SSH_FXP_CLOSE,
    SSH_FXP_DATA, SSH_FXP_FSTAT, SSH_FXP_HANDLE, SSH_FXP_INIT, SSH_FXP_LSTAT, SSH_FXP_MKDIR,
    SSH_FXP_NAME, SSH_FXP_OPEN, SSH_FXP_OPENDIR, SSH_FXP_READ, SSH_FXP_READDIR, SSH_FXP_READLINK,
    SSH_FXP_REALPATH, SSH_FXP_REMOVE, SSH_FXP_RENAME, SSH_FXP_RMDIR, SSH_FXP_SETSTAT, SSH_FXP_STAT,
    SSH_FXP_STATUS, SSH_FXP_SYMLINK, SSH_FXP_VERSION, SSH_FXP_WRITE, SftpAttributes, SftpClient,
    SftpError, SftpOpenFlags, SftpReadResult,
};

#[cfg(unix)]
#[test]
fn in_process_memory_server_round_trips_one_file() -> Result<(), Box<dyn Error>> {
    use std::os::unix::net::UnixStream;
    let (client_stream, server_stream) = UnixStream::pair()?;
    let server = std::thread::spawn(move || {
        let mut server = sftp::SftpServer::new(server_stream, std::collections::HashMap::new());
        for _ in 0..8 {
            server.serve_one().unwrap();
        }
    });
    let mut client = SftpClient::connect(client_stream)?;
    let handle = client.open(
        b"one",
        SftpOpenFlags::WRITE | SftpOpenFlags::READ | SftpOpenFlags::CREAT,
    )?;
    client.write(&handle, 0, b"bytes")?;
    client.close(&handle)?;
    let handle = client.open(b"one", SftpOpenFlags::READ)?;
    assert_eq!(
        client.read(&handle, 0, 16)?,
        SftpReadResult::Data(b"bytes".to_vec())
    );
    client.close(&handle)?;
    assert!(client.open(b"missing", SftpOpenFlags::READ).is_err());
    drop(client);
    server.join().map_err(|_| "server thread panicked")?;
    Ok(())
}

struct ScriptedStream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    read_lengths: Vec<usize>,
}

#[test]
fn data_longer_than_the_requested_read_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut responses = version_response()?;
    responses.extend(frame(&handle_response(0, b"h")?)?);
    responses.extend(frame(&data_response(1, b"too long")?)?);
    let mut client = SftpClient::new(ScriptedStream::new(responses));
    client.initialize()?;
    let handle = client.open(b"file", SftpOpenFlags::READ)?;
    assert!(matches!(
        client.read(&handle, 0, 1),
        Err(SftpError::InvalidFrame)
    ));
    Ok(())
}

#[test]
fn openssh_extensions_require_advertisement_versions_and_use_protocol_field_order()
-> Result<(), Box<dyn Error>> {
    let mut version = Writer::new();
    version.write_byte(SSH_FXP_VERSION);
    version.write_uint32(3);
    for (name, revision) in [
        ("posix-rename@openssh.com", "1"),
        ("hardlink@openssh.com", "1"),
        ("fsync@openssh.com", "1"),
        ("statvfs@openssh.com", "2"),
        ("limits@openssh.com", "1"),
    ] {
        version.write_string(name)?;
        version.write_string(revision)?;
    }
    let mut responses = frame(version.as_bytes())?;
    for id in 0..3 {
        responses.extend(frame(&status_response(id, 0, b"")?)?);
    }
    for (id, count) in [(3, 11), (4, 4)] {
        let mut reply = Writer::new();
        reply.write_byte(sftp::SSH_FXP_EXTENDED_REPLY);
        reply.write_uint32(id);
        for value in 1..=count {
            reply.write_uint64(value);
        }
        responses.extend(frame(reply.as_bytes())?);
    }
    for id in 5..7 {
        responses.extend(frame(&status_response(id, 0, b"")?)?);
    }
    let mut client = SftpClient::new(ScriptedStream::new(responses));
    client.initialize()?;
    client.posix_rename(b"old", b"new")?;
    client.hardlink(b"old", b"new")?;
    client.fsync(b"handle")?;
    let stats = client.statvfs(b"path")?;
    assert_eq!(stats.block_size, 1);
    assert_eq!(stats.files, 6);
    assert_eq!(stats.name_max, 11);
    let limits = client.limits()?;
    assert_eq!(limits.packet_length, 1);
    assert_eq!(limits.open_handles, 4);
    client.set_symlink_order(sftp::SymlinkOrder::OpenSsh);
    client.symlink(b"link", b"target")?;
    client.set_symlink_order(sftp::SymlinkOrder::Draft);
    client.symlink(b"link", b"target")?;
    let output = client.into_inner().output;
    let frames = all_frames(&output)?;
    for (index, name) in [
        (1, "posix-rename@openssh.com"),
        (2, "hardlink@openssh.com"),
        (3, "fsync@openssh.com"),
        (4, "statvfs@openssh.com"),
        (5, "limits@openssh.com"),
    ] {
        assert_eq!(frames[index][0], 200);
        let mut reader = neotales_ssh::Reader::new(&frames[index][5..]);
        assert_eq!(reader.read_string()?, name.as_bytes());
    }
    assert_eq!(
        parse_strings(&frames[6], 2)?,
        [b"target".to_vec(), b"link".to_vec()]
    );
    assert_eq!(
        parse_strings(&frames[7], 2)?,
        [b"link".to_vec(), b"target".to_vec()]
    );

    let mut client = SftpClient::new(ScriptedStream::new(version_response()?));
    client.initialize()?;
    let before = client.transport().output.len();
    assert!(matches!(
        client.posix_rename(b"old", b"new"),
        Err(SftpError::ExtensionUnavailable)
    ));
    assert!(matches!(
        client.hardlink(b"old", b"new"),
        Err(SftpError::ExtensionUnavailable)
    ));
    assert!(matches!(
        client.fsync(b"h"),
        Err(SftpError::ExtensionUnavailable)
    ));
    assert!(matches!(
        client.statvfs(b"p"),
        Err(SftpError::ExtensionUnavailable)
    ));
    assert!(matches!(
        client.limits(),
        Err(SftpError::ExtensionUnavailable)
    ));
    assert_eq!(client.transport().output.len(), before);
    Ok(())
}

#[test]
fn pipelined_stats_are_bounded_and_responses_are_matched_by_id() -> Result<(), Box<dyn Error>> {
    let mut responses = version_response()?;
    for (id, size) in [(1, 11), (0, 22)] {
        let mut reply = Writer::new();
        reply.write_byte(SSH_FXP_ATTRS);
        reply.write_uint32(id);
        reply.write_uint32(sftp::SSH_FILEXFER_ATTR_SIZE);
        reply.write_uint64(size);
        responses.extend(frame(reply.as_bytes())?);
    }
    let mut client = SftpClient::new(ScriptedStream::new(responses));
    client.initialize()?;
    let first = client.begin_stat(b"first")?;
    let second = client.begin_stat(b"second")?;
    assert_eq!(client.outstanding_requests(), 2);
    assert!(matches!(
        client.stat(b"mixing sync and async"),
        Err(SftpError::RequestInFlight)
    ));
    assert_eq!(client.finish_stat(first)?.size, Some(22));
    assert_eq!(client.finish_stat(second)?.size, Some(11));
    assert_eq!(client.outstanding_requests(), 0);
    for _ in 0..sftp::MAX_SFTP_OUTSTANDING {
        client.begin_stat(b"bounded")?;
    }
    let before = client.transport().output.len();
    assert!(matches!(
        client.begin_stat(b"over cap"),
        Err(SftpError::TooManyRequests)
    ));
    assert_eq!(client.transport().output.len(), before);

    let mut responses = version_response()?;
    responses.extend(frame(&attributes_response(100))?);
    let mut client = SftpClient::new(ScriptedStream::new(responses));
    client.initialize()?;
    let id = client.begin_stat(b"path")?;
    assert!(matches!(
        client.finish_stat(id),
        Err(SftpError::ResponseIdMismatch { actual: 100, .. })
    ));
    assert!(client.begin_stat(b"after bad id").is_err());
    assert_eq!(client.outstanding_requests(), 0);
    Ok(())
}

#[test]
fn empty_extension_pairs_and_tiny_directory_entries_have_item_budgets() -> Result<(), Box<dyn Error>>
{
    let mut version = Writer::new();
    version.write_byte(SSH_FXP_VERSION);
    version.write_uint32(3);
    for _ in 0..=sftp::MAX_SFTP_EXTENSIONS {
        version.write_string(b"")?;
        version.write_string(b"")?;
    }
    let mut client = SftpClient::new(ScriptedStream::new(frame(version.as_bytes())?));
    assert!(matches!(client.initialize(), Err(SftpError::InvalidFrame)));

    let mut attrs = Writer::new();
    attrs.write_uint32(sftp::SSH_FILEXFER_ATTR_EXTENDED);
    attrs.write_uint32(u32::try_from(sftp::MAX_SFTP_EXTENDED_ATTRIBUTES + 1)?);
    for _ in 0..=sftp::MAX_SFTP_EXTENDED_ATTRIBUTES {
        attrs.write_string(b"")?;
        attrs.write_string(b"")?;
    }
    assert!(matches!(
        SftpAttributes::decode(attrs.as_bytes()),
        Err(SftpError::InvalidAttributes)
    ));

    for (entries, pairs) in [(sftp::MAX_SFTP_DIRECTORY_ENTRIES + 1, 0), (17, 256)] {
        let mut names = Writer::new();
        names.write_byte(SSH_FXP_NAME);
        names.write_uint32(1);
        names.write_uint32(u32::try_from(entries)?);
        for _ in 0..entries {
            names.write_string(b"x")?;
            names.write_string(b"")?;
            names.write_uint32(if pairs == 0 {
                0
            } else {
                sftp::SSH_FILEXFER_ATTR_EXTENDED
            });
            if pairs > 0 {
                names.write_uint32(pairs);
                for _ in 0..pairs {
                    names.write_string(b"")?;
                    names.write_string(b"")?;
                }
            }
        }
        let mut responses = version_response()?;
        responses.extend(frame(&handle_response(0, b"h")?)?);
        responses.extend(frame(names.as_bytes())?);
        let mut client = SftpClient::new(ScriptedStream::new(responses));
        client.initialize()?;
        let handle = client.opendir(b"dir")?;
        assert!(client.readdir(&handle).is_err());
    }
    Ok(())
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
fn init_uses_version_three_and_ignores_extension_pairs() -> Result<(), Box<dyn Error>> {
    let mut response = Writer::new();
    response.write_byte(SSH_FXP_VERSION);
    response.write_uint32(SFTP_VERSION);
    response.write_string(b"future@example.test")?;
    response.write_string(b"opaque-value")?;
    let stream = ScriptedStream::new(frame(&response.into_bytes())?);
    let mut client = SftpClient::new(stream);

    client.initialize()?;

    assert!(client.initialized());
    assert_eq!(client.version(), 3);
    let transport = client.into_inner();
    assert_eq!(next_frame(&transport.output)?, [SSH_FXP_INIT, 0, 0, 0, 3]);
    Ok(())
}

#[test]
fn write_read_round_trip_and_a_later_eof_are_reported_as_data_and_eof() -> Result<(), Box<dyn Error>>
{
    let payload = b"round-trip\0bytes";
    let mut responses = version_response()?;
    responses.extend(frame(&handle_response(0, b"h")?)?);
    responses.extend(frame(&status_response(1, 0, b"ok")?)?);
    responses.extend(frame(&data_response(2, payload)?)?);
    responses.extend(frame(&status_response(3, SSH_FX_EOF, b"end")?)?);
    let mut client = SftpClient::new(ScriptedStream::new(responses));
    client.initialize()?;
    let handle = client.open(b"file", SftpOpenFlags::WRITE | SftpOpenFlags::READ)?;

    client.write(&handle, 7, payload)?;
    assert_eq!(
        client.read(&handle, 7, payload.len() + 5)?,
        SftpReadResult::Data(payload.to_vec())
    );
    assert_eq!(
        client.read(&handle, 7 + payload.len() as u64, 4)?,
        SftpReadResult::Eof
    );

    let transport = client.into_inner();
    let frames = all_frames(&transport.output)?;
    assert_eq!(frames[1][0], SSH_FXP_OPEN);
    assert_eq!(u32::from_be_bytes(frames[1][1..5].try_into()?), 0);
    assert_eq!(frames[2][0], SSH_FXP_WRITE);
    assert_eq!(u32::from_be_bytes(frames[2][1..5].try_into()?), 1);
    assert_eq!(frames[3][0], SSH_FXP_READ);
    assert_eq!(u32::from_be_bytes(frames[3][1..5].try_into()?), 2);
    assert_eq!(frames[4][0], SSH_FXP_READ);
    assert_eq!(u32::from_be_bytes(frames[4][1..5].try_into()?), 3);
    Ok(())
}

#[test]
fn oversized_inbound_length_is_rejected_before_body_allocation() -> Result<(), Box<dyn Error>> {
    let length = u32::try_from(MAX_SFTP_PACKET_SIZE + 1)?;
    let stream = ScriptedStream::new(length.to_be_bytes().to_vec());
    let mut client = SftpClient::new(stream);
    let error = client.initialize().expect_err("oversized frame must fail");

    assert!(matches!(error, SftpError::FrameTooLarge));
    let transport = client.into_inner();
    assert_eq!(transport.input.position(), 4);
    assert!(transport.read_lengths.iter().all(|length| *length <= 4));
    assert!(transport.output.starts_with(&[0, 0, 0, 5, SSH_FXP_INIT]));
    Ok(())
}

#[test]
fn zero_length_and_oversized_outbound_frames_are_rejected() {
    assert!(matches!(
        sftp::encode_packet(&[]),
        Err(SftpError::ZeroLength)
    ));
    let oversized = vec![0_u8; MAX_SFTP_PACKET_SIZE + 1];
    assert!(matches!(
        sftp::encode_packet(&oversized),
        Err(SftpError::FrameTooLarge)
    ));
}

#[test]
fn sftp_module_has_no_process_socket_or_fsetstat_api() {
    let source = include_str!("../src/sftp.rs");
    assert!(!source.contains("std::net"));
    assert!(!source.contains("std::process"));
    assert!(!source.contains("TcpStream"));
    assert!(!source.contains("UnixStream"));
    assert!(!source.contains("Command"));
    assert!(!source.contains("SSH_FXP_FSETSTAT"));
}

#[test]
fn attributes_decode_known_and_extended_pairs_but_reject_unknown_bits() -> Result<(), Box<dyn Error>>
{
    let mut encoded = Writer::new();
    encoded.write_uint32(
        sftp::SSH_FILEXFER_ATTR_SIZE
            | sftp::SSH_FILEXFER_ATTR_UIDGID
            | sftp::SSH_FILEXFER_ATTR_PERMISSIONS
            | sftp::SSH_FILEXFER_ATTR_ACMODTIME
            | sftp::SSH_FILEXFER_ATTR_EXTENDED,
    );
    encoded.write_uint64(42);
    encoded.write_uint32(1000);
    encoded.write_uint32(1001);
    encoded.write_uint32(0x81a4);
    encoded.write_uint32(10);
    encoded.write_uint32(20);
    encoded.write_uint32(1);
    encoded.write_string(b"x@example.test")?;
    encoded.write_string(b"opaque")?;
    let attributes = SftpAttributes::decode(&encoded.into_bytes())?;

    assert_eq!(attributes.size, Some(42));
    assert_eq!(attributes.uid, Some(1000));
    assert_eq!(attributes.gid, Some(1001));
    assert_eq!(attributes.permissions, Some(0x81a4));
    assert_eq!(attributes.access_time, Some(10));
    assert_eq!(attributes.modify_time, Some(20));
    assert_eq!(attributes.extended.len(), 1);
    assert_eq!(attributes.extended[0].type_name(), b"x@example.test");
    assert_eq!(attributes.extended[0].data(), b"opaque");

    let mut unknown = Writer::new();
    unknown.write_uint32(0x10);
    assert!(matches!(
        SftpAttributes::decode(&unknown.into_bytes()),
        Err(SftpError::InvalidAttributes)
    ));
    Ok(())
}

#[test]
fn status_errors_redact_server_message_and_report_numeric_code() -> Result<(), Box<dyn Error>> {
    let secret = b"server-message-that-must-not-leak";
    let mut response = version_response()?;
    response.extend(frame(&status_response(0, SSH_FX_FAILURE, secret)?)?);
    let mut client = SftpClient::new(ScriptedStream::new(response));
    client.initialize()?;

    let error = client
        .close(b"h")
        .expect_err("status must be returned as an error");
    assert!(matches!(error, SftpError::Status(SSH_FX_FAILURE)));
    assert!(!format!("{error}").contains(std::str::from_utf8(secret)?));
    assert!(!format!("{error:?}").contains(std::str::from_utf8(secret)?));
    Ok(())
}

#[test]
fn all_standard_operations_use_the_v3_packet_types_and_request_ids() -> Result<(), Box<dyn Error>> {
    let mut responses = version_response()?;
    responses.extend(frame(&handle_response(0, b"file-handle")?)?);
    responses.extend(frame(&status_response(1, 0, b"")?)?);
    responses.extend(frame(&attributes_response(2))?);
    responses.extend(frame(&attributes_response(3))?);
    responses.extend(frame(&status_response(4, 0, b"")?)?);
    responses.extend(frame(&handle_response(5, b"dir-handle")?)?);
    responses.extend(frame(&name_response(6, b"entry", b"entry")?)?);
    responses.extend(frame(&status_response(7, 0, b"")?)?);
    responses.extend(frame(&status_response(8, 0, b"")?)?);
    responses.extend(frame(&status_response(9, 0, b"")?)?);
    responses.extend(frame(&name_response(10, b"/resolved", b"/resolved")?)?);
    responses.extend(frame(&attributes_response(11))?);
    responses.extend(frame(&status_response(12, 0, b"")?)?);
    responses.extend(frame(&name_response(13, b"target", b"target")?)?);
    responses.extend(frame(&status_response(14, 0, b"")?)?);
    let mut client = SftpClient::new(ScriptedStream::new(responses));
    client.initialize()?;

    let file = client.open(b"file", SftpOpenFlags::READ | SftpOpenFlags::WRITE)?;
    client.close(&file)?;
    assert_eq!(client.lstat(b"file")?.size, None);
    assert_eq!(client.fstat(&file)?.size, None);
    client.setstat(b"file", SftpAttributes::new())?;
    let directory = client.opendir(b"dir")?;
    assert_eq!(client.readdir(&directory)?[0].name(), b"entry");
    client.remove(b"file")?;
    client.mkdir(b"dir", None)?;
    client.rmdir(b"dir")?;
    assert_eq!(client.realpath(b"file")?, b"/resolved");
    assert_eq!(client.stat(b"file")?.size, None);
    client.rename(b"old", b"new")?;
    assert_eq!(client.readlink(b"link")?, b"target");
    client.symlink(b"link", b"target")?;

    let transport = client.into_inner();
    let frames = all_frames(&transport.output)?;
    let operation_types: Vec<u8> = frames[1..].iter().map(|frame| frame[0]).collect();
    assert_eq!(
        operation_types,
        vec![
            SSH_FXP_OPEN,
            SSH_FXP_CLOSE,
            SSH_FXP_LSTAT,
            SSH_FXP_FSTAT,
            SSH_FXP_SETSTAT,
            SSH_FXP_OPENDIR,
            SSH_FXP_READDIR,
            SSH_FXP_REMOVE,
            SSH_FXP_MKDIR,
            SSH_FXP_RMDIR,
            SSH_FXP_REALPATH,
            SSH_FXP_STAT,
            SSH_FXP_RENAME,
            SSH_FXP_READLINK,
            SSH_FXP_SYMLINK,
        ]
    );
    Ok(())
}

/// "The draft" is draft-ietf-secsh-filexfer-02, the version `src/sftp.rs`
/// implements, and the field order it fixes is:
///
/// ```text
///   uint32     id
///   string     oldpath
///   string     newpath
/// ```
///
/// for `SSH_FXP_RENAME`, and
///
/// ```text
///   uint32     id
///   string     linkpath
///   string     targetpath
/// ```
///
/// for `SSH_FXP_SYMLINK`. Note that SYMLINK is link-then-target in draft-02; that
/// is the order this asserts, and it is the order that later versions reversed.
///
/// PROVENANCE: **generated by this crate.** The two expected values are the
/// strings this crate wrote, read back off its own output. What the test checks is
/// the order they were written in, against the draft quoted above; the bytes are
/// not the draft's, and the draft publishes no examples for either message.
#[test]
fn symlink_and_rename_use_the_draft_field_order() -> Result<(), Box<dyn Error>> {
    let mut responses = version_response()?;
    responses.extend(frame(&status_response(0, 0, b"")?)?);
    responses.extend(frame(&status_response(1, 0, b"")?)?);
    let mut client = SftpClient::new(ScriptedStream::new(responses));
    client.initialize()?;

    client.symlink(b"link", b"target")?;
    client.rename(b"old", b"new")?;
    let transport = client.into_inner();
    let frames = all_frames(&transport.output)?;
    let symlink = parse_strings(&frames[1], 2)?;
    assert_eq!(symlink, [b"link".to_vec(), b"target".to_vec()]);
    let rename = parse_strings(&frames[2], 2)?;
    assert_eq!(rename, [b"old".to_vec(), b"new".to_vec()]);
    Ok(())
}

#[test]
fn response_id_mismatch_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut response = version_response()?;
    response.extend(frame(&handle_response(99, b"h")?)?);
    let mut client = SftpClient::new(ScriptedStream::new(response));
    client.initialize()?;
    assert!(matches!(
        client.open(b"file", SftpOpenFlags::READ),
        Err(SftpError::ResponseIdMismatch { .. })
    ));
    Ok(())
}

fn version_response() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_FXP_VERSION);
    writer.write_uint32(SFTP_VERSION);
    frame(&writer.into_bytes())
}

fn frame(packet: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let length = u32::try_from(packet.len())?;
    let mut encoded = length.to_be_bytes().to_vec();
    encoded.extend_from_slice(packet);
    Ok(encoded)
}

fn next_frame(encoded: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if encoded.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "missing frame").into());
    }
    let length = u32::from_be_bytes(encoded[0..4].try_into()?);
    let end = 4_usize
        .checked_add(usize::try_from(length)?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "frame overflow"))?;
    encoded
        .get(4..end)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated frame").into())
}

fn all_frames(encoded: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < encoded.len() {
        let frame = next_frame(encoded.get(offset..).ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "missing frame suffix")
        })?)?;
        let frame_len = frame.len();
        offset = offset
            .checked_add(4 + frame_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "frame overflow"))?;
        result.push(frame);
    }
    Ok(result)
}

fn handle_response(id: u32, handle: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_FXP_HANDLE);
    writer.write_uint32(id);
    writer.write_string(handle)?;
    Ok(writer.into_bytes())
}

fn status_response(id: u32, code: u32, message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_FXP_STATUS);
    writer.write_uint32(id);
    writer.write_uint32(code);
    writer.write_string(message)?;
    writer.write_string(b"en")?;
    Ok(writer.into_bytes())
}

fn attributes_response(id: u32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_FXP_ATTRS);
    writer.write_uint32(id);
    writer.write_uint32(0);
    writer.into_bytes()
}

fn name_response(id: u32, name: &[u8], long_name: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_FXP_NAME);
    writer.write_uint32(id);
    writer.write_uint32(1);
    writer.write_string(name)?;
    writer.write_string(long_name)?;
    writer.write_uint32(0);
    Ok(writer.into_bytes())
}

fn data_response(id: u32, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_FXP_DATA);
    writer.write_uint32(id);
    writer.write_string(data)?;
    Ok(writer.into_bytes())
}

fn parse_strings(packet: &[u8], count: usize) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut reader = neotales_ssh::Reader::new(packet.get(5..).ok_or("missing packet body")?);
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(reader.read_string_bytes()?);
    }
    Ok(values)
}
