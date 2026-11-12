use super::{
    MAX_SFTP_HANDLE_SIZE, MAX_SFTP_PACKET_SIZE, MAX_SFTP_PATH_SIZE, PacketBuilder, SSH_FX_EOF,
    SSH_FX_FAILURE, SSH_FX_NO_SUCH_FILE, SSH_FX_OK, SSH_FX_OP_UNSUPPORTED,
    SSH_FX_PERMISSION_DENIED, SSH_FXF_APPEND, SSH_FXF_CREAT, SSH_FXF_EXCL, SSH_FXF_READ,
    SSH_FXF_TRUNC, SSH_FXF_WRITE, SSH_FXP_CLOSE, SSH_FXP_DATA, SSH_FXP_HANDLE, SSH_FXP_INIT,
    SSH_FXP_OPEN, SSH_FXP_READ, SSH_FXP_VERSION, SSH_FXP_WRITE, SftpError, SftpServer,
    decode_attributes, read_packet, read_string, read_u32, read_u64, write_packet,
};
use crate::transfer_root::{
    RootedTransferError, TransferAccess, TransferOpenOptions, TransferRoot,
};
use neotales_ssh::Reader;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Explicit filesystem-backed SFTP v3 server over a caller-owned byte stream.
///
/// Relative paths are beneath the canonicalized caller-supplied root; absolute
/// paths must be beneath that same root. `..`, escaping symlinks, and special
/// files are rejected. Linux uses `openat2`; other platforms reject all links
/// and require the caller to prevent concurrent directory modifications.
/// Open handles pin files, not pathnames; dropping the server closes all handles.
/// Only OPEN, READ, WRITE and CLOSE are implemented. No home or host root is used.
#[derive(Debug)]
pub struct RootedSftpServer<T> {
    transport: T,
    root: TransferRoot,
    handles: HashMap<Vec<u8>, File>,
    next_handle: u64,
    initialized: bool,
}

impl<T: Read + Write> RootedSftpServer<T> {
    /// Canonicalizes and pins an existing root directory, without creating it.
    ///
    /// # Errors
    /// Returns [`RootedTransferError::Io`] if the root cannot be opened as a directory.
    pub fn new(transport: T, root: impl AsRef<Path>) -> Result<Self, RootedTransferError> {
        Ok(Self {
            transport,
            root: TransferRoot::new(root.as_ref())?,
            handles: HashMap::new(),
            next_handle: 0,
            initialized: false,
        })
    }

    /// Serves one bounded request. File errors become SFTP statuses.
    ///
    /// # Errors
    /// Returns protocol/framing or transport errors. Writes are not transactional;
    /// I/O failure may leave partial data. Each READ/WRITE is frame-cap bounded.
    pub fn serve_one(&mut self) -> Result<(), SftpError> {
        let request = read_packet(&mut self.transport)?;
        if request.first() == Some(&SSH_FXP_INIT) {
            if request.len() != 5 || self.initialized {
                return Err(SftpError::InvalidFrame);
            }
            self.initialized = true;
            return write_packet(&mut self.transport, &[SSH_FXP_VERSION, 0, 0, 0, 3]);
        }
        if !self.initialized {
            return Err(SftpError::NotInitialized);
        }
        let mut reader = Reader::new(request.get(1..).ok_or(SftpError::InvalidFrame)?);
        let id = read_u32(&mut reader)?;
        let result = self.request(request[0], id, &mut reader);
        let reply = match result {
            Ok(reply) => reply,
            Err(SftpError::Io(error)) => status(
                id,
                match error.kind() {
                    io::ErrorKind::NotFound => SSH_FX_NO_SUCH_FILE,
                    io::ErrorKind::PermissionDenied => SSH_FX_PERMISSION_DENIED,
                    _ => SSH_FX_FAILURE,
                },
            )?,
            Err(SftpError::Status(code)) => status(id, code)?,
            Err(error) => return Err(error),
        };
        write_packet(&mut self.transport, &reply)
    }

    fn request(&mut self, kind: u8, id: u32, r: &mut Reader<'_>) -> Result<Vec<u8>, SftpError> {
        match kind {
            SSH_FXP_OPEN => {
                let path = read_string(r, MAX_SFTP_PATH_SIZE)?;
                let flags = read_u32(r)?;
                let _attrs = decode_attributes(r)?;
                complete(r)?;
                if flags & !0x3f != 0
                    || flags & (SSH_FXF_READ | SSH_FXF_WRITE) == 0
                    || (flags & (SSH_FXF_CREAT | SSH_FXF_TRUNC | SSH_FXF_APPEND) != 0
                        && flags & SSH_FXF_WRITE == 0)
                    || (flags & SSH_FXF_EXCL != 0 && flags & SSH_FXF_CREAT == 0)
                {
                    return status(id, SSH_FX_FAILURE);
                }
                let options = TransferOpenOptions {
                    access: match flags & (SSH_FXF_READ | SSH_FXF_WRITE) {
                        SSH_FXF_READ => TransferAccess::Read,
                        SSH_FXF_WRITE => TransferAccess::Write,
                        _ => TransferAccess::ReadWrite,
                    },
                    create: flags & SSH_FXF_CREAT != 0,
                    exclusive: flags & SSH_FXF_EXCL != 0,
                    append: flags & SSH_FXF_APPEND != 0,
                };
                let next = self
                    .next_handle
                    .checked_add(1)
                    .ok_or(SftpError::Status(SSH_FX_FAILURE))?;
                let file = self.root.open(&path, options)?;
                if flags & SSH_FXF_TRUNC != 0 {
                    file.set_len(0)?;
                }
                let handle = self.next_handle.to_be_bytes().to_vec();
                self.next_handle = next;
                self.handles.insert(handle.clone(), file);
                let mut p = PacketBuilder::with_capacity(32);
                p.push_byte(SSH_FXP_HANDLE);
                p.push_uint32(id);
                p.push_string(&handle, MAX_SFTP_HANDLE_SIZE, SftpError::InvalidHandle)?;
                p.finish()
            }
            SSH_FXP_CLOSE => {
                let handle = read_string(r, MAX_SFTP_HANDLE_SIZE)?;
                complete(r)?;
                status(
                    id,
                    if self.handles.remove(&handle).is_some() {
                        SSH_FX_OK
                    } else {
                        SSH_FX_FAILURE
                    },
                )
            }
            SSH_FXP_READ | SSH_FXP_WRITE => {
                let handle = read_string(r, MAX_SFTP_HANDLE_SIZE)?;
                let offset = read_u64(r)?;
                // Parse and bound the whole request before touching the file.
                let (length, data) = if kind == SSH_FXP_READ {
                    (read_u32(r)? as usize, Vec::new())
                } else {
                    (0, read_string(r, MAX_SFTP_PACKET_SIZE)?)
                };
                complete(r)?;
                if length > MAX_SFTP_PACKET_SIZE - 9 {
                    return status(id, SSH_FX_FAILURE);
                }
                let file = self
                    .handles
                    .get_mut(&handle)
                    .ok_or(SftpError::Status(SSH_FX_FAILURE))?;
                file.seek(SeekFrom::Start(offset))?;
                if kind == SSH_FXP_WRITE {
                    file.write_all(&data)?;
                    status(id, SSH_FX_OK)
                } else {
                    let mut data = vec![0; length];
                    let count = file.read(&mut data)?;
                    if count == 0 && length != 0 {
                        return status(id, SSH_FX_EOF);
                    }
                    let mut p = PacketBuilder::with_capacity(count + 9);
                    p.push_byte(SSH_FXP_DATA);
                    p.push_uint32(id);
                    p.push_string(
                        &data[..count],
                        MAX_SFTP_PACKET_SIZE - 9,
                        SftpError::FrameTooLarge,
                    )?;
                    p.finish()
                }
            }
            _ => status(id, SSH_FX_OP_UNSUPPORTED),
        }
    }
}

fn complete(reader: &Reader<'_>) -> Result<(), SftpError> {
    if reader.is_empty() {
        Ok(())
    } else {
        Err(SftpError::InvalidFrame)
    }
}

fn status(id: u32, code: u32) -> Result<Vec<u8>, SftpError> {
    SftpServer::<io::Cursor<Vec<u8>>>::status_reply(id, code)
}
