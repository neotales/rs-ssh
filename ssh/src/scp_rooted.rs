use super::{
    DEFAULT_SCP_MODE, SCP_ACK, ScpError, encode_file_line, parse_file_header, parse_time_line,
    read_ack, read_header_line, upload_basename, write_ack,
};
use crate::transfer_root::{
    RootedTransferError, TransferAccess, TransferOpenOptions, TransferRoot,
};
use std::io::{Read, Write};
use std::path::Path;

/// Explicit filesystem-backed, single-file SCP source/sink.
///
/// The caller supplies both the root and the exact file path for each transfer;
/// peer basenames never select a destination. The canonicalized root is pinned.
/// `..`, absolute paths outside it, escaping symlinks, and special files are
/// rejected using Linux `openat2`. Other platforms reject all links and require
/// the caller to prevent concurrent directory modifications. No process,
/// implicit host root, or home directory is used. Directory APIs stay in-memory.
#[derive(Debug)]
pub struct RootedScpServer<T> {
    transport: T,
    root: TransferRoot,
}

impl<T: Read + Write> RootedScpServer<T> {
    /// Canonicalizes and pins the caller's existing root directory.
    ///
    /// # Errors
    /// Returns [`RootedTransferError::Io`] if the root cannot be opened as a directory.
    pub fn new(transport: T, root: impl AsRef<Path>) -> Result<Self, RootedTransferError> {
        Ok(Self {
            transport,
            root: TransferRoot::new(root.as_ref())?,
        })
    }

    /// Receives one upload into an explicit root-relative or in-root absolute path.
    ///
    /// Replaces existing contents. Mode/time metadata is validated, not applied.
    /// Success is acknowledged only after the body is written and flushed.
    ///
    /// # Errors
    /// Returns a path, protocol or I/O error. Failure can leave a partial file;
    /// the caller should close the stream after failure (no protocol recovery).
    pub fn receive_file(&mut self, path: impl AsRef<[u8]>) -> Result<(), ScpError> {
        let result = self.receive(path.as_ref());
        self.report_failure(result)
    }

    /// Sends one file from an explicit root-relative or in-root absolute path.
    ///
    /// Uses the default SCP mode and no timestamps. Bodies retain the existing
    /// SCP size limit; individual disk reads/writes are below the SFTP frame cap.
    ///
    /// # Errors
    /// Returns path, protocol or I/O errors, including missing files. Concurrent
    /// file mutation may produce a partial or inconsistent transfer; close the
    /// stream after failure. This is not a filesystem snapshot.
    pub fn send_file(&mut self, path: impl AsRef<[u8]>) -> Result<(), ScpError> {
        let result = self.send(path.as_ref());
        self.report_failure(result)
    }

    fn report_failure(&mut self, result: Result<(), ScpError>) -> Result<(), ScpError> {
        if result.is_err() {
            // Never echo a path or host error. Preserve the original error even
            // when the peer has already closed its side of the stream.
            let _ = self.transport.write_all(b"\x02file transfer failed\n");
            let _ = self.transport.flush();
        }
        result
    }

    fn receive(&mut self, path: &[u8]) -> Result<(), ScpError> {
        let mut file = self.root.open(
            path,
            TransferOpenOptions {
                access: TransferAccess::Write,
                create: true,
                ..TransferOpenOptions::default()
            },
        )?;
        write_ack(&mut self.transport)?;
        let first = read_header_line(&mut self.transport)?;
        let line = if first.first() == Some(&b'T') {
            parse_time_line(&first)?;
            write_ack(&mut self.transport)?;
            read_header_line(&mut self.transport)?
        } else {
            first
        };
        let header = parse_file_header(&line)?;
        file.set_len(0)?;
        write_ack(&mut self.transport)?;
        copy_exact(&mut self.transport, &mut file, header.size)?;
        let mut trailer = [0];
        self.transport.read_exact(&mut trailer)?;
        if trailer[0] != SCP_ACK {
            return Err(ScpError::InvalidTrailer);
        }
        file.flush()?;
        write_ack(&mut self.transport)
    }

    fn send(&mut self, path: &[u8]) -> Result<(), ScpError> {
        let basename = upload_basename(path)?;
        let mut file = self.root.open(
            path,
            TransferOpenOptions {
                access: TransferAccess::Read,
                ..TransferOpenOptions::default()
            },
        )?;
        let size = usize::try_from(file.metadata()?.len()).map_err(|_| ScpError::FileTooLarge)?;
        let line = encode_file_line(basename, size, DEFAULT_SCP_MODE)?;
        read_ack(&mut self.transport)?;
        self.transport.write_all(&line)?;
        read_ack(&mut self.transport)?;
        copy_exact(&mut file, &mut self.transport, size)?;
        self.transport.write_all(&[SCP_ACK])?;
        self.transport.flush()?;
        read_ack(&mut self.transport)
    }
}

fn copy_exact(
    source: &mut impl Read,
    target: &mut impl Write,
    mut remaining: usize,
) -> Result<(), ScpError> {
    let mut buffer = vec![0; 64 * 1024];
    while remaining != 0 {
        let length = remaining
            .min(buffer.len())
            .min(crate::sftp::MAX_SFTP_PACKET_SIZE);
        source.read_exact(&mut buffer[..length])?;
        target.write_all(&buffer[..length])?;
        remaining -= length;
    }
    Ok(())
}
