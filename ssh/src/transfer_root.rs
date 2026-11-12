//! Shared, descriptor-relative filesystem boundary for explicit disk adapters.

use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::{Component, PathBuf};

#[cfg(target_os = "linux")]
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

/// Failure to construct an explicit rooted file-transfer adapter.
pub enum RootedTransferError {
    /// Secure rooted filesystem access is not implemented on this platform.
    /// No filesystem operation has been performed.
    UnsupportedPlatform,
    /// Opening the root on Linux failed.
    Io(io::Error),
}

impl std::fmt::Debug for RootedTransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedPlatform => "UnsupportedPlatform",
            Self::Io(_) => "Io",
        })
    }
}

impl std::fmt::Display for RootedTransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedPlatform => "rooted file transfers require Linux",
            Self::Io(_) => "opening the file-transfer root failed",
        })
    }
}

impl std::error::Error for RootedTransferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsupportedPlatform => None,
            Self::Io(error) => Some(error),
        }
    }
}

impl From<io::Error> for RootedTransferError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) enum TransferAccess {
    #[default]
    Read,
    Write,
    ReadWrite,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct TransferOpenOptions {
    pub(crate) access: TransferAccess,
    pub(crate) create: bool,
    pub(crate) exclusive: bool,
    pub(crate) append: bool,
}

pub(crate) struct TransferRoot {
    #[cfg(target_os = "linux")]
    path: PathBuf,
    #[cfg(target_os = "linux")]
    directory: File,
}

impl std::fmt::Debug for TransferRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransferRoot")
    }
}

impl TransferRoot {
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn new(_root: &Path) -> Result<Self, RootedTransferError> {
        Err(RootedTransferError::UnsupportedPlatform)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn open(&self, _path: &[u8], options: TransferOpenOptions) -> io::Result<File> {
        // Keep this branch filesystem-free even if internal construction changes.
        let _ = (
            options.access,
            options.create,
            options.exclusive,
            options.append,
        );
        Err(io::ErrorKind::Unsupported.into())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn new(root: &Path) -> Result<Self, RootedTransferError> {
        let path = root.canonicalize()?;
        let directory = openat2(
            rustix::fs::CWD,
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(io::Error::from)?;
        Ok(Self {
            path,
            directory: directory.into(),
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn open(&self, path: &[u8], options: TransferOpenOptions) -> io::Result<File> {
        let mut flags = match options.access {
            TransferAccess::ReadWrite => OFlags::RDWR,
            TransferAccess::Write => OFlags::WRONLY,
            TransferAccess::Read => OFlags::RDONLY,
        };
        if options.create {
            flags |= OFlags::CREATE;
        }
        if options.exclusive {
            flags |= OFlags::EXCL;
        }
        if options.append {
            flags |= OFlags::APPEND;
        }
        let path = Path::new(std::ffi::OsStr::from_bytes(path));
        if path.as_os_str().is_empty()
            || path.components().any(|c| matches!(c, Component::ParentDir))
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let relative = if path.is_absolute() {
            path.strip_prefix(&self.path)
                .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?
        } else {
            path
        };
        let mode = if flags.intersects(OFlags::CREATE) {
            Mode::RUSR | Mode::WUSR
        } else {
            Mode::empty()
        };
        // The kernel resolves every component beneath the pinned directory in one
        // operation. Canonicalize-then-open alone would permit symlink-swap races.
        // Absolute symlinks are conservatively rejected even if they point inside.
        let fd = openat2(
            &self.directory,
            relative,
            flags | OFlags::CLOEXEC | OFlags::NONBLOCK,
            mode,
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|error| match error {
            rustix::io::Errno::XDEV | rustix::io::Errno::LOOP => {
                io::Error::from(io::ErrorKind::PermissionDenied)
            }
            other => io::Error::from(other),
        })?;
        let file = File::from(fd);
        if !file.metadata()?.is_file() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(file)
    }
}
