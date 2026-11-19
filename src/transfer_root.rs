//! Shared, descriptor-relative filesystem boundary for explicit disk adapters.

use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::{Component, PathBuf};

#[cfg(target_os = "linux")]
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

/// Failure to construct an explicit rooted file-transfer adapter.
pub enum RootedTransferError {
    /// Secure rooted filesystem access is not implemented on this platform.
    /// No filesystem operation has been performed.
    UnsupportedPlatform,
    /// Opening the root failed.
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
            Self::UnsupportedPlatform => "rooted file transfers are unsupported on this platform",
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
    pub(crate) fn new(root: &Path) -> Result<Self, RootedTransferError> {
        let path = root.canonicalize()?;
        if !path.is_dir() {
            return Err(io::Error::from(io::ErrorKind::NotADirectory).into());
        }
        Ok(Self { path })
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn open(&self, path: &[u8], options: TransferOpenOptions) -> io::Result<File> {
        let path =
            std::str::from_utf8(path).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let path = Path::new(path);
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
        // Reject all links, including Windows junctions and other reparse points.
        // This validation is not atomic with open; callers must prevent concurrent
        // modification of the root's directories on platforms without openat2.
        let mut current = self.path.clone();
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            if !matches!(component, Component::Normal(_) | Component::CurDir) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            current.push(component.as_os_str());
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                        return Err(io::ErrorKind::PermissionDenied.into());
                    }
                    if !current.canonicalize()?.starts_with(&self.path) {
                        return Err(io::ErrorKind::PermissionDenied.into());
                    }
                }
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        && components.peek().is_none()
                        && options.create => {}
                Err(error) => return Err(error),
            }
        }
        let mut open = std::fs::OpenOptions::new();
        open.read(matches!(
            options.access,
            TransferAccess::Read | TransferAccess::ReadWrite
        ))
        .write(matches!(
            options.access,
            TransferAccess::Write | TransferAccess::ReadWrite
        ))
        .append(options.append)
        .create(options.create)
        .create_new(options.create && options.exclusive);
        let file = open.open(current)?;
        if !file.metadata()?.is_file() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(file)
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

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(any(windows, target_os = "linux")))]
fn is_reparse_point(_: &std::fs::Metadata) -> bool {
    false
}
