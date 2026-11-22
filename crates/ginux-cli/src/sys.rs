//! Thin Linux system-call wrappers used by the CLI's interim lifecycle
//! commands. Every `unsafe` block in the public CLI outside `wait.rs` lives
//! here, so the security inventory can name one small file.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

/// Open an unnamed regular file (mode 0600) in `directory`. The inode has no
/// name until [`link_unnamed`] gives it one and disappears when the last
/// descriptor closes, even if the process is killed.
pub fn open_unnamed(directory: &Path) -> io::Result<File> {
    let path = c_path(directory)?;
    // SAFETY: `path` is a valid NUL-terminated string that outlives the call;
    // the returned descriptor is checked before ownership is taken.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly opened descriptor owned by nobody else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Give an unnamed file from [`open_unnamed`] the name `target`. Fails with
/// `AlreadyExists` instead of replacing an existing entry.
pub fn link_unnamed(file: &File, target: &Path) -> io::Result<()> {
    let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid descriptor path"))?;
    let target = c_path(target)?;
    // SAFETY: both strings are valid NUL-terminated paths that outlive the
    // call; `linkat` does not retain them.
    let result = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// True when an [`open_unnamed`] failure means the filesystem does not offer
/// unnamed files, so the caller should fall back to a named partial file.
pub fn unnamed_unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EOPNOTSUPP) | Some(libc::EISDIR)
    )
}
