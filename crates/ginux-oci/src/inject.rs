//! `inject-tree`: write the members of one tar stream below a directory of an instance root.
//!
//! The root is a host directory that an untrusted identity (uid 65534) controlled earlier and
//! may have prepared with symbolic links, special files or odd modes; other processes running
//! as 65534 may still change it while the injection runs. The stream is caller-controlled.
//! Therefore:
//!
//! - when started as root the process first becomes uid/gid 65534 (as `export-tree` does), so
//!   every created object belongs to the workload identity and a resolver mistake can only
//!   write where that identity could write itself;
//! - every lookup is descriptor-relative through `openat2(2)`, pinned below the parent
//!   descriptor, with no symbolic links in any component, no magic links and no mount
//!   crossings; every descended directory is checked to be a real directory;
//! - nothing is ever overwritten: files are created with `O_CREAT|O_EXCL|O_NOFOLLOW`, symbolic
//!   links with `symlinkat` (both fail on any existing name), directories with `mkdirat`; an
//!   existing real directory is accepted and left untouched (its mode and time stay as they
//!   were, even when a directory member names it), any other existing object is a conflict;
//! - only regular files, directories and symbolic links are accepted; hard links, devices,
//!   FIFOs, sockets, PAX headers and sparse files are refused, as are absolute names, empty,
//!   `.` or `..` components, NUL bytes and duplicate names;
//! - sizes, member counts, name lengths and depth are bounded, and the byte bound is checked
//!   from the header before any body byte is read; the names kept for the whole run (for the
//!   duplicate check and the deferred directory pass) are charged against a fixed memory
//!   budget;
//! - after the end-of-archive block the rest of the input is read: it must be zero padding;
//! - modes keep the permission bits only (setuid, setgid and sticky are cleared) and are set
//!   with `fchmod`, so the umask has no effect; ownership in the stream is ignored.
//!
//! The injection is not atomic: it stops at the first error, and members written before that
//! stay in place. A caller must discard the instance when the command fails.

use crate::export::{
    drop_privileges, escaped, open_root, openat2, parse_bound, parse_path, stat_fd,
    unsupported_kernel,
};
use crate::{exit, ToolError};
use std::cell::Cell;
use std::collections::{BTreeSet, HashSet};
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::rc::Rc;

const USAGE: &str = "usage: ginux-image inject-tree ROOT MAX_BYTES MAX_MEMBERS MAX_PATH PATH";
/// Components of one member name below PATH.
const MAX_DEPTH: usize = 256;
/// Bound of a GNU LongLink body (target plus its NUL), as `export-tree` bounds link targets.
const MAX_LINK_RECORD: u64 = 4096;
const COPY_BUFFER: usize = 64 * 1024;
/// Mode of every directory this run creates until the final pass; it includes the owner bits,
/// so the contents of a created directory can always be written. Directories created without
/// a member of their own (PATH and implicit parents) keep it.
const PARENT_MODE: u32 = 0o755;
/// Memory the names kept for the whole run may take: the duplicate-check set, the deferred
/// directory list and the identities of created directories.
const RETAINED_BUDGET: usize = 256 * 1024 * 1024;
/// Bookkeeping charged per retained entry beside its name bytes.
const ENTRY_OVERHEAD: usize = 64;
/// Bytes after the end-of-archive block that are read and checked to be zero padding.
const TRAILING_LIMIT: u64 = 1 << 30;

/// Device and inode of a directory, as returned by `fstat`.
type Identity = (libc::dev_t, libc::ino_t);

fn identity(status: &libc::stat) -> Identity {
    (status.st_dev, status.st_ino)
}

/// Runs `inject-tree` with the tar stream on descriptor 0 and returns the exit code.
pub fn run(arguments: &[OsString]) -> u8 {
    match inject_tree(arguments, io::stdin().lock(), true) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("ginux-image: inject-tree: {}", error.message);
            error.code
        }
    }
}

/// Writes the members of the tar stream `input` below PATH inside ROOT.
///
/// `drop_identity` permits the switch to uid/gid 65534 when the effective uid is 0; tests pass
/// `false` so a test process running as root keeps its identity.
pub fn inject_tree<R: Read>(
    arguments: &[OsString],
    input: R,
    drop_identity: bool,
) -> Result<(), ToolError> {
    inject_with_budget(arguments, input, drop_identity, RETAINED_BUDGET)
}

fn inject_with_budget<R: Read>(
    arguments: &[OsString],
    input: R,
    drop_identity: bool,
    budget: usize,
) -> Result<(), ToolError> {
    let request = parse(arguments)?;
    let root = open_root(&request.root)?;
    if drop_identity {
        drop_privileges()?;
    }
    // Every lookup needs openat2; a kernel without it is refused before anything is written.
    openat2(root.as_raw_fd(), c".", libc::O_PATH | libc::O_DIRECTORY)
        .map_err(|error| fs_error(error, "/"))?;
    let mut opened: Option<OwnedFd> = None;
    let mut shown = String::new();
    for component in &request.path {
        shown.push('/');
        shown.push_str(&escaped(component));
        let parent = opened.as_ref().unwrap_or(&root);
        let (directory, _, _) = descend(parent, component, &shown)?;
        opened = Some(directory);
    }
    let target = opened.unwrap_or(root);
    let mut injector = Injector {
        target: &target,
        target_shown: shown,
        max_bytes: request.max_bytes,
        max_members: request.max_members,
        max_path: request.max_path,
        bytes: 0,
        members: 0,
        seen: BTreeSet::new(),
        directories: Vec::new(),
        created: HashSet::new(),
        retained: 0,
        budget,
    };
    injector.receive(input)?;
    injector.finish()
}

struct Request {
    root: CString,
    max_bytes: u64,
    max_members: u64,
    max_path: usize,
    /// PATH as components; empty means the root itself.
    path: Vec<Vec<u8>>,
}

fn usage(reason: impl std::fmt::Display) -> ToolError {
    ToolError::new(exit::USAGE, format!("{reason}\n{USAGE}"))
}

/// The shared argument checks report `export-tree`'s usage line; keep their reason only.
fn reword(error: ToolError) -> ToolError {
    usage(error.message.lines().next().unwrap_or_default())
}

fn parse(arguments: &[OsString]) -> Result<Request, ToolError> {
    let [root, max_bytes, max_members, max_path, path] = arguments else {
        return Err(usage("wrong number of arguments"));
    };
    if root.is_empty() {
        return Err(usage("ROOT is empty"));
    }
    let root = CString::new(root.as_bytes()).map_err(|_| usage("ROOT contains NUL"))?;
    let max_bytes = parse_bound(max_bytes, "MAX_BYTES").map_err(reword)?;
    let max_members = parse_bound(max_members, "MAX_MEMBERS").map_err(reword)?;
    let max_path = usize::try_from(parse_bound(max_path, "MAX_PATH").map_err(reword)?)
        .map_err(|_| usage("MAX_PATH is too large"))?;
    if path.as_bytes().contains(&0) {
        return Err(usage("PATH contains NUL"));
    }
    let path = parse_path(path.as_bytes(), max_path).map_err(reword)?;
    Ok(Request {
        root,
        max_bytes,
        max_members,
        max_path,
        path,
    })
}

fn invalid(message: impl Into<String>) -> ToolError {
    ToolError::new(exit::INVALID, message)
}

fn bound(message: impl Into<String>) -> ToolError {
    ToolError::new(exit::BOUND, message)
}

fn truncated() -> ToolError {
    ToolError::new(exit::OUTPUT, "archive is truncated")
}

/// Maps a failed filesystem call on `shown` to the exit-code table.
fn fs_error(error: io::Error, shown: &str) -> ToolError {
    match error.raw_os_error() {
        Some(libc::ENOSYS) => unsupported_kernel(),
        Some(libc::EEXIST) => invalid(format!("destination exists: {shown}")),
        Some(libc::ELOOP) => invalid(format!("symlink in destination path: {shown}")),
        Some(libc::ENOTDIR) => invalid(format!("destination is not a directory: {shown}")),
        Some(libc::EXDEV) => invalid(format!("destination crosses a mount point: {shown}")),
        Some(libc::EACCES | libc::EPERM) => invalid(format!("permission denied: {shown}")),
        Some(libc::ENAMETOOLONG) => invalid(format!("name too long for the filesystem: {shown}")),
        // Removed or renamed by someone else after it was created or checked.
        Some(libc::ENOENT | libc::EAGAIN) => ToolError::new(
            exit::CHANGED,
            format!("destination changed during injection: {shown}"),
        ),
        Some(
            libc::ENOSPC | libc::EDQUOT | libc::EIO | libc::EROFS | libc::EFBIG | libc::EMLINK,
        ) => ToolError::new(exit::OUTPUT, format!("unable to write {shown}: {error}")),
        _ => ToolError::new(exit::INTERNAL, format!("{shown}: {error}")),
    }
}

/// What the input reader saw, so a failed parse can tell a cut stream from a malformed one.
#[derive(Default)]
struct StreamState {
    ended: Cell<bool>,
    failed: Cell<bool>,
}

struct Input<R> {
    inner: R,
    state: Rc<StreamState>,
}

impl<R: Read> Read for Input<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.inner.read(buffer) {
                Ok(0) if !buffer.is_empty() => {
                    self.state.ended.set(true);
                    return Ok(0);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.state.failed.set(true);
                    return Err(error);
                }
                result => return result,
            }
        }
    }
}

fn stream_error(state: &StreamState, error: io::Error) -> ToolError {
    if state.failed.get() {
        ToolError::new(exit::OUTPUT, format!("unable to read the archive: {error}"))
    } else if state.ended.get() {
        truncated()
    } else {
        invalid(format!("archive is malformed: {error}"))
    }
}

fn c_name(bytes: &[u8], shown: &str) -> Result<CString, ToolError> {
    CString::new(bytes).map_err(|_| invalid(format!("name contains NUL: {shown}")))
}

/// Opens directory `name` below `parent`, creating it (mode 0700, then `PARENT_MODE`) when
/// missing. Returns the descriptor, its status and whether this call created it.
fn descend(
    parent: &OwnedFd,
    name: &[u8],
    shown: &str,
) -> Result<(OwnedFd, libc::stat, bool), ToolError> {
    let name = c_name(name, shown)?;
    // SAFETY: valid descriptor and NUL-terminated single-component name.
    let created = if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
        true
    } else {
        let error = io::Error::last_os_error();
        // Whatever exists is judged by the open below: a real directory is accepted, a
        // symlink fails with ELOOP and anything else with ENOTDIR.
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(fs_error(error, shown));
        }
        false
    };
    let directory = openat2(
        parent.as_raw_fd(),
        &name,
        libc::O_DIRECTORY | libc::O_RDONLY,
    )
    .map_err(|error| fs_error(error, shown))?;
    let status = stat_fd(&directory).map_err(|error| fs_error(error, shown))?;
    if status.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(invalid(format!("destination is not a directory: {shown}")));
    }
    if created {
        set_mode(&directory, PARENT_MODE, shown)?;
    }
    Ok((directory, status, created))
}

fn set_mode(fd: &OwnedFd, mode: u32, shown: &str) -> Result<(), ToolError> {
    // SAFETY: valid descriptor; fchmod takes a plain mode.
    if unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(fs_error(io::Error::last_os_error(), shown));
    }
    Ok(())
}

fn times(mtime: u64) -> [libc::timespec; 2] {
    [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: libc::time_t::try_from(mtime).unwrap_or(libc::time_t::MAX),
            tv_nsec: 0,
        },
    ]
}

fn set_mtime(fd: &OwnedFd, mtime: u64, shown: &str) -> Result<(), ToolError> {
    let times = times(mtime);
    // SAFETY: valid descriptor and an array of two timespecs.
    if unsafe { libc::futimens(fd.as_raw_fd(), times.as_ptr()) } != 0 {
        return Err(fs_error(io::Error::last_os_error(), shown));
    }
    Ok(())
}

/// Validates a member name and splits it into components. A directory may end in one `/`.
fn split_name(name: &[u8], is_dir: bool, shown: &str) -> Result<Vec<Vec<u8>>, ToolError> {
    let name = if is_dir {
        name.strip_suffix(b"/").unwrap_or(name)
    } else {
        name
    };
    if name.is_empty() {
        return Err(invalid(format!("empty member name: {shown}")));
    }
    if name.contains(&0) {
        return Err(invalid(format!("member name contains NUL: {shown}")));
    }
    if name[0] == b'/' {
        return Err(invalid(format!("absolute member name: {shown}")));
    }
    let mut components = Vec::new();
    for component in name.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return Err(invalid(format!(
                "member name has an empty, . or .. component: {shown}"
            )));
        }
        components.push(component.to_vec());
    }
    Ok(components)
}

/// Reads the body of a GNU LongName or LongLink record: at most `limit` bytes, trailing NULs
/// removed, no NUL left inside.
fn read_long(
    entry: &mut impl Read,
    size: u64,
    limit: u64,
    label: &str,
    state: &StreamState,
) -> Result<Vec<u8>, ToolError> {
    if size > limit {
        return Err(bound(format!(
            "GNU long {label} record is longer than {limit} bytes"
        )));
    }
    let mut value = Vec::new();
    entry
        .take(size)
        .read_to_end(&mut value)
        .map_err(|error| stream_error(state, error))?;
    if value.len() as u64 != size {
        return Err(truncated());
    }
    while value.last() == Some(&0) {
        value.pop();
    }
    if value.contains(&0) {
        return Err(invalid(format!(
            "GNU long {label} contains NUL: {}",
            escaped(&value)
        )));
    }
    Ok(value)
}

/// Reads what follows the end-of-archive block: tar stops at the first zero block, so the
/// second one and any record padding are still unread. Everything up to end of input must be
/// zero; at most `limit` bytes are accepted.
fn trailing(input: impl Read, limit: u64) -> Result<(), ToolError> {
    let mut input = input.take(limit.saturating_add(1));
    let mut buffer = vec![0u8; COPY_BUFFER];
    let mut total: u64 = 0;
    loop {
        let count = match input.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(ToolError::new(
                    exit::OUTPUT,
                    format!("unable to read the archive: {error}"),
                ))
            }
        };
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Err(invalid("data after the end of the archive"));
        }
        total += count as u64;
        if total > limit {
            return Err(bound(format!(
                "more than {limit} bytes follow the end of the archive"
            )));
        }
    }
}

/// A directory created by this run and named by a member; its final mode and time are
/// applied after the whole stream.
struct Directory {
    /// Checked again before the final mode is applied.
    identity: Identity,
    /// Name below PATH, components joined with `/`.
    path: Vec<u8>,
    mode: u32,
    mtime: u64,
}

struct Injector<'a> {
    target: &'a OwnedFd,
    /// PATH as shown in messages; empty for the root itself.
    target_shown: String,
    max_bytes: u64,
    max_members: u64,
    max_path: usize,
    bytes: u64,
    members: u64,
    /// Normalized member names seen so far (charged against `budget`).
    seen: BTreeSet<Vec<u8>>,
    directories: Vec<Directory>,
    /// Implicit parent directories this run created (charged against `budget`); a directory
    /// member naming one later still gets its mode and time.
    created: HashSet<Identity>,
    /// Bytes charged so far for retained names and identities.
    retained: usize,
    budget: usize,
}

impl Injector<'_> {
    fn shown(&self, relative: &[u8]) -> String {
        format!("{}/{}", self.target_shown, escaped(relative))
    }

    /// Charges one retained entry of `bytes` against the memory budget.
    fn charge(&mut self, bytes: usize) -> Result<(), ToolError> {
        self.retained = self
            .retained
            .saturating_add(bytes)
            .saturating_add(ENTRY_OVERHEAD);
        if self.retained > self.budget {
            return Err(bound(format!(
                "member names need more than {} bytes of memory",
                self.budget
            )));
        }
        Ok(())
    }

    fn receive<R: Read>(&mut self, input: R) -> Result<(), ToolError> {
        let state = Rc::new(StreamState::default());
        let mut archive = tar::Archive::new(Input {
            inner: input,
            state: Rc::clone(&state),
        });
        let mut long_name: Option<Vec<u8>> = None;
        let mut long_link: Option<Vec<u8>> = None;
        // Raw iteration: the default iterator reads GNU long name/link and PAX bodies into
        // memory without a cap and applies PAX overrides. Here GNU records are read with a
        // bound, PAX headers are refused.
        let entries = archive
            .entries()
            .map_err(|error| stream_error(&state, error))?
            .raw(true);
        for entry in entries {
            let mut entry = entry.map_err(|error| stream_error(&state, error))?;
            let kind = entry.header().entry_type().as_byte();
            let size = entry.size();
            match kind {
                b'L' => {
                    if long_name.is_some() {
                        return Err(invalid("two GNU long-name records for one member"));
                    }
                    let limit = u64::try_from(self.max_path)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1);
                    long_name = Some(read_long(&mut entry, size, limit, "name", &state)?);
                    continue;
                }
                b'K' => {
                    if long_link.is_some() {
                        return Err(invalid("two GNU long-link records for one member"));
                    }
                    long_link = Some(read_long(
                        &mut entry,
                        size,
                        MAX_LINK_RECORD,
                        "link",
                        &state,
                    )?);
                    continue;
                }
                _ => {}
            }
            let name = match long_name.take() {
                Some(name) => name,
                None => entry.path_bytes().into_owned(),
            };
            let link = match long_link.take() {
                Some(link) => Some(link),
                None => entry.link_name_bytes().map(|link| link.into_owned()),
            };
            self.member(&mut entry, kind, size, &name, link, &state)?;
        }
        if long_name.is_some() || long_link.is_some() {
            return Err(invalid(
                "archive ends after a GNU long-name or long-link record",
            ));
        }
        // The iterator also stops at end of input; only a zero block marks a complete archive.
        if state.ended.get() {
            return Err(truncated());
        }
        trailing(archive.into_inner(), TRAILING_LIMIT)
    }

    fn member<R: Read>(
        &mut self,
        entry: &mut tar::Entry<'_, R>,
        kind: u8,
        size: u64,
        name: &[u8],
        link: Option<Vec<u8>>,
        state: &StreamState,
    ) -> Result<(), ToolError> {
        let shown = self.shown(name);
        self.members += 1;
        if self.members > self.max_members {
            return Err(bound(format!(
                "archive has more than {} members",
                self.max_members
            )));
        }
        let what = match kind {
            b'0' | b'\0' | b'5' | b'2' => None,
            b'1' => Some("hard link"),
            b'3' => Some("character device"),
            b'4' => Some("block device"),
            b'6' => Some("FIFO"),
            b'x' | b'g' => Some("PAX extended header"),
            b'S' => Some("sparse file"),
            _ => Some("unknown"),
        };
        if let Some(what) = what {
            return Err(invalid(format!(
                "unsupported member type ({what}): {shown}"
            )));
        }
        if name.len() > self.max_path {
            return Err(bound(format!(
                "member name is longer than {} bytes: {shown}",
                self.max_path
            )));
        }
        let components = split_name(name, kind == b'5', &shown)?;
        if components.len() > MAX_DEPTH {
            return Err(bound(format!(
                "member name has more than {MAX_DEPTH} components: {shown}"
            )));
        }
        let joined = components.join(&b'/');
        if self.seen.contains(&joined) {
            return Err(invalid(format!("duplicate member: {shown}")));
        }
        self.charge(joined.len())?;
        self.seen.insert(joined.clone());
        let malformed = |error: io::Error| invalid(format!("bad header for {shown}: {error}"));
        let mode = entry.header().mode().map_err(malformed)? & 0o777;
        let mtime = entry.header().mtime().map_err(malformed)?;
        if kind != b'0' && kind != b'\0' && size != 0 {
            return Err(invalid(format!(
                "directory or symlink member has a body: {shown}"
            )));
        }
        let (last, parents) = components.split_last().expect("at least one component");
        let parent = self.parents(parents)?;
        let target = self.target;
        let directory = parent.as_ref().unwrap_or(target);
        match kind {
            b'5' => {
                let (_, status, created) = descend(directory, last, &shown)?;
                let identity = identity(&status);
                // Only a directory this run created takes the member's mode and time; it is
                // at PARENT_MODE until then. An existing directory is left exactly as it is.
                if created || self.created.contains(&identity) {
                    self.charge(joined.len())?;
                    self.directories.push(Directory {
                        identity,
                        path: joined,
                        mode,
                        mtime,
                    });
                }
                Ok(())
            }
            b'2' => {
                let target = link.unwrap_or_default();
                if target.is_empty() {
                    return Err(invalid(format!("symlink without a target: {shown}")));
                }
                let target = c_name(&target, &shown)?;
                let name = c_name(last, &shown)?;
                // SAFETY: NUL-terminated target and single-component name, valid descriptor.
                if unsafe { libc::symlinkat(target.as_ptr(), directory.as_raw_fd(), name.as_ptr()) }
                    != 0
                {
                    return Err(fs_error(io::Error::last_os_error(), &shown));
                }
                let times = times(mtime);
                // SAFETY: valid descriptor, NUL-terminated name, two timespecs; the link
                // itself is changed, never its target.
                if unsafe {
                    libc::utimensat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        times.as_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    return Err(fs_error(io::Error::last_os_error(), &shown));
                }
                Ok(())
            }
            _ => self.write_file(entry, directory, last, size, mode, mtime, &shown, state),
        }
    }

    /// Opens (creating when missing) the parent directories of a member below PATH.
    /// Created ones are remembered by identity.
    fn parents(&mut self, components: &[Vec<u8>]) -> Result<Option<OwnedFd>, ToolError> {
        let mut opened: Option<OwnedFd> = None;
        for (index, component) in components.iter().enumerate() {
            let shown = self.shown(&components[..=index].join(&b'/'));
            let parent = opened.as_ref().unwrap_or(self.target);
            let (directory, status, created) = descend(parent, component, &shown)?;
            if created {
                self.charge(std::mem::size_of::<Identity>())?;
                self.created.insert(identity(&status));
            }
            opened = Some(directory);
        }
        Ok(opened)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_file<R: Read>(
        &mut self,
        entry: &mut tar::Entry<'_, R>,
        directory: &OwnedFd,
        name: &[u8],
        size: u64,
        mode: u32,
        mtime: u64,
        shown: &str,
        state: &StreamState,
    ) -> Result<(), ToolError> {
        // Counted from the header, before any body byte is read.
        self.bytes = self
            .bytes
            .checked_add(size)
            .filter(|total| *total <= self.max_bytes)
            .ok_or_else(|| {
                bound(format!(
                    "archive exceeds {} bytes at {shown}",
                    self.max_bytes
                ))
            })?;
        let name = c_name(name, shown)?;
        // Mode 0 at creation; the final mode is set on the descriptor, so the umask does not
        // matter and the write descriptor is unaffected.
        let fd = openat2(
            directory.as_raw_fd(),
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOCTTY,
        )
        .map_err(|error| fs_error(error, shown))?;
        let mut file = File::from(fd);
        let mut buffer = vec![0u8; COPY_BUFFER];
        let mut remaining = size;
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(COPY_BUFFER as u64)).unwrap_or(COPY_BUFFER);
            let count = entry
                .read(&mut buffer[..wanted])
                .map_err(|error| stream_error(state, error))?;
            if count == 0 {
                return Err(truncated());
            }
            file.write_all(&buffer[..count])
                .map_err(|error| fs_error(error, shown))?;
            remaining -= count as u64;
        }
        let fd = OwnedFd::from(file);
        set_mode(&fd, mode, shown)?;
        set_mtime(&fd, mtime, shown)
    }

    /// Applies the final mode and time of every directory member this run created, deepest
    /// first, so a restrictive mode never blocks writing below it and child changes do not
    /// disturb a parent's time.
    fn finish(mut self) -> Result<(), ToolError> {
        self.directories.sort_by_cached_key(|directory| {
            std::cmp::Reverse(directory.path.iter().filter(|byte| **byte == b'/').count())
        });
        for directory in &self.directories {
            let shown = self.shown(&directory.path);
            let name = c_name(&directory.path, &shown)?;
            let fd = openat2(
                self.target.as_raw_fd(),
                &name,
                libc::O_DIRECTORY | libc::O_RDONLY,
            )
            .map_err(|error| fs_error(error, &shown))?;
            let status = stat_fd(&fd).map_err(|error| fs_error(error, &shown))?;
            if identity(&status) != directory.identity {
                return Err(ToolError::new(
                    exit::CHANGED,
                    format!("destination changed during injection: {shown}"),
                ));
            }
            set_mode(&fd, directory.mode, &shown)?;
            set_mtime(&fd, directory.mtime, &shown)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tar::{EntryType, Header};

    const MTIME: u64 = 1_700_000_000;
    const WIDE: [&str; 3] = ["1000000", "1000", "4096"];

    struct TempTree(PathBuf);

    impl TempTree {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ginux-oci-inject-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(path.join("root")).unwrap();
            fs::create_dir_all(path.join("outside")).unwrap();
            Self(path)
        }

        fn root(&self) -> PathBuf {
            self.0.join("root")
        }

        fn outside(&self) -> PathBuf {
            self.0.join("outside")
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Builds tar streams byte for byte, without the `tar` crate's name checks.
    struct Stream(tar::Builder<Vec<u8>>);

    impl Stream {
        fn new() -> Self {
            Self(tar::Builder::new(Vec::new()))
        }

        fn long(&mut self, kind: u8, value: &[u8]) {
            let mut header = Header::new_gnu();
            copy(&mut header.as_old_mut().name, b"././@LongLink");
            header.set_mode(0o644);
            header.set_size(value.len() as u64 + 1);
            header.set_entry_type(EntryType::new(kind));
            header.set_cksum();
            self.0.append(&header, value.chain(&b"\0"[..])).unwrap();
        }

        fn raw(&mut self, kind: EntryType, name: &[u8], mode: u32, link: &[u8], data: &[u8]) {
            if name.len() >= 100 {
                self.long(b'L', name);
            }
            if link.len() >= 100 {
                self.long(b'K', link);
            }
            let mut header = Header::new_gnu();
            header.set_entry_type(kind);
            header.set_mode(mode);
            header.set_uid(1234);
            header.set_gid(1234);
            header.set_mtime(MTIME);
            header.set_size(data.len() as u64);
            copy(&mut header.as_old_mut().name, name);
            copy(&mut header.as_old_mut().linkname, link);
            header.set_cksum();
            self.0.append(&header, data).unwrap();
        }

        fn file(mut self, name: &str, mode: u32, data: &[u8]) -> Self {
            self.raw(EntryType::Regular, name.as_bytes(), mode, b"", data);
            self
        }

        fn dir(mut self, name: &str, mode: u32) -> Self {
            self.raw(EntryType::Directory, name.as_bytes(), mode, b"", b"");
            self
        }

        fn link(mut self, name: &str, target: &str) -> Self {
            self.raw(
                EntryType::Symlink,
                name.as_bytes(),
                0o777,
                target.as_bytes(),
                b"",
            );
            self
        }

        fn kind(mut self, kind: EntryType, name: &str) -> Self {
            self.raw(kind, name.as_bytes(), 0o644, b"target", b"");
            self
        }

        fn finish(self) -> Vec<u8> {
            self.0.into_inner().unwrap()
        }
    }

    fn copy(field: &mut [u8], value: &[u8]) {
        let length = value.len().min(field.len());
        field[..length].copy_from_slice(&value[..length]);
    }

    fn arguments(root: &Path, bounds: [&str; 3], path: &str) -> Vec<OsString> {
        let mut arguments = vec![root.as_os_str().to_owned()];
        arguments.extend(bounds.iter().map(OsString::from));
        arguments.push(OsString::from(path));
        arguments
    }

    fn inject(root: &Path, bounds: [&str; 3], path: &str, stream: &[u8]) -> Result<(), ToolError> {
        inject_tree(&arguments(root, bounds, path), stream, false)
    }

    fn code(result: Result<(), ToolError>) -> u8 {
        result.expect_err("injection should fail").code
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn is_empty(path: &Path) -> bool {
        fs::read_dir(path).unwrap().next().is_none()
    }

    #[test]
    fn writes_a_nested_tree_with_modes_times_and_links() {
        let tree = TempTree::new("happy");
        let root = tree.root();
        let stream = Stream::new()
            .dir("a/", 0o750)
            .dir("a/b/", 0o1777)
            .file("a/tool", 0o6755, b"#!")
            .file("a/b/data", 0o640, &[7u8; 1500])
            .file("top", 0o644, b"")
            .link("a/passwd", "/etc/passwd")
            .finish();
        inject(&root, WIDE, "/inputs/deep", &stream).unwrap();
        let base = root.join("inputs/deep");
        assert_eq!(mode(&root.join("inputs")), 0o755);
        assert_eq!(mode(&base), 0o755);
        assert_eq!(mode(&base.join("a")), 0o750);
        assert_eq!(mode(&base.join("a/b")), 0o777);
        assert_eq!(mode(&base.join("a/tool")), 0o755);
        assert_eq!(fs::read(base.join("a/b/data")).unwrap(), vec![7u8; 1500]);
        assert_eq!(mode(&base.join("a/b/data")), 0o640);
        assert_eq!(fs::read(base.join("top")).unwrap(), b"");
        for name in ["a", "a/b", "a/tool", "top"] {
            let metadata = fs::symlink_metadata(base.join(name)).unwrap();
            assert_eq!(metadata.mtime() as u64, MTIME, "{name}");
            // Ownership in the stream is ignored.
            assert_ne!(metadata.uid(), 1234);
        }
        let link = base.join("a/passwd");
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("/etc/passwd"));
        assert_eq!(fs::symlink_metadata(&link).unwrap().mtime() as u64, MTIME);
    }

    #[test]
    fn restrictive_directory_mode_is_applied_after_its_contents() {
        let tree = TempTree::new("restrictive");
        let root = tree.root();
        let stream = Stream::new()
            .dir("ro/", 0o500)
            .file("ro/f", 0o444, b"x")
            .dir("ro/sub/", 0o500)
            .file("ro/sub/g", 0o444, b"y")
            .finish();
        inject(&root, WIDE, "/", &stream).unwrap();
        assert_eq!(mode(&root.join("ro")), 0o500);
        assert_eq!(mode(&root.join("ro/sub")), 0o500);
        assert_eq!(fs::read(root.join("ro/sub/g")).unwrap(), b"y");
        fs::set_permissions(root.join("ro/sub"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(root.join("ro"), fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn missing_parents_are_created_and_existing_directories_accepted() {
        let tree = TempTree::new("parents");
        let root = tree.root();
        fs::create_dir_all(root.join("dest/existing")).unwrap();
        let stream = Stream::new()
            .file("x/y/z", 0o600, b"z")
            .dir("existing/", 0o700)
            .file("existing/f", 0o600, b"f")
            .finish();
        inject(&root, WIDE, "/dest", &stream).unwrap();
        assert_eq!(fs::read(root.join("dest/x/y/z")).unwrap(), b"z");
        assert_eq!(mode(&root.join("dest/x/y")), 0o755);
        assert_eq!(fs::read(root.join("dest/existing/f")).unwrap(), b"f");
    }

    fn set_mtime_of(path: &Path, seconds: u64) {
        fs::File::open(path)
            .unwrap()
            .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(seconds))
            .unwrap();
    }

    fn mtime_of(path: &Path) -> u64 {
        fs::symlink_metadata(path).unwrap().mtime() as u64
    }

    #[test]
    fn existing_directory_member_keeps_its_mode_and_time() {
        const OLD: u64 = 1_600_000_000;
        let tree = TempTree::new("existing-mode");
        let root = tree.root();
        let tmp = root.join("tmp");
        fs::create_dir(&tmp).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o1777)).unwrap();
        set_mtime_of(&tmp, OLD);
        // Named by a directory member, at PATH=/: neither the mode nor the time changes.
        let stream = Stream::new()
            .dir("tmp/", 0o755)
            .file("other", 0o644, b"x")
            .finish();
        inject(&root, WIDE, "/", &stream).unwrap();
        assert_eq!(mode(&tmp), 0o1777);
        assert_eq!(mtime_of(&tmp), OLD);
        // Written into: the mode still stays.
        let stream = Stream::new()
            .dir("tmp/", 0o700)
            .file("tmp/f", 0o600, b"f")
            .finish();
        inject(&root, WIDE, "/", &stream).unwrap();
        assert_eq!(mode(&tmp), 0o1777);
        assert_eq!(fs::read(tmp.join("f")).unwrap(), b"f");
        // A failure before the final pass leaves it untouched as well.
        set_mtime_of(&tmp, OLD);
        let stream = Stream::new()
            .dir("tmp/", 0o700)
            .kind(EntryType::Link, "hard")
            .finish();
        assert_eq!(code(inject(&root, WIDE, "/", &stream)), exit::INVALID);
        assert_eq!(mode(&tmp), 0o1777);
        assert_eq!(mtime_of(&tmp), OLD);
    }

    #[test]
    fn existing_read_only_directory_is_never_chmoded() {
        let tree = TempTree::new("existing-ro");
        let root = tree.root();
        let ro = root.join("ro");
        fs::create_dir(&ro).unwrap();
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).unwrap();
        // SAFETY: geteuid has no preconditions.
        let privileged = unsafe { libc::geteuid() } == 0;
        for (path, stream) in [
            ("/", Stream::new().file("ro/sub/f", 0o644, b"x").finish()),
            (
                "/",
                Stream::new()
                    .dir("ro/", 0o755)
                    .file("ro/f", 0o644, b"x")
                    .finish(),
            ),
            ("/ro/sub", Stream::new().file("f", 0o644, b"x").finish()),
        ] {
            let result = inject(&root, WIDE, path, &stream);
            if !privileged {
                assert_eq!(code(result), exit::INVALID, "{path}");
            }
            assert_eq!(mode(&ro), 0o555, "{path}");
        }
        if !privileged {
            assert!(is_empty(&ro));
        }
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn implicit_parent_named_later_takes_the_member_mode() {
        let tree = TempTree::new("implicit-later");
        let root = tree.root();
        let stream = Stream::new()
            .file("p/f", 0o644, b"x")
            .dir("p/", 0o750)
            .finish();
        inject(&root, WIDE, "/", &stream).unwrap();
        assert_eq!(mode(&root.join("p")), 0o750);
        assert_eq!(mtime_of(&root.join("p")), MTIME);
    }

    #[test]
    fn retained_names_over_the_budget_fail_with_76() {
        let tree = TempTree::new("budget");
        let root = tree.root();
        let stream = Stream::new()
            .dir("d/", 0o755)
            .file("d/one", 0o644, b"")
            .file("d/two", 0o644, b"")
            .finish();
        let budget =
            |bytes| inject_with_budget(&arguments(&root, WIDE, "/b"), &stream[..], false, bytes);
        let error = budget(3 * ENTRY_OVERHEAD).unwrap_err();
        assert_eq!(error.code, exit::BOUND);
        assert!(error.message.contains("bytes of memory"));
        fs::remove_dir_all(root.join("b")).unwrap();
        assert!(budget(RETAINED_BUDGET).is_ok());
    }

    #[test]
    fn data_after_the_end_of_the_archive() {
        let tree = TempTree::new("trailing");
        let root = tree.root();
        let first = Stream::new().file("a", 0o644, b"a").finish();
        let second = Stream::new().file("b", 0o644, b"b").finish();
        // Record padding (zero blocks) after the end is fine.
        let mut padded = first.clone();
        padded.extend_from_slice(&[0u8; 10240]);
        inject(&root, WIDE, "/padded", &padded).unwrap();
        // A second archive appended after the end-of-archive block is refused.
        let end = first.len() - 1024 + 512;
        let mut appended = first[..end].to_vec();
        appended.extend_from_slice(&second);
        let error = inject(&root, WIDE, "/appended", &appended).unwrap_err();
        assert_eq!(error.code, exit::INVALID);
        assert!(error.message.contains("data after the end of the archive"));
        assert!(!root.join("appended/b").exists());
        // A read error after the end is an input failure.
        let failing = (&first[..]).chain(FailingReader);
        let error = inject_tree(&arguments(&root, WIDE, "/failing"), failing, false).unwrap_err();
        assert_eq!(error.code, exit::OUTPUT);
        // The amount read after the end is bounded.
        assert_eq!(code(trailing(&[0u8; 100][..], 50)), exit::BOUND);
        assert!(trailing(&[0u8; 50][..], 50).is_ok());
    }

    #[test]
    fn planted_symlink_in_path_is_never_followed() {
        let tree = TempTree::new("path-link");
        let root = tree.root();
        symlink(tree.outside(), root.join("inputs")).unwrap();
        let stream = Stream::new().file("f", 0o644, b"x").finish();
        assert_eq!(code(inject(&root, WIDE, "/inputs", &stream)), exit::INVALID);
        assert_eq!(
            code(inject(&root, WIDE, "/inputs/sub", &stream)),
            exit::INVALID
        );
        // A link to a directory inside the root is refused just the same.
        fs::create_dir(root.join("real")).unwrap();
        symlink("real", root.join("alias")).unwrap();
        assert_eq!(code(inject(&root, WIDE, "/alias", &stream)), exit::INVALID);
        assert!(is_empty(&tree.outside()));
        assert!(is_empty(&root.join("real")));
    }

    #[test]
    fn planted_symlink_in_member_path_is_never_followed() {
        let tree = TempTree::new("member-link");
        let root = tree.root();
        fs::create_dir(root.join("dest")).unwrap();
        symlink(tree.outside(), root.join("dest/a")).unwrap();
        for stream in [
            Stream::new().file("a/f", 0o644, b"x").finish(),
            Stream::new().dir("a/", 0o755).finish(),
            Stream::new().file("a", 0o644, b"x").finish(),
            Stream::new().link("a", "elsewhere").finish(),
            Stream::new().file("a/deeper/f", 0o644, b"x").finish(),
        ] {
            assert_eq!(code(inject(&root, WIDE, "/dest", &stream)), exit::INVALID);
        }
        assert!(is_empty(&tree.outside()));
        assert_eq!(fs::read_link(root.join("dest/a")).unwrap(), tree.outside());
    }

    #[test]
    fn existing_non_directories_are_conflicts() {
        let tree = TempTree::new("conflict");
        let root = tree.root();
        fs::create_dir(root.join("dest")).unwrap();
        fs::write(root.join("dest/x"), b"old").unwrap();
        for stream in [
            Stream::new().file("x", 0o644, b"new").finish(),
            Stream::new().dir("x/", 0o755).finish(),
            Stream::new().file("x/y", 0o644, b"new").finish(),
            Stream::new().link("x", "t").finish(),
        ] {
            assert_eq!(code(inject(&root, WIDE, "/dest", &stream)), exit::INVALID);
        }
        assert_eq!(fs::read(root.join("dest/x")).unwrap(), b"old");
        // PATH itself, or one of its parents, being a file.
        let stream = Stream::new().file("f", 0o644, b"x").finish();
        assert_eq!(code(inject(&root, WIDE, "/dest/x", &stream)), exit::INVALID);
        assert_eq!(
            code(inject(&root, WIDE, "/dest/x/below", &stream)),
            exit::INVALID
        );
    }

    #[test]
    fn every_bound_fails_with_76() {
        let tree = TempTree::new("bounds");
        let root = tree.root();
        let sized = Stream::new()
            .file("a", 0o644, &[1u8; 60])
            .file("b", 0o644, &[1u8; 50])
            .finish();
        assert_eq!(
            code(inject(&root, ["100", "1000", "4096"], "/b1", &sized)),
            exit::BOUND
        );
        assert!(inject(&root, ["110", "1000", "4096"], "/b2", &sized).is_ok());
        // The byte bound is checked from the header, before the (missing) body is read.
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_size(1 << 40);
        header.set_mode(0o644);
        header.set_mtime(MTIME);
        copy(&mut header.as_old_mut().name, b"huge");
        header.set_cksum();
        let mut bytes = header.as_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 100]);
        assert_eq!(code(inject(&root, WIDE, "/b3", &bytes)), exit::BOUND);
        // Members: three, limit two.
        let three = Stream::new()
            .dir("d/", 0o755)
            .file("d/1", 0o644, b"")
            .file("d/2", 0o644, b"")
            .finish();
        assert_eq!(
            code(inject(&root, ["1000", "2", "4096"], "/m1", &three)),
            exit::BOUND
        );
        assert!(inject(&root, ["1000", "3", "4096"], "/m2", &three).is_ok());
        // Name length: "d/1" is 3 bytes, "d/" counts with its slash.
        assert_eq!(
            code(inject(&root, ["1000", "1000", "2"], "/p", &three)),
            exit::BOUND
        );
        assert!(inject(&root, ["1000", "1000", "3"], "/q", &three).is_ok());
        // Depth: 256 components pass, 257 fail.
        let deep = vec!["d"; MAX_DEPTH].join("/");
        let ok = Stream::new().file(&deep, 0o644, b"").finish();
        assert!(inject(&root, WIDE, "/depth1", &ok).is_ok());
        let too_deep = Stream::new()
            .file(&format!("{deep}/e"), 0o644, b"")
            .finish();
        assert_eq!(code(inject(&root, WIDE, "/depth2", &too_deep)), exit::BOUND);
    }

    #[test]
    fn bad_member_names_are_refused() {
        let tree = TempTree::new("names");
        let root = tree.root();
        for (index, name) in [
            "../x", "/abs", "a/../b", "./a", "a//b", "a/.", ".", "..", "a/", "",
        ]
        .iter()
        .enumerate()
        {
            let stream = Stream::new().file(name, 0o644, b"x").finish();
            assert_eq!(
                code(inject(&root, WIDE, &format!("/n{index}"), &stream)),
                exit::INVALID,
                "{name:?}"
            );
        }
        for (index, stream) in [
            Stream::new()
                .file("a", 0o644, b"")
                .file("a", 0o644, b"")
                .finish(),
            Stream::new()
                .dir("d/", 0o755)
                .file("d", 0o644, b"")
                .finish(),
            Stream::new().dir("d/", 0o755).dir("d", 0o755).finish(),
            Stream::new().dir("../", 0o755).finish(),
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(
                code(inject(&root, WIDE, &format!("/dup{index}"), stream)),
                exit::INVALID
            );
        }
        // Nothing escaped the root.
        assert!(is_empty(&tree.outside()));
        assert!(!tree.0.join("x").exists());
    }

    #[test]
    fn unsupported_member_types_are_refused() {
        let tree = TempTree::new("types");
        let root = tree.root();
        for (index, kind) in [
            EntryType::Link,
            EntryType::Char,
            EntryType::Block,
            EntryType::Fifo,
            EntryType::XHeader,
            EntryType::XGlobalHeader,
            EntryType::GNUSparse,
            EntryType::Continuous,
        ]
        .into_iter()
        .enumerate()
        {
            let stream = Stream::new().kind(kind, "member").finish();
            let error = inject(&root, WIDE, &format!("/t{index}"), &stream).unwrap_err();
            assert_eq!(error.code, exit::INVALID, "{kind:?}");
            assert!(error.message.contains("unsupported member type"));
        }
    }

    #[test]
    fn long_names_and_link_targets_round_trip() {
        let tree = TempTree::new("long");
        let root = tree.root();
        let long_directory = "d".repeat(150);
        let long_file = format!("{long_directory}/{}", "f".repeat(200));
        let target = format!("../{}", "t/".repeat(150));
        let stream = Stream::new()
            .dir(&format!("{long_directory}/"), 0o755)
            .file(&long_file, 0o644, b"long")
            .link(&format!("{long_directory}/link"), &target)
            .finish();
        inject(&root, WIDE, "/out", &stream).unwrap();
        assert_eq!(
            fs::read(root.join("out").join(&long_file)).unwrap(),
            b"long"
        );
        assert_eq!(
            fs::read_link(root.join("out").join(&long_directory).join("link")).unwrap(),
            Path::new(&target)
        );
        // A long name over MAX_PATH is a bound, refused before its body is used.
        assert_eq!(
            code(inject(&root, ["1000", "1000", "200"], "/out2", &stream)),
            exit::BOUND
        );
        // Two long-name records in a row, or one at the end of the archive.
        let mut twice = Stream::new();
        twice.long(b'L', "x".repeat(120).as_bytes());
        let twice = twice.file(&"y".repeat(120), 0o644, b"").finish();
        assert_eq!(code(inject(&root, WIDE, "/out3", &twice)), exit::INVALID);
        let mut dangling = Stream::new();
        dangling.long(b'L', b"name");
        assert_eq!(
            code(inject(&root, WIDE, "/out4", &dangling.finish())),
            exit::INVALID
        );
        // A NUL inside a long name.
        let mut nul = Stream::new();
        nul.long(b'L', b"a\0b");
        let nul = nul.file("short", 0o644, b"").finish();
        assert_eq!(code(inject(&root, WIDE, "/out5", &nul)), exit::INVALID);
    }

    #[test]
    fn truncated_input_fails_with_74() {
        let tree = TempTree::new("truncated");
        let root = tree.root();
        let stream = Stream::new()
            .file("a", 0o644, &[3u8; 2000])
            .file("b", 0o644, b"b")
            .finish();
        let end = stream.len() - 1024;
        let header_b = end - 1024;
        for (index, cut) in [
            &stream[..0],
            &stream[..100],
            &stream[..512 + 700],
            &stream[..header_b],
            &stream[..header_b + 200],
            &stream[..end],
            &stream[..end + 300],
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(
                code(inject(&root, WIDE, &format!("/c{index}"), cut)),
                exit::OUTPUT,
                "cut {index}"
            );
        }
        assert!(inject(&root, WIDE, "/whole", &stream).is_ok());
    }

    #[test]
    fn corrupt_header_is_invalid() {
        let tree = TempTree::new("corrupt");
        let root = tree.root();
        let mut stream = Stream::new().file("a", 0o644, b"x").finish();
        stream[0] ^= 0x20;
        assert_eq!(code(inject(&root, WIDE, "/c", &stream)), exit::INVALID);
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn input_read_errors_fail_with_74() {
        let tree = TempTree::new("read-error");
        let root = tree.root();
        let error = inject_tree(&arguments(&root, WIDE, "/x"), FailingReader, false).unwrap_err();
        assert_eq!(error.code, exit::OUTPUT);
    }

    #[test]
    fn injected_tree_exports_with_the_same_members() {
        let tree = TempTree::new("round-trip");
        let root = tree.root();
        let long = "l".repeat(130);
        let stream = Stream::new()
            .dir("a/", 0o755)
            .dir("a/b/", 0o700)
            .file("a/b/c", 0o600, b"c")
            .file("a/f", 0o644, &[9u8; 700])
            .link("a/l", "b/c")
            .file(&long, 0o644, b"long")
            .finish();
        inject(&root, WIDE, "/out", &stream).unwrap();
        let mut exported = Vec::new();
        crate::export::export_tree(
            &[
                root.as_os_str().to_owned(),
                "1000000".into(),
                "1000".into(),
                "4096".into(),
                "/out".into(),
            ],
            &mut exported,
            false,
        )
        .unwrap();
        let listing = |bytes: &[u8]| -> Vec<(Vec<u8>, u32, Vec<u8>)> {
            let mut archive = tar::Archive::new(bytes);
            let mut listed: Vec<_> = archive
                .entries()
                .unwrap()
                .map(|entry| {
                    let mut entry = entry.unwrap();
                    let mut data = Vec::new();
                    entry.read_to_end(&mut data).unwrap();
                    let mode = entry.header().mode().unwrap();
                    (entry.path_bytes().into_owned(), mode, data)
                })
                .collect();
            listed.sort();
            listed
        };
        let mut expected = listing(&stream);
        for member in &mut expected {
            member.0.splice(0..0, b"out/".iter().copied());
        }
        expected.push((b"out/".to_vec(), 0o755, Vec::new()));
        expected.sort();
        assert_eq!(listing(&exported), expected);
    }

    #[test]
    fn malformed_arguments_and_missing_root() {
        let tree = TempTree::new("usage");
        let root = tree.root();
        let stream = Stream::new().finish();
        for (bounds, path) in [
            (["0", "1", "1"], "/x"),
            (["1x", "1", "1"], "/x"),
            (WIDE, "relative"),
            (WIDE, "/a/../b"),
            (WIDE, "/a/"),
            (["10", "10", "3"], "/abcd"),
        ] {
            let error = inject(&root, bounds, path, &stream).unwrap_err();
            assert_eq!(error.code, exit::USAGE, "{bounds:?} {path}");
            assert!(error.message.ends_with(USAGE));
        }
        let error = inject_tree(&[OsString::from("/")], &stream[..], false).unwrap_err();
        assert_eq!(error.code, exit::USAGE);
        assert_eq!(
            code(inject(&tree.0.join("absent"), WIDE, "/", &stream)),
            exit::NOT_FOUND
        );
        // An empty but complete archive is a successful no-op that still creates PATH.
        inject(&root, WIDE, "/made", &stream).unwrap();
        assert!(root.join("made").is_dir());
    }
}
