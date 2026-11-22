//! `export-tree`: one tar stream of named directories below an instance root.
//!
//! The root is writable by an untrusted identity (uid 65534) that may change it while the
//! export runs. Therefore every lookup is descriptor-relative through `openat2(2)` with
//! resolution pinned below the parent descriptor, no symbolic links in any component, no
//! magic links and no mount crossings; every opened object is checked against the inode that
//! `fstatat(2)` reported for its name; only directories, regular files and symbolic links are
//! exported (anything else fails without being opened); and when started as root the process
//! first becomes uid/gid 65534, so a resolver mistake cannot disclose anything the workload
//! could not read itself.

use crate::{exit, ToolError};
use std::ffi::{CStr, CString, OsString};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::mem::{ManuallyDrop, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use tar::{EntryType, Header};

const USAGE: &str = "usage: ginux-image export-tree ROOT MAX_BYTES MAX_MEMBERS MAX_PATH PATH...";
/// Host identity of the workload; the exporter reads with exactly its rights.
const WORKLOAD_ID: u32 = 65534;
/// Directories below a requested path (one open descriptor per level, at most 257).
const MAX_DEPTH: usize = 256;
/// A symbolic link target that fills this buffer may have been truncated: refused as a bound.
const LINK_BUFFER: usize = 4096;
const COPY_BUFFER: usize = 64 * 1024;
const BLOCK: u64 = 512;
/// Size of the ustar name and linkname fields; longer values use GNU LongName/LongLink.
const NAME_FIELD: usize = 100;
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Runs `export-tree` with the tar stream on descriptor 1 and returns the exit code.
pub fn run(arguments: &[OsString]) -> u8 {
    let result =
        standard_output().and_then(|mut output| export_tree(arguments, &mut *output, true));
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("ginux-image: export-tree: {}", error.message);
            error.code
        }
    }
}

/// Descriptor 1 as a file whose write errors are reported.
///
/// `io::stdout()` is not used: the standard library turns writes to a closed descriptor 1
/// into silent success, which would publish an empty result as a successful one.
pub(crate) fn standard_output() -> Result<ManuallyDrop<File>, ToolError> {
    // SAFETY: F_GETFD only queries the descriptor flags.
    if unsafe { libc::fcntl(1, libc::F_GETFD) } < 0 {
        return Err(ToolError::new(
            exit::OUTPUT,
            "standard output is not an open descriptor",
        ));
    }
    // SAFETY: descriptor 1 is open (checked above). ManuallyDrop keeps this File from closing
    // it, so no other owner is invalidated.
    Ok(ManuallyDrop::new(unsafe { File::from_raw_fd(1) }))
}

/// Writes the tar stream of the requested directories to `output`.
///
/// `drop_identity` permits the switch to uid/gid 65534 when the effective uid is 0; tests pass
/// `false` so a test process running as root keeps its identity.
pub fn export_tree<W: Write>(
    arguments: &[OsString],
    output: W,
    drop_identity: bool,
) -> Result<(), ToolError> {
    let request = parse(arguments)?;
    let root = open_root(&request.root)?;
    if drop_identity {
        drop_privileges()?;
    }
    let mut walker = Walker {
        out: tar::Builder::new(BufWriter::with_capacity(COPY_BUFFER, output)),
        max_bytes: request.max_bytes,
        max_members: request.max_members,
        max_path: request.max_path,
        bytes: 0,
        members: 0,
    };
    for components in &request.paths {
        if let Err(error) = walker.export_path(&root, components) {
            // No end-of-archive blocks and no flush of buffered bytes after a failure: a cut
            // stream must never read as a complete archive.
            std::mem::forget(walker);
            return Err(error);
        }
    }
    let mut buffered = walker.out.into_inner().map_err(output_error)?;
    buffered.flush().map_err(output_error)
}

struct Request {
    root: CString,
    max_bytes: u64,
    max_members: u64,
    max_path: usize,
    /// Requested directories as components; empty means the root itself.
    paths: Vec<Vec<Vec<u8>>>,
}

fn usage(reason: impl std::fmt::Display) -> ToolError {
    ToolError::new(exit::USAGE, format!("{reason}\n{USAGE}"))
}

fn parse(arguments: &[OsString]) -> Result<Request, ToolError> {
    let [root, max_bytes, max_members, max_path, paths @ ..] = arguments else {
        return Err(usage("wrong number of arguments"));
    };
    if paths.is_empty() {
        return Err(usage("at least one PATH is required"));
    }
    if root.is_empty() {
        return Err(usage("ROOT is empty"));
    }
    let root = CString::new(root.as_bytes()).map_err(|_| usage("ROOT contains NUL"))?;
    let max_bytes = parse_bound(max_bytes, "MAX_BYTES")?;
    let max_members = parse_bound(max_members, "MAX_MEMBERS")?;
    let max_path = usize::try_from(parse_bound(max_path, "MAX_PATH")?)
        .map_err(|_| usage("MAX_PATH is too large"))?;
    let mut parsed = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = path.as_bytes();
        parsed.push((bytes.to_vec(), parse_path(bytes, max_path)?));
    }
    // Same normalization as the caller: bytewise order, duplicates and paths below another
    // listed path dropped, so no member is ever emitted twice.
    parsed.sort();
    parsed.dedup();
    let mut kept: Vec<Vec<Vec<u8>>> = Vec::new();
    for (_, components) in parsed {
        if !kept
            .iter()
            .any(|outer| components.starts_with(outer.as_slice()))
        {
            kept.push(components);
        }
    }
    Ok(Request {
        root,
        max_bytes,
        max_members,
        max_path,
        paths: kept,
    })
}

fn parse_bound(value: &OsString, label: &str) -> Result<u64, ToolError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(usage(format!("{label} must be a decimal number")));
    }
    let value: u64 = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| usage(format!("{label} is too large")))?;
    if value == 0 {
        return Err(usage(format!("{label} must not be zero")));
    }
    Ok(value)
}

fn parse_path(value: &[u8], max_path: usize) -> Result<Vec<Vec<u8>>, ToolError> {
    let shown = escaped(value);
    if value.first() != Some(&b'/') {
        return Err(usage(format!("PATH is not absolute: {shown}")));
    }
    if value.len() > max_path {
        return Err(usage(format!(
            "PATH is longer than {max_path} bytes: {shown}"
        )));
    }
    if value == b"/" {
        return Ok(Vec::new());
    }
    let mut components = Vec::new();
    for component in value[1..].split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return Err(usage(format!(
                "PATH has an empty, . or .. component: {shown}"
            )));
        }
        components.push(component.to_vec());
    }
    Ok(components)
}

fn output_error(error: io::Error) -> ToolError {
    ToolError::new(
        exit::OUTPUT,
        format!("unable to write the archive: {error}"),
    )
}

fn internal(context: &str, error: io::Error) -> ToolError {
    ToolError::new(exit::INTERNAL, format!("{context}: {error}"))
}

fn changed(shown: &str) -> ToolError {
    ToolError::new(
        exit::CHANGED,
        format!("member changed during export: {shown}"),
    )
}

fn unsupported_kernel() -> ToolError {
    ToolError::new(exit::UNSUPPORTED, "openat2 is not supported by this kernel")
}

fn open_root(root: &CStr) -> Result<OwnedFd, ToolError> {
    // O_PATH: the root is never read through this descriptor; it only anchors the
    // descriptor-relative lookups. O_DIRECTORY with O_NOFOLLOW: a symlink as the final
    // component is refused instead of followed. Its parent directory is root-owned, so the
    // name itself cannot be swapped by the workload.
    // SAFETY: `root` is a valid NUL-terminated string.
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        let shown = root.to_string_lossy();
        return Err(match error.raw_os_error() {
            Some(libc::ENOENT) => {
                ToolError::new(exit::NOT_FOUND, format!("root not found: {shown}"))
            }
            Some(libc::ENOTDIR | libc::ELOOP) => {
                ToolError::new(exit::INVALID, format!("root is not a directory: {shown}"))
            }
            _ => internal(&format!("unable to open root {shown}"), error),
        });
    }
    // SAFETY: `fd` is a freshly opened descriptor owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// `openat2(dir, name)` with the walker's resolution rules; EINTR is retried.
fn openat2(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    let how = OpenHow {
        // O_NOFOLLOW: refuse a symlink as the final component even if the resolve flags were
        // ever relaxed. O_CLOEXEC: nothing executed later inherits tree descriptors.
        flags: u64::from((flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u32),
        mode: 0,
        // BENEATH: resolution can never leave `dir` (absolute names and escaping `..` fail).
        // NO_SYMLINKS: no component may be a symlink, so a swapped-in link fails with ELOOP.
        // NO_MAGICLINKS: /proc-style links cannot jump to arbitrary objects.
        // NO_XDEV: mount points inside the root (bind mounts placed by the host) are never
        // crossed.
        resolve: libc::RESOLVE_BENEATH
            | libc::RESOLVE_NO_SYMLINKS
            | libc::RESOLVE_NO_MAGICLINKS
            | libc::RESOLVE_NO_XDEV,
    };
    loop {
        // SAFETY: `name` is NUL-terminated and `how` is a live open_how of the size passed.
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dir,
                name.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if result >= 0 {
            // SAFETY: the kernel returned a new descriptor owned by nothing else.
            return Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) });
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}

/// `fstatat` without following a final symlink.
fn stat_at(dir: &OwnedFd, name: &CStr) -> io::Result<libc::stat> {
    let mut status = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: valid descriptor, NUL-terminated name and a writable stat buffer.
    let result = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat succeeded and filled the buffer.
    Ok(unsafe { status.assume_init() })
}

fn stat_fd(fd: &OwnedFd) -> io::Result<libc::stat> {
    let mut status = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: valid descriptor and a writable stat buffer.
    if unsafe { libc::fstat(fd.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat succeeded and filled the buffer.
    Ok(unsafe { status.assume_init() })
}

fn same_inode(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// When root: become uid/gid 65534 with no supplementary groups and no capabilities, then
/// set non-dumpable and no-new-privileges. Every step is verified; any failure stops.
fn drop_privileges() -> Result<(), ToolError> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let failed = |step: &str| {
        ToolError::new(
            exit::INTERNAL,
            format!(
                "unable to drop privileges ({step}): {}",
                io::Error::last_os_error()
            ),
        )
    };
    // Supplementary groups first: clearing them needs CAP_SETGID, which the uid change removes.
    // SAFETY: a zero-length list with a null pointer is valid for setgroups.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(failed("setgroups"));
    }
    // Group before user for the same reason. Real, effective and saved ids all change, so the
    // process cannot switch back.
    // SAFETY: plain id arguments.
    if unsafe { libc::setresgid(WORKLOAD_ID, WORKLOAD_ID, WORKLOAD_ID) } != 0 {
        return Err(failed("setresgid"));
    }
    // SAFETY: plain id arguments.
    if unsafe { libc::setresuid(WORKLOAD_ID, WORKLOAD_ID, WORKLOAD_ID) } != 0 {
        return Err(failed("setresuid"));
    }
    let (mut real, mut effective, mut saved) = (0, 0, 0);
    // SAFETY: three writable id slots.
    if unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) } != 0
        || [real, effective, saved] != [WORKLOAD_ID; 3]
    {
        return Err(failed("verify uid"));
    }
    // SAFETY: three writable id slots.
    if unsafe { libc::getresgid(&mut real, &mut effective, &mut saved) } != 0
        || [real, effective, saved] != [WORKLOAD_ID; 3]
    {
        return Err(failed("verify gid"));
    }
    // SAFETY: size 0 with a null list only returns the count.
    if unsafe { libc::getgroups(0, std::ptr::null_mut()) } != 0 {
        return Err(failed("verify groups"));
    }
    // A parent could have set securebits that keep capabilities across the uid change;
    // verify none survived instead of assuming it.
    let mut header = CapabilityHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapabilityData::default(); 2];
    // SAFETY: version-3 header and the two data slots that version requires.
    if unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapabilityHeader,
            data.as_mut_ptr(),
        )
    } != 0
        || data
            .iter()
            .any(|set| set.effective != 0 || set.permitted != 0)
    {
        return Err(failed("verify capabilities"));
    }
    const OFF: libc::c_ulong = 0;
    const ON: libc::c_ulong = 1;
    const UNUSED: libc::c_ulong = 0;
    // Not dumpable: other uid-65534 processes (the workload among them) cannot ptrace this
    // process or open its /proc files to steal its descriptors.
    // SAFETY: prctl with integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, OFF, UNUSED, UNUSED, UNUSED) } != 0 {
        return Err(failed("PR_SET_DUMPABLE"));
    }
    // No new privileges: nothing this process could ever execute regains privileges.
    // SAFETY: prctl with integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, ON, UNUSED, UNUSED, UNUSED) } != 0 {
        return Err(failed("PR_SET_NO_NEW_PRIVS"));
    }
    Ok(())
}

/// Owns a `DIR` stream so it is closed on every path.
struct DirStream(*mut libc::DIR);

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: the stream came from a successful fdopendir and is closed exactly once.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn header(kind: EntryType, status: &libc::stat, size: u64) -> Header {
    let mut header = Header::new_gnu();
    header.set_entry_type(kind);
    // Permission bits only: setuid, setgid and sticky are cleared.
    header.set_mode(status.st_mode & 0o777);
    // Ownership is not exported: uid/gid 0 and empty user/group names (left zeroed), device
    // numbers zero.
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(u64::try_from(status.st_mtime.max(0)).unwrap_or(0));
    header.set_size(size);
    header
}

fn copy_field(field: &mut [u8], value: &[u8]) {
    let length = value.len().min(field.len());
    field[..length].copy_from_slice(&value[..length]);
}

fn read_some(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match file.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

/// Renders caller-controlled bytes for an error message that reaches an operator's terminal.
/// Valid UTF-8 text stays readable; every control character (below 0x20, 0x7f and the C1
/// range), so no ESC sequence survives, and every byte that is not UTF-8 is written as an
/// escape.
pub(crate) fn escaped(bytes: &[u8]) -> String {
    let mut shown = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for character in chunk.valid().chars() {
            if character.is_control() {
                match u8::try_from(u32::from(character)) {
                    Ok(byte) if byte.is_ascii() => shown.push_str(&format!("\\x{byte:02x}")),
                    _ => shown.push_str(&character.escape_unicode().to_string()),
                }
            } else {
                shown.push(character);
            }
        }
        for byte in chunk.invalid() {
            shown.push_str(&format!("\\x{byte:02x}"));
        }
    }
    shown
}

fn shown_path(path: &[u8]) -> String {
    format!("/{}", escaped(path))
}

struct Walker<W: Write> {
    out: tar::Builder<BufWriter<W>>,
    max_bytes: u64,
    max_members: u64,
    max_path: usize,
    bytes: u64,
    members: u64,
}

impl<W: Write> Walker<W> {
    fn export_path(&mut self, root: &OwnedFd, components: &[Vec<u8>]) -> Result<(), ToolError> {
        let (relative, prefix, member) = if components.is_empty() {
            (b".".to_vec(), Vec::new(), b"./".to_vec())
        } else {
            let joined = components.join(&b"/"[..]);
            let mut member = joined.clone();
            member.push(b'/');
            (joined.clone(), joined, member)
        };
        let shown = shown_path(&prefix);
        let relative = CString::new(relative).map_err(|_| usage("PATH contains NUL"))?;
        let directory = openat2(
            root.as_raw_fd(),
            &relative,
            libc::O_DIRECTORY | libc::O_RDONLY,
        )
        .map_err(|error| requested_error(error, &shown))?;
        let status = stat_fd(&directory).map_err(|error| internal(&shown, error))?;
        self.count_member()?;
        self.check_path(&member)?;
        // The requested directory itself is a member; its ancestors are not.
        self.emit(header(EntryType::Directory, &status, 0), &member, None)?;
        self.walk(&directory, &prefix, 1)
    }

    fn walk(&mut self, directory: &OwnedFd, prefix: &[u8], depth: usize) -> Result<(), ToolError> {
        let names = self.read_names(directory, prefix)?;
        for name in names {
            let mut path = prefix.to_vec();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(name.to_bytes());
            let shown = shown_path(&path);
            let seen = stat_at(directory, &name).map_err(|error| {
                if error.raw_os_error() == Some(libc::ENOENT) {
                    changed(&shown)
                } else {
                    internal(&shown, error)
                }
            })?;
            match seen.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    if depth > MAX_DEPTH {
                        return Err(ToolError::new(
                            exit::BOUND,
                            format!("directory depth exceeds {MAX_DEPTH}: {shown}"),
                        ));
                    }
                    let mut member = path.clone();
                    member.push(b'/');
                    self.check_path(&member)?;
                    let child = openat2(
                        directory.as_raw_fd(),
                        &name,
                        libc::O_DIRECTORY | libc::O_RDONLY,
                    )
                    .map_err(|error| walk_error(error, &shown))?;
                    let status = stat_fd(&child).map_err(|error| internal(&shown, error))?;
                    if !same_inode(&seen, &status) {
                        return Err(changed(&shown));
                    }
                    self.emit(header(EntryType::Directory, &status, 0), &member, None)?;
                    self.walk(&child, &path, depth + 1)?;
                }
                libc::S_IFREG => self.emit_file(directory, &name, &path, &shown, &seen)?,
                libc::S_IFLNK => self.emit_symlink(directory, &name, &path, &shown, &seen)?,
                // FIFOs, sockets and device nodes are never opened (a FIFO would block).
                _ => {
                    return Err(ToolError::new(
                        exit::INVALID,
                        format!("unsupported member type: {shown}"),
                    ))
                }
            }
        }
        Ok(())
    }

    /// All names of a directory except `.` and `..`, sorted bytewise. The member bound is
    /// checked while reading, so a huge directory cannot exhaust memory.
    fn read_names(
        &mut self,
        directory: &OwnedFd,
        prefix: &[u8],
    ) -> Result<Vec<CString>, ToolError> {
        let shown = shown_path(prefix);
        // fdopendir takes ownership of its descriptor; a duplicate keeps `directory` usable
        // as the anchor for the following openat2 calls.
        // SAFETY: valid descriptor; F_DUPFD_CLOEXEC returns a new one or -1.
        let copy = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if copy < 0 {
            return Err(internal(&shown, io::Error::last_os_error()));
        }
        // SAFETY: `copy` is an open directory descriptor owned by nothing else.
        let stream = unsafe { libc::fdopendir(copy) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: fdopendir failed, so `copy` is still ours to close.
            unsafe {
                libc::close(copy);
            }
            return Err(internal(&shown, error));
        }
        let stream = DirStream(stream);
        let mut names = Vec::new();
        loop {
            // readdir reports errors only through errno, so clear it first.
            // SAFETY: errno is thread-local.
            unsafe {
                *libc::__errno_location() = 0;
            }
            // SAFETY: the stream is open.
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(0) {
                    return Err(internal(&format!("unable to read {shown}"), error));
                }
                break;
            }
            // SAFETY: readdir returned a valid entry whose d_name is NUL-terminated.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            self.count_member()?;
            names.push(name.to_owned());
        }
        names.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        Ok(names)
    }

    fn emit_file(
        &mut self,
        directory: &OwnedFd,
        name: &CStr,
        path: &[u8],
        shown: &str,
        seen: &libc::stat,
    ) -> Result<(), ToolError> {
        self.check_path(path)?;
        // O_NONBLOCK and O_NOCTTY: if the name was swapped for a FIFO or terminal after the
        // fstatat, the open neither blocks nor acquires a controlling terminal; the type check
        // below then refuses it.
        let fd = openat2(
            directory.as_raw_fd(),
            name,
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
        )
        .map_err(|error| walk_error(error, shown))?;
        let status = stat_fd(&fd).map_err(|error| internal(shown, error))?;
        if status.st_mode & libc::S_IFMT != libc::S_IFREG || !same_inode(seen, &status) {
            return Err(changed(shown));
        }
        let size = u64::try_from(status.st_size).map_err(|_| changed(shown))?;
        // Counted before the header is written, so the bound holds for the whole stream.
        // Each hard-linked name counts again: it is emitted as its own regular member.
        self.bytes = self
            .bytes
            .checked_add(size)
            .filter(|total| *total <= self.max_bytes)
            .ok_or_else(|| {
                ToolError::new(
                    exit::BOUND,
                    format!("export exceeds {} bytes at {shown}", self.max_bytes),
                )
            })?;
        self.emit(header(EntryType::Regular, &status, size), path, None)?;
        let mut file = File::from(fd);
        let mut buffer = vec![0u8; COPY_BUFFER];
        let mut remaining = size;
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(COPY_BUFFER as u64)).unwrap_or(COPY_BUFFER);
            let count = read_some(&mut file, &mut buffer[..wanted])
                .map_err(|error| internal(&format!("unable to read {shown}"), error))?;
            if count == 0 {
                // Shrank after fstat.
                return Err(changed(shown));
            }
            self.out
                .get_mut()
                .write_all(&buffer[..count])
                .map_err(output_error)?;
            remaining -= count as u64;
        }
        let mut extra = [0u8; 1];
        if read_some(&mut file, &mut extra)
            .map_err(|error| internal(&format!("unable to read {shown}"), error))?
            != 0
        {
            // Grew after fstat.
            return Err(changed(shown));
        }
        let padding = ((BLOCK - size % BLOCK) % BLOCK) as usize;
        self.out
            .get_mut()
            .write_all(&[0u8; BLOCK as usize][..padding])
            .map_err(output_error)
    }

    fn emit_symlink(
        &mut self,
        directory: &OwnedFd,
        name: &CStr,
        path: &[u8],
        shown: &str,
        seen: &libc::stat,
    ) -> Result<(), ToolError> {
        self.check_path(path)?;
        let mut buffer = [0u8; LINK_BUFFER];
        // The link is read by name relative to its directory and never followed.
        // SAFETY: valid descriptor, NUL-terminated name, writable buffer of the given size.
        let length = unsafe {
            libc::readlinkat(
                directory.as_raw_fd(),
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if length < 0 {
            let error = io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                // No longer a symlink, or gone.
                Some(libc::EINVAL | libc::ENOENT) => changed(shown),
                _ => internal(shown, error),
            });
        }
        let length = length as usize;
        if length >= LINK_BUFFER {
            return Err(ToolError::new(
                exit::BOUND,
                format!("symlink target is {LINK_BUFFER} bytes or longer: {shown}"),
            ));
        }
        if i64::try_from(length).ok() != Some(seen.st_size) {
            return Err(changed(shown));
        }
        self.emit(
            header(EntryType::Symlink, seen, 0),
            path,
            Some(&buffer[..length]),
        )
    }

    fn count_member(&mut self) -> Result<(), ToolError> {
        self.members += 1;
        if self.members > self.max_members {
            return Err(ToolError::new(
                exit::BOUND,
                format!("export exceeds {} members", self.max_members),
            ));
        }
        Ok(())
    }

    fn check_path(&self, member: &[u8]) -> Result<(), ToolError> {
        if member.len() > self.max_path {
            return Err(ToolError::new(
                exit::BOUND,
                format!(
                    "member path is longer than {} bytes: {}",
                    self.max_path,
                    escaped(member)
                ),
            ));
        }
        Ok(())
    }

    /// Writes one header. Names and link targets are copied byte for byte (the `tar` crate's
    /// path helpers would normalize `a/./b` or `a//b` in link targets); values of 100 bytes
    /// or more are preceded by GNU LongName (`L`) or LongLink (`K`) records.
    fn emit(
        &mut self,
        mut header: Header,
        name: &[u8],
        link: Option<&[u8]>,
    ) -> Result<(), ToolError> {
        if name.len() >= NAME_FIELD {
            self.long_record(b'L', name)?;
        }
        copy_field(&mut header.as_old_mut().name, name);
        if let Some(link) = link {
            if link.len() >= NAME_FIELD {
                self.long_record(b'K', link)?;
            }
            copy_field(&mut header.as_old_mut().linkname, link);
        }
        header.set_cksum();
        self.out.append(&header, io::empty()).map_err(output_error)
    }

    fn long_record(&mut self, kind: u8, value: &[u8]) -> Result<(), ToolError> {
        let mut header = Header::new_gnu();
        copy_field(&mut header.as_old_mut().name, b"././@LongLink");
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(value.len() as u64 + 1);
        header.set_entry_type(EntryType::new(kind));
        header.set_cksum();
        self.out
            .append(&header, value.chain(&b"\0"[..]))
            .map_err(output_error)
    }
}

/// Errors opening a requested PATH below the root.
fn requested_error(error: io::Error, shown: &str) -> ToolError {
    match error.raw_os_error() {
        Some(libc::ENOSYS) => unsupported_kernel(),
        Some(libc::ELOOP) => {
            ToolError::new(exit::INVALID, format!("symlink in requested path: {shown}"))
        }
        Some(libc::ENOENT) => ToolError::new(
            exit::NOT_FOUND,
            format!("requested path not found: {shown}"),
        ),
        Some(libc::ENOTDIR) => ToolError::new(
            exit::INVALID,
            format!("requested path is not a directory: {shown}"),
        ),
        Some(libc::EXDEV) => ToolError::new(
            exit::INVALID,
            format!("requested path crosses a mount point: {shown}"),
        ),
        Some(libc::EACCES | libc::EPERM) => {
            ToolError::new(exit::INVALID, format!("permission denied: {shown}"))
        }
        // Kernel reports a concurrent rename it could not prove safe: retryable.
        Some(libc::EAGAIN) => changed(shown),
        _ => internal(&format!("unable to open {shown}"), error),
    }
}

/// Errors opening a member that `fstatat` just reported as a directory or regular file.
fn walk_error(error: io::Error, shown: &str) -> ToolError {
    match error.raw_os_error() {
        Some(libc::ENOSYS) => unsupported_kernel(),
        Some(libc::EXDEV) => ToolError::new(
            exit::INVALID,
            format!("mount point inside the exported tree: {shown}"),
        ),
        Some(libc::EACCES | libc::EPERM) => {
            ToolError::new(exit::INVALID, format!("permission denied: {shown}"))
        }
        // Replaced by a symlink, removed, replaced by a non-directory, replaced by a socket,
        // or a concurrent rename: the name no longer denotes what fstatat saw.
        Some(libc::ELOOP | libc::ENOENT | libc::ENOTDIR | libc::ENXIO | libc::EAGAIN) => {
            changed(shown)
        }
        _ => internal(&format!("unable to open {shown}"), error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn names_in_error_text_are_escaped() {
        let name = b"a\x1b]52;c;x\x07\x7f\xc2\x9b\xff caf\xc3\xa9";
        let shown = escaped(name);
        assert_eq!(shown, "a\\x1b]52;c;x\\x07\\x7f\\u{9b}\\xff café");
        assert!(!shown.chars().any(char::is_control));
        assert_eq!(shown_path(b"x\x1b[2J"), "/x\\x1b[2J");
        // An error built from a hostile path carries no raw control byte.
        let error = parse_path(b"relative\x1b]52;c;x\x07", 4096).unwrap_err();
        assert!(error.message.contains("relative\\x1b]52;c;x\\x07"));
        // The usage line after the reason is fixed text; the reason itself is clean.
        let reason = error.message.lines().next().unwrap();
        assert!(!reason.chars().any(char::is_control));
    }

    struct TempTree(PathBuf);

    impl TempTree {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ginux-oci-export-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(path.join("root")).unwrap();
            Self(path)
        }

        fn root(&self) -> PathBuf {
            self.0.join("root")
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn arguments(root: &Path, bounds: [&str; 3], paths: &[&str]) -> Vec<OsString> {
        let mut arguments = vec![root.as_os_str().to_owned()];
        arguments.extend(bounds.iter().map(OsString::from));
        arguments.extend(paths.iter().map(OsString::from));
        arguments
    }

    fn export(root: &Path, bounds: [&str; 3], paths: &[&str]) -> Result<Vec<u8>, ToolError> {
        let mut output = Vec::new();
        export_tree(&arguments(root, bounds, paths), &mut output, false)?;
        Ok(output)
    }

    const WIDE: [&str; 3] = ["1000000", "1000", "4096"];

    struct Member {
        path: Vec<u8>,
        kind: EntryType,
        mode: u32,
        uid: u64,
        gid: u64,
        link: Option<Vec<u8>>,
        data: Vec<u8>,
    }

    fn members(bytes: &[u8]) -> Vec<Member> {
        let mut archive = tar::Archive::new(bytes);
        archive
            .entries()
            .unwrap()
            .map(|entry| {
                let mut entry = entry.unwrap();
                let mut data = Vec::new();
                let header = entry.header().clone();
                let path = entry.path_bytes().into_owned();
                let link = entry.link_name_bytes().map(|link| link.into_owned());
                entry.read_to_end(&mut data).unwrap();
                Member {
                    path,
                    kind: header.entry_type(),
                    mode: header.mode().unwrap(),
                    uid: header.uid().unwrap(),
                    gid: header.gid().unwrap(),
                    link,
                    data,
                }
            })
            .collect()
    }

    fn names(bytes: &[u8]) -> Vec<String> {
        members(bytes)
            .into_iter()
            .map(|member| String::from_utf8(member.path).unwrap())
            .collect()
    }

    fn code(result: Result<Vec<u8>, ToolError>) -> u8 {
        result.expect_err("export should fail").code
    }

    #[test]
    fn identical_trees_give_identical_bytes_in_sorted_order() {
        let tree = TempTree::new("deterministic");
        let root = tree.root();
        fs::create_dir_all(root.join("out/b")).unwrap();
        fs::write(root.join("out/c"), b"cee").unwrap();
        fs::write(root.join("out/a"), b"a").unwrap();
        fs::write(root.join("out/b/inner"), vec![7u8; 1500]).unwrap();
        fs::create_dir_all(root.join("other")).unwrap();
        fs::write(root.join("other/x"), b"x").unwrap();
        let first = export(&root, WIDE, &["/out"]).unwrap();
        let second = export(&root, WIDE, &["/out"]).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            names(&first),
            ["out/", "out/a", "out/b/", "out/b/inner", "out/c"]
        );
        let listed = members(&first);
        assert_eq!(listed[3].data, vec![7u8; 1500]);
        assert!(listed
            .iter()
            .all(|member| member.uid == 0 && member.gid == 0));
    }

    #[test]
    fn requested_paths_are_sorted_deduplicated_and_nested_ones_dropped() {
        let tree = TempTree::new("requests");
        let root = tree.root();
        fs::create_dir_all(root.join("b/inner")).unwrap();
        fs::create_dir_all(root.join("a")).unwrap();
        let bytes = export(&root, WIDE, &["/b", "/a", "/b/inner", "/a"]).unwrap();
        assert_eq!(names(&bytes), ["a/", "b/", "b/inner/"]);
        let whole = export(&root, WIDE, &["/", "/a"]).unwrap();
        assert_eq!(names(&whole), ["./", "a/", "b/", "b/inner/"]);
    }

    #[test]
    fn setuid_setgid_and_sticky_bits_are_cleared() {
        let tree = TempTree::new("modes");
        let root = tree.root();
        fs::create_dir_all(root.join("out/sticky")).unwrap();
        fs::write(root.join("out/tool"), b"#!").unwrap();
        fs::set_permissions(root.join("out/tool"), fs::Permissions::from_mode(0o6755)).unwrap();
        fs::set_permissions(root.join("out/sticky"), fs::Permissions::from_mode(0o1777)).unwrap();
        let listed = members(&export(&root, WIDE, &["/out"]).unwrap());
        let tool = listed.iter().find(|m| m.path == b"out/tool").unwrap();
        assert_eq!(tool.mode, 0o755);
        let sticky = listed.iter().find(|m| m.path == b"out/sticky/").unwrap();
        assert_eq!(sticky.mode, 0o777);
    }

    #[test]
    fn symlinks_are_emitted_as_links_and_never_followed() {
        let tree = TempTree::new("symlink");
        let root = tree.root();
        fs::create_dir_all(root.join("out")).unwrap();
        symlink("/etc/passwd", root.join("out/passwd")).unwrap();
        symlink("a/./b//c", root.join("out/odd")).unwrap();
        let listed = members(&export(&root, WIDE, &["/out"]).unwrap());
        let passwd = listed.iter().find(|m| m.path == b"out/passwd").unwrap();
        assert_eq!(passwd.kind, EntryType::Symlink);
        assert_eq!(passwd.link.as_deref(), Some(&b"/etc/passwd"[..]));
        assert!(passwd.data.is_empty());
        let odd = listed.iter().find(|m| m.path == b"out/odd").unwrap();
        assert_eq!(odd.link.as_deref(), Some(&b"a/./b//c"[..]));
    }

    #[test]
    fn symlink_component_in_requested_path_is_refused() {
        let tree = TempTree::new("requested-link");
        let root = tree.root();
        fs::create_dir_all(root.join("real/sub")).unwrap();
        symlink("real", root.join("link")).unwrap();
        assert_eq!(code(export(&root, WIDE, &["/link"])), exit::INVALID);
        assert_eq!(code(export(&root, WIDE, &["/link/sub"])), exit::INVALID);
        let outside = TempTree::new("requested-link-target");
        symlink(outside.root(), root.join("escape")).unwrap();
        assert_eq!(code(export(&root, WIDE, &["/escape"])), exit::INVALID);
    }

    #[test]
    fn missing_and_non_directory_requests_fail() {
        let tree = TempTree::new("requested-kind");
        let root = tree.root();
        fs::write(root.join("file"), b"x").unwrap();
        assert_eq!(code(export(&root, WIDE, &["/absent"])), exit::NOT_FOUND);
        assert_eq!(code(export(&root, WIDE, &["/file"])), exit::INVALID);
        assert_eq!(code(export(&root, WIDE, &["/file/below"])), exit::INVALID);
        assert_eq!(
            code(export(&tree.0.join("absent"), WIDE, &["/"])),
            exit::NOT_FOUND
        );
        let link = tree.0.join("root-link");
        symlink(&root, &link).unwrap();
        assert_eq!(code(export(&link, WIDE, &["/"])), exit::INVALID);
    }

    #[test]
    fn special_files_fail_without_blocking() {
        let tree = TempTree::new("fifo");
        let root = tree.root();
        fs::create_dir_all(root.join("out")).unwrap();
        let fifo = CString::new(root.join("out/pipe").as_os_str().as_bytes()).unwrap();
        // SAFETY: valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let error = export(&root, WIDE, &["/out"]).unwrap_err();
        assert_eq!(error.code, exit::INVALID);
        assert!(error.message.contains("unsupported member type: /out/pipe"));

        let tree = TempTree::new("socket");
        let root = tree.root();
        fs::create_dir_all(root.join("out")).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(root.join("out/socket")).unwrap();
        assert_eq!(code(export(&root, WIDE, &["/out"])), exit::INVALID);
    }

    #[test]
    fn every_bound_fails_with_its_own_code() {
        let tree = TempTree::new("bounds");
        let root = tree.root();
        fs::create_dir_all(root.join("out/dir")).unwrap();
        fs::write(root.join("out/big"), vec![1u8; 100]).unwrap();
        fs::write(root.join("out/dir/a-long-file-name"), b"x").unwrap();
        // Bytes: 101 bytes in total, limit 100.
        assert_eq!(
            code(export(&root, ["100", "1000", "4096"], &["/out"])),
            exit::BOUND
        );
        assert!(export(&root, ["101", "1000", "4096"], &["/out"]).is_ok());
        // Members: out/, big, dir/, dir/a-long-file-name = 4.
        assert_eq!(
            code(export(&root, ["1000", "3", "4096"], &["/out"])),
            exit::BOUND
        );
        assert!(export(&root, ["1000", "4", "4096"], &["/out"]).is_ok());
        // Path: "out/dir/a-long-file-name" is 24 bytes.
        assert_eq!(
            code(export(&root, ["1000", "1000", "23"], &["/out"])),
            exit::BOUND
        );
        assert!(export(&root, ["1000", "1000", "24"], &["/out"]).is_ok());
        // Depth: 256 directories below the requested one pass, 257 fail.
        let deep = TempTree::new("depth");
        let root = deep.root();
        let mut path = root.join("out");
        for _ in 0..MAX_DEPTH {
            path.push("d");
        }
        fs::create_dir_all(&path).unwrap();
        assert!(export(&root, WIDE, &["/out"]).is_ok());
        fs::create_dir(path.join("d")).unwrap();
        assert_eq!(code(export(&root, WIDE, &["/out"])), exit::BOUND);
    }

    #[test]
    fn hard_links_become_separate_regular_members() {
        let tree = TempTree::new("hardlink");
        let root = tree.root();
        fs::create_dir_all(root.join("out")).unwrap();
        fs::write(root.join("out/one"), b"shared").unwrap();
        fs::hard_link(root.join("out/one"), root.join("out/two")).unwrap();
        let bytes = export(&root, WIDE, &["/out"]).unwrap();
        let listed = members(&bytes);
        for name in [&b"out/one"[..], b"out/two"] {
            let member = listed.iter().find(|m| m.path == name).unwrap();
            assert_eq!(member.kind, EntryType::Regular);
            assert_eq!(member.data, b"shared");
        }
        assert!(listed.iter().all(|m| m.kind != EntryType::Link));
        // The shared bytes count twice against the byte bound.
        assert_eq!(
            code(export(&root, ["11", "1000", "4096"], &["/out"])),
            exit::BOUND
        );
    }

    #[test]
    fn long_names_and_link_targets_round_trip() {
        let tree = TempTree::new("long");
        let root = tree.root();
        let long_directory = "d".repeat(150);
        let long_file = "f".repeat(200);
        let directory = root.join("out").join(&long_directory);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(&long_file), b"long").unwrap();
        let target = format!("../{}", "t/".repeat(150));
        symlink(&target, directory.join("link")).unwrap();
        let exactly_hundred = "e".repeat(100 - "out/".len());
        fs::write(root.join("out").join(&exactly_hundred), b"edge").unwrap();
        let listed = members(&export(&root, WIDE, &["/out"]).unwrap());
        let file_path = format!("out/{long_directory}/{long_file}");
        let file = listed
            .iter()
            .find(|m| m.path == file_path.as_bytes())
            .unwrap();
        assert_eq!(file.data, b"long");
        assert!(listed
            .iter()
            .any(|m| m.path == format!("out/{long_directory}/").as_bytes()));
        let link = listed
            .iter()
            .find(|m| m.path == format!("out/{long_directory}/link").as_bytes())
            .unwrap();
        assert_eq!(link.link.as_deref(), Some(target.as_bytes()));
        let edge = listed
            .iter()
            .find(|m| m.path == format!("out/{exactly_hundred}").as_bytes())
            .unwrap();
        assert_eq!(edge.data, b"edge");
    }

    struct BrokenPipe;

    impl Write for BrokenPipe {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn output_errors_fail_with_74() {
        let tree = TempTree::new("epipe");
        let root = tree.root();
        fs::create_dir_all(root.join("out")).unwrap();
        fs::write(root.join("out/big"), vec![0u8; 200_000]).unwrap();
        let error = export_tree(&arguments(&root, WIDE, &["/out"]), BrokenPipe, false).unwrap_err();
        assert_eq!(error.code, exit::OUTPUT);
        fs::remove_file(root.join("out/big")).unwrap();
        // Small output fails at the final flush.
        let error = export_tree(&arguments(&root, WIDE, &["/out"]), BrokenPipe, false).unwrap_err();
        assert_eq!(error.code, exit::OUTPUT);
    }

    #[test]
    fn malformed_arguments_are_usage_errors() {
        let tree = TempTree::new("usage");
        let root = tree.root();
        fs::create_dir_all(root.join("out")).unwrap();
        for (bounds, paths) in [
            (WIDE, &[][..]),
            (["0", "1", "1"], &["/out"][..]),
            (["1x", "1", "1"], &["/out"][..]),
            (["+1", "1", "1"], &["/out"][..]),
            (["99999999999999999999999", "1", "1"], &["/out"][..]),
            (WIDE, &["out"][..]),
            (WIDE, &["/out/"][..]),
            (WIDE, &["/out//x"][..]),
            (WIDE, &["/out/../etc"][..]),
            (WIDE, &["/./out"][..]),
            (["10", "10", "3"], &["/out"][..]),
        ] {
            assert_eq!(
                code(export(&root, bounds, paths)),
                exit::USAGE,
                "{bounds:?} {paths:?}"
            );
        }
        let mut output = Vec::new();
        assert_eq!(
            export_tree(&[OsString::from("/")], &mut output, false)
                .unwrap_err()
                .code,
            exit::USAGE
        );
    }

    #[test]
    fn failed_export_writes_no_end_of_archive_marker() {
        let tree = TempTree::new("no-trailer");
        let root = tree.root();
        fs::create_dir_all(root.join("out")).unwrap();
        fs::write(root.join("out/a"), b"a").unwrap();
        let fifo = CString::new(root.join("out/z").as_os_str().as_bytes()).unwrap();
        // SAFETY: valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let mut output = Vec::new();
        assert!(export_tree(&arguments(&root, WIDE, &["/out"]), &mut output, false).is_err());
        assert!(output.is_empty());
    }
}
