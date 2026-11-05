//! Configured-launch ephemeral memory storage. Bytes and descriptors belong to
//! the supervisor; no writable host descriptor is installed in the workload.
//! Directory descriptions and executable references share the VFS owner.
//! Retained storage is not provided. File mappings use the supervised backing
//! transfer in file_mapping; writable shared mappings remain unsupported.

use crate::storage_memory::MemoryStorage;
use crate::supervisor::UserRegs;
use crate::tracee_io::{copy_memory, read_path};
use core::sync::atomic::{AtomicBool, Ordering};
use ginux_domain::{DomainConfig, Text};
use ginux_vfs::{
    BaseReader, Entry, Executable, FileMetadata, Index, NodeKind, VfsError, VirtualFs, HEADER_SIZE,
    MAX_PATH, O_APPEND, O_CLOEXEC, O_CREATE, O_EXCLUSIVE, O_NONBLOCK, O_READ, O_TRUNC, O_WRITE,
    RECORD_SIZE,
};

pub const FD_BASE: usize = 1 << 20;
const IO_SIZE: usize = 4096;
type Path = Text<MAX_PATH>;
pub(crate) const OBJECTS: usize = 4096;
type MemoryFs = VirtualFs<'static, EmptyReader, OBJECTS, 0, 64, MemoryStorage<OBJECTS>>;
static mut ROOT_INDEX: [u8; HEADER_SIZE + RECORD_SIZE] = [0; HEADER_SIZE + RECORD_SIZE];
static ROOT_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub struct EmptyReader;
impl BaseReader for EmptyReader {
    fn read_at(&mut self, _: u64, _: &mut [u8]) -> Result<(), VfsError> {
        Err(VfsError::Io)
    }
}

pub struct RestoreEntry<'a> {
    pub path: &'a [u8],
    pub kind: NodeKind,
    pub link: &'a [u8],
    pub mode: u32,
    pub length: usize,
}

pub struct LaunchFs {
    fs: MemoryFs,
    prefixes: [Path; 8],
    count: usize,
    cwd: Option<i32>,
}

impl LaunchFs {
    /// Called once, before fork. Assignments are domain paths, never host paths.
    pub fn prepare(config: &DomainConfig) -> Result<Self, &'static [u8]> {
        let mut prefixes = [Path::empty(); 8];
        let mut count = 0;
        for assignment in config.storage.as_slice() {
            let path = assignment
                .as_bytes()
                .strip_prefix(b"memory:")
                .ok_or(b"unsupported launch storage assignment".as_slice())?;
            if path.len() < 2
                || path[0] != b'/'
                || path.ends_with(b"/")
                || path
                    .split(|b| *b == b'/')
                    .skip(1)
                    .any(|p| p.is_empty() || p == b"." || p == b"..")
                || [b"/proc".as_slice(), b"/sys", b"/dev"]
                    .iter()
                    .any(|r| within(path, r) || within(r, path))
                || within(config.init.as_bytes(), path)
                || within(path, config.init.as_bytes())
                || prefixes[..count].iter().any(|p| p.as_bytes() == path)
            {
                return Err(b"invalid launch memory-storage path");
            }
            prefixes[count] =
                Path::from_bytes(path).map_err(|_| b"storage path exceeds bound".as_slice())?;
            count += 1;
        }
        // Root-only index: writable opens cannot copy image files into memory.
        // Never mutate the static index while any existing view can borrow it.
        if ROOT_INITIALIZED.swap(true, Ordering::Relaxed) {
            return Err(b"launch filesystem already initialized");
        }
        let index_bytes = unsafe { &mut *core::ptr::addr_of_mut!(ROOT_INDEX) };
        let (header, record) = index_bytes.split_at_mut(HEADER_SIZE);
        ginux_vfs::encode_header(1, header.try_into().unwrap());
        ginux_vfs::encode_record(
            Entry {
                path: b"/",
                kind: NodeKind::Directory,
                mode: 0o755,
                uid: 0,
                gid: 0,
                size: 0,
                data_offset: 0,
                link: b"",
            },
            record.try_into().unwrap(),
        )
        .map_err(|_| b"invalid storage root index".as_slice())?;
        let mut fs = MemoryFs::with_storage(
            Index::new(index_bytes).map_err(|_| b"invalid storage root index".as_slice())?,
            EmptyReader,
            MemoryStorage::new((config.memory_mib as usize) * 1024 * 1024),
        );
        for prefix in &prefixes[..count] {
            let path = prefix.as_bytes();
            for end in 1..=path.len() {
                if end == path.len() || path[end] == b'/' {
                    match fs.mkdir(&path[..end], 0o755) {
                        Ok(()) | Err(VfsError::AlreadyExists) => {}
                        Err(_) => return Err(b"memory storage directory capacity exceeded"),
                    }
                }
            }
        }
        Ok(Self {
            fs,
            prefixes,
            count,
            cwd: None,
        })
    }

    pub fn enabled(&self) -> bool {
        self.count != 0
    }

    pub fn restore_entry(
        &mut self,
        entry: RestoreEntry<'_>,
        seen: &mut [bool; OBJECTS],
        mut read: impl FnMut(&mut [u8]) -> Result<(), &'static [u8]>,
    ) -> Result<(), &'static [u8]> {
        let RestoreEntry {
            path,
            kind,
            link,
            mode,
            length,
        } = entry;
        let directory = kind == NodeKind::Directory;
        let canonical = normalize(b"/", path).map_err(|_| b"invalid restore path".as_slice())?;
        if canonical.as_bytes() != path
            || (!self.owns_path(path)
                && !(directory
                    && self.prefixes[..self.count]
                        .iter()
                        .any(|p| within(p.as_bytes(), path))))
        {
            return Err(b"restore path is outside assigned storage");
        }
        // Entries may precede their parents in the overlay's slot order.
        for end in 1..path.len() {
            if path[end] == b'/' {
                match self.fs.mkdir(&path[..end], 0o755) {
                    Ok(()) | Err(VfsError::AlreadyExists) => {}
                    Err(_) => return Err(b"restore parent creation failed"),
                }
                if self
                    .fs
                    .metadata_no_follow(&path[..end])
                    .map_err(|_| b"restore parent lookup failed".as_slice())?
                    .kind
                    != NodeKind::Directory
                {
                    return Err(b"restore parent is not a directory");
                }
            }
        }
        if directory {
            match self.fs.mkdir(path, mode) {
                Ok(()) | Err(VfsError::AlreadyExists) => {}
                Err(_) => return Err(b"restore directory creation failed"),
            }
            if self
                .fs
                .metadata_no_follow(path)
                .map_err(|_| b"restore directory lookup failed".as_slice())?
                .kind
                != NodeKind::Directory
            {
                return Err(b"restore directory collides with file");
            }
            self.fs
                .chmod(path, mode)
                .map_err(|_| b"restore directory mode failed".as_slice())?;
        } else if kind == NodeKind::Symlink {
            self.fs
                .symlink(link, path)
                .map_err(|_| b"restore link creation failed".as_slice())?;
        } else {
            let fd = self
                .fs
                .open(path, O_WRITE | O_CREATE | O_EXCLUSIVE)
                .map_err(|_| b"restore file creation failed".as_slice())?;
            let result = (|| {
                self.fs
                    .truncate(fd, length as u64)
                    .map_err(|_| b"restore storage bound exceeded".as_slice())?;
                let mut bytes = [0u8; IO_SIZE];
                let mut offset = 0;
                while offset < length {
                    let count = (length - offset).min(bytes.len());
                    read(&mut bytes[..count])?;
                    if self
                        .fs
                        .write(fd, &bytes[..count])
                        .map_err(|_| b"restore file write failed".as_slice())?
                        != count
                    {
                        return Err(b"restore file short write".as_slice());
                    }
                    offset += count;
                }
                self.fs
                    .fchmod(fd, mode)
                    .map_err(|_| b"restore file mode failed".as_slice())
            })();
            let closed = self.fs.close(fd);
            result?;
            closed.map_err(|_| b"restore file close failed".as_slice())?;
        }
        // This launch view has a one-entry immutable root; live owned inode
        // numbers are stable slot+2 for the duration of startup import.
        let inode = self
            .fs
            .metadata_no_follow(path)
            .map_err(|_| b"restore entry lookup failed".as_slice())?
            .inode;
        let slot = inode
            .checked_sub(2)
            .filter(|slot| *slot < OBJECTS as u64)
            .ok_or(b"invalid restored inode".as_slice())? as usize;
        if seen[slot] {
            return Err(b"duplicate restore entry");
        }
        seen[slot] = true;
        Ok(())
    }

    pub fn export(&self) -> Result<(), &'static [u8]> {
        crate::storage_export::finish(|archive| self.write_archive(archive))
    }

    pub fn snapshot(&self, path: *const u8) -> Result<(), &'static [u8]> {
        crate::storage_export::capture(path, |archive| self.write_archive(archive))
    }

    fn write_archive(
        &self,
        archive: &mut crate::storage_export::Archive,
    ) -> Result<(), &'static [u8]> {
        for slot in 0..OBJECTS {
            if let Some((path, metadata)) = self.fs.overlay_entry(slot) {
                archive.entry(path, metadata, |offset, buffer| {
                    self.fs
                        .read_overlay(slot, offset, buffer)
                        .map_err(|_| b"export read failed".as_slice())
                })?;
            }
        }
        Ok(())
    }

    pub fn teardown(&mut self) {
        assert_eq!(
            self.fs.executable_pins(),
            0,
            "overlay teardown retained executable references"
        );
        self.fs.teardown();
        assert_eq!(
            self.fs.storage().allocated_bytes(),
            0,
            "overlay teardown retained bytes"
        );
    }

    pub fn readiness(&self, handle: u32) -> Option<u16> {
        let slot = handle.checked_sub(FD_BASE as u32)?;
        if slot >= 64 {
            return None;
        }
        // This owner contains only regular memory files and directories.
        self.fs.fstat(slot as i32 + 3).ok().map(|_| 0x145)
    }

    fn owns_path(&self, path: &[u8]) -> bool {
        self.prefixes[..self.count]
            .iter()
            .any(|p| within(path, p.as_bytes()))
    }

    // Stop lexical normalization as soon as traversal enters owned storage.
    // Everything after that point must be interpreted by the VFS, including ..
    // after a symlink. Never route a failed owned lookup into the image.
    fn routed_path(&self, base: &[u8], name: &[u8]) -> Result<Path, i64> {
        let mut raw = [0; MAX_PATH];
        let mut length = 0;
        if name.first() != Some(&b'/') {
            let n = base.len();
            raw[..n].copy_from_slice(base);
            length = n;
            if length > 1 {
                if length == MAX_PATH {
                    return Err(-36);
                }
                raw[length] = b'/';
                length += 1;
            }
        }
        if length + name.len() > MAX_PATH {
            return Err(-36);
        }
        raw[length..length + name.len()].copy_from_slice(name);
        length += name.len();
        for end in 1..=length {
            if end == length || raw[end] == b'/' {
                let prefix = normalize(b"/", &raw[..end])?;
                if self.owns_path(prefix.as_bytes()) {
                    let mut joined = [0; MAX_PATH];
                    let n = prefix.as_bytes().len();
                    let size = n + length - end;
                    if size > MAX_PATH {
                        return Err(-36);
                    }
                    joined[..n].copy_from_slice(prefix.as_bytes());
                    joined[n..size].copy_from_slice(&raw[end..length]);
                    return Path::from_bytes(&joined[..size]).map_err(|_| -36);
                }
            }
        }
        normalize(b"/", &raw[..length])
    }

    fn mutation_path(&self, path: &[u8], missing: bool) -> Result<Path, i64> {
        let mut bytes = [0; MAX_PATH];
        let n = self
            .fs
            .canonical_namespace_path(path, missing, &mut bytes)
            .map_err(errno)?;
        if !self.owns_path(&bytes[..n]) {
            return Err(-95);
        }
        Path::from_bytes(&bytes[..n]).map_err(|_| -36)
    }

    fn owned_path(&self, path: &[u8], follow: bool, missing: bool) -> Result<Path, i64> {
        let mut bytes = [0; MAX_PATH];
        let n = self
            .fs
            .canonical_path(path, follow, missing, &mut bytes)
            .map_err(errno)?;
        if !self.owns_path(&bytes[..n]) {
            return Err(-95);
        }
        Path::from_bytes(&bytes[..n]).map_err(|_| -36)
    }

    pub(crate) fn path(&self, pid: usize, address: u64, dirfd: u64) -> Result<Path, i64> {
        let text = read_path(pid, address)?;
        if text.is_empty() {
            return Err(-2);
        }
        let absolute = text.as_bytes().first() == Some(&b'/');
        let cwd;
        let base = if absolute {
            b"/".as_slice()
        } else if dirfd as i32 == -100 {
            cwd = self.cwd_path(pid)?;
            cwd.as_bytes()
        } else {
            let fd = (dirfd as u32)
                .checked_sub(FD_BASE as u32)
                .filter(|n| *n < 64)
                .ok_or(-9)?;
            self.fs.directory_path(fd as i32 + 3).map_err(errno)?
        };
        let path = self.routed_path(base, text.as_bytes())?;
        if !absolute && dirfd as i32 != -100 && !self.owns_path(path.as_bytes()) {
            // The image does not share this directory descriptor. Never pass
            // the private integer to a native open outside assigned storage.
            return Err(-95);
        }
        Ok(path)
    }

    // Selected by the task owner before each entry. Threads share their
    // process cwd, while fork owns a separate reference to the same directory.
    pub fn select_cwd(&mut self, descriptor: Option<i32>) {
        self.cwd = descriptor;
    }

    pub fn cwd_path(&self, pid: usize) -> Result<Path, i64> {
        match self.cwd {
            Some(fd) => {
                Path::from_bytes(self.fs.directory_path(fd).map_err(errno)?).map_err(|_| -36)
            }
            None => crate::tracee_io::image_cwd(pid),
        }
    }

    pub fn copy_cwd(&mut self, fd: i32) -> Result<i32, i64> {
        self.fs.duplicate(fd, false).map_err(errno)
    }

    pub fn close_cwd(&mut self, fd: i32) -> Result<(), i64> {
        self.fs.close(fd).map_err(errno)
    }

    pub fn descriptor_cwd(&mut self, handle: u32) -> Result<i32, i64> {
        let fd = handle
            .checked_sub(FD_BASE as u32)
            .filter(|n| *n < 64)
            .ok_or(-20)? as i32
            + 3;
        self.fs.directory_path(fd).map_err(errno)?;
        self.copy_cwd(fd)
    }

    /// Owned cwd changes never enter the image directory hidden by storage.
    /// An image change is committed only after its native syscall succeeds.
    pub fn chdir(&mut self, pid: usize, address: u64) -> Result<Option<i32>, i64> {
        let path = self.path(pid, address, (-100i64) as u64)?;
        if self.owns_path(path.as_bytes()) {
            let path = self.owned_path(path.as_bytes(), true, false)?;
            return self
                .fs
                .open_directory(path.as_bytes(), 0)
                .map(Some)
                .map_err(errno);
        }
        if [b"/dev".as_slice(), b"/proc", b"/sys"]
            .iter()
            .any(|p| within(path.as_bytes(), p))
        {
            return Err(-13);
        }
        if self.cwd.is_some() && read_path(pid, address)?.as_bytes().first() != Some(&b'/') {
            return Err(-95);
        }
        Ok(None)
    }

    pub fn getcwd(&self, pid: usize, address: u64, capacity: u64) -> Result<i64, i64> {
        let path = self.cwd_path(pid)?;
        let n = path.as_bytes().len();
        if capacity == 0 {
            return Err(-22);
        }
        if capacity <= n as u64 {
            return Err(-34);
        }
        let mut bytes = [0; MAX_PATH + 1];
        bytes[..n].copy_from_slice(path.as_bytes());
        if copy_memory(pid, address, &mut bytes[..n + 1], true)? != (n + 1) as i64 {
            return Err(-14);
        }
        Ok((n + 1) as i64)
    }

    /// Assigned paths yield pinned program bytes; image paths retain the native
    /// readonly loader. Neither may fall through into the other's namespace.
    pub fn exec_path(
        &mut self,
        pid: usize,
        address: u64,
        dirfd: u64,
    ) -> Result<Option<Executable>, i64> {
        let path = self.path(pid, address, dirfd)?;
        self.exec_resolved(path.as_bytes())
    }

    pub fn exec_interpreter(&mut self, pid: usize, name: &[u8]) -> Result<Option<Executable>, i64> {
        let cwd;
        let base = if name.first() == Some(&b'/') {
            b"/".as_slice()
        } else {
            cwd = self.cwd_path(pid)?;
            cwd.as_bytes()
        };
        let path = self.routed_path(base, name)?;
        self.exec_resolved(path.as_bytes())
    }

    fn exec_resolved(&mut self, path: &[u8]) -> Result<Option<Executable>, i64> {
        if self.owns_path(path) {
            let path = self.owned_path(path, true, false)?;
            let image = self.fs.pin_executable(path.as_bytes()).map_err(errno)?;
            return self.check_exec(image).map(Some);
        }
        if [b"/dev".as_slice(), b"/proc", b"/sys"]
            .iter()
            .any(|p| within(path, p))
        {
            return Err(-13);
        }
        Ok(None)
    }

    pub fn exec_descriptor(&mut self, handle: u32) -> Result<Executable, i64> {
        let fd = handle
            .checked_sub(FD_BASE as u32)
            .filter(|n| *n < 64)
            .ok_or(-95)?;
        let image = self.fs.pin_executable_fd(fd as i32 + 3).map_err(errno)?;
        self.check_exec(image)
    }

    /// Readonly reopening through a public descriptor resolved by its owner.
    /// It cannot import a native fd or grant host filesystem write authority.
    pub fn open_descriptor(&mut self, handle: u32, suffix: &[u8], flags: u64) -> Result<i64, i64> {
        let fd = handle
            .checked_sub(FD_BASE as u32)
            .filter(|n| *n < 64)
            .ok_or(-95)? as i32
            + 3;
        const ALLOWED: u64 = 0o400 | 0o4000 | 0o100000 | 0o200000 | 0o400000 | 0o2000000;
        if flags & !ALLOWED != 0 {
            return Err(-13);
        }
        if !suffix.is_empty() {
            let directory = self.fs.directory_path(fd).map_err(errno)?;
            let relative = suffix.strip_prefix(b"/").unwrap_or(suffix);
            let path = self.routed_path(directory, relative)?;
            if !self.owns_path(path.as_bytes()) {
                return Err(-95);
            }
            return self.open(path.as_bytes(), flags, 0).map_err(|error| {
                if error == -22 {
                    -95
                } else {
                    error
                }
            });
        }
        let metadata = self.fs.fstat(fd).map_err(errno)?;
        if flags & 0o200000 != 0 && metadata.kind != NodeKind::Directory {
            return Err(-20);
        }
        let status = if flags & 0o2000000 != 0 { O_CLOEXEC } else { 0 }
            | if flags & 0o4000 != 0 { O_NONBLOCK } else { 0 };
        let reopened = self.fs.reopen_readonly(fd, status).map_err(errno)?;
        Ok(FD_BASE as i64 + reopened as i64 - 3)
    }

    fn check_exec(&mut self, image: Executable) -> Result<Executable, i64> {
        let mut header = [0u8; 64];
        let result = self.read_executable(image, 0, &mut header).and_then(|n| {
            if header.starts_with(b"#!") {
                Ok(image)
            } else if n < 64
                || &header[..4] != b"\x7fELF"
                || header[4] != 2
                || header[5] != 1
                || header[18..20] != [62, 0]
            {
                Err(-8)
            } else {
                Ok(image)
            }
        });
        if result.is_err() {
            self.release_executable(image)
                .expect("invalid executable pin release");
        }
        result
    }

    /// The kernel owns binfmt parsing and optional interpreter arguments. Check
    /// the first interpreter's namespace before handing it the sealed script.
    /// Owned interpreters need a separate owned-executable transaction.
    pub fn is_script(&self, image: Executable) -> Result<bool, i64> {
        let mut header = [0u8; 2];
        self.read_executable(image, 0, &mut header)?;
        Ok(header == *b"#!")
    }

    pub fn mapping_reference(&mut self, handle: u32) -> Result<usize, i64> {
        let slot = handle
            .checked_sub(FD_BASE as u32)
            .filter(|n| *n < 64)
            .ok_or(-9)?;
        let (storage, object) = self.fs.readable_storage(slot as i32 + 3).map_err(errno)?;
        let fd = storage.backing(object).map_err(errno)?;
        crate::file_mapping::readonly_reference(fd)
    }

    pub fn executable_name(&self, image: Executable) -> Result<Path, i64> {
        let (name, deleted) = self.fs.executable_name(image).map_err(errno)?;
        let mut bytes = [0u8; MAX_PATH];
        let suffix = if deleted {
            b" (deleted)".as_slice()
        } else {
            b""
        };
        let len = name
            .len()
            .checked_add(suffix.len())
            .filter(|n| *n <= MAX_PATH)
            .ok_or(-36)?;
        bytes[..name.len()].copy_from_slice(name);
        bytes[name.len()..len].copy_from_slice(suffix);
        Path::from_bytes(&bytes[..len]).map_err(|_| -36)
    }

    pub fn read_executable(
        &self,
        image: Executable,
        offset: usize,
        output: &mut [u8],
    ) -> Result<usize, i64> {
        self.fs
            .read_executable(image, offset, output)
            .map_err(errno)
    }
    pub fn retain_executable(&mut self, image: Executable) -> Result<(), i64> {
        self.fs.retain_executable(image).map_err(errno)
    }
    pub fn release_executable(&mut self, image: Executable) -> Result<(), i64> {
        self.fs.release_executable(image).map_err(errno)
    }

    /// Configured-launch dispatch only; demo paths keep their existing contract.
    pub fn claim(&mut self, pid: usize, r: &UserRegs) -> Option<i64> {
        if !self.enabled() {
            return None;
        }
        if matches!(r.orig_rax, 82 | 264 | 316) {
            return Some(self.rename(pid, r).unwrap_or_else(|error| error));
        }
        let fd = r.rdi as i32;
        if matches!(
            r.orig_rax,
            0 | 1
                | 3
                | 5
                | 8
                | 16
                | 17
                | 18
                | 19
                | 20
                | 32
                | 33
                | 72
                | 74
                | 75
                | 77
                | 91
                | 217
                | 292
        ) && fd >= FD_BASE as i32
        {
            return Some(self.descriptor_call(pid, r, fd - FD_BASE as i32 + 3));
        }
        if matches!(r.orig_rax, 262 | 332 | 439) {
            match read_path(pid, r.rsi) {
                Ok(p) if p.is_empty() && fd >= FD_BASE as i32 => {
                    return Some(self.descriptor_call(pid, r, fd - FD_BASE as i32 + 3))
                }
                Ok(p) if p.is_empty() => return None,
                Err(error) => return Some(error),
                _ => {}
            }
        }
        let (address, dirfd) = match r.orig_rax {
            88 => (r.rsi, (-100i64) as u64),
            266 => (r.rdx, r.rsi),
            2 | 4 | 6 | 21 | 83 | 84 | 87 | 89 | 90 => (r.rdi, (-100i64) as u64),
            257 | 258 | 262 | 263 | 267 | 268 | 269 | 332 | 439 => (r.rsi, r.rdi),
            _ => return None,
        };
        let path = match self.path(pid, address, dirfd) {
            Ok(path) => path,
            Err(error) => return Some(error),
        };
        if !self.owns_path(path.as_bytes()) {
            // The kernel cwd remains in the immutable image while the task
            // enters an owned directory. A relative fallback would enter the
            // hidden image tree; crossing namespaces is resolved explicitly.
            if self.cwd.is_some()
                && read_path(pid, address).is_ok_and(|p| p.as_bytes().first() != Some(&b'/'))
            {
                return Some(-95);
            }
            return None;
        }
        let original_path = path;
        let follow = match r.orig_rax {
            6 | 83 | 84 | 87 | 88 | 89 | 258 | 263 | 266 | 267 => false,
            262 => r.r10 & 0x100 == 0,
            332 => r.rdx & 0x100 == 0,
            439 => r.r10 & 0x100 == 0,
            // open handles O_EXCL and O_NOFOLLOW before following the final link.
            2 | 257 => false,
            _ => true,
        };
        let missing = matches!(r.orig_rax, 2 | 257 | 83 | 258 | 88 | 266);
        let resolved = if matches!(r.orig_rax, 83 | 84 | 87 | 258 | 263) {
            self.mutation_path(path.as_bytes(), missing)
        } else {
            self.owned_path(path.as_bytes(), follow, missing)
        };
        let path = match resolved {
            Ok(path) => path,
            Err(error) => return Some(error),
        };
        let result = match r.orig_rax {
            2 => self.open(path.as_bytes(), r.rsi, r.rdx),
            257 => self.open(path.as_bytes(), r.rdx, r.r10),
            4 | 6 => self.stat(pid, path.as_bytes(), r.rsi, false),
            21 | 269 | 439 => self
                .fs
                .metadata_no_follow(path.as_bytes())
                .map_err(errno)
                .and_then(|metadata| access(metadata, r)),
            88 | 266 => read_path(pid, r.rdi).and_then(|target| {
                self.fs
                    .symlink(target.as_bytes(), path.as_bytes())
                    .map(|_| 0)
                    .map_err(errno)
            }),
            89 | 267 => {
                let (address, length) = if r.orig_rax == 89 {
                    (r.rsi, r.rdx)
                } else {
                    (r.rdx, r.r10)
                };
                if length == 0 {
                    Err(-22)
                } else {
                    let mut target = [0; MAX_PATH];
                    let count = (length as usize).min(target.len());
                    self.fs
                        .read_link(path.as_bytes(), &mut target[..count])
                        .map_err(errno)
                        .and_then(|n| {
                            copy_memory(pid, address, &mut target[..n], true)?;
                            Ok(n as i64)
                        })
                }
            }
            262 => {
                if r.r10 & !0x900 != 0 {
                    Err(-22)
                } else {
                    self.stat(pid, path.as_bytes(), r.rdx, false)
                }
            }
            332 => {
                if r.rdx & !0x7900 != 0 || r.rdx & 0x6000 == 0x6000 {
                    Err(-22)
                } else {
                    self.stat(pid, path.as_bytes(), r.r8, true)
                }
            }
            83 => self
                .fs
                .mkdir(path.as_bytes(), r.rsi as u32 & 0o755)
                .map(|_| 0)
                .map_err(errno),
            258 => self
                .fs
                .mkdir(path.as_bytes(), r.rdx as u32 & 0o755)
                .map(|_| 0)
                .map_err(errno),
            87 => self.fs.unlink(path.as_bytes()).map(|_| 0).map_err(errno),
            84 => self.remove_directory(original_path.as_bytes()),
            263 => {
                if r.rdx == 0x200 {
                    self.remove_directory(original_path.as_bytes())
                } else if r.rdx != 0 {
                    Err(-95)
                } else {
                    self.fs.unlink(path.as_bytes()).map(|_| 0).map_err(errno)
                }
            }
            90 => self
                .fs
                .chmod(path.as_bytes(), r.rsi as u32)
                .map(|_| 0)
                .map_err(errno),
            268 => self
                .fs
                .chmod(path.as_bytes(), r.rdx as u32)
                .map(|_| 0)
                .map_err(errno),
            _ => Err(-38),
        };
        Some(result.unwrap_or_else(|error| error))
    }

    fn open(&mut self, path: &[u8], flags: u64, mode: u64) -> Result<i64, i64> {
        // Unsupported path-only behavior never falls through to native storage.
        const ALLOWED: u64 = 3
            | 0o100
            | 0o200
            | 0o400
            | 0o1000
            | 0o2000
            | 0o4000
            | 0o100000
            | 0o200000
            | 0o400000
            | 0o2000000;
        if flags & !ALLOWED != 0 || flags & 3 == 3 {
            return Err(-95);
        }
        if flags & (0o200000 | 0o100) == (0o200000 | 0o100) {
            return Err(-22);
        }
        let entry = self.fs.metadata_no_follow(path);
        if flags & (0o100 | 0o200) == (0o100 | 0o200) && entry.is_ok() {
            return Err(-17);
        }
        if flags & 0o400000 != 0 && entry.is_ok_and(|m| m.kind == NodeKind::Symlink) {
            return Err(-40);
        }
        let canonical = self.owned_path(path, true, flags & 0o100 != 0)?;
        let path = canonical.as_bytes();
        let metadata = self.fs.metadata(path);
        if metadata.is_ok_and(|m| m.kind == NodeKind::Directory) {
            if flags & (3 | 0o100 | 0o1000 | 0o2000) != 0 {
                return Err(-21);
            }
            let status = if flags & 0o2000000 != 0 { O_CLOEXEC } else { 0 }
                | if flags & 0o4000 != 0 { O_NONBLOCK } else { 0 };
            let fd = self.fs.open_directory(path, status).map_err(errno)?;
            return Ok(FD_BASE as i64 + fd as i64 - 3);
        }
        if flags & 0o200000 != 0 {
            return Err(metadata.err().map(errno).unwrap_or(-20));
        }
        let mut translated = match flags & 3 {
            0 => O_READ,
            1 => O_WRITE,
            _ => O_READ | O_WRITE,
        };
        for (native, internal) in [
            (0o100, O_CREATE),
            (0o200, O_EXCLUSIVE),
            (0o1000, O_TRUNC),
            (0o2000, O_APPEND),
            (0o4000, O_NONBLOCK),
            (0o2000000, O_CLOEXEC),
        ] {
            if flags & native != 0 {
                translated |= internal;
            }
        }
        let existed = self.fs.metadata(path).is_ok();
        let fd = self.fs.open(path, translated).map_err(errno)?;
        if !existed && flags & 0o100 != 0 {
            self.fs.fchmod(fd, mode as u32 & 0o755).map_err(errno)?;
        }
        Ok(FD_BASE as i64 + fd as i64 - 3)
    }

    fn remove_directory(&mut self, path: &[u8]) -> Result<i64, i64> {
        let canonical = self.mutation_path(path, false)?;
        if self.assignment_root(canonical.as_bytes()) {
            return Err(-16);
        }
        self.fs.remove_directory(path).map(|_| 0).map_err(errno)
    }

    fn assignment_root(&self, path: &[u8]) -> bool {
        self.prefixes[..self.count]
            .iter()
            .any(|p| p.as_bytes() == path)
            && !self.prefixes[..self.count]
                .iter()
                .any(|p| p.as_bytes() != path && within(path, p.as_bytes()))
    }

    fn rename(&mut self, pid: usize, r: &UserRegs) -> Result<i64, i64> {
        let (source, destination, flags) = if r.orig_rax == 82 {
            (
                self.path(pid, r.rdi, (-100i64) as u64)?,
                self.path(pid, r.rsi, (-100i64) as u64)?,
                0,
            )
        } else {
            (
                self.path(pid, r.rsi, r.rdi)?,
                self.path(pid, r.r10, r.rdx)?,
                if r.orig_rax == 316 { r.r8 } else { 0 },
            )
        };
        if flags > 1 {
            return Err(-95);
        }
        if !self.owns_path(source.as_bytes()) || !self.owns_path(destination.as_bytes()) {
            return Err(-18);
        }
        let original_source = source;
        let original_destination = destination;
        let directory_destination = destination.as_bytes().ends_with(b"/");
        let source = self.mutation_path(source.as_bytes(), false)?;
        let destination = self.mutation_path(destination.as_bytes(), true)?;
        if directory_destination
            && self
                .fs
                .metadata_no_follow(source.as_bytes())
                .map_err(errno)?
                .kind
                != NodeKind::Directory
        {
            return Err(-20);
        }
        if self.prefixes[..self.count].iter().any(|prefix| {
            self.assignment_root(prefix.as_bytes())
                && (within(prefix.as_bytes(), source.as_bytes())
                    || within(prefix.as_bytes(), destination.as_bytes()))
        }) {
            return Err(-16);
        }
        self.fs
            .rename(
                original_source.as_bytes(),
                original_destination.as_bytes(),
                flags == 1,
            )
            .map(|_| 0)
            .map_err(errno)
    }

    fn stat(&self, pid: usize, path: &[u8], destination: u64, statx: bool) -> Result<i64, i64> {
        copy_metadata(
            pid,
            destination,
            self.fs.metadata_no_follow(path).map_err(errno)?,
            statx,
        )
    }

    fn descriptor_call(&mut self, pid: usize, r: &UserRegs, fd: i32) -> i64 {
        let result = match r.orig_rax {
            0 => self.read(pid, fd, r.rsi, r.rdx, None),
            17 => self.read(pid, fd, r.rsi, r.rdx, Some(r.r10 as i64)),
            1 => self.write(pid, fd, r.rsi, r.rdx),
            3 => self.fs.close(fd).map(|_| 0).map_err(errno),
            5 => self
                .fs
                .fstat(fd)
                .map_err(errno)
                .and_then(|m| copy_metadata(pid, r.rsi, m, false)),
            8 => self
                .fs
                .seek(fd, r.rsi as i64, r.rdx as u32)
                .map(|n| n as i64)
                .map_err(errno),
            91 => self.fs.fchmod(fd, r.rsi as u32).map(|_| 0).map_err(errno),
            77 if r.rsi as i64 >= 0 => self.fs.truncate(fd, r.rsi).map(|_| 0).map_err(errno),
            77 => Err(-22),
            217 => self.getdents(pid, fd, r.rsi, r.rdx),
            72 => self
                .fs
                .descriptor_flags(fd)
                .map_err(errno)
                .and_then(|(flags, cloexec)| match r.rsi {
                    1 => Ok(cloexec as i64),
                    2 if r.rdx & !1 == 0 => self
                        .fs
                        .set_close_on_exec(fd, r.rdx != 0)
                        .map(|_| 0)
                        .map_err(errno),
                    3 => Ok(flags as i64),
                    _ => Err(-95),
                }),
            439 => {
                if r.r10 & 0x1000 == 0 {
                    Err(-2)
                } else {
                    self.fs.fstat(fd).map_err(errno).and_then(|m| access(m, r))
                }
            }
            262 | 332 => {
                let flags = if r.orig_rax == 262 { r.r10 } else { r.rdx };
                if flags != 0x1000 {
                    Err(-22)
                } else {
                    self.fs.fstat(fd).map_err(errno).and_then(|m| {
                        copy_metadata(
                            pid,
                            if r.orig_rax == 262 { r.rdx } else { r.r8 },
                            m,
                            r.orig_rax == 332,
                        )
                    })
                }
            }
            _ => Err(-95),
        };
        result.unwrap_or_else(|error| error)
    }

    fn read(
        &mut self,
        pid: usize,
        fd: i32,
        address: u64,
        length: u64,
        offset: Option<i64>,
    ) -> Result<i64, i64> {
        let previous = self.fs.seek(fd, 0, 1).map_err(errno)?;
        if let Some(offset) = offset {
            self.fs.seek(fd, offset, 0).map_err(errno)?;
        }
        let start = self.fs.seek(fd, 0, 1).map_err(errno)?;
        let mut buffer = [0u8; IO_SIZE];
        let read = self
            .fs
            .read(fd, &mut buffer[..length.min(IO_SIZE as u64) as usize])
            .map_err(errno);
        let result = read.and_then(|count| copy_memory(pid, address, &mut buffer[..count], true));
        let next = if offset.is_some() {
            previous
        } else {
            start + result.unwrap_or(0) as u64
        };
        self.fs.seek(fd, next as i64, 0).map_err(errno)?;
        result
    }

    fn write(&mut self, pid: usize, fd: i32, address: u64, length: u64) -> Result<i64, i64> {
        self.fs.fstat(fd).map_err(errno)?;
        let mut buffer = [0u8; IO_SIZE];
        let count = length.min(IO_SIZE as u64) as usize;
        let copied = copy_memory(pid, address, &mut buffer[..count], false)? as usize;
        self.fs
            .write(fd, &buffer[..copied])
            .map(|n| n as i64)
            .map_err(errno)
    }

    fn getdents(&mut self, pid: usize, fd: i32, address: u64, length: u64) -> Result<i64, i64> {
        if self.fs.fstat(fd).map_err(errno)?.kind != NodeKind::Directory {
            return Err(-20);
        }
        let mut cookie = self.fs.seek(fd, 0, 1).map_err(errno)?;
        let mut buffer = [0u8; IO_SIZE];
        let capacity = length.min(IO_SIZE as u64) as usize;
        let mut used = 0;
        while let Some(entry) = self.fs.directory_entry(fd, cookie).map_err(errno)? {
            let size = (19 + entry.name.len() + 1 + 7) & !7;
            if size > capacity - used {
                if used == 0 {
                    return Err(-22);
                }
                break;
            }
            let record = &mut buffer[used..used + size];
            record[..8].copy_from_slice(&entry.inode.to_ne_bytes());
            record[8..16].copy_from_slice(&entry.next.to_ne_bytes());
            record[16..18].copy_from_slice(&(size as u16).to_ne_bytes());
            record[18] = match entry.kind {
                NodeKind::File => 8,
                NodeKind::Directory => 4,
                NodeKind::Symlink => 10,
            };
            record[19..19 + entry.name.len()].copy_from_slice(entry.name);
            used += size;
            cookie = entry.next;
        }
        if copy_memory(pid, address, &mut buffer[..used], true)? != used as i64 {
            return Err(-14);
        }
        self.fs.seek(fd, cookie as i64, 0).map_err(errno)?;
        Ok(used as i64)
    }
}

// Owned files belong to the domain's virtual uid 0. Read/write checks reflect
// that authority; executing a regular file still requires an execute bit.
fn access(metadata: FileMetadata, r: &UserRegs) -> Result<i64, i64> {
    let mode = if r.orig_rax == 21 { r.rsi } else { r.rdx };
    let flags = if r.orig_rax == 439 { r.r10 } else { 0 };
    if mode & !7 != 0 || flags & !0x1300 != 0 {
        return Err(-22);
    }
    if mode & 1 != 0 && metadata.kind != NodeKind::Directory && metadata.mode & 0o111 == 0 {
        return Err(-13);
    }
    Ok(0)
}

fn within(path: &[u8], prefix: &[u8]) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.first() == Some(&b'/'))
}

fn normalize(cwd: &[u8], text: &[u8]) -> Result<Path, i64> {
    let mut output = [0u8; MAX_PATH];
    let mut len = 1;
    output[0] = b'/';
    for part in cwd.split(|b| *b == b'/').chain(text.split(|b| *b == b'/')) {
        match part {
            b"" | b"." => {}
            b".." => {
                len = output[..len]
                    .iter()
                    .rposition(|b| *b == b'/')
                    .unwrap_or(0)
                    .max(1);
            }
            _ => {
                let start = len + usize::from(len > 1);
                let end = start
                    .checked_add(part.len())
                    .filter(|end| *end <= MAX_PATH)
                    .ok_or(-36)?;
                if len > 1 {
                    output[len] = b'/';
                }
                output[start..end].copy_from_slice(part);
                len = end;
            }
        }
    }
    Path::from_bytes(&output[..len]).map_err(|_| -36)
}

fn copy_metadata(
    pid: usize,
    address: u64,
    metadata: FileMetadata,
    statx: bool,
) -> Result<i64, i64> {
    crate::tracee_io::write_stat(
        pid,
        address,
        crate::tracee_io::Stat {
            inode: metadata.inode,
            mode: metadata.mode
                | match metadata.kind {
                    NodeKind::Directory => 0o40000,
                    NodeKind::Symlink => 0o120000,
                    _ => 0o100000,
                },
            size: metadata.size,
            device_major: 0,
            device_minor: 0,
        },
        statx,
    )
}

fn errno(error: VfsError) -> i64 {
    match error {
        VfsError::NotFound => -2,
        VfsError::NotDirectory => -20,
        VfsError::IsDirectory => -21,
        VfsError::DirectoryNotEmpty => -39,
        VfsError::TextBusy => -26,
        VfsError::AlreadyExists => -17,
        VfsError::PermissionDenied => -13,
        VfsError::InvalidDescriptor => -9,
        VfsError::DescriptorLimit => -24,
        VfsError::OverlayLimit => -28,
        VfsError::FileTooLarge => -27,
        VfsError::InvalidPath => -22,
        VfsError::SymlinkLoop => -40,
        VfsError::InvalidIndex | VfsError::Io => -5,
    }
}

pub fn claims(_: u64) -> bool {
    false
}
pub fn claim(_: u64, _: u64, _: u64, _: u64) -> Option<i64> {
    None
}
