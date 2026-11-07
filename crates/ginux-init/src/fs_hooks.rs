//! Configured-launch ephemeral memory storage. Bytes and descriptors belong to
//! the supervisor; no writable host descriptor is installed in the workload.
//! Executable references share the VFS owner. File mappings use a private
//! read-only backing transfer; retained storage is not provided.

use crate::storage_memory::{MappedArray, MemoryStorage};
use crate::supervisor::UserRegs;
use crate::tracee_io::{copy_memory, read_path};
use core::sync::atomic::{AtomicBool, Ordering};
use ginux_instance::{InstanceConfig, Text};
use ginux_vfs::{
    BaseReader, Entry, Executable, FileMetadata, Index, NodeKind, VfsError, VirtualFs, HEADER_SIZE,
    MAX_PATH, O_APPEND, O_CLOEXEC, O_CREATE, O_EXCLUSIVE, O_NONBLOCK, O_READ, O_TRUNC, O_WRITE,
    RECORD_SIZE,
};

pub const FD_BASE: usize = 1 << 20;
// Internal tag for a registered native image directory, never a public FD.
pub const IMAGE_DIR_BASE: u64 = 0x0800_0000;
const IO_SIZE: usize = 4096;
type Path = Text<MAX_PATH>;
type ExecutableName = Text<{ MAX_PATH + 10 }>;
type MemoryFs =
    VirtualFs<'static, EmptyReader, 0, 0, 64, MemoryStorage, MappedArray<ginux_vfs::OverlayFile>>;
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
    pub hardlink: bool,
    pub modified: u64,
}

pub struct LaunchFs {
    fs: MemoryFs,
    byte_limit: usize,
    prefixes: [Path; 8],
    count: usize,
    cwd: Option<i32>,
    creation_mask: u32,
    init: Path,
    null: bool,
    process: u32,
    locks: crate::file_locks::Locks,
    flocks: crate::file_locks::Locks,
}

impl LaunchFs {
    /// Called once, before fork. Assignments are instance paths, never host paths.
    pub fn prepare(config: &InstanceConfig) -> Result<Self, &'static [u8]> {
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
        let objects = usize::try_from(config.storage_max_objects)
            .map_err(|_| b"storage object capacity exceeds address space".as_slice())?;
        let metadata = MappedArray::<ginux_vfs::OverlayFile>::bytes_for(objects)
            .and_then(|n| {
                MemoryStorage::metadata_bytes(objects)
                    .and_then(|m| n.checked_add(m).ok_or(VfsError::OverlayLimit))
            })
            .map_err(|_| b"storage metadata size overflow".as_slice())?;
        let memory = usize::try_from(config.memory_mib)
            .ok()
            .and_then(|mib| mib.checked_mul(1024 * 1024))
            .ok_or(b"memory storage capacity exceeds address space".as_slice())?;
        let available = memory
            .checked_sub(metadata)
            .ok_or(b"storage metadata exceeds memory bound".as_slice())?;
        let limit = if config.storage_max_bytes == 0 {
            available
        } else {
            let limit = usize::try_from(config.storage_max_bytes)
                .map_err(|_| b"storage data capacity exceeds address space".as_slice())?;
            if limit > available {
                return Err(b"storage data and metadata exceed memory bound");
            }
            limit
        };
        if count != 0 {
            // One backing FD per possible object plus bounded supervisor work.
            // The launcher captures the public limit before this reservation.
            let required = objects
                .checked_add(128)
                .ok_or(b"storage descriptor budget overflow".as_slice())?;
            let mut limits = [0usize; 2];
            if unsafe { crate::supervisor::syscall4(302, 0, 7, 0, limits.as_mut_ptr() as usize) }
                != 0
            {
                return Err(b"cannot inspect storage descriptor budget");
            }
            if limits[0] < required {
                if limits[1] < required {
                    return Err(b"storage descriptor budget exceeds host hard limit");
                }
                limits[0] = required;
                if unsafe { crate::supervisor::syscall4(302, 0, 7, limits.as_ptr() as usize, 0) }
                    != 0
                {
                    return Err(b"cannot reserve storage descriptor budget");
                }
            }
        }
        let namespace = MappedArray::new(objects, ginux_vfs::OverlayFile::empty())
            .map_err(|_| b"storage namespace allocation failed".as_slice())?;
        let mut fs = MemoryFs::with_namespace(
            Index::new(index_bytes).map_err(|_| b"invalid storage root index".as_slice())?,
            EmptyReader,
            MemoryStorage::new(limit, objects)
                .map_err(|_| b"storage metadata allocation failed".as_slice())?,
            namespace,
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
            process: 1,
            locks: crate::file_locks::Locks::new(),
            flocks: crate::file_locks::Locks::new(),
            fs,
            byte_limit: limit,
            prefixes,
            count,
            cwd: None,
            creation_mask: 0o022,
            null: config
                .devices
                .as_slice()
                .iter()
                .any(|name| name.as_bytes() == b"null"),
            init: Path::from_bytes(config.init.as_bytes())
                .map_err(|_| b"init path exceeds bound".as_slice())?,
        })
    }

    pub fn readiness(&self, handle: u32) -> Option<u16> {
        let slot = handle.checked_sub(FD_BASE as u32)?;
        if slot >= 64 {
            return None;
        }
        // This owner contains only regular memory files and directories.
        self.fs.fstat(slot as i32 + 3).ok().map(|_| 0x145)
    }

    pub fn byte_limit(&self) -> u64 {
        self.byte_limit as u64
    }

    pub fn capacity(&self) -> usize {
        self.fs.namespace_capacity()
    }

    pub fn restore_entry(
        &mut self,
        entry: RestoreEntry<'_>,
        seen: &mut [bool],
        mut read: impl FnMut(&mut [u8]) -> Result<(), &'static [u8]>,
    ) -> Result<(), &'static [u8]> {
        let RestoreEntry {
            path,
            kind,
            link,
            mode,
            length,
            hardlink,
            modified,
        } = entry;
        let directory = kind == NodeKind::Directory;
        // The archive parser has already validated absolute path components.
        if !self.owns_path(path)
            && !(directory
                && self.prefixes[..self.count]
                    .iter()
                    .any(|p| within(p.as_bytes(), path)))
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
        } else if hardlink {
            if link.is_empty()
                || link[0] == b'/'
                || link.contains(&0)
                || link
                    .split(|b| *b == b'/')
                    .any(|p| p.is_empty() || p == b"." || p == b"..")
            {
                return Err(b"invalid restore hardlink target");
            }
            let mut target = [0u8; MAX_PATH];
            if link.len() + 1 >= MAX_PATH {
                return Err(b"restore hardlink target exceeds path bound");
            }
            target[0] = b'/';
            target[1..1 + link.len()].copy_from_slice(link);
            let target = &target[..link.len() + 1];
            let slot = self
                .fs
                .named_overlay_slot(target)
                .ok_or(b"restore hardlink target is not a prior entry".as_slice())?;
            let (_, metadata) = self
                .fs
                .overlay_entry(slot)
                .ok_or(b"restore hardlink target missing".as_slice())?;
            if !seen[slot]
                || metadata.kind != NodeKind::File
                || metadata.mode != mode
                || metadata.modified.seconds != modified as i64
                || !self.owns_path(target)
            {
                return Err(b"restore hardlink target or mode is invalid");
            }
            self.fs
                .hard_link(target, path, false)
                .map_err(|_| b"restore hardlink creation failed".as_slice())?;
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
        self.fs
            .set_times(
                path,
                false,
                None,
                Some(ginux_vfs::Timestamp {
                    seconds: modified as i64,
                    nanoseconds: 0,
                }),
            )
            .map_err(|_| b"restore timestamp failed".as_slice())?;
        // Track exact names rather than canonical inodes, since aliases share data.
        let slot = self
            .fs
            .named_overlay_slot(path)
            .ok_or(b"restore entry lookup failed".as_slice())?;
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
        for slot in 0..self.fs.namespace_capacity() {
            if let Some((path, metadata)) = self.fs.overlay_entry(slot) {
                let prior = if metadata.kind == NodeKind::File && metadata.links > 1 {
                    (0..slot)
                        .filter_map(|slot| self.fs.overlay_entry(slot))
                        .find(|(_, prior)| {
                            prior.kind == NodeKind::File && prior.inode == metadata.inode
                        })
                        .map(|(path, _)| path)
                } else {
                    None
                };
                if let Some(target) = prior {
                    archive.hardlink(path, metadata, target)?;
                    continue;
                }
                archive.entry(path, metadata, |offset, buffer| {
                    self.fs
                        .read_overlay(slot, offset, buffer)
                        .map_err(|_| b"export read failed".as_slice())
                })?;
            }
        }
        Ok(())
    }

    pub fn select_process(&mut self, process: u32) {
        self.process = process;
    }
    pub fn release_process_locks(&mut self, process: u32) {
        self.locks.release(process, None);
    }
    pub fn close_locks(&mut self, handle: u32) {
        if (FD_BASE as u32..FD_BASE as u32 + 64).contains(&handle) {
            if let Ok(metadata) = self.fs.fstat((handle - FD_BASE as u32) as i32 + 3) {
                self.locks.release(self.process, Some(metadata.inode));
            }
        }
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

    fn owns_path(&self, path: &[u8]) -> bool {
        self.prefixes[..self.count]
            .iter()
            .any(|p| within(path, p.as_bytes()))
    }

    pub(crate) fn path(&self, pid: usize, address: u64, dirfd: u64) -> Result<Path, i64> {
        let text = read_path(pid, address)?;
        if text.is_empty() {
            return Err(-2);
        }
        let absolute = text.as_bytes().first() == Some(&b'/');
        let cwd;
        let base = if absolute {
            b"".as_slice()
        } else if dirfd as i32 == -100 {
            cwd = self.cwd_path(pid)?;
            cwd.as_bytes()
        } else if (IMAGE_DIR_BASE..IMAGE_DIR_BASE + 256).contains(&dirfd) {
            cwd = crate::tracee_io::image_fd_path(pid, (dirfd - IMAGE_DIR_BASE) as u32)?;
            let image = crate::path_hooks::ImageRoot::new(pid)?;
            if image
                .lookup(cwd.as_bytes(), &mut [0; MAX_PATH])
                .map_err(errno)?
                .0
                != NodeKind::Directory
            {
                return Err(-20);
            }
            cwd.as_bytes()
        } else {
            let fd = (dirfd as u32)
                .checked_sub(FD_BASE as u32)
                .filter(|slot| *slot < 64)
                .ok_or(-9)?;
            self.fs.directory_path(fd as i32 + 3).map_err(errno)?
        };
        join_path(base, text.as_bytes())
    }

    fn resolve(&self, pid: usize, path: &[u8], follow: bool, missing: bool) -> Result<Path, i64> {
        let image = crate::path_hooks::ImageRoot::new(pid)?;
        let mut output = [0; MAX_PATH];
        let n = ginux_vfs::resolve_namespace(path, follow, missing, &mut output, |path, target| {
            if self.owns_path(path)
                || path != b"/"
                    && self.prefixes[..self.count]
                        .iter()
                        .any(|prefix| within(prefix.as_bytes(), path))
            {
                let metadata = self.fs.metadata_no_follow(path)?;
                let n = if metadata.kind == NodeKind::Symlink {
                    self.fs.read_link(path, target)?
                } else {
                    0
                };
                return Ok((metadata.kind, n));
            }
            if path == b"/dev" {
                return Ok((NodeKind::Directory, 0));
            }
            if path == b"/dev/null" && self.null {
                return Ok((NodeKind::File, 0));
            }
            if within(path, b"/dev") {
                return Err(VfsError::NotFound);
            }
            if [b"/proc".as_slice(), b"/sys"]
                .iter()
                .any(|p| within(path, p))
            {
                return Err(VfsError::PermissionDenied);
            }
            image.lookup(path, target)
        })
        .map_err(errno)?;
        Path::from_bytes(&output[..n]).map_err(|_| -36)
    }

    fn mutation_path(&self, pid: usize, path: &[u8], missing: bool) -> Result<Path, i64> {
        let mut end = path.len();
        while end > 1 && path[end - 1] == b'/' {
            end -= 1;
        }
        let resolved = self.resolve(pid, &path[..end], false, missing)?;
        if end != path.len() {
            let kind = if self.owns_path(resolved.as_bytes()) {
                self.fs
                    .metadata_no_follow(resolved.as_bytes())
                    .map(|m| m.kind)
            } else {
                crate::path_hooks::ImageRoot::new(pid)?
                    .lookup(resolved.as_bytes(), &mut [0; MAX_PATH])
                    .map(|m| m.0)
            };
            match kind {
                Ok(NodeKind::Directory) => {}
                Err(VfsError::NotFound) if missing => {}
                Err(error) => return Err(errno(error)),
                _ => return Err(-20),
            }
        }
        Ok(resolved)
    }

    pub(crate) fn request_path(&self, pid: usize, r: &UserRegs) -> Result<Option<(u8, Path)>, i64> {
        // Descriptor futimens has no pathname; its public descriptor owner
        // validates/translates the handle before the filesystem claim.
        // Empty-path ownership likewise belongs to the descriptor owner.
        if (r.orig_rax == 280 && r.rsi == 0)
            || (r.orig_rax == 260 && read_path(pid, r.rsi)?.is_empty())
        {
            return Ok(None);
        }
        let (argument, address, dirfd, follow, missing) = match r.orig_rax {
            2 => (
                0,
                r.rdi,
                (-100i64) as u64,
                r.rsi & 0o400000 == 0 && r.rsi & 0o300 != 0o300,
                r.rsi & 0o100 != 0,
            ),
            257 => (
                1,
                r.rsi,
                r.rdi,
                r.rdx & 0o400000 == 0 && r.rdx & 0o300 != 0o300,
                r.rdx & 0o100 != 0,
            ),
            80 => (0, r.rdi, (-100i64) as u64, true, false),
            59 => (0, r.rdi, (-100i64) as u64, true, false),
            322 => (1, r.rsi, r.rdi, r.r8 & 0x100 == 0, false),
            4 | 21 | 90 | 92 => (0, r.rdi, (-100i64) as u64, true, false),
            6 | 84 | 87 | 89 | 94 => (0, r.rdi, (-100i64) as u64, false, false),
            83 => (0, r.rdi, (-100i64) as u64, false, true),
            88 => (1, r.rsi, (-100i64) as u64, false, true),
            266 => (2, r.rdx, r.rsi, false, true),
            258 => (1, r.rsi, r.rdi, false, true),
            260 if r.r8 & !0x1100 != 0 => return Err(-22),
            260 => (1, r.rsi, r.rdi, r.r8 & 0x100 == 0, false),
            262 | 280 => (1, r.rsi, r.rdi, r.r10 & 0x100 == 0, false),
            263 | 267 => (1, r.rsi, r.rdi, false, false),
            268 | 269 => (1, r.rsi, r.rdi, true, false),
            332 => (1, r.rsi, r.rdi, r.rdx & 0x100 == 0, false),
            439 => (1, r.rsi, r.rdi, r.r10 & 0x100 == 0, false),
            _ => return Ok(None),
        };
        if matches!(r.orig_rax, 260 | 262 | 332 | 439 | 322)
            && (dirfd as i32) < FD_BASE as i32
            && read_path(pid, address)?.is_empty()
        {
            return Ok(None);
        }
        let path = self.path(pid, address, dirfd)?;
        if (r.orig_rax == 84 || r.orig_rax == 263 && r.rdx == 0x200) && dot_entry(path.as_bytes()) {
            return Err(-22);
        }
        if matches!(r.orig_rax, 88 | 266) && path.as_bytes().ends_with(b"/") {
            return Err(-2);
        }
        let path = if matches!(r.orig_rax, 83 | 84 | 87 | 258 | 263) {
            self.mutation_path(pid, path.as_bytes(), missing)?
        } else {
            self.resolve(pid, path.as_bytes(), follow, missing)?
        };
        Ok(Some((argument, path)))
    }

    /// Canonical image paths preserve assignment precedence even through links
    /// and parent components; the kernel never follows a hidden image subtree.
    pub fn native_path(&self, pid: usize, r: &UserRegs) -> Result<Option<(u8, Path)>, i64> {
        if matches!(r.orig_rax, 88 | 266) {
            return Ok(None);
        }
        let Some((argument, path)) = self.request_path(pid, r)? else {
            return Ok(None);
        };
        if self.owns_path(path.as_bytes()) {
            return Ok(None);
        }
        let raw = read_path(pid, if argument == 0 { r.rdi } else { r.rsi })?;
        if raw == path {
            return Ok(None);
        }
        Ok(Some((argument, path)))
    }

    pub fn chdir(&mut self, pid: usize, address: u64) -> Result<Option<i32>, i64> {
        let path = self.path(pid, address, (-100i64) as u64)?;
        let path = self.resolve(pid, path.as_bytes(), true, false)?;
        if self.owns_path(path.as_bytes()) {
            return self
                .fs
                .open_directory(path.as_bytes(), 0)
                .map(Some)
                .map_err(errno);
        }
        self.check_exec_owner(path.as_bytes())?;
        Ok(None)
    }

    // Borrow the caller's cwd for this syscall; the task owns its reference.
    pub fn select_cwd(&mut self, descriptor: Option<i32>) {
        self.cwd = descriptor;
    }

    // Borrow the current process group's creation mask with its cwd.
    pub fn select_creation_mask(&mut self, mask: u32) {
        self.creation_mask = mask;
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

    /// Image execution never reopens assigned paths, including implicit script
    /// and ELF interpreters selected by the native kernel loader.
    fn native_exec_resolved(&self, pid: usize, path: Path, follow: bool) -> Result<(), i64> {
        self.check_exec_owner(path.as_bytes())?;
        if !follow {
            let image = crate::path_hooks::ImageRoot::new(pid)?;
            if image
                .lookup(path.as_bytes(), &mut [0; MAX_PATH])
                .map_err(errno)?
                .0
                == NodeKind::Symlink
            {
                return Ok(());
            }
        }
        self.check_interpreters(pid, path)
    }

    pub fn validate_initial_exec(&self, pid: usize) -> Result<(), i64> {
        let path = self.resolve(pid, self.init.as_bytes(), true, false)?;
        self.check_exec_owner(path.as_bytes())?;
        let image = crate::path_hooks::ImageRoot::new(pid)?;
        let mut physical = [0; MAX_PATH];
        let length = image
            .resolve_image(self.init.as_bytes(), &mut physical)
            .map_err(errno)?;
        if physical[..length] != *path.as_bytes() {
            return Err(-95);
        }
        self.check_interpreters(pid, path)
    }

    fn check_exec_owner(&self, path: &[u8]) -> Result<(), i64> {
        if self.owns_path(path) {
            return Err(-95);
        }
        if [b"/dev".as_slice(), b"/proc", b"/sys"]
            .iter()
            .any(|p| within(path, p))
        {
            return Err(-13);
        }
        Ok(())
    }

    pub fn native_exec_fd(&self, pid: usize, fd: u32) -> Result<(), i64> {
        let image = crate::path_hooks::ImageRoot::new(pid)?;
        let mut name = [0; MAX_PATH];
        let next = crate::path_hooks::ImageRoot::interpreter_fd(pid, fd, &mut name)?;
        self.check_interpreter_chain(pid, &image, name, next)
    }

    fn check_interpreters(&self, pid: usize, path: Path) -> Result<(), i64> {
        let image = crate::path_hooks::ImageRoot::new(pid)?;
        let mut name = [0; MAX_PATH];
        let next = image.interpreter(path.as_bytes(), &mut name)?;
        self.check_interpreter_chain(pid, &image, name, next)
    }

    fn check_interpreter_chain(
        &self,
        pid: usize,
        image: &crate::path_hooks::ImageRoot,
        mut name: [u8; MAX_PATH],
        mut next: Option<(usize, bool)>,
    ) -> Result<(), i64> {
        for _ in 0..16 {
            let Some((length, script)) = next else {
                return Ok(());
            };
            if self.cwd.is_some() && name.first() != Some(&b'/') {
                return Err(-95);
            }
            let mut joined = [0; MAX_PATH];
            let cwd;
            let base = if name.first() == Some(&b'/') {
                b"".as_slice()
            } else {
                cwd = self.cwd_path(pid)?;
                cwd.as_bytes()
            };
            let separator = usize::from(!base.is_empty() && base != b"/");
            let end = base
                .len()
                .checked_add(separator)
                .and_then(|n| n.checked_add(length))
                .filter(|end| *end < MAX_PATH)
                .ok_or(-36)?;
            joined[..base.len()].copy_from_slice(base);
            if separator != 0 {
                joined[base.len()] = b'/';
            }
            joined[base.len() + separator..end].copy_from_slice(&name[..length]);
            let path = self.resolve(pid, &joined[..end], true, true)?;
            self.check_exec_owner(path.as_bytes())?;
            let mut physical = [0; MAX_PATH];
            let n = image
                .resolve_image(&joined[..end], &mut physical)
                .map_err(errno)?;
            if physical[..n] != *path.as_bytes() {
                return Err(-95);
            }
            if !script {
                return Ok(());
            }
            next = image.interpreter(path.as_bytes(), &mut name)?;
        }
        Err(-40)
    }

    /// Assigned paths yield pinned program bytes; image paths retain the native
    /// readonly loader. Neither may fall through into the other's namespace.
    pub fn exec_path(
        &mut self,
        pid: usize,
        address: u64,
        dirfd: u64,
        follow: bool,
    ) -> Result<Option<Executable>, i64> {
        let path = self.path(pid, address, dirfd)?;
        let path = self.resolve(pid, path.as_bytes(), follow, false)?;
        if self.owns_path(path.as_bytes()) {
            let image = self.fs.pin_executable(path.as_bytes()).map_err(errno)?;
            return self.check_exec(pid, image).map(Some);
        }
        self.native_exec_resolved(pid, path, follow)?;
        Ok(None)
    }

    pub fn exec_descriptor(&mut self, pid: usize, handle: u32) -> Result<Executable, i64> {
        let fd = handle
            .checked_sub(FD_BASE as u32)
            .filter(|n| *n < 64)
            .ok_or(-95)?;
        let image = self.fs.pin_executable_fd(fd as i32 + 3).map_err(errno)?;
        self.check_exec(pid, image)
    }

    /// Readonly reopening through a public descriptor resolved by its owner.
    /// It cannot import a native fd or grant host filesystem write authority.
    pub fn open_descriptor(
        &mut self,
        pid: usize,
        handle: u32,
        suffix: &[u8],
        flags: u64,
    ) -> Result<i64, i64> {
        let fd = handle
            .checked_sub(FD_BASE as u32)
            .filter(|n| *n < 64)
            .ok_or(-95)? as i32
            + 3;
        const ALLOWED: u64 = 0o4000 | 0o100000 | 0o200000 | 0o400000 | 0o2000000;
        if flags & !ALLOWED != 0 {
            return Err(-13);
        }
        if !suffix.is_empty() {
            let directory = self.fs.directory_path(fd).map_err(errno)?;
            let joined = join_path(directory, &suffix[1..])?;
            let path = self.resolve(pid, joined.as_bytes(), true, false)?;
            if !self.owns_path(path.as_bytes()) {
                return Err(-95);
            }
            return self.open(path.as_bytes(), flags, 0);
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

    fn check_exec(&mut self, pid: usize, image: Executable) -> Result<Executable, i64> {
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
                let mut name = [0; MAX_PATH];
                let next = crate::path_hooks::interpreter_metadata(
                    |offset, output| {
                        self.read_executable(
                            image,
                            usize::try_from(offset).map_err(|_| -8)?,
                            output,
                        )
                    },
                    &mut name,
                )?;
                let root = crate::path_hooks::ImageRoot::new(pid)?;
                self.check_interpreter_chain(pid, &root, name, next)?;
                Ok(image)
            }
        });
        if result.is_err() {
            self.release_executable(image)
                .expect("invalid executable pin release");
        }
        result
    }

    pub fn is_script(&self, image: Executable) -> Result<bool, i64> {
        let mut header = [0; 2];
        self.read_executable(image, 0, &mut header)?;
        Ok(header == *b"#!")
    }

    /// Resolve an implicit interpreter through the same component and
    /// assignment owner as an explicit program. Native chains must also match
    /// the image kernel will traverse; owned scripts are resolved separately.
    pub fn interpreter_path(&self, pid: usize, name: &[u8]) -> Result<Path, i64> {
        let cwd;
        let base = if name.first() == Some(&b'/') {
            b"".as_slice()
        } else {
            cwd = self.cwd_path(pid)?;
            cwd.as_bytes()
        };
        let joined = join_path(base, name)?;
        self.resolve(pid, joined.as_bytes(), true, false)
    }

    pub fn exec_interpreter(&mut self, pid: usize, name: &[u8]) -> Result<Option<Executable>, i64> {
        let path = self.interpreter_path(pid, name)?;
        if self.owns_path(path.as_bytes()) {
            let image = self.fs.pin_executable(path.as_bytes()).map_err(errno)?;
            return self.check_exec(pid, image).map(Some);
        }
        self.check_exec_owner(path.as_bytes())?;
        self.check_interpreters(pid, path)?;
        Ok(None)
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

    pub fn mapping_reference(&mut self, handle: u32) -> Result<usize, i64> {
        let slot = handle
            .checked_sub(FD_BASE as u32)
            .filter(|n| *n < 64)
            .ok_or(-9)?;
        let (storage, object) = self.fs.readable_storage(slot as i32 + 3).map_err(errno)?;
        let fd = storage.backing(object).map_err(errno)?;
        crate::file_mapping::readonly_reference(fd)
    }

    pub fn executable_name(&self, image: Executable) -> Result<ExecutableName, i64> {
        let (name, deleted) = self.fs.executable_name(image).map_err(errno)?;
        let suffix = if deleted {
            b" (deleted)".as_slice()
        } else {
            b""
        };
        let mut bytes = [0; MAX_PATH + 10];
        bytes[..name.len()].copy_from_slice(name);
        bytes[name.len()..name.len() + suffix.len()].copy_from_slice(suffix);
        ExecutableName::from_bytes(&bytes[..name.len() + suffix.len()]).map_err(|_| -36)
    }

    /// Configured-launch dispatch only; demo paths keep their existing contract.
    pub fn claim(&mut self, pid: usize, r: &UserRegs) -> Option<i64> {
        if matches!(r.orig_rax, 86 | 265) {
            return Some(self.hard_link(pid, r).unwrap_or_else(|error| error));
        }
        if matches!(r.orig_rax, 82 | 264 | 316) {
            return Some(self.rename(pid, r).unwrap_or_else(|error| error));
        }
        let fd = r.rdi as i32;
        if r.orig_rax == 280 && r.rsi == 0 {
            return Some(if (FD_BASE as i32..FD_BASE as i32 + 64).contains(&fd) {
                self.descriptor_call(pid, r, fd - FD_BASE as i32 + 3)
            } else {
                -9
            });
        }
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
                | 73
                | 74
                | 75
                | 77
                | 91
                | 93
                | 217
                | 292
        ) && fd >= FD_BASE as i32
        {
            return Some(self.descriptor_call(pid, r, fd - FD_BASE as i32 + 3));
        }
        if matches!(r.orig_rax, 260 | 262 | 332 | 439) {
            match read_path(pid, r.rsi) {
                Ok(p) if p.is_empty() && fd >= FD_BASE as i32 => {
                    return Some(self.descriptor_call(pid, r, fd - FD_BASE as i32 + 3))
                }
                Ok(p) if p.is_empty() => return None,
                Err(error) => return Some(error),
                _ => {}
            }
        }
        let path = match self.request_path(pid, r) {
            Ok(Some((_, path))) => path,
            Ok(None) => return None,
            Err(error) => return Some(error),
        };
        if !self.owns_path(path.as_bytes()) {
            return None;
        }
        let result = match r.orig_rax {
            2 => self.open(path.as_bytes(), r.rsi, r.rdx),
            257 => self.open(path.as_bytes(), r.rdx, r.r10),
            4 | 6 => self.stat(pid, path.as_bytes(), r.rsi, false),
            280 => self.timestamps(pid, r).and_then(|times| {
                self.fs
                    .set_times(path.as_bytes(), false, times[0], times[1])
                    .map(|_| 0)
                    .map_err(errno)
            }),
            92 | 94 => self
                .fs
                .metadata_no_follow(path.as_bytes())
                .map_err(errno)
                .and_then(|_| preserve_owner(r.rsi, r.rdx)),
            260 if r.r8 & !0x1100 == 0 => self
                .fs
                .metadata_no_follow(path.as_bytes())
                .map_err(errno)
                .and_then(|_| preserve_owner(r.rdx, r.r10)),
            260 => Err(-22),
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
                            if copy_memory(pid, address, &mut target[..n], true) != Ok(n as i64) {
                                return Err(-14);
                            }
                            Ok(n as i64)
                        })
                }
            }
            262 => {
                if r.r10 & !0x1900 != 0 {
                    Err(-22)
                } else {
                    self.stat(pid, path.as_bytes(), r.rdx, false)
                }
            }
            332 => {
                if !valid_statx(r.rdx, r.r10) {
                    Err(-22)
                } else {
                    self.stat(pid, path.as_bytes(), r.r8, true)
                }
            }
            83 => self
                .fs
                .mkdir(path.as_bytes(), r.rsi as u32 & 0o777 & !self.creation_mask)
                .map(|_| 0)
                .map_err(errno),
            258 => self
                .fs
                .mkdir(path.as_bytes(), r.rdx as u32 & 0o777 & !self.creation_mask)
                .map(|_| 0)
                .map_err(errno),
            87 => self.fs.unlink(path.as_bytes()).map(|_| 0).map_err(errno),
            84 => self.remove_directory(path.as_bytes()),
            263 => {
                if r.rdx == 0x200 {
                    self.remove_directory(path.as_bytes())
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
            _ => Err(-95),
        };
        Some(result.unwrap_or_else(|error| error))
    }

    fn open(&mut self, path: &[u8], flags: u64, mode: u64) -> Result<i64, i64> {
        // Unsupported directory/path-only behavior never falls through to native storage.
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
            self.fs
                .fchmod(fd, mode as u32 & 0o777 & !self.creation_mask)
                .map_err(errno)?;
        }
        Ok(FD_BASE as i64 + fd as i64 - 3)
    }

    fn remove_directory(&mut self, path: &[u8]) -> Result<i64, i64> {
        if self.assignment_root(path) {
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

    fn hard_link(&mut self, pid: usize, r: &UserRegs) -> Result<i64, i64> {
        let (source, destination, flags) = if r.orig_rax == 86 {
            (
                self.path(pid, r.rdi, (-100i64) as u64)?,
                self.path(pid, r.rsi, (-100i64) as u64)?,
                0,
            )
        } else {
            (
                self.path(pid, r.rsi, r.rdi)?,
                self.path(pid, r.r10, r.rdx)?,
                r.r8,
            )
        };
        if flags & !0x400 != 0 {
            return Err(-95);
        }
        let source = self.resolve(pid, source.as_bytes(), flags & 0x400 != 0, false)?;
        let raw_destination_slash = destination.as_bytes().ends_with(b"/");
        let destination = self.mutation_path(pid, destination.as_bytes(), true)?;
        if !self.owns_path(source.as_bytes()) || !self.owns_path(destination.as_bytes()) {
            return Err(-18);
        }
        if raw_destination_slash && self.fs.metadata_no_follow(destination.as_bytes()).is_err() {
            return Err(-2);
        }
        self.fs
            .hard_link(source.as_bytes(), destination.as_bytes(), false)
            .map(|_| 0)
            .map_err(errno)
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
        if dot_entry(source.as_bytes()) || dot_entry(destination.as_bytes()) {
            return Err(-22);
        }
        let directory_destination = destination.as_bytes().ends_with(b"/");
        let source = self.mutation_path(pid, source.as_bytes(), false)?;
        let destination = self.mutation_path(pid, destination.as_bytes(), true)?;
        if flags > 1 {
            return Err(-95);
        }
        if !self.owns_path(source.as_bytes()) || !self.owns_path(destination.as_bytes()) {
            return Err(-18);
        }
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
            .rename(source.as_bytes(), destination.as_bytes(), flags == 1)
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
            1 => self.write(pid, fd, r.rsi, r.rdx, None),
            19 | 20 => self.vector_io(pid, fd, r),
            18 => self.write(pid, fd, r.rsi, r.rdx, Some(r.r10 as i64)),
            3 => {
                self.flocks.release((fd - 3) as u32, None);
                self.fs.close(fd).map(|_| 0).map_err(errno)
            }
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
            74 | 75 => self.fs.fstat(fd).map_err(errno).and_then(|metadata| {
                if metadata.kind == NodeKind::Directory {
                    return Ok(0);
                }
                let (storage, object) = self.fs.descriptor_storage(fd).map_err(errno)?;
                storage
                    .sync(object, r.orig_rax == 75)
                    .map(|_| 0)
                    .map_err(errno)
            }),
            93 => self
                .fs
                .fstat(fd)
                .map_err(errno)
                .and_then(|_| preserve_owner(r.rsi, r.rdx)),
            260 if r.r8 & !0x1100 != 0 => Err(-22),
            260 if r.r8 & 0x1000 == 0 => Err(-2),
            260 => self
                .fs
                .fstat(fd)
                .map_err(errno)
                .and_then(|_| preserve_owner(r.rdx, r.r10)),
            77 if r.rsi as i64 >= 0 => self.fs.truncate(fd, r.rsi).map(|_| 0).map_err(errno),
            77 => Err(-22),
            217 => self.getdents(pid, fd, r.rsi, r.rdx),
            439 => {
                if r.r10 & 0x1000 == 0 {
                    Err(-2)
                } else {
                    self.fs
                        .fstat(fd)
                        .map_err(errno)
                        .and_then(|metadata| access(metadata, r))
                }
            }
            73 => self.flock(fd, r.rsi),
            72 if matches!(r.rsi, 5..=7) => self.file_lock(pid, fd, r.rsi, r.rdx),
            280 if r.r10 == 0 => self.timestamps(pid, r).and_then(|times| {
                self.fs
                    .fset_times(fd, times[0], times[1])
                    .map(|_| 0)
                    .map_err(errno)
            }),
            280 => Err(-22),
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
            262 | 332 => {
                let flags = if r.orig_rax == 262 { r.r10 } else { r.rdx };
                let valid = if r.orig_rax == 262 {
                    flags & !0x1900 == 0
                } else {
                    valid_statx(flags, r.r10)
                };
                if flags & 0x1000 == 0 || !valid {
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

    fn flock(&mut self, fd: i32, operation: u64) -> Result<i64, i64> {
        let kind = operation & !4;
        if !matches!(kind, 1 | 2 | 8) {
            return Err(-22);
        }
        let metadata = self.fs.fstat(fd).map_err(errno)?;
        if !matches!(metadata.kind, NodeKind::File | NodeKind::Directory) {
            return Err(-9);
        }
        let lock = crate::file_locks::Lock {
            inode: metadata.inode,
            owner: (fd - 3) as u32,
            range: crate::file_locks::Range::new(0, 0, 0)?,
            write: kind == 2,
        };
        // flock belongs to the open description, including aliases across fork.
        // Converting a shared lock may release it before waiting for exclusive.
        self.flocks.release(lock.owner, None);
        if kind != 8 {
            self.flocks.set(lock, false)?;
        }
        Ok(0)
    }

    fn file_lock(&mut self, pid: usize, fd: i32, command: u64, address: u64) -> Result<i64, i64> {
        let metadata = self.fs.fstat(fd).map_err(errno)?;
        if metadata.kind != NodeKind::File {
            return Err(-9);
        }
        let mut bytes = [0u8; 32];
        if copy_memory(pid, address, &mut bytes, false)? != 32 {
            return Err(-14);
        }
        let kind = i16::from_ne_bytes(bytes[..2].try_into().unwrap());
        let whence = i16::from_ne_bytes(bytes[2..4].try_into().unwrap());
        let start = i64::from_ne_bytes(bytes[8..16].try_into().unwrap());
        let length = i64::from_ne_bytes(bytes[16..24].try_into().unwrap());
        if !(0..=2).contains(&kind) || (command == 5 && kind == 2) {
            return Err(-22);
        }
        let base = match whence {
            0 => 0,
            1 => self.fs.seek(fd, 0, 1).map_err(errno)?,
            2 => metadata.size,
            _ => return Err(-22),
        };
        let (flags, _) = self.fs.descriptor_flags(fd).map_err(errno)?;
        if command != 5 && ((kind == 0 && flags & 3 == 1) || (kind == 1 && flags & 3 == 0)) {
            return Err(-9);
        }
        let lock = crate::file_locks::Lock {
            inode: metadata.inode,
            owner: self.process,
            range: crate::file_locks::Range::new(base, start, length)?,
            write: kind == 1,
        };
        if command != 5 {
            self.locks.set(lock, kind == 2)?;
        } else {
            if let Some(conflict) = self.locks.conflict(lock) {
                bytes[..2]
                    .copy_from_slice(&(if conflict.write { 1i16 } else { 0i16 }).to_ne_bytes());
                bytes[2..4].copy_from_slice(&0i16.to_ne_bytes());
                bytes[8..16].copy_from_slice(&(conflict.range.start as i64).to_ne_bytes());
                let length = if conflict.range.end == i64::MAX as u64 + 1 {
                    0
                } else {
                    conflict.range.end - conflict.range.start
                };
                bytes[16..24].copy_from_slice(&(length as i64).to_ne_bytes());
                bytes[24..28].copy_from_slice(&(conflict.owner as i32).to_ne_bytes());
            } else {
                bytes[..2].copy_from_slice(&2i16.to_ne_bytes());
            }
            if copy_memory(pid, address, &mut bytes, true)? != 32 {
                return Err(-14);
            }
        }
        Ok(0)
    }

    fn timestamps(
        &self,
        pid: usize,
        r: &UserRegs,
    ) -> Result<[Option<ginux_vfs::Timestamp>; 2], i64> {
        if r.r10 & !0x100 != 0 {
            return Err(-22);
        }
        let mut bytes = [0u8; 32];
        if r.rdx != 0 && copy_memory(pid, r.rdx, &mut bytes, false)? != 32 {
            return Err(-14);
        }
        let mut times = [None; 2];
        let mut now = None;
        for (index, time) in times.iter_mut().enumerate() {
            let seconds = i64::from_ne_bytes(bytes[index * 16..index * 16 + 8].try_into().unwrap());
            let nanos = if r.rdx == 0 {
                (1 << 30) - 1
            } else {
                i64::from_ne_bytes(bytes[index * 16 + 8..index * 16 + 16].try_into().unwrap())
            };
            *time = match nanos {
                1_073_741_822 => None,
                1_073_741_823 => {
                    if now.is_none() {
                        let mut clock = [0i64; 2];
                        if unsafe {
                            crate::supervisor::syscall2(228, 0, clock.as_mut_ptr() as usize)
                        } != 0
                        {
                            return Err(-5);
                        }
                        now = Some(ginux_vfs::Timestamp {
                            seconds: clock[0],
                            nanoseconds: clock[1] as u32,
                        });
                    }
                    now
                }
                0..=999_999_999 => Some(ginux_vfs::Timestamp {
                    seconds,
                    nanoseconds: nanos as u32,
                }),
                _ => return Err(-22),
            };
        }
        Ok(times)
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

    fn vector_io(&mut self, pid: usize, fd: i32, r: &UserRegs) -> Result<i64, i64> {
        let vectors = crate::tracee_io::IoVectors::read(pid, r.rsi, r.rdx)?;
        let mut bytes = [0u8; IO_SIZE];
        let count = vectors.length.min(IO_SIZE);
        if r.orig_rax == 20 {
            let copied = vectors.copy(pid, &mut bytes[..count], false)?;
            self.fs
                .write(fd, &bytes[..copied])
                .map(|n| n as i64)
                .map_err(errno)
        } else {
            let offset = self.fs.seek(fd, 0, 1).map_err(errno)?;
            let read = self.fs.read(fd, &mut bytes[..count]).map_err(errno)?;
            let result = vectors.copy(pid, &mut bytes[..read], true);
            self.fs
                .seek(
                    fd,
                    (offset + result.as_ref().copied().unwrap_or(0) as u64) as i64,
                    0,
                )
                .map_err(errno)?;
            result.map(|n| n as i64)
        }
    }

    fn write(
        &mut self,
        pid: usize,
        fd: i32,
        address: u64,
        length: u64,
        offset: Option<i64>,
    ) -> Result<i64, i64> {
        self.fs.fstat(fd).map_err(errno)?;
        let previous = self.fs.seek(fd, 0, 1).map_err(errno)?;
        if let Some(offset) = offset {
            self.fs.seek(fd, offset, 0).map_err(errno)?;
        }
        let result = (|| {
            let mut buffer = [0u8; IO_SIZE];
            let limit = length.min(1024 * 1024) as usize;
            if limit == 0 {
                return self.fs.write(fd, &[]).map(|n| n as i64).map_err(errno);
            }
            let mut written = 0usize;
            while written < limit {
                let count = (limit - written).min(IO_SIZE);
                let copy = address
                    .checked_add(written as u64)
                    .ok_or(-14)
                    .and_then(|address| copy_memory(pid, address, &mut buffer[..count], false));
                let copied = match copy {
                    Ok(n) => n as usize,
                    Err(_) if written != 0 => break,
                    Err(error) => return Err(error),
                };
                match self.fs.write(fd, &buffer[..copied]).map_err(errno) {
                    Ok(n) => {
                        written += n;
                        if n != copied || copied != count {
                            break;
                        }
                    }
                    Err(_) if written != 0 => break,
                    Err(error) => return Err(error),
                }
            }
            Ok(written as i64)
        })();
        if offset.is_some() {
            self.fs.seek(fd, previous as i64, 0).map_err(errno)?;
        }
        result
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

pub(crate) fn valid_statx(flags: u64, mask: u64) -> bool {
    flags & !0x7900 == 0 && flags & 0x6000 != 0x6000 && mask & 0x8000_0000 == 0
}

// Owned inode uid/gid are always virtual root, as projected by copy_metadata.
// Preserving that identity is a real no-op; changing it is unsupported. No host
// chown syscall is issued for a instance path or private backing descriptor.
fn preserve_owner(uid: u64, gid: u64) -> Result<i64, i64> {
    if [uid, gid]
        .iter()
        .all(|id| matches!(*id as u32, 0 | u32::MAX))
    {
        Ok(0)
    } else {
        Err(-95)
    }
}

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

fn dot_entry(path: &[u8]) -> bool {
    path.rsplit(|byte| *byte == b'/')
        .find(|component| !component.is_empty())
        .is_some_and(|component| matches!(component, b"." | b".."))
}

fn within(path: &[u8], prefix: &[u8]) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.first() == Some(&b'/'))
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
            accessed: metadata.accessed,
            modified: metadata.modified,
            inode: metadata.inode,
            links: metadata.links,
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

fn join_path(base: &[u8], name: &[u8]) -> Result<Path, i64> {
    let mut bytes = [0; MAX_PATH];
    let separator = usize::from(!base.is_empty() && base != b"/");
    let end = base
        .len()
        .checked_add(separator)
        .and_then(|n| n.checked_add(name.len()))
        .filter(|n| *n < MAX_PATH)
        .ok_or(-36)?;
    bytes[..base.len()].copy_from_slice(base);
    if separator != 0 {
        bytes[base.len()] = b'/';
    }
    bytes[base.len() + separator..end].copy_from_slice(name);
    Path::from_bytes(&bytes[..end]).map_err(|_| -36)
}
