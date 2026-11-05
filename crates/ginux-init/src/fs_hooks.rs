//! Configured-launch ephemeral memory storage. Bytes and descriptors belong to
//! the supervisor; no writable host descriptor is installed in the workload.
//! Directory descriptions and executable references share the VFS owner.
//! Retained storage and guest file mappings are not provided.

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
const OBJECTS: usize = 4096;
type MemoryFs = VirtualFs<'static, EmptyReader, OBJECTS, 0, 64, MemoryStorage<OBJECTS>>;
static mut ROOT_INDEX: [u8; HEADER_SIZE + RECORD_SIZE] = [0; HEADER_SIZE + RECORD_SIZE];
static ROOT_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub struct EmptyReader;
impl BaseReader for EmptyReader {
    fn read_at(&mut self, _: u64, _: &mut [u8]) -> Result<(), VfsError> {
        Err(VfsError::Io)
    }
}

pub struct LaunchFs {
    fs: MemoryFs,
    prefixes: [Path; 8],
    count: usize,
    cwd: Path,
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
            cwd: Path::from_bytes(config.workdir.as_bytes())
                .map_err(|_| b"storage workdir exceeds bound".as_slice())?,
        })
    }

    pub fn enabled(&self) -> bool {
        self.count != 0
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

    pub(crate) fn path(&self, pid: usize, address: u64, dirfd: u64) -> Result<Path, i64> {
        let text = read_path(pid, address)?;
        if text.is_empty() {
            return Err(-2);
        }
        let absolute = text.as_bytes().first() == Some(&b'/');
        let base = if absolute {
            b"/".as_slice()
        } else if dirfd as i32 == -100 {
            self.cwd.as_bytes()
        } else {
            let fd = (dirfd as u32)
                .checked_sub(FD_BASE as u32)
                .filter(|n| *n < 64)
                .ok_or(-9)?;
            self.fs.directory_path(fd as i32 + 3).map_err(errno)?
        };
        let path = normalize(base, text.as_bytes())?;
        if !absolute && dirfd as i32 != -100 && !self.owns_path(path.as_bytes()) {
            // The image does not share this directory descriptor. Never pass
            // the private integer to a native open outside assigned storage.
            return Err(-95);
        }
        Ok(path)
    }

    /// Assigned paths yield pinned ELF bytes; image paths retain the native
    /// readonly loader. Neither may fall through into the other's namespace.
    pub fn exec_path(
        &mut self,
        pid: usize,
        address: u64,
        dirfd: u64,
    ) -> Result<Option<Executable>, i64> {
        let path = self.path(pid, address, dirfd)?;
        if self.owns_path(path.as_bytes()) {
            let image = self.fs.pin_executable(path.as_bytes()).map_err(errno)?;
            return self.check_exec(image).map(Some);
        }
        if [b"/dev".as_slice(), b"/proc", b"/sys"]
            .iter()
            .any(|p| within(path.as_bytes(), p))
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

    fn check_exec(&mut self, image: Executable) -> Result<Executable, i64> {
        let mut header = [0u8; 64];
        let result = self.read_executable(image, 0, &mut header).and_then(|n| {
            if header.starts_with(b"#!") {
                Err(-95)
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
        if matches!(r.orig_rax, 262 | 332) {
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
            2 | 4 | 6 | 83 | 84 | 87 | 90 => (r.rdi, (-100i64) as u64),
            257 | 258 | 262 | 263 | 268 | 332 => (r.rsi, r.rdi),
            _ => return None,
        };
        let path = match self.path(pid, address, dirfd) {
            Ok(path) => path,
            Err(error) => return Some(error),
        };
        if !self.owns_path(path.as_bytes()) {
            return None;
        }
        let result = match r.orig_rax {
            2 => self.open(path.as_bytes(), r.rsi, r.rdx),
            257 => self.open(path.as_bytes(), r.rdx, r.r10),
            4 | 6 => self.stat(pid, path.as_bytes(), r.rsi, false),
            262 => {
                if r.r10 & !0x100 != 0 {
                    Err(-22)
                } else {
                    self.stat(pid, path.as_bytes(), r.rdx, false)
                }
            }
            332 => {
                if r.rdx & !0x9100 != 0 {
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
            _ => Err(-38),
        };
        Some(result.unwrap_or_else(|error| error))
    }

    fn open(&mut self, path: &[u8], flags: u64, mode: u64) -> Result<i64, i64> {
        // NOFOLLOW is valid because this backend has no symlinks. Unsupported
        // path-only behavior never falls through to native storage.
        const ALLOWED: u64 = 3
            | 0o100
            | 0o200
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
            self.fs.metadata(path).map_err(errno)?,
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
                | if metadata.kind == NodeKind::Directory {
                    0o40000
                } else {
                    0o100000
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
