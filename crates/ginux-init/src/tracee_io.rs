//! Controlled copies and x86-64 metadata serialization for native tracees.
use crate::supervisor::{syscall4, syscall6};
use ginux_instance::Text;
use ginux_vfs::MAX_PATH;
type Path = Text<MAX_PATH>;

#[repr(C)]
struct IoVec {
    address: usize,
    length: usize,
}

// Parent-only calls honor guest page protections. No PTRACE forced copyout.
pub fn copy_memory(pid: usize, address: u64, buffer: &mut [u8], output: bool) -> Result<i64, i64> {
    if buffer.is_empty() {
        return Ok(0);
    }
    address.checked_add(buffer.len() as u64).ok_or(-14)?;
    let local = IoVec {
        address: buffer.as_mut_ptr() as usize,
        length: buffer.len(),
    };
    let remote = IoVec {
        address: address as usize,
        length: buffer.len(),
    };
    let result = unsafe {
        syscall6(
            if output { 311 } else { 310 },
            pid,
            &local as *const _ as usize,
            1,
            &remote as *const _ as usize,
            1,
            0,
        )
    };
    if result <= 0 {
        Err(-14)
    } else {
        Ok(result as i64)
    }
}

/// The NUL-terminated path at `address` of the stopped tracee, at most
/// `MAX_PATH` bytes. It is read a page at a time (one `process_vm_readv` per
/// page it touches, not one per byte), so a path that ends just before an
/// unmapped page is complete and a fault before its NUL is EFAULT, as a
/// byte-at-a-time read gives.
pub fn read_path(pid: usize, address: u64) -> Result<Path, i64> {
    let mut buffer = [0; MAX_PATH];
    let mut filled = 0;
    while filled < MAX_PATH {
        let start = address.checked_add(filled as u64).ok_or(-14)?;
        let room = (MAX_PATH - filled).min(4096 - (start % 4096) as usize);
        let read = copy_memory(pid, start, &mut buffer[filled..filled + room], false)? as usize;
        if let Some(end) = buffer[filled..filled + read].iter().position(|byte| *byte == 0) {
            return Path::from_bytes(&buffer[..filled + end]).map_err(|_| -36);
        }
        filled += read;
    }
    Err(-36)
}

/// Kernel-owned image cwd, expressed relative to the tracee's chroot. Reading
/// the two proc links does not let a workload select a supervisor host path.
/// Fork and CLONE_FS sharing retain their native directory semantics.
pub fn image_cwd(pid: usize) -> Result<Path, i64> {
    image_link(pid, b"/cwd")
}

pub fn image_fd_path(pid: usize, fd: u32) -> Result<Path, i64> {
    let mut member = [0u8; 24];
    member[..4].copy_from_slice(b"/fd/");
    let mut digits = [0; 10];
    let mut n = fd;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (n % 10) as u8;
        count += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for i in 0..count {
        member[4 + i] = digits[count - 1 - i];
    }
    image_link(pid, &member[..4 + count])
}

pub fn image_link(pid: usize, member: &[u8]) -> Result<Path, i64> {
    fn link(pid: usize, suffix: &[u8], output: &mut [u8]) -> Result<usize, i64> {
        let mut name = [0u8; 64];
        name[..6].copy_from_slice(b"/proc/");
        let mut digits = [0u8; 20];
        let mut number = pid;
        let mut count = 0;
        loop {
            digits[count] = b'0' + (number % 10) as u8;
            count += 1;
            number /= 10;
            if number == 0 {
                break;
            }
        }
        for n in 0..count {
            name[6 + n] = digits[count - n - 1];
        }
        name[6 + count..6 + count + suffix.len()].copy_from_slice(suffix);
        let result = unsafe {
            crate::supervisor::syscall3(
                89,
                name.as_ptr() as usize,
                output.as_mut_ptr() as usize,
                output.len(),
            )
        };
        if result < 0 {
            return Err(result as i64);
        }
        if result as usize == output.len() {
            return Err(-36);
        }
        Ok(result as usize)
    }
    let mut root = [0u8; 4096];
    let mut cwd = [0u8; 4096];
    let root_len = link(pid, b"/root", &mut root)?;
    let cwd_len = link(pid, member, &mut cwd)?;
    let relative = if &root[..root_len] == b"/" {
        &cwd[..cwd_len]
    } else {
        cwd[..cwd_len].strip_prefix(&root[..root_len]).ok_or(-13)?
    };
    if relative.is_empty() {
        return Path::from_bytes(b"/").map_err(|_| -36);
    }
    if relative[0] != b'/' || relative.ends_with(b" (deleted)") {
        return Err(-2);
    }
    Path::from_bytes(relative).map_err(|_| -36)
}

/// Thread-group and parent identity of a host task the supervisor traces,
/// as the kernel reports them. `None` once the task is gone.
pub fn native_identity(pid: usize) -> Option<(usize, usize)> {
    let mut text = [0u8; 4096];
    let length = read_status(pid, &mut text)?;
    let field = |name: &[u8]| -> Option<usize> {
        let line = text[..length]
            .split(|byte| *byte == b'\n')
            .find(|line| line.starts_with(name))?;
        let mut value = 0usize;
        for digit in line[name.len()..].trim_ascii() {
            value = value
                .checked_mul(10)?
                .checked_add((*digit as char).to_digit(10)? as usize)?;
        }
        Some(value)
    };
    Some((field(b"Tgid:")?, field(b"PPid:")?))
}

/// Reads `/proc/<pid>/status`. The name is built only from a host identity
/// the supervisor obtained from its own wait or ptrace results.
pub fn read_status(pid: usize, text: &mut [u8]) -> Option<usize> {
    let mut name = [0u8; 40];
    name[..6].copy_from_slice(b"/proc/");
    let mut digits = [0u8; 20];
    let mut number = pid;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (number % 10) as u8;
        count += 1;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    for n in 0..count {
        name[6 + n] = digits[count - n - 1];
    }
    name[6 + count..6 + count + 7].copy_from_slice(b"/status");
    let fd = unsafe {
        syscall4(
            257,
            (-100isize) as usize,
            name.as_ptr() as usize,
            0x80000,
            0,
        )
    };
    if fd < 0 {
        return None;
    }
    let mut length = 0;
    while length < text.len() {
        let read = unsafe {
            crate::supervisor::syscall3(
                0,
                fd as usize,
                text[length..].as_mut_ptr() as usize,
                text.len() - length,
            )
        };
        if read == -4 {
            continue;
        }
        if read <= 0 {
            break;
        }
        length += read as usize;
    }
    unsafe {
        crate::supervisor::syscall1(3, fd as usize);
    }
    Some(length)
}

/// Linux file type bits are part of mode; identities belong to the instance.
pub struct Stat {
    pub accessed: ginux_vfs::Timestamp,
    pub modified: ginux_vfs::Timestamp,
    pub inode: u64,
    pub links: u64,
    pub mode: u32,
    pub size: u64,
    pub device_major: u32,
    pub device_minor: u32,
}

pub fn write_stat(pid: usize, address: u64, metadata: Stat, statx: bool) -> Result<i64, i64> {
    let mut bytes = [0u8; 256];
    let mode = metadata.mode;
    let (ino, mode_at, size_at, blocks_at, length) = if statx {
        bytes[..4].copy_from_slice(&0x7ffu32.to_le_bytes());
        bytes[4..8].copy_from_slice(&4096u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&(metadata.links as u32).to_le_bytes());
        bytes[28..30].copy_from_slice(&(mode as u16).to_le_bytes());
        (32, None, 40, 48, 256)
    } else {
        bytes[16..24].copy_from_slice(&metadata.links.to_le_bytes());
        bytes[56..64].copy_from_slice(&4096u64.to_le_bytes());
        (8, Some(24), 48, 64, 144)
    };
    if statx {
        bytes[128..132].copy_from_slice(&metadata.device_major.to_le_bytes());
        bytes[132..136].copy_from_slice(&metadata.device_minor.to_le_bytes());
    } else {
        let major = metadata.device_major as u64;
        let minor = metadata.device_minor as u64;
        let rdev = (minor & 0xff)
            | ((major & 0xfff) << 8)
            | ((minor & !0xff) << 12)
            | ((major & !0xfff) << 32);
        bytes[40..48].copy_from_slice(&rdev.to_le_bytes());
    }
    for (index, time) in [metadata.accessed, metadata.modified].iter().enumerate() {
        let offset = if statx {
            64 + index * 48
        } else {
            72 + index * 16
        };
        bytes[offset..offset + 8].copy_from_slice(&time.seconds.to_le_bytes());
        if statx {
            bytes[offset + 8..offset + 12].copy_from_slice(&time.nanoseconds.to_le_bytes());
        } else {
            bytes[offset + 8..offset + 16]
                .copy_from_slice(&(time.nanoseconds as u64).to_le_bytes());
        }
    }
    bytes[ino..ino + 8].copy_from_slice(&metadata.inode.to_le_bytes());
    if let Some(mode_at) = mode_at {
        bytes[mode_at..mode_at + 4].copy_from_slice(&mode.to_le_bytes());
    }
    bytes[size_at..size_at + 8].copy_from_slice(&metadata.size.to_le_bytes());
    bytes[blocks_at..blocks_at + 8].copy_from_slice(&metadata.size.div_ceil(512).to_le_bytes());
    if copy_memory(pid, address, &mut bytes[..length], true)? != length as i64 {
        return Err(-14);
    }
    Ok(0)
}

/// Native open/dup cannot obtain descriptors reserved for instance objects.
/// Keep an operator's lower soft/hard limits, and never raise either bound.
pub fn reserve_native_descriptors(limit: usize) -> bool {
    let mut limits = [0u64; 2];
    if unsafe { syscall4(302, 0, 7, 0, limits.as_mut_ptr() as usize) } < 0 {
        return false;
    }
    limits[0] = limits[0].min(limit as u64);
    limits[1] = limits[1].min(limit as u64);
    unsafe { syscall4(302, 0, 7, limits.as_ptr() as usize, 0) == 0 }
}

/// Publish a word all or nothing across a page boundary. Reads may use ptrace,
/// but every write goes through the strict copy path and honors page protections.
pub fn store_u32(pid: usize, address: u64, value: u32) -> Result<(), i64> {
    let mut bytes = value.to_ne_bytes();
    address.checked_add(4).ok_or(-14)?;
    let head = 4096 - (address as usize & 4095);
    if head >= 4 {
        return if copy_memory(pid, address, &mut bytes, true) == Ok(4) {
            Ok(())
        } else {
            Err(-14)
        };
    }
    let tail = address + head as u64;
    let mut previous = 0usize;
    if crate::supervisor::ptrace(
        crate::supervisor::PTRACE_PEEKTEXT,
        pid,
        tail as usize,
        &mut previous as *mut _ as usize,
    ) < 0
    {
        return Err(-14);
    }
    if copy_memory(pid, tail, &mut bytes[head..], true) != Ok((4 - head) as i64) {
        return Err(-14);
    }
    if copy_memory(pid, address, &mut bytes[..head], true) != Ok(head as i64) {
        let mut original = previous.to_ne_bytes();
        if copy_memory(pid, tail, &mut original[..4 - head], true) != Ok((4 - head) as i64) {
            return Err(-5);
        }
        return Err(-14);
    }
    Ok(())
}

/// The total length a `readv` of `count` vectors at `address` requests, read
/// from the stopped tracee in bounded chunks. `None` when the kernel itself
/// rejects the array: it cannot be read, it has more than `UIO_MAXIOV`
/// entries, or one length is negative as `ssize_t`. Like the kernel, only the
/// low 32 bits of the count are significant; a total beyond `u64` saturates.
pub fn vector_total(pid: usize, address: u64, count: u64) -> Option<u64> {
    const UIO_MAXIOV: u64 = 1024;
    const CHUNK: usize = 64;
    let count = u64::from(count as u32);
    if count > UIO_MAXIOV {
        return None;
    }
    let mut bytes = [0u8; CHUNK * 16];
    let mut total = 0u64;
    let mut done = 0;
    while done < count {
        let size = (count - done).min(CHUNK as u64) as usize * 16;
        let start = address.checked_add(done * 16)?;
        if copy_memory(pid, start, &mut bytes[..size], false) != Ok(size as i64) {
            return None;
        }
        for entry in bytes[..size].as_chunks::<16>().0 {
            let length = u64::from_ne_bytes(entry[8..].try_into().unwrap());
            if length > i64::MAX as u64 {
                return None;
            }
            total = total.saturating_add(length);
        }
        done += (size / 16) as u64;
    }
    Some(total)
}

/// Bounded scatter/gather layout shared by owned byte-stream backends.
pub struct IoVectors {
    entries: [(u64, usize); 16],
    pub length: usize,
}
impl IoVectors {
    pub fn single(address: u64, length: u64) -> Self {
        let mut entries = [(0, 0); 16];
        entries[0] = (address, length as usize);
        Self {
            entries,
            length: length as usize,
        }
    }
    pub fn read(pid: usize, address: u64, count: u64) -> Result<Self, i64> {
        if count > 16 {
            return Err(-22);
        }
        let mut output = Self::single(0, 0);
        let mut bytes = [0u8; 16 * 16];
        let size = count as usize * 16;
        if size != 0 && copy_memory(pid, address, &mut bytes[..size], false)? != size as i64 {
            return Err(-14);
        }
        for (index, entry) in output.entries[..count as usize].iter_mut().enumerate() {
            let address = u64::from_ne_bytes(bytes[index * 16..index * 16 + 8].try_into().unwrap());
            let length =
                u64::from_ne_bytes(bytes[index * 16 + 8..index * 16 + 16].try_into().unwrap())
                    as usize;
            output.length = output.length.checked_add(length).ok_or(-22)?;
            if output.length > isize::MAX as usize {
                return Err(-22);
            }
            *entry = (address, length);
        }
        Ok(output)
    }
    pub fn copy(&self, pid: usize, buffer: &mut [u8], to_tracee: bool) -> Result<usize, i64> {
        self.copy_from(pid, buffer, to_tracee, 0)
    }
    pub fn copy_from(
        &self,
        pid: usize,
        buffer: &mut [u8],
        to_tracee: bool,
        mut offset: usize,
    ) -> Result<usize, i64> {
        let mut copied = 0;
        for (address, length) in self.entries {
            let skip = offset.min(length);
            offset -= skip;
            let count = (length - skip).min(buffer.len() - copied);
            if count == 0 {
                continue;
            }
            let address = match address.checked_add(skip as u64) {
                Some(address) => address,
                None if copied != 0 => break,
                None => return Err(-14),
            };
            match copy_memory(pid, address, &mut buffer[copied..copied + count], to_tracee) {
                Ok(n) => {
                    copied += n as usize;
                    if n as usize != count {
                        break;
                    }
                }
                Err(error) if copied == 0 => return Err(error),
                Err(_) => break,
            }
            if copied == buffer.len() {
                break;
            }
        }
        Ok(copied)
    }
}

/// Linux's answer to the xattr name at `address` of the stopped tracee,
/// read as `strncpy_from_user` reads it: up to 256 bytes, a page at a time,
/// so a short name that ends just before an unmapped page is complete.
/// `None` when the name is valid; see `ginux_core::xattr_name_error`.
pub fn xattr_name_error(pid: usize, address: u64) -> Option<i64> {
    const LIMIT: usize = 256;
    let mut bytes = [0u8; LIMIT];
    let mut copied = 0;
    while copied < LIMIT && !bytes[..copied].contains(&0) {
        let Some(start) = address.checked_add(copied as u64) else {
            break;
        };
        let room = (LIMIT - copied).min(4096 - (start % 4096) as usize);
        match copy_memory(pid, start, &mut bytes[copied..copied + room], false) {
            Ok(n) => {
                copied += n as usize;
                if (n as usize) < room {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    ginux_core::xattr_name_error(&bytes[..copied])
}

/// Whether all `length` bytes at `address` of the stopped tracee can be
/// read, as Linux copies an xattr value before using it. The bytes
/// themselves are discarded.
pub fn readable(pid: usize, address: u64, length: u64) -> bool {
    let mut scratch = [0u8; 4096];
    let mut done = 0;
    while done < length {
        let Some(start) = address.checked_add(done) else {
            return false;
        };
        let room = (length - done).min(4096 - start % 4096) as usize;
        if copy_memory(pid, start, &mut scratch[..room], false) != Ok(room as i64) {
            return false;
        }
        done += room as u64;
    }
    true
}

/// A supervisor duplicate of one registered native descriptor of a stopped
/// tracee: the same open file description, taken with `pidfd_getfd`, so
/// every read, write and seek through it is exactly what the tracee itself
/// could do with that descriptor and nothing more. Closed on drop.
pub struct NativeFile(usize);

impl NativeFile {
    pub fn open(pid: usize, fd: u32) -> Result<Self, i64> {
        use crate::supervisor::{syscall1, syscall2, syscall3};
        // The caller may be a thread other than its process leader:
        // address that thread's own descriptor table (PIDFD_THREAD).
        let mut pidfd = unsafe { syscall2(434, pid, 0x80) };
        if pidfd == -22 {
            pidfd = unsafe { syscall2(434, pid, 0) };
        }
        if pidfd < 0 {
            return Err(-5);
        }
        let file = unsafe { syscall3(438, pidfd as usize, fd as usize, 0) };
        unsafe {
            syscall1(3, pidfd as usize);
        }
        if file < 0 {
            return Err(-5);
        }
        Ok(Self(file as usize))
    }

    /// The host's own view of the description: access and append mode from
    /// `F_GETFL`, kind, size and identity from `fstat`.
    pub fn view(&self) -> Result<ginux_core::FileView, i64> {
        file_view(self.0)
    }

    pub fn read_at(&self, position: u64, output: &mut [u8]) -> Result<usize, i64> {
        result(unsafe {
            syscall4(
                17,
                self.0,
                output.as_mut_ptr() as usize,
                output.len(),
                position as usize,
            )
        })
    }

    pub fn position(&self) -> Result<u64, i64> {
        result(unsafe { crate::supervisor::syscall3(8, self.0, 0, 1) }).map(|n| n as u64)
    }

    pub fn seek(&self, position: u64) -> Result<(), i64> {
        result(unsafe { crate::supervisor::syscall3(8, self.0, position as usize, 0) }).map(|_| ())
    }
}

impl Drop for NativeFile {
    fn drop(&mut self) {
        unsafe {
            crate::supervisor::syscall1(3, self.0);
        }
    }
}

/// The view of a host descriptor `fd` the supervisor holds.
pub fn file_view(fd: usize) -> Result<ginux_core::FileView, i64> {
    let flags = result(unsafe { crate::supervisor::syscall3(72, fd, 3, 0) })? as u32;
    let mut stat = [0u8; 144];
    result(unsafe { crate::supervisor::syscall2(5, fd, stat.as_mut_ptr() as usize) })?;
    let word = |offset: usize| u64::from_ne_bytes(stat[offset..offset + 8].try_into().unwrap());
    let mode = u32::from_ne_bytes(stat[24..28].try_into().unwrap());
    Ok(ginux_core::FileView {
        readable: flags & 3 != 1,
        writable: flags & 3 != 0,
        append: flags & 0o2000 != 0,
        kind: ginux_core::FileKind::from_mode(mode),
        size: word(48),
        identity: (word(0), word(8)),
    })
}

fn result(value: isize) -> Result<usize, i64> {
    if value < 0 {
        Err(value as i64)
    } else {
        Ok(value as usize)
    }
}
