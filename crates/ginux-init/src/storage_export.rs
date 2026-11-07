//! Quiesced owned-file export. Build an unnamed file in the requested host
//! directory, then publish that exact, synced inode after closing its writer.
//! Guest names are archive data and never choose supervisor host destinations.
use crate::supervisor::{syscall1, syscall2, syscall3, syscall4, syscall5};
use ginux_vfs::{FileMetadata, NodeKind};

type Error = &'static [u8];
const PATH_BYTES: usize = crate::launch::MAX_RESULT_PATH_LEN + 1;
const AT_FDCWD: usize = (-100isize) as usize;
const AT_EMPTY_PATH: usize = 0x1000;
const AT_SYMLINK_NOFOLLOW: usize = 0x100;
const O_CLOEXEC: usize = 0x80000;
const O_DIRECTORY: usize = 0x10000;
const O_PATH: usize = 0x200000;
const O_TMPFILE: usize = 0x410000;
struct Export {
    fd: usize,
    inode_fd: usize,
    parent_fd: usize,
    parent: [u8; PATH_BYTES],
    destination: [u8; PATH_BYTES],
    name_offset: usize,
}
static mut EXPORT: Option<Export> = None;

fn take() -> Option<Export> {
    unsafe { core::ptr::replace(core::ptr::addr_of_mut!(EXPORT), None) }
}

fn close(fd: usize) -> isize {
    unsafe { syscall1(3, fd) }
}

fn reserve(fd: isize) -> Result<usize, Error> {
    if fd >= 3 {
        return Ok(fd as usize);
    }
    let duplicate = unsafe { syscall3(72, fd as usize, 1030, 3) };
    let closed = close(fd as usize);
    if duplicate < 0 || closed != 0 {
        if duplicate >= 0 {
            close(duplicate as usize);
        }
        return Err(b"export-file descriptor reservation failed");
    }
    Ok(duplicate as usize)
}

fn same_file(a: &[u64; 18], b: &[u64; 18]) -> bool {
    a[0] == b[0] && a[1] == b[1]
}

fn parent_is_current(state: &Export) -> bool {
    let mut opened = [0u64; 18];
    let mut named = [0u64; 18];
    unsafe {
        syscall2(5, state.parent_fd, opened.as_mut_ptr() as usize) == 0
            && syscall4(
                262,
                AT_FDCWD,
                state.parent.as_ptr() as usize,
                named.as_mut_ptr() as usize,
                0,
            ) == 0
            && same_file(&opened, &named)
    }
}

fn published_inode_is_current(state: &Export) -> bool {
    let mut written = [0u64; 18];
    let mut named = [0u64; 18];
    unsafe {
        syscall2(5, state.inode_fd, written.as_mut_ptr() as usize) == 0
            && syscall4(
                262,
                AT_FDCWD,
                state.destination.as_ptr() as usize,
                named.as_mut_ptr() as usize,
                AT_SYMLINK_NOFOLLOW,
            ) == 0
            && same_file(&written, &named)
    }
}

pub fn prepare(path: *const u8) -> Result<(), Error> {
    if path.is_null() {
        return Ok(());
    }
    let state = create(path)?;
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(EXPORT), Some(state));
    }
    Ok(())
}

fn create(path: *const u8) -> Result<Export, Error> {
    let mut destination = [0; PATH_BYTES];
    let mut length = 0;
    while length < PATH_BYTES {
        let byte = unsafe { core::ptr::read_volatile(path.add(length)) };
        if byte == 0 {
            break;
        }
        destination[length] = byte;
        length += 1;
    }
    if length == 0 || length == PATH_BYTES {
        return Err(b"export-file path length invalid");
    }
    let name_offset = destination[..length]
        .iter()
        .rposition(|b| *b == b'/')
        .map_or(0, |n| n + 1);
    if name_offset == length {
        return Err(b"export-file path length invalid");
    }
    let mut parent = [0; PATH_BYTES];
    if name_offset == 0 {
        parent[..2].copy_from_slice(b".\0");
    } else {
        parent[..name_offset].copy_from_slice(&destination[..name_offset]);
    }
    let mut stat = [0u64; 18];
    if unsafe {
        syscall4(
            262,
            AT_FDCWD,
            destination.as_ptr() as usize,
            stat.as_mut_ptr() as usize,
            AT_SYMLINK_NOFOLLOW,
        )
    } != -2
    {
        return Err(b"export-file path is not fresh or not creatable");
    }
    let parent_fd = unsafe {
        syscall4(
            257,
            AT_FDCWD,
            parent.as_ptr() as usize,
            O_PATH | O_DIRECTORY | O_CLOEXEC,
            0,
        )
    };
    if parent_fd < 0 {
        return Err(b"export-file parent unavailable");
    }
    let parent_fd = reserve(parent_fd)?;
    // O_TMPFILE has no replaceable staging name. The parent FD pins the
    // directory even if a host process renames its pathname during capture.
    let fd = unsafe {
        syscall4(
            257,
            parent_fd,
            c".".as_ptr() as usize,
            O_TMPFILE | 1 | O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        close(parent_fd);
        return Err(b"export-file unnamed staging unavailable");
    }
    let fd = match reserve(fd) {
        Ok(fd) => fd,
        Err(reason) => {
            close(parent_fd);
            return Err(reason);
        }
    };
    // Keep a path-only reference to the exact inode while closing the writer.
    // The proc path is supervisor-owned and contains only the returned FD.
    let mut proc_fd = [0u8; 48];
    let prefix = b"/proc/self/fd/";
    proc_fd[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [0u8; 20];
    let mut count = 0;
    let mut number = fd;
    loop {
        digits[count] = b'0' + (number % 10) as u8;
        count += 1;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    for (index, digit) in digits[..count].iter().rev().enumerate() {
        proc_fd[prefix.len() + index] = *digit;
    }
    let inode_fd = unsafe {
        syscall4(
            257,
            AT_FDCWD,
            proc_fd.as_ptr() as usize,
            O_PATH | O_CLOEXEC,
            0,
        )
    };
    if inode_fd < 0 {
        close(fd);
        close(parent_fd);
        return Err(b"export-file inode reference unavailable");
    }
    let inode_fd = match reserve(inode_fd) {
        Ok(fd) => fd,
        Err(reason) => {
            close(fd);
            close(parent_fd);
            return Err(reason);
        }
    };
    Ok(Export {
        fd,
        inode_fd,
        parent_fd,
        parent,
        destination,
        name_offset,
    })
}

pub fn cancel() -> Result<(), Error> {
    let Some(state) = take() else {
        return Ok(());
    };
    let closed = close(state.fd);
    close(state.inode_fd);
    close(state.parent_fd);
    if closed != 0 {
        return Err(b"export-file close failed");
    }
    Ok(())
}

pub fn finish(write: impl FnOnce(&mut Archive) -> Result<(), Error>) -> Result<(), Error> {
    let Some(state) = take() else {
        return Ok(());
    };
    complete(state, write)
}

pub fn capture(
    path: *const u8,
    write: impl FnOnce(&mut Archive) -> Result<(), Error>,
) -> Result<(), Error> {
    complete(create(path)?, write)
}

fn complete(
    state: Export,
    write: impl FnOnce(&mut Archive) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut archive = Archive(state.fd);
    let result = write(&mut archive)
        .and_then(|_| archive.bytes(&[0; 1024]))
        .and_then(|_| loop {
            match unsafe { syscall1(74, state.fd) } {
                0 => break Ok(()),
                -4 => continue,
                _ => break Err(b"export-file sync failed".as_slice()),
            }
        });
    let closed = close(state.fd);
    if let Err(reason) = result {
        close(state.inode_fd);
        close(state.parent_fd);
        return Err(reason);
    }
    if closed != 0 {
        close(state.inode_fd);
        close(state.parent_fd);
        return Err(b"export-file close failed");
    }
    if !parent_is_current(&state) {
        close(state.inode_fd);
        close(state.parent_fd);
        return Err(b"export-file parent changed");
    }
    // AT_EMPTY_PATH publishes the exact inode held by inode_fd. It cannot
    // follow a host replacement of a staging pathname or replace a final name.
    let linked = unsafe {
        syscall5(
            265,
            state.inode_fd,
            c"".as_ptr() as usize,
            state.parent_fd,
            state.destination[state.name_offset..].as_ptr() as usize,
            AT_EMPTY_PATH,
        )
    };
    let current = linked == 0 && parent_is_current(&state) && published_inode_is_current(&state);
    close(state.inode_fd);
    close(state.parent_fd);
    if !current {
        return Err(b"export-file publication failed");
    }
    Ok(())
}

pub struct Archive(usize);
impl Archive {
    fn bytes(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        while !bytes.is_empty() {
            let count = unsafe { syscall3(1, self.0, bytes.as_ptr() as usize, bytes.len()) };
            if count == -4 {
                continue;
            }
            if count <= 0 {
                return Err(b"export-file write failed");
            }
            bytes = &bytes[count as usize..];
        }
        Ok(())
    }

    pub fn entry(
        &mut self,
        path: &[u8],
        metadata: FileMetadata,
        read: impl FnMut(usize, &mut [u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.entry_data(path, metadata, None, read)
    }
    pub fn hardlink(
        &mut self,
        path: &[u8],
        metadata: FileMetadata,
        target: &[u8],
    ) -> Result<(), Error> {
        self.entry_data(path, metadata, Some(target), |_, _| {
            Err(b"hardlink has no payload")
        })
    }
    fn entry_data(
        &mut self,
        path: &[u8],
        metadata: FileMetadata,
        hardlink: Option<&[u8]>,
        mut read: impl FnMut(usize, &mut [u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let name = path
            .strip_prefix(b"/")
            .ok_or(b"export path is not absolute".as_slice())?;
        if name.is_empty()
            || name
                .split(|b| *b == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b"..")
        {
            return Err(b"invalid export path");
        }
        let (kind, length) = if hardlink.is_some() {
            (b'1', 0)
        } else {
            match metadata.kind {
                NodeKind::File => (b'0', metadata.size),
                NodeKind::Directory => (b'5', 0),
                NodeKind::Symlink => (b'2', 0),
            }
        };
        if name.len() > 100 {
            // GNU long names preserve any normalized VFS path, including a
            // single component longer than ustar's 100-byte name field.
            self.header(b"././@LongLink", 0, (name.len() + 1) as u64, b'L', b"", 0)?;
            self.bytes(name)?;
            self.bytes(&[0; 512][..512 - name.len()])?;
        }
        let mut target = [0; ginux_vfs::MAX_PATH];
        let target = if let Some(target) = hardlink {
            let target = target
                .strip_prefix(b"/")
                .ok_or(b"invalid hardlink export target".as_slice())?;
            if target.is_empty()
                || target
                    .split(|b| *b == b'/')
                    .any(|p| p.is_empty() || p == b"." || p == b"..")
            {
                return Err(b"invalid hardlink export target");
            }
            target
        } else if metadata.kind == NodeKind::Symlink {
            let length =
                usize::try_from(metadata.size).map_err(|_| b"invalid export link".as_slice())?;
            if length == 0 || length > target.len() {
                return Err(b"invalid export link");
            }
            read(0, &mut target[..length])?;
            &target[..length]
        } else {
            &[]
        };
        if target.len() > 100 {
            self.header(b"././@LongLink", 0, (target.len() + 1) as u64, b'K', b"", 0)?;
            self.bytes(target)?;
            self.bytes(&[0; 512][..512 - target.len()])?;
        }
        self.header(
            &name[..name.len().min(100)],
            (metadata.mode & 0o777) as u64,
            length,
            kind,
            &target[..target.len().min(100)],
            u64::try_from(metadata.modified.seconds)
                .map_err(|_| b"export timestamp is negative".as_slice())?,
        )?;
        let mut buffer = [0u8; 4096];
        let mut offset = 0usize;
        while (offset as u64) < length {
            let size = (length - offset as u64).min(buffer.len() as u64) as usize;
            read(offset, &mut buffer[..size])?;
            self.bytes(&buffer[..size])?;
            offset += size;
        }
        let padding = (512 - (length % 512)) % 512;
        self.bytes(&[0; 512][..padding as usize])
    }
    fn header(
        &mut self,
        name: &[u8],
        mode: u64,
        length: u64,
        kind: u8,
        link: &[u8],
        modified: u64,
    ) -> Result<(), Error> {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name);
        octal(&mut header[100..108], mode)?;
        octal(&mut header[108..116], 0)?;
        octal(&mut header[116..124], 0)?;
        octal(&mut header[124..136], length)?;
        octal(&mut header[136..148], modified)?;
        header[148..156].fill(b' ');
        header[156] = kind;
        header[157..157 + link.len()].copy_from_slice(link);
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|b| *b as u64).sum();
        octal(&mut header[148..155], checksum)?;
        self.bytes(&header)
    }
}

fn octal(output: &mut [u8], mut value: u64) -> Result<(), Error> {
    output.fill(b'0');
    let digits = output.len() - 1;
    output[digits] = 0;
    for byte in output[..digits].iter_mut().rev() {
        *byte = b'0' + (value & 7) as u8;
        value >>= 3;
    }
    if value != 0 {
        return Err(b"export metadata exceeds tar bound");
    }
    Ok(())
}
