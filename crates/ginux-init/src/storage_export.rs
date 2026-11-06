//! Quiesced owned-file export. Stage privately beside the requested host path,
//! then publish a complete, synced, closed archive without replacing a name.
//! Guest names are archive data and never choose supervisor host destinations.
use crate::supervisor::{syscall1, syscall3, syscall4, syscall5};
use ginux_vfs::{FileMetadata, NodeKind};

type Error = &'static [u8];
const PATH_BYTES: usize = crate::launch::MAX_RESULT_PATH_LEN + 1;
const AT_FDCWD: usize = (-100isize) as usize;
struct Export {
    fd: usize,
    destination: [u8; PATH_BYTES],
    temporary: [u8; PATH_BYTES],
}
static mut EXPORT: Option<Export> = None;
static mut SERIAL: u64 = 0;

impl Export {
    fn remove(&self) -> Result<(), Error> {
        if unsafe { syscall1(87, self.temporary.as_ptr() as usize) } == 0 {
            Ok(())
        } else {
            Err(b"export staging cleanup failed")
        }
    }
}

fn take() -> Option<Export> {
    unsafe { core::ptr::replace(core::ptr::addr_of_mut!(EXPORT), None) }
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
    let mut stat = [0u64; 18];
    let existing = unsafe {
        syscall4(
            262,
            AT_FDCWD,
            destination.as_ptr() as usize,
            stat.as_mut_ptr() as usize,
            0x100,
        )
    };
    if existing != -2 {
        return Err(b"export-file path is not fresh or not creatable");
    }
    let parent = destination[..length]
        .iter()
        .rposition(|b| *b == b'/')
        .map_or(0, |n| n + 1);
    let pid = unsafe { syscall1(39, 0) };
    if pid <= 0 {
        return Err(b"export staging identity unavailable");
    }
    let serial =
        unsafe { SERIAL.checked_add(1) }.ok_or(b"export staging identity exhausted".as_slice())?;
    unsafe {
        SERIAL = serial;
    }
    let mut suffix = [0; 41];
    let mut suffix_len = 0;
    for number in [pid as u64, serial] {
        if suffix_len != 0 {
            suffix[suffix_len] = b'-';
            suffix_len += 1;
        }
        let mut digits = [0; 20];
        let mut count = 0;
        let mut number = number;
        loop {
            digits[count] = b'0' + (number % 10) as u8;
            count += 1;
            number /= 10;
            if number == 0 {
                break;
            }
        }
        for digit in digits[..count].iter().rev() {
            suffix[suffix_len] = *digit;
            suffix_len += 1;
        }
    }
    let prefix = b".ginux-export-";
    let end = parent
        .checked_add(prefix.len())
        .and_then(|n| n.checked_add(suffix_len))
        .filter(|n| *n < PATH_BYTES)
        .ok_or(b"export staging path exceeds bound".as_slice())?;
    let mut temporary = [0; PATH_BYTES];
    temporary[..parent].copy_from_slice(&destination[..parent]);
    temporary[parent..parent + prefix.len()].copy_from_slice(prefix);
    temporary[parent + prefix.len()..end].copy_from_slice(&suffix[..suffix_len]);
    if temporary[..end] == destination[..length] {
        return Err(b"export staging name conflicts with destination");
    }
    // O_EXCL and mode0600 keep an incomplete archive private. A stale staging
    // name fails explicitly; it is never overwritten or treated as output.
    let opened = unsafe {
        syscall4(
            257,
            AT_FDCWD,
            temporary.as_ptr() as usize,
            1 | 64 | 128 | 0x80000,
            0o600,
        )
    };
    if opened < 0 {
        return Err(b"export staging path is not fresh or not creatable");
    }
    let mut state = Export {
        fd: opened as usize,
        destination,
        temporary,
    };
    if opened < 3 {
        let duplicate = unsafe { syscall3(72, opened as usize, 1030, 3) };
        let closed = unsafe { syscall1(3, opened as usize) };
        if duplicate < 0 || closed != 0 {
            if duplicate >= 0 {
                unsafe {
                    syscall1(3, duplicate as usize);
                }
            }
            state.remove()?;
            return Err(b"export-file descriptor reservation failed");
        }
        state.fd = duplicate as usize;
    }
    Ok(state)
}

pub fn cancel() -> Result<(), Error> {
    let Some(state) = take() else {
        return Ok(());
    };
    let closed = unsafe { syscall1(3, state.fd) };
    let removed = state.remove();
    if closed != 0 {
        return Err(b"export-file close failed");
    }
    removed
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
    let closed = unsafe { syscall1(3, state.fd) };
    if let Err(reason) = result {
        state.remove()?;
        return Err(reason);
    }
    if closed != 0 {
        state.remove()?;
        return Err(b"export-file close failed");
    }
    // RENAME_NOREPLACE is the publication point, after successful close. An
    // intervening destination creation cannot replace that caller's file.
    if unsafe {
        syscall5(
            316,
            AT_FDCWD,
            state.temporary.as_ptr() as usize,
            AT_FDCWD,
            state.destination.as_ptr() as usize,
            1,
        )
    } != 0
    {
        state.remove()?;
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
