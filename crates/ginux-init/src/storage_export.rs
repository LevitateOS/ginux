//! Successful-exit export of quiesced writable files to a caller-selected tar.
//! Guest names are archive data, never supervisor host paths. An incomplete
//! archive is not a result: consumers must also require successful completion.
use crate::supervisor::{syscall1, syscall3, syscall4};
use ginux_vfs::{FileMetadata, NodeKind};

static mut EXPORT_FD: isize = -1;
type Error = &'static [u8];

pub fn prepare(path: *const u8) -> Result<(), Error> {
    if path.is_null() {
        return Ok(());
    }
    let mut length = 0;
    while length <= crate::launch::MAX_RESULT_PATH_LEN {
        if unsafe { core::ptr::read_volatile(path.add(length)) } == 0 {
            break;
        }
        length += 1;
    }
    if length == 0 || length > crate::launch::MAX_RESULT_PATH_LEN {
        return Err(b"export-file path length invalid");
    }
    // O_EXCL refuses existing files and symlinks before any workload executes.
    let mut fd = unsafe {
        syscall4(
            257,
            (-100isize) as usize,
            path as usize,
            1 | 64 | 128 | 0x80000,
            0o600,
        )
    };
    if fd < 0 {
        return Err(b"export-file path is not fresh or not creatable");
    }
    if fd < 3 {
        let duplicate = unsafe { syscall3(72, fd as usize, 1030, 3) };
        unsafe {
            syscall1(3, fd as usize);
        }
        if duplicate < 0 {
            return Err(b"export-file descriptor reservation failed");
        }
        fd = duplicate;
    }
    unsafe {
        EXPORT_FD = fd;
    }
    Ok(())
}

pub fn finish(write: impl FnOnce(&mut Archive) -> Result<(), Error>) -> Result<(), Error> {
    let fd = unsafe { EXPORT_FD };
    if fd < 0 {
        return Ok(());
    }
    unsafe {
        EXPORT_FD = -1;
    }
    let mut archive = Archive(fd as usize);
    let result = write(&mut archive)
        .and_then(|_| archive.bytes(&[0; 1024]))
        .and_then(|_| {
            if unsafe { syscall1(74, fd as usize) } == 0 {
                Ok(())
            } else {
                Err(b"export-file sync failed".as_slice())
            }
        });
    let closed = unsafe { syscall1(3, fd as usize) };
    result?;
    if closed != 0 {
        return Err(b"export-file close failed");
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
        let (kind, length) = match metadata.kind {
            NodeKind::File => (b'0', metadata.size),
            NodeKind::Directory => (b'5', 0),
            _ => return Err(b"unsupported export entry kind"),
        };
        if name.len() > 100 {
            // GNU long names preserve any normalized VFS path, including a
            // single component longer than ustar's 100-byte name field.
            self.header(b"././@LongLink", 0, (name.len() + 1) as u64, b'L')?;
            self.bytes(name)?;
            self.bytes(&[0; 512][..512 - name.len()])?;
        }
        self.header(
            &name[..name.len().min(100)],
            (metadata.mode & 0o777) as u64,
            length,
            kind,
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
    fn header(&mut self, name: &[u8], mode: u64, length: u64, kind: u8) -> Result<(), Error> {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name);
        octal(&mut header[100..108], mode)?;
        octal(&mut header[108..116], 0)?;
        octal(&mut header[116..124], 0)?;
        octal(&mut header[124..136], length)?;
        octal(&mut header[136..148], 0)?;
        header[148..156].fill(b' ');
        header[156] = kind;
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
