//! Bounded startup import of an owned-filesystem snapshot. All entries are
//! validated before a workload starts; failures discard this new memory view.
use crate::fs_hooks::{LaunchFs, RestoreEntry};
use crate::storage_memory::MappedArray;
use crate::supervisor::{syscall1, syscall2, syscall3, syscall4};
use ginux_vfs::NodeKind;
type Error = &'static [u8];
const LIMIT: u64 = 2 * 1024 * 1024 * 1024;
struct Input(usize);
impl Drop for Input {
    fn drop(&mut self) {
        unsafe {
            syscall1(3, self.0);
        }
    }
}
impl Input {
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize, Error> {
        loop {
            let count = unsafe { syscall3(0, self.0, bytes.as_mut_ptr() as usize, bytes.len()) };
            if count == -4 {
                continue;
            }
            if count < 0 {
                return Err(b"restore archive read failed");
            }
            return Ok(count as usize);
        }
    }
    fn exact(&mut self, mut bytes: &mut [u8]) -> Result<(), Error> {
        while !bytes.is_empty() {
            let count = self.read(bytes)?;
            if count == 0 {
                return Err(b"truncated restore archive");
            }
            bytes = &mut bytes[count..];
        }
        Ok(())
    }
    fn padding(&mut self, length: usize) -> Result<(), Error> {
        let mut bytes = [0u8; 512];
        let count = (512 - length % 512) % 512;
        self.exact(&mut bytes[..count])?;
        if bytes.iter().any(|b| *b != 0) {
            return Err(b"nonzero restore padding");
        }
        Ok(())
    }
}

pub fn restore(path: *const u8, files: &mut LaunchFs) -> Result<(), Error> {
    if path.is_null() {
        return Ok(());
    }
    let mut length = 0;
    while length <= crate::launch::MAX_RESULT_PATH_LEN
        && unsafe { core::ptr::read_volatile(path.add(length)) } != 0
    {
        length += 1;
    }
    if length == 0 || length > crate::launch::MAX_RESULT_PATH_LEN {
        return Err(b"invalid restore-file path length");
    }
    let fd = unsafe {
        syscall4(
            257,
            (-100isize) as usize,
            path as usize,
            0x80000 | 0x20000,
            0,
        )
    };
    if fd < 0 {
        return Err(b"cannot open restore archive");
    }
    let mut input = Input(fd as usize);
    let mut stat = [0u64; 18];
    if unsafe { syscall2(5, input.0, stat.as_mut_ptr() as usize) } < 0
        || stat[3] & 0o170000 != 0o100000
        || stat[6] > LIMIT + 8 * 1024 * 1024
    {
        return Err(b"restore archive is not a bounded regular file");
    }
    let mut seen = MappedArray::new(files.capacity(), false)
        .map_err(|_| b"restore metadata allocation failed".as_slice())?;
    let mut long_name = [0u8; 256];
    let mut long_len = 0;
    let mut long_link = [0u8; 256];
    let mut link_len = 0;
    let mut total = 0u64;
    for _ in 0..=files.capacity() * 3 {
        let mut header = [0u8; 512];
        input.exact(&mut header)?;
        if header.iter().all(|b| *b == 0) {
            if long_len != 0 || link_len != 0 {
                return Err(b"restore long name or link has no entry");
            }
            input.exact(&mut header)?;
            if header.iter().any(|b| *b != 0) || input.read(&mut header[..1])? != 0 {
                return Err(b"invalid restore archive terminator");
            }
            return Ok(());
        }
        let checksum = octal(&header[148..156])?;
        let actual: u64 = header
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *b as u64
                }
            })
            .sum();
        if actual != checksum || &header[257..263] != b"ustar\0" {
            return Err(b"invalid restore header");
        }
        let size = octal(&header[124..136])?;
        if matches!(header[156], b'L' | b'K') {
            let (buffer, length) = if header[156] == b'L' {
                (&mut long_name, &mut long_len)
            } else {
                (&mut long_link, &mut link_len)
            };
            if *length != 0 || !(2..=256).contains(&size) {
                return Err(b"invalid restore long name or link");
            }
            input.exact(&mut buffer[..size as usize])?;
            if buffer[size as usize - 1] != 0 || buffer[..size as usize - 1].contains(&0) {
                return Err(b"unterminated restore long name or link");
            }
            *length = size as usize - 1;
            input.padding(size as usize)?;
            continue;
        }
        let kind = match header[156] {
            b'5' => NodeKind::Directory,
            b'0' | 0 => NodeKind::File,
            b'2' => NodeKind::Symlink,
            _ => return Err(b"unsupported restore entry kind"),
        };
        let directory = kind == NodeKind::Directory;
        if link_len != 0 && kind != NodeKind::Symlink {
            return Err(b"restore link target on non-link");
        }
        let target = if link_len != 0 {
            &long_link[..link_len]
        } else {
            field(&header[157..257])
        };
        let mode = octal(&header[100..108])?;
        if mode & !0o777 != 0 || (kind != NodeKind::File && size != 0) {
            return Err(b"invalid restore metadata");
        }
        total = total
            .checked_add(size)
            .filter(|n| *n <= LIMIT)
            .ok_or(b"restore archive byte bound exceeded".as_slice())?;
        let mut path = [0u8; 256];
        path[0] = b'/';
        let mut end = 1;
        if long_len != 0 {
            append(&mut path, &mut end, &long_name[..long_len])?;
            long_len = 0;
        } else {
            let prefix = field(&header[345..500]);
            if !prefix.is_empty() {
                append(&mut path, &mut end, prefix)?;
                append(&mut path, &mut end, b"/")?;
            }
            append(&mut path, &mut end, field(&header[..100]))?;
        }
        if directory && end > 1 && path[end - 1] == b'/' {
            end -= 1;
        }
        if end < 2
            || path[1..end]
                .split(|b| *b == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b".." || part.contains(&0))
        {
            return Err(b"invalid restore entry path");
        }
        files.restore_entry(
            RestoreEntry {
                path: &path[..end],
                kind,
                link: target,
                mode: mode as u32,
                length: size as usize,
            },
            &mut seen,
            |bytes| input.exact(bytes),
        )?;
        link_len = 0;
        input.padding(size as usize)?;
    }
    Err(b"restore archive entry bound exceeded")
}

fn field(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len())]
}
fn append(path: &mut [u8; 256], end: &mut usize, bytes: &[u8]) -> Result<(), Error> {
    let next = end
        .checked_add(bytes.len())
        .filter(|n| *n < path.len())
        .ok_or(b"restore path bound exceeded".as_slice())?;
    path[*end..next].copy_from_slice(bytes);
    *end = next;
    Ok(())
}
fn octal(bytes: &[u8]) -> Result<u64, Error> {
    let mut value = 0u64;
    let mut ended = false;
    for byte in bytes {
        if *byte == 0 || *byte == b' ' {
            ended = true;
            continue;
        }
        if ended || !(b'0'..=b'7').contains(byte) {
            return Err(b"invalid restore octal field");
        }
        value = value
            .checked_mul(8)
            .and_then(|n| n.checked_add((byte - b'0') as u64))
            .ok_or(b"restore field overflow".as_slice())?;
    }
    Ok(value)
}
