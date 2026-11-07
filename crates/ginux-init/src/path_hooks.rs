//! Exact component lookup beneath the tracee root and temporary native path
//! translation. Supervisor prefixes never enter a workload pathname.
use crate::supervisor::{syscall1, syscall4, UserRegs, INSTANCE_GID, INSTANCE_UID};
use crate::tracee_io::copy_memory;
use ginux_vfs::{NodeKind, VfsError, MAX_PATH};
pub struct ImageRoot(usize);
impl ImageRoot {
    pub fn new(pid: usize) -> Result<Self, i64> {
        let mut name = [0u8; 64];
        name[..6].copy_from_slice(b"/proc/");
        let mut number = pid;
        let mut digits = [0; 20];
        let mut count = 0;
        loop {
            digits[count] = b'0' + (number % 10) as u8;
            count += 1;
            number /= 10;
            if number == 0 {
                break;
            }
        }
        for i in 0..count {
            name[6 + i] = digits[count - 1 - i];
        }
        name[6 + count..11 + count].copy_from_slice(b"/root");
        let fd = unsafe {
            syscall4(
                257,
                (-100isize) as usize,
                name.as_ptr() as usize,
                0x280000,
                0,
            )
        };
        if fd < 0 {
            return Err(fd as i64);
        }
        Ok(Self(fd as usize))
    }
    /// Inspect only the kernel loader's interpreter metadata. The descriptor
    /// stays private and is closed on every return path.
    pub fn interpreter(
        &self,
        path: &[u8],
        output: &mut [u8; MAX_PATH],
    ) -> Result<Option<(usize, bool)>, i64> {
        let mut name = [0; MAX_PATH + 1];
        let path = path.strip_prefix(b"/").ok_or(-22)?;
        name[..path.len()].copy_from_slice(path);
        let fd = unsafe { syscall4(257, self.0, name.as_ptr() as usize, 0o2400000, 0) };
        if fd < 0 {
            return Err(fd as i64);
        }
        let file = ImageFile(fd as usize);
        file.interpreter(output)
    }

    pub fn interpreter_fd(
        pid: usize,
        fd: u32,
        output: &mut [u8; MAX_PATH],
    ) -> Result<Option<(usize, bool)>, i64> {
        let mut name = [0; 80];
        name[..6].copy_from_slice(b"/proc/");
        let mut cursor = 6;
        for (index, mut number) in [pid, fd as usize].into_iter().enumerate() {
            let mut digits = [0; 20];
            let mut length = 0;
            loop {
                digits[length] = b'0' + (number % 10) as u8;
                length += 1;
                number /= 10;
                if number == 0 {
                    break;
                }
            }
            for digit in digits[..length].iter().rev() {
                name[cursor] = *digit;
                cursor += 1;
            }
            if index == 0 {
                name[cursor..cursor + 4].copy_from_slice(b"/fd/");
                cursor += 4;
            }
        }
        // fd is a registered native image handle in a stopped, owned task.
        let opened = unsafe {
            syscall4(
                257,
                (-100isize) as usize,
                name.as_ptr() as usize,
                0o2000000,
                0,
            )
        };
        if opened < 0 {
            return Err(opened as i64);
        }
        ImageFile(opened as usize).interpreter(output)
    }

    pub fn resolve_image(
        &self,
        path: &[u8],
        output: &mut [u8; MAX_PATH],
    ) -> Result<usize, VfsError> {
        ginux_vfs::resolve_namespace(path, true, false, output, |path, target| {
            self.lookup(path, target)
        })
    }

    pub fn lookup(
        &self,
        path: &[u8],
        target: &mut [u8; MAX_PATH],
    ) -> Result<(NodeKind, usize), VfsError> {
        let path = path.strip_prefix(b"/").ok_or(VfsError::InvalidPath)?;
        let path = if path.is_empty() {
            b".".as_slice()
        } else {
            path
        };
        let mut name = [0; MAX_PATH + 1];
        name[..path.len()].copy_from_slice(path);
        let mut stat = [0u64; 18];
        let result = unsafe {
            syscall4(
                262,
                self.0,
                name.as_ptr() as usize,
                stat.as_mut_ptr() as usize,
                0x100,
            )
        };
        if result < 0 {
            return Err(match result {
                -2 => VfsError::NotFound,
                -20 => VfsError::NotDirectory,
                -13 => VfsError::PermissionDenied,
                _ => VfsError::Io,
            });
        }
        let mode = stat[3] as u32;
        match mode & 0o170000 {
            0o40000 => {
                let uid = (stat[3] >> 32) as u32;
                let gid = stat[4] as u32;
                let shift = if uid == INSTANCE_UID as u32 {
                    6
                } else if gid == INSTANCE_GID as u32 {
                    3
                } else {
                    0
                };
                if mode & (1 << shift) == 0 {
                    return Err(VfsError::PermissionDenied);
                }
                Ok((NodeKind::Directory, 0))
            }
            0o100000 => Ok((NodeKind::File, 0)),
            0o120000 => {
                let n = unsafe {
                    syscall4(
                        267,
                        self.0,
                        name.as_ptr() as usize,
                        target.as_mut_ptr() as usize,
                        target.len(),
                    )
                };
                if n < 0 {
                    return Err(VfsError::Io);
                }
                if n as usize >= target.len() {
                    return Err(VfsError::InvalidPath);
                }
                Ok((NodeKind::Symlink, n as usize))
            }
            _ => Err(VfsError::PermissionDenied),
        }
    }
}
impl Drop for ImageRoot {
    fn drop(&mut self) {
        unsafe {
            syscall1(3, self.0);
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ScriptHeader {
    pub interpreter: ginux_instance::Text<MAX_PATH>,
    pub argument: Option<ginux_instance::Text<MAX_PATH>>,
    pub payload: usize,
}

/// Linux's bounded shebang line has one optional argument, including spaces.
/// Inspect only bytes actually read, stopping at newline or the first NUL.
pub(crate) fn script_metadata(bytes: &[u8]) -> Result<Option<ScriptHeader>, i64> {
    if !bytes.starts_with(b"#!") {
        return Ok(None);
    }
    let line_end = bytes
        .iter()
        .position(|b| matches!(b, 0 | b'\n'))
        .unwrap_or(bytes.len());
    let mut end = line_end;
    while end > 2 && matches!(bytes[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    let start = (2..end)
        .find(|n| !matches!(bytes[*n], b' ' | b'\t'))
        .ok_or(-8)?;
    let separator = (start..end)
        .find(|n| matches!(bytes[*n], b' ' | b'\t'))
        .unwrap_or(end);
    if separator == start || separator == bytes.len() && bytes.len() == 256 {
        return Err(-8);
    }
    let interpreter =
        ginux_instance::Text::from_bytes(&bytes[start..separator]).map_err(|_| -36)?;
    let argument = (separator..end)
        .find(|n| !matches!(bytes[*n], b' ' | b'\t'))
        .map(|first| ginux_instance::Text::from_bytes(&bytes[first..end]).map_err(|_| -36))
        .transpose()?;
    Ok(Some(ScriptHeader {
        interpreter,
        argument,
        payload: bytes
            .iter()
            .position(|b| *b == b'\n')
            .map_or(bytes.len(), |n| n + 1),
    }))
}

pub(crate) fn interpreter_metadata(
    mut read: impl FnMut(u64, &mut [u8]) -> Result<usize, i64>,
    output: &mut [u8; MAX_PATH],
) -> Result<Option<(usize, bool)>, i64> {
    let mut first = [0; 256];
    let n = read(0, &mut first).map_err(|error| if error == -21 { -13 } else { error })?;
    if let Some(header) = script_metadata(&first[..n])? {
        let name = header.interpreter.as_bytes();
        output[..name.len()].copy_from_slice(name);
        return Ok(Some((name.len(), true)));
    }
    if n < 4 || &first[..4] != b"\x7fELF" {
        return Ok(None);
    }
    if n < 64 {
        return Err(-8);
    }
    if first[4] != 2 || first[5] != 1 {
        return Err(-95);
    }
    if u16::from_le_bytes(first[18..20].try_into().unwrap()) != 62 {
        return Err(-8);
    }
    let offset = u64::from_le_bytes(first[32..40].try_into().unwrap());
    let size = u16::from_le_bytes(first[54..56].try_into().unwrap());
    let count = u16::from_le_bytes(first[56..58].try_into().unwrap()) as usize;
    if size != 56 {
        return Err(-8);
    }
    offset.checked_add((count * 56) as u64).ok_or(-8)?;
    let mut buffer = [0; 56 * 73];
    let mut index = 0;
    let mut interpreter = None;
    while index < count {
        let headers = (count - index).min(73);
        let bytes = headers * 56;
        if read(offset + (index * 56) as u64, &mut buffer[..bytes])? != bytes {
            return Err(-8);
        }
        for header in buffer[..bytes].as_chunks::<56>().0 {
            if u32::from_le_bytes(header[..4].try_into().unwrap()) != 3 {
                continue;
            }
            if interpreter.is_some() {
                return Err(-8);
            }
            interpreter = Some((
                u64::from_le_bytes(header[8..16].try_into().unwrap()),
                u64::from_le_bytes(header[32..40].try_into().unwrap()),
            ));
        }
        index += headers;
    }
    let Some((offset, length)) = interpreter else {
        return Ok(None);
    };
    if length == 0 {
        return Err(-8);
    }
    if length > MAX_PATH as u64 {
        return Err(-36);
    }
    let length = length as usize;
    if read(offset, &mut output[..length])? != length || output[length - 1] != 0 {
        return Err(-8);
    }
    let end = output[..length]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(-8)?;
    if end == 0 {
        return Err(-8);
    }
    Ok(Some((end, false)))
}

struct ImageFile(usize);
impl ImageFile {
    fn interpreter(&self, output: &mut [u8; MAX_PATH]) -> Result<Option<(usize, bool)>, i64> {
        interpreter_metadata(|offset, buffer| self.read(offset, buffer), output)
    }

    fn read(&self, offset: u64, output: &mut [u8]) -> Result<usize, i64> {
        let n = unsafe {
            syscall4(
                17,
                self.0,
                output.as_mut_ptr() as usize,
                output.len(),
                offset as usize,
            )
        };
        if n < 0 {
            Err(n as i64)
        } else {
            Ok(n as usize)
        }
    }
}
impl Drop for ImageFile {
    fn drop(&mut self) {
        unsafe {
            syscall1(3, self.0);
        }
    }
}

pub struct Rewrite {
    address: u64,
    saved: [u8; MAX_PATH + 1],
    args: [u64; 7],
}
impl Rewrite {
    pub fn prepare(
        fs: &crate::fs_hooks::LaunchFs,
        pid: usize,
        r: &mut UserRegs,
    ) -> Result<Option<Self>, i64> {
        let Some((argument, path)) = fs.native_path(pid, r)? else {
            return Ok(None);
        };
        let address = r.rsp.checked_sub(512).ok_or(-14)?;
        let output = match r.orig_rax {
            4 | 6 => Some((r.rsi, 144)),
            262 => Some((r.rdx, 144)),
            332 => Some((r.r8, 256)),
            89 => Some((r.rsi, r.rdx)),
            _ => None,
        };
        if output.is_some_and(|(start, length)| {
            length != 0
                && start < address + (MAX_PATH + 1) as u64
                && start.checked_add(length).is_none_or(|end| end > address)
        }) {
            return Err(-14);
        }
        let mut saved = [0; MAX_PATH + 1];
        if copy_memory(pid, address, &mut saved, false)? != saved.len() as i64 {
            return Err(-14);
        }
        let mut bytes = [0; MAX_PATH + 1];
        bytes[..path.as_bytes().len()].copy_from_slice(path.as_bytes());
        let written = copy_memory(pid, address, &mut bytes, true)? as usize;
        if written != bytes.len() {
            // Restore exactly the prefix that was changed. The untouched suffix
            // may be readable but protected against writes.
            if copy_memory(pid, address, &mut saved[..written], true) != Ok(written as i64) {
                return Err(-5);
            }
            return Err(-14);
        }
        let args = [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9, r.orig_rax];
        if argument == 0 {
            r.rdi = address;
        } else {
            r.rsi = address;
        }
        Ok(Some(Self {
            address,
            saved,
            args,
        }))
    }
    pub fn original_args(&mut self, r: &UserRegs) {
        self.args = [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9, r.orig_rax];
    }
    pub fn finish(mut self, pid: usize, r: &mut UserRegs) -> Result<(), &'static [u8]> {
        if copy_memory(pid, self.address, &mut self.saved, true) != Ok(self.saved.len() as i64) {
            return Err(b"native path scratch restoration failed");
        }
        r.rdi = self.args[0];
        r.rsi = self.args[1];
        r.rdx = self.args[2];
        r.r10 = self.args[3];
        r.r8 = self.args[4];
        r.r9 = self.args[5];
        r.orig_rax = self.args[6];
        Ok(())
    }
}
