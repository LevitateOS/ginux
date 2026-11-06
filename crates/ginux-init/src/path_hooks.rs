//! Exact component lookup beneath the tracee root and temporary native path
//! translation. Supervisor prefixes never enter a workload pathname.
use crate::supervisor::{syscall1, syscall4, UserRegs, DOMAIN_GID, DOMAIN_UID};
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
                let shift = if uid == DOMAIN_UID as u32 {
                    6
                } else if gid == DOMAIN_GID as u32 {
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
        let mut saved = [0; MAX_PATH + 1];
        if copy_memory(pid, address, &mut saved, false)? != saved.len() as i64 {
            return Err(-14);
        }
        let mut bytes = [0; MAX_PATH + 1];
        bytes[..path.as_bytes().len()].copy_from_slice(path.as_bytes());
        if copy_memory(pid, address, &mut bytes, true)? != bytes.len() as i64 {
            if copy_memory(pid, address, &mut saved, true)? != saved.len() as i64 {
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
