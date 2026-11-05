//! Controlled copies and x86-64 metadata serialization for native tracees.
use crate::supervisor::syscall6;
use ginux_domain::Text;
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

pub fn read_path(pid: usize, address: u64) -> Result<Path, i64> {
    let mut buffer = [0; MAX_PATH];
    for i in 0..MAX_PATH {
        copy_memory(
            pid,
            address.checked_add(i as u64).ok_or(-14)?,
            &mut buffer[i..i + 1],
            false,
        )?;
        if buffer[i] == 0 {
            return Path::from_bytes(&buffer[..i]).map_err(|_| -36);
        }
    }
    Err(-36)
}

/// Linux file type bits are part of mode; identities belong to the domain.
pub struct Stat {
    pub inode: u64,
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
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[28..30].copy_from_slice(&(mode as u16).to_le_bytes());
        (32, None, 40, 48, 256)
    } else {
        bytes[16..24].copy_from_slice(&1u64.to_le_bytes());
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
