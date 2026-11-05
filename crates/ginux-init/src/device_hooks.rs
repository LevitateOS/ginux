//! Explicitly assigned character devices for configured native launch.
//! All IO uses ginux-devices objects; no host device node or descriptor is used.

use crate::fs_hooks::LaunchFs;
use crate::supervisor::UserRegs;
use crate::tracee_io::{read_path, write_stat, Stat};
use ginux_devices::{DeviceError, DeviceKind, DeviceName, DeviceRegistry};
use ginux_domain::DomainConfig;

const DOMAIN: u64 = 1; // One domain per configured supervisor process.
const FD_BASE: u32 = 0x4000_0000;
const FDS: usize = 64;
const CLOEXEC: u32 = 0o2000000;
const ACCESS_MODE: u32 = 3;

pub struct LaunchDevices {
    registry: DeviceRegistry<1, FDS>,
    flags: [Option<u32>; FDS],
    enabled: bool,
}

impl LaunchDevices {
    pub fn readiness(&self, handle: u32) -> Option<u16> {
        let slot = handle.checked_sub(FD_BASE)? as usize;
        // Configured launch currently assigns only null, whose reads/writes
        // never wait. Future device kinds must supply their own readiness.
        self.flags.get(slot).copied().flatten().map(|_| 0x145)
    }

    pub fn prepare(config: &DomainConfig) -> Result<Self, &'static [u8]> {
        let mut registry = DeviceRegistry::new();
        for device in config.devices.as_slice() {
            if device.as_bytes() != b"null" {
                return Err(b"unsupported launch device assignment");
            }
            registry
                .assign(
                    DOMAIN,
                    1,
                    DeviceName::new(b"null").unwrap(),
                    DeviceKind::Null,
                )
                .map_err(|_| b"duplicate launch device assignment".as_slice())?;
        }
        Ok(Self {
            registry,
            flags: [None; FDS],
            enabled: !config.devices.as_slice().is_empty(),
        })
    }

    pub fn claim(&mut self, pid: usize, r: &UserRegs, fs: &LaunchFs) -> Option<i64> {
        let fd = r.rdi as u32;
        if self.enabled
            && fd >= FD_BASE
            && matches!(
                r.orig_rax,
                0 | 1 | 3 | 5 | 8 | 16 | 17 | 18 | 19 | 20 | 32 | 33 | 72 | 74 | 75 | 77 | 91 | 292
            )
        {
            return Some(
                self.descriptor_call(pid, fd, r)
                    .unwrap_or_else(|error| error),
            );
        }
        if self.enabled && matches!(r.orig_rax, 262 | 332) && fd >= FD_BASE {
            match read_path(pid, r.rsi) {
                Ok(path) if path.is_empty() => {
                    return Some(
                        self.descriptor_call(pid, fd, r)
                            .unwrap_or_else(|error| error),
                    )
                }
                Err(error) => return Some(error),
                _ => {}
            }
        }
        let (pointer, dirfd) = match r.orig_rax {
            2 | 4 | 6 | 21 | 83 | 87 | 89 | 90 => (r.rdi, -100i64 as u64),
            257 | 258 | 262 | 263 | 268 | 269 | 332 | 439 => (r.rsi, r.rdi),
            _ => return None,
        };
        let path = match fs.path(pid, pointer, dirfd) {
            Ok(path) => path,
            Err(_) => return None,
        };
        if path.as_bytes() != b"/dev" && !path.as_bytes().starts_with(b"/dev/") {
            return None;
        }
        let null = path.as_bytes() == b"/dev/null";
        let dir = path.as_bytes() == b"/dev";
        if (!null && !dir) || (null && !self.enabled) {
            return Some(-2);
        }
        let result = match r.orig_rax {
            2 | 257 => {
                let flags = if r.orig_rax == 2 { r.rsi } else { r.rdx };
                if dir {
                    Err(-21)
                } else {
                    self.open(flags)
                }
            }
            4 | 6 => Self::stat(pid, r.rsi, false, dir),
            262 => {
                if r.r10 & !0x100 != 0 {
                    Err(-22)
                } else {
                    Self::stat(pid, r.rdx, false, dir)
                }
            }
            332 => {
                if r.rdx & !0x9100 != 0 {
                    Err(-22)
                } else {
                    Self::stat(pid, r.r8, true, dir)
                }
            }
            21 | 269 | 439 => {
                let mode = if r.orig_rax == 21 { r.rsi } else { r.rdx };
                let flags = if r.orig_rax == 439 { r.r10 } else { 0 };
                if mode & !7 != 0 || flags & !0x100 != 0 {
                    Err(-22)
                } else if (dir && mode & 2 != 0) || (!dir && mode & 1 != 0) {
                    Err(-13)
                } else {
                    Ok(0)
                }
            }
            89 => Err(-22), // Character devices are not symlinks.
            _ => Err(-30),  // Assignment metadata is immutable.
        };
        Some(result.unwrap_or_else(|error| error))
    }

    fn open(&mut self, flags: u64) -> Result<i64, i64> {
        const ALLOWED: u64 = 3
            | 0o100
            | 0o200
            | 0o400
            | 0o1000
            | 0o2000
            | 0o4000
            | 0o100000
            | 0o400000
            | CLOEXEC as u64;
        if flags & !ALLOWED != 0 || flags & 3 == 3 {
            return Err(-95);
        }
        if flags & 0o300 == 0o300 {
            return Err(-17);
        }
        let fd = self.registry.open(DOMAIN, b"null").map_err(device_errno)?;
        // Creation and truncation do not mutate an existing character device.
        self.flags[(fd - FD_BASE) as usize] = Some(flags as u32 & !0o1300);
        Ok(fd as i64)
    }

    fn descriptor_call(&mut self, pid: usize, fd: u32, r: &UserRegs) -> Result<i64, i64> {
        let slot = (fd - FD_BASE) as usize;
        let flags = self.flags.get(slot).copied().flatten().ok_or(-9)?;
        match r.orig_rax {
            0 => {
                if flags & ACCESS_MODE == 1 {
                    Err(-9)
                } else {
                    self.registry
                        .read(DOMAIN, fd, &mut [])
                        .map(|n| n as i64)
                        .map_err(device_errno)
                }
            }
            1 => {
                if flags & ACCESS_MODE == 0 {
                    Err(-9)
                } else {
                    // Null consumes no input bytes; an ignored guest buffer is never
                    // dereferenced. Bound discarded bytes per IO just like file IO.
                    let count = r.rdx.min(4096) as usize;
                    self.registry
                        .write(DOMAIN, fd, &[0; 4096][..count])
                        .map(|n| n as i64)
                        .map_err(device_errno)
                }
            }
            3 => {
                self.registry.close(DOMAIN, fd).map_err(device_errno)?;
                self.flags[slot] = None;
                Ok(0)
            }
            5 => Self::stat(pid, r.rsi, false, false),
            8 => {
                if r.rdx <= 4 {
                    Ok(0)
                } else {
                    Err(-22)
                }
            }
            72 => match r.rsi {
                1 => Ok(i64::from(flags & CLOEXEC != 0)),
                2 if r.rdx & !1 == 0 => {
                    self.flags[slot] =
                        Some((flags & !CLOEXEC) | if r.rdx == 1 { CLOEXEC } else { 0 });
                    Ok(0)
                }
                3 => Ok((flags & !CLOEXEC) as i64),
                _ => Err(-95),
            },
            262 | 332 => {
                let flags = if r.orig_rax == 262 { r.r10 } else { r.rdx };
                if flags != 0x1000 {
                    Err(-22)
                } else {
                    Self::stat(
                        pid,
                        if r.orig_rax == 262 { r.rdx } else { r.r8 },
                        r.orig_rax == 332,
                        false,
                    )
                }
            }
            16 => Err(-25),
            _ => Err(-95),
        }
    }

    fn stat(pid: usize, destination: u64, statx: bool, dir: bool) -> Result<i64, i64> {
        write_stat(
            pid,
            destination,
            Stat {
                inode: if dir { 0x1_0000_0000 } else { 0x1_0000_0001 },
                mode: if dir { 0o40555 } else { 0o20666 },
                size: 0,
                device_major: if dir { 0 } else { 1 },
                device_minor: if dir { 0 } else { 3 },
            },
            statx,
        )
    }
}

fn device_errno(error: DeviceError) -> i64 {
    match error {
        DeviceError::DescriptorLimit => -24,
        DeviceError::InvalidDescriptor => -9,
        DeviceError::NotAssigned | DeviceError::UnknownDevice => -2,
        _ => -5,
    }
}
