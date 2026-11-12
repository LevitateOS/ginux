//! Explicitly assigned character devices for configured native launch.
//! All IO uses ginux-devices objects; no host device node or descriptor is used.
//! The random devices draw from the host kernel's `getrandom(2)`, which the
//! workload may already call directly.

use crate::launch_storage::LaunchFs;
use crate::supervisor::{syscall3, UserRegs};
use crate::tracee_io::{read_path, store_u32, write_stat, IoVectors, Stat};
use ginux_devices::{
    DeviceError, DeviceKind, DeviceName, DeviceRegistry, DeviceView, EntropySource,
    IOCTL_RANDOM_GET_ENTROPY_COUNT,
};
use ginux_instance::InstanceConfig;

const INSTANCE: u64 = 1; // One instance per configured supervisor process.
const FD_BASE: u32 = 0x4000_0000;
const FDS: usize = 64;
const CLOEXEC: u32 = 0o2000000;
const ACCESS_MODE: u32 = 3;
/// Per-call transfer bound, as for owned files and channels. Callers retry
/// the remainder of a short read or write.
const IO_SIZE: usize = 4096;

/// The `[devices] assignments` names configured launch serves, each at
/// `/dev/<name>`. Every other name fails before launch.
pub const LAUNCH_DEVICES: [(&[u8], DeviceKind); 3] = [
    (b"null", DeviceKind::Null),
    (b"random", DeviceKind::Random),
    (b"urandom", DeviceKind::Urandom),
];

/// Host `getrandom(2)` that never blocks the supervisor. A host whose
/// generator is not ready yet reports EAGAIN instead of stalling every task.
pub struct HostEntropy;

impl EntropySource for HostEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), DeviceError> {
        const GRND_NONBLOCK: usize = 1;
        let mut filled = 0;
        while filled < output.len() {
            let result = unsafe {
                syscall3(
                    318,
                    output[filled..].as_mut_ptr() as usize,
                    output.len() - filled,
                    GRND_NONBLOCK,
                )
            };
            match result {
                n if n > 0 => filled += n as usize,
                -4 => {}
                -11 => return Err(DeviceError::WouldBlock),
                _ => return Err(DeviceError::Backend),
            }
        }
        Ok(())
    }
}

pub struct LaunchDevices {
    pub network: crate::network_hooks::LaunchNetwork,
    registry: DeviceRegistry<{ LAUNCH_DEVICES.len() }, FDS>,
    flags: [Option<u32>; FDS],
}

impl LaunchDevices {
    pub fn readiness(&mut self, handle: u32) -> Option<u16> {
        if crate::network_hooks::LaunchNetwork::owns(handle) {
            return self.network.readiness(handle);
        }
        let slot = handle.checked_sub(FD_BASE)? as usize;
        // Null and the random devices never wait: Linux reports them readable
        // and writable. A device kind that can wait needs its own readiness.
        self.flags.get(slot).copied().flatten().map(|_| 0x145)
    }

    pub fn prepare(config: &InstanceConfig) -> Result<Self, &'static [u8]> {
        let mut registry = DeviceRegistry::new();
        for device in config.devices.as_slice() {
            let (backend, (name, kind)) = LAUNCH_DEVICES
                .iter()
                .enumerate()
                .find(|(_, (name, _))| *name == device.as_bytes())
                .ok_or(b"unsupported launch device assignment".as_slice())?;
            registry
                .assign(
                    INSTANCE,
                    backend as u64 + 1,
                    DeviceName::new(name).unwrap(),
                    *kind,
                )
                .map_err(|_| b"duplicate launch device assignment".as_slice())?;
        }
        Ok(Self {
            network: crate::network_hooks::LaunchNetwork::prepare(config)?,
            registry,
            flags: [None; FDS],
        })
    }

    pub fn claim(&mut self, pid: usize, r: &UserRegs, fs: &LaunchFs) -> Option<i64> {
        let fd = r.rdi as u32;
        if (fd as i32) >= FD_BASE as i32
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
        if matches!(r.orig_rax, 262 | 332 | 439) {
            match read_path(pid, r.rsi) {
                Ok(path) if path.is_empty() && (fd as i32) >= FD_BASE as i32 => {
                    return Some(
                        self.descriptor_call(pid, fd, r)
                            .unwrap_or_else(|error| error),
                    );
                }
                Ok(path) if path.is_empty() => return None,
                Err(error) => return Some(error),
                _ => {}
            }
        }
        let path = match fs.request_path(pid, r) {
            Ok(Some((_, path))) => path,
            Ok(None) => return None,
            Err(error) => return Some(error),
        };
        if path.as_bytes() != b"/dev" && !path.as_bytes().starts_with(b"/dev/") {
            return None;
        }
        // `/dev` itself, or exactly `/dev/<assigned name>`; nothing else exists.
        let dir = path.as_bytes() == b"/dev";
        let device = path
            .as_bytes()
            .strip_prefix(b"/dev/")
            .and_then(|name| self.registry.view(INSTANCE, name));
        if !dir && device.is_none() {
            return Some(-2);
        }
        let result = match r.orig_rax {
            2 | 257 => {
                let flags = if r.orig_rax == 2 { r.rsi } else { r.rdx };
                match device {
                    Some(device) => self.open(device, flags),
                    None => Err(-21),
                }
            }
            4 | 6 => Self::stat(pid, r.rsi, false, device),
            262 => {
                if r.r10 & !0x1900 != 0 {
                    Err(-22)
                } else {
                    Self::stat(pid, r.rdx, false, device)
                }
            }
            332 => {
                if !crate::launch_storage::valid_statx(r.rdx, r.r10) {
                    Err(-22)
                } else {
                    Self::stat(pid, r.r8, true, device)
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

    fn open(&mut self, device: DeviceView, flags: u64) -> Result<i64, i64> {
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
        let fd = self
            .registry
            .open(INSTANCE, device.name.as_bytes())
            .map_err(device_errno)?;
        // Creation and truncation do not mutate an existing character device.
        self.flags[(fd - FD_BASE) as usize] = Some(flags as u32 & !0o1300);
        Ok(fd as i64)
    }

    fn descriptor_call(&mut self, pid: usize, fd: u32, r: &UserRegs) -> Result<i64, i64> {
        let slot = (fd - FD_BASE) as usize;
        let flags = self.flags.get(slot).copied().flatten().ok_or(-9)?;
        let device = self
            .registry
            .descriptor_view(INSTANCE, fd)
            .map_err(device_errno)?;
        match r.orig_rax {
            // read, pread64 and readv. Linux rejects a negative position first.
            0 | 17 | 19 => {
                if r.orig_rax == 17 && (r.r10 as i64) < 0 {
                    return Err(-22);
                }
                if flags & ACCESS_MODE == 1 {
                    return Err(-9);
                }
                let vectors = Self::vectors(pid, r)?;
                let mut bytes = [0u8; IO_SIZE];
                let count = vectors.length.min(IO_SIZE);
                let filled = self
                    .registry
                    .read(INSTANCE, fd, &mut bytes[..count], &mut HostEntropy)
                    .map_err(device_errno)?;
                // Null reaches EOF without touching the guest buffer. Other
                // bytes go out through the strict copy path, which honors page
                // protections; a partly inaccessible buffer is a short read.
                if filled == 0 {
                    return Ok(0);
                }
                vectors
                    .copy(pid, &mut bytes[..filled], true)
                    .map(|n| n as i64)
            }
            // write, pwrite64 and writev, bounded per call like file IO.
            1 | 18 | 20 => {
                if r.orig_rax == 18 && (r.r10 as i64) < 0 {
                    return Err(-22);
                }
                if flags & ACCESS_MODE == 0 {
                    return Err(-9);
                }
                let vectors = Self::vectors(pid, r)?;
                let mut bytes = [0u8; IO_SIZE];
                let count = vectors.length.min(IO_SIZE);
                // Linux null never dereferences the buffer. The random devices
                // read it (EFAULT or a short write on a bad one) and discard it.
                let consumed = if device.kind == DeviceKind::Null {
                    count
                } else {
                    vectors.copy(pid, &mut bytes[..count], false)?
                };
                self.registry
                    .write(INSTANCE, fd, &bytes[..consumed])
                    .map(|n| n as i64)
                    .map_err(device_errno)
            }
            3 => {
                self.registry.close(INSTANCE, fd).map_err(device_errno)?;
                self.flags[slot] = None;
                Ok(0)
            }
            5 => Self::stat(pid, r.rsi, false, Some(device)),
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
                let valid = if r.orig_rax == 262 {
                    flags & !0x1900 == 0
                } else {
                    crate::launch_storage::valid_statx(flags, r.r10)
                };
                if flags & 0x1000 == 0 || !valid {
                    Err(-22)
                } else {
                    Self::stat(
                        pid,
                        if r.orig_rax == 262 { r.rdx } else { r.r8 },
                        r.orig_rax == 332,
                        Some(device),
                    )
                }
            }
            439 => {
                if r.r10 & !0x1100 != 0 || r.rdx & !7 != 0 {
                    Err(-22)
                } else if r.r10 & 0x1000 == 0 {
                    Err(-2)
                } else if r.rdx & 1 != 0 {
                    Err(-13)
                } else {
                    Ok(0)
                }
            }
            16 => {
                // The kernel reads the request as 32 bits. Only RNDGETENTCNT
                // returns data; it is stored all or nothing in guest memory.
                let request = u64::from(r.rsi as u32);
                let mut payload = [0u8; 4];
                let size = if request == IOCTL_RANDOM_GET_ENTROPY_COUNT {
                    4
                } else {
                    0
                };
                self.registry
                    .ioctl(INSTANCE, fd, request, &mut payload[..size])
                    .map_err(device_errno)?;
                if size != 0 {
                    store_u32(pid, r.rdx, u32::from_ne_bytes(payload))?;
                }
                Ok(0)
            }
            _ => Err(-95),
        }
    }

    /// One buffer, or a readv/writev array of at most 16 entries.
    fn vectors(pid: usize, r: &UserRegs) -> Result<IoVectors, i64> {
        if matches!(r.orig_rax, 19 | 20) {
            IoVectors::read(pid, r.rsi, r.rdx)
        } else {
            Ok(IoVectors::single(r.rsi, r.rdx))
        }
    }

    /// Metadata of `/dev` (no device) or of one assigned character device.
    fn stat(
        pid: usize,
        destination: u64,
        statx: bool,
        device: Option<DeviceView>,
    ) -> Result<i64, i64> {
        let (major, minor) = device.map_or((0, 0), |device| (device.major, device.minor));
        write_stat(
            pid,
            destination,
            Stat {
                accessed: ginux_vfs::Timestamp::ZERO,
                modified: ginux_vfs::Timestamp::ZERO,
                links: 1,
                // Instance-owned identity, stable per device number.
                inode: 0x1_0000_0000 | u64::from(major) << 8 | u64::from(minor),
                mode: if device.is_some() { 0o20666 } else { 0o40555 },
                size: 0,
                device_major: major,
                device_minor: minor,
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
        DeviceError::PermissionDenied => -1,
        DeviceError::UnknownIoctl => -25,
        DeviceError::UnsupportedRequest | DeviceError::InvalidPayload => -22,
        DeviceError::WouldBlock => -11,
        _ => -5,
    }
}
