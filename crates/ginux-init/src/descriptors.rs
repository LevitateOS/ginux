//! Configured-launch public descriptors. Backend handles never cross this ABI.
//! Aliases share an open object; descriptor flags belong to each public slot.

use crate::channel_hooks::LaunchChannels;
use crate::device_hooks::LaunchDevices;
use crate::dispatch::{decide_objects, Lane, NativeDecision};
use crate::fs_hooks::LaunchFs;
use crate::supervisor::{syscall3, syscall4, UserRegs};
use crate::tracee_io::{copy_memory, read_path};
use ginux_core::decide_balanced;

pub const LIMIT: usize = 256;
const CLOEXEC: u64 = 0o2000000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Handle {
    Reserved,
    Native { fd: u32, console: bool },
    Owned(u32),
}

#[derive(Clone, Copy)]
struct Descriptor {
    handle: Handle,
    cloexec: bool,
}

#[derive(Clone, Copy)]
enum Pending {
    Open { slot: usize },
    Close { result: Option<i64> },
}

pub struct DescriptorTable {
    entries: [Option<Descriptor>; LIMIT],
    capacity: usize,
    pending: Option<Pending>,
    saved_args: Option<[u64; 7]>,
}

impl DescriptorTable {
    pub fn new() -> Result<Self, &'static [u8]> {
        let mut limits = [0u64; 2];
        if unsafe { syscall4(302, 0, 7, 0, limits.as_mut_ptr() as usize) } < 0 {
            return Err(b"descriptor limit query failed");
        }
        let mut table = Self {
            entries: [None; LIMIT],
            capacity: limits[0].min(LIMIT as u64) as usize,
            pending: None,
            saved_args: None,
        };
        for fd in 0..3 {
            // Closed bootstrap stdio must not invent an open public handle.
            if unsafe { syscall3(72, fd, 1, 0) } >= 0 {
                table.entries[fd] = Some(Descriptor {
                    handle: Handle::Native {
                        fd: fd as u32,
                        console: true,
                    },
                    cloexec: false,
                });
            }
        }
        Ok(table)
    }

    fn get(&self, fd: u64) -> Result<Descriptor, i64> {
        let fd = fd as i32;
        if fd < 0 {
            return Err(-9);
        }
        self.entries
            .get(fd as usize)
            .copied()
            .flatten()
            .filter(|d| d.handle != Handle::Reserved)
            .ok_or(-9)
    }

    fn free(&self, minimum: u64) -> Result<usize, i64> {
        if minimum > i32::MAX as u64 || minimum as usize >= self.capacity {
            return Err(-22);
        }
        self.entries[..self.capacity]
            .iter()
            .enumerate()
            .skip(minimum as usize)
            .find_map(|(i, d)| d.is_none().then_some(i))
            .ok_or(-24)
    }

    fn reserve(&mut self, cloexec: bool) -> Result<usize, i64> {
        let slot = self.free(0)?;
        self.entries[slot] = Some(Descriptor {
            handle: Handle::Reserved,
            cloexec,
        });
        Ok(slot)
    }

    fn save(&mut self, r: &UserRegs) {
        self.saved_args = Some([r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9, r.orig_rax]);
    }

    /// Called at the matching syscall exit, including emulated exits. Never
    /// restore memory/TLS or signal state: only the arguments we translated.
    pub fn finish(&mut self, r: &mut UserRegs) -> Result<bool, &'static [u8]> {
        let mut changed = false;
        if let Some(pending) = self.pending.take() {
            match pending {
                Pending::Open { slot } => {
                    if r.rax as i64 >= 0 {
                        if r.rax >= LIMIT as u64 {
                            return Err(b"native descriptor outside bounded table");
                        }
                        self.entries[slot].as_mut().unwrap().handle = Handle::Native {
                            fd: r.rax as u32,
                            console: false,
                        };
                        r.rax = slot as u64;
                    } else {
                        self.entries[slot] = None;
                    }
                }
                Pending::Close { result } => {
                    // Native handles are known live; EBADF means ownership drift.
                    if r.rax as i64 == -9 {
                        return Err(b"native descriptor close lost ownership");
                    }
                    if let Some(result) = result {
                        r.rax = result as u64;
                    }
                }
            }
            changed = true;
        }
        if let Some(args) = self.saved_args.take() {
            r.rdi = args[0];
            r.rsi = args[1];
            r.rdx = args[2];
            r.r10 = args[3];
            r.r8 = args[4];
            r.r9 = args[5];
            r.orig_rax = args[6];
            changed = true;
        }
        Ok(changed)
    }

    pub fn enter(
        &mut self,
        pid: usize,
        r: &mut UserRegs,
        fs: &mut LaunchFs,
        devices: &mut LaunchDevices,
        channels: &mut LaunchChannels,
    ) -> NativeDecision {
        // Resource changes cannot silently invalidate the public allocator.
        if r.orig_rax == 302 && r.rsi == 7 && r.rdx != 0 {
            return ready(-1);
        }
        let result = match r.orig_rax {
            2 | 257 => {
                self.save(r);
                self.open(pid, r, fs, devices, channels)
            }
            22 | 293 => {
                self.save(r);
                self.pipe(pid, r, channels)
            }
            3 => {
                self.save(r);
                self.get(r.rdi)
                    .and_then(|_| self.close(r.rdi as u32 as usize, r, pid, fs, devices, channels))
            }
            32 | 33 | 292 => {
                self.save(r);
                self.dup(pid, r, fs, devices, channels)
            }
            72 => {
                self.save(r);
                match self.get(r.rdi) {
                    Err(e) => Err(e),
                    Ok(entry) => match r.rsi {
                        0 | 1030 => self.dup(pid, r, fs, devices, channels),
                        1 => Ok(ready(entry.cloexec as i64)),
                        2 if r.rdx & !1 == 0 => {
                            self.entries[r.rdi as u32 as usize]
                                .as_mut()
                                .unwrap()
                                .cloexec = r.rdx != 0;
                            Ok(ready(0))
                        }
                        2 => Err(-22),
                        _ => self.descriptor(pid, r, entry, fs, devices, channels),
                    },
                }
            }
            0 | 1 | 5 | 8 | 16 | 17 | 18 | 19 | 20 | 74 | 75 | 77 | 78 | 91 | 217 => {
                self.save(r);
                self.get(r.rdi)
                    .and_then(|d| self.descriptor(pid, r, d, fs, devices, channels))
            }
            9 if r.r10 & 0x20 == 0 => {
                self.save(r);
                match self.get(r.r8) {
                    Ok(Descriptor {
                        handle: Handle::Native { fd, console: false },
                        ..
                    }) => {
                        r.r8 = fd as u64;
                        Ok(decide_objects(pid, r, fs, devices, channels))
                    }
                    Ok(_) => Err(-95),
                    Err(e) => Err(e),
                }
            }
            258 | 262 | 263 | 268 | 269 | 332 | 439 => {
                self.save(r);
                self.path_descriptor(pid, r, fs, devices, channels)
            }
            7 => self.console_poll(pid, r),
            _ => Ok(decide_objects(pid, r, fs, devices, channels)),
        };
        result.unwrap_or_else(ready)
    }

    fn path_descriptor(
        &mut self,
        pid: usize,
        r: &mut UserRegs,
        fs: &mut LaunchFs,
        devices: &mut LaunchDevices,
        channels: &mut LaunchChannels,
    ) -> Result<NativeDecision, i64> {
        let path = read_path(pid, r.rsi)?;
        if path.as_bytes().first() == Some(&b'/') {
            r.rdi = (-100i64) as u64;
        } else if r.rdi as i32 != -100 {
            let entry = self.get(r.rdi)?;
            if path.is_empty() {
                match entry.handle {
                    Handle::Native { fd, .. } => r.rdi = fd as u64,
                    Handle::Owned(handle) => r.rdi = handle as u64,
                    Handle::Reserved => return Err(-9),
                }
            } else {
                // Relative directory descriptors require resolved directory
                // views; never interpret a backend integer as a public fd.
                return Err(if matches!(entry.handle, Handle::Native { .. }) {
                    -95
                } else {
                    -20
                });
            }
        }
        Ok(decide_objects(pid, r, fs, devices, channels))
    }

    fn open(
        &mut self,
        pid: usize,
        r: &mut UserRegs,
        fs: &mut LaunchFs,
        devices: &mut LaunchDevices,
        channels: &mut LaunchChannels,
    ) -> Result<NativeDecision, i64> {
        let flags = if r.orig_rax == 2 { r.rsi } else { r.rdx };
        // Reserve before any create/truncate or native open can occur.
        let slot = self.reserve(flags & CLOEXEC != 0)?;
        if r.orig_rax == 2 {
            r.rsi &= !CLOEXEC;
        } else {
            r.rdx &= !CLOEXEC;
        }
        let decision = if r.orig_rax == 257 {
            self.path_descriptor(pid, r, fs, devices, channels)
        } else {
            Ok(decide_objects(pid, r, fs, devices, channels))
        };
        match decision {
            Ok(NativeDecision::Hooked { lane, result }) => {
                if result >= 0 {
                    self.entries[slot].as_mut().unwrap().handle = Handle::Owned(result as u32);
                } else {
                    self.entries[slot] = None;
                }
                Ok(NativeDecision::Hooked {
                    lane,
                    result: if result >= 0 { slot as i64 } else { result },
                })
            }
            Ok(NativeDecision::Contract(decision)) => {
                self.pending = Some(Pending::Open { slot });
                Ok(NativeDecision::Contract(decision))
            }
            other => {
                self.entries[slot] = None;
                other
            }
        }
    }

    fn pipe(
        &mut self,
        pid: usize,
        r: &UserRegs,
        channels: &mut LaunchChannels,
    ) -> Result<NativeDecision, i64> {
        let flags = if r.orig_rax == 293 { r.rsi } else { 0 };
        if flags & !(CLOEXEC | 0o4000) != 0 {
            return Err(-22);
        }
        let first = self.reserve(flags & CLOEXEC != 0)?;
        let second = match self.reserve(flags & CLOEXEC != 0) {
            Ok(s) => s,
            Err(e) => {
                self.entries[first] = None;
                return Err(e);
            }
        };
        let handles = match channels.allocate(flags & !CLOEXEC) {
            Ok(handles) => handles,
            Err(e) => {
                self.entries[first] = None;
                self.entries[second] = None;
                return Err(e);
            }
        };
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&(first as u32).to_le_bytes());
        bytes[4..].copy_from_slice(&(second as u32).to_le_bytes());
        let copied = copy_memory(pid, r.rdi, &mut bytes, true);
        if copied != Ok(8) {
            channels.release(handles[0]);
            channels.release(handles[1]);
            self.entries[first] = None;
            self.entries[second] = None;
            return Err(-14);
        }
        self.entries[first].as_mut().unwrap().handle = Handle::Owned(handles[0]);
        self.entries[second].as_mut().unwrap().handle = Handle::Owned(handles[1]);
        Ok(ready(0))
    }

    fn descriptor(
        &self,
        pid: usize,
        r: &mut UserRegs,
        entry: Descriptor,
        fs: &mut LaunchFs,
        devices: &mut LaunchDevices,
        channels: &mut LaunchChannels,
    ) -> Result<NativeDecision, i64> {
        let public_fd = r.rdi as u32;
        match entry.handle {
            Handle::Native { fd, console } => {
                if console && matches!(r.orig_rax, 78 | 217) {
                    return Err(-20);
                }
                if r.orig_rax == 72 {
                    // Duplication and descriptor flags are handled above.
                    // Never broker native locks, leases or signal ownership.
                    if !matches!(r.rsi, 3 | 4) {
                        return Err(-95);
                    }
                    const STATUS_FLAGS: u64 =
                        3 | 0o2000 | 0o4000 | 0o100000 | 0o200000 | 0o400000 | 0o10000000;
                    if r.rsi == 4 && r.rdx & !STATUS_FLAGS != 0 {
                        return Err(-95);
                    }
                }
                if !console && matches!(r.orig_rax, 1 | 20 | 18 | 77 | 91) {
                    return Err(-9);
                }
                r.rdi = fd as u64;
            }
            Handle::Owned(handle) => r.rdi = handle as u64,
            Handle::Reserved => return Err(-9),
        }
        Ok(match decide_objects(pid, r, fs, devices, channels) {
            NativeDecision::Park { .. } => NativeDecision::Park { fd: public_fd },
            decision => decision,
        })
    }

    fn close(
        &mut self,
        slot: usize,
        r: &mut UserRegs,
        pid: usize,
        fs: &mut LaunchFs,
        devices: &mut LaunchDevices,
        channels: &mut LaunchChannels,
    ) -> Result<NativeDecision, i64> {
        let result = if r.orig_rax == 3 {
            None
        } else {
            Some(slot as i64)
        };
        let entry = self.entries[slot].take().ok_or(-9)?;
        if self
            .entries
            .iter()
            .flatten()
            .any(|d| d.handle == entry.handle)
        {
            return Ok(ready(result.unwrap_or(0)));
        }
        match entry.handle {
            Handle::Native { fd, .. } => {
                r.orig_rax = 3;
                r.rdi = fd as u64;
                self.pending = Some(Pending::Close { result });
                Ok(NativeDecision::Contract(decide_balanced(3)))
            }
            Handle::Owned(handle) => {
                let mut close = *r;
                close.orig_rax = 3;
                close.rdi = handle as u64;
                match decide_objects(pid, &close, fs, devices, channels) {
                    NativeDecision::Hooked { result: 0, .. } => Ok(ready(result.unwrap_or(0))),
                    _ => Err(-5),
                }
            }
            Handle::Reserved => Err(-9),
        }
    }

    fn dup(
        &mut self,
        pid: usize,
        r: &mut UserRegs,
        fs: &mut LaunchFs,
        devices: &mut LaunchDevices,
        channels: &mut LaunchChannels,
    ) -> Result<NativeDecision, i64> {
        let source = r.rdi as i32;
        let mut entry = self.get(r.rdi)?;
        let (target, cloexec) = match r.orig_rax {
            32 => (self.free(0)?, false),
            72 => (self.free(r.rdx)?, r.rsi == 1030),
            33 | 292 => {
                let target = r.rsi as i32;
                if target < 0 || target as usize >= self.capacity {
                    return Err(-9);
                }
                if r.orig_rax == 292 && (target == source || r.rdx & !CLOEXEC != 0) {
                    return Err(-22);
                }
                if target == source {
                    return Ok(ready(target as i64));
                }
                (target as usize, r.orig_rax == 292 && r.rdx != 0)
            }
            _ => return Err(-22),
        };
        entry.cloexec = cloexec;
        // Preserve the source in its own slot until target retirement completes.
        let decision = if self.entries[target].is_some() {
            self.close(target, r, pid, fs, devices, channels)?
        } else {
            ready(target as i64)
        };
        self.entries[target] = Some(entry);
        Ok(decision)
    }

    fn console_poll(&self, pid: usize, r: &UserRegs) -> Result<NativeDecision, i64> {
        // Preserve the existing bounded bootstrap poll surface. Moved stdio or
        // other owned objects need the pending common readiness adapter.
        if r.rsi > 16 || r.rdx > 300000 {
            return Err(-1);
        }
        for i in 0..r.rsi {
            let address = r.rdi.checked_add(i * 8).ok_or(-1)?;
            let mut bytes = [0; 8];
            copy_memory(pid, address, &mut bytes, false).map_err(|_| -1)?;
            let fd = i32::from_le_bytes(bytes[..4].try_into().unwrap());
            if fd < 0 {
                continue;
            }
            if fd > 2 {
                return Err(-1);
            }
            match self.entries[fd as usize] {
                Some(Descriptor {
                    handle:
                        Handle::Native {
                            fd: raw,
                            console: true,
                        },
                    ..
                }) if raw == fd as u32 => {}
                None if !self
                    .entries
                    .iter()
                    .flatten()
                    .any(|d| matches!(d.handle,Handle::Native {fd:raw,..} if raw==fd as u32)) => {}
                _ => return Err(-1),
            }
        }
        Ok(NativeDecision::Contract(decide_balanced(7)))
    }
}

fn ready(result: i64) -> NativeDecision {
    NativeDecision::Hooked {
        lane: Lane::Filesystem,
        result,
    }
}
