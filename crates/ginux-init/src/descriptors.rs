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

/// Owned backend handles are domain-wide; native kernel numbers are per task.
pub struct ObjectReferences {
    counts: [u16; 144],
}
impl ObjectReferences {
    pub const fn new() -> Self {
        Self { counts: [0; 144] }
    }
    pub fn active(&self) -> usize {
        self.counts.iter().filter(|n| **n != 0).count()
    }
    fn index(handle: u32) -> usize {
        if (0x4000_0000..0x4000_0040).contains(&handle) {
            80 + (handle - 0x4000_0000) as usize
        } else if (0x2000_0000..0x2000_0010).contains(&handle) {
            64 + (handle - 0x2000_0000) as usize
        } else {
            assert!((1048576..1048640).contains(&handle));
            (handle - 1048576) as usize
        }
    }
    fn retain(&mut self, handle: u32) {
        let i = Self::index(handle);
        self.counts[i] = self.counts[i]
            .checked_add(1)
            .expect("owned descriptor reference overflow");
    }
    fn release(&mut self, handle: u32) -> bool {
        let i = Self::index(handle);
        assert!(self.counts[i] > 0);
        self.counts[i] -= 1;
        self.counts[i] == 0
    }
}

pub struct Backends<'a> {
    pub filesystem: &'a mut LaunchFs,
    pub devices: &'a mut LaunchDevices,
    pub channels: &'a mut LaunchChannels,
    pub refs: &'a mut ObjectReferences,
}
impl Backends<'_> {
    fn claim(&mut self, pid: usize, r: &UserRegs) -> NativeDecision {
        decide_objects(pid, r, self.filesystem, self.devices, self.channels)
    }
    fn release(&mut self, handle: u32) -> Result<(), &'static [u8]> {
        if !self.refs.release(handle) {
            return Ok(());
        }
        // Owned close does not use task memory or a native descriptor.
        let mut r = empty_regs();
        r.orig_rax = 3;
        r.rdi = handle as u64;
        match self.claim(0, &r) {
            NativeDecision::Hooked { result: 0, .. } => Ok(()),
            _ => Err(b"owned backend release failed"),
        }
    }
}

fn empty_regs() -> UserRegs {
    unsafe { core::mem::zeroed() }
}

pub struct DescriptorTable {
    entries: [Option<Descriptor>; LIMIT],
    capacity: usize,
}

/// Each native task owns its syscall transaction, even when tables are shared.
pub struct DescriptorCall {
    pending: Option<Pending>,
    saved_args: Option<[u64; 7]>,
    pinned: Option<Descriptor>,
}
impl DescriptorCall {
    pub const fn new() -> Self {
        Self {
            pending: None,
            saved_args: None,
            pinned: None,
        }
    }
    pub fn native_mutation(&self) -> bool {
        self.pending.is_some()
    }
    pub fn reset(&mut self, backends: &mut Backends) -> Result<(), &'static [u8]> {
        if let Some(Descriptor {
            handle: Handle::Owned(handle),
            ..
        }) = self.pinned.take()
        {
            backends.release(handle)?;
        }
        *self = Self::new();
        Ok(())
    }
    fn save(&mut self, r: &UserRegs) {
        self.saved_args = Some([r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9, r.orig_rax]);
    }
}

impl DescriptorCall {
    /// Called at the matching syscall exit, including emulated exits. Never
    /// restore memory/TLS or signal state: only the arguments we translated.
    pub fn finish(
        &mut self,
        table: &mut DescriptorTable,
        r: &mut UserRegs,
        backends: &mut Backends,
    ) -> Result<bool, &'static [u8]> {
        let mut changed = false;
        if let Some(pending) = self.pending.take() {
            match pending {
                Pending::Open { slot } => {
                    if r.rax as i64 >= 0 {
                        if r.rax >= LIMIT as u64 {
                            return Err(b"native descriptor outside bounded table");
                        }
                        table.entries[slot].as_mut().unwrap().handle = Handle::Native {
                            fd: r.rax as u32,
                            console: false,
                        };
                        r.rax = slot as u64;
                    } else {
                        table.entries[slot] = None;
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
        if self.pinned.is_some() {
            self.reset(backends)?;
            changed = true;
        }
        Ok(changed)
    }
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
        };
        for fd in 0..3 {
            // Bootstrap exec closes CLOEXEC stdio just like an already closed
            // descriptor. Neither may invent a live public console handle.
            if unsafe { syscall3(72, fd, 1, 0) } == 0 {
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

    pub fn fork_copy(&self, refs: &mut ObjectReferences) -> Result<Self, &'static [u8]> {
        if self
            .entries
            .iter()
            .flatten()
            .any(|d| d.handle == Handle::Reserved)
        {
            return Err(b"cannot inherit unfinished descriptor syscall");
        }
        for entry in self.entries.iter().flatten() {
            if let Handle::Owned(handle) = entry.handle {
                refs.retain(handle);
            }
        }
        Ok(Self {
            entries: self.entries,
            capacity: self.capacity,
        })
    }

    /// One native handle can back public aliases with different FD_CLOEXEC.
    /// Synchronize the kernel bit only when all aliases will be retired.
    pub fn next_exec_native(&self, first: usize) -> Option<(usize, bool)> {
        for fd in first..LIMIT {
            let mut aliases = self
                .entries
                .iter()
                .flatten()
                .filter(
                    |d| matches!(d.handle, Handle::Native { fd: raw, .. } if raw as usize == fd),
                )
                .peekable();
            if aliases.peek().is_some() {
                return Some((fd, aliases.all(|d| d.cloexec)));
            }
        }
        None
    }

    pub fn exec_native_descriptor(&self, fd: u64) -> Result<u32, i64> {
        match self.get(fd)?.handle {
            Handle::Native { fd, console: false } => Ok(fd),
            _ => Err(-95),
        }
    }

    /// PTRACE_EVENT_EXEC is the commit point. Failed exec never calls this.
    pub fn exec_completed(&mut self, backends: &mut Backends) -> Result<(), &'static [u8]> {
        if self
            .entries
            .iter()
            .flatten()
            .any(|d| d.handle == Handle::Reserved)
        {
            return Err(b"exec overlapped unfinished descriptor syscall");
        }
        for entry in &mut self.entries {
            if entry.is_some_and(|d| d.cloexec) {
                if let Handle::Owned(handle) = entry.take().unwrap().handle {
                    backends.release(handle)?;
                }
                // Kernel closed native handles with no surviving aliases.
            }
        }
        Ok(())
    }

    pub fn release_exited(&mut self, backends: &mut Backends) -> Result<(), &'static [u8]> {
        for entry in &mut self.entries {
            if let Some(Descriptor {
                handle: Handle::Owned(handle),
                ..
            }) = entry.take()
            {
                backends.release(handle)?;
            }
        }
        Ok(())
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

    pub fn enter(
        &mut self,
        pid: usize,
        r: &mut UserRegs,
        backends: &mut Backends,
        call: &mut DescriptorCall,
    ) -> NativeDecision {
        // Resource changes cannot silently invalidate the public allocator.
        if r.orig_rax == 302 && r.rsi == 7 && r.rdx != 0 {
            return ready(-1);
        }
        let result = match r.orig_rax {
            2 | 257 => {
                call.save(r);
                self.open(pid, r, backends, call)
            }
            22 | 293 => {
                call.save(r);
                self.pipe(pid, r, backends)
            }
            3 => {
                call.save(r);
                self.get(r.rdi)
                    .and_then(|_| self.close(r.rdi as u32 as usize, r, pid, backends, call))
            }
            32 | 33 | 292 => {
                call.save(r);
                self.dup(pid, r, backends, call)
            }
            72 => {
                call.save(r);
                match self.get(r.rdi) {
                    Err(e) => Err(e),
                    Ok(entry) => match r.rsi {
                        0 | 1030 => self.dup(pid, r, backends, call),
                        1 => Ok(ready(entry.cloexec as i64)),
                        2 if r.rdx & !1 == 0 => {
                            self.entries[r.rdi as u32 as usize]
                                .as_mut()
                                .unwrap()
                                .cloexec = r.rdx != 0;
                            Ok(ready(0))
                        }
                        2 => Err(-22),
                        _ => self.descriptor(pid, r, entry, backends, call),
                    },
                }
            }
            0 | 1 | 5 | 8 | 16 | 17 | 18 | 19 | 20 | 74 | 75 | 77 | 78 | 91 | 217 => {
                call.save(r);
                call.pinned
                    .map(Ok)
                    .unwrap_or_else(|| self.get(r.rdi))
                    .and_then(|d| self.descriptor(pid, r, d, backends, call))
            }
            9 if r.r10 & 0x20 == 0 => {
                call.save(r);
                match self.get(r.r8) {
                    Ok(Descriptor {
                        handle: Handle::Native { fd, console: false },
                        ..
                    }) => {
                        r.r8 = fd as u64;
                        Ok(backends.claim(pid, r))
                    }
                    Ok(_) => Err(-95),
                    Err(e) => Err(e),
                }
            }
            258 | 262 | 263 | 268 | 269 | 332 | 439 => {
                call.save(r);
                self.path_descriptor(pid, r, backends)
            }
            7 => self.console_poll(pid, r),
            _ => Ok(backends.claim(pid, r)),
        };
        result.unwrap_or_else(ready)
    }

    fn path_descriptor(
        &mut self,
        pid: usize,
        r: &mut UserRegs,
        backends: &mut Backends,
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
        Ok(backends.claim(pid, r))
    }

    fn open(
        &mut self,
        pid: usize,
        r: &mut UserRegs,
        backends: &mut Backends,
        call: &mut DescriptorCall,
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
            self.path_descriptor(pid, r, backends)
        } else {
            Ok(backends.claim(pid, r))
        };
        match decision {
            Ok(NativeDecision::Hooked { lane, result }) => {
                if result >= 0 {
                    backends.refs.retain(result as u32);
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
                call.pending = Some(Pending::Open { slot });
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
        backends: &mut Backends,
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
        let handles = match backends.channels.allocate(flags & !CLOEXEC) {
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
            backends.channels.release(handles[0]);
            backends.channels.release(handles[1]);
            self.entries[first] = None;
            self.entries[second] = None;
            return Err(-14);
        }
        backends.refs.retain(handles[0]);
        backends.refs.retain(handles[1]);
        self.entries[first].as_mut().unwrap().handle = Handle::Owned(handles[0]);
        self.entries[second].as_mut().unwrap().handle = Handle::Owned(handles[1]);
        Ok(ready(0))
    }

    fn descriptor(
        &self,
        pid: usize,
        r: &mut UserRegs,
        entry: Descriptor,
        backends: &mut Backends,
        call: &mut DescriptorCall,
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
        Ok(match backends.claim(pid, r) {
            NativeDecision::Park { .. } => {
                if call.pinned.is_none() {
                    if let Handle::Owned(handle) = entry.handle {
                        backends.refs.retain(handle);
                    }
                    call.pinned = Some(entry);
                }
                NativeDecision::Park { fd: public_fd }
            }
            decision => decision,
        })
    }

    fn close(
        &mut self,
        slot: usize,
        r: &mut UserRegs,
        pid: usize,
        backends: &mut Backends,
        call: &mut DescriptorCall,
    ) -> Result<NativeDecision, i64> {
        let result = if r.orig_rax == 3 {
            None
        } else {
            Some(slot as i64)
        };
        let entry = self.entries[slot].take().ok_or(-9)?;
        if let Handle::Owned(handle) = entry.handle {
            if !backends.refs.release(handle) {
                return Ok(ready(result.unwrap_or(0)));
            }
        } else if self
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
                call.pending = Some(Pending::Close { result });
                Ok(NativeDecision::Contract(decide_balanced(3)))
            }
            Handle::Owned(handle) => {
                let mut close = *r;
                close.orig_rax = 3;
                close.rdi = handle as u64;
                match backends.claim(pid, &close) {
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
        backends: &mut Backends,
        call: &mut DescriptorCall,
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
            self.close(target, r, pid, backends, call)?
        } else {
            ready(target as i64)
        };
        if let Handle::Owned(handle) = entry.handle {
            backends.refs.retain(handle);
        }
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
