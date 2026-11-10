//! Configured-launch public descriptors. Backend handles never cross this ABI.
//! Aliases share an open object; descriptor flags belong to each public slot.

use crate::channel_hooks::LaunchChannels;
use crate::device_hooks::LaunchDevices;
use crate::dispatch::{decide_objects, Lane, NativeDecision};
use crate::event_hooks::{Event, Key, ALLOWED_EVENTS, WATCHES};
use crate::launch_storage::LaunchFs;
use crate::supervisor::{syscall2, syscall3, syscall4, UserRegs};
use crate::tracee_io::{copy_memory, read_path};
use ginux_core::decide_balanced;

pub const LIMIT: usize = 256;
pub enum ExecDescriptor {
    Native(u32),
    Owned(u32),
}
const CLOEXEC: u64 = 0o2000000;
const PATH_ONLY: u64 = 0o10000000;

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
    // Immutable metadata-only kind; copies/aliases must never gain data access.
    path_flags: u32,
}

#[derive(Clone, Copy)]
enum Pending {
    Open { slot: usize },
    Close { result: Option<i64> },
}

/// Owned backend handles are instance-wide; native kernel numbers are per task.
pub struct ObjectReferences {
    counts: [u16; 128 + crate::channel_hooks::FDS + crate::network_hooks::FDS],
    generations: [u64; 128 + crate::channel_hooks::FDS + crate::network_hooks::FDS],
}
impl ObjectReferences {
    pub const fn new() -> Self {
        Self {
            counts: [0; 128 + crate::channel_hooks::FDS + crate::network_hooks::FDS],
            generations: [0; 128 + crate::channel_hooks::FDS + crate::network_hooks::FDS],
        }
    }
    pub fn active(&self) -> usize {
        self.counts.iter().filter(|n| **n != 0).count()
    }
    fn index(handle: u32) -> usize {
        if crate::network_hooks::LaunchNetwork::owns(handle) {
            128 + crate::channel_hooks::FDS + (handle - crate::network_hooks::FD_BASE) as usize
        } else if (0x4000_0000..0x4000_0040).contains(&handle) {
            64 + crate::channel_hooks::FDS + (handle - 0x4000_0000) as usize
        } else if (0x2000_0000..0x2000_0000 + crate::channel_hooks::FDS as u32).contains(&handle) {
            64 + (handle - 0x2000_0000) as usize
        } else {
            assert!((1048576..1048640).contains(&handle));
            (handle - 1048576) as usize
        }
    }
    fn retain(&mut self, handle: u32) {
        let i = Self::index(handle);
        if self.counts[i] == 0 {
            self.generations[i] = self.generations[i]
                .checked_add(1)
                .expect("owned descriptor generation overflow");
        }
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
    fn key(&self, handle: u32) -> Key {
        Key {
            handle,
            generation: self.generations[Self::index(handle)],
        }
    }
    fn current(&self, key: Key) -> bool {
        let index = Self::index(key.handle);
        self.counts[index] != 0 && self.generations[index] == key.generation
    }
}

pub struct Backends<'a> {
    pub filesystem: &'a mut LaunchFs,
    pub devices: &'a mut LaunchDevices,
    pub channels: &'a mut LaunchChannels,
    pub refs: &'a mut ObjectReferences,
}
impl Backends<'_> {
    fn readiness(&mut self, handle: u32) -> Option<u16> {
        self.channels
            .readiness(handle)
            .or_else(|| self.filesystem.readiness(handle))
            .or_else(|| self.devices.readiness(handle))
    }

    fn refresh_epolls(&mut self) {
        if !self.channels.has_epolls() {
            return;
        }
        for handle in self.channels.epolls().into_iter().flatten() {
            let Some(snapshot) = self.channels.epoll(handle).copied() else {
                continue;
            };
            for (index, watch) in snapshot.watches.into_iter().enumerate() {
                let Some(watch) = watch else {
                    continue;
                };
                let current = self.refs.current(watch.key);
                let available = if current {
                    let mut available = self.readiness(watch.key.handle).unwrap_or(8 | 16);
                    if watch.events & 0x2000 != 0
                        && self.devices.network.read_half_closed(watch.key.handle)
                    {
                        available |= 0x2000;
                    }
                    available
                } else {
                    0
                };
                if let Some(epoll) = self.channels.epoll_mut(handle) {
                    if !current {
                        epoll.watches[index] = None;
                    } else if let Some(watch) = &mut epoll.watches[index] {
                        watch.observe(available);
                    }
                }
            }
        }
    }

    fn claim(&mut self, pid: usize, r: &UserRegs) -> NativeDecision {
        self.claim_with_write(pid, 0, r, &mut crate::channel_hooks::WriteProgress::new())
    }
    fn claim_with_write(
        &mut self,
        pid: usize,
        signal_tgid: usize,
        r: &UserRegs,
        progress: &mut crate::channel_hooks::WriteProgress,
    ) -> NativeDecision {
        let counter = matches!(r.orig_rax, 0 | 1)
            && matches!(
                self.channels.event(r.rdi as u32),
                Some(Event::Counter { .. })
            );
        let decision = decide_objects(
            pid,
            signal_tgid,
            r,
            self.filesystem,
            self.devices,
            self.channels,
            progress,
        );
        if counter && matches!(&decision, NativeDecision::Hooked { result: 8, .. }) {
            self.channels
                .notify_counter(r.rdi as u32, if r.orig_rax == 1 { 1 } else { 4 });
        }
        decision
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

/// A traced task owns its in-flight syscall and poll state independently of
/// the descriptor table it uses.
pub struct DescriptorCall {
    pending: Option<Pending>,
    saved_args: Option<[u64; 7]>,
    pinned: Option<Descriptor>,
    poll_wait: bool,
    poll_tick: bool,
    poll_deadline: Option<u64>,
    poll_input: [u8; 128],
    channel_write: crate::channel_hooks::WriteProgress,
}

impl DescriptorCall {
    pub const fn new() -> Self {
        Self {
            pending: None,
            saved_args: None,
            pinned: None,
            poll_wait: false,
            poll_tick: false,
            poll_deadline: None,
            poll_input: [0; 128],
            channel_write: crate::channel_hooks::WriteProgress::new(),
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

    pub fn needs_poll_tick(&self) -> bool {
        self.poll_tick
    }

    /// Bytes a parked blocking write already published. A signal handler
    /// ends that write with this count rather than a restart, as Linux does.
    pub fn interrupted_result(&self) -> Option<i64> {
        let written = self.channel_write.written();
        (written != 0).then_some(written as i64)
    }

    fn save(&mut self, r: &UserRegs) {
        self.saved_args = Some([r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9, r.orig_rax]);
    }

    /// Called at the matching syscall exit, including emulated exits. Never
    /// restore memory/TLS or signal state: only the arguments we translated.
    pub fn finish(
        &mut self,
        table: &mut DescriptorTable,
        r: &mut UserRegs,
        backends: &mut Backends,
    ) -> Result<bool, &'static [u8]> {
        self.channel_write = crate::channel_hooks::WriteProgress::new();
        self.poll_wait = false;
        self.poll_tick = false;
        self.poll_deadline = None;
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
                    path_flags: 0,
                });
            }
        }
        Ok(table)
    }

    pub fn console_descriptor(&self, fd: u64) -> bool {
        matches!(
            self.get(fd).map(|d| d.handle),
            Ok(Handle::Native { console: true, .. })
        )
    }

    pub fn network_descriptor(&self, fd: u64) -> bool {
        matches!(self.get(fd).map(|d| d.handle), Ok(Handle::Owned(handle)) if crate::network_hooks::LaunchNetwork::owns(handle))
    }

    pub fn capacity(&self) -> usize {
        self.capacity
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

    pub fn native_descriptor_set(&self) -> [bool; LIMIT] {
        let mut used = [false; LIMIT];
        for descriptor in self.entries.iter().flatten() {
            if let Handle::Native { fd, .. } = descriptor.handle {
                used[fd as usize] = true;
            }
        }
        used
    }

    pub fn mapping_file(&self, fd: u64) -> Result<Option<u32>, i64> {
        let entry = self.get(fd)?;
        if entry.path_flags != 0 {
            return Err(-9);
        }
        match entry.handle {
            Handle::Native { .. } => Ok(None),
            Handle::Owned(handle) if (1048576..1048640).contains(&handle) => Ok(Some(handle)),
            _ => Err(-95),
        }
    }

    pub fn exec_descriptor(&self, fd: u64) -> Result<ExecDescriptor, i64> {
        let entry = self.get(fd)?;
        if entry.path_flags != 0 {
            return Err(-9);
        }
        match entry.handle {
            Handle::Native { fd, console: false } => Ok(ExecDescriptor::Native(fd)),
            Handle::Owned(handle) if (1048576..1048640).contains(&handle) => {
                Ok(ExecDescriptor::Owned(handle))
            }
            _ => Err(-95),
        }
    }
    pub fn exec_path_dirfd(&self, pid: usize, fd: u64, address: u64) -> Result<u64, i64> {
        self.path_handle(pid, fd, address)
    }

    /// Only a calling task's live public filesystem descriptors have a name.
    /// Path digits do not use the i32 syscall-argument narrowing rule.
    pub fn self_fd_path(
        &self,
        pid: usize,
        path: &[u8],
        filesystem: &LaunchFs,
    ) -> Option<Result<ginux_instance::Text<{ ginux_vfs::MAX_PATH }>, i64>> {
        let digits = path.strip_prefix(b"/proc/self/fd/")?;
        Some((|| {
            if digits.is_empty() {
                return Err(-2);
            }
            let mut fd = 0usize;
            for digit in digits {
                if !digit.is_ascii_digit() {
                    return Err(-2);
                }
                fd = fd
                    .checked_mul(10)
                    .and_then(|fd| fd.checked_add((digit - b'0') as usize))
                    .filter(|fd| *fd < LIMIT)
                    .ok_or(-2)?;
            }
            match self.get(fd as u64).map_err(|_| -2)?.handle {
                Handle::Native { fd, console: false } => crate::tracee_io::image_fd_path(pid, fd),
                Handle::Owned(handle) if (1048576..1048640).contains(&handle) => {
                    filesystem.descriptor_path(handle)
                }
                _ => Err(-2),
            }
        })())
    }
    pub fn exec_cloexec(&self, fd: u64) -> Result<bool, i64> {
        Ok(self.get(fd)?.cloexec)
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
                    backends.filesystem.close_locks(handle);
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
        // Linux FD arguments are 32-bit. Narrow before public-table lookup;
        // high register bits never select a backend/native private descriptor.
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
            path_flags: 0,
        });
        Ok(slot)
    }

    pub fn enter(
        &mut self,
        pid: usize,
        signal_tgid: usize,
        r: &mut UserRegs,
        backends: &mut Backends,
        call: &mut DescriptorCall,
    ) -> NativeDecision {
        backends.refresh_epolls();
        let result = self.enter_inner(pid, signal_tgid, r, backends, call);
        backends.refresh_epolls();
        result
    }

    fn enter_inner(
        &mut self,
        pid: usize,
        signal_tgid: usize,
        r: &mut UserRegs,
        backends: &mut Backends,
        call: &mut DescriptorCall,
    ) -> NativeDecision {
        // Resource changes cannot invalidate the public allocator or address-space bound.
        if r.orig_rax == 302 && matches!(r.rsi, 7 | 9) && r.rdx != 0 {
            return ready(-1);
        }
        // Signal-driven I/O would let the host kernel signal a process the
        // workload names. Refuse it as the balanced policy does, before any
        // backend answers the request.
        if ginux_core::signal_driven_io(r.orig_rax, r.rsi, r.rdx) {
            return ready(-1);
        }
        let result = match r.orig_rax {
            290 => {
                let flags = r.rsi as u32;
                if flags & !(0o2000000 | 0o4000 | 1) != 0 {
                    Err(-22)
                } else {
                    self.create_event(
                        Event::Counter {
                            value: u64::from(r.rdi as u32),
                            semaphore: flags & 1 != 0,
                        },
                        flags,
                        backends,
                    )
                }
            }
            291 => {
                let flags = r.rdi as u32;
                if flags & !0o2000000 != 0 {
                    Err(-22)
                } else {
                    self.create_event(Event::Epoll, flags, backends)
                }
            }
            233 => self.epoll_control(pid, r, backends),
            232 | 281 => self.epoll_wait(pid, r, backends, call),
            2 | 257 => {
                call.save(r);
                self.open(pid, r, backends, call)
            }
            41 => {
                call.save(r);
                self.socket(pid, r, backends)
            }
            22 | 53 | 293 => {
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
            280 if r.rsi == 0 => {
                call.save(r);
                call.pinned
                    .map(Ok)
                    .unwrap_or_else(|| self.get(r.rdi))
                    .and_then(|d| self.descriptor(pid, signal_tgid, r, d, backends, call))
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
                        _ => self.descriptor(pid, signal_tgid, r, entry, backends, call),
                    },
                }
            }
            0 | 1 | 5 | 8 | 16 | 17 | 18 | 19 | 20 | 42 | 44 | 45 | 48 | 51 | 52 | 54 | 55 | 74
            | 138 | 73 | 75 | 77 | 78 | 91 | 93 | 217 => {
                call.save(r);
                call.pinned
                    .map(Ok)
                    .unwrap_or_else(|| self.get(r.rdi))
                    .and_then(|d| self.descriptor(pid, signal_tgid, r, d, backends, call))
            }
            9 if r.r10 & 0x20 == 0 => {
                call.save(r);
                match self.get(r.r8) {
                    Ok(Descriptor { path_flags, .. }) if path_flags != 0 => Err(-9),
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
            264 | 265 | 316 => {
                call.save(r);
                self.rename_paths(pid, r, backends)
            }
            266 => {
                call.save(r);
                self.path_handle(pid, r.rsi, r.rdx).map(|handle| {
                    r.rsi = handle;
                    backends.claim(pid, r)
                })
            }
            258 | 260 | 262 | 263 | 267 | 268 | 269 | 280 | 332 | 439 | 452 => {
                call.save(r);
                self.path_descriptor(pid, r, backends)
            }
            7 | 271 => self.poll(pid, r, backends, call),
            275 => {
                // Owned storage/devices do not offer splice. Linux uses EINVAL
                // for an unsupported endpoint so callers can retry with read/write.
                // Validate public handles first; never submit them to the host.
                self.get(r.rdi).and_then(|input| {
                    self.get(r.rdx).and_then(|output| {
                        if input.path_flags != 0 || output.path_flags != 0 {
                            Err(-9)
                        } else {
                            Err(-22)
                        }
                    })
                })
            }
            _ => Ok(backends.claim(pid, r)),
        };
        result.unwrap_or_else(ready)
    }

    fn socket(
        &mut self,
        pid: usize,
        r: &UserRegs,
        backends: &mut Backends,
    ) -> Result<NativeDecision, i64> {
        let slot = self.reserve(r.rsi & CLOEXEC != 0)?;
        match backends.claim(pid, r) {
            NativeDecision::Hooked { result, .. } if result >= 0 => {
                backends.refs.retain(result as u32);
                self.entries[slot].as_mut().unwrap().handle = Handle::Owned(result as u32);
                Ok(ready(slot as i64))
            }
            decision => {
                self.entries[slot] = None;
                Ok(decision)
            }
        }
    }

    fn path_descriptor(
        &mut self,
        pid: usize,
        r: &mut UserRegs,
        backends: &mut Backends,
    ) -> Result<NativeDecision, i64> {
        r.rdi = self.path_reference(
            pid,
            r.rdi,
            r.rsi,
            matches!(r.orig_rax, 262 | 267 | 269 | 332 | 439 | 452),
        )?;
        Ok(backends.claim(pid, r))
    }

    fn path_handle(&self, pid: usize, dirfd: u64, address: u64) -> Result<u64, i64> {
        self.path_reference(pid, dirfd, address, false)
    }

    fn path_reference(
        &self,
        pid: usize,
        dirfd: u64,
        address: u64,
        metadata: bool,
    ) -> Result<u64, i64> {
        let path = read_path(pid, address)?;
        if path.as_bytes().first() == Some(&b'/') {
            return Ok((-100i64) as u64);
        }
        if dirfd as i32 == -100 {
            return Ok(dirfd);
        }
        let entry = self.get(dirfd)?;
        // O_PATH forbids direct data access, but a directory reference remains
        // valid as the starting point for relative *at operations.
        if entry.path_flags != 0 && path.is_empty() && !metadata {
            return Err(-9);
        }
        match entry.handle {
            Handle::Owned(handle) if path.is_empty() || (1048576..1048640).contains(&handle) => {
                Ok(handle as u64)
            }
            Handle::Native { fd, .. } if path.is_empty() => Ok(fd as u64),
            Handle::Owned(_) => Err(-20),
            Handle::Native { fd, .. } => Ok(crate::launch_storage::IMAGE_DIR_BASE + fd as u64),
            Handle::Reserved => Err(-9),
        }
    }

    fn rename_paths(
        &self,
        pid: usize,
        r: &mut UserRegs,
        backends: &mut Backends,
    ) -> Result<NativeDecision, i64> {
        r.rdi = self.path_handle(pid, r.rdi, r.rsi)?;
        r.rdx = self.path_handle(pid, r.rdx, r.r10)?;
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
        if flags & PATH_ONLY != 0
            && flags & !(PATH_ONLY | CLOEXEC | 0o100000 | 0o400 | 0o200000) != 0
        {
            return Err(-95);
        }
        // Reserve before any create/truncate or native open can occur.
        let slot = self.reserve(flags & CLOEXEC != 0)?;
        if flags & PATH_ONLY != 0 {
            self.entries[slot].as_mut().unwrap().path_flags =
                (flags & (PATH_ONLY | 0o200000)) as u32;
        }
        if r.orig_rax == 2 {
            r.rsi &= !CLOEXEC;
        } else {
            r.rdx &= !CLOEXEC;
        }
        let address = if r.orig_rax == 2 { r.rdi } else { r.rsi };
        let stack_view =
            read_path(pid, address).is_ok_and(|path| path.as_bytes() == crate::stack_view::PATH);
        let decision = if stack_view {
            backends
                .filesystem
                .open_stack_snapshot(pid, flags)
                .map(ready)
        } else if let Some(decision) = self.open_descriptor_path(pid, r, backends) {
            decision
        } else if r.orig_rax == 257 {
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

    fn open_descriptor_path(
        &self,
        pid: usize,
        r: &UserRegs,
        backends: &mut Backends,
    ) -> Option<Result<NativeDecision, i64>> {
        let address = if r.orig_rax == 2 { r.rdi } else { r.rsi };
        let path = match read_path(pid, address) {
            Ok(path) => path,
            Err(error) => return Some(Err(error)),
        };
        let suffix = path.as_bytes().strip_prefix(b"/dev/fd/")?;
        Some((|| {
            let end = suffix
                .iter()
                .position(|b| *b == b'/')
                .unwrap_or(suffix.len());
            if end == 0 {
                return Err(-2);
            }
            let mut fd = 0u64;
            for digit in &suffix[..end] {
                if !digit.is_ascii_digit() {
                    return Err(-2);
                }
                fd = fd
                    .checked_mul(10)
                    .and_then(|n| n.checked_add((digit - b'0') as u64))
                    .ok_or(-2)?;
            }
            // Path digits are names, not an i32 syscall argument. Never let a
            // larger number wrap onto a different public descriptor.
            if fd >= LIMIT as u64 {
                return Err(-2);
            }
            let entry = self.get(fd).map_err(|_| -2)?;
            if entry.path_flags != 0 {
                return Err(-9);
            }
            let handle = match entry.handle {
                Handle::Owned(handle) if (1048576..1048640).contains(&handle) => handle,
                _ => return Err(-95),
            };
            let flags = if r.orig_rax == 2 { r.rsi } else { r.rdx };
            let tail = &suffix[end..];
            let handle = backends
                .filesystem
                .open_descriptor(pid, handle, tail, flags)?;
            Ok(ready(handle))
        })())
    }

    fn pipe(
        &mut self,
        pid: usize,
        r: &UserRegs,
        backends: &mut Backends,
    ) -> Result<NativeDecision, i64> {
        let packet = r.orig_rax == 53;
        if packet && (r.rdi != 1 || r.rsi & !(CLOEXEC | 0o4000) != 5 || r.rdx != 0) {
            return Err(-95);
        }
        let flags = if packet {
            r.rsi & !5
        } else if r.orig_rax == 293 {
            r.rsi
        } else {
            0
        };
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
        let allocated = if packet {
            backends.channels.allocate_packet_pair(flags & !CLOEXEC)
        } else {
            backends.channels.allocate(flags & !CLOEXEC)
        };
        let handles = match allocated {
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
        let copied = copy_memory(pid, if packet { r.r10 } else { r.rdi }, &mut bytes, true);
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
        &mut self,
        pid: usize,
        signal_tgid: usize,
        r: &mut UserRegs,
        entry: Descriptor,
        backends: &mut Backends,
        call: &mut DescriptorCall,
    ) -> Result<NativeDecision, i64> {
        if entry.path_flags != 0 {
            if r.orig_rax == 72 && r.rsi == 3 {
                return Ok(ready(entry.path_flags as i64));
            }
            if r.orig_rax != 5 {
                return Err(-9);
            }
        }
        if r.orig_rax == 138 {
            return Ok(ready(backends.filesystem.statfs(
                pid,
                r.rsi,
                matches!(entry.handle, Handle::Owned(_)),
            )?));
        }
        let public_fd = r.rdi as u32;
        let network = matches!(entry.handle, Handle::Owned(h) if crate::network_hooks::LaunchNetwork::owns(h));
        let packet = matches!(entry.handle, Handle::Owned(h) if backends.channels.is_socket(h));
        if matches!(r.orig_rax, 42 | 44 | 45 | 48 | 51 | 52 | 54 | 55)
            && !network
            && !(packet && matches!(r.orig_rax, 44 | 45))
        {
            return Err(-88);
        }
        if network
            && call
                .poll_deadline
                .is_some_and(|end| monotonic_nanoseconds().is_ok_and(|now| now >= end))
        {
            return Ok(ready(-11));
        }
        match entry.handle {
            Handle::Native { fd, console } => {
                if r.orig_rax == 93 {
                    return Err(-1);
                }
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
        let decision = match backends.claim_with_write(pid, signal_tgid, r, &mut call.channel_write)
        {
            NativeDecision::Hooked { result: -11, .. }
                if (r.orig_rax == 72 && r.rsi == 7) || (r.orig_rax == 73 && r.rsi & 4 == 0) =>
            {
                NativeDecision::Park {
                    fd: public_fd,
                    progressed: false,
                }
            }
            decision => decision,
        };
        Ok(match decision {
            NativeDecision::Park { progressed, .. } => {
                if call.pinned.is_none() {
                    if let Handle::Owned(handle) = entry.handle {
                        backends.refs.retain(handle);
                    }
                    call.pinned = Some(entry);
                }
                if network {
                    if !call.poll_tick {
                        let timeout = backends.devices.network.timeout(r.rdi as u32, r.orig_rax);
                        if timeout != 0 {
                            call.poll_deadline =
                                Some(monotonic_nanoseconds()?.checked_add(timeout).ok_or(-22)?);
                        }
                    }
                    call.poll_tick = true;
                }
                NativeDecision::Park {
                    fd: public_fd,
                    progressed,
                }
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
            backends.filesystem.close_locks(handle);
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
        if self.entries[target].is_some_and(|entry| entry.handle == Handle::Reserved) {
            return Err(-16);
        }
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
    fn create_event(
        &mut self,
        event: Event,
        flags: u32,
        backends: &mut Backends,
    ) -> Result<NativeDecision, i64> {
        let slot = self.reserve(flags & CLOEXEC as u32 != 0)?;
        match backends.channels.allocate_event(event, flags) {
            Ok(handle) => {
                backends.refs.retain(handle);
                self.entries[slot].as_mut().unwrap().handle = Handle::Owned(handle);
                Ok(ready(slot as i64))
            }
            Err(error) => {
                self.entries[slot] = None;
                Err(error)
            }
        }
    }

    fn epoll_control(
        &mut self,
        pid: usize,
        r: &UserRegs,
        backends: &mut Backends,
    ) -> Result<NativeDecision, i64> {
        let handle = match self.get(r.rdi)?.handle {
            Handle::Owned(handle)
                if matches!(backends.channels.event(handle), Some(Event::Epoll)) =>
            {
                handle
            }
            _ => return Err(-22),
        };
        let operation = r.rsi as i32;
        if !(1..=3).contains(&operation) {
            return Err(-22);
        }
        let target = match self.get(r.rdx)?.handle {
            Handle::Owned(target)
                if crate::network_hooks::LaunchNetwork::owns(target)
                    || backends.channels.readiness(target).is_some()
                        && !matches!(backends.channels.event(target), Some(Event::Epoll)) =>
            {
                target
            }
            _ => return Err(-1),
        };
        let (events, data) = if operation == 2 {
            (0, 0)
        } else {
            let mut event = [0; 12];
            if copy_memory(pid, r.r10, &mut event, false)? != 12 {
                return Err(-14);
            }
            let events = u32::from_ne_bytes(event[..4].try_into().unwrap());
            if events & !ALLOWED_EVENTS != 0 {
                return Err(-22);
            }
            (events, u64::from_ne_bytes(event[4..].try_into().unwrap()))
        };
        let key = backends.refs.key(target);
        let Some(epoll) = backends.channels.epoll_mut(handle) else {
            return Err(-9);
        };
        epoll.control(operation, key, r.rdx as u32, events, data)?;
        Ok(ready(0))
    }

    fn epoll_wait(
        &mut self,
        pid: usize,
        r: &UserRegs,
        backends: &mut Backends,
        call: &mut DescriptorCall,
    ) -> Result<NativeDecision, i64> {
        let descriptor = call.pinned.map(Ok).unwrap_or_else(|| self.get(r.rdi))?;
        let handle = match descriptor.handle {
            Handle::Owned(handle)
                if matches!(backends.channels.event(handle), Some(Event::Epoll)) =>
            {
                handle
            }
            _ => return Err(-22),
        };
        if r.orig_rax == 281 && r.r8 != 0 && !call.poll_wait {
            // A no-op mask needs no temporary signal-mask implementation.
            // Snapshot it once, then retain admission across parked retries.
            if r.r9 != 8 {
                return Err(-22);
            }
            let mut bytes = [0; 8];
            if copy_memory(pid, r.r8, &mut bytes, false)? != 8 {
                return Err(-14);
            }
            let requested = u64::from_ne_bytes(bytes);
            let mut current = 0u64;
            if crate::supervisor::ptrace(0x420a, pid, 8, &mut current as *mut _ as usize) < 0 {
                return Err(-95);
            }
            let unmaskable = (1u64 << (9 - 1)) | (1u64 << (19 - 1));
            if requested & !unmaskable != current & !unmaskable {
                return Err(-95);
            }
        }
        let maximum = r.rdx as i32;
        if maximum <= 0 {
            return Err(-22);
        }
        // maxevents is output capacity, not an input array. At most WATCHES
        // bounded events can be returned even when the caller has more room.
        let maximum = (maximum as usize).min(WATCHES);
        let timeout = r.r10 as i32;
        if timeout > 300000 {
            return Err(-22);
        }
        let now = monotonic_nanoseconds()?;
        if !call.poll_wait && timeout > 0 {
            call.poll_deadline = Some(now.checked_add(timeout as u64 * 1_000_000).ok_or(-22)?);
        }
        let Some(epoll) = backends.channels.epoll(handle) else {
            return Err(-9);
        };
        let mut bytes = [0; WATCHES * 12];
        let mut selected = [0; WATCHES];
        let count = epoll.pending(maximum, &mut bytes, &mut selected);
        let network = epoll
            .watches
            .iter()
            .flatten()
            .any(|w| crate::network_hooks::LaunchNetwork::owns(w.key.handle));
        if count != 0 || timeout == 0 || call.poll_deadline.is_some_and(|end| now >= end) {
            if count != 0 {
                if copy_memory(pid, r.rsi, &mut bytes[..count * 12], true)? != (count * 12) as i64 {
                    return Err(-14);
                }
                let Some(epoll) = backends.channels.epoll_mut(handle) else {
                    return Err(-9);
                };
                epoll.acknowledge(&selected[..count]);
            }
            return Ok(ready(count as i64));
        }
        if call.pinned.is_none() {
            backends.refs.retain(handle);
            call.pinned = Some(descriptor);
        }
        call.poll_wait = true;
        call.poll_tick = network || call.poll_deadline.is_some();
        Ok(NativeDecision::ParkPoll)
    }

    fn poll(
        &mut self,
        pid: usize,
        r: &UserRegs,
        backends: &mut Backends,
        call: &mut DescriptorCall,
    ) -> Result<NativeDecision, i64> {
        // Snapshot ppoll's relative timeout once, like the pollfd layout. A
        // parked task must retain its original deadline across scheduler ticks.
        let timeout = if call.poll_wait {
            -1
        } else if r.orig_rax == 271 {
            if r.r10 != 0 {
                return Err(-95);
            }
            if r.rdx == 0 {
                -1
            } else {
                let mut time = [0u8; 16];
                if copy_memory(pid, r.rdx, &mut time, false)? != 16 {
                    return Err(-14);
                }
                let sec = i64::from_ne_bytes(time[..8].try_into().unwrap());
                let ns = i64::from_ne_bytes(time[8..].try_into().unwrap());
                if sec < 0 || !(0..1_000_000_000).contains(&ns) || sec > 300 {
                    return Err(-22);
                }
                (sec * 1000 + (ns + 999999) / 1000000) as i32
            }
        } else {
            r.rdx as i32
        };
        if r.rsi > 16 || timeout > 300000 {
            return Err(-1);
        }
        let count = r.rsi as usize;
        let mut bytes = [0u8; 128];
        let length = count * 8;
        if call.poll_wait {
            bytes = call.poll_input;
        } else {
            if copy_memory(pid, r.rdi, &mut bytes[..length], false)? != length as i64 {
                return Err(-14);
            }
            call.poll_input = bytes;
        }
        // Console OFDs are inherited unchanged from this supervisor. Only
        // explicitly tracked console handles can query those host descriptors.
        // Image descriptors are not supervisor handles and remain unsupported.
        let mut consoles = [PollFd {
            fd: -1,
            events: 0,
            revents: 0,
        }; 16];
        let mut ready_count = 0;
        let mut network_wait = false;
        for i in 0..count {
            let entry = &mut bytes[i * 8..i * 8 + 8];
            let fd = i32::from_ne_bytes(entry[..4].try_into().unwrap());
            let events = u16::from_ne_bytes(entry[4..6].try_into().unwrap());
            entry[6..8].fill(0);
            if fd < 0 {
                continue;
            }
            let revents = match self.get(fd as u64) {
                Ok(Descriptor { path_flags, .. }) if path_flags != 0 => 32,
                Ok(Descriptor {
                    handle: Handle::Native { fd, console: true },
                    ..
                }) => {
                    assert!(fd < 3);
                    consoles[i] = PollFd {
                        fd: fd as i32,
                        events,
                        revents: 0,
                    };
                    0
                }
                Ok(Descriptor {
                    handle: Handle::Native { .. },
                    ..
                }) => return Err(-95),
                Ok(Descriptor {
                    handle: Handle::Owned(handle),
                    ..
                }) => {
                    // Assigned regular memory files/directories and null are
                    // immediately ready. Pipes supply their own live state.
                    network_wait |= crate::network_hooks::LaunchNetwork::owns(handle);
                    let available = backends.readiness(handle).ok_or(-95)?;
                    available & (events | 8 | 16)
                }
                _ => 32, // POLLNVAL, even when events is zero.
            };
            entry[6..8].copy_from_slice(&revents.to_ne_bytes());
        }
        let result = unsafe { syscall3(7, consoles.as_mut_ptr() as usize, count, 0) };
        if result < 0 {
            return Err(result as i64);
        }
        for i in 0..count {
            let output = &mut bytes[i * 8 + 6..i * 8 + 8];
            let revents = u16::from_ne_bytes(output.try_into().unwrap()) | consoles[i].revents;
            output.copy_from_slice(&revents.to_ne_bytes());
            ready_count += i64::from(revents != 0);
        }
        let now = monotonic_nanoseconds()?;
        if !call.poll_wait && timeout > 0 {
            call.poll_deadline = Some(now.checked_add(timeout as u64 * 1_000_000).ok_or(-22)?);
        }
        if ready_count != 0 || timeout == 0 || call.poll_deadline.is_some_and(|end| now >= end) {
            for i in 0..count {
                let address = r.rdi.checked_add((i * 8 + 6) as u64).ok_or(-14)?;
                if copy_memory(pid, address, &mut bytes[i * 8 + 6..i * 8 + 8], true)? != 2 {
                    return Err(-14);
                }
            }
            return Ok(ready(ready_count));
        }
        call.poll_wait = true;
        // Infinite owned-object waits need no timer: object progress/death
        // already wakes them. External console IO needs periodic observation.
        call.poll_tick = network_wait
            || call.poll_deadline.is_some()
            || consoles[..count].iter().any(|fd| fd.fd >= 0);
        Ok(NativeDecision::ParkPoll)
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct PollFd {
    fd: i32,
    events: u16,
    revents: u16,
}

pub fn monotonic_nanoseconds() -> Result<u64, i64> {
    let mut time = [0u64; 2];
    if unsafe { syscall2(228, 1, time.as_mut_ptr() as usize) } < 0 {
        return Err(-5);
    }
    time[0]
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(time[1]))
        .ok_or(-5)
}

fn ready(result: i64) -> NativeDecision {
    NativeDecision::Hooked {
        lane: Lane::Filesystem,
        result,
    }
}
