//! Native channel-lane dispatch hooks.
//!
//! Owner: G-files/channel adapter lane (serialized with G-files changes).
//! Balanced bootstrap polling validates the tracee's descriptor array before
//! a bounded console-readiness query. Configured anonymous pipes below use
//! supervisor-owned memory and virtual handles, never native tracee pipes.

use crate::supervisor::{ptrace, PTRACE_PEEKDATA};

/// Only the three assigned bootstrap descriptors (and ignored negative slots)
/// may appear in a bounded poll. The kernel supplies readiness and
/// POLLNVAL for closed descriptors; no descriptor is created or transferred.
pub fn bootstrap_poll_allowed(pid: usize, address: u64, count: u64) -> bool {
    if count > ginux_core::MAX_BOOTSTRAP_POLL_FDS {
        return false;
    }
    for index in 0..count {
        let Some(address) = address.checked_add(index * 8) else {
            return false;
        };
        let mut entry = 0u64;
        if ptrace(
            PTRACE_PEEKDATA,
            pid,
            address as usize,
            &mut entry as *mut _ as usize,
        ) < 0
        {
            return false;
        }
        let descriptor = entry as u32 as i32;
        if descriptor > 2 {
            return false;
        }
    }
    true
}

/// Lane membership by syscall number. Reserved for G14.
pub fn claims(syscall: u64) -> bool {
    let _ = syscall;
    false
}

/// Emulated result when this lane handles the entry. `None` falls through to
/// the shared balanced-contract decision. Reserved for G14.
pub fn claim(syscall: u64, rdi: u64, rsi: u64, rdx: u64) -> Option<i64> {
    let _ = (syscall, rdi, rsi, rdx);
    None
}

use crate::supervisor::{syscall2, UserRegs, SYS_KILL};
use crate::tracee_io::{copy_memory, read_path, write_stat, Stat};

pub const PIPE_FD_BASE: u32 = 0x2000_0000;
const FDS: usize = 2 * PIPES;
const PIPES: usize = 8;
const CAPACITY: usize = 65536;
const IO_SIZE: usize = 4096;
const CLOEXEC: u32 = 0o2000000;
const NONBLOCK: u32 = 0o4000;
const APPEND: u32 = 0o2000;

#[derive(Clone, Copy)]
struct Pipe {
    live: bool,
    data: [u8; CAPACITY],
    head: usize,
    len: usize,
    readers: u16,
    writers: u16,
    read_flags: u32,
    write_flags: u32,
}

impl Pipe {
    const fn empty() -> Self {
        Self {
            live: false,
            data: [0; CAPACITY],
            head: 0,
            len: 0,
            readers: 0,
            writers: 0,
            read_flags: 0,
            write_flags: 1,
        }
    }
}

#[derive(Clone, Copy)]
struct PipeFd {
    pipe: usize,
    write: bool,
}

pub enum ChannelResult {
    Ready(i64),
    /// No bytes were consumed or published. The task must remain stopped until
    /// peer progress, an interrupt, or termination; this is not guest EAGAIN.
    Blocked {
        fd: u32,
    },
}

pub struct LaunchChannels {
    pipes: [Pipe; PIPES],
    descriptors: [Option<PipeFd>; FDS],
}

impl LaunchChannels {
    pub const fn new() -> Self {
        Self {
            pipes: [Pipe::empty(); PIPES],
            descriptors: [None; FDS],
        }
    }

    pub fn claim(&mut self, pid: usize, r: &UserRegs) -> Option<ChannelResult> {
        let fd = r.rdi as u32;
        if !(PIPE_FD_BASE..0x4000_0000).contains(&fd) {
            return None;
        }
        let slot = (fd - PIPE_FD_BASE) as usize;
        if matches!(r.orig_rax, 262 | 332) {
            match read_path(pid, r.rsi) {
                Ok(path) if !path.is_empty() => return None, // Absolute paths ignore dirfd.
                Err(error) => return Some(ChannelResult::Ready(error)),
                _ => {}
            }
        } else if !matches!(
            r.orig_rax,
            0 | 1 | 3 | 5 | 8 | 16 | 17 | 18 | 19 | 20 | 32 | 33 | 72 | 74 | 75 | 77 | 91 | 292
        ) {
            return None;
        }
        let entry = match self.entry(slot) {
            Ok(entry) => entry,
            Err(error) => return Some(ChannelResult::Ready(error)),
        };
        if matches!(r.orig_rax, 0 | 1) {
            return Some(match self.io(pid, slot, entry, r) {
                Ok(result) => result,
                Err(error) => ChannelResult::Ready(error),
            });
        }
        let result = match r.orig_rax {
            3 => {
                self.close(slot);
                Ok(0)
            }
            5 => Self::stat(pid, r.rsi, false, entry.pipe),
            8 | 17 | 18 => Err(-29),
            16 if r.rsi == 0x5421 => {
                // FIONBIO changes the shared open-file status, not this
                // public descriptor's CLOEXEC bit. Copy the complete int
                // before changing anything; a partial read is EFAULT.
                let mut value = [0u8; 4];
                match copy_memory(pid, r.rdx, &mut value, false) {
                    Ok(4) => {
                        let flags = self.flags(entry);
                        self.set_flags(
                            entry,
                            if i32::from_ne_bytes(value) == 0 {
                                flags & !NONBLOCK
                            } else {
                                flags | NONBLOCK
                            },
                        );
                        Ok(0)
                    }
                    _ => Err(-14),
                }
            }
            16 => Err(-25),
            72 => match r.rsi {
                3 => Ok(self.flags(entry) as i64),
                4 if r.rdx & !((NONBLOCK | APPEND | 3) as u64) == 0 => {
                    let flags = (r.rdx as u32 & (NONBLOCK | APPEND)) | u32::from(entry.write);
                    self.set_flags(entry, flags);
                    Ok(0)
                }
                1032 => Ok(CAPACITY as i64),
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
                        entry.pipe,
                    )
                }
            }
            _ => Err(-95),
        };
        Some(ChannelResult::Ready(result.unwrap_or_else(|e| e)))
    }

    pub fn allocate(&mut self, flags: u64) -> Result<[u32; 2], i64> {
        if flags & !((CLOEXEC | NONBLOCK) as u64) != 0 {
            return Err(-22);
        }
        let pipe = self.pipes.iter().position(|p| !p.live).ok_or(-24)?;
        let first = self
            .descriptors
            .iter()
            .position(|fd| fd.is_none())
            .ok_or(-24)?;
        let second = self
            .descriptors
            .iter()
            .enumerate()
            .find_map(|(i, fd)| (i != first && fd.is_none()).then_some(i))
            .ok_or(-24)?;
        let p = &mut self.pipes[pipe];
        p.live = true;
        p.head = 0;
        p.len = 0;
        p.readers = 1;
        p.writers = 1;
        p.read_flags = flags as u32 & NONBLOCK;
        p.write_flags = 1 | p.read_flags;
        self.descriptors[first] = Some(PipeFd { pipe, write: false });
        self.descriptors[second] = Some(PipeFd { pipe, write: true });
        Ok([PIPE_FD_BASE + first as u32, PIPE_FD_BASE + second as u32])
    }

    pub fn release(&mut self, handle: u32) {
        self.close((handle - PIPE_FD_BASE) as usize);
    }

    /// Current readiness of a live owned endpoint. ERR/HUP do not depend on
    /// the requested event mask; buffered bytes and HUP may coexist.
    pub fn readiness(&self, handle: u32) -> Option<u16> {
        let slot = handle.checked_sub(PIPE_FD_BASE)? as usize;
        let entry = self.entry(slot).ok()?;
        let pipe = &self.pipes[entry.pipe];
        Some(if entry.write {
            (if pipe.len < CAPACITY { 0x104 } else { 0 }) | (if pipe.readers == 0 { 8 } else { 0 })
        } else {
            (if pipe.len != 0 { 0x41 } else { 0 }) | (if pipe.writers == 0 { 16 } else { 0 })
        })
    }

    fn entry(&self, slot: usize) -> Result<PipeFd, i64> {
        self.descriptors.get(slot).copied().flatten().ok_or(-9)
    }

    fn flags(&self, entry: PipeFd) -> u32 {
        if entry.write {
            self.pipes[entry.pipe].write_flags
        } else {
            self.pipes[entry.pipe].read_flags
        }
    }

    fn set_flags(&mut self, entry: PipeFd, flags: u32) {
        if entry.write {
            self.pipes[entry.pipe].write_flags = flags;
        } else {
            self.pipes[entry.pipe].read_flags = flags;
        }
    }

    fn close(&mut self, slot: usize) {
        if let Some(entry) = self.descriptors[slot].take() {
            let p = &mut self.pipes[entry.pipe];
            if entry.write {
                p.writers -= 1;
            } else {
                p.readers -= 1;
            }
            if p.readers == 0 && p.writers == 0 {
                p.live = false;
                p.len = 0;
                p.head = 0;
            }
        }
    }

    fn io(
        &mut self,
        pid: usize,
        slot: usize,
        entry: PipeFd,
        r: &UserRegs,
    ) -> Result<ChannelResult, i64> {
        let writing = r.orig_rax == 1;
        if writing != entry.write {
            return Err(-9);
        }
        if r.rdx == 0 {
            return Ok(ChannelResult::Ready(0));
        }
        let nonblock = self.flags(entry) & NONBLOCK != 0;
        let fd = PIPE_FD_BASE + slot as u32;
        let mut buffer = [0u8; IO_SIZE];
        let p = &mut self.pipes[entry.pipe];
        if writing {
            if p.readers == 0 {
                // Deliver the ordinary SIGPIPE to this supervised caller, not
                // to the supervisor. Its disposition determines the outcome.
                let _ = unsafe { syscall2(SYS_KILL, pid, 13) };
                return Err(-32);
            }
            let available = CAPACITY - p.len;
            let atomic = r.rdx <= IO_SIZE as u64;
            if available == 0 || (atomic && available < r.rdx as usize) {
                return Ok(if nonblock {
                    ChannelResult::Ready(-11)
                } else {
                    ChannelResult::Blocked { fd }
                });
            }
            let count = r.rdx.min(IO_SIZE as u64).min(available as u64) as usize;
            let copied = copy_memory(pid, r.rsi, &mut buffer[..count], false)? as usize;
            if atomic && copied != count {
                return Err(-14);
            }
            for byte in &buffer[..copied] {
                p.data[(p.head + p.len) % CAPACITY] = *byte;
                p.len += 1;
            }
            Ok(ChannelResult::Ready(copied as i64))
        } else {
            if p.len == 0 {
                return Ok(if p.writers == 0 {
                    ChannelResult::Ready(0)
                } else if nonblock {
                    ChannelResult::Ready(-11)
                } else {
                    ChannelResult::Blocked { fd }
                });
            }
            let count = r.rdx.min(IO_SIZE as u64).min(p.len as u64) as usize;
            for (i, byte) in buffer[..count].iter_mut().enumerate() {
                *byte = p.data[(p.head + i) % CAPACITY];
            }
            let copied = copy_memory(pid, r.rsi, &mut buffer[..count], true)? as usize;
            p.head = (p.head + copied) % CAPACITY;
            p.len -= copied;
            Ok(ChannelResult::Ready(copied as i64))
        }
    }

    fn stat(pid: usize, address: u64, statx: bool, pipe: usize) -> Result<i64, i64> {
        write_stat(
            pid,
            address,
            Stat {
                inode: 0x2_0000_0000 + pipe as u64,
                mode: 0o10600,
                size: 0,
                device_major: 0,
                device_minor: 0,
            },
            statx,
        )
    }
}
