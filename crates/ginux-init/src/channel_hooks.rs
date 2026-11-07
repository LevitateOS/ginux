//! Native channel-lane dispatch hooks.
//!
//! Owner: G-files/channel adapter lane (serialized with G-files changes).
//! Next task: G14 supplies the generic opaque transport the §4 frames ride
//! on. Until then every hook declines and the supervisor keeps its existing
//! behavior byte-identical.

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
pub const FDS: usize = 2 * PIPES;
const PIPES: usize = 16;
const CAPACITY: usize = 65536;
const IO_SIZE: usize = 4096;
const CLOEXEC: u32 = 0o2000000;
const NONBLOCK: u32 = 0o4000;
const APPEND: u32 = 0o2000;

#[derive(Clone, Copy)]
struct Pipe {
    live: bool,
    packet: bool,
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
            packet: false,
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
    peer: Option<usize>,
}

/// Progress belongs to the task's current syscall, not its shared endpoint.
pub struct WriteProgress {
    vectors: Option<crate::tracee_io::IoVectors>,
    written: usize,
}
impl WriteProgress {
    pub const fn new() -> Self {
        Self {
            vectors: None,
            written: 0,
        }
    }
}

pub enum ChannelResult {
    Ready(i64),
    /// Retain the task's syscall until peer progress or termination. Partial
    /// blocking writes wake readers without returning a short guest result.
    Blocked {
        fd: u32,
        progressed: bool,
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

    pub fn claim(
        &mut self,
        pid: usize,
        r: &UserRegs,
        progress: &mut WriteProgress,
    ) -> Option<ChannelResult> {
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
            0 | 1
                | 3
                | 5
                | 8
                | 16
                | 17
                | 18
                | 19
                | 20
                | 32
                | 33
                | 44
                | 45
                | 72
                | 74
                | 75
                | 77
                | 91
                | 292
        ) {
            return None;
        }
        let entry = match self.entry(slot) {
            Ok(entry) => entry,
            Err(error) => return Some(ChannelResult::Ready(error)),
        };
        if matches!(r.orig_rax, 0 | 1 | 19 | 20 | 44 | 45) {
            if matches!(r.orig_rax, 44 | 45)
                && (entry.peer.is_none() || r.r10 & !(0x40 | 0x4000) != 0 || r.r8 != 0 || r.r9 != 0)
            {
                return Some(ChannelResult::Ready(-95));
            }
            return Some(match self.io(pid, slot, entry, r, progress) {
                Ok(result) => result,
                Err(error) => ChannelResult::Ready(error),
            });
        }
        let result = match r.orig_rax {
            3 => {
                self.close(slot);
                Ok(0)
            }
            5 => Self::stat(pid, r.rsi, false, entry.pipe, entry.peer.is_some()),
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
                    let flags = (r.rdx as u32 & (NONBLOCK | APPEND))
                        | if entry.peer.is_some() {
                            2
                        } else {
                            u32::from(entry.write)
                        };
                    self.set_flags(entry, flags);
                    Ok(0)
                }
                1032 => Ok(CAPACITY as i64),
                _ => Err(-95),
            },
            262 | 332 => {
                let flags = if r.orig_rax == 262 { r.r10 } else { r.rdx };
                let valid = if r.orig_rax == 262 {
                    flags & !0x1900 == 0
                } else {
                    crate::fs_hooks::valid_statx(flags, r.r10)
                };
                if flags & 0x1000 == 0 || !valid {
                    Err(-22)
                } else {
                    Self::stat(
                        pid,
                        if r.orig_rax == 262 { r.rdx } else { r.r8 },
                        r.orig_rax == 332,
                        entry.pipe,
                        entry.peer.is_some(),
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
        p.packet = false;
        p.head = 0;
        p.len = 0;
        p.readers = 1;
        p.writers = 1;
        p.read_flags = flags as u32 & NONBLOCK;
        p.write_flags = 1 | p.read_flags;
        self.descriptors[first] = Some(PipeFd {
            pipe,
            write: false,
            peer: None,
        });
        self.descriptors[second] = Some(PipeFd {
            pipe,
            write: true,
            peer: None,
        });
        Ok([PIPE_FD_BASE + first as u32, PIPE_FD_BASE + second as u32])
    }

    /// Connected local sequenced-packet endpoints: no names, networking,
    /// descriptor transfer, or native workload sockets are involved.
    pub fn allocate_packet_pair(&mut self, flags: u64) -> Result<[u32; 2], i64> {
        let first = self.allocate(flags)?;
        let second = match self.allocate(flags) {
            Ok(pair) => pair,
            Err(error) => {
                self.release(first[0]);
                self.release(first[1]);
                return Err(error);
            }
        };
        let a = (first[0] - PIPE_FD_BASE) as usize;
        let b = (second[0] - PIPE_FD_BASE) as usize;
        let pa = self.descriptors[a].unwrap().pipe;
        let pb = self.descriptors[b].unwrap().pipe;
        self.descriptors[a].as_mut().unwrap().peer = Some(pb);
        self.descriptors[b].as_mut().unwrap().peer = Some(pa);
        // Transfer writer ownership into the opposite duplex endpoint.
        self.descriptors[(first[1] - PIPE_FD_BASE) as usize] = None;
        self.descriptors[(second[1] - PIPE_FD_BASE) as usize] = None;
        for index in [pa, pb] {
            self.pipes[index].packet = true;
            self.pipes[index].read_flags |= 2;
        }
        Ok([first[0], second[0]])
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
        if let Some(peer) = entry.peer {
            let output = &self.pipes[peer];
            return Some(
                (if pipe.len != 0 { 0x41 } else { 0 })
                    | (if CAPACITY - output.len >= 2 { 0x104 } else { 0 })
                    | (if pipe.writers == 0 { 16 } else { 0 })
                    | (if output.readers == 0 { 8 } else { 0 }),
            );
        }
        Some(if entry.write {
            (if pipe.len < CAPACITY { 0x104 } else { 0 }) | (if pipe.readers == 0 { 8 } else { 0 })
        } else {
            (if pipe.len != 0 { 0x41 } else { 0 }) | (if pipe.writers == 0 { 16 } else { 0 })
        })
    }

    pub fn is_socket(&self, handle: u32) -> bool {
        handle
            .checked_sub(PIPE_FD_BASE)
            .and_then(|slot| self.descriptors.get(slot as usize))
            .and_then(|entry| *entry)
            .is_some_and(|entry| entry.peer.is_some())
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
            self.close_direction(entry.pipe, entry.write);
            if let Some(peer) = entry.peer {
                self.close_direction(peer, true);
            }
        }
    }

    fn close_direction(&mut self, index: usize, write: bool) {
        let pipe = &mut self.pipes[index];
        if write {
            pipe.writers -= 1;
        } else {
            pipe.readers -= 1;
        }
        if pipe.readers == 0 && pipe.writers == 0 {
            pipe.live = false;
            pipe.len = 0;
            pipe.head = 0;
        }
    }

    fn io(
        &mut self,
        pid: usize,
        slot: usize,
        entry: PipeFd,
        r: &UserRegs,
        progress: &mut WriteProgress,
    ) -> Result<ChannelResult, i64> {
        let writing = matches!(r.orig_rax, 1 | 20 | 44);
        // The current blocking write retains its admitted mode and vector
        // layout while another task can change the shared endpoint flags.
        let nonblock = progress.vectors.is_none()
            && (self.flags(entry) & NONBLOCK != 0
                || matches!(r.orig_rax, 44 | 45) && r.r10 & 0x40 != 0);
        let complete_write = writing && !nonblock && entry.peer.is_none();
        let vectors = if let Some(vectors) = progress.vectors.take() {
            vectors
        } else if matches!(r.orig_rax, 19 | 20) {
            crate::tracee_io::IoVectors::read(pid, r.rsi, r.rdx)?
        } else {
            crate::tracee_io::IoVectors::single(r.rsi, r.rdx)
        };
        let vectors = if complete_write {
            progress.vectors.get_or_insert(vectors)
        } else {
            &vectors
        };
        let requested = vectors.length;
        if entry.peer.is_none() && writing != entry.write {
            return Err(-9);
        }
        if requested == 0 && entry.peer.is_none() {
            return Ok(ChannelResult::Ready(0));
        }
        let fd = PIPE_FD_BASE + slot as u32;
        let mut buffer = [0u8; IO_SIZE];
        let pipe = if writing {
            entry.peer.unwrap_or(entry.pipe)
        } else {
            entry.pipe
        };
        let p = &mut self.pipes[pipe];
        if writing {
            if p.readers == 0 {
                // Deliver the ordinary SIGPIPE to this supervised caller, not
                // to the supervisor. Its disposition determines the outcome.
                if r.orig_rax != 44 || r.r10 & 0x4000 == 0 {
                    let _ = unsafe { syscall2(SYS_KILL, pid, 13) };
                }
                return if progress.written != 0 {
                    Ok(ChannelResult::Ready(progress.written as i64))
                } else {
                    Err(-32)
                };
            }
            if p.packet && requested > IO_SIZE {
                return Err(-90);
            }
            let overhead = if p.packet { 2 } else { 0 };
            let available = (CAPACITY - p.len).saturating_sub(overhead);
            let atomic = requested <= IO_SIZE;
            if CAPACITY - p.len < overhead
                || (available == 0 && requested != 0)
                || (atomic && available < requested)
            {
                return Ok(if nonblock {
                    ChannelResult::Ready(-11)
                } else {
                    ChannelResult::Blocked {
                        fd,
                        progressed: false,
                    }
                });
            }
            let mut written = if complete_write { progress.written } else { 0 };
            let before = written;
            loop {
                let available = (CAPACITY - p.len).saturating_sub(overhead);
                let count = (requested - written).min(IO_SIZE).min(available);
                if count == 0 && written != requested {
                    progress.written = written;
                    return Ok(ChannelResult::Blocked {
                        fd,
                        progressed: written != before,
                    });
                }
                let copied = match vectors.copy_from(pid, &mut buffer[..count], false, written) {
                    Ok(n) => n,
                    Err(_) if written != 0 => return Ok(ChannelResult::Ready(written as i64)),
                    Err(error) => return Err(error),
                };
                if atomic && copied != count {
                    return Err(-14);
                }
                if p.packet {
                    for byte in (copied as u16).to_le_bytes() {
                        p.data[(p.head + p.len) % CAPACITY] = byte;
                        p.len += 1;
                    }
                }
                for byte in &buffer[..copied] {
                    p.data[(p.head + p.len) % CAPACITY] = *byte;
                    p.len += 1;
                }
                written += copied;
                if !complete_write || written == requested || copied != count {
                    return Ok(ChannelResult::Ready(written as i64));
                }
            }
        } else {
            if p.len == 0 {
                return Ok(if p.writers == 0 {
                    ChannelResult::Ready(0)
                } else if nonblock {
                    ChannelResult::Ready(-11)
                } else {
                    ChannelResult::Blocked {
                        fd,
                        progressed: false,
                    }
                });
            }
            let overhead = if p.packet { 2 } else { 0 };
            let length = if p.packet {
                u16::from_le_bytes([p.data[p.head], p.data[(p.head + 1) % CAPACITY]]) as usize
            } else {
                p.len
            };
            let count = requested.min(IO_SIZE).min(length);
            for (i, byte) in buffer[..count].iter_mut().enumerate() {
                *byte = p.data[(p.head + overhead + i) % CAPACITY];
            }
            let copied = vectors.copy(pid, &mut buffer[..count], true)?;
            if p.packet && copied != count {
                return Err(-14);
            }
            let consumed = if p.packet { length + overhead } else { copied };
            p.head = (p.head + consumed) % CAPACITY;
            p.len -= consumed;
            Ok(ChannelResult::Ready(copied as i64))
        }
    }

    fn stat(pid: usize, address: u64, statx: bool, pipe: usize, socket: bool) -> Result<i64, i64> {
        write_stat(
            pid,
            address,
            Stat {
                accessed: ginux_vfs::Timestamp::ZERO,
                modified: ginux_vfs::Timestamp::ZERO,
                links: 1,
                inode: 0x2_0000_0000 + pipe as u64,
                mode: if socket { 0o140600 } else { 0o10600 },
                size: 0,
                device_major: 0,
                device_minor: 0,
            },
            statx,
        )
    }
}
