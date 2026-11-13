//! Native channel-lane dispatch hooks.
//!
//! Owner: G-files/channel adapter lane (serialized with G-files changes).
//! Next task: G14 supplies the generic opaque transport the §4 frames ride
//! on. Until then every hook declines and the supervisor keeps its existing
//! behavior byte-identical.

/// Lane membership by syscall number. Reserved for G14.
pub const fn claims(syscall: u64) -> bool {
    let _ = syscall;
    false
}

/// Emulated result when this lane handles the entry. `None` falls through to
/// the shared balanced-contract decision. Reserved for G14.
pub fn claim(syscall: u64, rdi: u64, rsi: u64, rdx: u64) -> Option<i64> {
    let _ = (syscall, rdi, rsi, rdx);
    None
}

use crate::event_hooks::Event;
use crate::supervisor::{syscall3, UserRegs, SYS_TGKILL};
use crate::tracee_io::{copy_memory, read_path, write_stat, Stat};

pub const PIPE_FD_BASE: u32 = 0x2000_0000;
pub const FDS: usize = 2 * PIPES;
const PIPES: usize = 32;
const CAPACITY: usize = 65536;
const IO_SIZE: usize = 4096;
const CLOEXEC: u32 = 0o2000000;
const NONBLOCK: u32 = 0o4000;
const APPEND: u32 = 0o2000;

#[derive(Clone, Copy)]
struct Pipe {
    live: bool,
    event: Event,
    packet: bool,
    // A local socket shutdown closed this direction: writes get EPIPE and the
    // reader sees end-of-file once buffered bytes are consumed.
    shut: bool,
    data: [u8; CAPACITY],
    head: usize,
    len: usize,
    readers: u16,
    writers: u16,
    fifo: Option<u64>,
    reader_generation: u64,
    writer_generation: u64,
}

impl Pipe {
    const fn empty() -> Self {
        Self {
            live: false,
            event: Event::None,
            packet: false,
            shut: false,
            data: [0; CAPACITY],
            head: 0,
            len: 0,
            readers: 0,
            writers: 0,
            fifo: None,
            reader_generation: 0,
            writer_generation: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct PipeFd {
    pipe: usize,
    flags: u32,
    peer: Option<usize>,
    fifo: Option<FifoFd>,
}

#[derive(Clone, Copy)]
struct FifoFd {
    reference: u32,
    reader_generation: u64,
    writer_generation: u64,
}

impl PipeFd {
    fn readable(self) -> bool {
        self.flags & 3 != 1
    }

    fn writable(self) -> bool {
        self.flags & 3 != 0
    }
}

/// Progress belongs to the task's current syscall, not its shared endpoint.
pub struct WriteProgress {
    vectors: Option<crate::tracee_io::IoVectors>,
    written: usize,
    event_value: Option<u64>,
    event_nonblock: Option<bool>,
}
impl WriteProgress {
    pub const fn new() -> Self {
        Self {
            vectors: None,
            written: 0,
            event_value: None,
            event_nonblock: None,
        }
    }

    pub fn written(&self) -> usize {
        self.written
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
    epolls: [crate::event_hooks::Epoll; PIPES],
    epoll_count: usize,
}

impl LaunchChannels {
    pub const fn new() -> Self {
        Self {
            pipes: [Pipe::empty(); PIPES],
            descriptors: [None; FDS],
            epolls: [crate::event_hooks::Epoll::new(); PIPES],
            epoll_count: 0,
        }
    }

    pub fn claim(
        &mut self,
        pid: usize,
        signal_tgid: usize,
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
                | 42
                | 44
                | 45
                | 48
                | 51
                | 52
                | 54
                | 55
                | 72
                | 74
                | 75
                | 77
                | 91
                | 292
                | 295
        ) {
            return None;
        }
        let entry = match self.entry(slot) {
            Ok(entry) => entry,
            Err(error) => return Some(ChannelResult::Ready(error)),
        };
        if matches!(r.orig_rax, 42 | 48 | 51 | 52 | 54 | 55) {
            let result = match entry.peer {
                Some(peer) => self.socket_control(pid, entry, peer, r),
                None => Err(-88),
            };
            return Some(ChannelResult::Ready(result.unwrap_or_else(|e| e)));
        }
        if matches!(r.orig_rax, 0 | 1 | 19 | 20 | 44 | 45) {
            if !matches!(self.pipes[entry.pipe].event, Event::None) {
                return Some(
                    self.event_io(pid, slot, entry, r, progress)
                        .unwrap_or_else(ChannelResult::Ready),
                );
            }
            if matches!(r.orig_rax, 44 | 45)
                && (entry.peer.is_none() || r.r10 & !(0x40 | 0x4000) != 0 || r.r8 != 0 || r.r9 != 0)
            {
                return Some(ChannelResult::Ready(-95));
            }
            return Some(match self.io(pid, signal_tgid, slot, entry, r, progress) {
                Ok(result) => result,
                Err(error) => ChannelResult::Ready(error),
            });
        }
        let result = match r.orig_rax {
            3 => {
                self.close(slot);
                Ok(0)
            }
            5 => Self::stat(
                pid,
                r.rsi,
                false,
                entry.pipe,
                entry.peer.is_some(),
                !matches!(self.pipes[entry.pipe].event, Event::None),
            ),
            8 | 17 | 18 | 295 => Err(-29),
            16 if r.rsi == 0x5421 => {
                // FIONBIO changes the shared open-file status, not this
                // public descriptor's CLOEXEC bit. Copy the complete int
                // before changing anything; a partial read is EFAULT.
                let mut value = [0u8; 4];
                match copy_memory(pid, r.rdx, &mut value, false) {
                    Ok(4) => {
                        let flags = self.flags(entry);
                        self.set_flags(
                            slot,
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
            // FIONREAD: queued bytes; a packet socket sums its queued
            // payloads, as Linux SIOCINQ does.
            16 if r.rsi == 0x541b
                && matches!(self.pipes[entry.pipe].event, Event::None)
                && (entry.peer.is_some() || !self.pipes[entry.pipe].packet) =>
            {
                let mut bytes = (self.queued(entry.pipe) as i32).to_ne_bytes();
                match copy_memory(pid, r.rdx, &mut bytes, true) {
                    Ok(4) => Ok(0),
                    _ => Err(-14),
                }
            }
            16 => Err(-25),
            72 => match r.rsi {
                3 => Ok(self.flags(entry) as i64),
                4 if !matches!(self.pipes[entry.pipe].event, Event::None)
                    && r.rdx & !((NONBLOCK | 3) as u64) != 0 =>
                {
                    Err(-22)
                }
                4 if r.rdx & !((NONBLOCK | APPEND | 3) as u64) == 0 => {
                    let flags = (r.rdx as u32 & (NONBLOCK | APPEND)) | (entry.flags & 3);
                    self.set_flags(slot, flags);
                    Ok(0)
                }
                1032 if !matches!(self.pipes[entry.pipe].event, Event::None)
                    || entry.peer.is_some() =>
                {
                    Err(-9)
                }
                1032 => Ok(CAPACITY as i64),
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
                        entry.pipe,
                        entry.peer.is_some(),
                        !matches!(self.pipes[entry.pipe].event, Event::None),
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
        p.event = Event::None;
        p.packet = false;
        p.shut = false;
        p.head = 0;
        p.len = 0;
        p.readers = 1;
        p.writers = 1;
        p.fifo = None;
        p.reader_generation = 0;
        p.writer_generation = 0;
        self.descriptors[first] = Some(PipeFd {
            pipe,
            flags: flags as u32 & NONBLOCK,
            peer: None,
            fifo: None,
        });
        self.descriptors[second] = Some(PipeFd {
            pipe,
            flags: 1 | (flags as u32 & NONBLOCK),
            peer: None,
            fifo: None,
        });
        Ok([PIPE_FD_BASE + first as u32, PIPE_FD_BASE + second as u32])
    }

    /// Connected local socket endpoints, one bounded buffer per direction:
    /// no names, networking, descriptor transfer, or native workload sockets
    /// are involved. `packet` preserves record boundaries (`SOCK_SEQPACKET`);
    /// otherwise each direction is a byte stream (`SOCK_STREAM`).
    pub fn allocate_socket_pair(&mut self, flags: u64, packet: bool) -> Result<[u32; 2], i64> {
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
        self.descriptors[a].as_mut().unwrap().flags |= 2;
        self.descriptors[b].as_mut().unwrap().flags |= 2;
        // Transfer writer ownership into the opposite duplex endpoint.
        self.descriptors[(first[1] - PIPE_FD_BASE) as usize] = None;
        self.descriptors[(second[1] - PIPE_FD_BASE) as usize] = None;
        for index in [pa, pb] {
            self.pipes[index].packet = packet;
        }
        Ok([first[0], second[0]])
    }

    pub fn release(&mut self, handle: u32) {
        self.close((handle - PIPE_FD_BASE) as usize);
    }

    /// Open the pipe belonging to a VFS inode. The private storage reference
    /// pins that inode across unlink; the descriptor owner releases it when
    /// this endpoint's last public alias closes. Failed opens do not consume it.
    pub fn open_fifo(&mut self, inode: u64, reference: u32, flags: u32) -> Result<u32, i64> {
        let access = flags & 3;
        if access == 3 {
            return Err(-22);
        }
        let existing = self
            .pipes
            .iter()
            .position(|pipe| pipe.live && pipe.fifo == Some(inode));
        if access == 1
            && flags & NONBLOCK != 0
            && existing.is_none_or(|index| self.pipes[index].readers == 0)
        {
            return Err(-6);
        }
        let slot = self
            .descriptors
            .iter()
            .position(Option::is_none)
            .ok_or(-24)?;
        let index = existing
            .or_else(|| self.pipes.iter().position(|pipe| !pipe.live))
            .ok_or(-24)?;
        let pipe = &mut self.pipes[index];
        if existing.is_none() {
            pipe.live = true;
            pipe.event = Event::None;
            pipe.packet = false;
            pipe.shut = false;
            pipe.head = 0;
            pipe.len = 0;
            pipe.readers = 0;
            pipe.writers = 0;
            pipe.fifo = Some(inode);
            pipe.reader_generation = 0;
            pipe.writer_generation = 0;
        }
        // Remember a peer that is already present, or one that opens and
        // closes before a parked open is retried. A reader opened before the
        // first writer has EOF but no POLLHUP until a writer has appeared.
        let fifo = FifoFd {
            reference,
            reader_generation: pipe
                .reader_generation
                .wrapping_sub(u64::from(pipe.readers != 0)),
            writer_generation: pipe
                .writer_generation
                .wrapping_sub(u64::from(pipe.writers != 0)),
        };
        if access != 1 {
            pipe.readers += 1;
            pipe.reader_generation = pipe.reader_generation.wrapping_add(1);
        }
        if access != 0 {
            pipe.writers += 1;
            pipe.writer_generation = pipe.writer_generation.wrapping_add(1);
        }
        self.descriptors[slot] = Some(PipeFd {
            pipe: index,
            flags: flags & (3 | NONBLOCK | APPEND),
            peer: None,
            fifo: Some(fifo),
        });
        Ok(PIPE_FD_BASE + slot as u32)
    }

    pub fn fifo_open_ready(&self, handle: u32) -> bool {
        let Some(slot) = handle.checked_sub(PIPE_FD_BASE) else {
            return false;
        };
        let Ok(entry) = self.entry(slot as usize) else {
            return false;
        };
        let Some(fifo) = entry.fifo else {
            return false;
        };
        let pipe = &self.pipes[entry.pipe];
        match entry.flags & 3 {
            0 => entry.flags & NONBLOCK != 0 || pipe.writer_generation != fifo.writer_generation,
            1 => pipe.reader_generation != fifo.reader_generation,
            _ => true,
        }
    }

    pub fn fifo_reference(&self, handle: u32) -> Option<u32> {
        self.entry(handle.checked_sub(PIPE_FD_BASE)? as usize)
            .ok()?
            .fifo
            .map(|fifo| fifo.reference)
    }

    /// Event objects share the existing bounded pipe/object pool. They add no
    /// host descriptor and never bypass the public descriptor allocator.
    pub fn allocate_event(&mut self, event: Event, flags: u32) -> Result<u32, i64> {
        let pipe = self.pipes.iter().position(|p| !p.live).ok_or(-24)?;
        let slot = self
            .descriptors
            .iter()
            .position(Option::is_none)
            .ok_or(-24)?;
        let object = &mut self.pipes[pipe];
        object.live = true;
        object.event = event;
        object.packet = false;
        object.shut = false;
        object.head = 0;
        object.len = 0;
        object.readers = 1;
        object.writers = 1;
        object.fifo = None;
        object.reader_generation = 0;
        object.writer_generation = 0;
        if matches!(event, Event::Epoll) {
            self.epolls[pipe] = crate::event_hooks::Epoll::new();
            self.epoll_count += 1;
        }
        self.descriptors[slot] = Some(PipeFd {
            pipe,
            flags: 2 | (flags & NONBLOCK),
            peer: None,
            fifo: None,
        });
        Ok(PIPE_FD_BASE + slot as u32)
    }

    pub fn event(&self, handle: u32) -> Option<&Event> {
        let entry = self
            .entry(handle.checked_sub(PIPE_FD_BASE)? as usize)
            .ok()?;
        Some(&self.pipes[entry.pipe].event)
    }

    pub fn epoll(&self, handle: u32) -> Option<&crate::event_hooks::Epoll> {
        let entry = self
            .entry(handle.checked_sub(PIPE_FD_BASE)? as usize)
            .ok()?;
        if !matches!(self.pipes[entry.pipe].event, Event::Epoll) {
            return None;
        }
        Some(&self.epolls[entry.pipe])
    }

    pub fn epoll_mut(&mut self, handle: u32) -> Option<&mut crate::event_hooks::Epoll> {
        let entry = self
            .entry(handle.checked_sub(PIPE_FD_BASE)? as usize)
            .ok()?;
        if !matches!(self.pipes[entry.pipe].event, Event::Epoll) {
            return None;
        }
        Some(&mut self.epolls[entry.pipe])
    }

    pub fn has_epolls(&self) -> bool {
        self.epoll_count != 0
    }

    pub fn notify_counter(&mut self, handle: u32, events: u32) {
        for (index, object) in self.pipes.iter().enumerate() {
            if object.live && matches!(object.event, Event::Epoll) {
                for watch in self.epolls[index].watches.iter_mut().flatten() {
                    if watch.key.handle == handle {
                        watch.notify(events);
                    }
                }
            }
        }
    }

    pub fn epolls(&self) -> [Option<u32>; PIPES] {
        let mut output = [None; PIPES];
        let mut count = 0;
        for (slot, entry) in self.descriptors.iter().enumerate() {
            if entry.is_some_and(|entry| matches!(self.pipes[entry.pipe].event, Event::Epoll)) {
                output[count] = Some(PIPE_FD_BASE + slot as u32);
                count += 1;
            }
        }
        output
    }

    /// Current readiness of a live owned endpoint. ERR/HUP do not depend on
    /// the requested event mask; buffered bytes and HUP may coexist.
    pub fn readiness(&self, handle: u32) -> Option<u16> {
        let slot = handle.checked_sub(PIPE_FD_BASE)? as usize;
        let entry = self.entry(slot).ok()?;
        let pipe = &self.pipes[entry.pipe];
        match pipe.event {
            Event::Counter { value, .. } => {
                return Some(
                    (if value != 0 { 0x41 } else { 0 })
                        | (if value < u64::MAX - 1 { 0x104 } else { 0 }),
                )
            }
            Event::Epoll => {
                let epoll = &self.epolls[entry.pipe];
                return Some(if epoll.watches.iter().flatten().any(|w| w.pending != 0) {
                    0x41
                } else {
                    0
                });
            }
            Event::None => {}
        }
        if let Some(peer) = entry.peer {
            let output = &self.pipes[peer];
            // A stream write of up to IO_SIZE bytes is placed whole, so
            // writability promises that much room; a record needs its header.
            let room = if output.packet { 2 } else { IO_SIZE };
            return Some(ginux_core::local_socket_readiness(
                pipe.len,
                pipe.writers == 0 || pipe.shut,
                CAPACITY - output.len >= room,
                output.readers == 0 || output.shut,
            ));
        }
        let mut events = 0;
        if entry.writable() {
            events |= (if pipe.len < CAPACITY { 0x104 } else { 0 })
                | (if pipe.readers == 0 { 8 } else { 0 });
        }
        if entry.readable() {
            let hung_up = pipe.writers == 0
                && entry
                    .fifo
                    .is_none_or(|fifo| fifo.writer_generation != pipe.writer_generation);
            events |= (if pipe.len != 0 { 0x41 } else { 0 }) | (if hung_up { 16 } else { 0 });
        }
        Some(events)
    }

    /// What `readahead`, `fadvise64`, `sendfile` and `copy_file_range` need
    /// to know about a channel endpoint: a local socket, an event counter or
    /// epoll instance (an anonymous object), or else a pipe or FIFO end, with
    /// the access mode of its open.
    pub fn file_view(&self, handle: u32) -> Result<ginux_core::FileView, i64> {
        use ginux_core::FileKind;
        let entry = self.entry(handle.checked_sub(PIPE_FD_BASE).ok_or(-9)? as usize)?;
        Ok(ginux_core::FileView {
            readable: entry.readable(),
            writable: entry.writable(),
            append: entry.flags & APPEND != 0,
            kind: if entry.peer.is_some() {
                FileKind::Socket
            } else if !matches!(self.pipes[entry.pipe].event, Event::None) {
                FileKind::Other
            } else {
                FileKind::Fifo
            },
            size: 0,
            identity: (u64::MAX - 2, entry.pipe as u64),
        })
    }

    pub fn is_socket(&self, handle: u32) -> bool {
        handle
            .checked_sub(PIPE_FD_BASE)
            .and_then(|slot| self.descriptors.get(slot as usize))
            .and_then(|entry| *entry)
            .is_some_and(|entry| entry.peer.is_some())
    }

    /// Bytes a reader of this direction may still receive. Packet buffers
    /// hold a two-byte length before each record; only payload counts.
    fn queued(&self, index: usize) -> usize {
        let pipe = &self.pipes[index];
        if !pipe.packet {
            return pipe.len;
        }
        let (mut offset, mut total) = (0, 0);
        while offset < pipe.len {
            let at = |i: usize| pipe.data[(pipe.head + offset + i) % CAPACITY];
            let length = u16::from_le_bytes([at(0), at(1)]) as usize;
            total += length;
            offset += 2 + length;
        }
        total
    }

    /// Socket calls on a connected local pair endpoint. The pair has no name
    /// and is already connected, so nothing here resolves, binds or connects
    /// an address; peer credentials are never disclosed.
    fn socket_control(
        &mut self,
        pid: usize,
        entry: PipeFd,
        peer: usize,
        r: &UserRegs,
    ) -> Result<i64, i64> {
        let kind = if self.pipes[peer].packet {
            ginux_core::LocalSocketKind::SequencedPacket
        } else {
            ginux_core::LocalSocketKind::Stream
        };
        let length = |address: u64| -> Result<i32, i64> {
            let mut bytes = [0u8; 4];
            match copy_memory(pid, address, &mut bytes, false) {
                Ok(4) => Ok(i32::from_ne_bytes(bytes)),
                _ => Err(-14),
            }
        };
        let put_length = |address: u64, value: i32| -> Result<i64, i64> {
            match copy_memory(pid, address, &mut value.to_ne_bytes(), true) {
                Ok(4) => Ok(0),
                _ => Err(-14),
            }
        };
        match r.orig_rax {
            // A pair is connected at creation; the address is never read.
            42 => Err(-106),
            48 => {
                let (receive, send) = ginux_core::local_socket_shutdown(r.rsi)?;
                if receive {
                    self.pipes[entry.pipe].shut = true;
                }
                if send {
                    self.pipes[peer].shut = true;
                }
                Ok(0)
            }
            // getsockname/getpeername: both endpoints are unnamed AF_UNIX
            // sockets, reported as a bare two-byte family.
            51 | 52 => {
                let requested = length(r.rdx)?;
                if requested < 0 {
                    return Err(-22);
                }
                let mut family = 1u16.to_ne_bytes();
                let count = (requested as usize).min(family.len());
                if copy_memory(pid, r.rsi, &mut family[..count], true) != Ok(count as i64) {
                    return Err(-14);
                }
                put_length(r.rdx, family.len() as i32)
            }
            54 => {
                // Linux copies the int before it looks at the option name.
                let checked = ginux_core::local_socket_set_option(r.rsi, r.rdx, r.r8);
                if matches!(checked, Ok(()) | Err(-92)) {
                    length(r.r10)?;
                }
                checked.map(|()| 0)
            }
            55 => {
                let requested = length(r.r8)?;
                if requested < 0 {
                    return Err(-22);
                }
                let value = ginux_core::local_socket_option(r.rsi, r.rdx, kind, CAPACITY)?;
                let mut bytes = value.to_ne_bytes();
                let count = (requested as usize).min(bytes.len());
                if copy_memory(pid, r.r10, &mut bytes[..count], true) != Ok(count as i64) {
                    return Err(-14);
                }
                put_length(r.r8, count as i32)
            }
            _ => Err(-95),
        }
    }

    fn entry(&self, slot: usize) -> Result<PipeFd, i64> {
        self.descriptors.get(slot).copied().flatten().ok_or(-9)
    }

    fn flags(&self, entry: PipeFd) -> u32 {
        entry.flags
    }

    fn set_flags(&mut self, slot: usize, flags: u32) {
        self.descriptors[slot].as_mut().unwrap().flags = flags;
    }

    fn close(&mut self, slot: usize) {
        if let Some(entry) = self.descriptors[slot].take() {
            if !matches!(self.pipes[entry.pipe].event, Event::None) {
                if matches!(self.pipes[entry.pipe].event, Event::Epoll) {
                    self.epoll_count -= 1;
                }
                let object = &mut self.pipes[entry.pipe];
                object.live = false;
                object.event = Event::None;
                object.readers = 0;
                object.writers = 0;
                object.len = 0;
                object.head = 0;
                return;
            }
            if entry.readable() {
                self.close_direction(entry.pipe, false);
            }
            if let Some(peer) = entry.peer {
                self.close_direction(peer, true);
            } else if entry.writable() {
                self.close_direction(entry.pipe, true);
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

    fn event_io(
        &mut self,
        pid: usize,
        slot: usize,
        entry: PipeFd,
        r: &UserRegs,
        progress: &mut WriteProgress,
    ) -> Result<ChannelResult, i64> {
        let (value, semaphore) = match self.pipes[entry.pipe].event {
            Event::Counter { value, semaphore } => (value, semaphore),
            _ => return Err(-22),
        };
        let nonblock = *progress
            .event_nonblock
            .get_or_insert(self.flags(entry) & NONBLOCK != 0);
        let blocked = || {
            if nonblock {
                ChannelResult::Ready(-11)
            } else {
                ChannelResult::Blocked {
                    fd: PIPE_FD_BASE + slot as u32,
                    progressed: false,
                }
            }
        };
        match r.orig_rax {
            0 => {
                if r.rdx < 8 {
                    return Err(-22);
                }
                if value == 0 {
                    return Ok(blocked());
                }
                let read = if semaphore { 1 } else { value };
                let mut bytes = read.to_ne_bytes();
                if copy_memory(pid, r.rsi, &mut bytes, true)? != 8 {
                    return Err(-14);
                }
                if let Event::Counter { value, .. } = &mut self.pipes[entry.pipe].event {
                    *value -= read;
                }
            }
            1 => {
                if r.rdx != 8 {
                    return Err(-22);
                }
                let incoming = if let Some(value) = progress.event_value {
                    value
                } else {
                    let mut bytes = [0; 8];
                    if copy_memory(pid, r.rsi, &mut bytes, false)? != 8 {
                        return Err(-14);
                    }
                    let value = u64::from_ne_bytes(bytes);
                    if value == u64::MAX {
                        return Err(-22);
                    }
                    progress.event_value = Some(value);
                    value
                };
                let Some(next) = value.checked_add(incoming).filter(|n| *n < u64::MAX) else {
                    return Ok(blocked());
                };
                if let Event::Counter { value, .. } = &mut self.pipes[entry.pipe].event {
                    *value = next;
                }
            }
            _ => return Err(-95),
        }
        Ok(ChannelResult::Ready(8))
    }

    fn io(
        &mut self,
        pid: usize,
        signal_tgid: usize,
        slot: usize,
        entry: PipeFd,
        r: &UserRegs,
        progress: &mut WriteProgress,
    ) -> Result<ChannelResult, i64> {
        let writing = matches!(r.orig_rax, 1 | 20 | 44);
        let pipe = if writing {
            entry.peer.unwrap_or(entry.pipe)
        } else {
            entry.pipe
        };
        let socket = entry.peer.is_some();
        let packet = self.pipes[pipe].packet;
        // The current blocking write retains its admitted mode and vector
        // layout while another task can change the shared endpoint flags.
        let nonblock = progress.vectors.is_none()
            && (self.flags(entry) & NONBLOCK != 0
                || matches!(r.orig_rax, 44 | 45) && r.r10 & 0x40 != 0);
        // Pipes and stream sockets complete a blocking write; a record is
        // placed whole or not at all.
        let complete_write = writing && !nonblock && !packet;
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
        if (writing && !entry.writable()) || (!writing && !entry.readable()) {
            return Err(-9);
        }
        // An empty request transfers nothing. An empty record is still a
        // record, and a stream socket write first reports a closed peer.
        if requested == 0 && !packet && !(socket && writing) {
            return Ok(ChannelResult::Ready(0));
        }
        let fd = PIPE_FD_BASE + slot as u32;
        let mut buffer = [0u8; IO_SIZE];
        let p = &mut self.pipes[pipe];
        if writing {
            if p.readers == 0 || p.shut {
                // Deliver the ordinary SIGPIPE to this supervised caller, not
                // to the supervisor. Its disposition determines the outcome.
                // A stream socket that already sent part of the request
                // returns that count without a signal, as Linux does.
                if (r.orig_rax != 44 || r.r10 & 0x4000 == 0)
                    && !(socket && !packet && progress.written != 0)
                {
                    // kill(2) is process-directed even when pid is a host TID.
                    // The host thread-group ID prevents TID-reuse misdelivery.
                    let _ = unsafe { syscall3(SYS_TGKILL, signal_tgid, pid, 13) };
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
                return Ok(if p.writers == 0 || p.shut {
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

    fn stat(
        pid: usize,
        address: u64,
        statx: bool,
        pipe: usize,
        socket: bool,
        event: bool,
    ) -> Result<i64, i64> {
        write_stat(
            pid,
            address,
            Stat {
                accessed: ginux_vfs::Timestamp::ZERO,
                modified: ginux_vfs::Timestamp::ZERO,
                links: 1,
                inode: 0x2_0000_0000 + pipe as u64,
                mode: if event {
                    0o600
                } else if socket {
                    0o140777
                } else {
                    0o10600
                },
                size: 0,
                device_major: 0,
                device_minor: 0,
            },
            statx,
        )
    }
}
