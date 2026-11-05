//! Supervisor-owned bidirectional byte channels: the opaque transport the
//! §4 worker-protocol frames ride on.
//!
//! One [`ByteChannel`] moves bytes one way through a bounded buffer; the
//! supervisor installs two of them per managed program (controller-to-managed
//! as tracee fd 0, managed-to-controller as tracee fd 1) to form the
//! bidirectional channel. Bytes stay opaque end to end: this module never
//! interprets frame headers, versions, sequence numbers, or Recipe op
//! codes. Framing (`[u32 BE total-length][u32 BE version][u32 BE seq]`
//! `[u16 BE op]` plus payload, `total-length` 14..=`CHANNEL_FRAME_LIMIT`)
//! is agreed between the invoking controller and the managed program only;
//! see `docs/ginux-recipe-interfaces.md` §4.
//!
//! The managed endpoint is a domain object by construction: the supervisor
//! creates both ends with [`ChannelSpace::create`], owns them for the whole
//! invocation, and hands the workload nothing but its own end number. This
//! module holds zero host descriptors, so there is no controller descriptor
//! that could leak to the workload; the supervision-loop wiring (a later
//! task) only ever installs the [`ChannelEnd::Managed`] end as tracee fds
//! 0/1 and pumps tracee bytes through the seam in
//! `super::channel_hooks`.
//!
//! Transfer rules mirror pipe short-I/O: [`ChannelSpace::read`] returns at
//! most what is buffered, [`ChannelSpace::write`] stores at most what fits,
//! and either may make short progress. A read on an empty buffer whose
//! writer can still produce fails with [`ChannelError::WouldBlock`]; once
//! the writer half-closes ([`ChannelSpace::shutdown_write`]) or fully
//! closes ([`ChannelSpace::close`]) and the buffer drains, reads report
//! `Ok(0)` end-of-stream. A write that fits nothing while the reader is
//! still present fails with [`ChannelError::WouldBlock`]; a write with no
//! possible reader (reader end closed, or this end already shut for writing)
//! fails with [`ChannelError::PeerClosed`]. [`ChannelError::errno`] maps
//! each failure to its faithful negative errno for the loop wiring.
//!
//! Everything here is pure `core` logic over caller buffers: no host calls,
//! no allocation, so a denial or exhaustion has zero host effect by
//! construction.

/// Per-direction buffer bound: one Linux default pipe worth of bytes.
/// A §4 frame (up to 4 MiB total) crosses the transport as a sequence of
/// bounded writes and reads, never as one atomic transfer.
pub const CHANNEL_CAPACITY: usize = 64 * 1024;

/// Supervisor channel-table size the merge-time loop wiring instantiates:
/// `ChannelSpace<CHANNEL_SLOTS, CHANNEL_CAPACITY>`.
pub const CHANNEL_SLOTS: usize = 8;

/// Negative-errno constants reported by [`ChannelError::errno`]. Only the
/// values consumed by live in-crate code paths need stay in sync with
/// `linux/errno.h`; the mappers carry the rest for the loop wiring.
pub const EBADF: i64 = 9;
/// No progress possible now: read on an empty buffer with a live writer,
/// or write to a full buffer with a live reader.
pub const EAGAIN: i64 = 11;
/// Too many open channels: [`ChannelSpace::create`] with no free slot.
pub const EMFILE: i64 = 24;
/// No possible reader: write after the reader end closed, or after this
/// end shut its own writes down.
pub const EPIPE: i64 = 32;

/// Which side of a channel an operation acts as. A channel's writer is
/// fixed at creation; [`ChannelSpace`] checks every operation against it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelEnd {
    /// The invoking controller side, kept supervisor-side only.
    Controller,
    /// The managed-program side; the only end a tracee fd ever names.
    Managed,
}

impl ChannelEnd {
    /// The opposite end of the same channel.
    pub const fn other(self) -> ChannelEnd {
        match self {
            ChannelEnd::Controller => ChannelEnd::Managed,
            ChannelEnd::Managed => ChannelEnd::Controller,
        }
    }
}

/// Channel failures. [`ChannelError::errno`] maps each to the negative
/// errno the supervision loop reports to the tracee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelError {
    /// No free channel slot; the supervisor table is full.
    TableFull,
    /// Channel number out of range or naming a fully closed channel.
    Unknown,
    /// This end is already closed.
    EndClosed,
    /// The write path is gone: the reader end is closed, or this end
    /// already shut its own writes down.
    PeerClosed,
    /// Valid request, zero progress: empty read with a live writer, or
    /// full write with a live reader. The caller retries after the peer
    /// moves bytes.
    WouldBlock,
    /// Read attempted by the writer end, write or half-close attempted by
    /// the reader end. Byte channels are unidirectional like pipes.
    WrongDirection,
}

impl ChannelError {
    /// Faithful negative errno for supervisor wiring.
    pub const fn errno(self) -> i64 {
        match self {
            ChannelError::TableFull => -EMFILE,
            ChannelError::Unknown => -EBADF,
            ChannelError::EndClosed => -EBADF,
            ChannelError::PeerClosed => -EPIPE,
            ChannelError::WouldBlock => -EAGAIN,
            ChannelError::WrongDirection => -EBADF,
        }
    }
}

/// Bounded first-in-first-out byte buffer. `head` is the oldest live byte,
/// `len` the live count; both stay below `CAP`, so the indexing below can
/// never divide by zero even for `CAP == 0` (empty then means full).
#[derive(Clone, Copy)]
struct Ring<const CAP: usize> {
    buf: [u8; CAP],
    head: usize,
    len: usize,
}

impl<const CAP: usize> Ring<CAP> {
    const fn empty() -> Self {
        Self {
            buf: [0; CAP],
            head: 0,
            len: 0,
        }
    }

    /// Store a prefix of `bytes`; returns the stored count (short when the
    /// buffer fills).
    fn push(&mut self, bytes: &[u8]) -> usize {
        let mut count = 0;
        while count < bytes.len() && self.len < CAP {
            self.buf[(self.head + self.len) % CAP] = bytes[count];
            self.len += 1;
            count += 1;
        }
        count
    }

    /// Remove into a prefix of `out`; returns the removed count (short
    /// when the buffer drains).
    fn pop(&mut self, out: &mut [u8]) -> usize {
        let mut count = 0;
        while count < out.len() && self.len > 0 {
            out[count] = self.buf[self.head];
            self.head = (self.head + 1) % CAP;
            self.len -= 1;
            count += 1;
        }
        count
    }
}

/// One unidirectional supervisor-owned byte channel: a bounded buffer plus
/// the open/shutdown state of both ends. Created by the supervisor, never
/// by a tracee syscall.
#[derive(Clone, Copy)]
struct ByteChannel<const CAP: usize> {
    live: bool,
    writer: ChannelEnd,
    data: Ring<CAP>,
    writer_open: bool,
    reader_open: bool,
    writer_shut: bool,
}

impl<const CAP: usize> ByteChannel<CAP> {
    const fn empty() -> Self {
        Self {
            live: false,
            writer: ChannelEnd::Controller,
            data: Ring::empty(),
            writer_open: false,
            reader_open: false,
            writer_shut: false,
        }
    }

    const fn reader(self) -> ChannelEnd {
        self.writer.other()
    }
}

/// Supervisor-owned channel table: live channel objects plus the per-end
/// open state. Sized by the supervision loop; every mutation follows a
/// supervisor-side decision, so the table never names a descriptor the
/// supervisor did not create.
pub struct ChannelSpace<const SLOTS: usize, const CAP: usize> {
    channels: [ByteChannel<CAP>; SLOTS],
}

impl<const SLOTS: usize, const CAP: usize> ChannelSpace<SLOTS, CAP> {
    /// Empty table: no live channels.
    pub const fn new() -> Self {
        Self {
            channels: [ByteChannel::empty(); SLOTS],
        }
    }

    /// Create a channel whose `writer` end produces bytes and whose other
    /// end consumes them. Both ends start open. Returns the channel number
    /// (`1`-based slot index); ids die with the object, so a reused slot
    /// never aliases a live channel.
    pub fn create(&mut self, writer: ChannelEnd) -> Result<u32, ChannelError> {
        let slot = self
            .channels
            .iter()
            .position(|channel| !channel.live)
            .ok_or(ChannelError::TableFull)?;
        self.channels[slot].live = true;
        self.channels[slot].writer = writer;
        self.channels[slot].data = Ring::empty();
        self.channels[slot].writer_open = true;
        self.channels[slot].reader_open = true;
        self.channels[slot].writer_shut = false;
        Ok(slot as u32 + 1)
    }

    fn slot(&self, id: u32) -> Result<usize, ChannelError> {
        let slot = id.checked_sub(1).ok_or(ChannelError::Unknown)? as usize;
        if slot < SLOTS && self.channels[slot].live {
            Ok(slot)
        } else {
            Err(ChannelError::Unknown)
        }
    }

    /// Store a prefix of `bytes`, written by the channel's writer end.
    /// Returns the stored count: short when the buffer fills. Zero-length
    /// writes on a usable channel report `Ok(0)`; a full buffer with a live
    /// reader reports [`ChannelError::WouldBlock`].
    pub fn write(
        &mut self,
        id: u32,
        by: ChannelEnd,
        bytes: &[u8],
    ) -> Result<usize, ChannelError> {
        let slot = self.slot(id)?;
        let channel = &mut self.channels[slot];
        if by != channel.writer {
            return Err(ChannelError::WrongDirection);
        }
        if !channel.writer_open {
            return Err(ChannelError::EndClosed);
        }
        if channel.writer_shut || !channel.reader_open {
            return Err(ChannelError::PeerClosed);
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let stored = channel.data.push(bytes);
        if stored == 0 {
            return Err(ChannelError::WouldBlock);
        }
        Ok(stored)
    }

    /// Remove buffered bytes into `out`, read by the channel's reader end.
    /// Returns the removed count: short when the buffer drains. A drained
    /// buffer whose writer half-closed or closed reports `Ok(0)`
    /// end-of-stream; a drained buffer with a live writer reports
    /// [`ChannelError::WouldBlock`].
    pub fn read(
        &mut self,
        id: u32,
        by: ChannelEnd,
        out: &mut [u8],
    ) -> Result<usize, ChannelError> {
        let slot = self.slot(id)?;
        let channel = &mut self.channels[slot];
        if by != channel.reader() {
            return Err(ChannelError::WrongDirection);
        }
        if !channel.reader_open {
            return Err(ChannelError::EndClosed);
        }
        if out.is_empty() {
            return Ok(0);
        }
        let removed = channel.data.pop(out);
        if removed > 0 {
            return Ok(removed);
        }
        if channel.writer_shut || !channel.writer_open {
            return Ok(0);
        }
        Err(ChannelError::WouldBlock)
    }

    /// Half-close: the writer end will produce no more bytes. Buffered
    /// bytes still drain; reads past the drain report end-of-stream.
    /// Idempotent: shutting an already-shut writer still reports `Ok(())`.
    pub fn shutdown_write(&mut self, id: u32, by: ChannelEnd) -> Result<(), ChannelError> {
        let slot = self.slot(id)?;
        let channel = &mut self.channels[slot];
        if by != channel.writer {
            return Err(ChannelError::WrongDirection);
        }
        if !channel.writer_open {
            return Err(ChannelError::EndClosed);
        }
        channel.writer_shut = true;
        Ok(())
    }

    /// Fully close one end. Buffered bytes still drain to the surviving
    /// reader; writes with no reader fail with [`ChannelError::PeerClosed`].
    /// Returns whether the object died (both ends closed).
    pub fn close(&mut self, id: u32, end: ChannelEnd) -> Result<bool, ChannelError> {
        let slot = self.slot(id)?;
        let channel = &mut self.channels[slot];
        let open = if end == channel.writer {
            &mut channel.writer_open
        } else {
            &mut channel.reader_open
        };
        if !*open {
            return Err(ChannelError::EndClosed);
        }
        *open = false;
        if !channel.writer_open && !channel.reader_open {
            self.channels[slot] = ByteChannel::empty();
            return Ok(true);
        }
        Ok(false)
    }

    /// Live channel count, for teardown leak checks.
    pub fn active(&self) -> usize {
        self.channels.iter().filter(|channel| channel.live).count()
    }

    /// Buffered bytes waiting on a channel, for pump scheduling.
    pub fn pending(&self, id: u32) -> Result<usize, ChannelError> {
        let slot = self.slot(id)?;
        Ok(self.channels[slot].data.len)
    }

    /// Whether the writer end already half-closed, for EOF propagation.
    pub fn writer_shut(&self, id: u32) -> Result<bool, ChannelError> {
        let slot = self.slot(id)?;
        Ok(self.channels[slot].writer_shut)
    }

    /// Whether one end is still open. Unknown channels report closed.
    pub fn end_open(&self, id: u32, end: ChannelEnd) -> bool {
        let Ok(slot) = self.slot(id) else {
            return false;
        };
        let channel = &self.channels[slot];
        if end == channel.writer {
            channel.writer_open
        } else {
            channel.reader_open
        }
    }
}

impl<const SLOTS: usize, const CAP: usize> Default for ChannelSpace<SLOTS, CAP> {
    fn default() -> Self {
        Self::new()
    }
}
