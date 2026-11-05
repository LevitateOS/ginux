//! Native channel-lane dispatch hooks.
//!
//! Owner: G-files/channel adapter lane (serialized with G-files edits).
//!
//! G14 supplies the generic opaque byte transport the §4 worker-protocol
//! frames ride on. The transport itself lives in the child module
//! [`channel_transport`]: supervisor-created, supervisor-owned
//! [`ChannelSpace`](channel_transport::ChannelSpace) objects with bounded
//! buffers, short-I/O reads/writes, half-close
//! ([`shutdown_write`](ChannelSpace::shutdown_write)) and full-close
//! ([`close`](ChannelSpace::close)) semantics. Bytes stay opaque end to
//! end: nothing here interprets frame headers, versions, sequence numbers,
//! or Recipe op codes, and the module holds zero host descriptors, so no
//! raw controller descriptor can ever reach the workload. The managed
//! program's side of the bidirectional channel is tracee fds 0 (reads) and
//! 1 (writes), backed by the two supervisor-created channels
//! ([`CHANNEL_STDIN_FD`]/[`CHANNEL_STDOUT_FD`]).
//!
//! Lane entry today: none. The data path uses `read`/`write`/`close` on
//! fds 0/1, which the process supervision loop already mediates (G05a
//! stdio/pipe arms); closing those numbers against the host without the
//! tracee-memory/fd-table plumbing would break the existing demonstrations,
//! so this hook keeps declining and the supervisor keeps its existing
//! behavior byte-identical.
//!
//! LIMIT (merge-time wiring, owned by G09 with main.rs/process_hooks.rs):
//! the loop instantiates one `ChannelSpace<CHANNEL_SLOTS,
//! CHANNEL_CAPACITY>` at launch, creates the stdin channel with writer
//! [`ChannelEnd::Controller`] and the stdout channel with writer
//! [`ChannelEnd::Managed`], installs the managed ends as tracee fds 0/1,
//! and routes entries through the seam below. Exact seam signatures:
//!
//! * `channel_managed_read(&mut ChannelSpace<S, CAP>, stdin: u32, out:
//!   &mut [u8]) -> Result<usize, ChannelError>` — tracee `read(0, ...)`.
//! * `channel_managed_write(&mut ChannelSpace<S, CAP>, stdout: u32, bytes:
//!   &[u8]) -> Result<usize, ChannelError>` — tracee `write(1, ...)`.
//! * `channel_managed_close(&mut ChannelSpace<S, CAP>, stdin: u32, stdout:
//!   u32, fd: u32) -> Option<Result<bool, ChannelError>>` — tracee
//!   `close(fd)`; `None` means "not a channel fd, keep existing behavior".
//!
//! The controller side calls [`ChannelSpace`] directly: `write(stdin,
//! Controller, ...)` to deliver bytes, `read(stdout, Controller, ...)` to
//! collect them, `shutdown_write(stdin, Controller)` to propagate
//! end-of-stream to the workload, and `close(.., Controller)` per end at
//! teardown. `ChannelError::errno` already maps every failure to its
//! faithful negative errno for that wiring.

// Whole-module allow: every transport item waits for the G09 merge
// wiring above; remove it when the loop calls the seam.
#[allow(dead_code)]
#[path = "channel_transport.rs"]
mod channel_transport;

// Re-export allow: the loop wiring consumes these at merge time.
#[allow(dead_code, unused_imports)]
pub use channel_transport::{
    ChannelEnd, ChannelError, ChannelSpace, EAGAIN, EBADF, EMFILE, EPIPE, CHANNEL_CAPACITY,
    CHANNEL_SLOTS,
};

/// Tracee fd reading from the controller: the managed end of the
/// controller-to-managed channel.
#[allow(dead_code)]
pub const CHANNEL_STDIN_FD: u32 = 0;
/// Tracee fd writing to the controller: the managed end of the
/// managed-to-controller channel.
#[allow(dead_code)]
pub const CHANNEL_STDOUT_FD: u32 = 1;

/// Lane membership by syscall number. No entry belongs to the channel lane
/// yet: the data path rides on `read`/`write`/`close`, which stay with the
/// process loop's existing arms until the G09 merge wiring lands.
pub fn claims(syscall: u64) -> bool {
    let _ = syscall;
    false
}

/// Emulated result when this lane handles the entry. `None` always: the
/// lane declines and the caller falls through to existing behavior.
pub fn claim(syscall: u64, rdi: u64, rsi: u64, rdx: u64) -> Option<i64> {
    let _ = (syscall, rdi, rsi, rdx);
    None
}

/// Supervisor seam: outcome of a tracee `read(0, out)` against the stdin
/// channel's managed end. Short counts, `WouldBlock`, and `Ok(0)`
/// end-of-stream carry the transport semantics straight to the caller.
#[allow(dead_code)]
pub fn channel_managed_read<const SLOTS: usize, const CAP: usize>(
    channels: &mut ChannelSpace<SLOTS, CAP>,
    stdin: u32,
    out: &mut [u8],
) -> Result<usize, ChannelError> {
    channels.read(stdin, ChannelEnd::Managed, out)
}

/// Supervisor seam: outcome of a tracee `write(1, bytes)` against the
/// stdout channel's managed end. Short counts and `WouldBlock` carry the
/// bounded-buffer semantics straight to the caller.
#[allow(dead_code)]
pub fn channel_managed_write<const SLOTS: usize, const CAP: usize>(
    channels: &mut ChannelSpace<SLOTS, CAP>,
    stdout: u32,
    bytes: &[u8],
) -> Result<usize, ChannelError> {
    channels.write(stdout, ChannelEnd::Managed, bytes)
}

/// Supervisor seam: outcome of a tracee `close(fd)` that may name a
/// channel end. `Some` carries the managed-end close of the matching
/// channel (`true` when the object died); `None` means `fd` is not a
/// channel fd and the loop keeps its existing close behavior.
#[allow(dead_code)]
pub fn channel_managed_close<const SLOTS: usize, const CAP: usize>(
    channels: &mut ChannelSpace<SLOTS, CAP>,
    stdin: u32,
    stdout: u32,
    fd: u32,
) -> Option<Result<bool, ChannelError>> {
    if fd == CHANNEL_STDIN_FD {
        Some(channels.close(stdin, ChannelEnd::Managed))
    } else if fd == CHANNEL_STDOUT_FD {
        Some(channels.close(stdout, ChannelEnd::Managed))
    } else {
        None
    }
}
