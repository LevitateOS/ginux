//! Configured file calls answered through the public descriptor table, each
//! with no authority beyond a call the instance already has on the same
//! descriptor or path:
//!
//! - `preadv` and `preadv2` are `preadv` or `readv` (zero flags only): owned
//!   backends read at the offset, an image descriptor reads in the kernel;
//! - `readahead` and `fadvise64` give Linux's answer for the descriptor and
//!   have no host effect;
//! - the xattr calls resolve their path as `stat`/`lstat` (as a
//!   `faccessat2(F_OK)` through the shared path mediation) or their
//!   descriptor as `fstat`, then report a filesystem without attributes;
//! - `sendfile` and `copy_file_range` read their input as `pread64` would and
//!   write their output as `write` or `pwrite64` would, a bounded chunk at a
//!   time, through the owned backends or the descriptor's own open file
//!   description. No host `sendfile`, `splice` or `copy_file_range` runs.

use super::{ready, Backends, Descriptor, DescriptorCall, DescriptorTable, Handle};
use crate::dispatch::NativeDecision;
use crate::supervisor::{syscall3, syscall4, UserRegs};
use crate::tracee_io::{copy_memory, NativeFile};
use ginux_core::{
    copy_range_count, copy_range_files, fadvise_result, readahead_result, sendfile_input,
    sendfile_output, transfer_range, vectored_read_flags, vectored_read_form, xattr_call,
    xattr_flags_error, xattr_size_error, FileKind, FileView, SYS_COPY_FILE_RANGE, SYS_PREADV2,
    SYS_READAHEAD, TRANSFER_BOUND,
};

/// One transfer chunk, as the owned backends copy.
const CHUNK: usize = 4096;
/// The per-call bound of a console or device write, which a transfer into
/// one keeps.
const STREAM_BOUND: u64 = 4096;

/// What a transfer can do with one open descriptor.
enum Object {
    /// An inherited console descriptor. The supervisor's own descriptor of
    /// that number is the same open file description (see `select`).
    Console(usize),
    /// A registered image descriptor, through its own open file description.
    Native(NativeFile),
    /// An owned file.
    File(u32),
    /// An assigned device.
    Device(u32),
    /// A channel endpoint or TCP socket: not a transfer endpoint.
    Unserved,
}

struct Endpoint {
    view: FileView,
    object: Object,
}

impl Endpoint {
    /// Read at `position` without moving the shared offset, as `pread64`.
    fn read_at(
        &self,
        backends: &mut Backends,
        position: u64,
        output: &mut [u8],
    ) -> Result<usize, i64> {
        match &self.object {
            Object::Console(fd) => host_result(unsafe {
                syscall4(
                    17,
                    *fd,
                    output.as_mut_ptr() as usize,
                    output.len(),
                    position as usize,
                )
            }),
            Object::Native(file) => file.read_at(position, output),
            Object::File(handle) => backends.filesystem.transfer_read(*handle, position, output),
            Object::Device(_) | Object::Unserved => Err(-22),
        }
    }

    fn position(&self, backends: &mut Backends) -> Result<u64, i64> {
        match &self.object {
            Object::Console(fd) => host_result(unsafe { syscall3(8, *fd, 0, 1) }).map(|n| n as u64),
            Object::Native(file) => file.position(),
            Object::File(handle) => backends.filesystem.transfer_position(*handle),
            Object::Device(_) | Object::Unserved => Ok(0),
        }
    }

    fn seek(&self, backends: &mut Backends, position: u64) -> Result<(), i64> {
        match &self.object {
            Object::Console(fd) => {
                host_result(unsafe { syscall3(8, *fd, position as usize, 0) }).map(|_| ())
            }
            Object::Native(file) => file.seek(position),
            Object::File(handle) => backends.filesystem.transfer_seek(*handle, position),
            Object::Device(_) | Object::Unserved => Ok(()),
        }
    }

    /// Write as `write` (no position) or `pwrite64` would.
    fn write(
        &self,
        backends: &mut Backends,
        position: Option<u64>,
        input: &[u8],
    ) -> Result<usize, i64> {
        match &self.object {
            Object::Console(fd) => console_write(*fd, position, input),
            Object::File(handle) => backends.filesystem.transfer_write(*handle, position, input),
            Object::Device(handle) => backends.devices.transfer_write(*handle, input),
            // Image descriptors are never writable; other objects are not
            // transfer endpoints. Checks before any transfer refuse both.
            Object::Native(_) => Err(-9),
            Object::Unserved => Err(-22),
        }
    }

    /// Whether `sendfile` writes into this object.
    fn served(&self) -> bool {
        matches!(
            self.object,
            Object::Console(_) | Object::File(_) | Object::Device(_)
        )
    }

    /// The most bytes one call writes here.
    fn bound(&self) -> u64 {
        match self.object {
            Object::File(_) => TRANSFER_BOUND,
            _ => STREAM_BOUND,
        }
    }
}

impl Backends<'_> {
    /// The view of an owned handle from the backend that owns it.
    fn owned_view(&mut self, handle: u32) -> Result<FileView, i64> {
        if (1048576..1048640).contains(&handle) {
            self.filesystem.file_view(handle)
        } else if crate::network_hooks::LaunchNetwork::owns(handle) {
            self.devices.network.file_view(handle)
        } else if (0x4000_0000..0x4000_0040).contains(&handle) {
            self.devices.file_view(handle)
        } else if (crate::channel_hooks::PIPE_FD_BASE..0x4000_0000).contains(&handle) {
            self.channels.file_view(handle)
        } else {
            Err(-9)
        }
    }
}

impl DescriptorTable {
    /// An open descriptor that may carry data. Linux looks these calls'
    /// descriptors up with `fdget`, which refuses an `O_PATH` reference with
    /// EBADF like a closed number.
    fn data_descriptor(&self, fd: u64) -> Result<Descriptor, i64> {
        let entry = self.get(fd)?;
        if entry.path_flags != 0 {
            return Err(-9);
        }
        Ok(entry)
    }

    fn endpoint(pid: usize, entry: Descriptor, backends: &mut Backends) -> Result<Endpoint, i64> {
        Ok(match entry.handle {
            Handle::Native { fd, console: true } => {
                assert!(fd < 3);
                Endpoint {
                    view: crate::tracee_io::file_view(fd as usize)?,
                    object: Object::Console(fd as usize),
                }
            }
            Handle::Native { fd, .. } => {
                let file = NativeFile::open(pid, fd)?;
                Endpoint {
                    view: file.view()?,
                    object: Object::Native(file),
                }
            }
            Handle::Owned(handle) => Endpoint {
                view: backends.owned_view(handle)?,
                object: if (1048576..1048640).contains(&handle) {
                    Object::File(handle)
                } else if (0x4000_0000..0x4000_0040).contains(&handle) {
                    Object::Device(handle)
                } else {
                    Object::Unserved
                },
            },
            Handle::Reserved | Handle::OpeningFifo(_) => return Err(-9),
        })
    }

    /// `preadv` and `preadv2`, as the `preadv` or `readv` they are. The
    /// offset is checked before the descriptor and the flags after it, as
    /// Linux does; the plain form then takes the descriptor owner's ordinary
    /// path, so every backend answers with its own `readv` or `pread64`
    /// semantics and bounds. The caller saved the registers; they return at
    /// the matching exit.
    pub(super) fn vectored_read(
        &mut self,
        pid: usize,
        signal_tgid: usize,
        r: &mut UserRegs,
        backends: &mut Backends,
        call: &mut DescriptorCall,
    ) -> Result<NativeDecision, i64> {
        let form = vectored_read_form(r.orig_rax, r.r10)?;
        let flags = if r.orig_rax == SYS_PREADV2 { r.r9 } else { 0 };
        let entry = call.pinned.map(Ok).unwrap_or_else(|| self.get(r.rdi))?;
        if entry.path_flags != 0 {
            return Err(-9);
        }
        vectored_read_flags(flags)?;
        r.orig_rax = form;
        // x86-64 ignores preadv's high offset word; no flags remain.
        r.r8 = 0;
        r.r9 = 0;
        let decision = self.descriptor(pid, signal_tgid, r, entry, backends, call)?;
        // Every owned backend answers preadv itself; an owned handle never
        // reaches the kernel as a descriptor number.
        if matches!(entry.handle, Handle::Owned(_))
            && matches!(decision, NativeDecision::Contract(_))
        {
            return Err(-9);
        }
        Ok(decision)
    }

    /// `readahead` and `fadvise64`: Linux's answer for the descriptor, with
    /// no read, no page-cache change and no other host effect.
    pub(super) fn advice(
        &self,
        pid: usize,
        r: &UserRegs,
        backends: &mut Backends,
    ) -> Result<NativeDecision, i64> {
        let entry = self.data_descriptor(r.rdi)?;
        let view = Self::endpoint(pid, entry, backends)?.view;
        Ok(ready(if r.orig_rax == SYS_READAHEAD {
            readahead_result(view)
        } else {
            fadvise_result(view.kind, r.rdx, r.r10)
        }))
    }

    /// The xattr calls of a filesystem without extended attributes. Names,
    /// values and flags are checked as Linux checks them; a descriptor form
    /// then answers once its descriptor is open, and a path form resolves its
    /// path exactly as `stat` (or `lstat`) does, as the `faccessat2(AT_FDCWD,
    /// path, F_OK, flags)` it is rewritten to, through every backend and the
    /// shared image path mediation. Only a successful resolution becomes the
    /// call's answer. Nothing reads, lists, sets or removes a host attribute.
    pub(super) fn xattr(
        &mut self,
        pid: usize,
        r: &mut UserRegs,
        backends: &mut Backends,
        call: &mut DescriptorCall,
    ) -> Result<NativeDecision, i64> {
        let xattr = xattr_call(r.orig_rax).ok_or(-38)?;
        let Some(follow) = xattr.follow else {
            self.data_descriptor(r.rdi)?;
            xattr_arguments(pid, xattr, r)?;
            return Ok(ready(xattr.result));
        };
        xattr_arguments(pid, xattr, r)?;
        const AT_FDCWD: u64 = -100i64 as u64;
        const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
        r.orig_rax = 439;
        r.rsi = r.rdi;
        r.rdi = AT_FDCWD;
        r.rdx = 0;
        r.r10 = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };
        call.success = Some(xattr.result);
        self.path_descriptor(pid, r, backends)
    }

    /// `sendfile` and `copy_file_range`: a bounded read of the input
    /// composed with a write of the output, never more than `pread64` on the
    /// input and `write`/`pwrite64` on the output could do.
    pub(super) fn transfer(
        &mut self,
        pid: usize,
        signal_tgid: usize,
        r: &UserRegs,
        backends: &mut Backends,
        call: &mut DescriptorCall,
    ) -> Result<NativeDecision, i64> {
        if r.orig_rax == SYS_COPY_FILE_RANGE {
            return self.copy_range(pid, r, backends).map(ready);
        }
        // Linux reads the offset first and always stores it back, unchanged
        // when the transfer fails.
        let offset = r.rdx;
        let from = if offset != 0 {
            Some(read_offset(pid, offset)?)
        } else {
            None
        };
        let (result, position) = match self.sendfile(pid, signal_tgid, r, from, backends) {
            Ok(Sent::Done(count, position)) => (count, position),
            Ok(Sent::Wait) => {
                call.poll_wait = true;
                call.poll_tick = true;
                return Ok(NativeDecision::ParkPoll);
            }
            Err(error) => (error, from.unwrap_or(0)),
        };
        if offset != 0 && write_offset(pid, offset, position).is_err() {
            return Err(-14);
        }
        Ok(ready(result))
    }

    fn sendfile(
        &self,
        pid: usize,
        signal_tgid: usize,
        r: &UserRegs,
        from: Option<u64>,
        backends: &mut Backends,
    ) -> Result<Sent, i64> {
        let input = Self::endpoint(pid, self.data_descriptor(r.rsi)?, backends)?;
        sendfile_input(input.view, from.is_some())?;
        // Only a regular input can be transferred; any other is refused
        // below, so its position never matters.
        let start = match from {
            Some(position) => position,
            None if matches!(input.view.kind, FileKind::Regular | FileKind::Block) => {
                input.position(backends)?
            }
            None => 0,
        };
        let count = transfer_range(start, r.r10)?;
        let output = Self::endpoint(pid, self.data_descriptor(r.rdi)?, backends)?;
        sendfile_output(input.view, output.view, output.served())?;
        if let Object::Console(fd) = output.object {
            if !console_writable(fd)? {
                return if console_nonblocking(fd)? {
                    Err(-11)
                } else {
                    Ok(Sent::Wait)
                };
            }
        }
        let bound = count.min(output.bound());
        let moved = move_bytes(backends, &input, start, &output, None, bound)
            .inspect_err(|error| pipe_signal(*error, signal_tgid, pid))?;
        let end = start + moved;
        if from.is_none() {
            input.seek(backends, end)?;
        }
        Ok(Sent::Done(moved as i64, end))
    }

    fn copy_range(&self, pid: usize, r: &UserRegs, backends: &mut Backends) -> Result<i64, i64> {
        let input = self.data_descriptor(r.rdi)?;
        let output = self.data_descriptor(r.rdx)?;
        let from = if r.rsi != 0 {
            Some(read_offset(pid, r.rsi)?)
        } else {
            None
        };
        let to = if r.r10 != 0 {
            Some(read_offset(pid, r.r10)?)
        } else {
            None
        };
        let input = Self::endpoint(pid, input, backends)?;
        let output = Self::endpoint(pid, output, backends)?;
        copy_range_files(input.view, output.view, r.r9)?;
        // Only regular owned files and inherited regular console files get
        // here, as an output must be open for writing.
        let start = match from {
            Some(position) => position,
            None => input.position(backends)?,
        };
        let target = match to {
            Some(position) => position,
            None => output.position(backends)?,
        };
        let count = copy_range_count(input.view, start, output.view, target, r.r8)?;
        if count == 0 {
            return Ok(0);
        }
        let bound = count.min(output.bound());
        let moved = move_bytes(backends, &input, start, &output, Some(target), bound)?;
        let mut result = moved as i64;
        if moved != 0 {
            match from {
                Some(_) => {
                    if write_offset(pid, r.rsi, start + moved).is_err() {
                        result = -14;
                    }
                }
                None => input.seek(backends, start + moved)?,
            }
            match to {
                Some(_) => {
                    if write_offset(pid, r.r10, target + moved).is_err() {
                        result = -14;
                    }
                }
                None => output.seek(backends, target + moved)?,
            }
        }
        Ok(result)
    }
}

enum Sent {
    /// The result and the input position after it.
    Done(i64, u64),
    /// A blocking console output has no room yet; retry when it does.
    Wait,
}

/// Move up to `bound` bytes from `input` at `start` to `output` (at `target`
/// when given), a chunk at a time. Stops at end of input or a short write;
/// an error ends the call only before the first byte, as a short count
/// afterwards.
fn move_bytes(
    backends: &mut Backends,
    input: &Endpoint,
    start: u64,
    output: &Endpoint,
    target: Option<u64>,
    bound: u64,
) -> Result<u64, i64> {
    let mut buffer = [0u8; CHUNK];
    let mut moved = 0u64;
    while moved < bound {
        let want = (bound - moved).min(CHUNK as u64) as usize;
        let read = match input.read_at(backends, start + moved, &mut buffer[..want]) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) if moved != 0 => break,
            Err(error) => return Err(error),
        };
        let written = match output.write(backends, target.map(|to| to + moved), &buffer[..read]) {
            Ok(written) => written.min(read),
            Err(_) if moved != 0 => break,
            Err(error) => return Err(error),
        };
        moved += written as u64;
        if written < read || read < want {
            break;
        }
    }
    Ok(moved)
}

/// The set forms' flags, name, size and value, or a named form's name, in
/// Linux's order. List forms take no name.
fn xattr_arguments(pid: usize, xattr: ginux_core::XattrCall, r: &UserRegs) -> Result<(), i64> {
    if xattr.value {
        if let Some(error) = xattr_flags_error(r.r8) {
            return Err(error);
        }
    }
    if xattr.named {
        if let Some(error) = crate::tracee_io::xattr_name_error(pid, r.rsi) {
            return Err(error);
        }
    }
    if xattr.value {
        if let Some(error) = xattr_size_error(r.r10) {
            return Err(error);
        }
        if r.r10 != 0 && !crate::tracee_io::readable(pid, r.rdx, r.r10) {
            return Err(-14);
        }
    }
    Ok(())
}

fn read_offset(pid: usize, address: u64) -> Result<u64, i64> {
    let mut bytes = [0u8; 8];
    if copy_memory(pid, address, &mut bytes, false)? != 8 {
        return Err(-14);
    }
    Ok(u64::from_ne_bytes(bytes))
}

fn write_offset(pid: usize, address: u64, value: u64) -> Result<(), i64> {
    let mut bytes = value.to_ne_bytes();
    if copy_memory(pid, address, &mut bytes, true)? != 8 {
        return Err(-14);
    }
    Ok(())
}

/// Whether a console write would not wait now. A regular file always is.
fn console_writable(fd: usize) -> Result<bool, i64> {
    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }
    let mut poll = PollFd {
        fd: fd as i32,
        events: 4,
        revents: 0,
    };
    host_result(unsafe { syscall3(7, &mut poll as *mut PollFd as usize, 1, 0) })?;
    // POLLOUT, or POLLERR/POLLHUP: the write itself then reports the error.
    Ok(poll.revents & (4 | 8 | 16) != 0)
}

fn console_nonblocking(fd: usize) -> Result<bool, i64> {
    host_result(unsafe { syscall3(72, fd, 3, 0) }).map(|flags| flags & 0o4000 != 0)
}

/// A console write of at most 4096 bytes. SIGPIPE is held while the
/// supervisor writes, so a closed console reader ends only the caller's
/// transfer (EPIPE, then SIGPIPE to the caller by `pipe_signal`), never the
/// supervisor.
fn console_write(fd: usize, position: Option<u64>, input: &[u8]) -> Result<usize, i64> {
    const SIGPIPE_SET: u64 = 1 << (13 - 1);
    let count = input.len().min(STREAM_BOUND as usize);
    let held = SIGPIPE_SET;
    let mut previous = 0u64;
    unsafe {
        crate::supervisor::syscall4(
            14,
            0,
            &held as *const u64 as usize,
            &mut previous as *mut u64 as usize,
            8,
        );
    }
    let result = match position {
        Some(position) => unsafe {
            syscall4(18, fd, input.as_ptr() as usize, count, position as usize)
        },
        None => unsafe { syscall3(1, fd, input.as_ptr() as usize, count) },
    };
    if result == -32 {
        let zero = [0u64; 2];
        unsafe {
            crate::supervisor::syscall4(
                128,
                &held as *const u64 as usize,
                0,
                zero.as_ptr() as usize,
                8,
            );
        }
    }
    unsafe {
        crate::supervisor::syscall4(14, 2, &previous as *const u64 as usize, 0, 8);
    }
    host_result(result)
}

/// A transfer that found its output's reader gone delivers SIGPIPE to its
/// caller, as Linux and an owned channel write do.
fn pipe_signal(error: i64, signal_tgid: usize, pid: usize) {
    if error == -32 {
        let _ = unsafe { syscall3(crate::supervisor::SYS_TGKILL, signal_tgid, pid, 13) };
    }
}

fn host_result(value: isize) -> Result<usize, i64> {
    if value < 0 {
        Err(value as i64)
    } else {
        Ok(value as usize)
    }
}
