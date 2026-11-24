//! Outcome record for `native CONFIG ROOT configured --result-file PATH`.
//!
//! Owner: G-launch. When a result path is given, the supervisor creates the
//! file while it still has the caller's identity, before the tracee is
//! forked and before `reduce_native_supervisor_authority` drops to the
//! managed host identity (which cannot create files in a root-owned 0700
//! directory). It keeps the descriptor and writes one version-1 record
//! through it at the single normal exit of `supervise_native`, after the
//! workload's root task is gone:
//! {"version":1,"outcome":"exited|signaled","code":<u8|null>,
//!  "signal":<u8|null>,"generation":null}
//! followed by a newline, then syncs and closes it.
//!
//! The file is created with O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, mode 0600.
//! Once the run has started the file therefore always exists: a reader must
//! treat an empty file, or one without a complete newline-terminated record,
//! as a supervisor error. Every runtime exit other than the normal one
//! (supervisor failure, panic, a kill) leaves it empty; a write, sync or
//! close failure prints a `ginux:` line on fd 2 and exits 1 with the file
//! empty or incomplete. Hooks never get a result path. Without the option
//! nothing here runs.
//!
//! The descriptor never reaches the workload: the tracee closes every
//! descriptor from 3 up with `close_range` before it does anything else, and
//! O_CLOEXEC would drop it at exec regardless. The supervisor's own
//! descriptor sweep in `reduce_native_supervisor_authority` keeps it, and the
//! supervisor's broker children close their copy at once.

use crate::launch::line_stderr;
use crate::supervisor::{
    exit_process, syscall1, syscall2, syscall3, syscall4, AT_FDCWD, SYS_CLOSE_HOST, SYS_FSTAT,
    SYS_FSYNC, SYS_OPENAT_HOST, SYS_WRITE_HOST,
};
use core::sync::atomic::{AtomicIsize, AtomicU64, AtomicUsize, Ordering};

const O_WRONLY: usize = 0o1;
const O_CREAT: usize = 0o100;
const O_EXCL: usize = 0o200;
const O_NOFOLLOW: usize = 0o400000;
const O_CLOEXEC: usize = 0o2000000;
const SYS_NEWFSTATAT_HOST: usize = 262;
const SYS_FCNTL_HOST: usize = 72;
const F_DUPFD_CLOEXEC: usize = 1030;
const AT_SYMLINK_NOFOLLOW: usize = 0x100;
const ENOENT: isize = 2;
const EINTR: isize = 4;
/// The optional controller channel the supervisor probes by number.
const CONTROL_FD: isize = 10;
/// `reduce_native_supervisor_authority` closes everything from here up.
const SWEEP_LIMIT: isize = 256;

/// The result path from argv (a NUL-terminated string on the initial stack,
/// valid for the life of the process), or 0 when no path was given.
static RESULT_PATH: AtomicUsize = AtomicUsize::new(0);
/// The open result file, or -1.
static RESULT_FD: AtomicIsize = AtomicIsize::new(-1);
/// Device and inode of the created file, checked again before writing.
static RESULT_DEVICE: AtomicU64 = AtomicU64::new(0);
static RESULT_INODE: AtomicU64 = AtomicU64::new(0);

/// Store the result path before the workload starts. A path that already
/// exists (as anything, a symlink included) or cannot be checked is refused
/// here, before the configuration is read. The exclusive create in `open`
/// still decides.
pub fn set(path: *const u8) {
    let mut status = [0u8; 144];
    let checked = unsafe {
        syscall4(
            SYS_NEWFSTATAT_HOST,
            AT_FDCWD,
            path as usize,
            status.as_mut_ptr() as usize,
            AT_SYMLINK_NOFOLLOW,
        )
    };
    if checked != -ENOENT {
        line_stderr(b"ginux: result-file path is not fresh or not creatable");
        exit_process(1);
    }
    RESULT_PATH.store(path as usize, Ordering::Relaxed);
}

/// Create the result file when a path is stored. Call it once the standard
/// streams are known to be open (so the descriptor cannot take 0 to 2) and
/// before the tracee is forked and the supervisor drops its identity. Any
/// failure exits 1 before a workload runs.
pub fn open() {
    let path = RESULT_PATH.load(Ordering::Relaxed);
    if path == 0 {
        return;
    }
    let mut descriptor = unsafe {
        syscall4(
            SYS_OPENAT_HOST,
            AT_FDCWD,
            path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        line_stderr(b"ginux: result-file path is not fresh or not creatable");
        exit_process(1);
    }
    // Keep off the controller number, which the supervisor probes, and below
    // the authority sweep, which would close it.
    if descriptor == CONTROL_FD || descriptor >= SWEEP_LIMIT {
        let moved = unsafe {
            syscall3(
                SYS_FCNTL_HOST,
                descriptor as usize,
                F_DUPFD_CLOEXEC,
                CONTROL_FD as usize + 1,
            )
        };
        let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
        if !(0..SWEEP_LIMIT).contains(&moved) {
            if moved >= 0 {
                let _ = unsafe { syscall1(SYS_CLOSE_HOST, moved as usize) };
            }
            line_stderr(b"ginux: result-file descriptor reservation failed");
            exit_process(1);
        }
        descriptor = moved;
    }
    let Some((device, inode)) = identity(descriptor as usize) else {
        let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
        line_stderr(b"ginux: result-file descriptor reservation failed");
        exit_process(1);
    };
    RESULT_DEVICE.store(device, Ordering::Relaxed);
    RESULT_INODE.store(inode, Ordering::Relaxed);
    RESULT_FD.store(descriptor, Ordering::Relaxed);
}

/// The open result descriptor, or `usize::MAX` when there is none.
pub fn descriptor() -> usize {
    let descriptor = RESULT_FD.load(Ordering::Relaxed);
    if descriptor < 0 {
        usize::MAX
    } else {
        descriptor as usize
    }
}

/// In a child forked from the supervisor that never records the outcome:
/// close this process's copy of the result descriptor.
pub fn close_in_child() {
    let descriptor = RESULT_FD.load(Ordering::Relaxed);
    if descriptor >= 0 {
        let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
        RESULT_FD.store(-1, Ordering::Relaxed);
    }
}

/// Record the root task's raw wait `status` when a result file is open.
/// Returns normally only when no file is open or the record is durable.
pub fn finish(status: i32) {
    let descriptor = RESULT_FD.load(Ordering::Relaxed);
    if descriptor < 0 {
        return;
    }
    let descriptor = descriptor as usize;
    // The number must still name the file created at start, not another
    // object that took it after an accidental close.
    if identity(descriptor)
        != Some((
            RESULT_DEVICE.load(Ordering::Relaxed),
            RESULT_INODE.load(Ordering::Relaxed),
        ))
    {
        line_stderr(b"ginux: result-file descriptor lost");
        exit_process(1);
    }
    let mut record = [0u8; 96];
    let mut length = 0usize;
    push(&mut record, &mut length, b"{\"version\":1,\"outcome\":");
    if status & 0x7f == 0 {
        push(&mut record, &mut length, b"\"exited\",\"code\":");
        push_decimal(&mut record, &mut length, ((status >> 8) & 0xff) as u8);
        push(&mut record, &mut length, b",\"signal\":null");
    } else {
        push(
            &mut record,
            &mut length,
            b"\"signaled\",\"code\":null,\"signal\":",
        );
        push_decimal(&mut record, &mut length, (status & 0x7f) as u8);
    }
    push(&mut record, &mut length, b",\"generation\":null}\n");

    let mut offset = 0usize;
    while offset < length {
        let written = unsafe {
            syscall3(
                SYS_WRITE_HOST,
                descriptor,
                record.as_ptr().add(offset) as usize,
                length - offset,
            )
        };
        if written == -EINTR {
            continue;
        }
        if written <= 0 {
            let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor) };
            line_stderr(b"ginux: result-file write failed");
            exit_process(1);
        }
        offset += written as usize;
    }
    let synced = loop {
        let result = unsafe { syscall1(SYS_FSYNC, descriptor) };
        if result != -EINTR {
            break result;
        }
    };
    let closed = unsafe { syscall1(SYS_CLOSE_HOST, descriptor) };
    RESULT_FD.store(-1, Ordering::Relaxed);
    if synced < 0 || closed < 0 {
        line_stderr(b"ginux: result-file sync or close failed");
        exit_process(1);
    }
}

/// Device and inode of an open descriptor (x86_64 struct stat: st_dev and
/// st_ino are the first two u64 fields).
fn identity(descriptor: usize) -> Option<(u64, u64)> {
    let mut status = [0u64; 18];
    if unsafe { syscall2(SYS_FSTAT, descriptor, status.as_mut_ptr() as usize) } < 0 {
        return None;
    }
    Some((status[0], status[1]))
}

fn push(buffer: &mut [u8], length: &mut usize, bytes: &[u8]) {
    for &byte in bytes {
        buffer[*length] = byte;
        *length += 1;
    }
}

fn push_decimal(buffer: &mut [u8], length: &mut usize, value: u8) {
    if value >= 100 {
        push(buffer, length, &[b'0' + value / 100]);
    }
    if value >= 10 {
        push(buffer, length, &[b'0' + value / 10 % 10]);
    }
    push(buffer, length, &[b'0' + value % 10]);
}
