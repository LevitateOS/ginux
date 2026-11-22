//! Outcome record for `native CONFIG ROOT configured --result-file PATH`.
//!
//! Owner: G-launch. When a result path is given, the supervisor writes one
//! version-1 record to it at the single normal exit of `supervise_native`,
//! after the workload's root task is gone:
//! {"version":1,"outcome":"exited|signaled","code":<u8|null>,
//!  "signal":<u8|null>,"generation":null}
//! The file is created with O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600, written,
//! synced and closed. Any failure prints a `ginux:` line on fd 2 and exits 1,
//! so the record is absent: a caller reads absence as a supervisor error.
//! Every other runtime exit (supervisor failure, panic) leaves no record.
//! Hooks never get a result path. Without the option nothing here runs.

use crate::launch::line_stderr;
use crate::supervisor::{
    exit_process, syscall1, syscall3, syscall4, AT_FDCWD, SYS_CLOSE_HOST, SYS_FSYNC,
    SYS_OPENAT_HOST, SYS_WRITE_HOST,
};
use core::sync::atomic::{AtomicUsize, Ordering};

const O_WRONLY: usize = 0o1;
const O_CREAT: usize = 0o100;
const O_EXCL: usize = 0o200;
const O_NOFOLLOW: usize = 0o400000;
const O_CLOEXEC: usize = 0o2000000;
const SYS_NEWFSTATAT_HOST: usize = 262;
const AT_SYMLINK_NOFOLLOW: usize = 0x100;
const ENOENT: isize = 2;
const EINTR: isize = 4;

/// The result path from argv (a NUL-terminated string on the initial stack,
/// valid for the life of the process), or 0 when no path was given.
static RESULT_PATH: AtomicUsize = AtomicUsize::new(0);

/// Store the result path before the workload starts. A path that already
/// exists (as anything, a symlink included) or cannot be checked is refused
/// here, so no workload runs for an invocation that could never record its
/// outcome. The exclusive create in `finish` still decides.
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

/// Record the root task's raw wait `status` when a result path is stored.
/// Returns normally only when no path is stored or the record is durable.
pub fn finish(status: i32) {
    let path = RESULT_PATH.load(Ordering::Relaxed);
    if path == 0 {
        return;
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

    let descriptor = unsafe {
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
    let descriptor = descriptor as usize;
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
    if synced < 0 || closed < 0 {
        line_stderr(b"ginux: result-file sync or close failed");
        exit_process(1);
    }
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
