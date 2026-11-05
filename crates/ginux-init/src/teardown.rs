//! Domain teardown for the native process supervision loop.
//!
//! Owner: G-process/lifecycle (L01). When the root workload dies or the host
//! asks the supervisor to stop, the loop funnels through a full teardown:
//! SIGKILL every still-traced descendant, reap each host death, release
//! every descriptor-mirror end, run the storage/backends close seams, prove
//! the live-object audit is zero, then report the outcome and exit.
//!
//! Host cancellation uses raw `rt_sigaction` (no libc): `SIGTERM`/`SIGINT`
//! run a flag-only handler installed *without* `SA_RESTART`, so a blocking
//! `wait4` in the supervision loop returns `EINTR` and the loop tears down
//! instead of dying with descendants still traced. `PTRACE_O_EXITKILL` (set
//! by the loop on every attached tracee) remains the backstop: if the
//! supervisor itself dies, the kernel SIGKILLs every tracee, so no
//! descendant survives a supervisor loss either.
//!
//! Storage flush is a seam for G12a: [`flush_storage_seam`] is the call site
//! the durable-flush owner implements; it performs no I/O here. Assigned
//! device/backends close through [`close_backends_seam`]; no backend
//! registry is attached to this loop yet, so the seam records zero closes.

use crate::supervisor::{ptrace, syscall2, syscall4, PTRACE_KILL};

pub const SYS_RT_SIGACTION: usize = 13;
pub const SYS_RT_SIGRETURN: usize = 15;
pub const SYS_KILL: usize = 62;
pub const SIGINT: usize = 2;
pub const SIGTERM: usize = 15;
pub const SIGKILL: usize = 9;
pub const SA_RESTORER: usize = 0x04000000;
pub const EINTR: isize = 4;

/// Exit code after a host cancellation (128 + SIGTERM).
pub const CANCEL_EXIT: usize = 143;
/// Exit code for startup failures (mirrors the G02 `startup` convention).
pub const STARTUP_EXIT: usize = 2;
/// Exit code for mid-run supervision failures.
pub const SUPERVISOR_EXIT: usize = 1;

/// Set by the cancellation handler; polled by the supervision loop. A single
/// byte store from the handler is all the handler ever does.
pub static mut CANCEL_REQUESTED: u8 = 0;

unsafe extern "C" fn cancel_handler(_signal: i32) {
    unsafe {
        CANCEL_REQUESTED = 1;
    }
}

/// Return trampoline for the raw `rt_sigaction` install below. The kernel
/// transfers control here when the flag-only handler returns; it issues
/// `rt_sigreturn` and never comes back.
unsafe extern "C" fn sig_restore() {
    unsafe {
        crate::supervisor::syscall0(SYS_RT_SIGRETURN);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[repr(C)]
struct KernelSigaction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: usize,
}

fn install(signal: usize) -> bool {
    let action = KernelSigaction {
        handler: cancel_handler as *const () as usize,
        flags: SA_RESTORER,
        restorer: sig_restore as *const () as usize,
        mask: 0,
    };
    unsafe { syscall4(SYS_RT_SIGACTION, signal, &action as *const _ as usize, 0, 8) >= 0 }
}

/// Arm host cancellation: `SIGTERM`/`SIGINT` set the cancel flag instead of
/// killing the supervisor, with no `SA_RESTART` so a blocking `wait4`
/// returns `EINTR`. Must run in the supervisor after its tracee fork, never
/// before: the tracee's post-`execve` dispositions stay at their defaults.
pub fn arm_cancel_signals() -> bool {
    install(SIGTERM) && install(SIGINT)
}

/// True once the host has asked the supervisor to stop.
pub fn cancel_requested() -> bool {
    unsafe { CANCEL_REQUESTED != 0 }
}

/// True when a raw `wait4` result is an interrupted call with a host
/// cancellation pending: the loop must tear down, not fail.
pub fn is_cancel_wait(wait_result: isize) -> bool {
    wait_result == -EINTR && cancel_requested()
}

/// SIGKILL every host pid still under supervision. Delivery races are
/// resolved by the reap drain, so per-target errors are ignored: an
/// already-dead target is reaped, not signalled.
pub fn kill_remaining(host_pids: &[usize]) {
    for pid in host_pids {
        let _ = ptrace(PTRACE_KILL, *pid, 0, 0);
        let _ = unsafe { syscall2(SYS_KILL, *pid, SIGKILL) };
    }
}

/// What the teardown drain reports once every descendant is reaped.
pub enum TeardownOutcome {
    /// The root workload exited; carries its code (0 completes cleanly,
    /// anything else is a `workload` failure per §1).
    Exited(i32),
    /// The root workload died by signal; carries the signal number.
    Signaled(u8),
    /// The host asked the supervisor to stop (`SIGTERM`/`SIGINT`).
    Cancelled,
}

/// Storage flush seam owned by G12a. The teardown drain calls this after the
/// last descendant is reaped and before reporting: the durable-flush owner
/// implements quiesce/flush/generation-publish here. No retained store is
/// attached to this loop yet, so the seam performs no I/O.
pub fn flush_storage_seam() {}

/// Assigned-backends close seam. Device/backends owners close every backend
/// assigned to the domain here once a registry is attached to this loop.
/// Returns the number of backends closed; none are attached yet.
pub fn close_backends_seam() -> usize {
    0
}
