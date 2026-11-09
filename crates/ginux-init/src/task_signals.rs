//! Signals and supervisor-held syscalls in configured native launch.
//!
//! The supervisor holds a task's syscall in three ways: parked at its entry
//! stop, replayed as bounded sleep quanta, or replaced by an injected private
//! transaction. This module owns what a signal means in each of them:
//!
//! - An injected transaction is atomic. `hold` blocks every blockable signal
//!   in the stopped tracee for its duration; the kernel keeps them pending
//!   and delivers them at the original syscall's boundary after `release`.
//! - A parked or sleeping call ends early only for a signal that runs a
//!   handler or ends the task. `Signals` answers that from the kernel's own
//!   per-task view. Ignored signals and supervisor-requested stops never
//!   surface in the guest result.
use crate::supervisor::ptrace;

const PTRACE_GETSIGMASK: usize = 0x420a;
const PTRACE_SETSIGMASK: usize = 0x420b;
const SIGNAL_SET_SIZE: usize = 8;

/// Restart results the kernel resolves against the task's signal action when
/// it delivers the interrupting signal (include/linux/errno.h).
pub const RESTART_SYSCALL: i64 = -512;
pub const RESTART_WITHOUT_HANDLER: i64 = -514;

/// Block every blockable signal in a stopped tracee. Returns its own mask.
pub fn hold(host: usize) -> Result<u64, isize> {
    let mut saved = 0u64;
    let result = ptrace(
        PTRACE_GETSIGMASK,
        host,
        SIGNAL_SET_SIZE,
        &mut saved as *mut _ as usize,
    );
    if result < 0 {
        return Err(result);
    }
    let all = u64::MAX;
    let result = ptrace(
        PTRACE_SETSIGMASK,
        host,
        SIGNAL_SET_SIZE,
        &all as *const _ as usize,
    );
    if result < 0 {
        return Err(result);
    }
    Ok(saved)
}

/// Restore the mask `hold` replaced. Pending signals are delivered when the
/// tracee next returns to user mode.
pub fn release(host: usize, saved: u64) -> Result<(), isize> {
    let result = ptrace(
        PTRACE_SETSIGMASK,
        host,
        SIGNAL_SET_SIZE,
        &saved as *const _ as usize,
    );
    if result < 0 {
        Err(result)
    } else {
        Ok(())
    }
}

/// One stopped task's signal state as the kernel reports it.
#[derive(Clone, Copy)]
pub struct Signals {
    pending: u64,
    blocked: u64,
    ignored: u64,
    caught: u64,
}

impl Signals {
    pub fn read(host: usize) -> Option<Self> {
        let mut text = [0u8; 4096];
        let length = crate::tracee_io::read_status(host, &mut text)?;
        Self::parse(&text[..length])
    }

    fn parse(text: &[u8]) -> Option<Self> {
        let field = |name: &[u8]| -> Option<u64> {
            let line = text
                .split(|byte| *byte == b'\n')
                .find(|line| line.starts_with(name))?;
            let digits = line[name.len()..].trim_ascii();
            if digits.len() != 16 {
                return None;
            }
            let mut value = 0u64;
            for digit in digits {
                value = value << 4 | (*digit as char).to_digit(16)? as u64;
            }
            Some(value)
        };
        Some(Self {
            pending: field(b"SigPnd:")? | field(b"ShdPnd:")?,
            blocked: field(b"SigBlk:")?,
            ignored: field(b"SigIgn:")?,
            caught: field(b"SigCgt:")?,
        })
    }

    /// Whether delivering `signal` runs a handler in this task.
    pub fn handled(&self, signal: usize) -> bool {
        (1..=64).contains(&signal) && self.caught & (1u64 << (signal - 1)) != 0
    }

    /// Whether a queued, unblocked signal would run a handler or end the
    /// task. A call held for such a signal must be handed back to the kernel;
    /// one the task ignores leaves the call held, as it would natively.
    pub fn interrupt_held_call(&self) -> bool {
        let deliverable = self.pending & !self.blocked;
        (1..=64u8).any(|signal| {
            let bit = 1u64 << (signal - 1);
            deliverable & bit != 0
                && (self.caught & bit != 0
                    || self.ignored & bit == 0 && crate::fatal_default_signal(signal))
        })
    }
}
