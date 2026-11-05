//! Native process-lane dispatch hooks.
//!
//! Owner: G-process lane. G03 claims the raw fork entry for the process lane
//! and mediates it through the supervision loop's fork-event path: the host
//! fork executes, the supervisor creates the virtual child from
//! `PTRACE_EVENT_FORK`, and the parent's observed result is rewritten to the
//! virtual pid. Completion and ownership live in the supervision loop, which
//! records the real child status in the existing `ProcessTable` and returns
//! it through the parent's wait.

use crate::supervisor::SYS_FORK;

/// Lane membership by syscall number: the raw fork entry belongs to the
/// process lane. Other entries stay with the supervision loop's existing
/// match until their owning tasks claim them.
pub fn claims(syscall: u64) -> bool {
    syscall == SYS_FORK as u64
}

/// Emulated result when this lane handles the entry. Fork is mediated, not
/// emulated: `None` falls through to the supervision loop, which lets the
/// host fork execute and translates the outcome via the fork-event path.
pub fn claim(syscall: u64, rdi: u64, rsi: u64, rdx: u64) -> Option<i64> {
    let _ = (syscall, rdi, rsi, rdx);
    None
}
