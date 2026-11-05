//! Native process-lane dispatch hooks.
//!
//! Owner: G-process lane. G03 mediates the raw fork entry through the
//! supervision loop's fork-event path; G03a extends the same path to the
//! remaining libc process-creation variants. Raw `clone` (56) is what glibc
//! `fork()` emits, and the `posix_spawn`/`system` fallback after a denied
//! `clone3` is `clone` with `CLONE_VM|CLONE_VFORK`; raw `vfork` (58) is the
//! classic third spelling. All three create ordinary parent/child process
//! pairs, so the host call executes and the supervisor creates the virtual
//! child from the corresponding `PTRACE_EVENT_*` stop, rewriting the
//! parent's observed result to the virtual pid. `clone` with `CLONE_THREAD`
//! is thread creation, which stays with G04, and `clone` with `CLONE_VM`
//! but without `CLONE_VFORK` shares the parent's memory concurrently: both
//! fail explicitly with `-ENOSYS` and no host child is created. `clone3`
//! (435) is left for a follow-up and keeps the existing explicit `-ENOSYS`
//! denial, which is what makes glibc fall back to `clone`.
//!
//! G03b extends the same path to executable replacement. `execve` (59) and
//! the plain `execveat` variant (dirfd `AT_FDCWD`, zero flags) execute on the
//! host with supervision still attached; the supervisor records the virtual
//! transition from the `PTRACE_EVENT_EXEC` stop, so the task keeps its
//! virtual identity (same pid, bumped exec epoch, reset signal state) and is
//! never detached. Other `execveat` shapes need descriptor-table plumbing
//! from G05a/G07 and fail explicitly with `-ENOSYS` without executing.

use crate::supervisor::{ENOSYS, SYS_FORK};

/// Raw clone entry: what glibc `fork()` and the `posix_spawn` fallback emit.
pub const SYS_CLONE: u64 = 56;
/// Raw vfork entry: classic process-creation spelling, parent-blocked.
pub const SYS_VFORK: u64 = 58;
/// Raw execve entry: replaces the calling task's image, same pid.
pub const SYS_EXECVE: u64 = 59;
/// Raw execveat entry: dirfd-relative executable replacement.
pub const SYS_EXECVEAT: u64 = 322;

/// `AT_FDCWD` dirfd: resolve the path against the working directory.
pub const AT_FDCWD: u64 = (-100i64) as u64;

/// `CLONE_THREAD` flag (bit 16): thread-group creation belongs to G04.
pub const CLONE_THREAD: u64 = 0x0001_0000;
/// `CLONE_VM` flag (bit 8): child shares the parent's address space.
pub const CLONE_VM: u64 = 0x0000_0100;
/// `CLONE_VFORK` flag (bit 14): parent stays blocked until the child
/// releases shared memory by exiting or executing.
pub const CLONE_VFORK: u64 = 0x0000_4000;

/// Ptrace fork-event stops delivered for the three mediated entries.
pub const PTRACE_EVENT_VFORK: usize = 2;
pub const PTRACE_EVENT_CLONE: usize = 3;

/// Ptrace options requesting the vfork/clone event stops alongside fork.
/// Each option is the event number as a bit, per `linux/ptrace.h`.
pub const PTRACE_O_TRACECLONE: usize = 1 << PTRACE_EVENT_CLONE;
pub const PTRACE_O_TRACEVFORK: usize = 1 << PTRACE_EVENT_VFORK;

/// Lane membership by syscall number: the three process-creation entries
/// plus the two executable-replacement entries belong to the process lane.
/// Other entries stay with the supervision loop's existing match until their
/// owning tasks claim them.
pub fn claims(syscall: u64) -> bool {
    syscall == SYS_FORK as u64
        || syscall == SYS_CLONE
        || syscall == SYS_VFORK
        || syscall == SYS_EXECVE
        || syscall == SYS_EXECVEAT
}

/// Emulated result when this lane handles the entry. Process creation and
/// executable replacement are mediated, not emulated: `None` falls through
/// to the supervision loop, which lets the host call execute and translates
/// the outcome via the fork-event or exec-event path. Two `clone` shapes
/// never execute and fail explicitly with `-ENOSYS`: thread creation
/// (`CLONE_THREAD` set, which stays with G04) and concurrent address-space
/// sharing (`CLONE_VM` without `CLONE_VFORK`, which has no managed-task
/// representation because the child runs alongside the parent in the same
/// memory). `execveat` shapes beyond the plain variant are gated by
/// [`exec_mediated`], which the supervision loop consults because it sees
/// the flags register this hook does not receive.
pub fn claim(syscall: u64, rdi: u64, _rsi: u64, _rdx: u64) -> Option<i64> {
    if syscall == SYS_CLONE
        && ((rdi & CLONE_THREAD) != 0 || (rdi & (CLONE_VM | CLONE_VFORK)) == CLONE_VM)
    {
        return Some(-ENOSYS);
    }
    None
}

/// Whether an executable-replacement entry executes under supervision.
/// Plain `execve` and `execveat(AT_FDCWD, path, argv, envp, 0)` are mediated:
/// the host kernel performs shebang and loader transitions with the tracee
/// still attached. Any other `execveat` shape (non-CWD dirfd, or nonzero
/// flags such as `AT_EMPTY_PATH`) needs descriptor-table plumbing from
/// G05a/G07 and is denied so it never executes on the host.
pub fn exec_mediated(syscall: u64, dirfd: u64, flags: u64) -> bool {
    if syscall == SYS_EXECVE {
        return true;
    }
    if syscall == SYS_EXECVEAT {
        return dirfd == AT_FDCWD && flags == 0;
    }
    false
}
