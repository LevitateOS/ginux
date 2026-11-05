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
//! parent's observed result to the virtual pid. `clone` with `CLONE_VM`
//! but without `CLONE_VFORK` shares the parent's memory concurrently and
//! fails explicitly with `-ENOSYS` with no host child created. `clone3`
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
//!
//! G04 extends the same path to thread creation. `clone` carrying
//! `CLONE_THREAD` in the supported shape (shared memory and signal handlers,
//! no exit signal, no reparenting, no host namespaces, no untraceable
//! children; see [`thread_supported`]) executes on the host and the
//! supervisor creates the virtual thread from the `PTRACE_EVENT_CLONE` stop
//! through the existing [`ginx_process::ProcessTable::clone_thread`] managed
//! path: no parallel task model. The parent's observed return value and its
//! parent-tid cell are rewritten to the virtual tid, `gettid` (186) is
//! translated like `getpid`, and thread exit drops the host slot (threads
//! are joined over a futex, never reaped by `wait4`). Thread-local state the
//! C library needs around creation — TLS base (`arch_prctl`), the
//! exit-clear registration (`set_tid_address`, tid translated at the exit
//! stop), futex wait/wake on the thread group's own shared memory, robust
//! lists, and `rseq` — is mediated on the host: it touches only the calling
//! thread or its group's memory, so it is not a host escape. Thread shapes
//! outside [`thread_supported`] fail explicitly with `-ENOSYS` and never
//! execute.

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
/// `CLONE_SIGHAND` flag (bit 11): child shares the parent's signal handlers.
/// Required alongside `CLONE_VM` for every supported thread shape.
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
/// `CLONE_PARENT` flag (bit 15): child takes the caller's parent, which
/// would break managed ownership; thread shapes carrying it are denied.
pub const CLONE_PARENT: u64 = 0x0000_8000;
/// Host-namespace creation flags: a thread that also unshares host state has
/// no managed representation; thread shapes carrying any of them are denied.
pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;
pub const CLONE_NEWTIME: u64 = 0x0000_0080;
/// `CLONE_UNTRACED` flag (bit 23): an untraced child would escape
/// supervision; thread shapes carrying it are denied.
pub const CLONE_UNTRACED: u64 = 0x0080_0000;
/// Low byte of the clone flags: the child exit signal. Threads never carry
/// one; any nonzero value in a thread shape is denied.
pub const CLONE_EXIT_SIGNAL_MASK: u64 = 0x0000_00ff;

/// Raw `arch_prctl` entry: installs or reads the calling thread's TLS base.
/// Thread-local register state only; mediated for every subcommand.
pub const SYS_ARCH_PRCTL: u64 = 158;
/// Raw `gettid` entry: translated to the virtual tid like `getpid`.
pub const SYS_GETTID: u64 = 186;
/// Raw `futex` entry: wait/wake on the thread group's own shared memory.
/// The host kernel performs the blocking and wakeup, so join/mutex observe
/// real results; mediated for every op.
pub const SYS_FUTEX: u64 = 202;
/// Raw `set_tid_address` entry: per-thread exit-clear registration. The
/// returned tid is translated to the virtual tid at the exit stop.
pub const SYS_SET_TID_ADDRESS: u64 = 309;
/// Raw `set_robust_list` entry: per-thread robust-mutex registration in
/// tracee memory; mediated.
pub const SYS_SET_ROBUST_LIST: u64 = 311;
/// Raw `get_robust_list` entry: reads back the calling thread's own
/// registration; mediated.
pub const SYS_GET_ROBUST_LIST: u64 = 312;
/// Raw `rseq` entry: per-thread restartable-sequence registration in tracee
/// memory; mediated.
pub const SYS_RSEQ: u64 = 498;

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

/// Whether a `CLONE_THREAD` flag word names the one supported thread shape:
/// a thread-group member sharing memory and signal handlers (`CLONE_VM` +
/// `CLONE_SIGHAND`, the glibc `pthread_create` basis), without `CLONE_VFORK`
/// (parent blocking is meaningless inside a thread group), without an exit
/// signal, without reparenting (`CLONE_PARENT`), without host-namespace
/// creation, and without `CLONE_UNTRACED` (which would evade supervision).
/// The remaining sharing flags (`CLONE_FS`, `CLONE_FILES`), `CLONE_SYSVSEM`,
/// and the `CLONE_SETTLS` / `CLONE_PARENT_SETTID` / `CLONE_CHILD_CLEARTID`
/// tid plumbing are accepted in any combination: they stay inside the thread
/// group's own memory. Anything else with `CLONE_THREAD` fails explicitly
/// with `-ENOSYS` and never executes on the host.
pub fn thread_supported(flags: u64) -> bool {
    const NAMESPACES: u64 = CLONE_NEWNS
        | CLONE_NEWCGROUP
        | CLONE_NEWUTS
        | CLONE_NEWIPC
        | CLONE_NEWUSER
        | CLONE_NEWPID
        | CLONE_NEWNET
        | CLONE_NEWTIME;
    flags & CLONE_THREAD != 0
        && flags & (CLONE_VM | CLONE_SIGHAND) == (CLONE_VM | CLONE_SIGHAND)
        && flags & (CLONE_VFORK | CLONE_PARENT | CLONE_UNTRACED | NAMESPACES) == 0
        && flags & CLONE_EXIT_SIGNAL_MASK == 0
}

/// Emulated result when this lane handles the entry. Process creation,
/// supported thread creation, and executable replacement are mediated, not
/// emulated: `None` falls through to the supervision loop, which lets the
/// host call execute and translates the outcome via the fork-event, clone
/// thread-event, or exec-event path. Three `clone` shapes never execute and
/// fail explicitly with `-ENOSYS`: unsupported thread creation
/// (`CLONE_THREAD` set but outside [`thread_supported`]) and concurrent
/// address-space sharing (`CLONE_VM` without `CLONE_VFORK`, which has no
/// managed-task representation because the child runs alongside the parent
/// in the same memory). `execveat` shapes beyond the plain variant are gated
/// by [`exec_mediated`], which the supervision loop consults because it sees
/// the flags register this hook does not receive.
pub fn claim(syscall: u64, rdi: u64, _rsi: u64, _rdx: u64) -> Option<i64> {
    if syscall == SYS_CLONE {
        if (rdi & CLONE_THREAD) != 0 {
            return if thread_supported(rdi) {
                None
            } else {
                Some(-ENOSYS)
            };
        }
        if (rdi & (CLONE_VM | CLONE_VFORK)) == CLONE_VM {
            return Some(-ENOSYS);
        }
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
