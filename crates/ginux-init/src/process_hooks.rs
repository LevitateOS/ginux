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
//!
//! G05 owns child waits and termination signals in the supervision loop
//! (not in this lane hook, which stays synchronous): `wait4` (61) is fully
//! emulated against the process table — blocking waits park the caller
//! until a matching exit or signal death wakes it, `WNOHANG` returns zero,
//! unknown options fail with `-EINVAL`, stale selectors with `-ECHILD` —
//! and `kill` (62) forwards the normal termination signals to the
//! translated host task while signal deaths are recorded as signaled
//! outcomes with SIGCHLD queued for the parent.
//!
//! G05a owns inherited pipes and close-on-exec descriptors, also in the
//! supervision loop after the wait/kill precedent (no lane-hook claim, so
//! the other supervision loops keep byte-identical behavior). `pipe` (22)
//! and `pipe2` (293) execute on the host and the loop mirrors the pair as
//! supervisor-owned domain objects; `dup` (32), `dup2` (33), `dup3` (292),
//! and the `fcntl` (72) duplication/flag subset execute the same way with
//! shared-offset and close-on-exec semantics carried by the host, while
//! `close` (3) always executes and the mirror drops the entry. Reads and
//! writes execute only for stdio and tracked ends. Flag shapes the mirror
//! cannot represent fail here before the host runs: `pipe2` accepts only
//! `O_CLOEXEC|O_NONBLOCK` (`O_DIRECT` and anything else get `-EINVAL`),
//! `dup3` accepts only `O_CLOEXEC` (`-EINVAL` otherwise), and only the
//! `F_DUPFD`/`F_GETFD`/`F_SETFD`/`F_DUPFD_CLOEXEC` `fcntl` commands run
//! (anything else gets `-ENOSYS`). Fork/clone inheritance and exec scrub
//! live in the loop next to the fork-event and exec-event paths.
//!
//! G09 connects domain-produced executables to the same supervised exec
//! mediation. The supervision loop (in `main.rs`, the only other file this
//! lane edits this round) resolves a mediated `execve`/`execveat` path in
//! the loop's domain view: a file with any execute bit set is materialized
//! at its domain path so the host kernel loads those exact bytes with the
//! tracee still attached (same pid, exec-epoch bump, never detached); a
//! directory or a file with no execute bit fails with `-EACCES` and never
//! executes; a path the domain does not know falls through to the host so
//! existing host binaries keep working byte-identically; a script whose
//! interpreter resolves in the domain is staged the same way, while a
//! malformed script line fails with `-ENOEXEC`. This file owns only the
//! register-free policy predicates ([`exec_bit_set`], [`parse_script_interp`]);
//! the tracee-memory and VFS orchestration lives in the loop.

use crate::supervisor::{EACCES, EINVAL, ENODEV, ENOMEM, ENOSYS, EPERM, SYS_FORK};

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

/// Raw `read` entry: gated in the supervision loop to stdio and tracked
/// pipe ends; anything else fails closed with `-EBADF`.
pub const SYS_READ: u64 = 0;
/// Raw `close` entry: always executes on the host; the loop drops the
/// mirrored entry when the host reports success.
pub const SYS_CLOSE: u64 = 3;
/// Raw `pipe` entry: creates a connected pair, both ends owned by the caller.
pub const SYS_PIPE: u64 = 22;
/// Raw `dup` entry: lowest-free alias with `FD_CLOEXEC` cleared.
pub const SYS_DUP: u64 = 32;
/// Raw `dup2` entry: alias at an explicit number with `FD_CLOEXEC` cleared.
pub const SYS_DUP2: u64 = 33;
/// Raw `fcntl` entry: only the duplication and flag commands below run.
pub const SYS_FCNTL: u64 = 72;
/// Raw `dup3` entry: alias at an explicit number with `O_CLOEXEC` choice.
pub const SYS_DUP3: u64 = 292;
/// Raw `pipe2` entry: pipe pair with atomic flags.
pub const SYS_PIPE2: u64 = 293;

/// `O_CLOEXEC` creation flag: the end dies with executable replacement.
pub const O_CLOEXEC: u64 = 0o2000000;
/// `O_NONBLOCK` creation flag: the only other flag a pipe pair accepts.
pub const O_NONBLOCK: u64 = 0o4000;
/// `O_DIRECT` creation flag: packetized pipe mode the mirror does not
/// represent; explicitly denied on pipes.
pub const O_DIRECT: u64 = 0o40000;
/// The only `pipe2` flags the mirror represents.
pub const PIPE2_ALLOWED_FLAGS: u64 = O_CLOEXEC | O_NONBLOCK;
/// `fcntl` duplication/flag commands the mirror represents.
pub const F_DUPFD: u64 = 0;
pub const F_GETFD: u64 = 1;
pub const F_SETFD: u64 = 2;
pub const F_DUPFD_CLOEXEC: u64 = 1030;
/// `FD_CLOEXEC` flag bit for `F_GETFD`/`F_SETFD`.
pub const FD_CLOEXEC: u64 = 1;

/// Whether a `pipe2` flag word names a representable pair: the allowed
/// subset only. `O_DIRECT` and every other bit fail explicitly with
/// `-EINVAL` before the host runs.
pub fn pipe2_flags_valid(flags: u64) -> bool {
    flags & !PIPE2_ALLOWED_FLAGS == 0 && flags & O_DIRECT == 0
}

/// Whether a `dup3` flag word names a representable alias: empty or
/// `O_CLOEXEC` only. Anything else fails explicitly with `-EINVAL`.
pub fn dup3_flags_valid(flags: u64) -> bool {
    flags == 0 || flags == O_CLOEXEC
}

/// Whether an `fcntl` command belongs to the mediated duplication/flag
/// subset. Anything else (file status flags, locks, leases, signals,
/// pipe sizing) keeps the existing explicit `-ENOSYS` denial.
pub fn fcntl_supported(command: u64) -> bool {
    command == F_DUPFD
        || command == F_GETFD
        || command == F_SETFD
        || command == F_DUPFD_CLOEXEC
}

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

/// Raw `mmap` entry: anonymous private mappings only; every other shape
/// is denied by [`mmap_shape_error`] before the host runs.
pub const SYS_MMAP: u64 = 9;
/// Raw `mprotect` entry: protection changes on already-mapped memory.
pub const SYS_MPROTECT: u64 = 10;
/// Raw `munmap` entry: releases mappings; reconciled, never denied.
pub const SYS_MUNMAP: u64 = 11;
/// Raw `brk` entry: extends or queries the data-segment break.
pub const SYS_BRK: u64 = 12;

/// `mmap`/`mprotect` protection bits (`linux/mman.h`). Read needs no
/// gate (bit `0x1`); only the write/execute combination is denied.
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;

/// `mmap` flag bits (`linux/mman.h`).
pub const MAP_SHARED: u64 = 0x01;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_FIXED: u64 = 0x10;
pub const MAP_ANONYMOUS: u64 = 0x20;
pub const MAP_NORESERVE: u64 = 0x4000;
pub const MAP_POPULATE: u64 = 0x8000;
pub const MAP_STACK: u64 = 0x20000;
pub const MAP_FIXED_NOREPLACE: u64 = 0x100000;

/// Benign `mmap` hints a loader or allocator may set on anonymous
/// private mappings: overcommit and prefetch advice (`NORESERVE`,
/// `POPULATE`) and the thread-stack marker (`STACK`). Everything else
/// outside `PRIVATE`/`ANONYMOUS` is denied.
pub const MAP_ALLOWED_HINTS: u64 = MAP_NORESERVE | MAP_POPULATE | MAP_STACK;

/// I04-M1 bounds. A single mapping may not exceed 64 MiB; one thread
/// group (one address space, `mmap` ranges plus `brk` growth) may not
/// exceed 256 MiB, matching the default domain memory declaration; at
/// most 256 live ranges per group. Past any of them the entry fails
/// closed with `-ENOMEM` before the host runs.
pub const MMAP_SINGLE_MAX: u64 = 64 << 20;
pub const MMAP_TOTAL_MAX: u64 = 256 << 20;
pub const MMAP_REGION_MAX: usize = 256;
/// Page granularity for length accounting: the kernel maps whole pages,
/// so the ledger rounds requests up the same way.
pub const MMAP_PAGE: u64 = 4096;

/// Round a mapping length up to page granularity. Callers check the raw
/// length against [`MMAP_SINGLE_MAX`] first, so this cannot overflow.
pub const fn round_len(len: u64) -> u64 {
    (len + MMAP_PAGE - 1) & !(MMAP_PAGE - 1)
}

/// Lane membership by syscall number: the three process-creation entries,
/// the two executable-replacement entries, and the four anonymous-memory
/// entries belong to the process lane. Other entries stay with the
/// supervision loop's existing match until their owning tasks claim them.
pub fn claims(syscall: u64) -> bool {
    syscall == SYS_FORK as u64
        || syscall == SYS_CLONE
        || syscall == SYS_VFORK
        || syscall == SYS_EXECVE
        || syscall == SYS_EXECVEAT
        || syscall == SYS_MMAP
        || syscall == SYS_MPROTECT
        || syscall == SYS_MUNMAP
        || syscall == SYS_BRK
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

/// Whether an `mmap` shape may execute on the host. Anonymous private
/// mappings (with the benign hints in [`MAP_ALLOWED_HINTS`]) return
/// `None`: the supervision loop checks the lane caps, lets the host map
/// supervisor-owned anonymous memory, and records the outcome. Every
/// other shape returns an explicit errno and never executes:
/// - zero length: `-EINVAL`, like the kernel;
/// - file-backed (`MAP_ANONYMOUS` clear): `-ENODEV`, because the domain
///   view holds no mappable file content yet (M2 owns that; file-backed
///   `mmap` stays denied until it exists);
/// - shared: `-EPERM`, no shared mappings in the domain;
/// - fixed (`MAP_FIXED`, `MAP_FIXED_NOREPLACE`): `-EPERM`, fixed
///   overwrite could clobber loader and library mappings;
/// - unknown flag bits: `-EINVAL`, like the kernel;
/// - a single request past [`MMAP_SINGLE_MAX`]: `-ENOMEM`;
/// - writable-executable protections: `-EACCES`, matching the balanced
///   contract's existing `mmap`/`mprotect` argument gate and
///   SELinux-enforcing kernels.
pub fn mmap_shape_error(flags: u64, len: u64, prot: u64) -> Option<i64> {
    if len == 0 {
        return Some(EINVAL);
    }
    if flags & MAP_ANONYMOUS == 0 {
        return Some(ENODEV);
    }
    if flags & MAP_SHARED != 0 {
        return Some(EPERM);
    }
    if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 {
        return Some(EPERM);
    }
    if flags & !(MAP_PRIVATE | MAP_ANONYMOUS | MAP_ALLOWED_HINTS) != 0 {
        return Some(EINVAL);
    }
    if len > MMAP_SINGLE_MAX {
        return Some(ENOMEM);
    }
    if prot & (PROT_WRITE | PROT_EXEC) == (PROT_WRITE | PROT_EXEC) {
        return Some(EACCES);
    }
    None
}

/// Whether a mapping of `len` bytes still fits the lane caps for a group
/// already holding `regions` ranges and `total` bytes. Past either cap
/// the entry fails closed with `-ENOMEM` before the host runs.
pub fn reserve_error(regions: usize, total: u64, len: u64) -> Option<i64> {
    if regions >= MMAP_REGION_MAX {
        return Some(ENOMEM);
    }
    if total.saturating_add(round_len(len)) > MMAP_TOTAL_MAX {
        return Some(ENOMEM);
    }
    None
}

/// Whether an `mprotect` shape may execute: zero length fails with
/// `-EINVAL`, writable-executable with `-EACCES`, like [`mmap_shape_error`].
/// Anything else (RELRO, newly executable text) runs on the host and
/// changes no accounting.
pub fn mprotect_shape_error(prot: u64, len: u64) -> Option<i64> {
    if len == 0 {
        return Some(EINVAL);
    }
    if prot & (PROT_WRITE | PROT_EXEC) == (PROT_WRITE | PROT_EXEC) {
        return Some(EACCES);
    }
    None
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
/// the flags register this hook does not receive. The memory entries
/// (`mmap`, `mprotect`, `munmap`, `brk`) likewise always return `None`
/// here: `mmap` needs its flags from `r10` and its file descriptor from
/// `r8`, which this hook does not receive, so the loop consults
/// [`mmap_shape_error`], [`mprotect_shape_error`], and [`reserve_error`]
/// with the full register set instead — the same split as `exec_mediated`.
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
///
/// G09 keeps this gate unchanged and adds a domain step after it in the
/// supervision loop: a mediated path that resolves to a domain file is
/// staged (see [`exec_bit_set`]) before the host call runs, so staging
/// never widens the shapes that execute.
pub fn exec_mediated(syscall: u64, dirfd: u64, flags: u64) -> bool {
    if syscall == SYS_EXECVE {
        return true;
    }
    if syscall == SYS_EXECVEAT {
        return dirfd == AT_FDCWD && flags == 0;
    }
    false
}

/// Permission bits that make a domain file executable: any of owner, group,
/// or other execute, matching the kernel's check shape for a domain without
/// user/group distinction. The loop denies a domain
/// file with none of these set (`-EACCES`) before the host runs.
pub const EXEC_MODE_BITS: u32 = 0o111;

/// Whether a domain file's stored mode carries any execute bit.
pub fn exec_bit_set(mode: u32) -> bool {
    mode & EXEC_MODE_BITS != 0
}

/// Capacity of the script-interpreter path buffer: one domain path.
pub const SCRIPT_INTERP_MAX: usize = 256;

/// What a staged file's first bytes say about script execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptInterp {
    /// Not a script (fewer than two bytes or no `#!` prefix): the kernel
    /// loads the bytes as an executable image.
    NotScript,
    /// A script whose interpreter path fills `out[..len]`.
    Interp(usize),
    /// A `#!` line with no interpreter (empty or overlong): the kernel
    /// would report `ENOEXEC`, so the loop denies without executing.
    Bad,
}

/// Parse the interpreter out of script bytes: `#!`, optional blanks, then
/// the interpreter up to the first blank or newline, mirroring the kernel's
/// `binfmt_script` split (one interpreter word; the loop leaves any
/// trailing argument to the kernel). The caller stages the `out[..len]`
/// path when it resolves in the domain and lets the host resolve the rest
/// (for example `/bin/sh`), exactly like the staged script itself.
pub fn parse_script_interp(content: &[u8], out: &mut [u8; SCRIPT_INTERP_MAX]) -> ScriptInterp {
    if content.len() < 2 || content[0] != b'#' || content[1] != b'!' {
        return ScriptInterp::NotScript;
    }
    let mut index = 2;
    while index < content.len() && (content[index] == b' ' || content[index] == b'\t') {
        index += 1;
    }
    let start = index;
    while index < content.len()
        && content[index] != b' '
        && content[index] != b'\t'
        && content[index] != b'\n'
    {
        index += 1;
    }
    if index == start {
        return ScriptInterp::Bad;
    }
    let len = index - start;
    if len > SCRIPT_INTERP_MAX {
        return ScriptInterp::Bad;
    }
    out[..len].copy_from_slice(&content[start..index]);
    ScriptInterp::Interp(len)
}
