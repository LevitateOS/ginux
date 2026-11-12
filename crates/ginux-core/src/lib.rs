#![no_std]

pub const SYS_WRITE: u64 = 1;
pub const SYS_STAT: u64 = 4;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_READV: u64 = 19;
pub const SYS_GETPID: u64 = 39;
pub const SYS_FORK: u64 = 57;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_UNAME: u64 = 63;
pub const SYS_GETUID: u64 = 102;
pub const SYS_GETGID: u64 = 104;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_SETUID: u64 = 105;
pub const SYS_SETGID: u64 = 106;
pub const SYS_SETREUID: u64 = 113;
pub const SYS_SETREGID: u64 = 114;
pub const SYS_SETGROUPS: u64 = 116;
pub const SYS_SETRESUID: u64 = 117;
pub const SYS_SETRESGID: u64 = 119;
pub const SYS_GETPPID: u64 = 110;
pub const SYS_GETPGRP: u64 = 111;
pub const SYS_FUTEX: u64 = 202;
pub const SYS_SET_TID_ADDRESS: u64 = 218;
pub const SYS_GETPRIORITY: u64 = 140;
pub const SYS_SETPRIORITY: u64 = 141;
pub const SYS_REBOOT: u64 = 169;
pub const SYS_GETTID: u64 = 186;
pub const SYS_EXIT_GROUP: u64 = 231;
pub const SYS_NEWFSTATAT: u64 = 262;
pub const SYS_UNLINKAT: u64 = 263;
pub const SYS_RENAMEAT: u64 = 264;
pub const SYS_LINKAT: u64 = 265;
pub const SYS_SYMLINKAT: u64 = 266;
pub const SYS_READLINKAT: u64 = 267;
pub const SYS_FACCESSAT: u64 = 269;
pub const SYS_MEMFD_CREATE: u64 = 319;
pub const SYS_CLOSE_RANGE: u64 = 436;
pub const SYS_PIDFD_OPEN: u64 = 434;
pub const SYS_PIDFD_SEND_SIGNAL: u64 = 424;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Emulate,
    Mediate,
    Deny(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    pub syscall: u64,
    pub action: Action,
}

pub const fn decide(syscall: u64) -> Decision {
    let action = match syscall {
        SYS_GETPID | SYS_EXIT => Action::Emulate,
        SYS_WRITE => Action::Mediate,
        SYS_UNAME => Action::Deny(1),
        _ => Action::Deny(38),
    };
    Decision { syscall, action }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BalancedSurface {
    ImageRead,
    InstanceWrite,
    Memory,
    Task,
    Console,
    Random,
    Network,
    VirtualIdentity,
    Lifecycle,
    Denied,
}

pub const fn is_shared_network_syscall(syscall: u64) -> bool {
    matches!(syscall, 41..=55 | 288 | 299 | 307)
}

pub const fn decide_systemd(syscall: u64, shared_network: bool) -> Decision {
    if shared_network && is_shared_network_syscall(syscall) {
        return Decision {
            syscall,
            action: Action::Mediate,
        };
    }
    let action = match syscall {
        63 | 92 | 93 | 94 | 109 | 112 | 153 | 165 | 166 | 260 | SYS_GETPRIORITY
        | SYS_SETPRIORITY | SYS_GETTID | SYS_SETUID | SYS_SETGID | SYS_SETREUID | SYS_SETREGID
        | SYS_SETGROUPS | SYS_SETRESUID | SYS_SETRESGID | SYS_REBOOT => Action::Emulate,
        7
        | 15
        | 16
        | 18
        | 24
        | 25
        | 32
        | 33
        | 56
        | 57
        | 58
        | 59
        | 61
        | 62
        | 73
        | 74
        | 75
        | 76
        | 77
        | 79
        | 80
        | 81
        | 82
        | 83
        | 84
        | 87
        | 88
        | 90
        | 91
        | 95
        | 125
        | 126
        | 137
        | 138
        | 157
        | 190
        | 193
        | 128
        | 133
        | 135
        | 196
        | 199
        | 213
        | 228
        | 230
        | 232
        | 233
        | 247
        | 253
        | 254
        | 255
        | 258
        | 259
        | SYS_UNLINKAT
        | SYS_RENAMEAT
        | SYS_LINKAT
        | SYS_SYMLINKAT
        | SYS_READLINKAT
        | 270
        | 271
        | 280
        | 281
        | 283
        | 285
        | 286
        | 287
        | 289
        | 290
        | 291
        | 292
        | 293
        | 294
        | 306
        | 317
        | SYS_MEMFD_CREATE
        | SYS_PIDFD_SEND_SIGNAL
        | SYS_PIDFD_OPEN
        | 435
        | SYS_CLOSE_RANGE
        | 441
        | 452 => Action::Mediate,
        _ => decide_balanced(syscall).action,
    };
    Decision { syscall, action }
}

pub const fn systemd_surface(syscall: u64, shared_network: bool) -> BalancedSurface {
    if shared_network && is_shared_network_syscall(syscall) {
        BalancedSurface::Network
    } else if syscall == SYS_REBOOT {
        BalancedSurface::Lifecycle
    } else if matches!(syscall, SYS_GETPRIORITY | SYS_SETPRIORITY) {
        BalancedSurface::VirtualIdentity
    } else if matches!(
        syscall,
        18 | 73
            | 74
            | 75
            | 76
            | 77
            | 82
            | 84
            | 87
            | 88
            | 90
            | 91
            | 92
            | 93
            | 94
            | 133
            | 190
            | 196
            | 199
            | 259
            | 260
            | 280
            | 285
            | 306
            | SYS_UNLINKAT
            | SYS_RENAMEAT
            | SYS_LINKAT
            | SYS_SYMLINKAT
    ) {
        BalancedSurface::InstanceWrite
    } else if syscall == 153 {
        BalancedSurface::Console
    } else if matches!(syscall, 25 | SYS_MEMFD_CREATE) {
        BalancedSurface::Memory
    } else if matches!(
        syscall,
        SYS_SETUID
            | SYS_SETGID
            | SYS_SETREUID
            | SYS_SETREGID
            | SYS_SETGROUPS
            | SYS_SETRESUID
            | SYS_SETRESGID
    ) {
        BalancedSurface::VirtualIdentity
    } else if matches!(syscall, 193 | SYS_READLINKAT) {
        BalancedSurface::ImageRead
    } else if matches!(
        syscall,
        7 | 15
            | 24
            | 32
            | 33
            | 56
            | 57
            | 58
            | 61
            | 62
            | 79
            | 81
            | 109
            | 112
            | 128
            | 135
            | 213
            | 228
            | 230
            | 232
            | 233
            | 247
            | 253
            | 254
            | 255
            | 270
            | 271
            | 281
            | 283
            | 286
            | 287
            | 289
            | 290
            | 291
            | 292
            | 293
            | 294
            | 317
            | SYS_PIDFD_SEND_SIGNAL
            | SYS_PIDFD_OPEN
            | 435
            | SYS_CLOSE_RANGE
            | 441
            | 452
    ) {
        if syscall == 452 {
            BalancedSurface::InstanceWrite
        } else {
            BalancedSurface::Task
        }
    } else {
        balanced_surface(syscall)
    }
}

pub const fn balanced_surface(syscall: u64) -> BalancedSurface {
    match syscall {
        0 | 2 | 3 | 4 | 5 | 8 | 17 | 21 | 72 | 89 | 217 | 257 | 262 | 332 | 439 => {
            BalancedSurface::ImageRead
        }
        9 | 10 | 11 | 12 | 28 => BalancedSurface::Memory,
        13 | 14 | 15 | 24 | SYS_FORK | SYS_WAIT4 | 98 | 99 | 100 | 158 | 202 | 218 | 273 | 302
        | 334 => BalancedSurface::Task,
        1 | 20 => BalancedSurface::Console,
        318 => BalancedSurface::Random,
        SYS_GETPID | SYS_GETUID | SYS_GETGID | SYS_GETEUID | SYS_GETEGID | SYS_GETPPID
        | SYS_GETPGRP => BalancedSurface::VirtualIdentity,
        SYS_EXIT | SYS_EXIT_GROUP => BalancedSurface::Lifecycle,
        _ => BalancedSurface::Denied,
    }
}

pub const fn decide_balanced(syscall: u64) -> Decision {
    surface_decision(syscall, balanced_surface(syscall))
}

/// Configured launch mediates every read-only form of an image read that
/// programs issue, not only the forms the balanced surface lists: `readv`
/// on an image descriptor (musl stdio reads into the caller's buffer and its
/// own buffer at once), and `readlinkat` and `faccessat` on an image path as
/// `readlink` and `access` are. They take the same image mediation: the
/// descriptor owner translates only a registered native image descriptor,
/// and an image path is resolved and rewritten to its canonical form, which
/// never names a hidden subtree, `/proc` or `/sys`. Native balanced policy
/// keeps `balanced_surface`.
pub const fn configured_surface(syscall: u64) -> BalancedSurface {
    match syscall {
        SYS_READV | SYS_READLINKAT | SYS_FACCESSAT => BalancedSurface::ImageRead,
        _ => balanced_surface(syscall),
    }
}

pub const fn decide_configured(syscall: u64) -> Decision {
    surface_decision(syscall, configured_surface(syscall))
}

const fn surface_decision(syscall: u64, surface: BalancedSurface) -> Decision {
    let action = match surface {
        BalancedSurface::VirtualIdentity | BalancedSurface::Lifecycle => Action::Emulate,
        BalancedSurface::Denied => Action::Deny(38),
        _ => Action::Mediate,
    };
    Decision { syscall, action }
}

/// The virtual pid of the single task in the balanced contract. The task
/// has no threads (thread creation is denied), so it is also its tid.
pub const BALANCED_VIRTUAL_PID: i64 = 4242;

pub const fn balanced_identity_result(syscall: u64) -> Option<i64> {
    match syscall {
        SYS_GETPID => Some(BALANCED_VIRTUAL_PID),
        SYS_GETPPID => Some(1),
        SYS_GETPGRP => Some(BALANCED_VIRTUAL_PID),
        SYS_GETUID | SYS_GETGID | SYS_GETEUID | SYS_GETEGID => Some(0),
        _ => None,
    }
}

/// Result reported for a mediated call whose host result is the caller's
/// host tid. `set_tid_address` executes on the host for its clear-on-exit
/// registration, but its return value is the caller's tid, so the task
/// sees its virtual tid instead. `None` keeps the host result.
pub const fn balanced_mediated_result(syscall: u64) -> Option<i64> {
    match syscall {
        SYS_SET_TID_ADDRESS => Some(BALANCED_VIRTUAL_PID),
        _ => None,
    }
}

/// Whether a futex operation word selects a priority-inheritance operation.
/// PI futexes keep the owner's tid in the futex word: `FUTEX_LOCK_PI`,
/// `FUTEX_LOCK_PI2` and `FUTEX_TRYLOCK_PI` store the caller's host tid in
/// workload memory, and `FUTEX_UNLOCK_PI` and the requeue-PI operations
/// compare the word against it. The command is classified by its low 7 bits
/// alone, so any combination of flag bits above it is covered:
/// `FUTEX_PRIVATE_FLAG` and `FUTEX_CLOCK_REALTIME`, and the additional flag
/// bits newer kernels accept.
pub const fn futex_priority_inheritance(op: u64) -> bool {
    const FUTEX_COMMAND: u64 = 0x7f;
    matches!(op & FUTEX_COMMAND, 6..=8 | 11..=13)
}

/// Whether an `fcntl` or `ioctl` request would set up signal-driven I/O, so
/// that the host kernel signals a process when a descriptor becomes ready.
/// The workload could name any host process its credentials may signal
/// (`F_SETOWN`, `F_SETOWN_EX`, `FIOSETOWN`, `SIOCSPGRP`); `getpid()` gives its
/// virtual pid, so even naming itself would name an unrelated host process.
/// Enabling the I/O alone (`F_SETFL` with `O_ASYNC`, `FIOASYNC`) signals a
/// descriptor's existing owner, such as the foreground process group of a
/// terminal it inherited, which includes the supervisor; and `F_SETSIG`
/// chooses the signal an existing owner receives. The kernel reads requests
/// as 32-bit values. Other commands are not refused here; they do not let the
/// workload choose a signal target.
pub const fn signal_driven_io(syscall: u64, request: u64, argument: u64) -> bool {
    const SYS_IOCTL: u64 = 16;
    const SYS_FCNTL: u64 = 72;
    const F_SETFL: u32 = 4;
    const F_SETOWN: u32 = 8;
    const F_SETSIG: u32 = 10;
    const F_SETOWN_EX: u32 = 15;
    const O_ASYNC: u64 = 0o20000;
    const FIOASYNC: u32 = 0x5452;
    const FIOSETOWN: u32 = 0x8901;
    const SIOCSPGRP: u32 = 0x8902;
    match syscall {
        SYS_FCNTL => match request as u32 {
            F_SETOWN | F_SETOWN_EX | F_SETSIG => true,
            F_SETFL => argument & O_ASYNC != 0,
            _ => false,
        },
        SYS_IOCTL => matches!(request as u32, FIOASYNC | FIOSETOWN | SIOCSPGRP),
        _ => false,
    }
}

pub const fn balanced_arguments_allowed(syscall: u64, arg0: u64, arg1: u64, arg2: u64) -> bool {
    const O_ACCMODE: u64 = 3;
    const O_CREAT: u64 = 0o100;
    const O_EXCL: u64 = 0o200;
    const O_TRUNC: u64 = 0o1000;
    const O_APPEND: u64 = 0o2000;
    // O_TMPFILE is __O_TMPFILE | O_DIRECTORY. Only the __O_TMPFILE bit marks
    // a mutating open; masking the composite also rejected a plain
    // O_DIRECTORY, which glibc opendir() always passes.
    const O_TMPFILE_BIT: u64 = 0o20000000;
    const MUTATING_OPEN_FLAGS: u64 = O_CREAT | O_EXCL | O_TRUNC | O_APPEND | O_TMPFILE_BIT;
    const PROT_WRITE: u64 = 2;
    const PROT_EXEC: u64 = 4;
    match syscall {
        0 => arg2 <= 1024 * 1024,
        1 => matches!(arg0, 1 | 2) && arg2 <= 4096,
        20 => matches!(arg0, 1 | 2) && arg2 <= 16,
        2 => arg1 & (O_ACCMODE | MUTATING_OPEN_FLAGS) == 0,
        9 | 10 => arg2 & (PROT_WRITE | PROT_EXEC) != (PROT_WRITE | PROT_EXEC),
        17 => arg2 <= 1024 * 1024,
        // ioctl is outside the balanced surface; native systemd mode falls
        // back to this check for both.
        16 | 72 => !signal_driven_io(syscall, arg1, arg2),
        257 => arg2 & (O_ACCMODE | MUTATING_OPEN_FLAGS) == 0,
        302 => arg0 == 0 && arg1 <= 15,
        318 => arg2 <= 256,
        SYS_WAIT4 => arg0 == u64::MAX || arg0 > 0,
        SYS_FUTEX => !futex_priority_inheritance(arg1),
        _ => true,
    }
}

/// The finite request bound of one configured image read, in bytes.
pub const CONFIGURED_READ_BOUND: u64 = 64 * 1024 * 1024;

/// Configured image reads have a separate finite request bound. Native callers
/// retain the balanced policy and its existing transfer errors.
pub const fn configured_arguments_allowed(syscall: u64, arg0: u64, arg1: u64, arg2: u64) -> bool {
    match syscall {
        0 | 17 => arg2 <= CONFIGURED_READ_BOUND,
        _ => balanced_arguments_allowed(syscall, arg0, arg1, arg2),
    }
}

/// Whether a configured `readv` requesting `total` bytes, the sum of its
/// vector lengths, is within the bound of one image read. `None` is an
/// array the kernel itself rejects (EFAULT, or EINVAL above `UIO_MAXIOV`
/// entries or `SSIZE_MAX` bytes), so the call carries its own error.
pub const fn configured_vectors_allowed(total: Option<u64>) -> bool {
    match total {
        Some(total) => total <= CONFIGURED_READ_BOUND,
        None => true,
    }
}

/// The `newfstatat` call a legacy `stat` or `lstat` entry is defined as, as
/// `[dirfd, path, buffer, flags]`: `stat(path, buffer)` is
/// `newfstatat(AT_FDCWD, path, buffer, 0)` and `lstat(path, buffer)` is
/// `newfstatat(AT_FDCWD, path, buffer, AT_SYMLINK_NOFOLLOW)`. Both use the
/// same `struct stat` layout on x86-64. `None` for every other syscall.
pub const fn legacy_stat_arguments(syscall: u64, path: u64, buffer: u64) -> Option<[u64; 4]> {
    const AT_FDCWD: u64 = -100i64 as u64;
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    match syscall {
        SYS_STAT => Some([AT_FDCWD, path, buffer, 0]),
        SYS_LSTAT => Some([AT_FDCWD, path, buffer, AT_SYMLINK_NOFOLLOW]),
        _ => None,
    }
}

/// What a thread-directed signal (`tkill`, `tgkill`) does once its target
/// thread is known to be a running task of the same instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadSignal {
    /// Signal 0: the target exists and nothing is sent.
    Exists,
    /// The kernel queues the signal on a thread of the caller's own process,
    /// with the caller's own identity, exactly as `raise` and `pthread_kill`
    /// expect.
    Deliver,
    /// SIGKILL to another process of the instance, as `kill` allows.
    Kill,
    /// Refused with this negative errno.
    Refuse(i64),
}

/// Decide a thread-directed signal. `own_process` says whether the target is
/// a thread of the caller's own process. `default_stop` says whether the
/// target would take the default action of SIGTSTP, SIGTTIN or SIGTTOU (no
/// handler, not ignored). Stopping a process is a group stop, which
/// supervised execution does not offer, so SIGSTOP and default-action stop
/// signals are refused like the other signals `kill` does not support.
/// Another process of the instance can only be probed or killed, as with
/// `kill`.
pub const fn thread_signal(signal: u64, own_process: bool, default_stop: bool) -> ThreadSignal {
    const SIGKILL: u64 = 9;
    const SIGSTOP: u64 = 19;
    if signal > 64 {
        return ThreadSignal::Refuse(-22);
    }
    if signal == 0 {
        return ThreadSignal::Exists;
    }
    if !own_process {
        return if signal == SIGKILL {
            ThreadSignal::Kill
        } else {
            ThreadSignal::Refuse(-95)
        };
    }
    if signal == SIGSTOP || (matches!(signal, 20..=22) && default_stop) {
        return ThreadSignal::Refuse(-95);
    }
    ThreadSignal::Deliver
}

/// Record semantics of a configured local socket pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalSocketKind {
    /// `SOCK_STREAM`: an ordered byte stream in each direction.
    Stream,
    /// `SOCK_SEQPACKET`: ordered records whose boundaries are preserved.
    SequencedPacket,
}

impl LocalSocketKind {
    /// The `SO_TYPE` value Linux reports for this kind.
    pub const fn socket_type(self) -> i32 {
        match self {
            LocalSocketKind::Stream => 1,
            LocalSocketKind::SequencedPacket => 5,
        }
    }
}

/// An admitted `socketpair` request: two connected, unnamed endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalSocketPair {
    pub kind: LocalSocketKind,
    pub cloexec: bool,
    pub nonblock: bool,
}

/// Decide `socketpair(family, type, protocol)` for a supervisor-owned pair.
/// Only `AF_UNIX` with `SOCK_STREAM` or `SOCK_SEQPACKET` (optionally with
/// `SOCK_CLOEXEC` and `SOCK_NONBLOCK`) and protocol 0 or `PF_UNIX` qualify.
/// Such a pair has no name, binds and connects nothing and carries no
/// descriptors, so it grants no network or filesystem naming authority.
/// Every other family, type, flag or protocol, including `SOCK_DGRAM`, is
/// EOPNOTSUPP; arguments are compared at full register width, as configured
/// `pipe2` compares its flags.
pub const fn local_socket_pair(
    family: u64,
    kind: u64,
    protocol: u64,
) -> Result<LocalSocketPair, i64> {
    const AF_UNIX: u64 = 1;
    const SOCK_NONBLOCK: u64 = 0o4000;
    const SOCK_CLOEXEC: u64 = 0o2000000;
    if family != AF_UNIX || !matches!(protocol, 0 | 1) {
        return Err(-95);
    }
    let kind_only = match kind & !(SOCK_CLOEXEC | SOCK_NONBLOCK) {
        1 => LocalSocketKind::Stream,
        5 => LocalSocketKind::SequencedPacket,
        _ => return Err(-95),
    };
    Ok(LocalSocketPair {
        kind: kind_only,
        cloexec: kind & SOCK_CLOEXEC != 0,
        nonblock: kind & SOCK_NONBLOCK != 0,
    })
}

/// Directions a local socket `shutdown(how)` closes, as
/// `(receive, send)` from the caller's endpoint. Linux applies the mirrored
/// state to the connected peer: a closed send direction is the peer's
/// end-of-file, and a closed receive direction makes the peer's writes EPIPE.
pub const fn local_socket_shutdown(how: u64) -> Result<(bool, bool), i64> {
    match how {
        0 => Ok((true, false)),
        1 => Ok((false, true)),
        2 => Ok((true, true)),
        _ => Err(-22),
    }
}

/// The `getsockopt` value of a local socket pair endpoint. Only identity and
/// state queries are answered; credentials (`SO_PEERCRED`) and every other
/// option are ENOPROTOOPT, and levels other than `SOL_SOCKET` EOPNOTSUPP.
pub const fn local_socket_option(
    level: u64,
    name: u64,
    kind: LocalSocketKind,
    buffer: usize,
) -> Result<i32, i64> {
    if level != 1 {
        return Err(-95);
    }
    match name {
        // SO_TYPE
        3 => Ok(kind.socket_type()),
        // SO_ERROR, SO_ACCEPTCONN and SO_PROTOCOL
        4 | 30 | 38 => Ok(0),
        // SO_SNDBUF and SO_RCVBUF: the fixed per-direction bound
        7 | 8 => Ok(buffer as i32),
        // The socket family option: AF_UNIX
        39 => Ok(1),
        _ => Err(-92),
    }
}

/// Validate a local socket pair `setsockopt`. Buffer-size requests
/// (`SO_SNDBUF`, `SO_RCVBUF`) succeed without changing the fixed bound, as a
/// clamped Linux request would; every other option is ENOPROTOOPT and other
/// levels are EOPNOTSUPP. Linux rejects a value shorter than an int first.
pub const fn local_socket_set_option(level: u64, name: u64, length: u64) -> Result<(), i64> {
    if level != 1 {
        return Err(-95);
    }
    // The kernel reads the length as an unsigned int.
    if (length as u32) < 4 {
        return Err(-22);
    }
    match name {
        7 | 8 => Ok(()),
        _ => Err(-92),
    }
}

/// Linux poll readiness of a local socket endpoint. `inbound` bytes are
/// queued for this endpoint; `read_closed` means the peer can no longer send
/// (its endpoint closed or either side shut the direction down); `room` means
/// a write can make progress; `write_closed` means this endpoint can no longer
/// send. A closed receive direction is readable end-of-file with RDHUP, both
/// closed directions are HUP, and a closed send direction stays writable so
/// the next write reports EPIPE rather than hanging.
pub const fn local_socket_readiness(
    inbound: usize,
    read_closed: bool,
    room: bool,
    write_closed: bool,
) -> u16 {
    const POLLIN: u16 = 0x1 | 0x40;
    const POLLOUT: u16 = 0x4 | 0x100;
    const POLLHUP: u16 = 0x10;
    const POLLRDHUP: u16 = 0x2000;
    (if inbound != 0 || read_closed {
        POLLIN
    } else {
        0
    }) | (if room || write_closed { POLLOUT } else { 0 })
        | (if read_closed { POLLRDHUP } else { 0 })
        | (if read_closed && write_closed {
            POLLHUP
        } else {
            0
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_socket_pair_admits_only_unnamed_unix_streams_and_packets() {
        let stream = local_socket_pair(1, 1 | 0o2000000, 0).unwrap();
        assert_eq!(stream.kind, LocalSocketKind::Stream);
        assert!(stream.cloexec && !stream.nonblock);
        let packet = local_socket_pair(1, 5 | 0o4000, 1).unwrap();
        assert_eq!(packet.kind, LocalSocketKind::SequencedPacket);
        assert!(!packet.cloexec && packet.nonblock);
        assert_eq!(local_socket_pair(1, 1, 0).unwrap().kind.socket_type(), 1);
        assert_eq!(packet.kind.socket_type(), 5);
        // Other families keep EOPNOTSUPP, including inet and netlink.
        for family in [0, 2, 10, 16, 1 << 32 | 1] {
            assert_eq!(local_socket_pair(family, 1, 0), Err(-95));
        }
        // Datagrams, raw and unknown types, unknown flags and protocols.
        for kind in [0, 2, 3, 4, 6, 10, 1 | 0o40, 1 | 1 << 32] {
            assert_eq!(local_socket_pair(1, kind, 0), Err(-95));
        }
        for protocol in [2, 6, 17, 1 << 32] {
            assert_eq!(local_socket_pair(1, 1, protocol), Err(-95));
        }
    }

    #[test]
    fn local_socket_shutdown_maps_linux_modes() {
        assert_eq!(local_socket_shutdown(0), Ok((true, false)));
        assert_eq!(local_socket_shutdown(1), Ok((false, true)));
        assert_eq!(local_socket_shutdown(2), Ok((true, true)));
        for how in [3, u64::MAX, 1 << 32] {
            assert_eq!(local_socket_shutdown(how), Err(-22));
        }
    }

    #[test]
    fn local_socket_options_answer_identity_only() {
        let stream = LocalSocketKind::Stream;
        assert_eq!(local_socket_option(1, 3, stream, 65536), Ok(1));
        assert_eq!(
            local_socket_option(1, 3, LocalSocketKind::SequencedPacket, 65536),
            Ok(5)
        );
        assert_eq!(local_socket_option(1, 39, stream, 65536), Ok(1));
        for name in [4, 30, 38] {
            assert_eq!(local_socket_option(1, name, stream, 65536), Ok(0));
        }
        assert_eq!(local_socket_option(1, 7, stream, 65536), Ok(65536));
        // SO_PEERCRED, SO_PEERSEC, SO_PASSCRED and unknown options.
        for name in [17, 31, 16, 999] {
            assert_eq!(local_socket_option(1, name, stream, 65536), Err(-92));
        }
        assert_eq!(local_socket_option(0, 3, stream, 65536), Err(-95));
        assert_eq!(local_socket_set_option(1, 7, 4), Ok(()));
        assert_eq!(local_socket_set_option(1, 8, 8), Ok(()));
        assert_eq!(local_socket_set_option(1, 8, 3), Err(-22));
        assert_eq!(local_socket_set_option(1, 8, 1 << 32 | 2), Err(-22));
        assert_eq!(local_socket_set_option(1, 16, 4), Err(-92));
        assert_eq!(local_socket_set_option(6, 1, 4), Err(-95));
    }

    #[test]
    fn local_socket_readiness_follows_linux_unix_poll() {
        assert_eq!(local_socket_readiness(0, false, true, false), 0x104);
        assert_eq!(local_socket_readiness(3, false, false, false), 0x41);
        // Peer shut its sending side: readable EOF with RDHUP, not HUP.
        assert_eq!(local_socket_readiness(0, true, true, false), 0x2145);
        // Peer gone: every direction closed, still writable for EPIPE.
        assert_eq!(local_socket_readiness(0, true, false, true), 0x2155);
        assert_eq!(local_socket_readiness(0, false, false, true), 0x104);
    }

    #[test]
    fn legacy_stat_calls_are_their_newfstatat_form() {
        const AT_FDCWD: u64 = -100i64 as u64;
        assert_eq!(
            legacy_stat_arguments(SYS_STAT, 0x1000, 0x2000),
            Some([AT_FDCWD, 0x1000, 0x2000, 0])
        );
        assert_eq!(
            legacy_stat_arguments(SYS_LSTAT, 0x1000, 0x2000),
            Some([AT_FDCWD, 0x1000, 0x2000, 0x100])
        );
        // Faulting addresses are passed through for the shared path to report.
        assert_eq!(
            legacy_stat_arguments(SYS_LSTAT, 0, u64::MAX),
            Some([AT_FDCWD, 0, u64::MAX, 0x100])
        );
        // fstat (5), newfstatat itself, statx and the other legacy path
        // calls keep their own form.
        for syscall in [5, 21, 89, SYS_NEWFSTATAT, 332] {
            assert_eq!(legacy_stat_arguments(syscall, 0x1000, 0x2000), None);
        }
        // The rewritten call is mediated on the same image surface.
        assert_eq!(balanced_surface(SYS_NEWFSTATAT), BalancedSurface::ImageRead);
    }

    #[test]
    fn thread_signals_stay_inside_the_callers_process_except_probe_and_kill() {
        // raise(), abort() and pthread_kill() within one process.
        for signal in [1, 6, 9, 10, 11, 12, 15, 17, 18, 34, 64] {
            assert_eq!(thread_signal(signal, true, true), ThreadSignal::Deliver);
        }
        assert_eq!(thread_signal(0, true, false), ThreadSignal::Exists);
        assert_eq!(thread_signal(0, false, false), ThreadSignal::Exists);
        assert_eq!(thread_signal(65, true, false), ThreadSignal::Refuse(-22));
        assert_eq!(
            thread_signal(u64::MAX, false, false),
            ThreadSignal::Refuse(-22)
        );
        // Group stops are never started.
        assert_eq!(thread_signal(19, true, false), ThreadSignal::Refuse(-95));
        for signal in 20..=22 {
            assert_eq!(thread_signal(signal, true, true), ThreadSignal::Refuse(-95));
            assert_eq!(thread_signal(signal, true, false), ThreadSignal::Deliver);
        }
        // Another process of the instance: the kill subset only.
        assert_eq!(thread_signal(9, false, false), ThreadSignal::Kill);
        for signal in [1, 6, 10, 15, 19] {
            assert_eq!(
                thread_signal(signal, false, false),
                ThreadSignal::Refuse(-95)
            );
        }
    }

    #[test]
    fn configured_image_reads_allow_large_headers_with_a_finite_bound() {
        for syscall in [0, 17] {
            assert!(configured_arguments_allowed(syscall, 3, 0x1000, 1_862_989));
            assert!(configured_arguments_allowed(
                syscall,
                3,
                0x1000,
                64 * 1024 * 1024
            ));
            assert!(!configured_arguments_allowed(
                syscall,
                3,
                0x1000,
                64 * 1024 * 1024 + 1
            ));
            assert!(!configured_arguments_allowed(syscall, 3, 0x1000, u64::MAX));
            assert!(balanced_arguments_allowed(syscall, 3, 0x1000, 1024 * 1024));
            assert!(!balanced_arguments_allowed(
                syscall,
                3,
                0x1000,
                1024 * 1024 + 1
            ));
        }
    }

    #[test]
    fn configured_vectored_reads_share_the_image_read_bound() {
        // musl stdio's {1, N} and {0, N} shapes, and the bound itself.
        assert!(configured_vectors_allowed(Some(1 + 1024)));
        assert!(configured_vectors_allowed(Some(1024)));
        assert!(configured_vectors_allowed(Some(0)));
        assert!(configured_vectors_allowed(Some(CONFIGURED_READ_BOUND)));
        assert!(!configured_vectors_allowed(Some(CONFIGURED_READ_BOUND + 1)));
        assert!(!configured_vectors_allowed(Some(u64::MAX)));
        // An array the kernel rejects is answered by the kernel.
        assert!(configured_vectors_allowed(None));
    }

    #[test]
    fn configured_surface_mediates_every_read_only_image_form() {
        // readv, readlinkat and faccessat are image reads in configured
        // launch, as read, readlink and access are in both.
        for (configured, balanced) in [(SYS_READV, 0), (SYS_READLINKAT, 89), (SYS_FACCESSAT, 21)] {
            assert_eq!(configured_surface(configured), BalancedSurface::ImageRead);
            assert_eq!(decide_configured(configured).action, Action::Mediate);
            assert_eq!(balanced_surface(balanced), BalancedSurface::ImageRead);
            // Native balanced policy is unchanged.
            assert_eq!(balanced_surface(configured), BalancedSurface::Denied);
            assert_eq!(decide_balanced(configured).action, Action::Deny(38));
        }
        // Every other number keeps its balanced classification and decision.
        for syscall in 0..1024 {
            if matches!(syscall, SYS_READV | SYS_READLINKAT | SYS_FACCESSAT) {
                continue;
            }
            assert_eq!(configured_surface(syscall), balanced_surface(syscall));
            assert_eq!(decide_configured(syscall), decide_balanced(syscall));
        }
        // Writing, vectored writing and the uncatalogued read forms stay
        // outside the image surface: pwritev, writev to an image, preadv,
        // preadv2, readahead, fadvise64, the xattr reads, sendfile and
        // copy_file_range.
        for syscall in [
            20, 296, 295, 327, 187, 221, 191, 192, 193, 194, 195, 196, 40, 326,
        ] {
            assert_ne!(configured_surface(syscall), BalancedSurface::ImageRead);
        }
        assert_eq!(decide_configured(u64::MAX).action, Action::Deny(38));
    }

    #[test]
    fn emulates_virtual_identity() {
        assert_eq!(decide(SYS_GETPID).action, Action::Emulate);
    }

    #[test]
    fn mediates_output_instead_of_continuing_it() {
        assert_eq!(decide(SYS_WRITE).action, Action::Mediate);
    }

    #[test]
    fn denies_selected_and_unknown_syscalls() {
        assert_eq!(decide(SYS_UNAME).action, Action::Deny(1));
        assert_eq!(decide(0xffff).action, Action::Deny(38));
    }

    #[test]
    fn balanced_contract_is_classified_and_fail_closed() {
        assert_eq!(balanced_surface(257), BalancedSurface::ImageRead);
        assert_eq!(balanced_surface(9), BalancedSurface::Memory);
        assert_eq!(balanced_surface(1), BalancedSurface::Console);
        assert_eq!(balanced_surface(SYS_FORK), BalancedSurface::Task);
        assert_eq!(balanced_surface(SYS_WAIT4), BalancedSurface::Task);
        // rt_sigaction and rt_sigprocmask without rt_sigreturn would let a
        // handler run but never return.
        assert_eq!(balanced_surface(15), BalancedSurface::Task);
        assert_eq!(decide_balanced(15).action, Action::Mediate);
        assert_eq!(decide_balanced(0).action, Action::Mediate);
        assert_eq!(decide_balanced(SYS_GETPID).action, Action::Emulate);
        assert_eq!(balanced_identity_result(SYS_GETUID), Some(0));
        assert_eq!(decide_balanced(16).action, Action::Deny(38));
        assert_eq!(decide_balanced(41).action, Action::Deny(38));
        assert_eq!(decide_balanced(999).action, Action::Deny(38));
    }

    #[test]
    fn balanced_contract_rejects_sensitive_and_mutating_operations() {
        assert!(balanced_arguments_allowed(257, 0, 0, 0));
        assert!(!balanced_arguments_allowed(257, 0, 0, 0o100));
        assert!(!balanced_arguments_allowed(257, 0, 0, 1));
        assert!(!balanced_arguments_allowed(10, 0, 0, 6));
        assert_eq!(balanced_surface(16), BalancedSurface::Denied);
        assert_eq!(balanced_surface(41), BalancedSurface::Denied);
        assert_eq!(balanced_surface(105), BalancedSurface::Denied);
    }

    #[test]
    fn balanced_contract_reports_the_virtual_tid() {
        // set_tid_address stays mediated for its clear-on-exit registration,
        // but reports the same virtual id as getpid instead of the host tid.
        assert_eq!(decide_balanced(SYS_SET_TID_ADDRESS).action, Action::Mediate);
        assert!(balanced_arguments_allowed(
            SYS_SET_TID_ADDRESS,
            0x1000,
            0,
            0
        ));
        assert_eq!(
            balanced_mediated_result(SYS_SET_TID_ADDRESS),
            balanced_identity_result(SYS_GETPID)
        );
        for syscall in [0, 1, 9, SYS_FUTEX, SYS_WAIT4, 273, 334] {
            assert_eq!(balanced_mediated_result(syscall), None);
        }
    }

    #[test]
    fn balanced_contract_refuses_signal_driven_io() {
        const SYS_IOCTL: u64 = 16;
        const SYS_FCNTL: u64 = 72;
        const F_DUPFD: u64 = 0;
        const F_GETFD: u64 = 1;
        const F_SETFD: u64 = 2;
        const F_GETFL: u64 = 3;
        const F_SETFL: u64 = 4;
        const F_SETLK: u64 = 6;
        const F_SETOWN: u64 = 8;
        const F_SETSIG: u64 = 10;
        const F_SETOWN_EX: u64 = 15;
        const F_DUPFD_CLOEXEC: u64 = 1030;
        const O_NONBLOCK: u64 = 0o4000;
        const O_ASYNC: u64 = 0o20000;
        const HIGH: u64 = 0xffff_ffff_0000_0000;
        const FIOASYNC: u64 = 0x5452;
        const FIOSETOWN: u64 = 0x8901;
        const SIOCSPGRP: u64 = 0x8902;
        const TIOCGWINSZ: u64 = 0x5413;
        for command in [F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETLK, F_DUPFD_CLOEXEC] {
            assert!(balanced_arguments_allowed(SYS_FCNTL, 1, command, 0));
            // The kernel ignores register bits above the 32-bit command.
            assert!(balanced_arguments_allowed(SYS_FCNTL, 1, command | HIGH, 0));
        }
        for command in [F_SETOWN, F_SETSIG, F_SETOWN_EX] {
            assert!(!balanced_arguments_allowed(SYS_FCNTL, 1, command, 0));
            assert!(!balanced_arguments_allowed(SYS_FCNTL, 1, command | HIGH, 0));
        }
        assert!(balanced_arguments_allowed(
            SYS_FCNTL, 1, F_SETFL, O_NONBLOCK
        ));
        assert!(balanced_arguments_allowed(
            SYS_FCNTL,
            1,
            F_SETFL,
            O_ASYNC << 32
        ));
        assert!(!balanced_arguments_allowed(
            SYS_FCNTL,
            1,
            F_SETFL,
            O_NONBLOCK | O_ASYNC
        ));
        assert!(!balanced_arguments_allowed(
            SYS_FCNTL,
            1,
            F_SETFL | HIGH,
            O_ASYNC | HIGH
        ));
        for request in [FIOASYNC, FIOSETOWN, SIOCSPGRP] {
            assert!(signal_driven_io(SYS_IOCTL, request, 0));
            assert!(!balanced_arguments_allowed(SYS_IOCTL, 1, request | HIGH, 0));
        }
        assert!(balanced_arguments_allowed(SYS_IOCTL, 1, TIOCGWINSZ, 0));
    }

    #[test]
    fn balanced_contract_rejects_priority_inheritance_futexes() {
        const PRIVATE: u64 = 128;
        const CLOCK_REALTIME: u64 = 256;
        // LOCK_PI, UNLOCK_PI, TRYLOCK_PI, WAIT_REQUEUE_PI, CMP_REQUEUE_PI,
        // LOCK_PI2 keep the owner's host tid in the futex word.
        for command in [6, 7, 8, 11, 12, 13] {
            for op in [
                command,
                command | PRIVATE,
                command | CLOCK_REALTIME,
                command | PRIVATE | CLOCK_REALTIME,
                command | PRIVATE | 512,
                command | PRIVATE | 1024,
                command | 1 << 20,
                // Register bits above the 32-bit operation word.
                command | 0xffff_ffff_0000_0000,
            ] {
                assert!(futex_priority_inheritance(op), "{op:#x}");
                assert!(!balanced_arguments_allowed(SYS_FUTEX, 0x1000, op, 0));
            }
        }
        // WAIT, WAKE, FD, REQUEUE, CMP_REQUEUE, WAKE_OP, WAIT_BITSET,
        // WAKE_BITSET and unknown commands stay mediated.
        for command in [0, 1, 2, 3, 4, 5, 9, 10, 14, 0x46] {
            for op in [
                command,
                command | PRIVATE,
                command | PRIVATE | CLOCK_REALTIME,
            ] {
                assert!(!futex_priority_inheritance(op), "{op:#x}");
                assert!(balanced_arguments_allowed(SYS_FUTEX, 0x1000, op, 0));
            }
        }
    }

    #[test]
    fn balanced_contract_allows_read_only_directory_opens() {
        const AT_FDCWD: u64 = -100i64 as u64;
        const O_WRONLY: u64 = 1;
        const O_RDWR: u64 = 2;
        const O_CREAT: u64 = 0o100;
        const O_TRUNC: u64 = 0o1000;
        const O_APPEND: u64 = 0o2000;
        const O_NONBLOCK: u64 = 0o4000;
        const O_DIRECTORY: u64 = 0o200000;
        const O_CLOEXEC: u64 = 0o2000000;
        const O_TMPFILE: u64 = 0o20200000;
        // glibc opendir(): openat(AT_FDCWD, path, O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY)
        let opendir = O_NONBLOCK | O_CLOEXEC | O_DIRECTORY;
        assert!(balanced_arguments_allowed(257, AT_FDCWD, 0x1000, opendir));
        assert!(balanced_arguments_allowed(2, 0x1000, O_DIRECTORY, 0));
        // O_DIRECTORY does not unlock anything mutating, and O_TMPFILE stays
        // denied with or without its O_DIRECTORY bit.
        for flags in [
            O_DIRECTORY | O_WRONLY,
            O_DIRECTORY | O_RDWR,
            O_DIRECTORY | O_CREAT,
            O_DIRECTORY | O_TRUNC,
            O_DIRECTORY | O_APPEND,
            O_TMPFILE,
            O_TMPFILE & !O_DIRECTORY,
        ] {
            assert!(!balanced_arguments_allowed(257, AT_FDCWD, 0x1000, flags));
            assert!(!balanced_arguments_allowed(2, 0x1000, flags, 0));
        }
    }

    #[test]
    fn systemd_contract_adds_shared_network_without_changing_balanced_policy() {
        assert_eq!(decide_balanced(41).action, Action::Deny(38));
        assert_eq!(decide_systemd(41, false).action, Action::Deny(38));
        assert_eq!(decide_systemd(41, true).action, Action::Mediate);
        assert_eq!(systemd_surface(42, true), BalancedSurface::Network);
        assert_eq!(decide_systemd(59, true).action, Action::Mediate);
        assert_eq!(
            decide_systemd(SYS_GETPRIORITY, true).action,
            Action::Emulate
        );
        assert_eq!(
            systemd_surface(SYS_GETPRIORITY, true),
            BalancedSurface::VirtualIdentity
        );
        assert_eq!(
            decide_systemd(SYS_SETPRIORITY, true).action,
            Action::Emulate
        );
        assert_eq!(
            systemd_surface(SYS_SETPRIORITY, true),
            BalancedSurface::VirtualIdentity
        );
        assert_eq!(decide_systemd(165, true).action, Action::Emulate);
        assert_eq!(decide_systemd(166, true).action, Action::Emulate);
        assert_eq!(decide_systemd(63, true).action, Action::Emulate);
        assert_eq!(decide_systemd(291, true).action, Action::Mediate);
        assert_eq!(decide_systemd(289, true).action, Action::Mediate);
        assert_eq!(decide_systemd(294, true).action, Action::Mediate);
        assert_eq!(decide_systemd(283, true).action, Action::Mediate);
        assert_eq!(decide_systemd(56, true).action, Action::Mediate);
        assert_eq!(decide_systemd(62, true).action, Action::Mediate);
        assert_eq!(systemd_surface(62, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(112, true).action, Action::Emulate);
        assert_eq!(systemd_surface(112, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(109, true).action, Action::Emulate);
        assert_eq!(systemd_surface(109, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(93, true).action, Action::Emulate);
        assert_eq!(systemd_surface(93, true), BalancedSurface::InstanceWrite);
        assert_eq!(decide_systemd(153, true).action, Action::Emulate);
        assert_eq!(systemd_surface(153, true), BalancedSurface::Console);
        assert_eq!(decide_systemd(SYS_REBOOT, true).action, Action::Emulate);
        assert_eq!(
            systemd_surface(SYS_REBOOT, true),
            BalancedSurface::Lifecycle
        );
        assert_eq!(decide_balanced(SYS_REBOOT).action, Action::Deny(38));
        assert_eq!(decide_systemd(91, true).action, Action::Mediate);
        assert_eq!(systemd_surface(91, true), BalancedSurface::InstanceWrite);
        assert_eq!(decide_systemd(270, true).action, Action::Mediate);
        assert_eq!(systemd_surface(270, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(290, true).action, Action::Mediate);
        assert_eq!(systemd_surface(290, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(7, true).action, Action::Mediate);
        assert_eq!(systemd_surface(7, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(100, true).action, Action::Mediate);
        assert_eq!(systemd_surface(100, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(98, true).action, Action::Mediate);
        assert_eq!(systemd_surface(98, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(228, true).action, Action::Mediate);
        assert_eq!(systemd_surface(228, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(271, true).action, Action::Mediate);
        assert_eq!(systemd_surface(271, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(292, true).action, Action::Mediate);
        assert_eq!(systemd_surface(292, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(293, true).action, Action::Mediate);
        assert_eq!(systemd_surface(293, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(32, true).action, Action::Mediate);
        assert_eq!(systemd_surface(32, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(33, true).action, Action::Mediate);
        assert_eq!(systemd_surface(33, true), BalancedSurface::Task);
        assert_eq!(decide_systemd(77, true).action, Action::Mediate);
        assert_eq!(systemd_surface(77, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(18, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(73, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(74, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(75, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(76, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(90, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(92, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(93, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(94, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(260, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(280, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(306, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(79, true), BalancedSurface::Task);
        assert_eq!(systemd_surface(81, true), BalancedSurface::Task);
        assert_eq!(systemd_surface(190, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(196, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(199, true), BalancedSurface::InstanceWrite);
        assert_eq!(decide_systemd(25, true).action, Action::Mediate);
        assert_eq!(systemd_surface(25, true), BalancedSurface::Memory);
        assert_eq!(systemd_surface(82, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(87, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(84, true), BalancedSurface::InstanceWrite);
        assert_eq!(systemd_surface(193, true), BalancedSurface::ImageRead);
        assert_eq!(
            systemd_surface(SYS_SETUID, true),
            BalancedSurface::VirtualIdentity
        );
        assert_eq!(
            systemd_surface(SYS_SETGID, true),
            BalancedSurface::VirtualIdentity
        );
        assert_eq!(
            systemd_surface(SYS_SETGROUPS, true),
            BalancedSurface::VirtualIdentity
        );
        assert_eq!(
            systemd_surface(SYS_SETREUID, true),
            BalancedSurface::VirtualIdentity
        );
        assert_eq!(
            systemd_surface(SYS_SETREGID, true),
            BalancedSurface::VirtualIdentity
        );
        assert_eq!(
            systemd_surface(SYS_CLOSE_RANGE, true),
            BalancedSurface::Task
        );
        assert_eq!(decide_systemd(435, true).action, Action::Mediate);
        assert_eq!(decide_systemd(SYS_PIDFD_OPEN, true).action, Action::Mediate);
        assert_eq!(systemd_surface(SYS_PIDFD_OPEN, true), BalancedSurface::Task);
        assert_eq!(
            decide_systemd(SYS_PIDFD_SEND_SIGNAL, true).action,
            Action::Mediate
        );
        assert_eq!(decide_systemd(452, true).action, Action::Mediate);
        assert_eq!(systemd_surface(452, true), BalancedSurface::InstanceWrite);
        assert_eq!(decide_systemd(247, true).action, Action::Mediate);
        assert_eq!(decide_systemd(SYS_READLINKAT, true).action, Action::Mediate);
        assert_eq!(decide_systemd(88, true).action, Action::Mediate);
        assert_eq!(decide_systemd(SYS_UNLINKAT, true).action, Action::Mediate);
        assert_eq!(decide_systemd(SYS_RENAMEAT, true).action, Action::Mediate);
        assert_eq!(decide_systemd(SYS_LINKAT, true).action, Action::Mediate);
        assert_eq!(decide_systemd(SYS_SYMLINKAT, true).action, Action::Mediate);
        assert_eq!(
            decide_systemd(SYS_MEMFD_CREATE, true).action,
            Action::Mediate
        );
        assert_eq!(decide_systemd(SYS_GETTID, true).action, Action::Emulate);
        assert_eq!(
            systemd_surface(SYS_READLINKAT, true),
            BalancedSurface::ImageRead
        );
        assert_eq!(systemd_surface(88, true), BalancedSurface::InstanceWrite);
        assert_eq!(
            systemd_surface(SYS_UNLINKAT, true),
            BalancedSurface::InstanceWrite
        );
        assert_eq!(
            systemd_surface(SYS_RENAMEAT, true),
            BalancedSurface::InstanceWrite
        );
        assert_eq!(
            systemd_surface(SYS_LINKAT, true),
            BalancedSurface::InstanceWrite
        );
        assert_eq!(
            systemd_surface(SYS_SYMLINKAT, true),
            BalancedSurface::InstanceWrite
        );
        assert_eq!(decide_balanced(SYS_READLINKAT).action, Action::Deny(38));
        assert_eq!(decide_balanced(88).action, Action::Deny(38));
        assert_eq!(decide_balanced(SYS_UNLINKAT).action, Action::Deny(38));
        assert_eq!(decide_balanced(SYS_RENAMEAT).action, Action::Deny(38));
        assert_eq!(decide_balanced(SYS_LINKAT).action, Action::Deny(38));
        assert_eq!(decide_balanced(SYS_SYMLINKAT).action, Action::Deny(38));
        assert_eq!(decide_balanced(SYS_MEMFD_CREATE).action, Action::Deny(38));
        assert_eq!(decide_balanced(SYS_GETTID).action, Action::Deny(38));
        assert_eq!(decide_balanced(63).action, Action::Deny(38));
        assert_eq!(decide_balanced(291).action, Action::Deny(38));
        assert_eq!(decide_balanced(289).action, Action::Deny(38));
        assert_eq!(decide_balanced(294).action, Action::Deny(38));
        assert_eq!(decide_balanced(283).action, Action::Deny(38));
        assert_eq!(decide_balanced(56).action, Action::Deny(38));
        assert_eq!(decide_balanced(62).action, Action::Deny(38));
        assert_eq!(decide_balanced(435).action, Action::Deny(38));
        assert_eq!(decide_balanced(247).action, Action::Deny(38));
    }
}
