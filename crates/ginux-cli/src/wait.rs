//! Foreground `start --wait`: tie the helper's waiting process to this CLI
//! process and relay terminating signals to it.
//!
//! The CLI does not `exec` sudo here. A parent's `PR_SET_PDEATHSIG` on this
//! process would be cleared by exec of a set-user-ID program, so this process
//! stays alive as the caller the helper watches (by PID and start time).

use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

/// How long a relayed terminating signal may take to end the helper before
/// this process exits on that signal itself. Once it is gone, the helper sees
/// its caller vanish and stops the instance on its own.
const RELAY_GRACE: Duration = Duration::from_secs(1);

const TERMINATING: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// This process's PID and its start time in clock ticks since boot (field 22
/// of `/proc/self/stat`), which together identify it across PID reuse.
pub fn caller_identity() -> io::Result<(u32, u64)> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    let start = start_time(&stat)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unreadable /proc/self/stat"))?;
    Ok((std::process::id(), start))
}

/// Field 22 of a `/proc/PID/stat` line. Fields are counted after the last
/// `)`, because the command name in field 2 may contain spaces and `)`.
pub fn start_time(stat: &str) -> Option<u64> {
    let (_, rest) = stat.rsplit_once(')')?;
    // `rest` begins with field 3, so field 22 is the 20th word.
    rest.split_whitespace().nth(19)?.parse().ok()
}

struct SignalSet(libc::sigset_t);

impl SignalSet {
    fn new(signals: &[libc::c_int]) -> Self {
        let mut set = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: `sigemptyset` initializes the set; `sigaddset` only receives
        // valid signal numbers and the initialized set.
        unsafe {
            libc::sigemptyset(set.as_mut_ptr());
            for signal in signals {
                libc::sigaddset(set.as_mut_ptr(), *signal);
            }
            Self(set.assume_init())
        }
    }
}

/// Restores the previous signal mask when dropped.
struct MaskGuard(libc::sigset_t);

impl MaskGuard {
    fn block(set: &SignalSet) -> io::Result<Self> {
        let mut previous = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: both pointers refer to valid sigset storage for the call.
        let result =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set.0, previous.as_mut_ptr()) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        // SAFETY: a successful `pthread_sigmask` wrote the previous mask.
        Ok(Self(unsafe { previous.assume_init() }))
    }
}

impl Drop for MaskGuard {
    fn drop(&mut self) {
        // SAFETY: restores a mask previously returned by `pthread_sigmask`.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut());
        }
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

/// Run `command` (the `sudo` helper invocation) in the foreground and return
/// its exit code. `SIGINT`, `SIGTERM`, `SIGHUP` and `SIGQUIT` are relayed to
/// it. The child gets an empty signal mask before exec: the standard library
/// does not reset an inherited mask, and the relayed signals are blocked here.
pub fn run_waiting(command: &mut Command) -> io::Result<i32> {
    let mut all = TERMINATING.to_vec();
    all.push(libc::SIGCHLD);
    let set = SignalSet::new(&all);
    let guard = MaskGuard::block(&set)?;
    // SAFETY: the closure runs in the forked child before exec and only calls
    // the async-signal-safe `sigemptyset` and `pthread_sigmask` on local
    // storage.
    unsafe {
        command.pre_exec(|| {
            let mut empty = MaybeUninit::<libc::sigset_t>::uninit();
            libc::sigemptyset(empty.as_mut_ptr());
            let result =
                libc::pthread_sigmask(libc::SIG_SETMASK, empty.as_ptr(), std::ptr::null_mut());
            if result != 0 {
                return Err(io::Error::from_raw_os_error(result));
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    loop {
        if let Some(status) = child.try_wait()? {
            drop(guard);
            return Ok(exit_code(status));
        }
        let mut signal: libc::c_int = 0;
        // SAFETY: `set` is initialized and every member is blocked by `guard`.
        let result = unsafe { libc::sigwait(&set.0, &mut signal) };
        if result != 0 || signal == libc::SIGCHLD {
            continue;
        }
        if let Some(code) = relay(&mut child, signal)? {
            drop(guard);
            return Ok(code);
        }
        drop(guard);
        die_by(signal);
    }
}

/// Relay `signal` to the child and give it [`RELAY_GRACE`] to finish.
fn relay(child: &mut Child, signal: libc::c_int) -> io::Result<Option<i32>> {
    if let Ok(pid) = libc::pid_t::try_from(child.id()) {
        // SAFETY: `kill` takes plain integers; `pid` is our own unreaped child,
        // so the number cannot have been reused.
        unsafe {
            libc::kill(pid, signal);
        }
    }
    let deadline = Instant::now() + RELAY_GRACE;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(exit_code(status)));
        }
        thread::sleep(Duration::from_millis(20));
    }
    Ok(None)
}

/// Terminate this process by `signal` with its default action, so the caller
/// sees the conventional signal status.
fn die_by(signal: libc::c_int) -> ! {
    // SAFETY: resetting a standard signal to its default action and raising it
    // has no memory-safety preconditions.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
    std::process::exit(128 + signal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_time_counts_fields_after_the_last_parenthesis() {
        let stat =
            "1234 (a) b) c) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10";
        assert_eq!(start_time(stat), Some(987654));
        let plain = "77 (ginux) R 1 77 77 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 42 0 0";
        assert_eq!(start_time(plain), Some(42));
    }

    #[test]
    fn start_time_rejects_truncated_lines() {
        assert_eq!(start_time("1 (x) S 1 2 3"), None);
        assert_eq!(start_time("no parenthesis"), None);
    }

    #[test]
    fn own_identity_is_readable() {
        let (pid, start) = caller_identity().unwrap();
        assert_eq!(pid, std::process::id());
        assert!(start > 0);
    }
}
