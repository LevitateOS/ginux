//! Task ownership for configured native launch. A newborn never runs before
//! its process identity and descriptor snapshot are installed.

use crate::descriptors::{Backends, DescriptorCall, DescriptorTable, ExecDescriptor};
use crate::dispatch::{
    balanced_surface_name, decide_launch, launch_arguments_allowed, NativeDecision,
};
use crate::launch::{
    audit_i64, audit_u64, audit_write, finish_exited, finish_signaled, launch_early_fail,
    launch_exit_reason, line_stderr, supervision_error, write_stderr, write_stderr_u64,
};
use crate::supervisor::*;
use crate::tracee_io::copy_memory;
use ginux_contract::{Action as ContractAction, EffectiveContract};
use ginux_core::{balanced_identity_result, configured_surface, Action, NumberStep};
use ginux_instance::Instance;
use ginux_process::{Credentials, ProcessError, ProcessTable, TaskId, WaitTarget};
use ginux_vfs::Executable;

const TASKS: usize = 32;
const WALL: usize = 0x4000_0000;
// Linux x86-64: sys/ptrace and asm/unistd_64.h.
const SYSCALL_STOP_OPTIONS: usize = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | 2 | 4 | 8 | 16;
/// Options the bootstrap tracee is seized with. Seccomp events must already
/// be traced when it installs the launch filter and executes the workload;
/// without the filter none arrive, and supervision drops the option.
pub(crate) const OPTIONS: usize = SYSCALL_STOP_OPTIONS | PTRACE_O_TRACESECCOMP;
/// Legacy vsyscall page. The kernel emulates calls made there and reports
/// them to seccomp, but never as ptrace syscall stops.
const VSYSCALL_PAGE: u64 = 0xffff_ffff_ff60_0000;
/// Linux x86-64 `eventfd2` and its `EFD_CLOEXEC`: an inert host placeholder
/// at the lowest free number, closed by any exec.
const SYS_EVENTFD2: u64 = 290;
const EFD_CLOEXEC: u64 = 0o2000000;

#[derive(Clone, Copy)]
enum Pending {
    None,
    Fork {
        child: usize,
        flags: u64,
        thread: bool,
        child_tid: Option<u64>,
        parent_tid: Option<u64>,
    },
    Wait {
        child: usize,
        original: [u64; 7],
        status: u32,
    },
}

/// A reserved creation the kernel abandoned with ERESTARTNOINTR before it
/// made a child. Only the kernel's reissue of the same call claims it.
#[derive(Clone, Copy)]
struct Restart {
    reservation: Pending,
    syscall: u64,
    rip: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExecStage {
    Sync,
    Reenter,
    Create,
    Close,
    Kernel,
    Completed,
    Retire,
    RetireReenter,
}

#[derive(Clone, Copy)]
struct Exec {
    original: UserRegs,
    native_dirfd: u64,
    next_native: usize,
    stage: ExecStage,
    owned: Option<OwnedExec>,
    retire: Option<u32>,
}

#[derive(Clone, Copy)]
struct OwnedExec {
    image: Executable,
    empty_path: u64,
    descriptor: Option<u32>,
    legacy_create: bool,
    failure: Option<i64>,
    script: Option<crate::exec_script::Script>,
}

struct Task {
    id: TaskId,
    host: usize,
    alive: bool,
    running: bool,
    held_status: Option<i32>,
    adopted_reaped: bool,
    wait_status: Option<i32>,
    group: usize,
    call: DescriptorCall,
    image_chdir: Option<u64>,
    pending: Pending,
    /// A creation awaiting the kernel's reissue of its call; not pending, so
    /// the calls of a signal handler run before the reissue are its own.
    restart: Option<Restart>,
    override_result: Option<i64>,
    blocked: Option<UserRegs>,
    sequence: u64,
    exec: Option<Exec>,
    mapping: Option<crate::file_mapping::MappingCall>,
    path_rewrite: Option<crate::path_hooks::Rewrite>,
    waiter: Option<usize>,
    sleep: Option<crate::clock_hooks::Sleep>,
    /// Restart result of a parked object wait; `None` while the park is only
    /// a short ordering gate that no signal may end.
    interruptible: Option<i64>,
    /// A parked call handed back to the kernel so a queued signal can arrive.
    unpark: Option<Unpark>,
    /// The tracee's own signal mask while an injected transaction blocks it.
    signal_hold: Option<u64>,
    /// Native reaps the supervisor had completed when this task last resumed.
    reaps_seen: u64,
    /// A peer queued a signal on this task since a park last examined it.
    signalled: bool,
    /// Host thread this task's in-flight `tgkill` signals, other than itself.
    signal_target: Option<usize>,
    /// The task's current syscall has been seen at its entry and its exit
    /// is still to come: either the task is stopped at that entry, or it was
    /// resumed to stop at the exit.
    in_flight: bool,
    /// The registers read at this task's current stop, while nothing has
    /// written others: `run` resumes without PTRACE_SETREGS when it would
    /// write exactly these.
    stopped: Option<UserRegs>,
    /// The registers the in-flight syscall runs with need its exit: saved
    /// arguments differ from them, or the kernel may end it with an internal
    /// restart the exit translates.
    exit_registers: bool,
    alignment: Option<Alignment>,
}

/// A native open whose host table is being made to give it its public
/// number. Each placeholder step replaces the stopped open, its exit replays
/// the open's own instruction, and the open runs once no step is left. The
/// open holds the argument guard throughout, so no other task changes the
/// host table meanwhile.
#[derive(Clone, Copy)]
struct Alignment {
    /// The workload's registers at the open's entry, replayed after each step.
    original: UserRegs,
    /// The open as it runs once the table is aligned.
    open: UserRegs,
    /// The public number the open has reserved.
    slot: usize,
    /// The step in flight, settled at its exit.
    step: Option<NumberStep>,
    /// The kernel had no descriptor for a placeholder: the open runs as it
    /// stands, and its number is translated as any unequal one is.
    abandoned: bool,
}

/// A parked syscall being returned to its own instruction. The skipped entry
/// exits first; the replayed entry is then an ordinary retry of the call.
#[derive(Clone, Copy)]
struct Unpark {
    original: UserRegs,
    restart: i64,
    replaying: bool,
}

impl Task {
    fn new(id: TaskId, host: usize, group: usize) -> Self {
        Self {
            id,
            host,
            alive: true,
            running: false,
            held_status: None,
            adopted_reaped: false,
            wait_status: None,
            group,
            call: DescriptorCall::new(),
            image_chdir: None,
            pending: Pending::None,
            restart: None,
            override_result: None,
            blocked: None,
            sequence: 0,
            exec: None,
            mapping: None,
            path_rewrite: None,
            waiter: None,
            sleep: None,
            interruptible: None,
            unpark: None,
            signal_hold: None,
            reaps_seen: 0,
            signalled: false,
            signal_target: None,
            in_flight: false,
            stopped: None,
            exit_registers: true,
            alignment: None,
        }
    }
}

struct DescriptorGroup {
    table: DescriptorTable,
    owners: usize,
    leader: TaskId,
    status: Option<i32>,
    creating: Option<usize>,
    image: Option<Executable>,
    cwd: Option<i32>,
    creation_mask: u32,
}

#[derive(Clone, Copy)]
struct Denial {
    count: u64,
    first_sequence: u64,
    first_pid: u32,
    first_syscall: u64,
}

struct Supervisor<'a> {
    tasks: [Option<Task>; TASKS],
    groups: [Option<DescriptorGroup>; TASKS],
    processes: ProcessTable<TASKS>,
    objects: Backends<'a>,
    contract: &'a EffectiveContract,
    denials: [Option<Denial>; ginux_contract::MAX_OPERATIONS + 1],
    unknown_stops: [usize; TASKS],
    retired: [(usize, u32); TASKS],
    retired_next: usize,
    sequence: u64,
    wake_needed: bool,
    tearing_down: bool,
    signal_fd: Option<usize>,
    root_status: Option<i32>,
    creation_failure_reported: bool,
    argument_guard: Option<usize>,
    /// Terminal statuses collected so far. Each native reap can queue SIGCHLD
    /// for a task the supervisor is holding in a stop.
    reaps: u64,
    /// The launch filter is installed: every workload syscall reaches the
    /// supervisor as a seccomp event at its entry, tasks run between
    /// syscalls under `PTRACE_CONT`, and a syscall stops at its exit only
    /// when that exit has work. Without the filter every task is resumed
    /// with `PTRACE_SYSCALL` and every syscall stops at entry and exit.
    seccomp: bool,
}

fn birth_stop(status: i32) -> bool {
    stopped(status) && (status as u32 >> 16) == 128 && ((status >> 8) & 255) == 5
}

fn path_call(syscall: u64) -> bool {
    matches!(
        syscall,
        2 | 4
            | 6
            | 21
            | 59
            | 80
            | 82
            | 83
            | 84
            | 86
            | 87
            | 88
            | 89
            | 90
            | 92
            | 94
            | 133
            | 257
            | 258
            | 259
            | 260
            | 262
            | 263
            | 264
            | 265
            | 266
            | 267
            | 268
            | 269
            | 280
            | 316
            | 322
            | 332
            | 439
            | 452
    )
}

// Created only after the tracee's initial exec stop, so neither the blocked
// signal nor this private descriptor can enter the workload. SIGCHLD remains
// blocked between wait4(WNOHANG) and poll: a new ptrace stop cannot be lost in
// that interval. wait4 owns statuses; signalfd is only a wakeup notification.
fn task_events() -> Result<usize, &'static [u8]> {
    let mask = 1u64 << (SIGCHLD - 1);
    let action = [0u64; 4];
    if unsafe {
        syscall4(
            SYS_RT_SIGPROCMASK,
            SIG_BLOCK,
            &mask as *const _ as usize,
            0,
            8,
        )
    } < 0
        || unsafe { syscall4(13, SIGCHLD, action.as_ptr() as usize, 0, 8) } < 0
    {
        return Err(b"task event signal setup failed");
    }
    let fd = unsafe {
        syscall4(
            SYS_SIGNALFD4,
            usize::MAX,
            &mask as *const _ as usize,
            8,
            0x80800,
        )
    };
    if fd < 0 {
        return Err(b"task event descriptor setup failed");
    }
    Ok(fd as usize)
}

fn wait_events(signal_fd: usize, polling: bool) -> Result<(), &'static [u8]> {
    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }
    let (control, events) = crate::checkpoint_control::readiness();
    let mut fds = [
        PollFd {
            fd: signal_fd as i32,
            events: 1,
            revents: 0,
        },
        PollFd {
            fd: control,
            events,
            revents: 0,
        },
    ];
    // Private task/control events wake immediately. External IO and finite
    // owned polls also get a bounded tick, without a separate sleep loop.
    let timeout = if polling { 1 } else { usize::MAX };
    let result = unsafe { syscall3(7, fds.as_mut_ptr() as usize, fds.len(), timeout) };
    if result < 0 && result != -4 {
        return Err(b"task event wait failed");
    }
    if fds[0].revents & !1 != 0 {
        return Err(b"task event descriptor failed");
    }
    if fds[0].revents & 1 != 0 {
        let mut info = [0u8; 128];
        let count = unsafe {
            syscall3(
                SYS_READ_HOST,
                signal_fd,
                info.as_mut_ptr() as usize,
                info.len(),
            )
        };
        if count != 128 && count != -4 && count != -11 {
            return Err(b"task event read failed");
        }
    }
    Ok(())
}

/// Stops between two reads of the checkpoint control socket while the
/// workload keeps the loop busy.
const CONTROL_CHECK_STOPS: u32 = 64;

pub fn supervise(
    root: usize,
    instance: &mut Instance,
    objects: Backends,
    descriptors: DescriptorTable,
    contract: &EffectiveContract,
) -> ! {
    let mut status = 0;
    let mut seccomp = false;
    let waited = loop {
        let result = wait(root, &mut status);
        if result == -4 {
            continue;
        }
        // The bootstrap's own exec, and its failure report if that exec
        // fails, are supervisor code: they run as before, unexamined.
        if result == root as isize
            && stopped(status)
            && (status as u32 >> 16) as usize == PTRACE_EVENT_SECCOMP
        {
            seccomp = true;
            if ptrace(PTRACE_CONT, root, 0, 0) >= 0 {
                continue;
            }
        }
        break result;
    };
    if waited < 0 {
        if waited != -10 {
            let _ = unsafe { syscall2(SYS_KILL, root, SIGKILL) };
            while wait(root, &mut status) == -4 {}
        }
        supervision_error(instance, b"launch tracee wait after exec failed");
    }
    if exited(status) {
        launch_early_fail(instance, launch_exit_reason((status >> 8) & 255));
    }
    if signaled(status) {
        // The terminal wait already reaped this PID; never signal it again.
        supervision_error(instance, b"launch tracee signaled before supervision");
    }
    if !stopped(status) || (status >> 8) & 255 != 5 {
        let _ = unsafe { syscall2(SYS_KILL, root, SIGKILL) };
        while wait(root, &mut status) == -4 {}
        supervision_error(instance, b"launch tracee did not stop after exec");
    }
    if objects.filesystem.validate_initial_exec(root).is_err() {
        let _ = unsafe { syscall2(SYS_KILL, root, SIGKILL) };
        while wait(root, &mut status) == -4 {}
        supervision_error(
            instance,
            b"initial executable interpreter is outside its image namespace",
        );
    }
    let mut processes = ProcessTable::new();
    let id = processes
        .create_init(Credentials::unprivileged(0, 0))
        .unwrap();
    let mut s = Supervisor {
        tasks: core::array::from_fn(|_| None),
        groups: core::array::from_fn(|_| None),
        processes,
        objects,
        contract,
        denials: [None; ginux_contract::MAX_OPERATIONS + 1],
        unknown_stops: [0; TASKS],
        retired: [(0, 0); TASKS],
        retired_next: 0,
        sequence: 0,
        wake_needed: false,
        tearing_down: false,
        signal_fd: None,
        root_status: None,
        creation_failure_reported: false,
        argument_guard: None,
        reaps: 0,
        seccomp,
    };
    s.groups[0] = Some(DescriptorGroup {
        table: descriptors,
        owners: 1,
        leader: id,
        status: None,
        creating: None,
        image: None,
        cwd: None,
        creation_mask: 0o022,
    });
    s.tasks[0] = Some(Task::new(id, root, 0));
    if ptrace(PTRACE_SETOPTIONS, root, 0, s.options()) < 0 {
        s.fail(instance, b"launch ptrace setup failed");
    }
    line_stderr(b"ginux: launch backend=ptrace-native profile=balanced elf-loader=host");
    // The host identity the tracee runs as: 65534 for a root caller, else the
    // caller's own (inside its private user namespace).
    let identity = managed_host_identity();
    write_stderr(b"ginux: launch tracee-uid=");
    write_stderr_u64(identity.uid as u64);
    write_stderr(b" tracee-gid=");
    write_stderr_u64(identity.gid as u64);
    line_stderr(b" root=host-path-read-only");
    let signal_fd = task_events().unwrap_or_else(|reason| s.fail(instance, reason));
    s.signal_fd = Some(signal_fd);
    s.resume(0, 0, instance);
    let mut poll_tick = 0;
    let mut control_countdown: u32 = 1;
    loop {
        let polling = s
            .tasks
            .iter()
            .flatten()
            .any(|t| t.blocked.is_some() && t.call.needs_poll_tick());
        if polling {
            let now = crate::descriptors::monotonic_nanoseconds()
                .unwrap_or_else(|_| s.fail(instance, b"readiness clock failed"))
                / 1_000_000;
            if now != poll_tick {
                poll_tick = now;
                s.wake_needed = true;
            }
        }
        s.wake(instance);
        // The control socket is read when the loop has just waited for events
        // (its readiness is among them) and otherwise once every
        // CONTROL_CHECK_STOPS stops, rather than with a failing nonblocking
        // read on every stop: a busy workload still sees a request within a
        // few milliseconds.
        control_countdown = control_countdown.saturating_sub(1);
        if control_countdown == 0 {
            control_countdown = CONTROL_CHECK_STOPS;
            if let Err(reason) = crate::checkpoint_control::poll(|path| {
                if s.argument_guard.is_some() {
                    return Ok(false);
                }
                // A snapshot has no guest owner: stop every task, including
                // userspace writers through shared owned-file mappings.
                s.begin_argument_guard(usize::MAX, instance);
                let result = s.objects.filesystem.snapshot(path);
                s.release_argument_guard(instance);
                result.map(|_| true)
            }) {
                s.fail(instance, reason);
            }
        }
        status = 0;
        let held = if s.argument_guard.is_none() {
            s.tasks
                .iter_mut()
                .flatten()
                .find_map(|task| task.held_status.take().map(|status| (task.host, status)))
        } else {
            None
        };
        let host = if let Some((saved_host, saved_status)) = held {
            status = saved_status;
            saved_host as isize
        } else {
            unsafe {
                syscall4(
                    SYS_WAIT4,
                    usize::MAX,
                    &mut status as *mut _ as usize,
                    WALL | 1,
                    0,
                )
            }
        };
        if host == 0 {
            if let Err(reason) = wait_events(signal_fd, polling) {
                s.fail(instance, reason);
            }
            control_countdown = 1;
            continue;
        }
        if host == -4 {
            continue;
        }
        if host < 0 {
            s.fail(instance, b"launch task wait failed")
        }
        let host = host as usize;
        if held.is_none() && (exited(status) || signaled(status)) {
            s.reaps += 1;
        }
        let index = s
            .tasks
            .iter()
            .position(|t| t.as_ref().is_some_and(|t| t.host == host && host != 0));
        let Some(index) = index else {
            if exited(status) || signaled(status) {
                // A newborn that died before its parent could publish it, or
                // a task already retired from the table. It is reaped and
                // holds nothing; only its ledger entry remains to clear.
                for unknown in s.unknown_stops.iter_mut().filter(|p| **p == host) {
                    *unknown = 0;
                }
                continue;
            }
            // This stop has been consumed: nothing else would report the
            // task again, so it must not outlive a failure unrecorded.
            if birth_stop(status) {
                // Auto-attached children can report their birth stop before
                // the parent's event. Hold them; GETEVENTMSG must confirm
                // ownership.
                let Some(slot) = s.unknown_stops.iter().position(|p| *p == 0) else {
                    let _ = unsafe { syscall2(SYS_KILL, host, SIGKILL) };
                    s.fail(instance, b"unregistered task bound exceeded")
                };
                s.unknown_stops[slot] = host;
                s.settle_newborns();
                continue;
            }
            let _ = unsafe { syscall2(SYS_KILL, host, SIGKILL) };
            s.fail(instance, b"event from unregistered task");
        };
        s.task_mut(index).running = false;
        if s.argument_guard.is_some_and(|owner| owner != index) {
            if let Some(saved) = s.task(index).held_status {
                // exit_group can terminate a peer while its earlier syscall or
                // interrupt stop is held. The terminal event supersedes that
                // now-invalid stop; never resume it or inspect stale registers.
                // Conflicting nonterminal or repeated terminal events still
                // require explicit ownership rather than silently overwriting.
                if !stopped(saved) || !(exited(status) || signaled(status)) {
                    s.fail(instance, b"multiple held stops for one task");
                }
            }
            s.task_mut(index).held_status = Some(status);
            continue;
        }
        if exited(status) || signaled(status) {
            if s.argument_guard == Some(index) {
                s.release_argument_guard(instance);
            }
            s.died(index, status, instance);
            if let Some(status) = s.root_status {
                s.teardown(instance, status == 0);
                let normal = exited(status);
                let _ = instance.task_exited(normal);
                if normal {
                    finish_exited(((status >> 8) & 255) as u64)
                } else {
                    finish_signaled((status & 127) as u64)
                }
            }
            continue;
        }
        if !stopped(status) {
            s.fail(instance, b"task escaped supervision")
        }
        let event = (status as u32 >> 16) as usize;
        if matches!(event, 1..=3) {
            s.birth(index, instance);
            continue;
        }
        if event == 4 {
            if s.argument_guard == Some(index) {
                s.release_argument_guard(instance);
            }
            s.exec_completed(index, instance);
            continue;
        }
        if event == 128 {
            // An interrupt requested by the path guard may arrive after its
            // owner released the hold. Resume that synthetic SIGTRAP stop.
            if birth_stop(status) {
                s.resume(index, 0, instance);
                continue;
            }
            // Real group stops cannot be forwarded as signal delivery.
            s.fail(instance, b"launch group stops are unsupported")
        }
        let seccomp_stop = event == PTRACE_EVENT_SECCOMP && s.seccomp;
        if event != 0 && !seccomp_stop {
            s.fail(instance, b"unsupported task transition")
        }
        let signal = ((status >> 8) & 255) as usize;
        if !seccomp_stop && signal != 133 {
            s.signal_reaches_held_call(index, signal, instance);
            // Injected transactions block signals for their whole duration,
            // so this stop cannot belong to one.
            if s.task(index).mapping.is_some()
                || s.task(index).alignment.is_some()
                || s.task(index).exec.is_some_and(|e| {
                    matches!(
                        e.stage,
                        ExecStage::Sync
                            | ExecStage::Reenter
                            | ExecStage::Create
                            | ExecStage::Close
                            | ExecStage::Retire
                            | ExecStage::RetireReenter
                    )
                })
            {
                s.fail(instance, b"signal interrupted exec descriptor setup");
            }
            let mut info = [0u64; 16];
            if ptrace(0x4202, host, 0, info.as_mut_ptr() as usize) < 0 {
                s.fail(instance, b"launch group stops are unsupported")
            }
            let bytes =
                unsafe { core::slice::from_raw_parts_mut(info.as_mut_ptr().cast::<u8>(), 128) };
            let code = i32::from_ne_bytes(bytes[8..12].try_into().unwrap());
            if signal == 17 || matches!(code, 0 | -1 | -6) {
                let source = u32::from_ne_bytes(bytes[16..20].try_into().unwrap()) as usize;
                let virtual_pid = s.virtual_pid(source).unwrap_or(0);
                bytes[16..20].copy_from_slice(&virtual_pid.to_ne_bytes());
                bytes[20..24].copy_from_slice(&0u32.to_ne_bytes());
                if ptrace(0x4203, host, 0, info.as_ptr() as usize) < 0 {
                    s.fail(instance, b"signal identity projection failed")
                }
            }
            audit_write(b"ginux: audit phase=signal-forwarded signal=");
            audit_u64(signal as u64);
            audit_write(b"\n");
            s.resume(index, signal, instance);
            continue;
        }
        let mut r = match s.read_registers(index) {
            Ok(registers) => registers,
            Err(-3) => continue,
            Err(_) => s.fail(instance, b"launch register read failed"),
        };
        s.task_mut(index).stopped = Some(r);
        let mut info = [0u64; 11];
        let info_length = ptrace(
            0x420e,
            host,
            core::mem::size_of_val(&info),
            info.as_mut_ptr() as usize,
        );
        // Preserve task ownership when a peer's SIGKILL invalidates this stop;
        // wait4's actual terminal event remains the sole death transition.
        if info_length == -3 {
            continue;
        }
        if info_length < 24 || (info[0] >> 32) as u32 != 0xc000003e {
            s.fail(instance, b"launch requires the x86-64 syscall ABI")
        }
        // SEIZE reports the initial exec event before its syscall-exit stop.
        // No guest syscall entry has occurred yet, so do not audit a phantom
        // sequence-zero exit or run per-syscall completion logic.
        if index == 0 && s.task(index).sequence == 0 && info[0] as u8 == 2 {
            s.resume(index, 0, instance);
            continue;
        }
        if seccomp_stop {
            if info[0] as u8 != 3 {
                s.fail(instance, b"unknown syscall stop");
            }
            // Never a ptrace syscall stop: the vsyscall page stays unexamined,
            // as it is without the launch filter. Its emulation refuses any
            // change of syscall or instruction pointer.
            if info[1] & !0xfff == VSYSCALL_PAGE {
                s.resume(index, 0, instance);
                continue;
            }
            // A task resumed for its exit stops there before any new entry,
            // and no workload filter can exist (see `run`).
            if s.task(index).in_flight || info[10] as u32 != LAUNCH_FILTER_DATA {
                s.fail(instance, b"unexpected seccomp stop");
            }
        } else if s.seccomp && info[0] as u8 == 1 {
            // Tasks are resumed with PTRACE_SYSCALL only to stop at the exit
            // of a call already seen at its seccomp stop.
            s.fail(instance, b"unexpected syscall-entry stop");
        }
        match info[0] as u8 {
            1 | 3 => {
                let task = s.task_mut(index);
                task.in_flight = true;
                task.exit_registers = true;
                if s.needs_argument_guard(index, &r) {
                    s.begin_argument_guard(index, instance);
                }
                s.entry(index, &mut r, instance);
                if s.argument_guard == Some(index)
                    && (s.task(index).blocked.is_some() || !s.task(index).in_flight)
                {
                    s.release_argument_guard(instance);
                }
            }
            2 => {
                s.task_mut(index).in_flight = false;
                s.syscall_exit(index, &mut r, instance);
                if s.argument_guard == Some(index)
                    && s.task(index).exec.is_none()
                    && s.task(index).mapping.is_none()
                    && s.task(index).alignment.is_none()
                {
                    s.release_argument_guard(instance);
                }
            }
            _ => s.fail(instance, b"unknown syscall stop"),
        }
    }
}

impl Supervisor<'_> {
    fn group(&self, index: usize) -> &DescriptorGroup {
        self.groups[self.task(index).group].as_ref().unwrap()
    }
    fn group_mut(&mut self, index: usize) -> &mut DescriptorGroup {
        let group = self.task(index).group;
        self.groups[group].as_mut().unwrap()
    }
    fn table(&self, index: usize) -> &DescriptorTable {
        &self.group(index).table
    }
    /// Options for every traced task: seccomp events only while the launch
    /// filter is installed.
    fn options(&self) -> usize {
        if self.seccomp {
            OPTIONS
        } else {
            SYSCALL_STOP_OPTIONS
        }
    }
    fn needs_argument_guard(&self, index: usize, r: &UserRegs) -> bool {
        // Thread clone publishes parent_tid only after the native birth event.
        path_call(r.orig_rax)
            || (r.orig_rax == 13 && r.rdi == 17 && r.rsi != 0 && r.r10 == 8)
            || (r.orig_rax == 56 && matches!(r.rdi, 0x3d0f00 | 0x7d0f00))
            || (r.orig_rax == 9
                && r.r10 & 0x20 == 0
                && self
                    .table(index)
                    .mapping_file(r.r8)
                    .is_ok_and(|file| file.is_some()))
    }
    fn release_group(
        &mut self,
        index: usize,
        instance: &mut Instance,
    ) -> Option<(TaskId, Option<i32>)> {
        let group = self.task(index).group;
        let state = self.groups[group].as_mut().unwrap();
        state.owners -= 1;
        if state.owners != 0 {
            return None;
        }
        let mut state = self.groups[group].take().unwrap();
        if let Some(cwd) = state.cwd.take() {
            if self.objects.filesystem.close_cwd(cwd).is_err() {
                self.fail(instance, b"process cwd release failed");
            }
        }
        if let Some(image) = state.image.take() {
            if self.objects.filesystem.release_executable(image).is_err() {
                self.fail(instance, b"process executable release failed");
            }
        }
        self.objects
            .filesystem
            .release_process_locks(state.leader.pid);
        if let Err(reason) = state.table.release_exited(&mut self.objects) {
            self.fail(instance, reason);
        }
        Some((state.leader, state.status))
    }

    /// Withdraw a creation whose child was never published: the reserved
    /// virtual identity, its descriptor group reference and the gate on the
    /// parent's group all go together. Returns whether a reservation was
    /// withdrawn; a published child is a task of its own and stays.
    fn cancel_creation(&mut self, parent: usize, instance: &mut Instance) -> bool {
        let Pending::Fork { child, thread, .. } = self.task(parent).pending else {
            return false;
        };
        if self.task(child).host != 0 {
            return false;
        }
        self.task_mut(parent).pending = Pending::None;
        self.release_group(child, instance);
        let (id, reserved) = (self.task(parent).id, self.task(child).id);
        let rollback = if thread {
            self.processes.cancel_thread(id, reserved)
        } else {
            self.processes.cancel_fork(id, reserved)
        };
        if self.group(parent).creating == Some(parent) {
            self.group_mut(parent).creating = None;
            self.wake_needed = true;
        }
        if rollback.is_err() {
            self.fail(instance, b"task creation rollback failed");
        }
        self.tasks[child] = None;
        true
    }

    /// Host identity of the thread group a task belongs to.
    fn host_tgid(&self, index: usize) -> Option<usize> {
        let leader = self.group(index).leader;
        self.tasks
            .iter()
            .flatten()
            .find(|task| task.id == leader)
            .map(|task| task.host)
            .filter(|host| *host != 0)
    }

    /// An auto-attached newborn stays stopped until its parent's birth event
    /// claims it. Only a live task with an unpublished creation can do that:
    /// the newborn is a thread of that task's group or a child of its
    /// process. Any other newborn lost its parent before publication. It
    /// never ran and no virtual task names it, so it is killed; its terminal
    /// event is consumed like that of any task the table no longer holds.
    fn settle_newborns(&mut self) {
        for slot in 0..TASKS {
            let host = self.unknown_stops[slot];
            if host == 0 {
                continue;
            }
            let identity = crate::tracee_io::native_identity(host);
            let claimable = identity.is_some_and(|(tgid, parent)| {
                (0..TASKS).any(|index| {
                    let Some(task) = self.tasks[index].as_ref() else {
                        return false;
                    };
                    let Pending::Fork { child, thread, .. } = task.pending else {
                        return false;
                    };
                    task.alive
                        && self.task(child).host == 0
                        && self.host_tgid(index).is_some_and(|group| {
                            if thread {
                                group == tgid
                            } else {
                                group == parent
                            }
                        })
                })
            });
            if !claimable {
                let _ = unsafe { syscall2(SYS_KILL, host, SIGKILL) };
                self.unknown_stops[slot] = 0;
                audit_write(b"ginux: unclaimed newborn retired\n");
            }
        }
    }

    fn report_creation_failure(&mut self, reason: &[u8]) {
        // Keep the first concrete resource failure visible after ordinary audit
        // truncation, without permitting a failed-clone loop to flood stderr.
        if !self.creation_failure_reported {
            self.creation_failure_reported = true;
            line_stderr(reason);
        }
    }

    fn task(&self, index: usize) -> &Task {
        self.tasks[index].as_ref().unwrap()
    }
    fn task_mut(&mut self, index: usize) -> &mut Task {
        self.tasks[index].as_mut().unwrap()
    }
    fn virtual_pid(&self, host: usize) -> Option<u32> {
        if host == 0 {
            return None;
        }
        self.tasks
            .iter()
            .flatten()
            .find(|t| t.host == host)
            .map(|t| t.id.pid)
            .or_else(|| {
                self.retired
                    .iter()
                    .find(|p| p.0 == host && host != 0)
                    .map(|p| p.1)
            })
    }
    fn read_registers(&self, index: usize) -> Result<UserRegs, isize> {
        let mut r = core::mem::MaybeUninit::uninit();
        let result = ptrace(
            PTRACE_GETREGS,
            self.task(index).host,
            0,
            r.as_mut_ptr() as usize,
        );
        if result < 0 {
            return Err(result);
        }
        Ok(unsafe { r.assume_init() })
    }
    fn registers(&mut self, index: usize, instance: &mut Instance) -> UserRegs {
        self.read_registers(index)
            .unwrap_or_else(|_| self.fail(instance, b"launch register read failed"))
    }
    fn resume(&mut self, index: usize, signal: usize, instance: &mut Instance) {
        if !self.tearing_down {
            if let Some(reason) = self.objects.filesystem.cleanup_error() {
                self.fail(instance, reason);
            }
        }
        self.settle_signal_hold(index, instance);
        self.task_mut(index).reaps_seen = self.reaps;
        let request = if !self.seccomp || self.task(index).in_flight && self.exit_needed(index) {
            PTRACE_SYSCALL
        } else {
            if self.task(index).in_flight {
                // The call runs natively and its exit would change nothing:
                // finish it here, as its exit would.
                self.wake_needed |= self.task_mut(index).call.complete_without_exit();
                self.retire_threads();
                self.task_mut(index).in_flight = false;
            }
            PTRACE_CONT
        };
        let result = ptrace(request, self.task(index).host, 0, signal);
        if result == -3 {
            // SIGKILL can end a ptrace stop between an object retry and
            // resume. Keep ownership until wait4 supplies the actual death.
            self.task_mut(index).blocked = None;
            self.task_mut(index).running = false;
        } else if result < 0 {
            self.fail(instance, b"launch task resume failed")
        } else {
            self.task_mut(index).running = true;
        }
    }
    /// Task state that gives the exit of its in-flight syscall work which
    /// needs the kernel to have run first, or runs further supervisor-chosen
    /// syscalls: a skipped call with any of it still takes its exit stop.
    fn exit_state(&self, index: usize) -> bool {
        let task = self.task(index);
        task.call.signal_wait_pending()
            || task.unpark.is_some()
            || task.sleep.is_some()
            || task.mapping.is_some()
            || task.exec.is_some()
            || task.path_rewrite.is_some()
            || task.signal_target.is_some()
            || !matches!(task.pending, Pending::None)
            || task.image_chdir.is_some()
            || task.alignment.is_some()
    }

    /// Whether the in-flight syscall of a task about to be resumed must stop
    /// again at its exit. Exactly when `syscall_exit` would do more than
    /// `complete_without_exit` and an unchanged register write: the exit
    /// records the native result while per-syscall audit lasts, an override
    /// or the argument guard waits for it, or the call's state needs it.
    fn exit_needed(&self, index: usize) -> bool {
        let task = self.task(index);
        crate::launch::audit_tracing()
            || task.exit_registers
            || task.override_result.is_some()
            || self.argument_guard == Some(index)
            || self.exit_state(index)
    }

    fn injecting(&self, index: usize) -> bool {
        let task = self.task(index);
        task.mapping.is_some()
            || task.alignment.is_some()
            || task.exec.is_some_and(|e| {
                matches!(
                    e.stage,
                    ExecStage::Sync
                        | ExecStage::Reenter
                        | ExecStage::Create
                        | ExecStage::Close
                        | ExecStage::Retire
                        | ExecStage::RetireReenter
                )
            })
    }

    /// Every stop ends by resuming the task or parking its call, and both
    /// pass through here: signals are blocked exactly while supervisor-chosen
    /// syscalls replace the task's own, so none can be delivered in between.
    fn settle_signal_hold(&mut self, index: usize, instance: &mut Instance) {
        let host = self.task(index).host;
        let result = match (self.injecting(index), self.task(index).signal_hold) {
            (true, None) => crate::task_signals::hold(host).map(Some),
            (false, Some(saved)) => crate::task_signals::release(host, saved).map(|_| None),
            _ => return,
        };
        match result {
            Ok(hold) => self.task_mut(index).signal_hold = hold,
            // SIGKILL ended the stop; wait4 supplies the actual death.
            Err(-3) => {}
            Err(_) => self.fail(instance, b"signal hold update failed"),
        }
    }

    /// Hold a syscall at its entry stop. `restart` marks an object wait that
    /// a signal may end; an ordering gate passes `None` and is released only
    /// by the transition it waits for.
    fn park(
        &mut self,
        index: usize,
        original: UserRegs,
        restart: Option<i64>,
        instance: &mut Instance,
    ) {
        self.settle_signal_hold(index, instance);
        let reaps = self.reaps;
        let task = self.task_mut(index);
        task.blocked = Some(original);
        task.interruptible = restart;
        // A child reaped since this task last resumed can have queued SIGCHLD
        // after the kernel last looked. The next wake pass examines it.
        if restart.is_some() && task.reaps_seen != reaps {
            self.wake_needed = true;
        }
    }

    /// Hand a parked object wait back to the kernel when a queued signal
    /// would run a handler or end the task. The call skips this entry and is
    /// replayed from its own instruction: the kernel delivers the signal on
    /// the way, and a replay nobody claimed is an ordinary retry.
    fn interrupt_parked(&mut self, index: usize, instance: &mut Instance) {
        let reaps = self.reaps;
        let task = self.task_mut(index);
        let (Some(original), Some(restart)) = (task.blocked, task.interruptible) else {
            return;
        };
        // pselect arbitrates its snapshotted temporary mask in its descriptor
        // owner and the kernel's zero-FD completion call.
        if matches!(original.orig_rax, 270 | 271) || task.reaps_seen == reaps && !task.signalled {
            return;
        }
        task.reaps_seen = reaps;
        task.signalled = false;
        let host = task.host;
        let mut instruction = [0u8; 2];
        if !crate::task_signals::Signals::read(host)
            .is_some_and(|signals| signals.interrupt_held_call())
            || original.rip < 2
            || copy_memory(host, original.rip - 2, &mut instruction, false) != Ok(2)
            || instruction != [0x0f, 0x05]
        {
            return;
        }
        let task = self.task_mut(index);
        task.blocked = None;
        task.interruptible = None;
        task.unpark = Some(Unpark {
            original,
            restart,
            replaying: false,
        });
        audit_write(b"ginux: park interrupted surface=pending-signal virtual-pid=");
        audit_u64(self.task(index).id.pid as u64);
        audit_write(b"\n");
        let mut skipped = original;
        skipped.orig_rax = u64::MAX;
        self.run(index, &skipped, instance);
    }

    /// A signal-delivery stop for a task whose call the supervisor still
    /// holds. Only a handler ends the call; an ignored signal leaves it held
    /// and a fatal one needs no result.
    fn signal_reaches_held_call(&mut self, index: usize, signal: usize, instance: &mut Instance) {
        if self.task(index).sleep.is_none() && self.task(index).unpark.is_none() {
            return;
        }
        let host = self.task(index).host;
        // An unreadable signal view keeps the conservative result.
        if !crate::task_signals::Signals::read(host).is_none_or(|signals| signals.handled(signal)) {
            return;
        }
        if let Some(sleep) = self.task_mut(index).sleep.take() {
            let mut registers = self.registers(index, instance);
            if let Err(result) = sleep.interrupt(host, &mut registers) {
                sleep.restore(&mut registers, result);
            }
            self.task_mut(index).stopped = None;
            if ptrace(PTRACE_SETREGS, host, 0, &registers as *const _ as usize) < 0 {
                self.fail(instance, b"sleep interruption register update failed");
            }
        }
        if let Some(unpark) = self.task_mut(index).unpark.take() {
            // The kernel resolves the restart result against this handler's
            // flags: EINTR, or a transparent restart of the same call.
            let mut registers = unpark.original;
            let group = self.task(index).group;
            let task = self.tasks[index].as_mut().unwrap();
            let progress = task.call.interrupted_result();
            if let Err(reason) = task.call.finish(
                &mut self.groups[group].as_mut().unwrap().table,
                &mut registers,
                &mut self.objects,
            ) {
                self.fail(instance, reason);
            }
            self.wake_needed = true;
            registers.rax = progress.unwrap_or(unpark.restart) as u64;
            self.task_mut(index).stopped = None;
            let result = ptrace(PTRACE_SETREGS, host, 0, &registers as *const _ as usize);
            if result < 0 && result != -3 {
                self.fail(instance, b"interrupted call register update failed");
            }
            audit_write(b"ginux: audit sequence=");
            audit_u64(self.task(index).sequence);
            audit_write(b" phase=exit result=interrupted\n");
        }
    }

    fn begin_argument_guard(&mut self, owner: usize, instance: &mut Instance) {
        if self.argument_guard.is_some() {
            return;
        }
        let deadline = crate::descriptors::monotonic_nanoseconds()
            .unwrap_or_else(|_| self.fail(instance, b"argument peer-stop clock failed"))
            .saturating_add(5_000_000_000);
        let mut requested = [false; TASKS];
        for (index, wanted) in requested.iter_mut().enumerate() {
            let Some(task) = self.tasks[index].as_ref() else {
                continue;
            };
            if index == owner || !task.running || task.host == 0 {
                continue;
            }
            // A pending clone/fork cannot return to guest code before its
            // ptrace event or syscall-exit stop. Its autoattached child is
            // stopped too. Waiting for the parent here can deadlock while
            // the child awaits supervisor handling, so defer both events.
            if matches!(task.pending, Pending::Fork { .. }) {
                continue;
            }
            *wanted = true;
            let result = ptrace(PTRACE_INTERRUPT, task.host, 0, 0);
            if result < 0 && result != -3 && result != -5 {
                self.fail(instance, b"argument peer interrupt failed");
            }
        }
        for (index, wanted) in requested.iter().enumerate() {
            if !*wanted {
                continue;
            }
            let host = self.task(index).host;
            loop {
                let mut status = 0;
                let waited = unsafe {
                    syscall4(SYS_WAIT4, host, &mut status as *mut _ as usize, WALL | 1, 0)
                };
                if waited == 0 {
                    if crate::descriptors::monotonic_nanoseconds()
                        .map_or(true, |now| now >= deadline)
                    {
                        self.fail(instance, b"argument peer interrupt timed out");
                    }
                    unsafe {
                        syscall0(24);
                    }
                    continue;
                }
                if waited == -4 {
                    continue;
                }
                if waited != host as isize {
                    self.fail(instance, b"argument peer stop missing");
                }
                let peer = self.task_mut(index);
                peer.running = false;
                peer.held_status = Some(status);
                if exited(status) || signaled(status) {
                    self.reaps += 1;
                }
                break;
            }
        }
        self.argument_guard = Some(owner);
    }

    fn release_argument_guard(&mut self, instance: &mut Instance) {
        let owner = self.argument_guard.take().unwrap();
        for index in 0..TASKS {
            if index == owner || self.tasks[index].is_none() {
                continue;
            }
            let status = self.task(index).held_status;
            if status.is_some_and(birth_stop) {
                self.task_mut(index).held_status = None;
                self.resume(index, 0, instance);
            }
        }
        self.wake_needed = true;
    }

    fn run(&mut self, index: usize, r: &UserRegs, instance: &mut Instance) {
        let mut registers = *r;
        if self.seccomp && self.task(index).in_flight {
            // A filter the workload installed could outrank the launch
            // filter and decide calls the supervisor never sees. Configured
            // launch denies both ways to install one, so none can exist.
            if ginux_core::seccomp_change_request(r.orig_rax, r.rdi) {
                self.fail(instance, b"workload seccomp filters are unsupported");
            }
            if r.orig_rax == u64::MAX && !self.exit_state(index) {
                // The kernel runs nothing between the entry of a skipped call
                // and its exit, and its exit registers are the ones written
                // here: complete it now, exactly as its exit stop would.
                self.finish_call(index, &mut registers, instance);
                registers.orig_rax = u64::MAX;
                self.task_mut(index).in_flight = false;
            } else {
                let exit_registers = self.task(index).call.exit_work(r)
                    || r.orig_rax == ginux_core::SYS_FUTEX
                        && ginux_core::futex_restart_block(r.rsi);
                self.task_mut(index).exit_registers = exit_registers;
            }
        }
        // Unchanged registers need no write: the kernel still holds the ones
        // read at this stop.
        let result = if self.task_mut(index).stopped.take() == Some(registers) {
            0
        } else {
            ptrace(
                PTRACE_SETREGS,
                self.task(index).host,
                0,
                &registers as *const _ as usize,
            )
        };
        if result == -3 {
            // A parked task may die while copyin/readiness is being retried.
            // Do not invent an IO result or a supervisor failure for its exit.
            self.task_mut(index).blocked = None;
            return;
        }
        if result < 0 {
            self.fail(instance, b"launch register update failed")
        }
        self.resume(index, 0, instance);
    }
    fn emulate(&mut self, index: usize, r: &mut UserRegs, result: i64, instance: &mut Instance) {
        self.task_mut(index).override_result = Some(result);
        r.orig_rax = u64::MAX;
        audit_write(b"emulate result=");
        audit_i64(result);
        self.objects.devices.network.audit_attempt();
        audit_write(b"\n");
        self.run(index, r, instance);
    }
    /// The first entry after an abandoned creation settles it. The kernel's
    /// reissue (the same call at the same instruction with the same flags)
    /// takes the reservation back, child identity included, and runs as its
    /// first entry ran. Any other call means a handler runs first, which may
    /// change what the child would copy: the reservation is withdrawn and
    /// the reissue, when it comes, reserves anew. Returns whether the entry
    /// was handled.
    fn settle_restart(&mut self, index: usize, r: &mut UserRegs, instance: &mut Instance) -> bool {
        let Some(restart) = self.task_mut(index).restart.take() else {
            return false;
        };
        self.task_mut(index).pending = restart.reservation;
        let Pending::Fork {
            flags,
            child_tid,
            parent_tid,
            ..
        } = restart.reservation
        else {
            self.fail(instance, b"abandoned creation without a reservation");
        };
        if r.orig_rax != restart.syscall || r.rip != restart.rip || r.rdi != flags {
            self.cancel_creation(index, instance);
            return false;
        }
        if child_tid.is_some() {
            r.rdi &= !0x1000000;
        }
        if parent_tid.is_some() {
            r.rdi &= !0x100000;
        }
        // The reissue continues the admitted call: its sequence, its exit.
        audit_write(b"ginux: audit sequence=");
        audit_u64(self.task(index).sequence);
        audit_write(b" phase=restart surface=owned-process-create\n");
        self.run(index, r, instance);
        true
    }
    fn entry(&mut self, index: usize, r: &mut UserRegs, instance: &mut Instance) {
        self.objects.filesystem.begin_entry();
        if self.settle_restart(index, r, instance) {
            return;
        }
        if let Some(unpark) = self.task_mut(index).unpark.take() {
            if !unpark.replaying
                || r.orig_rax != unpark.original.orig_rax
                || r.rip != unpark.original.rip
            {
                self.fail(instance, b"interrupted park left its syscall instruction");
            }
        }
        if let Some(sleep) = self.task(index).sleep {
            match sleep.enter(r) {
                Ok(()) => self.run(index, r, instance),
                Err(_) => self.fail(instance, b"sleep clock failed"),
            }
            return;
        }
        self.objects
            .filesystem
            .select_process(self.processes.view(self.task(index).id).unwrap().tgid);
        self.objects.filesystem.select_cwd(self.group(index).cwd);
        self.objects
            .filesystem
            .select_creation_mask(self.group(index).creation_mask);
        if let Some(mapping) = &self.task(index).mapping {
            match mapping.entry(r) {
                Ok(next) => self.run(index, &next, instance),
                Err(reason) => self.fail(instance, reason),
            }
            return;
        }
        if let Some(alignment) = self.task(index).alignment {
            if r.orig_rax != alignment.original.orig_rax || r.rip != alignment.original.rip {
                self.fail(
                    instance,
                    b"descriptor alignment left its syscall instruction",
                );
            }
            self.alignment_step(index, instance);
            return;
        }

        if let Some(exec) = self.task(index).exec {
            match exec.stage {
                ExecStage::Reenter => {
                    if r.orig_rax != exec.original.orig_rax || r.rip != exec.original.rip {
                        self.fail(instance, b"exec replay left its syscall instruction");
                    }
                    self.exec_step(index, r, instance);
                    return;
                }
                ExecStage::Completed => {
                    if let Some(fd) = exec.retire {
                        let mut instruction = [0u8; 2];
                        if r.rip < 2
                            || copy_memory(
                                self.task(index).host,
                                r.rip - 2,
                                &mut instruction,
                                false,
                            ) != Ok(2)
                            || instruction != [0x0f, 0x05]
                        {
                            self.fail(
                                instance,
                                b"script descriptor retirement requires a syscall instruction",
                            );
                        }
                        let state = self.task_mut(index).exec.as_mut().unwrap();
                        state.original = *r;
                        state.stage = ExecStage::Retire;
                        r.orig_rax = 3;
                        r.rax = 3;
                        r.rdi = fd as u64;
                        self.run(index, r, instance);
                        return;
                    }
                    self.task_mut(index).exec = None;
                }
                ExecStage::RetireReenter => {
                    if r.orig_rax != exec.original.orig_rax || r.rip != exec.original.rip {
                        self.fail(
                            instance,
                            b"script descriptor retirement replay left its syscall instruction",
                        );
                    }
                    self.task_mut(index).exec = None;
                }
                _ => self.fail(instance, b"unexpected entry during exec"),
            }
        }
        self.sequence += 1;
        self.task_mut(index).sequence = self.sequence;
        audit_write(b"ginux: audit sequence=");
        audit_u64(self.sequence);
        audit_write(b" phase=entry syscall=");
        audit_u64(r.orig_rax);
        audit_write(b" virtual-pid=");
        audit_u64(self.task(index).id.pid as u64);
        let rule = self.contract.runtime_rule(
            r.orig_rax,
            crate::launch::launch_semantic_operation(r, self.table(index)),
        );
        // A transfer also reads its input: a denial of that read decides it
        // when its write is admitted.
        let rule = match crate::launch::launch_transfer_input_operation(r, self.table(index)) {
            Some(input)
                if rule.is_some_and(|rule| !matches!(rule.action, ContractAction::Deny(_))) =>
            {
                let read = self.contract.runtime_rule(r.orig_rax, Some(input));
                if read.is_some_and(|read| matches!(read.action, ContractAction::Deny(_))) {
                    read
                } else {
                    rule
                }
            }
            _ => rule,
        };
        crate::launch::audit_rule(rule);
        audit_write(b" action=");
        // All workload calls pass here before clock/task/storage/FD effects.
        // Internal supervisor replay stages above are already-owned transactions.
        if let ContractAction::Deny(errno) = rule.map_or(ContractAction::Deny(38), |r| r.action) {
            let slot = rule
                .and_then(|rule| {
                    self.contract
                        .rules()
                        .iter()
                        .position(|candidate| candidate.operation.id == rule.operation.id)
                })
                .unwrap_or(ginux_contract::MAX_OPERATIONS);
            let first_pid = self.task(index).id.pid;
            let denial = self.denials[slot].get_or_insert(Denial {
                count: 0,
                first_sequence: self.sequence,
                first_pid,
                first_syscall: r.orig_rax,
            });
            denial.count = denial.count.saturating_add(1);
            audit_write(b"deny result=-");
            audit_u64(errno as u64);
            audit_write(b"\n");
            self.task_mut(index).override_result = Some(-(errno as i64));
            r.orig_rax = u64::MAX;
            self.run(index, r, instance);
            return;
        }
        if r.orig_rax == 318 && r.rsi > 256 {
            // The balanced 256-byte getrandom bound (Gate 20) gives a larger
            // request a short read, as Linux may; the caller's length
            // returns at the exit.
            self.task_mut(index).call.save(r);
            r.rsi = 256;
        }
        let original = *r;
        let id = self.task(index).id;
        let parent_group = self.task(index).group;
        if self
            .group(index)
            .creating
            .is_some_and(|owner| owner != index)
            && !matches!(r.orig_rax, 60 | 231 | 62)
        {
            self.park(index, original, None, instance);
            audit_write(b"park surface=descriptor-snapshot\n");
            return;
        }
        if let Some(result) = crate::clock_hooks::read(self.task(index).host, r) {
            self.emulate(index, r, result, instance);
            return;
        }
        if matches!(r.orig_rax, 35 | 230) {
            match crate::clock_hooks::Sleep::begin(self.task(index).host, r) {
                Ok(sleep) => {
                    if sleep.enter(r).is_err() {
                        self.fail(instance, b"sleep clock failed");
                    }
                    self.task_mut(index).sleep = Some(sleep);
                    audit_write(b"mediate surface=configured-global-clock-sleep\n");
                    self.run(index, r, instance);
                }
                Err(result) => self.emulate(index, r, result, instance),
            }
            return;
        }
        if r.orig_rax == 99 {
            // A deterministic system view (Gates 22-23): total memory is the
            // configured instance memory and no host counter is exposed.
            let result = crate::supervisor::write_tracee_bytes_strict(
                self.task(index).host,
                r.rdi as usize,
                &crate::supervisor::virtual_sysinfo(instance.config().memory_mib),
            )
            .map(|_| 0)
            .unwrap_or_else(|error| error);
            self.emulate(index, r, result, instance);
            return;
        }
        if r.orig_rax == ginux_core::SYS_UNAME {
            let identity = ginux_kernel_views::IdentityView {
                hostname: instance.config().id.as_bytes(),
                machine_id: b"",
                boot_id: b"",
            };
            let mut bytes = [0u8; 390];
            let result = identity
                .uname(b"x86_64", &mut bytes)
                .map_err(|_| -5)
                .and_then(|_| {
                    crate::supervisor::write_tracee_bytes_strict(
                        self.task(index).host,
                        r.rdi as usize,
                        &bytes,
                    )
                })
                .map(|_| 0)
                .unwrap_or_else(|error| error);
            self.emulate(index, r, result, instance);
            return;
        }
        if r.orig_rax == 9 && r.r10 & 0x20 == 0 {
            match self.table(index).mapping_file(r.r8) {
                Ok(Some(handle)) => {
                    if r.r10 & 3 == 0 || r.r10 & 3 == 3 && r.rdx & 2 != 0 {
                        self.emulate(index, r, -95, instance);
                        return;
                    }
                    if r.rsi == 0 || r.r9 & 4095 != 0 {
                        self.emulate(index, r, -22, instance);
                        return;
                    }
                    // Cleanup replays the syscall and restores private stack
                    // scratch. A fixed map must not replace either region.
                    if r.r10 & 0x10 != 0 {
                        let end = r
                            .rsi
                            .checked_add(4095)
                            .map(|n| n & !4095)
                            .and_then(|n| r.rdi.checked_add(n));
                        let Some(end) = end else {
                            self.emulate(index, r, -22, instance);
                            return;
                        };
                        if r.rdi < r.rsp.saturating_sub(256) && end > r.rsp.saturating_sub(512)
                            || r.rdi < r.rip && end > r.rip.saturating_sub(2)
                        {
                            self.emulate(index, r, -95, instance);
                            return;
                        }
                    }
                    let backing = match self
                        .objects
                        .filesystem
                        .mapping_reference(handle, r.r10 & 3 == 1 && r.rdx & 2 != 0)
                    {
                        Ok(fd) => fd,
                        Err(error) => {
                            self.emulate(index, r, error, instance);
                            return;
                        }
                    };
                    let mapping = match crate::file_mapping::MappingCall::new(
                        self.task(index).host,
                        original,
                        backing,
                        self.table(index).host_descriptor_set(),
                    ) {
                        Ok(mapping) => mapping,
                        Err(reason) => self.fail(instance, reason),
                    };
                    let next = match mapping.entry(r) {
                        Ok(next) => next,
                        Err(reason) => self.fail(instance, reason),
                    };
                    self.task_mut(index).mapping = Some(mapping);
                    audit_write(b"mediate surface=owned-file-mapping\n");
                    self.run(index, &next, instance);
                    return;
                }
                Err(error) => {
                    self.emulate(index, r, error, instance);
                    return;
                }
                Ok(None) => {}
            }
        }
        // Credentials belong to virtual processes. Never forward identity
        // changes to host syscalls; children inherit and can irreversibly drop
        // this virtual identity independently of the supervisor's credentials.
        if matches!(r.orig_rax, 102 | 104 | 107 | 108) {
            let credentials = self.processes.view(id).unwrap().credentials;
            let value = if matches!(r.orig_rax, 102 | 107) {
                credentials.uid
            } else {
                credentials.gid
            };
            self.emulate(index, r, value as i64, instance);
            return;
        }
        if matches!(r.orig_rax, 105 | 106 | 113 | 114 | 116 | 117 | 119) {
            let result = (|| -> Result<i64, i64> {
                let current = self.processes.view(id).map_err(|_| -3)?.credentials;
                if r.orig_rax == 116 {
                    let count = usize::try_from(r.rdi).map_err(|_| -22)?;
                    if count > ginux_process::MAX_GROUPS {
                        return Err(-22);
                    }
                    let mut groups = [0u32; ginux_process::MAX_GROUPS];
                    for (i, group) in groups[..count].iter_mut().enumerate() {
                        let mut bytes = [0u8; 4];
                        let address = r.rsi.checked_add((i * 4) as u64).ok_or(-14)?;
                        if copy_memory(self.task(index).host, address, &mut bytes, false) != Ok(4) {
                            return Err(-14);
                        }
                        *group = u32::from_ne_bytes(bytes);
                    }
                    self.processes
                        .credentials_mut(id)
                        .map_err(|_| -3)?
                        .set_groups(&groups[..count])
                        .map_err(|_| -1)?;
                } else {
                    let uid = matches!(r.orig_rax, 105 | 113 | 117);
                    let old = if uid { current.uid } else { current.gid };
                    let values = if matches!(r.orig_rax, 105 | 106) {
                        [r.rdi, u64::MAX, u64::MAX]
                    } else if matches!(r.orig_rax, 113 | 114) {
                        [r.rdi, r.rsi, u64::MAX]
                    } else {
                        [r.rdi, r.rsi, r.rdx]
                    };
                    let value = crate::virtual_credential_target(old, &values).ok_or(-22)?;
                    let credentials = self.processes.credentials_mut(id).map_err(|_| -3)?;
                    if uid {
                        credentials.set_uid(value)
                    } else {
                        credentials.set_gid(value)
                    }
                    .map_err(|_| -1)?;
                }
                Ok(0)
            })()
            .unwrap_or_else(|error| error);
            self.emulate(index, r, result, instance);
            return;
        }
        if r.orig_rax == 137 {
            let host = self.task(index).host;
            let result = self
                .objects
                .filesystem
                .statfs_path(host, r.rdi, r.rsi)
                .unwrap_or_else(|error| error);
            self.emulate(index, r, result, instance);
            return;
        }
        match r.orig_rax {
            95 => {
                let previous = self.group(index).creation_mask;
                self.group_mut(index).creation_mask = r.rdi as u32 & 0o777;
                self.emulate(index, r, previous as i64, instance);
                return;
            }
            89 | 267 => {
                let host = self.task(index).host;
                let (address, output, size, dirfd) = if r.orig_rax == 89 {
                    (r.rdi, r.rsi, r.rdx, (-100i64) as u64)
                } else {
                    (r.rsi, r.rdx, r.r10, r.rdi)
                };
                // Snapshot the FD name once. This is a virtual metadata view,
                // never permission to open a host proc path or backend handle.
                if let Ok(path) = crate::tracee_io::read_path(host, address) {
                    if let Some(name) = self.table(index).self_fd_path(
                        host,
                        path.as_bytes(),
                        self.objects.filesystem,
                        self.objects.channels,
                    ) {
                        let result = name
                            .and_then(|name| {
                                if size == 0 {
                                    return Err(-22);
                                }
                                let count = name.as_bytes().len().min(size as usize);
                                let mut bytes = [0; ginux_vfs::MAX_PATH];
                                bytes[..count].copy_from_slice(&name.as_bytes()[..count]);
                                if copy_memory(host, output, &mut bytes[..count], true)?
                                    != count as i64
                                {
                                    return Err(-14);
                                }
                                Ok(count as i64)
                            })
                            .unwrap_or_else(|error| error);
                        self.emulate(index, r, result, instance);
                        return;
                    }
                }
                let path = self.objects.filesystem.path(host, address, dirfd);
                if path.as_ref().is_ok_and(|path| {
                    matches!(
                        path.as_bytes(),
                        b"/proc/self/exe" | b"/proc/thread-self/exe"
                    )
                }) {
                    let result = (|| {
                        if size == 0 {
                            return Err(-22);
                        }
                        let name = if let Some(image) = self.group(index).image {
                            self.objects.filesystem.executable_name(image)?
                        } else {
                            let image = crate::tracee_io::image_link(host, b"/exe")?;
                            ginux_instance::Text::<{ ginux_vfs::MAX_PATH + 10 }>::from_bytes(
                                image.as_bytes(),
                            )
                            .map_err(|_| -36)?
                        };
                        let count = name.as_bytes().len().min(size as usize);
                        let mut bytes = [0; ginux_vfs::MAX_PATH + 10];
                        bytes[..count].copy_from_slice(&name.as_bytes()[..count]);
                        if copy_memory(host, output, &mut bytes[..count], true)? != count as i64 {
                            return Err(-14);
                        }
                        Ok(count as i64)
                    })()
                    .unwrap_or_else(|error| error);
                    self.emulate(index, r, result, instance);
                    return;
                }
            }
            79 => {
                let result = self
                    .objects
                    .filesystem
                    .getcwd(self.task(index).host, r.rdi, r.rsi)
                    .unwrap_or_else(|error| error);
                self.emulate(index, r, result, instance);
                return;
            }
            80 => {
                let host = self.task(index).host;
                match self.objects.filesystem.chdir(host, r.rdi) {
                    Ok(Some(fd)) => {
                        self.replace_cwd(index, Some(fd), instance);
                        self.emulate(index, r, 0, instance);
                    }
                    Ok(None) => {
                        let original = r.rdi;
                        match crate::path_hooks::Rewrite::prepare(self.objects.filesystem, host, r)
                        {
                            Ok(rewrite) => {
                                self.task_mut(index).path_rewrite = rewrite;
                                self.task_mut(index).image_chdir = Some(original);
                                audit_write(b"mediate surface=image-cwd\n");
                                self.run(index, r, instance);
                            }
                            Err(-5) => {
                                self.fail(instance, b"chdir path scratch restoration failed")
                            }
                            Err(error) => self.emulate(index, r, error, instance),
                        }
                    }
                    Err(error) => self.emulate(index, r, error, instance),
                }
                return;
            }
            81 => {
                match self.table(index).exec_descriptor(r.rdi) {
                    Ok(ExecDescriptor::Owned(handle)) => {
                        match self.objects.filesystem.descriptor_cwd(handle) {
                            Ok(fd) => {
                                self.replace_cwd(index, Some(fd), instance);
                                self.emulate(index, r, 0, instance);
                            }
                            Err(error) => self.emulate(index, r, error, instance),
                        }
                    }
                    Ok(ExecDescriptor::Native(fd)) => {
                        self.task_mut(index).image_chdir = Some(r.rdi);
                        let mut native = *r;
                        native.rdi = fd as u64;
                        self.run(index, &native, instance);
                    }
                    Err(error) => self.emulate(index, r, error, instance),
                }
                return;
            }
            203 => {
                self.emulate(index, r, -1, instance);
                return;
            }
            204 => {
                let result = (|| {
                    let target = r.rdi as u32;
                    let tgid = self.processes.view(id).unwrap().tgid;
                    if target != 0 && target != id.pid && target != tgid {
                        return Err(-3);
                    }
                    if r.rsi > 1024 {
                        return Err(-22);
                    }
                    let mut mask = [0u8; 1024];
                    let size = unsafe {
                        crate::supervisor::syscall3(
                            204,
                            self.task(index).host,
                            r.rsi as usize,
                            mask.as_mut_ptr() as usize,
                        )
                    };
                    if size < 0 {
                        return Err(size as i64);
                    }
                    if copy_memory(
                        self.task(index).host,
                        r.rdx,
                        &mut mask[..size as usize],
                        true,
                    )? != size as i64
                    {
                        return Err(-14);
                    }
                    Ok(size as i64)
                })()
                .unwrap_or_else(|error| error);
                self.emulate(index, r, result, instance);
                return;
            }
            59 | 322 => {
                // Replacing a live shared address space requires group exec ownership.
                if self.group(index).owners != 1 || self.group(index).leader != id {
                    self.emulate(index, r, -95, instance);
                    return;
                }
                let result = self.prepare_exec(index, r);
                if result == Err(-5) {
                    self.fail(instance, b"exec path scratch restoration failed");
                }
                if let Err(errno) = result {
                    self.emulate(index, r, errno, instance);
                } else {
                    audit_write(b"mediate surface=owned-exec\n");
                    self.exec_step(index, r, instance);
                }
                return;
            }
            13 if r.rdi == 17 && r.rsi != 0 && r.r10 == 8 => {
                // Native auto-reaping would bypass the explicit virtual wait
                // lifecycle. Keep unsupported dispositions fail-closed.
                let mut action = [0u8; 16];
                if copy_memory(self.task(index).host, r.rsi, &mut action, false) != Ok(16) {
                    self.emulate(index, r, -14, instance);
                    return;
                }
                let handler = u64::from_ne_bytes(action[..8].try_into().unwrap());
                let flags = u64::from_ne_bytes(action[8..].try_into().unwrap());
                if handler == 1 || flags & 2 != 0 {
                    self.emulate(index, r, -95, instance);
                    return;
                }
            }
            39 | 186 => {
                let value = if r.orig_rax == 39 {
                    self.processes.view(id).unwrap().tgid
                } else {
                    id.pid
                };
                self.emulate(index, r, value as i64, instance);
                return;
            }
            127 | 131 => {
                // Thread-local kernel state; the configured catalog and
                // effective contract have already admitted this operation.
                audit_write(b"mediate surface=thread-signal-state\n");
                self.run(index, r, instance);
                return;
            }
            109 => {
                let result = if (r.rdi as i32) < 0 || (r.rsi as i32) < 0 {
                    -22
                } else {
                    self.processes
                        .set_process_group_for(id, r.rdi as u32, r.rsi as u32)
                        .map(|_| 0)
                        .unwrap_or_else(|error| match error {
                            ProcessError::InvalidTask => -3,
                            _ => -1,
                        })
                };
                self.emulate(index, r, result, instance);
                return;
            }
            110 | 111 => {
                let view = self.processes.view(id).unwrap();
                self.emulate(
                    index,
                    r,
                    if r.orig_rax == 110 {
                        view.parent
                    } else {
                        view.process_group
                    } as i64,
                    instance,
                );
                return;
            }
            56..=58 => {
                // A reservation lasts from its entry to its exit; a kernel
                // restart is settled before any entry (`settle_restart`).
                if !matches!(self.task(index).pending, Pending::None) {
                    self.fail(instance, b"task creation entered with a call pending");
                }
                let flags = r.rdi;
                let libc_fork = r.orig_rax == 56 && flags == 0x1200011;
                let thread = r.orig_rax == 56 && matches!(flags, 0xd0f00 | 0x3d0f00 | 0x7d0f00);
                let parent_tid = thread && flags & 0x100000 != 0;
                if r.orig_rax == 56 && !thread && !matches!(flags, 17 | 0x4111 | 0x1200011) {
                    self.emulate(index, r, -38, instance);
                    return;
                }
                if !thread
                    && self
                        .tasks
                        .iter()
                        .flatten()
                        .any(|t| t.group == parent_group && t.call.native_mutation())
                {
                    self.park(index, original, None, instance);
                    audit_write(b"park surface=descriptor-snapshot\n");
                    return;
                }
                if parent_tid {
                    let mut before = [0u8; 4];
                    if copy_memory(self.task(index).host, r.rdx, &mut before, false) != Ok(4) {
                        self.emulate(index, r, -14, instance);
                        return;
                    }
                    match crate::tracee_io::store_u32(
                        self.task(index).host,
                        r.rdx,
                        u32::from_ne_bytes(before),
                    ) {
                        Ok(()) => {}
                        Err(-5) => self.fail(instance, b"parent tid rollback failed"),
                        Err(error) => {
                            self.emulate(index, r, error, instance);
                            return;
                        }
                    }
                }
                let Some(slot) = self.tasks.iter().position(|t| t.is_none()) else {
                    self.report_creation_failure(
                        b"ginux: launch task slots exhausted; creation returns EAGAIN",
                    );
                    self.emulate(index, r, -11, instance);
                    return;
                };
                let child = match if thread {
                    self.processes.clone_thread(id)
                } else {
                    self.processes.fork(id)
                } {
                    Ok(child) => child,
                    Err(error) => {
                        if error == ProcessError::TableFull {
                            self.report_creation_failure(
                                b"ginux: virtual process slots exhausted; creation returns EAGAIN",
                            );
                        }
                        self.emulate(index, r, -11, instance);
                        return;
                    }
                };
                let group = if thread {
                    self.group_mut(index).owners += 1;
                    parent_group
                } else {
                    let group = self.groups.iter().position(|g| g.is_none()).unwrap();
                    let mut table = self.groups[parent_group]
                        .as_ref()
                        .unwrap()
                        .table
                        .fork_copy(self.objects.refs)
                        .unwrap_or_else(|reason| self.fail(instance, reason));
                    let image = self.group(index).image;
                    if let Some(image) = image {
                        if self.objects.filesystem.retain_executable(image).is_err() {
                            if let Err(reason) = table.release_exited(&mut self.objects) {
                                self.fail(instance, reason);
                            }
                            self.fail(instance, b"fork executable retain failed");
                        }
                    }
                    self.groups[group] = Some(DescriptorGroup {
                        table,
                        owners: 1,
                        leader: child,
                        status: None,
                        creating: None,
                        image,
                        cwd: None,
                        creation_mask: self.group(index).creation_mask,
                    });
                    self.group_mut(index).creating = Some(index);
                    group
                };
                // The reservation is complete from here: the syscall result,
                // the birth event or the parent's death settles it, and every
                // failure below leaves through `cancel_creation`.
                self.tasks[slot] = Some(Task::new(child, 0, group));
                self.task_mut(index).pending = Pending::Fork {
                    child: slot,
                    flags,
                    thread,
                    child_tid: libc_fork.then_some(r.r10),
                    parent_tid: parent_tid.then_some(r.rdx),
                };
                if !thread {
                    if let Some(fd) = self.group(index).cwd {
                        match self.objects.filesystem.copy_cwd(fd) {
                            Ok(fd) => self.groups[group].as_mut().unwrap().cwd = Some(fd),
                            Err(error) => {
                                self.cancel_creation(index, instance);
                                self.emulate(index, r, error, instance);
                                return;
                            }
                        }
                    }
                }
                if libc_fork {
                    r.rdi &= !0x1000000;
                }
                if thread {
                    r.rdi &= !0x100000;
                }
                audit_write(b"mediate surface=owned-process-create\n");
                self.run(index, r, instance);
                return;
            }
            61 => {
                self.wait_entry(index, r, instance);
                return;
            }
            200 | 234 => {
                self.thread_kill(index, r, instance);
                return;
            }
            62 => {
                let target = r.rdi as i32;
                let signal = r.rsi;
                if target <= 0 || !matches!(signal, 0 | 9) {
                    self.emulate(index, r, -95, instance);
                    return;
                }
                let found = self
                    .tasks
                    .iter()
                    .flatten()
                    .find(|t| {
                        t.id.pid == target as u32
                            && t.host != 0
                            && self
                                .processes
                                .view(t.id)
                                .is_ok_and(|v| v.state == ginux_process::TaskState::Running)
                    })
                    .map(|t| t.host);
                let result = found
                    .map(|host| unsafe { syscall2(SYS_KILL, host, signal as usize) } as i64)
                    .unwrap_or(-3);
                self.emulate(index, r, result, instance);
                return;
            }
            218 => {
                self.task_mut(index).override_result = Some(id.pid as i64);
            }
            _ => {}
        }
        let decision = {
            let group = self.task(index).group;
            let leader = self.groups[group].as_ref().unwrap().leader;
            let signal_tgid = self
                .tasks
                .iter()
                .flatten()
                .find(|task| task.id == leader)
                .map(|task| task.host)
                .filter(|host| *host != 0)
                .unwrap_or_else(|| self.fail(instance, b"thread group leader missing"));
            let task = self.tasks[index].as_mut().unwrap();
            let state = self.groups[group].as_mut().unwrap();
            let shared = state.owners > 1;
            decide_launch(
                task.host,
                signal_tgid,
                r,
                &mut state.table,
                &mut self.objects,
                &mut task.call,
                shared,
            )
        };
        // The descriptor owner already rewrote the call into the host change
        // it decided: no path or stat handling applies to it.
        let effect = self.task(index).call.kernel_effect();
        let decision = match decision {
            NativeDecision::Contract(decision) if !effect => {
                match if matches!(decision.action, Action::Mediate)
                    && launch_arguments_allowed(self.task(index).host, r.orig_rax, r)
                {
                    crate::path_hooks::image_stat(self.objects.filesystem, self.task(index).host, r)
                } else {
                    Ok(None)
                } {
                    // An image file's stat the contract mediates, answered here
                    // (`image_stat`) with the audit line its native run writes.
                    Ok(Some(result)) => {
                        audit_write(b"mediate surface=");
                        audit_write(balanced_surface_name(configured_surface(r.orig_rax)));
                        audit_write(b"\n");
                        NativeDecision::Hooked {
                            lane: crate::dispatch::Lane::Filesystem,
                            result,
                        }
                    }
                    // A path that does not resolve: the rewrite gives the same.
                    Err(result) => NativeDecision::Hooked {
                        lane: crate::dispatch::Lane::Filesystem,
                        result,
                    },
                    Ok(None) => match crate::path_hooks::Rewrite::prepare(
                        self.objects.filesystem,
                        self.task(index).host,
                        r,
                    ) {
                        Ok(rewrite) => {
                            self.task_mut(index).path_rewrite = rewrite;
                            NativeDecision::Contract(decision)
                        }
                        Err(-5) => self.fail(instance, b"launch path scratch restoration failed"),
                        Err(result) => NativeDecision::Hooked {
                            lane: crate::dispatch::Lane::Filesystem,
                            result,
                        },
                    },
                }
            }
            decision => decision,
        };
        match decision {
            NativeDecision::SignalWait { retry } => {
                // Only the native completion borrows scratch; parked readiness
                // queries must not acquire/release a guard and wake themselves.
                self.begin_argument_guard(index, instance);
                let host = self.task(index).host;
                match self
                    .task_mut(index)
                    .call
                    .prepare_signal_wait(host, r, retry)
                {
                    Ok(()) => {
                        audit_write(b"mediate surface=pselect-signal-mask\n");
                        self.run(index, r, instance);
                    }
                    Err(-5) => self.fail(instance, b"pselect scratch rollback failed"),
                    Err(error) => self.emulate(index, r, error, instance),
                }
            }
            NativeDecision::ParkPoll => {
                self.park(
                    index,
                    original,
                    Some(crate::task_signals::RESTART_WITHOUT_HANDLER),
                    instance,
                );
                audit_write(b"park surface=owned-poll");
                self.objects.devices.network.audit_attempt();
                audit_write(b"\n");
            }
            NativeDecision::Park { fd, progressed } => {
                self.wake_needed |= progressed;
                self.park(
                    index,
                    original,
                    Some(crate::task_signals::RESTART_SYSCALL),
                    instance,
                );
                audit_write(b"park");
                self.objects.devices.network.audit_attempt();
                audit_write(b"\nginux: park surface=lane-channel fd=");
                audit_u64(fd as u64);
                audit_write(b"\n");
            }
            NativeDecision::Hooked { result, .. } => {
                self.wake_needed = true;
                if self.task_mut(index).call.take_kernel_effect() {
                    // Decided and audited as this result; the kernel makes
                    // the host descriptor change with the registers the
                    // descriptor owner set, and its exit checks any result.
                    audit_write(b"emulate result=");
                    audit_i64(result);
                    self.objects.devices.network.audit_attempt();
                    audit_write(b"\n");
                    self.run(index, r, instance);
                } else {
                    self.emulate(index, r, result, instance)
                }
            }
            NativeDecision::Contract(decision) => match decision.action {
                Action::Emulate if matches!(original.orig_rax, 60 | 231) => {
                    audit_write(b"emulate result=instance-stop\n");
                    self.run(index, r, instance);
                    // exit and exit_group cannot return to guest memory. A thread-group
                    // leader can remain a zombie until its final peer exits, without
                    // producing another ptrace stop for PTRACE_INTERRUPT to collect.
                    self.task_mut(index).running = false;
                }
                Action::Emulate => self.emulate(
                    index,
                    r,
                    balanced_identity_result(original.orig_rax).unwrap_or(0),
                    instance,
                ),
                Action::Mediate if self.task_mut(index).call.take_kernel_effect() => {
                    // A host change in place of the native call the decision
                    // names (a duplication that replaces a native target in
                    // place of closing it): audited as that call.
                    audit_write(b"mediate surface=");
                    audit_write(balanced_surface_name(configured_surface(decision.syscall)));
                    audit_write(b"\n");
                    self.run(index, r, instance)
                }
                Action::Mediate
                    if launch_arguments_allowed(self.task(index).host, r.orig_rax, r) =>
                {
                    audit_write(b"mediate surface=");
                    audit_write(balanced_surface_name(configured_surface(r.orig_rax)));
                    audit_write(b"\n");
                    if !self.begin_alignment(index, &original, r, instance) {
                        self.run(index, r, instance)
                    }
                }
                Action::Mediate => self.emulate(index, r, -1, instance),
                Action::Deny(errno) => {
                    audit_write(b"deny result=-");
                    audit_u64(errno as u64);
                    audit_write(b"\n");
                    self.task_mut(index).override_result = Some(-(errno as i64));
                    r.orig_rax = u64::MAX;
                    self.run(index, r, instance)
                }
            },
        }
    }
    /// Start aligning the host table for a native open about to run with
    /// registers `r`, when the kernel would not give it its reserved public
    /// number. Returns whether the alignment now owns the call. Only with the
    /// launch filter, where an equal number spares later calls their exit
    /// stops, and only under the open's argument guard.
    fn begin_alignment(
        &mut self,
        index: usize,
        original: &UserRegs,
        r: &UserRegs,
        instance: &mut Instance,
    ) -> bool {
        if !self.seccomp || self.argument_guard != Some(index) {
            return false;
        }
        let Some(slot) = self.task(index).call.pending_open() else {
            return false;
        };
        if self.table(index).number_step(slot).is_none() {
            return false;
        }
        // Each step's exit replays the open's own syscall instruction.
        let mut instruction = [0u8; 2];
        if original.rip < 2
            || copy_memory(
                self.task(index).host,
                original.rip - 2,
                &mut instruction,
                false,
            ) != Ok(2)
            || instruction != [0x0f, 0x05]
        {
            return false;
        }
        self.task_mut(index).alignment = Some(Alignment {
            original: *original,
            open: *r,
            slot,
            step: None,
            abandoned: false,
        });
        self.alignment_step(index, instance);
        true
    }

    /// Run an aligning open's next placeholder step in place of the open,
    /// or the open itself once none is left.
    fn alignment_step(&mut self, index: usize, instance: &mut Instance) {
        let mut alignment = self.task(index).alignment.unwrap();
        let step = if alignment.abandoned {
            None
        } else {
            self.table(index).number_step(alignment.slot)
        };
        let Some(step) = step else {
            self.task_mut(index).alignment = None;
            self.run(index, &alignment.open, instance);
            return;
        };
        let mut next = alignment.open;
        match step {
            NumberStep::Release(fd) => {
                next.orig_rax = 3;
                next.rdi = fd as u64;
            }
            NumberStep::Occupy(_) => {
                next.orig_rax = SYS_EVENTFD2;
                next.rdi = 0;
                next.rsi = EFD_CLOEXEC;
            }
        }
        next.rax = next.orig_rax;
        alignment.step = Some(step);
        self.task_mut(index).alignment = Some(alignment);
        self.run(index, &next, instance);
    }

    /// Settle a placeholder step at its exit and replay the open.
    fn alignment_exit(
        &mut self,
        index: usize,
        mut alignment: Alignment,
        r: &UserRegs,
        instance: &mut Instance,
    ) {
        let result = r.rax as i64;
        match alignment.step.take() {
            Some(NumberStep::Release(fd)) if r.orig_rax == 3 => {
                if result != 0 {
                    self.fail(instance, b"descriptor placeholder close failed");
                }
                self.group_mut(index).table.placeholder_released(fd);
            }
            Some(NumberStep::Occupy(fd)) if r.orig_rax == SYS_EVENTFD2 => {
                if result < 0 {
                    alignment.abandoned = true;
                } else if result as usize != fd {
                    self.fail(instance, b"descriptor placeholder outside its number");
                } else {
                    self.group_mut(index).table.placeholder_placed(fd);
                }
            }
            _ => self.fail(instance, b"descriptor alignment lost its syscall"),
        }
        self.task_mut(index).alignment = Some(alignment);
        let mut replay = alignment.original;
        replay.rip -= 2;
        replay.rax = replay.orig_rax;
        self.run(index, &replay, instance);
    }

    fn prepare_exec(&mut self, index: usize, r: &mut UserRegs) -> Result<(), i64> {
        let host = self.task(index).host;
        let mut instruction = [0; 2];
        if copy_memory(
            host,
            r.rip.checked_sub(2).ok_or(-95)?,
            &mut instruction,
            false,
        ) != Ok(2)
            || instruction != [0x0f, 0x05]
        {
            return Err(-95);
        }
        let original = *r;
        let mut translated = *r;
        let mut native_dirfd = r.rdi;
        let (image, empty_path) = if r.orig_rax == 59 {
            let path = crate::tracee_io::read_path(host, r.rdi)?;
            let end = r.rdi.checked_add(path.as_bytes().len() as u64).ok_or(-14)?;
            let image = self
                .objects
                .filesystem
                .exec_path(host, r.rdi, (-100i64) as u64, true)?;
            (image, end)
        } else {
            if r.r8 & !0x1100 != 0 {
                return Err(-22);
            }
            let path = crate::tracee_io::read_path(host, r.rsi)?;
            let end = r.rsi.checked_add(path.as_bytes().len() as u64).ok_or(-14)?;
            let image = if path.is_empty() {
                if r.r8 & 0x1000 == 0 {
                    return Err(-2);
                }
                match self.table(index).exec_descriptor(r.rdi)? {
                    ExecDescriptor::Native(fd) => {
                        native_dirfd = fd as u64;
                        self.objects.filesystem.native_exec_fd(host, fd)?;
                        None
                    }
                    ExecDescriptor::Owned(handle) => {
                        Some(self.objects.filesystem.exec_descriptor(host, handle)?)
                    }
                }
            } else {
                let dirfd = self.table(index).exec_path_dirfd(host, r.rdi, r.rsi)?;
                native_dirfd = (-100i64) as u64;
                translated.rdi = dirfd;
                self.objects
                    .filesystem
                    .exec_path(host, r.rsi, dirfd, r.r8 & 0x100 == 0)?
            };
            (image, end)
        };
        if image.is_none() {
            let rewrite = crate::path_hooks::Rewrite::prepare(
                self.objects.filesystem,
                host,
                &mut translated,
            )?;
            if let Some(mut rewrite) = rewrite {
                rewrite.original_args(&original);
                self.task_mut(index).path_rewrite = Some(rewrite);
                *r = translated;
            }
            if r.orig_rax == 59 {
                native_dirfd = r.rdi;
            }
        }
        let mut image = image;
        let script = if let Some(initial) = image {
            let check = (|| {
                if self.objects.filesystem.is_script(initial)? && r.orig_rax == 322 {
                    let path = crate::tracee_io::read_path(host, r.rsi)?;
                    if (path.is_empty() || (path.as_bytes()[0] != b'/' && r.rdi as i32 != -100))
                        && self.table(index).exec_cloexec(r.rdi)?
                    {
                        return Err(-2);
                    }
                }
                Ok(())
            })();
            if let Err(error) = check {
                self.objects
                    .filesystem
                    .release_executable(initial)
                    .expect("script setup release");
                return Err(error);
            }
            // Resolution consumes the initial pin on both success and failure.
            let (resolved, script) =
                crate::exec_script::Script::resolve(self.objects.filesystem, host, r, initial)?;
            image = Some(resolved);
            script
        } else {
            None
        };
        let hosts: [usize; TASKS] = core::array::from_fn(|i| {
            self.tasks[i]
                .as_ref()
                .filter(|t| t.alive)
                .map_or(0, |t| t.host)
        });
        let mappings = (|| {
            if let Some(image) = image {
                self.objects
                    .filesystem
                    .validate_exec_mappings(image, &hosts)?;
            }
            if let Some(script) = script {
                script.validate_mappings(self.objects.filesystem, &hosts)?;
            }
            Ok(())
        })();
        if let Err(error) = mappings {
            if let Some(script) = script {
                script.release_held(self.objects.filesystem)?;
            }
            if let Some(image) = image {
                self.objects.filesystem.release_executable(image)?;
            }
            return Err(error);
        }
        self.task_mut(index).exec = Some(Exec {
            original: *r,
            native_dirfd,
            next_native: 0,
            stage: ExecStage::Reenter,
            retire: None,
            owned: image.map(|image| OwnedExec {
                image,
                empty_path,
                descriptor: None,
                legacy_create: false,
                failure: None,
                script,
            }),
        });
        Ok(())
    }

    fn exec_step(&mut self, index: usize, r: &mut UserRegs, instance: &mut Instance) {
        let exec = self.task(index).exec.unwrap();
        if let Some((fd, cloexec)) = self.table(index).next_exec_native(exec.next_native) {
            let state = self.task_mut(index).exec.as_mut().unwrap();
            state.next_native = fd + 1;
            state.stage = ExecStage::Sync;
            // This replaces the stopped exec syscall with a supervisor-chosen
            // fcntl. Its exit replays the verified original syscall instruction.
            r.orig_rax = 72;
            r.rax = 72;
            r.rdi = fd as u64;
            r.rsi = 2;
            r.rdx = cloexec as u64;
            audit_write(b"ginux: exec native-fd=");
            audit_u64(fd as u64);
            audit_write(b" close-on-exec=");
            audit_u64(cloexec as u64);
            audit_write(b"\n");
        } else if let Some(owned) = exec.owned {
            *r = exec.original;
            if owned.failure.is_some() {
                r.orig_rax = 3;
                r.rax = 3;
                r.rdi = owned.descriptor.unwrap() as u64;
                self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::Close;
            } else {
                let mut empty = [1u8];
                if copy_memory(self.task(index).host, owned.empty_path, &mut empty, false) != Ok(1)
                    || empty[0] != 0
                {
                    self.task_mut(index)
                        .exec
                        .as_mut()
                        .unwrap()
                        .owned
                        .as_mut()
                        .unwrap()
                        .failure = Some(-14);
                    if owned.descriptor.is_some() {
                        self.exec_step(index, r, instance);
                        return;
                    }
                    self.finish_exec_failure(index, r, -14, instance);
                    self.emulate(index, r, -14, instance);
                    return;
                }
                if let Some(fd) = owned.descriptor {
                    r.orig_rax = 322;
                    r.rax = 322;
                    r.rdi = fd as u64;
                    r.rsi = owned.empty_path;
                    r.rdx = if exec.original.orig_rax == 59 {
                        exec.original.rsi
                    } else {
                        exec.original.rdx
                    };
                    r.r10 = if exec.original.orig_rax == 59 {
                        exec.original.rdx
                    } else {
                        exec.original.r10
                    };
                    r.r8 = 0x1000;
                    self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::Kernel;
                } else {
                    r.orig_rax = 319;
                    r.rax = 319;
                    r.rdi = owned.empty_path;
                    // binfmt_script requires its backing to survive the kernel
                    // exec. Retire it before the interpreter's first syscall.
                    r.rsi = if owned.legacy_create { 2 } else { 0x12 }
                        | u64::from(!owned.script.is_some_and(|script| script.kernel_script));
                    self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::Create;
                }
            }
        } else {
            *r = exec.original;
            r.rdi = exec.native_dirfd;
            self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::Kernel;
        }
        self.run(index, r, instance);
    }

    fn replay_exec(&mut self, index: usize, instance: &mut Instance) {
        let mut replay = self.task(index).exec.unwrap().original;
        replay.rip -= 2;
        replay.rax = replay.orig_rax;
        self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::Reenter;
        self.run(index, &replay, instance);
    }

    fn finish_exec_failure(
        &mut self,
        index: usize,
        r: &mut UserRegs,
        error: i64,
        instance: &mut Instance,
    ) {
        let exec = self.task_mut(index).exec.take().unwrap();
        if let Some(owned) = exec.owned {
            if owned
                .script
                .is_some_and(|script| script.release_held(self.objects.filesystem).is_err())
            {
                self.fail(instance, b"failed interpreter reference release failed");
            }
            if self
                .objects
                .filesystem
                .release_executable(owned.image)
                .is_err()
            {
                self.fail(instance, b"failed exec reference release failed");
            }
        }
        *r = exec.original;
        r.rax = error as u64;
    }

    fn exec_completed(&mut self, index: usize, instance: &mut Instance) {
        self.objects
            .filesystem
            .select_process(self.processes.view(self.task(index).id).unwrap().tgid);
        if !self
            .task(index)
            .exec
            .is_some_and(|e| e.stage == ExecStage::Kernel)
        {
            self.fail(instance, b"unreserved exec transition");
        }
        let group = self.task(index).group;
        let result = self.groups[group]
            .as_mut()
            .unwrap()
            .table
            .exec_completed(&mut self.objects);
        if let Err(reason) = result {
            self.fail(instance, reason);
        }
        if self.processes.exec(self.task(index).id).is_err() {
            self.fail(instance, b"virtual exec transition failed");
        }
        let owned = self.task(index).exec.as_ref().unwrap().owned;
        let image = if let Some(owned) = owned {
            if let Some(script) = owned.script {
                let mut r = self.registers(index, instance);
                let fd = owned.descriptor.unwrap();
                if script.restore(self.task(index).host, fd, &mut r).is_err() {
                    // The kernel has replaced the mm. Returning a fabricated
                    // exec errno here would resume the wrong address space.
                    self.fail(instance, b"new script stack restoration failed");
                }
                self.task_mut(index).stopped = None;
                if ptrace(
                    PTRACE_SETREGS,
                    self.task(index).host,
                    0,
                    &r as *const _ as usize,
                ) < 0
                {
                    self.fail(instance, b"new script stack register update failed");
                }
                if script.release_held(self.objects.filesystem).is_err() {
                    self.fail(instance, b"committed interpreter references release failed");
                }
                if script.kernel_script {
                    self.task_mut(index).exec.as_mut().unwrap().retire = Some(fd);
                    if self
                        .objects
                        .filesystem
                        .release_executable(owned.image)
                        .is_err()
                    {
                        self.fail(instance, b"committed script reference release failed");
                    }
                    None
                } else {
                    Some(owned.image)
                }
            } else {
                self.task_mut(index).exec.as_mut().unwrap().owned = None;
                Some(owned.image)
            }
        } else {
            None
        };
        self.task_mut(index).exec.as_mut().unwrap().owned = None;
        let old = core::mem::replace(&mut self.group_mut(index).image, image);
        if let Some(old) = old {
            if self.objects.filesystem.release_executable(old).is_err() {
                self.fail(instance, b"replaced executable release failed");
            }
        }
        // Exec replaced the address space: the old path scratch no longer exists.
        self.task_mut(index).path_rewrite = None;
        self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::Completed;
        self.wake_needed = true;
        audit_write(b"ginux: task exec virtual-pid=");
        audit_u64(self.task(index).id.pid as u64);
        audit_write(b"\n");
        self.resume(index, 0, instance);
    }

    /// Publish a reserved child: bind its native identity, then finish the
    /// identity copyouts both tasks observe. Until `host` is bound the
    /// reservation can still be cancelled; afterwards the child is a task of
    /// its own and its death is an ordinary death.
    fn birth(&mut self, parent: usize, instance: &mut Instance) {
        let Pending::Fork {
            child: slot,
            flags,
            child_tid,
            parent_tid,
            ..
        } = self.task(parent).pending
        else {
            self.fail(instance, b"unreserved child event")
        };
        let parent_host = self.task(parent).host;
        let mut host = 0usize;
        let identity = ptrace(
            PTRACE_GETEVENTMSG,
            parent_host,
            0,
            &mut host as *mut _ as usize,
        );
        if identity == -3 {
            // The parent was killed out of this event stop. Its death cancels
            // the reservation and retires the newborn it cannot claim.
            return;
        }
        if identity < 0 || host == 0 {
            self.fail(instance, b"child event identity missing")
        }
        let early = self.unknown_stops.iter().position(|p| *p == host);
        if let Some(i) = early {
            self.unknown_stops[i] = 0;
        } else {
            let mut status = 0;
            let waited =
                unsafe { syscall4(SYS_WAIT4, host, &mut status as *mut _ as usize, WALL, 0) };
            if waited == host as isize
                && (exited(status) || signaled(status))
                && self.task(slot).group == self.task(parent).group
            {
                // A thread born into a group that is being killed never
                // reached its birth stop. Nothing was published; the caller
                // sees a failed creation if it outlives the group at all.
                self.reaps += 1;
                self.cancel_creation(parent, instance);
                self.task_mut(parent).override_result = Some(-11);
                self.resume(parent, 0, instance);
                return;
            }
            if waited < 0 || !birth_stop(status) {
                self.fail(instance, b"child birth stop missing")
            }
        }
        self.task_mut(slot).host = host;
        let virtual_id = self.task(slot).id.pid;
        let options = self.options();
        let setup = (|| -> Result<(), &'static [u8]> {
            if ptrace(PTRACE_SETOPTIONS, host, 0, options) < 0 {
                return Err(b"child supervision setup failed");
            }
            if let Some(address) = child_tid {
                match crate::tracee_io::store_u32(host, address, virtual_id) {
                    Ok(()) | Err(-14) => {}
                    Err(_) => return Err(b"child tid rollback failed"),
                }
            }
            if let Some(address) = parent_tid {
                if crate::tracee_io::store_u32(parent_host, address, virtual_id).is_err() {
                    return Err(b"thread identity copyout failed");
                }
            }
            if child_tid.is_some() || parent_tid.is_some() {
                let mut registers = self
                    .read_registers(slot)
                    .map_err(|_| b"child birth register read failed".as_slice())?;
                registers.rdi = flags;
                self.task_mut(slot).stopped = None;
                if ptrace(PTRACE_SETREGS, host, 0, &registers as *const _ as usize) < 0 {
                    return Err(b"child birth register update failed");
                }
            }
            Ok(())
        })();
        if let Err(reason) = setup {
            // SIGKILL can reach either task inside its stop. The published
            // child and its parent then die through their own wait events.
            if !crate::tracee_killed(host) && !crate::tracee_killed(parent_host) {
                self.fail(instance, reason);
            }
        }
        if self.group(parent).creating == Some(parent) {
            self.group_mut(parent).creating = None;
            self.wake_needed = true;
        }
        audit_write(b"ginux: task registered virtual-pid=");
        audit_u64(virtual_id as u64);
        audit_write(b"\n");
        self.resume(slot, 0, instance);
        self.resume(parent, 0, instance);
    }
    fn syscall_exit(&mut self, index: usize, r: &mut UserRegs, instance: &mut Instance) {
        let host = self.task(index).host;
        match self.task_mut(index).call.finish_signal_wait(host, r) {
            Ok(true) => {
                self.run(index, r, instance);
                return;
            }
            Ok(false) => {}
            Err(reason) => self.fail(instance, reason),
        }
        if let Some(unpark) = self.task(index).unpark {
            if unpark.replaying {
                self.fail(instance, b"interrupted park exited before its replay");
            }
            let mut replay = unpark.original;
            replay.rip -= 2;
            replay.rax = replay.orig_rax;
            self.task_mut(index).unpark.as_mut().unwrap().replaying = true;
            self.run(index, &replay, instance);
            return;
        }
        if let Some(sleep) = self.task(index).sleep {
            match sleep.finish(r) {
                Ok(true) => {
                    self.run(index, r, instance);
                    return;
                }
                Ok(false) => {}
                Err(result) => sleep.restore(r, result),
            }
            self.task_mut(index).sleep = None;
        }
        if let Some(mut mapping) = self.task_mut(index).mapping.take() {
            match mapping.exit(self.task(index).host, r) {
                Ok(crate::file_mapping::Progress::Run(next)) => {
                    self.task_mut(index).mapping = Some(mapping);
                    self.run(index, &next, instance);
                }
                Ok(crate::file_mapping::Progress::Done(next)) => {
                    self.wake_needed = true;
                    self.run(index, &next, instance);
                }
                Err(reason) => self.fail(instance, reason),
            }
            return;
        }
        if let Some(alignment) = self.task(index).alignment {
            self.alignment_exit(index, alignment, r, instance);
            return;
        }

        if let Some(exec) = self.task(index).exec {
            match exec.stage {
                ExecStage::Sync => {
                    if r.orig_rax != 72 || r.rax != 0 {
                        self.fail(instance, b"exec native descriptor synchronization failed");
                    }
                    let mut replay = exec.original;
                    replay.rip -= 2;
                    replay.rax = replay.orig_rax;
                    self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::Reenter;
                    self.run(index, &replay, instance);
                    return;
                }
                ExecStage::Create => {
                    if r.orig_rax != 319 {
                        self.fail(
                            instance,
                            b"exec private descriptor creation lost its syscall",
                        );
                    }
                    let owned = exec.owned.unwrap();
                    if r.rax as i64 == -22 && !owned.legacy_create {
                        self.task_mut(index)
                            .exec
                            .as_mut()
                            .unwrap()
                            .owned
                            .as_mut()
                            .unwrap()
                            .legacy_create = true;
                        self.replay_exec(index, instance);
                        return;
                    }
                    if (r.rax as i64) < 0 {
                        self.finish_exec_failure(index, r, r.rax as i64, instance);
                    } else {
                        if r.rax >= crate::descriptors::LIMIT as u64 {
                            self.fail(instance, b"exec private descriptor outside table bound");
                        }
                        let fd = r.rax as u32;
                        self.task_mut(index)
                            .exec
                            .as_mut()
                            .unwrap()
                            .owned
                            .as_mut()
                            .unwrap()
                            .descriptor = Some(fd);
                        if let Err(error) = crate::exec_image::populate(
                            self.task(index).host,
                            fd,
                            self.objects.filesystem,
                            owned.image,
                            owned.script.as_ref(),
                        ) {
                            self.task_mut(index)
                                .exec
                                .as_mut()
                                .unwrap()
                                .owned
                                .as_mut()
                                .unwrap()
                                .failure = Some(error);
                        }
                        self.replay_exec(index, instance);
                        return;
                    }
                }
                ExecStage::Close => {
                    if r.orig_rax != 3 || r.rax != 0 {
                        self.fail(instance, b"exec private descriptor close failed");
                    }
                    self.finish_exec_failure(
                        index,
                        r,
                        exec.owned.unwrap().failure.unwrap(),
                        instance,
                    );
                }
                ExecStage::Kernel => {
                    if r.rax as i64 >= 0 {
                        self.fail(instance, b"exec success missing its ownership event");
                    }
                    if exec.owned.is_some() {
                        self.task_mut(index)
                            .exec
                            .as_mut()
                            .unwrap()
                            .owned
                            .as_mut()
                            .unwrap()
                            .failure = Some(r.rax as i64);
                        self.replay_exec(index, instance);
                        return;
                    }
                    let error = r.rax as i64;
                    self.finish_exec_failure(index, r, error, instance);
                }
                ExecStage::Completed => {
                    // This can be the kernel's exec syscall exit, before the
                    // interpreter has entered userspace. Keep retirement state.
                    if exec.retire.is_none() {
                        self.task_mut(index).exec = None;
                    }
                }
                ExecStage::Retire => {
                    if r.orig_rax != 3 || r.rax != 0 {
                        self.fail(instance, b"script private descriptor close failed");
                    }
                    let mut replay = exec.original;
                    replay.rip -= 2;
                    replay.rax = replay.orig_rax;
                    self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::RetireReenter;
                    self.run(index, &replay, instance);
                    return;
                }
                ExecStage::Reenter | ExecStage::RetireReenter => {
                    self.fail(instance, b"unexpected exit during exec replay")
                }
            }
        }
        if let Some(rewrite) = self.task_mut(index).path_rewrite.take() {
            let result = rewrite.finish(self.task(index).host, r);
            if let Err(reason) = result {
                self.fail(instance, reason);
            }
        }
        if let Some(host) = self.task_mut(index).signal_target.take() {
            // The kernel has queued the signal; a parked peer must notice it.
            if r.rax == 0 {
                if let Some(target) = self.tasks.iter_mut().flatten().find(|t| t.host == host) {
                    target.signalled = true;
                    self.wake_needed = true;
                }
            }
        }
        self.finish_call(index, r, instance);
        self.run(index, r, instance);
    }

    /// The part of a syscall exit every call shares: settle a creation or a
    /// child wait, apply the supervisor's result, finish descriptor state and
    /// record the result. A skipped call with no `exit_state` runs exactly
    /// this, at its entry.
    fn finish_call(&mut self, index: usize, r: &mut UserRegs, instance: &mut Instance) {
        let pending = self.task(index).pending;
        match pending {
            Pending::Fork { child, flags, .. } => {
                r.rdi = flags;
                if r.rax as i64 == -513 {
                    // A signal queued since the entry stop made the kernel
                    // abandon the creation before it made a child. It reissues
                    // the call itself, at once or after a handler has run
                    // guest code and calls of its own: those must not settle
                    // the reservation, so it waits apart for the reissue
                    // (see `settle_restart`). The exit finishes as any other.
                    self.task_mut(index).restart = Some(Restart {
                        reservation: pending,
                        syscall: r.orig_rax,
                        rip: r.rip,
                    });
                } else if (r.rax as i64) < 0 {
                    if r.rax as i64 == -11 {
                        self.report_creation_failure(
                            b"ginux: native task creation returned EAGAIN",
                        );
                    }
                    self.cancel_creation(index, instance);
                } else {
                    if self.task(child).host == 0 || r.rax as usize != self.task(child).host {
                        self.fail(instance, b"unregistered fork result");
                    }
                    r.rax = self.task(child).id.pid as u64;
                }
            }
            Pending::Wait {
                child,
                original,
                status,
            } => {
                // An adopted orphan is a native child of this subreaper,
                // not of virtual init. ECHILD is expected there: the status
                // reported status comes from its observed ptrace death.
                let usage_fault = r.rax as i64 == -14;
                if (r.rax as i64) > 0 || usage_fault || r.rax as i64 == -10 && original[3] == 0 {
                    let id = self.task(child).id;
                    if self
                        .processes
                        .wait(self.task(index).id, WaitTarget::Specific(id.pid), 0)
                        .is_err()
                    {
                        self.fail(instance, b"virtual child reap failed")
                    }
                    self.retired[self.retired_next] = (self.task(child).host, id.pid);
                    self.retired_next = (self.retired_next + 1) % TASKS;
                    self.tasks[child] = None;
                    r.rax = if usage_fault {
                        (-14i64) as u64
                    } else {
                        id.pid as u64
                    };
                    if original[1] != 0 {
                        match crate::tracee_io::store_u32(
                            self.task(index).host,
                            original[1],
                            status,
                        ) {
                            Ok(()) => {}
                            Err(-5) => self.fail(instance, b"wait status rollback failed"),
                            Err(error) => r.rax = error as u64,
                        }
                    }
                }
                if r.rax as i64 == -10 && original[3] != 0 {
                    // An adopted orphan was reaped by this subreaper. Do not
                    // fabricate usage: leave its virtual status waitable.
                    r.rax = (-95i64) as u64;
                }
                if let Some(child) = self.tasks[child].as_mut() {
                    child.waiter = None;
                }
                self.wake_needed = true;
                r.rdi = original[0];
                r.rsi = original[1];
                r.rdx = original[2];
                r.r10 = original[3];
                r.r8 = original[4];
                r.r9 = original[5];
                r.orig_rax = original[6];
            }
            Pending::None => {}
        }
        self.task_mut(index).pending = Pending::None;
        self.retire_threads();
        if let Some(result) = self.task_mut(index).override_result.take() {
            r.rax = result as u64;
        }
        // A supervisor stop can interrupt an admitted timed futex with the
        // kernel's internal ERESTART_RESTARTBLOCK. Do not let it become an
        // ungranted restart_syscall: expose EINTR and let userspace retry the
        // original operation through its normal contract checks.
        if r.orig_rax == ginux_core::SYS_FUTEX && r.rax as i64 == -516 {
            r.rax = (-4i64) as u64;
        }
        if let Some(original) = self.task_mut(index).image_chdir.take() {
            r.rdi = original;
            if r.rax == 0 {
                self.replace_cwd(index, None, instance);
            }
        }
        let group = self.task(index).group;
        let task = self.tasks[index].as_mut().unwrap();
        match task.call.finish(
            &mut self.groups[group].as_mut().unwrap().table,
            r,
            &mut self.objects,
        ) {
            Ok(changed) => self.wake_needed |= changed,
            Err(reason) => self.fail(instance, reason),
        }
        audit_write(b"ginux: audit sequence=");
        audit_u64(self.task(index).sequence);
        audit_write(b" phase=exit result=");
        audit_i64(r.rax as i64);
        audit_write(b"\n");
    }
    fn replace_cwd(&mut self, index: usize, next: Option<i32>, instance: &mut Instance) {
        let old = core::mem::replace(&mut self.group_mut(index).cwd, next);
        if let Some(fd) = old {
            if self.objects.filesystem.close_cwd(fd).is_err() {
                self.fail(instance, b"cwd reference release failed");
            }
        }
    }

    /// `tkill` and `tgkill` name virtual thread ids. A signal for a thread of
    /// the caller's own process is queued by the kernel: the caller runs
    /// `tgkill` with its own host thread group and the target's host thread,
    /// so the kernel itself refuses any thread outside that group, and
    /// delivery takes the ordinary forwarded path with the sender's identity
    /// projected back to its virtual pid. Other processes of the instance get
    /// the `kill` subset; every other id is ESRCH, never a host task.
    fn thread_kill(&mut self, index: usize, r: &mut UserRegs, instance: &mut Instance) {
        let (tgid, tid, signal) = if r.orig_rax == 234 {
            (Some(r.rdi as i32), r.rsi as i32, r.rdx)
        } else {
            (None, r.rdi as i32, r.rsi)
        };
        if tid <= 0 || tgid.is_some_and(|tgid| tgid <= 0) {
            self.emulate(index, r, -22, instance);
            return;
        }
        let target = self
            .processes
            .thread_signal_target(
                self.task(index).id,
                tgid.map(|tgid| tgid as u32),
                tid as u32,
            )
            .ok()
            .and_then(|(view, own)| {
                self.tasks
                    .iter()
                    .position(|t| t.as_ref().is_some_and(|t| t.id == view.id && t.host != 0))
                    .map(|target| (target, own))
            });
        let Some((target, own_process)) = target else {
            self.emulate(index, r, -3, instance);
            return;
        };
        let host = self.task(target).host;
        // An unreadable signal view keeps the conservative answer.
        let default_stop = matches!(signal, 20..=22)
            && crate::task_signals::Signals::read(host)
                .is_none_or(|signals| signals.default_action(signal as usize));
        match ginux_core::thread_signal(signal, own_process, default_stop) {
            ginux_core::ThreadSignal::Exists => self.emulate(index, r, 0, instance),
            ginux_core::ThreadSignal::Refuse(errno) => self.emulate(index, r, errno, instance),
            ginux_core::ThreadSignal::Kill => {
                let result = unsafe { syscall2(SYS_KILL, host, SIGKILL) } as i64;
                self.emulate(index, r, result, instance)
            }
            ginux_core::ThreadSignal::Deliver => {
                let Some((thread_group, _)) =
                    crate::tracee_io::native_identity(self.task(index).host)
                else {
                    self.emulate(index, r, -3, instance);
                    return;
                };
                self.task_mut(index).call.save(r);
                if target != index {
                    self.task_mut(index).signal_target = Some(host);
                }
                r.orig_rax = 234;
                r.rdi = thread_group as u64;
                r.rsi = host as u64;
                r.rdx = signal;
                audit_write(b"mediate surface=own-process-thread-signal\n");
                self.run(index, r, instance);
            }
        }
    }

    fn wait_entry(&mut self, index: usize, r: &mut UserRegs, instance: &mut Instance) {
        let selector = r.rdi as i32;
        if selector != -1 && selector <= 0 || r.rdx & !1 != 0 {
            self.emulate(index, r, -95, instance);
            return;
        }
        let selected = (selector > 0).then_some(selector as u32);
        let parent = self.task(index).id;
        match self.processes.peek_wait(
            parent,
            selected.map_or(WaitTarget::Any, WaitTarget::Specific),
            r.rdx as u32,
        ) {
            Ok(result) => {
                let child = self
                    .tasks
                    .iter()
                    .position(|t| t.as_ref().is_some_and(|t| t.id == result.child))
                    .unwrap();
                if self.task(child).waiter.is_some() {
                    if r.rdx & 1 != 0 {
                        self.emulate(index, r, 0, instance);
                    } else {
                        self.park(
                            index,
                            *r,
                            Some(crate::task_signals::RESTART_SYSCALL),
                            instance,
                        );
                        audit_write(b"park surface=owned-child-wait\n");
                    }
                    return;
                }
                self.task_mut(child).waiter = Some(index);
                let original = [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9, r.orig_rax];
                self.task_mut(index).pending = Pending::Wait {
                    child,
                    original,
                    status: result.status.word(),
                };
                r.rdi = self.task(child).host as u64;
                // Reap natively before status copyout, including when the
                // caller's buffer faults. Never publish host wait status.
                r.rsi = 0;
                r.rdx = 0;
                // r10 stays the caller's usage buffer. Native wait4 writes
                // real counters for this one translated, owned child only.
                audit_write(b"mediate surface=owned-child-wait\n");
                self.run(index, r, instance);
            }
            Err(ProcessError::NotChild) => self.emulate(index, r, -10, instance),
            Err(ProcessError::NoExitedChild) => {
                let has_child = self.tasks.iter().flatten().any(|t| {
                    self.processes.view(t.id).is_ok_and(|v| {
                        v.parent == self.processes.view(parent).unwrap().tgid
                            && v.id.pid == v.tgid
                            && selected.is_none_or(|id| id == t.id.pid)
                    })
                });
                if !has_child {
                    self.emulate(index, r, -10, instance)
                } else if r.rdx & 1 != 0 {
                    self.emulate(index, r, 0, instance)
                } else {
                    self.park(
                        index,
                        *r,
                        Some(crate::task_signals::RESTART_SYSCALL),
                        instance,
                    );
                    audit_write(b"park surface=owned-child-wait\n");
                }
            }
            Err(_) => self.fail(instance, b"invalid virtual wait state"),
        }
    }
    fn wake(&mut self, instance: &mut Instance) {
        // Do not resume a peer while kernel-consumed guest arguments are in flight.
        if self.argument_guard.is_some() || !core::mem::replace(&mut self.wake_needed, false) {
            return;
        }
        for index in 0..TASKS {
            if self.argument_guard.is_some() {
                break;
            }
            let Some(mut r) = self.tasks[index].as_mut().and_then(|t| t.blocked.take()) else {
                continue;
            };
            self.task_mut(index).interruptible = None;
            if self.needs_argument_guard(index, &r) {
                self.begin_argument_guard(index, instance);
            }
            self.entry(index, &mut r, instance);
            if self.argument_guard == Some(index)
                && (self.task(index).blocked.is_some() || !self.task(index).in_flight)
            {
                self.release_argument_guard(instance);
            }
            self.interrupt_parked(index, instance);
        }
    }
    fn release_task_images(&mut self, index: usize, instance: &mut Instance) {
        let owned = self.task_mut(index).exec.take().and_then(|exec| exec.owned);
        if owned
            .and_then(|owned| owned.script)
            .is_some_and(|script| script.release_held(self.objects.filesystem).is_err())
        {
            self.fail(instance, b"task interpreter reference release failed");
        }
        if let Some(owned) = owned {
            if self
                .objects
                .filesystem
                .release_executable(owned.image)
                .is_err()
            {
                self.fail(instance, b"task executable release failed");
            }
        }
    }
    fn retire_threads(&mut self) {
        for index in 0..TASKS {
            let Some(task) = self.tasks[index].as_ref() else {
                continue;
            };
            if task.alive
                || self.processes.view(task.id).is_ok()
                || self.tasks.iter().flatten().any(|parent| {
                    parent.alive
                        && matches!(parent.pending, Pending::Fork {child, ..} if child == index)
                })
            {
                continue;
            }
            self.retired[self.retired_next] = (task.host, task.id.pid);
            self.retired_next = (self.retired_next + 1) % TASKS;
            self.tasks[index] = None;
        }
    }
    fn record_death(&mut self, id: TaskId, status: i32) -> Result<(), ProcessError> {
        if exited(status) {
            self.processes.exit(id, (status >> 8) & 255)
        } else {
            self.processes.signaled(id, (status & 127) as u8)
        }
    }
    fn died(&mut self, index: usize, status: i32, instance: &mut Instance) {
        // Its pid may be reused: no later lookup may borrow its root.
        crate::path_hooks::forget_root(self.task(index).host);
        self.wake_needed = true;
        if !self.task(index).alive {
            let task = self.task(index);
            if !task.adopted_reaped
                && task.id.pid != 1
                && task.wait_status == Some(status)
                && self
                    .processes
                    .view(task.id)
                    .is_ok_and(|view| view.id.pid == view.tgid)
            {
                self.task_mut(index).adopted_reaped = true;
                audit_write(b"ginux: adopted zombie native-reap virtual-pid=");
                audit_u64(self.task(index).id.pid as u64);
                audit_write(b"\n");
                return;
            }
            self.fail(instance, b"inconsistent repeated task death");
        }
        let id = self.task(index).id;
        let group = self.task(index).group;
        if let Some(restart) = self.task_mut(index).restart.take() {
            self.task_mut(index).pending = restart.reservation;
        }
        if self.cancel_creation(index, instance) {
            // The kernel may already have created the child this parent can
            // no longer claim.
            self.settle_newborns();
        }
        if self.group(index).creating == Some(index) {
            self.group_mut(index).creating = None;
        }
        if let Pending::Wait { child, .. } = self.task(index).pending {
            if let Some(child) = self.tasks[child].as_mut() {
                child.waiter = None;
            }
        }
        self.release_task_images(index, instance);
        self.task_mut(index).alive = false;
        let mapping_aborted = self.task_mut(index).mapping.take().is_some();
        if mapping_aborted && !self.tearing_down {
            self.fail(instance, b"task died during private mapping transaction");
        }
        self.task_mut(index).wait_status = Some(status);
        self.task_mut(index).blocked = None;
        if let Err(reason) = self.tasks[index].as_mut().unwrap().call.reset(
            Some(&mut self.groups[group].as_mut().unwrap().table),
            &mut self.objects,
        ) {
            self.fail(instance, reason);
        }
        if id == self.groups[group].as_ref().unwrap().leader {
            self.groups[group].as_mut().unwrap().status = Some(status);
        } else if self.record_death(id, status).is_err() || self.processes.reap_thread(id).is_err()
        {
            self.fail(instance, b"virtual thread exit failed");
        }
        if let Some((leader, status)) = self.release_group(index, instance) {
            let Some(status) = status else {
                self.fail(instance, b"process ended without leader status");
            };
            if self.record_death(leader, status).is_err() {
                self.fail(instance, b"virtual process exit failed");
            }
            if leader.pid == 1 {
                self.root_status = Some(status);
            }
        }
        audit_write(b"ginux: task exited virtual-pid=");
        audit_u64(id.pid as u64);
        audit_write(b"\n");
        self.retire_threads();
    }
    fn teardown(&mut self, instance: &mut Instance, export: bool) {
        self.tearing_down = true;
        for t in self
            .tasks
            .iter()
            .flatten()
            .filter(|t| t.alive && t.host != 0)
        {
            let _ = unsafe { syscall2(SYS_KILL, t.host, SIGKILL) };
        }
        for host in self.unknown_stops.iter().filter(|p| **p != 0) {
            let _ = unsafe { syscall2(SYS_KILL, *host, SIGKILL) };
        }
        loop {
            let mut status = 0;
            let host = unsafe {
                syscall4(
                    SYS_WAIT4,
                    usize::MAX,
                    &mut status as *mut _ as usize,
                    WALL,
                    0,
                )
            };
            if host == -10 {
                break;
            }
            if host == -4 {
                continue;
            }
            if host < 0 {
                supervision_error(instance, b"instance teardown wait failed")
            }
            if stopped(status) {
                let _ = unsafe { syscall2(SYS_KILL, host as usize, SIGKILL) };
                continue;
            }
            if let Some(index) = self.tasks.iter().position(|t| {
                t.as_ref()
                    .is_some_and(|t| t.host == host as usize && t.alive)
            }) {
                self.died(index, status, instance);
            }
        }
        for index in 0..TASKS {
            if self.tasks[index].is_some() {
                self.release_task_images(index, instance);
            }
        }
        for task in self.tasks.iter_mut().flatten() {
            if let Err(reason) = task.call.reset(
                self.groups[task.group]
                    .as_mut()
                    .map(|group| &mut group.table),
                &mut self.objects,
            ) {
                supervision_error(instance, reason);
            }
        }
        for group in self.groups.iter_mut().flatten() {
            if let Err(reason) = group.table.release_exited(&mut self.objects) {
                supervision_error(instance, reason);
            }
            if let Some(cwd) = group.cwd.take() {
                if self.objects.filesystem.close_cwd(cwd).is_err() {
                    supervision_error(instance, b"process cwd release failed");
                }
            }
            if let Some(image) = group.image.take() {
                if self.objects.filesystem.release_executable(image).is_err() {
                    supervision_error(instance, b"process image release failed");
                }
            }
        }
        self.processes.shutdown(137);
        self.processes.reap_all();
        if self.objects.refs.active() != 0 || self.processes.active() != 0 {
            supervision_error(instance, b"instance teardown retained owned state")
        }
        let control_closed = crate::checkpoint_control::close();
        let event_closed = if let Some(fd) = self.signal_fd.take() {
            if unsafe { syscall1(3, fd) } == 0 {
                Ok(())
            } else {
                Err(b"task event close failed".as_slice())
            }
        } else {
            Ok(())
        };
        let settled = control_closed
            .and(event_closed)
            .and(self.objects.filesystem.cleanup_error().map_or(Ok(()), Err));
        let staged = settled.and_then(|_| {
            if export {
                self.objects.filesystem.stage_export()
            } else {
                crate::storage_export::cancel().map(|_| None)
            }
        });
        self.objects.devices.network.audit_summary();
        let count = self
            .denials
            .iter()
            .filter(|denial| denial.is_some())
            .count();
        crate::launch::audit_summary(format_args!(
            "ginux: denial-summary version=1 operations={count}\n"
        ));
        for (index, denial) in self.denials.iter().enumerate() {
            if let Some(denial) = denial {
                let rule = self.contract.rules().get(index);
                let errno = rule
                    .and_then(|rule| {
                        if let ContractAction::Deny(errno) = rule.action {
                            Some(errno)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(38);
                crate::launch::audit_summary(format_args!(
                    "ginux: denial-summary operation={} policy-source={} policy-rule={} result=-{} count={} first-sequence={} first-pid={} first-syscall={}\n",
                    rule.map_or("unknown", |rule| rule.operation.id), rule.map_or("default-deny", |rule| rule.source),
                    rule.map_or(0, |rule| rule.source_rule), errno, denial.count, denial.first_sequence, denial.first_pid, denial.first_syscall));
            }
        }
        let released = self.objects.filesystem.teardown();
        // Capture needs live backing bytes; publication must wait until their
        // final release has succeeded. A backing release failure must leave no
        // final archive name.
        let exported = match (staged, released) {
            (Ok(Some(archive)), Ok(())) => archive.publish(),
            (Ok(Some(archive)), Err(reason)) => {
                let _ = archive.cancel();
                Err(reason)
            }
            (Ok(None), result) => result,
            (Err(reason), _) => {
                let _ = crate::storage_export::cancel();
                Err(reason)
            }
        };
        line_stderr(b"ginux: teardown tasks=0 owned-handles=0");
        if let Err(reason) = exported {
            supervision_error(instance, reason);
        }
    }
    fn fail(&mut self, instance: &mut Instance, reason: &[u8]) -> ! {
        self.teardown(instance, false);
        supervision_error(instance, reason)
    }
}

fn exited(status: i32) -> bool {
    status & 127 == 0
}
fn signaled(status: i32) -> bool {
    status & 127 != 0 && status & 127 != 127
}
