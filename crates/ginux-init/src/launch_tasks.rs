//! Task ownership for configured native launch. A newborn never runs before
//! its process identity and descriptor snapshot are installed.

use crate::descriptors::{Backends, DescriptorTable};
use crate::dispatch::{
    balanced_surface_name, decide_launch, native_arguments_allowed, NativeDecision,
};
use crate::launch::{
    audit_i64, audit_u64, audit_write, finish_exited, finish_signaled, launch_early_fail,
    launch_exit_reason, line_stderr, supervision_error,
};
use crate::supervisor::*;
use crate::tracee_io::copy_memory;
use ginux_core::{balanced_identity_result, balanced_surface, Action};
use ginux_domain::Domain;
use ginux_process::{Credentials, ProcessError, ProcessTable, TaskId};

const TASKS: usize = 16;
const WALL: usize = 0x4000_0000;
// Linux x86-64: sys/ptrace and asm/unistd_64.h.
const OPTIONS: usize = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | 2 | 4 | 8 | 16;

#[derive(Clone, Copy)]
enum Pending {
    None,
    Fork(usize),
    Wait { child: usize, original: [u64; 7] },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExecStage {
    Sync,
    Reenter,
    Kernel,
    Completed,
}

#[derive(Clone, Copy)]
struct Exec {
    original: UserRegs,
    native_dirfd: u64,
    next_native: usize,
    stage: ExecStage,
}

struct Task {
    id: TaskId,
    host: usize,
    alive: bool,
    descriptors: DescriptorTable,
    pending: Pending,
    override_result: Option<i64>,
    blocked: Option<UserRegs>,
    sequence: u64,
    exec: Option<Exec>,
}

struct Supervisor<'a> {
    tasks: [Option<Task>; TASKS],
    processes: ProcessTable<TASKS>,
    objects: Backends<'a>,
    unknown_stops: [usize; TASKS],
    retired: [(usize, u32); TASKS],
    retired_next: usize,
    sequence: u64,
    wake_needed: bool,
}

pub fn supervise(
    root: usize,
    domain: &mut Domain,
    objects: Backends,
    descriptors: DescriptorTable,
) -> ! {
    let mut status = 0;
    let waited = loop {
        let result = wait(root, &mut status);
        if result != -4 {
            break result;
        }
    };
    if waited < 0 {
        let _ = unsafe { syscall2(SYS_KILL, root, SIGKILL) };
        while wait(root, &mut status) == -4 {}
        supervision_error(domain, b"launch tracee wait after exec failed");
    }
    if exited(status) {
        launch_early_fail(domain, launch_exit_reason((status >> 8) & 255));
    }
    if !stopped(status) || (status >> 8) & 255 != 5 {
        let _ = unsafe { syscall2(SYS_KILL, root, SIGKILL) };
        while wait(root, &mut status) == -4 {}
        supervision_error(domain, b"launch tracee did not stop after exec");
    }
    let mut processes = ProcessTable::new();
    let id = processes
        .create_init(Credentials::unprivileged(0, 0))
        .unwrap();
    let mut s = Supervisor {
        tasks: core::array::from_fn(|_| None),
        processes,
        objects,
        unknown_stops: [0; TASKS],
        retired: [(0, 0); TASKS],
        retired_next: 0,
        sequence: 0,
        wake_needed: false,
    };
    s.tasks[0] = Some(Task {
        id,
        host: root,
        alive: true,
        descriptors,
        pending: Pending::None,
        override_result: None,
        blocked: None,
        sequence: 0,
        exec: None,
    });
    if ptrace(PTRACE_SETOPTIONS, root, 0, OPTIONS) < 0 {
        s.fail(domain, b"launch ptrace setup failed");
    }
    line_stderr(b"ginux: launch backend=ptrace-native profile=balanced elf-loader=host");
    line_stderr(b"ginux: launch tracee-uid=1000 tracee-gid=1000 root=host-path-read-only");
    s.resume(0, 0, domain);
    loop {
        s.wake(domain);
        status = 0;
        let host = unsafe {
            syscall4(
                SYS_WAIT4,
                usize::MAX,
                &mut status as *mut _ as usize,
                WALL,
                0,
            )
        };
        if host == -4 {
            continue;
        }
        if host < 0 {
            s.fail(domain, b"launch task wait failed")
        }
        let host = host as usize;
        let index = s
            .tasks
            .iter()
            .position(|t| t.as_ref().is_some_and(|t| t.host == host && host != 0));
        let Some(index) = index else {
            // Auto-attached children can report their birth stop before the
            // parent's event. Hold them; GETEVENTMSG must confirm ownership.
            if stopped(status) && ((status >> 8) & 255) == 19 {
                let slot = s
                    .unknown_stops
                    .iter()
                    .position(|p| *p == 0)
                    .unwrap_or_else(|| s.fail(domain, b"unregistered task bound exceeded"));
                s.unknown_stops[slot] = host;
                continue;
            }
            s.fail(domain, b"event from unregistered task");
        };
        if exited(status) || signaled(status) {
            s.died(index, status, domain);
            if index == 0 {
                s.teardown(domain);
                let normal = exited(status);
                let _ = domain.task_exited(normal);
                if normal {
                    finish_exited(((status >> 8) & 255) as u64)
                } else {
                    finish_signaled((status & 127) as u64)
                }
            }
            continue;
        }
        if !stopped(status) {
            s.fail(domain, b"task escaped supervision")
        }
        let event = (status as u32 >> 16) as usize;
        if matches!(event, 1..=3) {
            s.birth(index, domain);
            continue;
        }
        if event == 4 {
            s.exec_completed(index, domain);
            continue;
        }
        if event != 0 {
            s.fail(domain, b"unsupported task transition")
        }
        let signal = ((status >> 8) & 255) as usize;
        if signal != 133 {
            if s.task(index)
                .exec
                .is_some_and(|e| matches!(e.stage, ExecStage::Sync | ExecStage::Reenter))
            {
                s.fail(domain, b"signal interrupted exec descriptor setup");
            }
            let mut info = [0u64; 16];
            if ptrace(0x4202, host, 0, info.as_mut_ptr() as usize) < 0 {
                s.fail(domain, b"launch group stops are unsupported")
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
                    s.fail(domain, b"signal identity projection failed")
                }
            }
            audit_write(b"ginux: audit phase=signal-forwarded signal=");
            audit_u64(signal as u64);
            audit_write(b"\n");
            s.resume(index, signal, domain);
            continue;
        }
        let mut r = s.registers(index, domain);
        let mut info = [0u64; 11];
        if ptrace(
            0x420e,
            host,
            core::mem::size_of_val(&info),
            info.as_mut_ptr() as usize,
        ) < 24
            || (info[0] >> 32) as u32 != 0xc000003e
        {
            s.fail(domain, b"launch requires the x86-64 syscall ABI")
        }
        match info[0] as u8 {
            1 => s.entry(index, &mut r, domain),
            2 => s.syscall_exit(index, &mut r, domain),
            _ => s.fail(domain, b"unknown syscall stop"),
        }
    }
}

impl Supervisor<'_> {
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
    fn registers(&mut self, index: usize, domain: &mut Domain) -> UserRegs {
        let mut r = core::mem::MaybeUninit::uninit();
        if ptrace(
            PTRACE_GETREGS,
            self.task(index).host,
            0,
            r.as_mut_ptr() as usize,
        ) < 0
        {
            self.fail(domain, b"launch register read failed")
        }
        unsafe { r.assume_init() }
    }
    fn resume(&mut self, index: usize, signal: usize, domain: &mut Domain) {
        if ptrace(PTRACE_SYSCALL, self.task(index).host, 0, signal) < 0 {
            self.fail(domain, b"launch task resume failed")
        }
    }
    fn run(&mut self, index: usize, r: &UserRegs, domain: &mut Domain) {
        if ptrace(
            PTRACE_SETREGS,
            self.task(index).host,
            0,
            r as *const _ as usize,
        ) < 0
        {
            self.fail(domain, b"launch register update failed")
        }
        self.resume(index, 0, domain);
    }
    fn emulate(&mut self, index: usize, r: &mut UserRegs, result: i64, domain: &mut Domain) {
        self.task_mut(index).override_result = Some(result);
        r.orig_rax = u64::MAX;
        audit_write(b"emulate result=");
        audit_i64(result);
        audit_write(b"\n");
        self.run(index, r, domain);
    }
    fn entry(&mut self, index: usize, r: &mut UserRegs, domain: &mut Domain) {
        if let Some(exec) = self.task(index).exec {
            match exec.stage {
                ExecStage::Reenter => {
                    if r.orig_rax != exec.original.orig_rax || r.rip != exec.original.rip {
                        self.fail(domain, b"exec replay left its syscall instruction");
                    }
                    self.exec_step(index, r, domain);
                    return;
                }
                ExecStage::Completed => {
                    self.task_mut(index).exec = None;
                }
                _ => self.fail(domain, b"unexpected entry during exec"),
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
        audit_write(b" action=");
        let original = *r;
        let id = self.task(index).id;
        match r.orig_rax {
            59 | 322 => {
                let result = self.prepare_exec(index, r);
                if let Err(errno) = result {
                    self.emulate(index, r, errno, domain);
                } else {
                    audit_write(b"mediate surface=owned-exec\n");
                    self.exec_step(index, r, domain);
                }
                return;
            }
            13 if r.rdi == 17 && r.rsi != 0 && r.r10 == 8 => {
                // Native auto-reaping would bypass the explicit virtual wait
                // lifecycle. Keep unsupported dispositions fail-closed.
                let mut action = [0u8; 16];
                if copy_memory(self.task(index).host, r.rsi, &mut action, false) != Ok(16) {
                    self.emulate(index, r, -14, domain);
                    return;
                }
                let handler = u64::from_ne_bytes(action[..8].try_into().unwrap());
                let flags = u64::from_ne_bytes(action[8..].try_into().unwrap());
                if handler == 1 || flags & 2 != 0 {
                    self.emulate(index, r, -95, domain);
                    return;
                }
            }
            39 | 186 => {
                self.emulate(index, r, id.pid as i64, domain);
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
                    domain,
                );
                return;
            }
            56..=58 => {
                if r.orig_rax == 56 && !matches!(r.rdi, 17 | 0x4111) {
                    self.emulate(index, r, -38, domain);
                    return;
                }
                let Some(slot) = self.tasks.iter().position(|t| t.is_none()) else {
                    self.emulate(index, r, -11, domain);
                    return;
                };
                let child = match self.processes.fork(id) {
                    Ok(id) => id,
                    Err(_) => {
                        self.emulate(index, r, -11, domain);
                        return;
                    }
                };
                let table = match self.tasks[index]
                    .as_ref()
                    .unwrap()
                    .descriptors
                    .fork_copy(self.objects.refs)
                {
                    Ok(table) => table,
                    Err(reason) => self.fail(domain, reason),
                };
                self.tasks[slot] = Some(Task {
                    id: child,
                    host: 0,
                    alive: true,
                    descriptors: table,
                    pending: Pending::None,
                    override_result: None,
                    blocked: None,
                    sequence: 0,
                    exec: None,
                });
                self.task_mut(index).pending = Pending::Fork(slot);
                audit_write(b"mediate surface=owned-process-create\n");
                self.run(index, r, domain);
                return;
            }
            61 => {
                self.wait_entry(index, r, domain);
                return;
            }
            62 => {
                let target = r.rdi as i32;
                let signal = r.rsi;
                if target <= 0 || !matches!(signal, 0 | 9) {
                    self.emulate(index, r, -95, domain);
                    return;
                }
                let found = self
                    .tasks
                    .iter()
                    .flatten()
                    .find(|t| t.id.pid == target as u32 && t.alive && t.host != 0)
                    .map(|t| t.host);
                let result = found
                    .map(|host| unsafe { syscall2(SYS_KILL, host, signal as usize) } as i64)
                    .unwrap_or(-3);
                self.emulate(index, r, result, domain);
                return;
            }
            218 => {
                self.task_mut(index).override_result = Some(id.pid as i64);
            }
            _ => {}
        }
        let decision = {
            let task = self.tasks[index].as_mut().unwrap();
            decide_launch(task.host, r, &mut task.descriptors, &mut self.objects)
        };
        match decision {
            NativeDecision::Park { fd } => {
                self.task_mut(index).blocked = Some(original);
                audit_write(b"park\nginux: park surface=lane-channel fd=");
                audit_u64(fd as u64);
                audit_write(b"\n");
            }
            NativeDecision::Hooked { result, .. } => {
                self.wake_needed = true;
                self.emulate(index, r, result, domain)
            }
            NativeDecision::Contract(decision) => match decision.action {
                Action::Emulate if matches!(original.orig_rax, 60 | 231) => {
                    audit_write(b"emulate result=domain-stop\n");
                    self.run(index, r, domain)
                }
                Action::Emulate => self.emulate(
                    index,
                    r,
                    balanced_identity_result(original.orig_rax).unwrap_or(0),
                    domain,
                ),
                Action::Mediate
                    if native_arguments_allowed(self.task(index).host, r.orig_rax, r) =>
                {
                    audit_write(b"mediate surface=");
                    audit_write(balanced_surface_name(balanced_surface(r.orig_rax)));
                    audit_write(b"\n");
                    self.run(index, r, domain)
                }
                Action::Mediate => self.emulate(index, r, -1, domain),
                Action::Deny(errno) => {
                    audit_write(b"deny result=-");
                    audit_u64(errno as u64);
                    audit_write(b"\n");
                    self.task_mut(index).override_result = Some(-(errno as i64));
                    r.orig_rax = u64::MAX;
                    self.run(index, r, domain)
                }
            },
        }
    }
    fn prepare_exec(&mut self, index: usize, r: &UserRegs) -> Result<(), i64> {
        let host = self.task(index).host;
        let mut native_dirfd = r.rdi;
        if r.orig_rax == 59 {
            self.objects.filesystem.native_exec_path(host, r.rdi)?;
        } else {
            if r.r8 & !0x1100 != 0 {
                return Err(-22);
            }
            let path = crate::tracee_io::read_path(host, r.rsi)?;
            if path.is_empty() {
                if r.r8 & 0x1000 == 0 {
                    return Err(-2);
                }
                native_dirfd = self.task(index).descriptors.exec_native_descriptor(r.rdi)? as u64;
            } else {
                if path.as_bytes()[0] != b'/' && r.rdi as i32 != -100 {
                    return Err(-95);
                }
                self.objects.filesystem.native_exec_path(host, r.rsi)?;
                native_dirfd = (-100i64) as u64;
            }
        }
        let mut instruction = [0u8; 2];
        let address = r.rip.checked_sub(2).ok_or(-95)?;
        if copy_memory(host, address, &mut instruction, false) != Ok(2)
            || instruction != [0x0f, 0x05]
        {
            return Err(-95);
        }
        self.task_mut(index).exec = Some(Exec {
            original: *r,
            native_dirfd,
            next_native: 0,
            stage: ExecStage::Reenter,
        });
        Ok(())
    }

    fn exec_step(&mut self, index: usize, r: &mut UserRegs, domain: &mut Domain) {
        let exec = self.task(index).exec.unwrap();
        if let Some((fd, cloexec)) = self
            .task(index)
            .descriptors
            .next_exec_native(exec.next_native)
        {
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
        } else {
            *r = exec.original;
            r.rdi = exec.native_dirfd;
            self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::Kernel;
        }
        self.run(index, r, domain);
    }

    fn exec_completed(&mut self, index: usize, domain: &mut Domain) {
        if !self
            .task(index)
            .exec
            .is_some_and(|e| e.stage == ExecStage::Kernel)
        {
            self.fail(domain, b"unreserved exec transition");
        }
        let result = self.tasks[index]
            .as_mut()
            .unwrap()
            .descriptors
            .exec_completed(&mut self.objects);
        if let Err(reason) = result {
            self.fail(domain, reason);
        }
        if self.processes.exec(self.task(index).id).is_err() {
            self.fail(domain, b"virtual exec transition failed");
        }
        self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::Completed;
        self.wake_needed = true;
        audit_write(b"ginux: task exec virtual-pid=");
        audit_u64(self.task(index).id.pid as u64);
        audit_write(b"\n");
        self.resume(index, 0, domain);
    }

    fn birth(&mut self, parent: usize, domain: &mut Domain) {
        let Pending::Fork(slot) = self.task(parent).pending else {
            self.fail(domain, b"unreserved child event")
        };
        let mut host = 0usize;
        if ptrace(
            PTRACE_GETEVENTMSG,
            self.task(parent).host,
            0,
            &mut host as *mut _ as usize,
        ) < 0
            || host == 0
        {
            self.fail(domain, b"child event identity missing")
        }
        self.task_mut(slot).host = host;
        let early = self.unknown_stops.iter().position(|p| *p == host);
        if let Some(i) = early {
            self.unknown_stops[i] = 0;
        } else {
            let mut status = 0;
            if unsafe { syscall4(SYS_WAIT4, host, &mut status as *mut _ as usize, WALL, 0) } < 0
                || !stopped(status)
                || ((status >> 8) & 255) != 19
            {
                self.fail(domain, b"child birth stop missing")
            }
        }
        if ptrace(PTRACE_SETOPTIONS, host, 0, OPTIONS) < 0 {
            self.fail(domain, b"child supervision setup failed")
        }
        audit_write(b"ginux: task registered virtual-pid=");
        audit_u64(self.task(slot).id.pid as u64);
        audit_write(b"\n");
        self.resume(slot, 0, domain);
        self.resume(parent, 0, domain);
    }
    fn syscall_exit(&mut self, index: usize, r: &mut UserRegs, domain: &mut Domain) {
        if let Some(exec) = self.task(index).exec {
            match exec.stage {
                ExecStage::Sync => {
                    if r.orig_rax != 72 || r.rax != 0 {
                        self.fail(domain, b"exec native descriptor synchronization failed");
                    }
                    let mut replay = exec.original;
                    replay.rip -= 2;
                    replay.rax = replay.orig_rax;
                    self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::Reenter;
                    self.run(index, &replay, domain);
                    return;
                }
                ExecStage::Kernel => {
                    if r.rax as i64 >= 0 {
                        self.fail(domain, b"exec success missing its ownership event");
                    }
                    let old = exec.original;
                    r.rdi = old.rdi;
                    r.rsi = old.rsi;
                    r.rdx = old.rdx;
                    r.r10 = old.r10;
                    r.r8 = old.r8;
                    r.r9 = old.r9;
                    r.orig_rax = old.orig_rax;
                    // Public descriptors, aliases and owned refs are unchanged.
                    self.task_mut(index).exec = None;
                }
                ExecStage::Completed => {
                    self.task_mut(index).exec = None;
                }
                ExecStage::Reenter => self.fail(domain, b"unexpected exit during exec replay"),
            }
        }
        let pending = self.task(index).pending;
        match pending {
            Pending::Fork(child) => {
                if (r.rax as i64) < 0 {
                    let result = self.tasks[child]
                        .as_mut()
                        .unwrap()
                        .descriptors
                        .release_exited(&mut self.objects);
                    if let Err(reason) = result {
                        self.fail(domain, reason)
                    }
                    let child_id = self.task(child).id;
                    if self
                        .processes
                        .cancel_fork(self.task(index).id, child_id)
                        .is_err()
                    {
                        self.fail(domain, b"fork rollback failed")
                    }
                    self.tasks[child] = None;
                } else {
                    if self.task(child).host == 0 || r.rax as usize != self.task(child).host {
                        self.fail(domain, b"unregistered fork result")
                    }
                    r.rax = self.task(child).id.pid as u64;
                }
            }
            Pending::Wait { child, original } => {
                // An adopted orphan is a native child of this subreaper,
                // not of virtual init. ECHILD is expected there: the status
                // already copied out came from its observed ptrace death.
                if (r.rax as i64) > 0 || r.rax as i64 == -10 {
                    let id = self.task(child).id;
                    if self
                        .processes
                        .wait(self.task(index).id, Some(id.pid))
                        .is_err()
                    {
                        self.fail(domain, b"virtual child reap failed")
                    }
                    self.retired[self.retired_next] = (self.task(child).host, id.pid);
                    self.retired_next = (self.retired_next + 1) % TASKS;
                    self.tasks[child] = None;
                    r.rax = id.pid as u64;
                }
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
        if let Some(result) = self.task_mut(index).override_result.take() {
            r.rax = result as u64;
        }
        let result = self.tasks[index].as_mut().unwrap().descriptors.finish(r);
        if let Err(reason) = result {
            self.fail(domain, reason)
        }
        audit_write(b"ginux: audit sequence=");
        audit_u64(self.task(index).sequence);
        audit_write(b" phase=exit result=");
        audit_i64(r.rax as i64);
        audit_write(b"\n");
        self.run(index, r, domain);
    }
    fn wait_entry(&mut self, index: usize, r: &mut UserRegs, domain: &mut Domain) {
        let selector = r.rdi as i32;
        if selector != -1 && selector <= 0 || r.rdx & !1 != 0 || r.r10 != 0 {
            self.emulate(index, r, -95, domain);
            return;
        }
        let selected = (selector > 0).then_some(selector as u32);
        let parent = self.task(index).id;
        match self.processes.peek_wait(parent, selected) {
            Ok(result) => {
                let child = self
                    .tasks
                    .iter()
                    .position(|t| t.as_ref().is_some_and(|t| t.id == result.child))
                    .unwrap();
                if r.rsi != 0 {
                    let mut status = result.status.to_ne_bytes();
                    if copy_memory(self.task(index).host, r.rsi, &mut status, true) != Ok(4) {
                        self.emulate(index, r, -14, domain);
                        return;
                    }
                }
                let original = [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9, r.orig_rax];
                self.task_mut(index).pending = Pending::Wait { child, original };
                r.rdi = self.task(child).host as u64;
                r.rdx = 0;
                audit_write(b"mediate surface=owned-child-wait\n");
                self.run(index, r, domain);
            }
            Err(ProcessError::NotChild) => self.emulate(index, r, -10, domain),
            Err(ProcessError::NoExitedChild) => {
                let has_child = self.tasks.iter().flatten().any(|t| {
                    self.processes.view(t.id).is_ok_and(|v| {
                        v.parent == parent.pid && selected.is_none_or(|id| id == t.id.pid)
                    })
                });
                if !has_child {
                    self.emulate(index, r, -10, domain)
                } else if r.rdx & 1 != 0 {
                    self.emulate(index, r, 0, domain)
                } else {
                    self.task_mut(index).blocked = Some(*r);
                    audit_write(b"park surface=owned-child-wait\n");
                }
            }
            Err(_) => self.fail(domain, b"invalid virtual wait state"),
        }
    }
    fn wake(&mut self, domain: &mut Domain) {
        // Only object operations and observed deaths can satisfy these waits.
        // Other tasks' register/signal/fork stops do not change readiness.
        if !core::mem::replace(&mut self.wake_needed, false) {
            return;
        }
        for index in 0..TASKS {
            let Some(mut r) = self.tasks[index].as_mut().and_then(|t| t.blocked.take()) else {
                continue;
            };
            self.entry(index, &mut r, domain);
        }
    }
    fn died(&mut self, index: usize, status: i32, domain: &mut Domain) {
        self.wake_needed = true;
        if !self.task(index).alive {
            self.fail(domain, b"duplicate task death")
        }
        self.task_mut(index).alive = false;
        self.task_mut(index).blocked = None;
        if self.processes.exit(self.task(index).id, status).is_err() {
            self.fail(domain, b"virtual task exit failed")
        }
        let result = self.tasks[index]
            .as_mut()
            .unwrap()
            .descriptors
            .release_exited(&mut self.objects);
        if let Err(reason) = result {
            self.fail(domain, reason)
        }
        audit_write(b"ginux: task exited virtual-pid=");
        audit_u64(self.task(index).id.pid as u64);
        audit_write(b"\n");
    }
    fn teardown(&mut self, domain: &mut Domain) {
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
                supervision_error(domain, b"domain teardown wait failed")
            }
            if stopped(status) {
                let _ = unsafe { syscall2(SYS_KILL, host as usize, SIGKILL) };
                continue;
            }
            if let Some(index) = self.tasks.iter().position(|t| {
                t.as_ref()
                    .is_some_and(|t| t.host == host as usize && t.alive)
            }) {
                self.died(index, status, domain);
            }
        }
        for task in self.tasks.iter_mut().flatten() {
            if let Err(reason) = task.descriptors.release_exited(&mut self.objects) {
                supervision_error(domain, reason)
            }
        }
        self.processes.shutdown(137);
        self.processes.reap_all();
        if self.objects.refs.active() != 0 || self.processes.active() != 0 {
            supervision_error(domain, b"domain teardown retained owned state")
        }
        line_stderr(b"ginux: teardown tasks=0 owned-handles=0");
    }
    fn fail(&mut self, domain: &mut Domain, reason: &[u8]) -> ! {
        self.teardown(domain);
        supervision_error(domain, reason)
    }
}

fn exited(status: i32) -> bool {
    status & 127 == 0
}
fn signaled(status: i32) -> bool {
    status & 127 != 0 && status & 127 != 127
}
