//! Task ownership for configured native launch. A newborn never runs before
//! its process identity and descriptor snapshot are installed.

use crate::descriptors::{Backends, DescriptorCall, DescriptorTable, ExecDescriptor};
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
use ginux_instance::Instance;
use ginux_process::{Credentials, ProcessError, ProcessTable, TaskId, WaitTarget};
use ginux_vfs::Executable;

const TASKS: usize = 32;
const WALL: usize = 0x4000_0000;
// Linux x86-64: sys/ptrace and asm/unistd_64.h.
const OPTIONS: usize = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | 2 | 4 | 8 | 16;

#[derive(Clone, Copy)]
enum Pending {
    None,
    Fork {
        child: usize,
        flags: u64,
        child_tid: Option<u64>,
        parent_tid: Option<u64>,
    },
    Wait {
        child: usize,
        original: [u64; 7],
        status: u32,
    },
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
    adopted_reaped: bool,
    wait_status: Option<i32>,
    group: usize,
    call: DescriptorCall,
    image_chdir: Option<u64>,
    pending: Pending,
    override_result: Option<i64>,
    blocked: Option<UserRegs>,
    sequence: u64,
    exec: Option<Exec>,
    mapping: Option<crate::file_mapping::MappingCall>,
    path_rewrite: Option<crate::path_hooks::Rewrite>,
    waiter: Option<usize>,
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

struct Supervisor<'a> {
    tasks: [Option<Task>; TASKS],
    groups: [Option<DescriptorGroup>; TASKS],
    processes: ProcessTable<TASKS>,
    objects: Backends<'a>,
    unknown_stops: [usize; TASKS],
    retired: [(usize, u32); TASKS],
    retired_next: usize,
    sequence: u64,
    wake_needed: bool,
    tearing_down: bool,
    signal_fd: Option<usize>,
    root_status: Option<i32>,
    creation_failure_reported: bool,
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

pub fn supervise(
    root: usize,
    instance: &mut Instance,
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
        unknown_stops: [0; TASKS],
        retired: [(0, 0); TASKS],
        retired_next: 0,
        sequence: 0,
        wake_needed: false,
        tearing_down: false,
        signal_fd: None,
        root_status: None,
        creation_failure_reported: false,
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
    s.tasks[0] = Some(Task {
        id,
        host: root,
        alive: true,
        adopted_reaped: false,
        wait_status: None,
        group: 0,
        call: DescriptorCall::new(),
        image_chdir: None,
        pending: Pending::None,
        override_result: None,
        blocked: None,
        sequence: 0,
        exec: None,
        mapping: None,
        path_rewrite: None,
        waiter: None,
    });
    if ptrace(PTRACE_SETOPTIONS, root, 0, OPTIONS) < 0 {
        s.fail(instance, b"launch ptrace setup failed");
    }
    line_stderr(b"ginux: launch backend=ptrace-native profile=balanced elf-loader=host");
    line_stderr(b"ginux: launch tracee-uid=1000 tracee-gid=1000 root=host-path-read-only");
    let signal_fd = task_events().unwrap_or_else(|reason| s.fail(instance, reason));
    s.signal_fd = Some(signal_fd);
    s.resume(0, 0, instance);
    let mut poll_tick = 0;
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
        // Only this owner mediates owned mutations; snapshot serialization
        // cannot interleave with another owned write.
        if let Err(reason) = crate::checkpoint_control::poll(s.objects.filesystem) {
            s.fail(instance, reason);
        }
        status = 0;
        let host = unsafe {
            syscall4(
                SYS_WAIT4,
                usize::MAX,
                &mut status as *mut _ as usize,
                WALL | 1,
                0,
            )
        };
        if host == 0 {
            if let Err(reason) = wait_events(signal_fd, polling) {
                s.fail(instance, reason);
            }
            continue;
        }
        if host == -4 {
            continue;
        }
        if host < 0 {
            s.fail(instance, b"launch task wait failed")
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
                    .unwrap_or_else(|| s.fail(instance, b"unregistered task bound exceeded"));
                s.unknown_stops[slot] = host;
                continue;
            }
            s.fail(instance, b"event from unregistered task");
        };
        if exited(status) || signaled(status) {
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
            s.exec_completed(index, instance);
            continue;
        }
        if event != 0 {
            s.fail(instance, b"unsupported task transition")
        }
        let signal = ((status >> 8) & 255) as usize;
        if signal != 133 {
            if s.task(index).mapping.is_some()
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
        match info[0] as u8 {
            1 => s.entry(index, &mut r, instance),
            2 => s.syscall_exit(index, &mut r, instance),
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
        let result = ptrace(PTRACE_SYSCALL, self.task(index).host, 0, signal);
        if result == -3 {
            // SIGKILL can end a ptrace stop between an object retry and
            // resume. Keep ownership until wait4 supplies the actual death.
            self.task_mut(index).blocked = None;
        } else if result < 0 {
            self.fail(instance, b"launch task resume failed")
        }
    }
    fn run(&mut self, index: usize, r: &UserRegs, instance: &mut Instance) {
        let result = ptrace(
            PTRACE_SETREGS,
            self.task(index).host,
            0,
            r as *const _ as usize,
        );
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
        audit_write(b"\n");
        self.run(index, r, instance);
    }
    fn entry(&mut self, index: usize, r: &mut UserRegs, instance: &mut Instance) {
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
        audit_write(b" action=");
        let original = *r;
        let id = self.task(index).id;
        let parent_group = self.task(index).group;
        if self
            .group(index)
            .creating
            .is_some_and(|owner| owner != index)
            && !matches!(r.orig_rax, 60 | 231 | 62)
        {
            self.task_mut(index).blocked = Some(original);
            audit_write(b"park surface=descriptor-snapshot\n");
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
                    if r.r10 & 3 == 0 || r.r10 & 3 != 2 && r.rdx & 2 != 0 {
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
                    let backing = match self.objects.filesystem.mapping_reference(handle) {
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
                        self.table(index).native_descriptor_set(),
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
                let flags = r.rdi;
                let libc_fork = r.orig_rax == 56 && flags == 0x1200011;
                let thread = r.orig_rax == 56 && matches!(flags, 0x3d0f00 | 0x7d0f00);
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
                    self.task_mut(index).blocked = Some(original);
                    audit_write(b"park surface=descriptor-snapshot\n");
                    return;
                }
                if thread {
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
                    let cwd = match self.group(index).cwd {
                        Some(fd) => match self.objects.filesystem.copy_cwd(fd) {
                            Ok(fd) => Some(fd),
                            Err(error) => {
                                if let Some(image) = image {
                                    if self.objects.filesystem.release_executable(image).is_err() {
                                        self.fail(
                                            instance,
                                            b"cwd-limited fork image rollback failed",
                                        );
                                    }
                                }
                                if let Err(reason) = table.release_exited(&mut self.objects) {
                                    self.fail(instance, reason);
                                }
                                if self.processes.cancel_fork(id, child).is_err() {
                                    self.fail(instance, b"cwd-limited fork rollback failed");
                                }
                                self.emulate(index, r, error, instance);
                                return;
                            }
                        },
                        None => None,
                    };
                    self.groups[group] = Some(DescriptorGroup {
                        table,
                        owners: 1,
                        leader: child,
                        status: None,
                        creating: None,
                        image,
                        cwd,
                        creation_mask: self.group(index).creation_mask,
                    });
                    self.group_mut(index).creating = Some(index);
                    group
                };
                self.tasks[slot] = Some(Task {
                    id: child,
                    host: 0,
                    alive: true,
                    adopted_reaped: false,
                    wait_status: None,
                    group,
                    call: DescriptorCall::new(),
                    image_chdir: None,
                    pending: Pending::None,
                    override_result: None,
                    blocked: None,
                    sequence: 0,
                    exec: None,
                    mapping: None,
                    path_rewrite: None,
                    waiter: None,
                });
                self.task_mut(index).pending = Pending::Fork {
                    child: slot,
                    flags,
                    child_tid: libc_fork.then_some(r.r10),
                    parent_tid: thread.then_some(r.rdx),
                };
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
            let task = self.tasks[index].as_mut().unwrap();
            decide_launch(
                task.host,
                r,
                &mut self.groups[group].as_mut().unwrap().table,
                &mut self.objects,
                &mut task.call,
            )
        };
        let decision = match decision {
            NativeDecision::Contract(decision) => {
                match crate::path_hooks::Rewrite::prepare(
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
                }
            }
            decision => decision,
        };
        match decision {
            NativeDecision::ParkPoll => {
                self.task_mut(index).blocked = Some(original);
                audit_write(b"park surface=owned-poll\n");
            }
            NativeDecision::Park { fd, progressed } => {
                self.wake_needed |= progressed;
                self.task_mut(index).blocked = Some(original);
                audit_write(b"park\nginux: park surface=lane-channel fd=");
                audit_u64(fd as u64);
                audit_write(b"\n");
            }
            NativeDecision::Hooked { result, .. } => {
                self.wake_needed = true;
                self.emulate(index, r, result, instance)
            }
            NativeDecision::Contract(decision) => match decision.action {
                Action::Emulate if matches!(original.orig_rax, 60 | 231) => {
                    audit_write(b"emulate result=instance-stop\n");
                    self.run(index, r, instance)
                }
                Action::Emulate => self.emulate(
                    index,
                    r,
                    balanced_identity_result(original.orig_rax).unwrap_or(0),
                    instance,
                ),
                Action::Mediate if native_arguments_allowed(r.orig_rax, r) => {
                    audit_write(b"mediate surface=");
                    audit_write(balanced_surface_name(balanced_surface(r.orig_rax)));
                    audit_write(b"\n");
                    self.run(index, r, instance)
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

    fn birth(&mut self, parent: usize, instance: &mut Instance) {
        let Pending::Fork {
            child: slot,
            flags,
            child_tid,
            parent_tid,
        } = self.task(parent).pending
        else {
            self.fail(instance, b"unreserved child event")
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
            self.fail(instance, b"child event identity missing")
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
                self.fail(instance, b"child birth stop missing")
            }
        }
        if ptrace(PTRACE_SETOPTIONS, host, 0, OPTIONS) < 0 {
            self.fail(instance, b"child supervision setup failed")
        }
        if let Some(address) = child_tid {
            match crate::tracee_io::store_u32(host, address, self.task(slot).id.pid) {
                Ok(()) | Err(-14) => {}
                Err(_) => self.fail(instance, b"child tid rollback failed"),
            }
            let mut registers = self.registers(slot, instance);
            registers.rdi = flags;
            if ptrace(PTRACE_SETREGS, host, 0, &registers as *const _ as usize) < 0 {
                self.fail(instance, b"child clone argument restoration failed");
            }
        }
        if let Some(address) = parent_tid {
            if crate::tracee_io::store_u32(self.task(parent).host, address, self.task(slot).id.pid)
                .is_err()
            {
                self.fail(instance, b"thread identity copyout failed");
            }
            let mut registers = self.registers(slot, instance);
            registers.rdi = flags;
            if ptrace(PTRACE_SETREGS, host, 0, &registers as *const _ as usize) < 0 {
                self.fail(instance, b"thread birth register update failed");
            }
        }
        if self.group(parent).creating == Some(parent) {
            self.group_mut(parent).creating = None;
            self.wake_needed = true;
        }
        audit_write(b"ginux: task registered virtual-pid=");
        audit_u64(self.task(slot).id.pid as u64);
        audit_write(b"\n");
        self.resume(slot, 0, instance);
        self.resume(parent, 0, instance);
    }
    fn syscall_exit(&mut self, index: usize, r: &mut UserRegs, instance: &mut Instance) {
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
        let pending = self.task(index).pending;
        match pending {
            Pending::Fork {
                child,
                flags,
                parent_tid,
                ..
            } => {
                r.rdi = flags;
                if (r.rax as i64) < 0 {
                    if r.rax as i64 == -11 {
                        self.report_creation_failure(
                            b"ginux: native task creation returned EAGAIN",
                        );
                    }
                    self.release_group(child, instance);
                    let child_id = self.task(child).id;
                    let rollback = if parent_tid.is_some() {
                        self.processes.cancel_thread(self.task(index).id, child_id)
                    } else {
                        self.processes.cancel_fork(self.task(index).id, child_id)
                    };
                    if self.group(index).creating == Some(index) {
                        self.group_mut(index).creating = None;
                        self.wake_needed = true;
                    }
                    if rollback.is_err() {
                        self.fail(instance, b"fork rollback failed");
                    }
                    self.tasks[child] = None;
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
                if (r.rax as i64) > 0 || r.rax as i64 == -10 {
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
                    r.rax = id.pid as u64;
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
        self.run(index, r, instance);
    }
    fn replace_cwd(&mut self, index: usize, next: Option<i32>, instance: &mut Instance) {
        let old = core::mem::replace(&mut self.group_mut(index).cwd, next);
        if let Some(fd) = old {
            if self.objects.filesystem.close_cwd(fd).is_err() {
                self.fail(instance, b"cwd reference release failed");
            }
        }
    }

    fn wait_entry(&mut self, index: usize, r: &mut UserRegs, instance: &mut Instance) {
        let selector = r.rdi as i32;
        if selector != -1 && selector <= 0 || r.rdx & !1 != 0 || r.r10 != 0 {
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
                        self.task_mut(index).blocked = Some(*r);
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
                    self.task_mut(index).blocked = Some(*r);
                    audit_write(b"park surface=owned-child-wait\n");
                }
            }
            Err(_) => self.fail(instance, b"invalid virtual wait state"),
        }
    }
    fn wake(&mut self, instance: &mut Instance) {
        // Object operations, observed deaths and readiness ticks retry parked calls.
        if !core::mem::replace(&mut self.wake_needed, false) {
            return;
        }
        for index in 0..TASKS {
            let Some(mut r) = self.tasks[index].as_mut().and_then(|t| t.blocked.take()) else {
                continue;
            };
            self.entry(index, &mut r, instance);
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
        if let Pending::Fork {
            child, parent_tid, ..
        } = self.task(index).pending
        {
            if self.task(child).host == 0 {
                self.release_group(child, instance);
                let reserved = self.task(child).id;
                let rollback = if parent_tid.is_some() {
                    self.processes.cancel_thread(id, reserved)
                } else {
                    self.processes.cancel_fork(id, reserved)
                };
                if rollback.is_err() {
                    self.fail(instance, b"unpublished task rollback failed");
                }
                self.tasks[child] = None;
            }
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
        if let Err(reason) = self.tasks[index]
            .as_mut()
            .unwrap()
            .call
            .reset(&mut self.objects)
        {
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
            if let Err(reason) = task.call.reset(&mut self.objects) {
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
        let settled = control_closed.and(event_closed);
        let exported = settled.and_then(|_| {
            if export {
                self.objects.filesystem.export()
            } else {
                crate::storage_export::cancel()
            }
        });
        self.objects.filesystem.teardown();
        if let Err(reason) = exported {
            supervision_error(instance, reason);
        }
        line_stderr(b"ginux: teardown tasks=0 owned-handles=0");
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
