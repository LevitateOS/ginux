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
use ginux_domain::Domain;
use ginux_process::{Credentials, ProcessError, ProcessTable, TaskId, WaitTarget};
use ginux_vfs::Executable;

const TASKS: usize = 16;
const WALL: usize = 0x4000_0000;
// Linux x86-64: sys/ptrace and asm/unistd_64.h.
const OPTIONS: usize = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | 2 | 4 | 8 | 16;

#[derive(Clone, Copy)]
enum Pending {
    None,
    Fork {
        child: usize,
        flags: u64,
        parent_tid: Option<u64>,
        child_tid: Option<u64>,
    },
    Wait {
        child: usize,
        original: [u64; 7],
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
    wait_status: Option<i32>,
    group: usize,
    call: DescriptorCall,
    pending: Pending,
    override_result: Option<i64>,
    blocked: Option<UserRegs>,
    sequence: u64,
    exec: Option<Exec>,
    mapping: Option<crate::file_mapping::MappingCall>,
    waiter: Option<usize>,
}

struct DescriptorGroup {
    table: DescriptorTable,
    owners: usize,
    leader: TaskId,
    status: Option<i32>,
    creating: Option<usize>,
    image: Option<Executable>,
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
    root_status: Option<i32>,
    tearing_down: bool,
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

fn wait_events(signal_fd: usize, timer: bool) -> Result<(), &'static [u8]> {
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
    // Owned finite polls need a millisecond tick; otherwise either descriptor
    // wakes us immediately, including control requests while all tasks sleep.
    let result = unsafe {
        syscall3(
            7,
            fds.as_mut_ptr() as usize,
            fds.len(),
            if timer { 1 } else { usize::MAX },
        )
    };
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
        groups: core::array::from_fn(|_| None),
        processes,
        objects,
        unknown_stops: [0; TASKS],
        retired: [(0, 0); TASKS],
        retired_next: 0,
        sequence: 0,
        wake_needed: false,
        root_status: None,
        tearing_down: false,
    };
    s.groups[0] = Some(DescriptorGroup {
        table: descriptors,
        owners: 1,
        leader: id,
        status: None,
        creating: None,
        image: None,
    });
    s.tasks[0] = Some(Task {
        id,
        host: root,
        alive: true,
        wait_status: None,
        group: 0,
        call: DescriptorCall::new(),
        pending: Pending::None,
        override_result: None,
        blocked: None,
        sequence: 0,
        exec: None,
        mapping: None,
        waiter: None,
    });
    if ptrace(PTRACE_SETOPTIONS, root, 0, OPTIONS) < 0 {
        s.fail(domain, b"launch ptrace setup failed");
    }
    line_stderr(b"ginux: launch backend=ptrace-native profile=balanced elf-loader=host");
    line_stderr(b"ginux: launch tracee-uid=1000 tracee-gid=1000 root=host-path-read-only");
    let signal_fd = task_events().unwrap_or_else(|reason| s.fail(domain, reason));
    s.resume(0, 0, domain);
    let mut poll_tick = 0;
    loop {
        // No owned mutation can interleave with snapshot serialization here.
        // Native mappings only hold readonly backing references.
        if let Err(reason) = crate::checkpoint_control::poll(s.objects.filesystem) {
            s.fail(domain, reason);
        }
        let polling = s
            .tasks
            .iter()
            .flatten()
            .any(|t| t.blocked.is_some() && t.call.needs_poll_tick());
        if polling {
            let now = crate::descriptors::monotonic_nanoseconds()
                .unwrap_or_else(|_| s.fail(domain, b"readiness clock failed"))
                / 1_000_000;
            if now != poll_tick {
                poll_tick = now;
                s.wake_needed = true;
            }
        }
        s.wake(domain);
        status = 0;
        let host = unsafe {
            syscall4(
                SYS_WAIT4,
                usize::MAX,
                &mut status as *mut _ as usize,
                WALL | 1, // WNOHANG; private event descriptors provide the blocking wait.
                0,
            )
        };
        if host == -4 {
            continue;
        }
        if host == 0 {
            if let Err(reason) = wait_events(signal_fd, polling) {
                s.fail(domain, reason);
            }
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
            if let Some(status) = s.root_status {
                s.teardown(domain, status == 0);
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
        let mut r = match s.read_registers(index) {
            Ok(registers) => registers,
            Err(-3) => continue, // Keep the task until its actual wait status arrives.
            Err(_) => s.fail(domain, b"launch register read failed"),
        };
        let mut info = [0u64; 11];
        let info_length = ptrace(
            0x420e,
            host,
            core::mem::size_of_val(&info),
            info.as_mut_ptr() as usize,
        );
        if info_length == -3 {
            // A peer's exit_group or SIGKILL can invalidate this ptrace stop
            // after GETREGS. Preserve ownership until wait4 reports its death.
            continue;
        }
        if info_length < 24 || (info[0] >> 32) as u32 != 0xc000003e {
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
    fn table(&self, index: usize) -> &DescriptorTable {
        &self.groups[self.task(index).group].as_ref().unwrap().table
    }
    fn release_group(
        &mut self,
        index: usize,
        domain: &mut Domain,
    ) -> Option<(TaskId, Option<i32>)> {
        let group = self.task(index).group;
        self.groups[group].as_mut().unwrap().owners -= 1;
        if self.groups[group].as_ref().unwrap().owners == 0 {
            let owner = self.groups[group].as_ref().unwrap();
            let result = (owner.leader, owner.status);
            if let Err(reason) = self.groups[group]
                .as_mut()
                .unwrap()
                .table
                .release_exited(&mut self.objects)
            {
                self.fail(domain, reason);
            }
            if let Some(image) = self.groups[group].as_mut().unwrap().image.take() {
                if self.objects.filesystem.release_executable(image).is_err() {
                    self.fail(domain, b"process executable release failed");
                }
            }
            self.groups[group] = None;
            return Some(result);
        }
        None
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
    fn registers(&mut self, index: usize, domain: &mut Domain) -> UserRegs {
        self.read_registers(index)
            .unwrap_or_else(|_| self.fail(domain, b"launch register read failed"))
    }
    fn resume(&mut self, index: usize, signal: usize, domain: &mut Domain) {
        let result = ptrace(PTRACE_SYSCALL, self.task(index).host, 0, signal);
        if result == -3 {
            // SIGKILL can end a ptrace stop between an object retry and
            // resume. Keep ownership until wait4 supplies the actual death.
            self.task_mut(index).blocked = None;
        } else if result < 0 {
            self.fail(domain, b"launch task resume failed")
        }
    }
    fn run(&mut self, index: usize, r: &UserRegs, domain: &mut Domain) {
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
        if let Some(mapping) = &self.task(index).mapping {
            match mapping.entry(r) {
                Ok(next) => self.run(index, &next, domain),
                Err(reason) => self.fail(domain, reason),
            }
            return;
        }
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
                                domain,
                                b"script descriptor retirement requires a syscall instruction",
                            );
                        }
                        let state = self.task_mut(index).exec.as_mut().unwrap();
                        state.original = *r;
                        state.stage = ExecStage::Retire;
                        r.orig_rax = 3;
                        r.rax = 3;
                        r.rdi = fd as u64;
                        self.run(index, r, domain);
                        return;
                    }
                    self.task_mut(index).exec = None;
                }
                ExecStage::RetireReenter => {
                    if r.orig_rax != exec.original.orig_rax || r.rip != exec.original.rip {
                        self.fail(
                            domain,
                            b"script descriptor retirement replay left its syscall instruction",
                        );
                    }
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
        let parent_group = self.task(index).group;
        if self.groups[parent_group]
            .as_ref()
            .unwrap()
            .creating
            .is_some_and(|owner| owner != index)
            && !matches!(r.orig_rax, 60 | 231 | 62)
        {
            self.task_mut(index).blocked = Some(original);
            audit_write(b"park surface=descriptor-snapshot\n");
            return;
        }
        if r.orig_rax == 9 && r.r10 & 0x20 == 0 {
            match self.table(index).mapping_file(r.r8) {
                Ok(Some(handle)) => {
                    if r.r10 & 3 == 0 || r.r10 & 3 != 2 && r.rdx & 2 != 0 {
                        self.emulate(index, r, -95, domain);
                        return;
                    }
                    if r.rsi == 0 || r.r9 & 4095 != 0 {
                        self.emulate(index, r, -22, domain);
                        return;
                    }
                    if self
                        .tasks
                        .iter()
                        .flatten()
                        .any(|task| task.group == parent_group && task.call.native_mutation())
                    {
                        self.task_mut(index).blocked = Some(original);
                        audit_write(b"park surface=mapping-descriptors\n");
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
                            self.emulate(index, r, -22, domain);
                            return;
                        };
                        if r.rdi < r.rsp.saturating_sub(256) && end > r.rsp.saturating_sub(512)
                            || r.rdi < r.rip && end > r.rip.saturating_sub(2)
                        {
                            self.emulate(index, r, -95, domain);
                            return;
                        }
                    }
                    let backing = match self.objects.filesystem.mapping_reference(handle) {
                        Ok(fd) => fd,
                        Err(error) => {
                            self.emulate(index, r, error, domain);
                            return;
                        }
                    };
                    self.groups[parent_group].as_mut().unwrap().creating = Some(index);
                    let mapping = match crate::file_mapping::MappingCall::new(
                        self.task(index).host,
                        original,
                        backing,
                        self.table(index).native_descriptor_set(),
                    ) {
                        Ok(mapping) => mapping,
                        Err(reason) => self.fail(domain, reason),
                    };
                    let next = match mapping.entry(r) {
                        Ok(next) => next,
                        Err(reason) => self.fail(domain, reason),
                    };
                    self.task_mut(index).mapping = Some(mapping);
                    audit_write(b"mediate surface=owned-file-mapping\n");
                    self.run(index, &next, domain);
                    return;
                }
                Err(error) => {
                    self.emulate(index, r, error, domain);
                    return;
                }
                Ok(None) => {}
            }
        }
        match r.orig_rax {
            89 | 267 => {
                let host = self.task(index).host;
                let (address, output, size, dirfd) = if r.orig_rax == 89 {
                    (r.rdi, r.rsi, r.rdx, (-100i64) as u64)
                } else {
                    (r.rsi, r.rdx, r.r10, r.rdi)
                };
                let path = self.objects.filesystem.path(host, address, dirfd);
                if path.as_ref().is_ok_and(|p| {
                    matches!(p.as_bytes(), b"/proc/self/exe" | b"/proc/thread-self/exe")
                }) {
                    let result = (|| {
                        if size == 0 {
                            return Err(-22);
                        }
                        let name =
                            crate::tracee_io::image_link(host, b"/exe").or_else(|error| {
                                self.groups[parent_group]
                                    .as_ref()
                                    .unwrap()
                                    .image
                                    .ok_or(error)
                                    .and_then(|image| {
                                        self.objects.filesystem.executable_name(image)
                                    })
                            })?;
                        let mut bytes = [0u8; ginux_vfs::MAX_PATH];
                        let count = name.as_bytes().len().min(size as usize);
                        bytes[..count].copy_from_slice(&name.as_bytes()[..count]);
                        if copy_memory(host, output, &mut bytes[..count], true)? != count as i64 {
                            return Err(-14);
                        }
                        Ok(count as i64)
                    })()
                    .unwrap_or_else(|error| error);
                    self.emulate(index, r, result, domain);
                    return;
                }
            }
            80 => {
                match self
                    .objects
                    .filesystem
                    .image_chdir(self.task(index).host, r.rdi)
                {
                    Ok(()) => {
                        audit_write(b"mediate surface=image-cwd\n");
                        self.run(index, r, domain);
                    }
                    Err(error) => self.emulate(index, r, error, domain),
                }
                return;
            }
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
            202 => {
                let operation = r.rsi & 0x7f;
                // PI futexes let the kernel publish its native owner TID.
                // Ordinary wait/wake/requeue operate on caller-owned values.
                if r.rsi & !0x1ff != 0
                    || !matches!(operation, 0 | 1 | 3 | 4 | 5 | 9 | 10)
                    || r.rsi & 0x100 != 0 && operation != 9
                {
                    self.emulate(index, r, -95, domain);
                    return;
                }
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
                let value = if r.orig_rax == 39 {
                    self.processes.view(id).unwrap().tgid
                } else {
                    id.pid
                };
                self.emulate(index, r, value as i64, domain);
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
                let flags = r.rdi;
                let thread = r.orig_rax == 56 && flags == 0x3d0f00;
                let libc_fork = r.orig_rax == 56 && flags == 0x1200011;
                if r.orig_rax == 56 && !thread && !matches!(flags, 17 | 0x4111 | 0x1200011) {
                    self.emulate(index, r, -38, domain);
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
                    // Suppress kernel PARENT_SETTID copyout, which would expose
                    // a native TID to peers sharing memory. Publish the virtual
                    // TID at the confirmed birth stop before parent/child run.
                    let mut before = [0u8; 4];
                    if copy_memory(self.task(index).host, r.rdx, &mut before, false) != Ok(4)
                        || copy_memory(self.task(index).host, r.rdx, &mut before, true) != Ok(4)
                    {
                        self.emulate(index, r, -14, domain);
                        return;
                    }
                }
                let Some(slot) = self.tasks.iter().position(|t| t.is_none()) else {
                    self.emulate(index, r, -11, domain);
                    return;
                };
                let child = match if thread {
                    self.processes.clone_thread(id)
                } else {
                    self.processes.fork(id)
                } {
                    Ok(id) => id,
                    Err(_) => {
                        self.emulate(index, r, -11, domain);
                        return;
                    }
                };
                let group = if thread {
                    self.groups[parent_group].as_mut().unwrap().owners += 1;
                    parent_group
                } else {
                    let group = self.groups.iter().position(|g| g.is_none()).unwrap();
                    let table = match self.groups[parent_group]
                        .as_ref()
                        .unwrap()
                        .table
                        .fork_copy(self.objects.refs)
                    {
                        Ok(table) => table,
                        Err(reason) => self.fail(domain, reason),
                    };
                    let image = self.groups[parent_group].as_ref().unwrap().image;
                    if let Some(image) = image {
                        if self.objects.filesystem.retain_executable(image).is_err() {
                            self.fail(domain, b"fork executable retain failed");
                        }
                    }
                    self.groups[group] = Some(DescriptorGroup {
                        table,
                        owners: 1,
                        leader: child,
                        status: None,
                        creating: None,
                        image,
                    });
                    self.groups[parent_group].as_mut().unwrap().creating = Some(index);
                    group
                };
                self.tasks[slot] = Some(Task {
                    id: child,
                    host: 0,
                    alive: true,
                    wait_status: None,
                    group,
                    call: DescriptorCall::new(),
                    pending: Pending::None,
                    override_result: None,
                    blocked: None,
                    sequence: 0,
                    exec: None,
                    mapping: None,
                    waiter: None,
                });
                self.task_mut(index).pending = Pending::Fork {
                    child: slot,
                    flags,
                    parent_tid: thread.then_some(r.rdx),
                    child_tid: libc_fork.then_some(r.r10),
                };
                if thread {
                    r.rdi &= !0x100000;
                }
                if libc_fork {
                    // Keep CHILD_CLEARTID, but suppress the native child TID
                    // copyout. Publish virtual identity at the birth barrier.
                    r.rdi &= !0x1000000;
                }
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
                let found =
                    self.tasks
                        .iter()
                        .flatten()
                        .find(|t| {
                            t.id.pid == target as u32
                                && t.host != 0
                                && self.processes.view(t.id).is_ok_and(|v| {
                                    matches!(v.state, ginux_process::TaskState::Running)
                                })
                        })
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
        match decision {
            NativeDecision::ParkPoll => {
                self.task_mut(index).blocked = Some(original);
                audit_write(b"park surface=owned-poll\n");
            }
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
        let group = self.task(index).group;
        if self.groups[group].as_ref().unwrap().owners != 1
            || self.task(index).id != self.groups[group].as_ref().unwrap().leader
        {
            return Err(-95);
        }
        let host = self.task(index).host;
        let mut instruction = [0u8; 2];
        let address = r.rip.checked_sub(2).ok_or(-95)?;
        if copy_memory(host, address, &mut instruction, false) != Ok(2)
            || instruction != [0x0f, 0x05]
        {
            return Err(-95);
        }
        let mut native_dirfd = r.rdi;
        let (image, empty_path) = if r.orig_rax == 59 {
            let path = crate::tracee_io::read_path(host, r.rdi)?;
            let image = self
                .objects
                .filesystem
                .exec_path(host, r.rdi, (-100i64) as u64)?;
            (image, r.rdi + path.as_bytes().len() as u64)
        } else {
            if r.r8 & !0x1100 != 0 {
                return Err(-22);
            }
            let path = crate::tracee_io::read_path(host, r.rsi)?;
            let image = if path.is_empty() {
                if r.r8 & 0x1000 == 0 {
                    return Err(-2);
                }
                match self.table(index).exec_descriptor(r.rdi)? {
                    ExecDescriptor::Native(fd) => {
                        native_dirfd = fd as u64;
                        None
                    }
                    ExecDescriptor::Owned(handle) => {
                        Some(self.objects.filesystem.exec_descriptor(handle)?)
                    }
                }
            } else {
                let dirfd = self.table(index).exec_path_dirfd(host, r.rdi, r.rsi)?;
                native_dirfd = (-100i64) as u64;
                self.objects.filesystem.exec_path(host, r.rsi, dirfd)?
            };
            (image, r.rsi + path.as_bytes().len() as u64)
        };
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

    fn exec_step(&mut self, index: usize, r: &mut UserRegs, domain: &mut Domain) {
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
                        self.exec_step(index, r, domain);
                        return;
                    }
                    self.finish_exec_failure(index, r, -14, domain);
                    self.emulate(index, r, -14, domain);
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
        self.run(index, r, domain);
    }

    fn replay_exec(&mut self, index: usize, domain: &mut Domain) {
        let mut replay = self.task(index).exec.unwrap().original;
        replay.rip -= 2;
        replay.rax = replay.orig_rax;
        self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::Reenter;
        self.run(index, &replay, domain);
    }

    fn finish_exec_failure(
        &mut self,
        index: usize,
        r: &mut UserRegs,
        error: i64,
        domain: &mut Domain,
    ) {
        let exec = self.task_mut(index).exec.take().unwrap();
        if let Some(owned) = exec.owned {
            if owned
                .script
                .is_some_and(|script| script.release_held(self.objects.filesystem).is_err())
            {
                self.fail(domain, b"interpreter reference release failed");
            }
            if self
                .objects
                .filesystem
                .release_executable(owned.image)
                .is_err()
            {
                self.fail(domain, b"failed exec reference release failed");
            }
        }
        *r = exec.original;
        r.rax = error as u64;
    }

    fn exec_completed(&mut self, index: usize, domain: &mut Domain) {
        if !self
            .task(index)
            .exec
            .is_some_and(|e| e.stage == ExecStage::Kernel)
        {
            self.fail(domain, b"unreserved exec transition");
        }
        let group = self.task(index).group;
        let result = self.groups[group]
            .as_mut()
            .unwrap()
            .table
            .exec_completed(&mut self.objects);
        if let Err(reason) = result {
            self.fail(domain, reason);
        }
        if self.processes.exec(self.task(index).id).is_err() {
            self.fail(domain, b"virtual exec transition failed");
        }
        let owned = self.task(index).exec.as_ref().unwrap().owned;
        let image = if let Some(owned) = owned {
            if let Some(script) = owned.script {
                let mut r = self.registers(index, domain);
                let fd = owned.descriptor.unwrap();
                if script.restore(self.task(index).host, fd, &mut r).is_err() {
                    // The kernel has replaced the mm. Returning a fabricated
                    // exec errno here would resume the wrong address space.
                    self.fail(domain, b"new script stack restoration failed");
                }
                if ptrace(
                    PTRACE_SETREGS,
                    self.task(index).host,
                    0,
                    &r as *const _ as usize,
                ) < 0
                {
                    self.fail(domain, b"new script stack register update failed");
                }
                self.task_mut(index).exec.as_mut().unwrap().owned = None;
                if script.release_held(self.objects.filesystem).is_err() {
                    self.fail(domain, b"committed interpreter references release failed");
                }
                if script.kernel_script {
                    self.task_mut(index).exec.as_mut().unwrap().retire = Some(fd);
                    if self
                        .objects
                        .filesystem
                        .release_executable(owned.image)
                        .is_err()
                    {
                        self.fail(domain, b"committed script reference release failed");
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
        let old = core::mem::replace(&mut self.groups[group].as_mut().unwrap().image, image);
        if let Some(old) = old {
            if self.objects.filesystem.release_executable(old).is_err() {
                self.fail(domain, b"replaced executable release failed");
            }
        }
        self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::Completed;
        self.wake_needed = true;
        audit_write(b"ginux: task exec virtual-pid=");
        audit_u64(self.task(index).id.pid as u64);
        audit_write(b"\n");
        self.resume(index, 0, domain);
    }

    fn birth(&mut self, parent: usize, domain: &mut Domain) {
        let Pending::Fork {
            child: slot,
            flags,
            parent_tid,
            child_tid,
        } = self.task(parent).pending
        else {
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
        if let Some(address) = parent_tid {
            let mut virtual_tid = self.task(slot).id.pid.to_ne_bytes();
            if copy_memory(self.task(parent).host, address, &mut virtual_tid, true) != Ok(4) {
                self.fail(domain, b"thread identity copyout failed");
            }
        }
        if let Some(address) = child_tid {
            let mut virtual_tid = self.task(slot).id.pid.to_ne_bytes();
            // Linux ignores a failed CHILD_SETTID put_user, unlike the parent
            // copyout. Never force a write through readonly guest memory.
            let _ = copy_memory(host, address, &mut virtual_tid, true);
        }
        if parent_tid.is_some() || child_tid.is_some() {
            let mut child_regs = self.registers(slot, domain);
            child_regs.rdi = flags;
            if ptrace(PTRACE_SETREGS, host, 0, &child_regs as *const _ as usize) < 0 {
                self.fail(domain, b"thread birth register update failed");
            }
        }
        let group = self.task(parent).group;
        if self.groups[group].as_ref().unwrap().creating == Some(parent) {
            self.groups[group].as_mut().unwrap().creating = None;
            self.wake_needed = true;
        }
        audit_write(b"ginux: task registered virtual-pid=");
        audit_u64(self.task(slot).id.pid as u64);
        audit_write(b"\n");
        self.resume(slot, 0, domain);
        self.resume(parent, 0, domain);
    }
    fn syscall_exit(&mut self, index: usize, r: &mut UserRegs, domain: &mut Domain) {
        if let Some(mut mapping) = self.task_mut(index).mapping.take() {
            match mapping.exit(self.task(index).host, r) {
                Ok(crate::file_mapping::Progress::Run(next)) => {
                    self.task_mut(index).mapping = Some(mapping);
                    self.run(index, &next, domain);
                }
                Ok(crate::file_mapping::Progress::Done(next)) => {
                    let group = self.task(index).group;
                    self.groups[group].as_mut().unwrap().creating = None;
                    self.wake_needed = true;
                    self.run(index, &next, domain);
                }
                Err(reason) => self.fail(domain, reason),
            }
            return;
        }
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
                ExecStage::Create => {
                    if r.orig_rax != 319 {
                        self.fail(domain, b"exec private descriptor creation lost its syscall");
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
                        self.replay_exec(index, domain);
                        return;
                    }
                    if (r.rax as i64) < 0 {
                        self.finish_exec_failure(index, r, r.rax as i64, domain);
                    } else {
                        if r.rax >= crate::descriptors::LIMIT as u64 {
                            self.fail(domain, b"exec private descriptor outside table bound");
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
                        self.replay_exec(index, domain);
                        return;
                    }
                }
                ExecStage::Close => {
                    if r.orig_rax != 3 || r.rax != 0 {
                        self.fail(domain, b"exec private descriptor close failed");
                    }
                    self.finish_exec_failure(
                        index,
                        r,
                        exec.owned.unwrap().failure.unwrap(),
                        domain,
                    );
                }
                ExecStage::Kernel => {
                    if r.rax as i64 >= 0 {
                        self.fail(domain, b"exec success missing its ownership event");
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
                        self.replay_exec(index, domain);
                        return;
                    }
                    let error = r.rax as i64;
                    self.finish_exec_failure(index, r, error, domain);
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
                        self.fail(domain, b"script private descriptor close failed");
                    }
                    let mut replay = exec.original;
                    replay.rip -= 2;
                    replay.rax = replay.orig_rax;
                    self.task_mut(index).exec.as_mut().unwrap().stage = ExecStage::RetireReenter;
                    self.run(index, &replay, domain);
                    return;
                }
                ExecStage::Reenter | ExecStage::RetireReenter => {
                    self.fail(domain, b"unexpected exit during exec replay")
                }
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
                    self.release_group(child, domain);
                    let child_id = self.task(child).id;
                    let rollback = if parent_tid.is_some() {
                        self.processes.cancel_thread(self.task(index).id, child_id)
                    } else {
                        self.processes.cancel_fork(self.task(index).id, child_id)
                    };
                    let group = self.task(index).group;
                    if self.groups[group].as_ref().unwrap().creating == Some(index) {
                        self.groups[group].as_mut().unwrap().creating = None;
                        self.wake_needed = true;
                    }
                    if rollback.is_err() {
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
                        .wait(self.task(index).id, WaitTarget::Specific(id.pid), 0)
                        .is_err()
                    {
                        self.fail(domain, b"virtual child reap failed")
                    }
                    self.retired[self.retired_next] = (self.task(child).host, id.pid);
                    self.retired_next = (self.retired_next + 1) % TASKS;
                    self.tasks[child] = None;
                    r.rax = id.pid as u64;
                } else {
                    self.task_mut(child).waiter = None;
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
        if let Some(result) = self.task_mut(index).override_result.take() {
            r.rax = result as u64;
        }
        let group = self.task(index).group;
        let task = self.tasks[index].as_mut().unwrap();
        match task.call.finish(
            &mut self.groups[group].as_mut().unwrap().table,
            r,
            &mut self.objects,
        ) {
            Ok(changed) => self.wake_needed |= changed,
            Err(reason) => self.fail(domain, reason),
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
        match self.processes.peek_wait(
            parent,
            selected.map_or(WaitTarget::Any, WaitTarget::Specific),
        ) {
            Ok(result) => {
                let child = self
                    .tasks
                    .iter()
                    .position(|t| t.as_ref().is_some_and(|t| t.id == result.child))
                    .unwrap();
                if self.task(child).waiter.is_some() {
                    if r.rdx & 1 != 0 {
                        self.emulate(index, r, 0, domain);
                    } else {
                        self.task_mut(index).blocked = Some(*r);
                        audit_write(b"park surface=owned-child-wait\n");
                    }
                    return;
                }
                if r.rsi != 0 {
                    let mut status = self
                        .task(child)
                        .wait_status
                        .expect("reportable child status")
                        .to_ne_bytes();
                    if copy_memory(self.task(index).host, r.rsi, &mut status, true) != Ok(4) {
                        self.emulate(index, r, -14, domain);
                        return;
                    }
                }
                let original = [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9, r.orig_rax];
                self.task_mut(child).waiter = Some(index);
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
                        v.parent == self.processes.view(parent).unwrap().tgid
                            && v.id.pid == v.tgid
                            && selected.is_none_or(|id| id == t.id.pid)
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
        // Object operations, observed deaths and readiness ticks retry parked
        // calls. Unrelated register/signal stops do not request a retry.
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
    fn record_death(&mut self, id: TaskId, status: i32) -> Result<(), ProcessError> {
        if status & 0x7f == 0 {
            self.processes.exit(id, (status >> 8) & 0xff)
        } else {
            self.processes.signaled(id, (status & 0x7f) as u8)
        }
    }

    fn died(&mut self, index: usize, status: i32, domain: &mut Domain) {
        self.wake_needed = true;
        if !self.task(index).alive {
            self.fail(domain, b"duplicate task death");
        }
        let id = self.task(index).id;
        let group = self.task(index).group;
        if let Some(owned) = self.task_mut(index).exec.take().and_then(|exec| exec.owned) {
            if owned
                .script
                .is_some_and(|script| script.release_held(self.objects.filesystem).is_err())
            {
                self.fail(domain, b"interpreter reference release failed");
            }
            if self
                .objects
                .filesystem
                .release_executable(owned.image)
                .is_err()
            {
                self.fail(domain, b"terminated exec reference release failed");
            }
        }
        if let Pending::Fork {
            child, parent_tid, ..
        } = self.task(index).pending
        {
            if self.task(child).host == 0 {
                self.release_group(child, domain);
                let reserved = self.task(child).id;
                let result = if parent_tid.is_some() {
                    self.processes.cancel_thread(id, reserved)
                } else {
                    self.processes.cancel_fork(id, reserved)
                };
                if result.is_err() {
                    self.fail(domain, b"unpublished task rollback failed");
                }
                self.tasks[child] = None;
            }
        }
        if self.groups[group].as_ref().unwrap().creating == Some(index) {
            self.groups[group].as_mut().unwrap().creating = None;
        }
        if let Pending::Wait { child, .. } = self.task(index).pending {
            if let Some(child) = self.tasks[child].as_mut() {
                child.waiter = None;
            }
        }
        self.task_mut(index).alive = false;
        let mapping_aborted = self.task_mut(index).mapping.take().is_some();
        self.task_mut(index).wait_status = Some(status);
        self.task_mut(index).blocked = None;
        if mapping_aborted && !self.tearing_down {
            self.fail(domain, b"task died during private mapping transaction");
        }
        if let Err(reason) = self.tasks[index]
            .as_mut()
            .unwrap()
            .call
            .reset(&mut self.objects)
        {
            self.fail(domain, reason);
        }
        if id == self.groups[group].as_ref().unwrap().leader {
            self.groups[group].as_mut().unwrap().status = Some(status);
        } else {
            if self.record_death(id, status).is_err() || self.processes.reap_thread(id).is_err() {
                self.fail(domain, b"virtual thread exit failed");
            }
        }
        if let Some((leader, status)) = self.release_group(index, domain) {
            let Some(status) = status else {
                self.fail(domain, b"process ended without leader status");
            };
            if self.record_death(leader, status).is_err() {
                self.fail(domain, b"virtual process exit failed");
            }
            if leader.pid == 1 {
                self.root_status = Some(status);
            }
        }
        audit_write(b"ginux: task exited virtual-pid=");
        audit_u64(id.pid as u64);
        audit_write(b"\n");
        if self.processes.view(id).is_err() {
            self.retired[self.retired_next] = (self.task(index).host, id.pid);
            self.retired_next = (self.retired_next + 1) % TASKS;
            self.tasks[index] = None;
        }
    }
    fn teardown(&mut self, domain: &mut Domain, export: bool) {
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
            if let Err(reason) = task.call.reset(&mut self.objects) {
                supervision_error(domain, reason);
            }
        }
        for group in self.groups.iter_mut().flatten() {
            if let Err(reason) = group.table.release_exited(&mut self.objects) {
                supervision_error(domain, reason);
            }
            if let Some(image) = group.image.take() {
                if self.objects.filesystem.release_executable(image).is_err() {
                    supervision_error(domain, b"teardown executable release failed");
                }
            }
        }
        self.processes.shutdown(137);
        self.processes.reap_all();
        if self.objects.refs.active() != 0 || self.processes.active() != 0 {
            supervision_error(domain, b"domain teardown retained owned state")
        }
        if export {
            if let Err(reason) = self.objects.filesystem.export() {
                supervision_error(domain, reason);
            }
        }
        self.objects.filesystem.teardown();
        line_stderr(b"ginux: teardown tasks=0 owned-handles=0");
    }
    fn fail(&mut self, domain: &mut Domain, reason: &[u8]) -> ! {
        self.teardown(domain, false);
        supervision_error(domain, reason)
    }
}

fn exited(status: i32) -> bool {
    status & 127 == 0
}
fn signaled(status: i32) -> bool {
    status & 127 != 0 && status & 127 != 127
}
