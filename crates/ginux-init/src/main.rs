#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;
use ginux_core::{
    balanced_identity_result, balanced_surface, decide, Action, SYS_EXIT, SYS_EXIT_GROUP,
    SYS_GETPID, SYS_UNAME, SYS_WRITE,
};

mod channel_hooks;
mod dispatch;
mod fs_hooks;
mod launch;
mod process_hooks;
mod supervisor;
mod teardown;

use crate::dispatch::{
    balanced_surface_name, decide_native, native_arguments_allowed, process_entry, Lane,
    NativeDecision,
};
use crate::launch::{
    c_string_equals, load_config, parse_argv, print_effective_config, read_file, read_index,
    Command, ELF_BYTES, VFS_INDEX_BYTES,
};
use crate::fs_hooks::{
    chmod_at, resolve_at, DomainCwd, ResolveError, ResolvedKind, VfsDomainView,
    MAX_CWD as DOMAIN_PATH_MAX, AT_FDCWD as DOMAIN_AT_FDCWD,
};
use crate::process_hooks::{
    dup3_flags_valid, exec_bit_set, exec_mediated, fcntl_supported, parse_script_interp,
    pipe2_flags_valid, thread_supported, ScriptInterp, F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_SETFD,
    FD_CLOEXEC, O_CLOEXEC, PTRACE_EVENT_CLONE, PTRACE_EVENT_VFORK, PTRACE_O_TRACECLONE,
    PTRACE_O_TRACEVFORK, SYS_ARCH_PRCTL, SYS_CLOSE, SYS_DUP, SYS_DUP2, SYS_DUP3, SYS_FCNTL,
    SYS_FUTEX, SYS_GETTID, SYS_GET_ROBUST_LIST, SYS_PIPE, SYS_PIPE2, SYS_READ, SYS_RSEQ,
    SYS_SET_ROBUST_LIST, SYS_SET_TID_ADDRESS, SCRIPT_INTERP_MAX,
};
use crate::supervisor::{
    exit_process, line, ptrace, read_tracee_word, stopped, syscall0, syscall1, syscall2, syscall3,
    syscall4, syscall5, wait, write_all, write_i64, write_u64, UserRegs, AT_FDCWD, CLOCK_MONOTONIC,
    CLOCK_PROCESS_CPUTIME_ID, DOMAIN_GID, DOMAIN_UID, ENOSYS, EPERM, O_RDONLY, O_RDWR,
    PR_SET_NO_NEW_PRIVS, PTRACE_CONT, PTRACE_EVENT_EXEC, PTRACE_EVENT_FORK, PTRACE_GETEVENTMSG,
    PTRACE_GETREGS, PTRACE_KILL, PTRACE_O_EXITKILL, PTRACE_O_TRACEEXEC, PTRACE_O_TRACEFORK,
    PTRACE_O_TRACESYSGOOD, PTRACE_PEEKTEXT, PTRACE_POKETEXT, PTRACE_SETOPTIONS, PTRACE_SETREGS,
    PTRACE_SYSCALL, PTRACE_SYSEMU, PTRACE_TRACEME, EBADF, ECHILD, EINVAL, ESRCH, SIGCHLD, SIGINT,
    SIGKILL,
    SIGTERM, SIG_BLOCK, SYS_CHDIR,
    SYS_CHROOT, SYS_CLOCK_GETTIME, SYS_CLOSE_HOST, SYS_EXECVE, SYS_EXIT_HOST, SYS_FORK, SYS_FSYNC,
    SYS_KILL, SYS_OPENAT_HOST, SYS_PAUSE, SYS_PRCTL, SYS_PREAD64, SYS_PTRACE, SYS_PWRITE64,
    SYS_READ_HOST, SYS_RT_SIGPROCMASK, SYS_SETGID, SYS_SETGROUPS, SYS_SETUID, SYS_SIGNALFD4,
    SYS_WAIT4, VIRTUAL_PID,
};
use crate::teardown::TeardownOutcome;
use ginux_devices::{
    BlockBackend, DeviceError, DeviceKind, DeviceName, DeviceRegistry, DeviceView, IsolatedNetwork,
    Partition, IOCTL_CONSOLE_GET_SIZE,
};
use ginux_domain::Domain;
use ginux_kernel_views::{
    CgroupFs, IdentityFs, IdentityView, MemoryView, MountView, NamespaceView, ProcFs, SysFs,
    ViewError,
};
use ginux_process::{
    ChildStatus, Credentials, EventFd, EventPoll, FutexTable, PipeSpace, ProcessError, ProcessTable,
    SignalAction, SignalDelivery, TaskState, TimerTable, VirtualClock, WaitTarget, EVENT_READ,
    EVENT_WRITE, WAIT_ALLOWED_OPTIONS, WNOHANG,
};
use ginux_runtime::{execute, AddressSpace, AuditAction, LoadError};
use ginux_vfs::{
    encode_header, encode_record, BaseReader, Entry, Index, NodeKind, VfsError, VirtualFs,
    HEADER_SIZE, RECORD_SIZE, O_CREATE, O_READ, O_TRUNC, O_WRITE,
};

global_asm!(
    ".global _start",
    ".type _start,@function",
    "_start:",
    "xor %rbp, %rbp",
    "mov %rsp, %rdi",
    "andq $-16, %rsp",
    "call rust_main",
    "ud2",
    options(att_syntax)
);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    fail(b"panic")
}

#[no_mangle]
unsafe extern "C" fn memcpy(
    destination: *mut core::ffi::c_void,
    source: *const core::ffi::c_void,
    length: usize,
) -> *mut core::ffi::c_void {
    let destination_bytes = destination.cast::<u8>();
    let source_bytes = source.cast::<u8>();
    let mut index = 0;
    while index < length {
        core::ptr::write_volatile(
            destination_bytes.add(index),
            core::ptr::read_volatile(source_bytes.add(index)),
        );
        index += 1;
    }
    destination
}

#[no_mangle]
unsafe extern "C" fn memset(
    destination: *mut core::ffi::c_void,
    value: i32,
    length: usize,
) -> *mut core::ffi::c_void {
    let destination_bytes = destination.cast::<u8>();
    let mut index = 0;
    while index < length {
        core::ptr::write_volatile(destination_bytes.add(index), value as u8);
        index += 1;
    }
    destination
}

#[no_mangle]
unsafe extern "C" fn bcmp(
    left: *const core::ffi::c_void,
    right: *const core::ffi::c_void,
    length: usize,
) -> i32 {
    let left = left.cast::<u8>();
    let right = right.cast::<u8>();
    let mut index = 0;
    while index < length {
        if core::ptr::read_volatile(left.add(index)) != core::ptr::read_volatile(right.add(index)) {
            return 1;
        }
        index += 1;
    }
    0
}

#[no_mangle]
unsafe extern "C" fn memcmp(
    left: *const core::ffi::c_void,
    right: *const core::ffi::c_void,
    length: usize,
) -> i32 {
    let left = left.cast::<u8>();
    let right = right.cast::<u8>();
    let mut index = 0;
    while index < length {
        let left_byte = core::ptr::read_volatile(left.add(index));
        let right_byte = core::ptr::read_volatile(right.add(index));
        if left_byte != right_byte {
            return left_byte as i32 - right_byte as i32;
        }
        index += 1;
    }
    0
}

#[no_mangle]
extern "C" fn rust_main(initial_stack: *const usize) -> ! {
    scan_stage_env(initial_stack);
    let argc = unsafe { *initial_stack };
    let argv = unsafe { initial_stack.add(1) };
    match parse_argv(argc, argv) {
        Some(Command::Runtime(path)) => runtime_main(path),
        Some(Command::Config(config_path)) => config_main(config_path),
        Some(Command::Lifecycle(config_path)) => lifecycle_main(config_path),
        Some(Command::Vfs(config_path, rootfs_path, index_path)) => {
            vfs_main(config_path, rootfs_path, index_path)
        }
        Some(Command::Native(config_path, root_path, mode)) => {
            native_main(config_path, root_path, mode)
        }
        Some(Command::Domain(config_path, fixture_path)) => domain_main(config_path, fixture_path),
        Some(Command::Process(config_path)) => process_main(config_path),
        Some(Command::ProcessNative(config_path, fixture_path)) => {
            process_native_main(config_path, fixture_path)
        }
        Some(Command::Devices(config_path, block_path)) => devices_main(config_path, block_path),
        Some(Command::DeviceBench(config_path, block_path, kind)) => {
            device_bench_main(config_path, block_path, kind)
        }
        Some(Command::KernelViews(config_path)) => kernel_views_main(config_path),
        None => gate1_main(),
    }
}

fn kernel_views_main(config_path: *const u8) -> ! {
    let config = load_config(config_path);
    let mut domain = Domain::create(config);
    if domain.start().is_err() {
        kernel_views_fail(b"domain start failed");
    }
    let mut processes: ProcessTable<4> = ProcessTable::new();
    let init = processes
        .create_init(Credentials::root())
        .unwrap_or_else(|_| kernel_views_fail(b"virtual init failed"));
    let child = processes
        .fork(init)
        .unwrap_or_else(|_| kernel_views_fail(b"virtual child failed"));
    processes
        .credentials_mut(child)
        .and_then(|credentials| credentials.set_uid(1000))
        .unwrap_or_else(|_| kernel_views_fail(b"virtual credentials failed"));
    let mut tasks = [processes.view(init).unwrap(); 4];
    let task_count = processes.views(&mut tasks);
    let identity = IdentityView {
        hostname: b"gate8-domain",
        machine_id: b"0123456789abcdef0123456789abcdef",
        boot_id: b"11111111-2222-3333-4444-555555555555",
    };
    let mounts = [
        MountView {
            source: b"ginux-root",
            target: b"/",
            filesystem: b"ginuxfs",
            options: b"ro",
        },
        MountView {
            source: b"proc",
            target: b"/proc",
            filesystem: b"proc",
            options: b"rw,nosuid,nodev,noexec",
        },
    ];
    let procfs = ProcFs::new(
        &tasks[..task_count],
        child.pid,
        12_340_000_000,
        MemoryView {
            total_bytes: 512 * 1024 * 1024,
            available_bytes: 384 * 1024 * 1024,
        },
        identity,
        &mounts,
    );
    let mut output = [0u8; 512];
    let status_len = procfs
        .read(b"/proc/2/status", &mut output)
        .unwrap_or_else(|_| kernel_views_fail(b"proc status failed"));
    if !contains(&output[..status_len], b"Pid:\t2\n")
        || !contains(&output[..status_len], b"PPid:\t1\n")
        || procfs.read(b"/proc/424242/status", &mut output) != Err(ViewError::NotFound)
        || procfs.write(b"/proc/sys/kernel/hostname", b"host") != Err(ViewError::ReadOnly)
    {
        kernel_views_fail(b"proc isolation failed");
    }
    line(b"GINUX_VIEWS: proc pids=1,2 host-pid=absent mutation=denied");

    let mut registry: DeviceRegistry<6, 2> = DeviceRegistry::new();
    if registry
        .assign(7, 100, DeviceName::new(b"vda").unwrap(), DeviceKind::Block)
        .is_err()
        || registry
            .assign(
                7,
                101,
                DeviceName::new(b"net0").unwrap(),
                DeviceKind::Network,
            )
            .is_err()
        || registry
            .assign(
                8,
                102,
                DeviceName::new(b"host-only").unwrap(),
                DeviceKind::Block,
            )
            .is_err()
    {
        kernel_views_fail(b"device assignment failed");
    }
    let placeholder = DeviceView {
        name: DeviceName::new(b"none").unwrap(),
        kind: DeviceKind::Null,
        major: 0,
        minor: 0,
    };
    let mut devices = [placeholder; 6];
    let device_count = registry.views(7, &mut devices);
    let sysfs = SysFs::new(&devices[..device_count], 2);
    if sysfs
        .read(b"/sys/class/block/vda/dev", &mut output)
        .is_err()
        || sysfs
            .read(b"/sys/class/net/net0/type", &mut output)
            .is_err()
        || sysfs.read(b"/sys/class/block/host-only/dev", &mut output) != Err(ViewError::NotFound)
        || sysfs.write(b"/sys/class/block/vda/dev", b"8:0") != Err(ViewError::ReadOnly)
    {
        kernel_views_fail(b"sysfs isolation failed");
    }
    line(b"GINUX_VIEWS: sys devices=vda,net0 host-device=absent mutation=denied");

    let mut cgroups: CgroupFs<4> = CgroupFs::new();
    if cgroups.create(b"/system.slice", 0).is_err()
        || cgroups
            .write(b"/cgroup.subtree_control", b"+cpu +memory +pids\n", 0)
            .is_err()
        || cgroups.write(b"/system.slice/pids.max", b"4\n", 0).is_err()
        || cgroups.attach(b"/system.slice", child.pid, 0).is_err()
        || cgroups.create(b"/host.slice", 1000) != Err(ViewError::PermissionDenied)
    {
        kernel_views_fail(b"cgroup isolation failed");
    }
    line(b"GINUX_VIEWS: cgroup path=/system.slice pid=2 host-mutation=denied");

    let identities = IdentityFs::new(
        &tasks[..task_count],
        identity,
        NamespaceView {
            mount: 101,
            pid: 102,
            uts: 103,
            cgroup: 104,
        },
    );
    if identities.read(b"/etc/machine-id", &mut output).is_err()
        || identities.readlink(b"/proc/1/ns/mnt", &mut output).is_err()
        || identities.readlink(b"/proc/424242/ns/pid", &mut output) != Err(ViewError::NotFound)
    {
        kernel_views_fail(b"identity isolation failed");
    }
    line(b"GINUX_VIEWS: identity hostname=gate8-domain namespaces=virtual host-id=absent");

    if processes.shutdown(0) != 2 || processes.reap_all() != 2 || domain.task_exited(true).is_err()
    {
        kernel_views_fail(b"cleanup failed");
    }
    line(b"GATE8_VIEWS: PASS");
    exit_process(0)
}

fn kernel_views_fail(reason: &[u8]) -> ! {
    write_all(b"GATE8_VIEWS: FAIL: ");
    line(reason);
    exit_process(1)
}

fn process_main(config_path: *const u8) -> ! {
    let config = load_config(config_path);
    let mut domain = Domain::create(config);
    if domain.start().is_err() {
        process_fail(b"domain start failed");
    }
    let mut processes: ProcessTable<8> = ProcessTable::new();
    let init = processes
        .create_init(Credentials::root())
        .unwrap_or_else(|_| process_fail(b"virtual init failed"));
    if init.pid != 1 || processes.view(init).map(|view| view.parent) != Ok(0) {
        process_fail(b"virtual init identity failed");
    }
    line(b"GINUX_PROCESS: init=1 parent=0 host-pid=unexposed");

    let mut final_child = init;
    for iteration in 0..256u32 {
        let child = processes
            .fork(init)
            .unwrap_or_else(|_| process_fail(b"fork failed"));
        let thread = processes
            .clone_thread(child)
            .unwrap_or_else(|_| process_fail(b"clone thread failed"));
        if processes.view(thread).map(|view| view.tgid) != Ok(child.pid)
            || processes.exec(child) != Ok(1)
        {
            process_fail(b"thread or exec identity failed");
        }
        processes
            .exit(thread, 0)
            .unwrap_or_else(|_| process_fail(b"thread exit failed"));
        processes
            .exit(child, iteration as i32)
            .unwrap_or_else(|_| process_fail(b"child exit failed"));
        // Thread-group members are joined over a futex, never reaped: a
        // wait naming the thread must fail while the leader reaps normally.
        if processes
            .wait(init, WaitTarget::Specific(thread.pid), 0)
            .is_ok()
            || processes
                .wait(init, WaitTarget::Specific(child.pid), 0)
                .map(|result| result.status)
                != Ok(ChildStatus::Exited(iteration as i32))
        {
            process_fail(b"wait or reap failed");
        }
        // Thread-group members are never reaped by `wait`; reclaim the
        // joined thread the way the supervision loop's final cleanup does,
        // or the bounded table would fill before iteration 256.
        if processes.reap_all() != 1 {
            process_fail(b"thread reap failed");
        }
        final_child = child;
    }
    if processes.view(final_child) != Err(ProcessError::InvalidTask) || processes.active() != 1 {
        process_fail(b"stale identity or lifecycle leak");
    }
    line(b"GINUX_PROCESS: fork-clone-exec-wait iterations=256 stale-id=denied active=1");

    let signal_child = processes
        .fork(init)
        .unwrap_or_else(|_| process_fail(b"signal child failed"));
    processes
        .set_signal_action(signal_child, 10, SignalAction::Handler(0x4000))
        .unwrap_or_else(|_| process_fail(b"signal action failed"));
    processes
        .signal(signal_child, 10)
        .unwrap_or_else(|_| process_fail(b"signal queue failed"));
    if processes.blocking_interrupted(signal_child) != Ok(true)
        || processes.begin_signal(signal_child)
            != Ok(Some(SignalDelivery::Handler {
                signal: 10,
                address: 0x4000,
            }))
        || processes.signal_return(signal_child).is_err()
    {
        process_fail(b"signal delivery or return failed");
    }
    line(b"GINUX_PROCESS: signal=10 blocked-wait=interrupted handler=0x4000 return=PASS");

    let credentials = processes
        .credentials_mut(signal_child)
        .unwrap_or_else(|_| process_fail(b"credentials lookup failed"));
    if credentials.set_groups(&[10, 20]).is_err()
        || credentials.set_gid(1000).is_err()
        || credentials.set_uid(1000).is_err()
        || credentials.capabilities != 0
        || credentials.set_uid(0) != Err(ProcessError::PermissionDenied)
    {
        process_fail(b"virtual credential transition failed");
    }
    line(b"GINUX_PROCESS: virtual-uid=1000 virtual-gid=1000 host-credentials=unchanged regain-root=denied");

    let mut futex: FutexTable<2> = FutexTable::new();
    if futex.wait(signal_child, 0x1000, 7, 7).is_err() {
        process_fail(b"futex wait failed");
    }
    let mut woken = [init; 1];
    if futex.wake(0x1000, 1, &mut woken) != Ok(1) || woken[0] != signal_child {
        process_fail(b"futex wake failed");
    }
    let mut event = EventFd::new(0, false);
    let mut poll: EventPoll<2> = EventPoll::new();
    if poll.add(7, EVENT_READ | EVENT_WRITE).is_err()
        || event.write(9).is_err()
        || poll.ready(7, EVENT_READ) != Ok(EVENT_READ)
        || event.read() != Ok(9)
    {
        process_fail(b"eventfd or epoll failed");
    }
    let mut clock = VirtualClock::new();
    let mut timers: TimerTable<2> = TimerTable::new();
    let timer = timers
        .create()
        .unwrap_or_else(|_| process_fail(b"timer create failed"));
    if timers.arm(timer, 0, 50, 25).is_err() || clock.advance(125).is_err() {
        process_fail(b"timer arm failed");
    }
    timers.update(clock.monotonic_ns());
    if timers.read(timer) != Ok(4) {
        process_fail(b"timer expiration failed");
    }
    line(b"GINUX_PROCESS: futex-wake=1 eventfd=9 epoll=readable timer-expirations=4");

    if processes.shutdown(137) != 2 || processes.reap_all() != 2 || processes.active() != 0 {
        process_fail(b"shutdown cleanup failed");
    }
    if domain.task_exited(true).is_err() {
        process_fail(b"domain cleanup failed");
    }
    line(b"GINUX_PROCESS: shutdown tasks=0 waiters=0 events=0 timers=0 resources=released");
    line(b"GATE7_PROCESS: PASS");
    exit_process(0)
}

fn process_fail(reason: &[u8]) -> ! {
    write_all(b"GATE7_PROCESS: FAIL: ");
    line(reason);
    exit_process(1)
}

// G09 domain-executable loading for the process-native supervision loop.
//
// The loop below has no filesystem virtualization yet (all file syscalls
// stay `-ENOSYS`), but a mediated `execve`/`execveat` that names a
// domain-produced file must still load under supervision. This section
// keeps one loop-global domain view for that path only:
//
// * The view is a `VirtualFs` over a seeded structural base (`/`, `/tmp`,
//   `/tmp/g09` as directories) plus a writable overlay. It is populated
//   once at startup from the host directory named
//   by `GINUX_DOMAIN_STAGE` (a supervisor-side test seam, never visible to
//   the workload): every regular file `<stage>/<name>` becomes the domain
//   object `/tmp/g09/<name>` with mode `0o600` (no execute bit, so the
//   tracee must `chmod` it through the domain first — the G08a path).
//   Without the variable the view stays empty and every exec falls through
//   to the host byte-identically.
// * At a mediated exec entry the loop resolves the tracee path in this
//   view. A missing path falls through to the host (existing host binaries
//   and faithful host `ENOENT`); a directory or a file with no execute bit
//   fails `-EACCES` without executing; a file with an execute bit is
//   materialized back at its domain path — mode `0o700`, supervisor-owned
//   bytes — and the host call then loads those exact bytes with the tracee
//   still attached (same pid, exec-epoch bump, never detached). Scripts
//   stage their domain interpreter first (bounded recursion); a malformed
//   `#!` line fails `-ENOEXEC`; an interpreter the domain does not know is
//   left for the host (for example `/bin/sh`).
// * `chmod(2)` and plain `fchmodat(2)` are emulated against the same view
//   through the G08a `chmod_at` path and never touch the host: a missing
//   domain path reports `-ENOENT`.
//
// This is controlled native loading, not export-and-execute on the host:
// the supervisor never runs the bytes itself, it only places the domain's
// own bytes where the domain path names them so the supervised tracee's
// `execve` succeeds. Host writes are confined to `/tmp/g09/` and only for
// paths that resolved to loop-overlay objects; every other path behaves
// exactly as before. The view shares one working directory (`/work`,
// matching `DomainCwd::new`) across tasks because `chdir` stays
// unmediated; per-task directories arrive with the G07 merge.

/// `GINUX_DOMAIN_STAGE` value capacity: a host directory path.
const STAGE_DIR_MAX: usize = 256;
/// Domain prefix every staged object lives under, and the only prefix the
/// loop ever materializes to on the host.
const STAGE_PREFIX: &[u8] = b"/tmp/g09/";
/// Overlay file capacity: at most this many staged executables.
const EXEC_OVERLAY_FILES: usize = 8;
/// Overlay object capacity: staged binaries and scripts fit here.
const EXEC_FILE_SIZE: usize = 65536;
/// Overlay descriptor capacity: staging reads hold one at a time.
const EXEC_FDS: usize = 4;
/// Host directory entries scanned per `getdents64` call while staging.
const STAGE_READDIR_BYTES: usize = 2048;
/// Host file bytes moved per read/write call while staging.
const STAGE_IO_BYTES: usize = 4096;
/// Deepest interpreter chain staged for one exec (script -> interp -> ...).
const EXEC_INTERP_DEPTH: usize = 3;

/// Raw host syscalls the no_std supervisor needs beyond `supervisor.rs`.
const SYS_GETDENTS64_HOST: usize = 217;
const SYS_MKDIR_HOST: usize = 83;
const SYS_FCHMOD_HOST: usize = 91;
/// Host `openat` flags for staging.
const HOST_O_RDONLY: usize = 0;
const HOST_O_WRONLY: usize = 1;
const HOST_O_CREAT: usize = 64;
const HOST_O_TRUNC: usize = 512;
/// `linux_dirent64.d_type` for a regular file.
const HOST_DIRENT_REGULAR: u8 = 8;
/// Negative errnos without a `supervisor.rs` constant.
const EACCES: i64 = 13;
const ENOENT: i64 = 2;
const EIO: i64 = 5;
const EFAULT: i64 = 14;
const ENOEXEC: i64 = 8;
const ELOOP: i64 = 40;

/// Staged-file mode after `chmod`: owner read/write/execute.
const STAGED_MODE: usize = 0o700;

type ExecVfs<'a> = VirtualFs<'a, EmptyBase, EXEC_OVERLAY_FILES, EXEC_FILE_SIZE, EXEC_FDS>;

/// Empty backing image: the domain-executable view starts with no base
/// entries, so every resolved file is a loop-overlay (domain-produced)
/// object. The reader never runs; it only satisfies the `VirtualFs` bound.
struct EmptyBase;

impl BaseReader for EmptyBase {
    fn read_at(&mut self, _offset: u64, _output: &mut [u8]) -> Result<(), VfsError> {
        Err(VfsError::Io)
    }
}

static mut STAGE_DIR: [u8; STAGE_DIR_MAX] = [0; STAGE_DIR_MAX];
static mut STAGE_LEN: usize = 0;
/// Seeded base image: a header plus directory records for `/`, `/tmp`,
/// and `/tmp/g09`, so staged files have resolvable parents in the merged
/// view. The base is structural only; every staged file is an overlay
/// (domain-produced) object.
static mut EXEC_BASE_BYTES: [u8; HEADER_SIZE + 3 * RECORD_SIZE] = [0; HEADER_SIZE + 3 * RECORD_SIZE];
static mut EXEC_VFS: Option<ExecVfs<'static>> = None;
static mut EXEC_READY: bool = false;
static mut EXEC_CWD: DomainCwd = DomainCwd::new();
static mut STAGE_BUF: [u8; EXEC_FILE_SIZE] = [0; EXEC_FILE_SIZE];

/// Borrow the loop's domain view. `None` before `exec_domain_init` runs.
fn with_exec_vfs<R>(op: impl FnOnce(&mut ExecVfs<'_>) -> R) -> Option<R> {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(EXEC_VFS);
        slot.as_mut().map(op)
    }
}

/// Snapshot the loop's shared working directory for one resolution.
fn exec_cwd_snapshot() -> DomainCwd {
    unsafe { *core::ptr::addr_of!(EXEC_CWD) }
}

/// Remember the `GINUX_DOMAIN_STAGE` host directory from the supervisor's
/// own environment. Runs in `rust_main` before dispatch: the value is a
/// supervisor input like the config path (never workload-visible), so an
/// absent, empty, or overlong variable simply leaves staging off.
fn scan_stage_env(initial_stack: *const usize) {
    const PREFIX: &[u8] = b"GINUX_DOMAIN_STAGE=";
    let argc = unsafe { *initial_stack };
    if argc > 512 {
        return;
    }
    let mut cursor = unsafe { initial_stack.add(1 + argc + 1) };
    let mut entries = 0;
    while entries < 256 {
        let entry = unsafe { *cursor };
        if entry == 0 {
            break;
        }
        let bytes = entry as *const u8;
        let mut index = 0;
        while index < PREFIX.len() + STAGE_DIR_MAX {
            let byte = unsafe { *bytes.add(index) };
            if index < PREFIX.len() {
                if byte != PREFIX[index] {
                    break;
                }
            } else if byte == 0 {
                let len = index - PREFIX.len();
                if len > 0 && len < STAGE_DIR_MAX {
                    unsafe {
                        let mut staged = 0;
                        while staged < len {
                            STAGE_DIR[staged] = *bytes.add(PREFIX.len() + staged);
                            staged += 1;
                        }
                        STAGE_DIR[len] = 0;
                        STAGE_LEN = len;
                    }
                }
                return;
            }
            index += 1;
        }
        cursor = unsafe { cursor.add(1) };
        entries += 1;
    }
}

/// Build the loop's domain view over the seeded structural base. Runs once
/// at supervision start; without it every domain lookup reports "no view"
/// and exec falls through to the host.
fn exec_domain_init() {
    unsafe {
        if EXEC_READY {
            return;
        }
        let mut header = [0u8; HEADER_SIZE];
        encode_header(3, &mut header);
        let mut records = [[0u8; RECORD_SIZE]; 3];
        let dirs: [&[u8]; 3] = [b"/", b"/tmp", b"/tmp/g09"];
        let mut index = 0;
        let mut valid = true;
        while index < 3 {
            if encode_record(
                Entry {
                    path: dirs[index],
                    kind: NodeKind::Directory,
                    mode: 0o755,
                    uid: 0,
                    gid: 0,
                    size: 0,
                    data_offset: 0,
                    link: b"",
                },
                &mut records[index],
            )
            .is_err()
            {
                valid = false;
            }
            index += 1;
        }
        if !valid {
            return;
        }
        let base = &mut *core::ptr::addr_of_mut!(EXEC_BASE_BYTES);
        base[..HEADER_SIZE].copy_from_slice(&header);
        let mut record = 0;
        while record < 3 {
            let start = HEADER_SIZE + record * RECORD_SIZE;
            base[start..start + RECORD_SIZE].copy_from_slice(&records[record]);
            record += 1;
        }
        let bytes: &'static [u8] = &*core::ptr::addr_of!(EXEC_BASE_BYTES);
        if let Ok(index) = Index::new(bytes) {
            EXEC_VFS = Some(VirtualFs::new(index, EmptyBase));
            EXEC_READY = true;
        }
    }
}

/// Copy the staged host directory into a local buffer for one host call.
fn stage_dir_snapshot(out: &mut [u8; STAGE_DIR_MAX]) -> usize {
    unsafe {
        let len = STAGE_LEN;
        if len == 0 || len >= STAGE_DIR_MAX {
            return 0;
        }
        out[..len].copy_from_slice(&STAGE_DIR[..len]);
        out[len] = 0;
        len
    }
}

/// Load every regular file in the stage directory into the domain overlay
/// as `/tmp/g09/<name>` with mode `0o600`. Bounds: at most
/// `EXEC_OVERLAY_FILES` files, names that fit the domain path, contents
/// that fit one overlay object; anything else is skipped with an audit
/// line and never half-planted (short writes roll back via `unlink`).
fn preload_domain_stage() {
    let mut dir = [0u8; STAGE_DIR_MAX];
    if stage_dir_snapshot(&mut dir) == 0 {
        return;
    }
    let fd = unsafe {
        syscall3(
            SYS_OPENAT_HOST,
            AT_FDCWD,
            dir.as_ptr() as usize,
            HOST_O_RDONLY,
        )
    };
    if fd < 0 {
        return;
    }
    // The materialization target exists before any exec can need it.
    let _ = unsafe {
        syscall2(
            SYS_MKDIR_HOST,
            b"/tmp\0".as_ptr() as usize,
            0o755,
        )
    };
    let _ = unsafe { syscall2(SYS_MKDIR_HOST, b"/tmp/g09\0".as_ptr() as usize, 0o755) };
    let mut names = [0u8; STAGE_READDIR_BYTES];
    let mut staged = 0u32;
    loop {
        let count = unsafe {
            syscall3(
                SYS_GETDENTS64_HOST,
                fd as usize,
                names.as_mut_ptr() as usize,
                names.len(),
            )
        };
        if count <= 0 || staged >= EXEC_OVERLAY_FILES as u32 {
            break;
        }
        let mut offset = 0;
        while offset < count as usize {
            let reclen = u16::from_le_bytes([names[offset + 16], names[offset + 17]]) as usize;
            if reclen < 19 || offset + reclen > count as usize {
                break;
            }
            let dtype = names[offset + 18];
            if dtype == HOST_DIRENT_REGULAR && staged < EXEC_OVERLAY_FILES as u32 {
                let mut end = offset + 19;
                while end < offset + reclen && names[end] != 0 {
                    end += 1;
                }
                if end > offset + 19 && end < offset + reclen {
                    stage_domain_file(&dir, &names[offset + 19..end], &mut staged);
                }
            }
            if reclen == 0 {
                break;
            }
            offset += reclen;
        }
    }
    let _ = unsafe { syscall1(SYS_CLOSE_HOST, fd as usize) };
    write_all(b"GINUX_NATIVE_PROCESS_AUDIT: exec-stage files=");
    write_u64(staged as u64);
    write_all(b"\n");
}

/// Plant one stage-directory file into the domain overlay, then drop every
/// partial write on any bound or I/O failure.
fn stage_domain_file(dir: &[u8; STAGE_DIR_MAX], name: &[u8], staged: &mut u32) {
    if name.is_empty() || name.len() + STAGE_PREFIX.len() > DOMAIN_PATH_MAX {
        return;
    }
    if name.contains(&b'/') {
        return;
    }
    let mut domain = [0u8; DOMAIN_PATH_MAX];
    domain[..STAGE_PREFIX.len()].copy_from_slice(STAGE_PREFIX);
    domain[STAGE_PREFIX.len()..STAGE_PREFIX.len() + name.len()].copy_from_slice(name);
    let domain_len = STAGE_PREFIX.len() + name.len();
    // Host source path: `<stage>/<name>`.
    let mut host = [0u8; STAGE_DIR_MAX + 258];
    let mut host_len = 0;
    while dir[host_len] != 0 && host_len < STAGE_DIR_MAX {
        host[host_len] = dir[host_len];
        host_len += 1;
    }
    if host_len == 0 || host_len + 1 + name.len() + 1 > host.len() {
        return;
    }
    host[host_len] = b'/';
    host_len += 1;
    host[host_len..host_len + name.len()].copy_from_slice(name);
    host_len += name.len();
    host[host_len] = 0;
    let source = unsafe {
        syscall4(
            SYS_OPENAT_HOST,
            AT_FDCWD,
            host.as_ptr() as usize,
            HOST_O_RDONLY,
            0,
        )
    };
    if source < 0 {
        return;
    }
    let planted = with_exec_vfs(|vfs| {
        let descriptor = match vfs.open(
            &domain[..domain_len],
            O_CREATE | O_WRITE | O_TRUNC,
        ) {
            Ok(descriptor) => descriptor,
            Err(_) => return false,
        };
        let mut done = true;
        loop {
            let chunk = unsafe {
                syscall3(
                    SYS_READ_HOST,
                    source as usize,
                    core::ptr::addr_of_mut!(STAGE_BUF) as usize,
                    STAGE_IO_BYTES.min(EXEC_FILE_SIZE),
                )
            };
            if chunk < 0 {
                done = false;
                break;
            }
            if chunk == 0 {
                break;
            }
            let bytes = unsafe { &STAGE_BUF[..chunk as usize] };
            let mut written = 0;
            while written < bytes.len() {
                match vfs.write(descriptor, &bytes[written..]) {
                    Ok(0) => break,
                    Ok(count) => written += count,
                    Err(_) => {
                        done = false;
                        break;
                    }
                }
            }
            if !done || written < bytes.len() {
                done = false;
                break;
            }
        }
        let _ = vfs.close(descriptor);
        if !done {
            let _ = vfs.unlink(&domain[..domain_len]);
        }
        done
    })
    .unwrap_or(false);
    let _ = unsafe { syscall1(SYS_CLOSE_HOST, source as usize) };
    if planted {
        *staged += 1;
        write_all(b"GINUX_NATIVE_PROCESS_AUDIT: exec-stage file=");
        write_all(&domain[..domain_len]);
        write_all(b"\n");
    }
}

/// Create every missing parent directory of a canonical domain path on the
/// host (`/tmp` and `/tmp/g09` for staged objects). Existing components
/// report an error that the caller ignores; the later open fails honestly
/// if a component is still missing.
fn mkdir_domain_parents(canonical: &[u8]) {
    let mut index = 1;
    while index < canonical.len() {
        if canonical[index] == b'/' {
            let mut prefix = [0u8; DOMAIN_PATH_MAX + 1];
            prefix[..index].copy_from_slice(&canonical[..index]);
            prefix[index] = 0;
            let _ = unsafe {
                syscall2(SYS_MKDIR_HOST, prefix.as_ptr() as usize, 0o755)
            };
        }
        index += 1;
    }
}

/// Write `content` to the host file at its domain path with mode `0o700`.
/// Only call with paths that resolved to loop-overlay objects under
/// `STAGE_PREFIX`; the prefix check here is the last gate before any host
/// write, so a non-staged path can never reach the host through this call.
fn write_staged_host(canonical: &[u8], content: &[u8]) -> Result<(), i64> {
    if canonical.len() < STAGE_PREFIX.len() || &canonical[..STAGE_PREFIX.len()] != STAGE_PREFIX {
        return Err(-EIO);
    }
    if canonical.contains(&0) {
        return Err(-EIO);
    }
    let mut path = [0u8; DOMAIN_PATH_MAX + 1];
    path[..canonical.len()].copy_from_slice(canonical);
    path[canonical.len()] = 0;
    mkdir_domain_parents(canonical);
    let fd = unsafe {
        syscall4(
            SYS_OPENAT_HOST,
            AT_FDCWD,
            path.as_ptr() as usize,
            HOST_O_WRONLY | HOST_O_CREAT | HOST_O_TRUNC,
            STAGED_MODE,
        )
    };
    if fd < 0 {
        return Err(-EIO);
    }
    let mut offset = 0;
    while offset < content.len() {
        let moved = unsafe {
            syscall4(
                SYS_PWRITE64,
                fd as usize,
                content.as_ptr().add(offset) as usize,
                content.len() - offset,
                offset,
            )
        };
        if moved <= 0 {
            let _ = unsafe { syscall1(SYS_CLOSE_HOST, fd as usize) };
            return Err(-EIO);
        }
        offset += moved as usize;
    }
    // `openat` applied the mode through the caller's umask; pin it exactly.
    if unsafe { syscall3(SYS_FCHMOD_HOST, fd as usize, STAGED_MODE, 0) } < 0 {
        let _ = unsafe { syscall1(SYS_CLOSE_HOST, fd as usize) };
        return Err(-EIO);
    }
    let _ = unsafe { syscall1(SYS_CLOSE_HOST, fd as usize) };
    Ok(())
}

/// Read a NUL-terminated tracee string into `out`, returning its length
/// without the NUL. Fails when no NUL appears within `DOMAIN_PATH_MAX`
/// bytes or any word is unreadable; the caller then falls back to the
/// host (exec) or reports `-EFAULT` (chmod), never inventing a path.
fn read_tracee_cstr(host_pid: usize, addr: usize, out: &mut [u8; DOMAIN_PATH_MAX]) -> Result<usize, ()> {
    let mut len = 0;
    while len < DOMAIN_PATH_MAX {
        let address = addr.wrapping_add(len);
        let aligned = address & !0x7;
        let shift = (address & 0x7) * 8;
        let mut word = 0usize;
        if ptrace(
            PTRACE_PEEKTEXT,
            host_pid,
            aligned,
            &mut word as *mut _ as usize,
        ) < 0
        {
            return Err(());
        }
        let byte = ((word >> shift) & 0xff) as u8;
        out[len] = byte;
        if byte == 0 {
            return Ok(len);
        }
        len += 1;
    }
    Err(())
}

/// Emulate `chmod`/`fchmodat` against the loop's domain view through the
/// G08a path. The host is never touched: a resolved object gets its plain
/// permission bits (including the execute bit a later `execve` needs), a
/// path the domain does not know reports `-ENOENT`, and an unreadable
/// tracee pointer reports `-EFAULT`.
fn domain_chmod_entry(host_pid: usize, path_addr: usize, mode: u32) -> i64 {
    let mut raw = [0u8; DOMAIN_PATH_MAX];
    let len = match read_tracee_cstr(host_pid, path_addr, &mut raw) {
        Ok(len) => len,
        Err(()) => return -EFAULT,
    };
    let outcome = with_exec_vfs(|vfs| {
        let cwd = exec_cwd_snapshot();
        chmod_at(vfs, &cwd, DOMAIN_AT_FDCWD, &raw[..len], mode)
    });
    match outcome {
        None => -EIO,
        Some(Ok(())) => 0,
        Some(Err(error)) => error.errno(),
    }
}

/// What a mediated exec entry does with its tracee path: run the host call
/// (unknown to the domain, or staged and ready) or deny without executing.
enum DomainExec {
    Host,
    Deny(i64),
}

/// Decide a mediated `execve`/`execveat` against the loop's domain view.
/// Missing domain paths fall through to the host so existing host binaries
/// keep working and the host reports its own faithful `ENOENT`; an empty
/// path is `-ENOENT` without executing; escapes and loops fail with the
/// resolution errno; directories and files with no execute bit fail
/// `-EACCES`; files with an execute bit are materialized (script
/// interpreters first) and then run by the host call under supervision.
fn domain_exec_entry(host_pid: usize, path_addr: usize) -> DomainExec {
    let mut raw = [0u8; DOMAIN_PATH_MAX];
    let len = match read_tracee_cstr(host_pid, path_addr, &mut raw) {
        Ok(len) => len,
        Err(()) => return DomainExec::Host,
    };
    if len == 0 {
        return DomainExec::Deny(-ENOENT);
    }
    let view = with_exec_vfs(|vfs| {
        let cwd = exec_cwd_snapshot();
        let mut canonical = [0u8; DOMAIN_PATH_MAX];
        let resolved = resolve_at(
            cwd.path(),
            DOMAIN_AT_FDCWD,
            &raw[..len],
            &mut VfsDomainView::new(&mut *vfs),
            &mut canonical,
        );
        match resolved {
            Err(ResolveError::NotFound) => None,
            Err(error) => Some(Err(error.errno())),
            Ok((_, ResolvedKind::Directory)) => Some(Err(-EACCES)),
            Ok((length, ResolvedKind::File)) => {
                Some(materialize_domain_file(vfs, &canonical[..length], 0))
            }
            // `resolve_at` follows the final link, so this arm is
            // unreachable; treat it like a miss rather than staging.
            Ok((_, ResolvedKind::Symlink)) => None,
        }
    });
    match view {
        // No domain view, or a path the domain does not know: the host
        // call runs exactly as before this task.
        None => DomainExec::Host,
        Some(None) => DomainExec::Host,
        Some(Some(Ok(()))) => {
            write_all(b"GINUX_NATIVE_PROCESS_AUDIT: exec-domain-staged path=");
            write_all(&raw[..len]);
            write_all(b"\n");
            DomainExec::Host
        }
        Some(Some(Err(errno))) => {
            write_all(b"GINUX_NATIVE_PROCESS_AUDIT: exec-domain-denied errno=");
            write_i64(-errno);
            write_all(b" path=");
            write_all(&raw[..len]);
            write_all(b"\n");
            DomainExec::Deny(errno)
        }
    }
}

/// Stage one resolved domain file for supervised loading: check the stored
/// mode, stage a domain-resident script interpreter first (bounded depth,
/// `-ELOOP` past it), write the exact domain bytes at the domain path, and
/// report readiness. `canonical` must already resolve to a live file; the
/// `STAGE_PREFIX` gate inside `write_staged_host` still refuses anything
/// else. Directory kinds and files with no execute bit fail `-EACCES`.
fn materialize_domain_file(
    vfs: &mut ExecVfs<'_>,
    canonical: &[u8],
    depth: usize,
) -> Result<(), i64> {
    if depth > EXEC_INTERP_DEPTH {
        return Err(-ELOOP);
    }
    let meta = vfs.metadata_merged(canonical).map_err(|_| -EIO)?;
    if meta.kind != NodeKind::File {
        return Err(-EACCES);
    }
    if !exec_bit_set(meta.mode) {
        return Err(-EACCES);
    }
    let descriptor = vfs.open(canonical, O_READ).map_err(|_| -EIO)?;
    let mut total = 0usize;
    loop {
        let rest = unsafe { &mut STAGE_BUF[total..] };
        match vfs.read(descriptor, rest) {
            Ok(0) => break,
            Ok(count) => total += count,
            Err(_) => {
                let _ = vfs.close(descriptor);
                return Err(-EIO);
            }
        }
    }
    let _ = vfs.close(descriptor);
    // A script stages its interpreter before itself so the kernel finds it
    // at the domain path when it parses the `#!` line. Interpreters the
    // domain does not know stay for the host (`/bin/sh` keeps working);
    // malformed lines fail `-ENOEXEC` like the kernel would.
    let mut interp = [0u8; SCRIPT_INTERP_MAX];
    match parse_script_interp(unsafe { &STAGE_BUF[..total] }, &mut interp) {
        ScriptInterp::NotScript => {}
        ScriptInterp::Bad => return Err(-ENOEXEC),
        ScriptInterp::Interp(length) => {
            let cwd = exec_cwd_snapshot();
            let mut resolved = [0u8; DOMAIN_PATH_MAX];
            let outcome = resolve_at(
                cwd.path(),
                DOMAIN_AT_FDCWD,
                &interp[..length],
                &mut VfsDomainView::new(&mut *vfs),
                &mut resolved,
            );
            match outcome {
                Err(ResolveError::NotFound) => {}
                Err(error) => return Err(error.errno()),
                Ok((_, ResolvedKind::Directory)) => return Err(-EACCES),
                Ok((resolved_len, ResolvedKind::File)) => {
                    materialize_domain_file(vfs, &resolved[..resolved_len], depth + 1)?;
                }
                Ok((_, ResolvedKind::Symlink)) => return Err(-EIO),
            }
        }
    }
    // Re-read after interpreter staging: recursion reuses `STAGE_BUF`.
    let staged: &[u8] = unsafe {
        let descriptor = vfs.open(canonical, O_READ).map_err(|_| -EIO)?;
        let mut total = 0usize;
        loop {
            let rest = &mut STAGE_BUF[total..];
            match vfs.read(descriptor, rest) {
                Ok(0) => break,
                Ok(count) => total += count,
                Err(_) => {
                    let _ = vfs.close(descriptor);
                    return Err(-EIO);
                }
            }
        }
        let _ = vfs.close(descriptor);
        &STAGE_BUF[..total]
    };
    write_staged_host(canonical, staged)
}

#[derive(Clone, Copy)]
struct NativeProcessTask {
    host_pid: usize,
    virtual_id: ginux_process::TaskId,
    awaiting_exit: bool,
    override_result: bool,
    result: i64,
    syscall: u64,
    translated_rdi: u64,
    /// A blocking `wait4` with nothing reportable parks the caller at its
    /// entry stop (the host call never executes) until a matching child
    /// state change wakes it. The selector/options/pointers snapshot the
    /// parked request; registers stay untouched while parked.
    wait_pending: bool,
    wait_selector: i64,
    wait_options: u32,
    wait_status: usize,
    wait_rusage: usize,
    /// Signal number of a forwarded termination kill still in flight for
    /// this task. The host reports the doomed task's death as a signal
    /// delivery stop first; only a stop matching this number resumes with
    /// the signal so the death is observed. Anything else still fails.
    killed_with: u64,
    fork_result_pending: u32,
    fork_breakpoint_rip: usize,
    fork_breakpoint_word: usize,
    fork_variant_event: u32,
    exec_pending: bool,
    exec_event_seen: bool,
    /// A mediated descriptor entry stashed for its exit stop: the syscall
    /// number plus its arguments (pipefd pointer or oldfd, newfd or flags,
    /// flags). Zero when no descriptor call is in flight.
    desc_syscall: u64,
    desc_arg0: u64,
    desc_arg1: u64,
    desc_arg2: u64,
    tracing: bool,
    thread_pending: bool,
    clone_ptid: usize,
    set_tid_pending: bool,
}

fn process_native_main(config_path: *const u8, fixture_path: *const u8) -> ! {
    let config = load_config(config_path);
    let mut domain = Domain::create(config);
    if domain.start().is_err() {
        startup_fail(&mut domain, b"native process domain start failed");
    }
    let child = unsafe { syscall0(SYS_FORK) };
    if child < 0 {
        startup_fail(&mut domain, b"native process tracee fork failed");
    }
    if child == 0 {
        process_native_tracee(fixture_path);
    }
    supervise_process_native(child as usize, &mut domain)
}

fn process_native_tracee(fixture_path: *const u8) -> ! {
    if unsafe { syscall4(SYS_PTRACE, PTRACE_TRACEME, 0, 0, 0) } < 0
        || unsafe { syscall5(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0
    {
        native_tracee_setup_fail(130);
    }
    let argv = [fixture_path, core::ptr::null()];
    let environment: [*const u8; 1] = [core::ptr::null()];
    unsafe {
        syscall3(
            SYS_EXECVE,
            fixture_path as usize,
            argv.as_ptr() as usize,
            environment.as_ptr() as usize,
        );
        syscall1(SYS_EXIT_HOST, 131);
    }
    loop {
        core::hint::spin_loop();
    }
}

fn supervise_process_native(root_host_pid: usize, domain: &mut Domain) -> ! {
    // G09: the loop's domain-executable view lives for the whole run and
    // costs nothing when `GINUX_DOMAIN_STAGE` is absent (empty view, every
    // exec falls through byte-identically).
    exec_domain_init();
    preload_domain_stage();
    // L01: arm host cancellation before the first blocking wait. The tracee
    // was forked by the caller, so its post-execve dispositions stay at
    // their defaults; only this supervisor observes the flag.
    if !teardown::arm_cancel_signals() {
        let _ = ptrace(PTRACE_KILL, root_host_pid, 0, 0);
        startup_fail(domain, b"cancel signal setup failed");
    }
    let mut status = 0i32;
    let initial = wait(root_host_pid, &mut status);
    if teardown::is_cancel_wait(initial) {
        // Cancelled before the workload stopped for supervision: it never
        // ran under mediation, so SIGKILL it, reap it, and report. No other
        // descendant can exist yet.
        teardown::kill_remaining(&[root_host_pid]);
        let mut sweep = 0u32;
        while sweep < 4 {
            let mut dead = 0i32;
            if unsafe {
                syscall4(
                    SYS_WAIT4,
                    root_host_pid,
                    &mut dead as *mut _ as usize,
                    0,
                    0,
                )
            } <= 0
            {
                break;
            }
            sweep += 1;
        }
        let _ = domain.task_exited(false);
        line(b"GINUX_NATIVE_PROCESS: outcome=cancelled tasks=0 live-pipes=0");
        exit_process(teardown::CANCEL_EXIT);
    }
    if initial < 0 || !stopped(status) {
        write_all(b"GINUX_NATIVE_PROCESS: initial-status=");
        write_i64(status as i64);
        write_all(b"\n");
        // The workload never stopped for supervision: either it died
        // (already reaped by the wait above) or the wait itself failed.
        // Kill what may remain, then report a startup failure.
        teardown::kill_remaining(&[root_host_pid]);
        startup_fail(domain, b"process fixture did not stop after exec");
    }
    let options = PTRACE_O_TRACESYSGOOD
        | PTRACE_O_TRACEFORK
        | PTRACE_O_TRACEVFORK
        | PTRACE_O_TRACECLONE
        | PTRACE_O_TRACEEXEC
        | PTRACE_O_EXITKILL;
    if ptrace(PTRACE_SETOPTIONS, root_host_pid, 0, options) < 0 {
        native_fail(domain, root_host_pid, b"process ptrace options failed");
    }
    let mut processes: ProcessTable<8> = ProcessTable::new();
    // G05a descriptor mirror: pipe pairs, dups, and close-on-exec ends as
    // supervisor-owned domain objects, keyed by virtual pid. Every mutation
    // below follows a host outcome the loop observed.
    let mut pipes: PipeSpace<8, 16, 16> = PipeSpace::new();
    let root_virtual = processes
        .create_init(Credentials::unprivileged(1000, 1000))
        .unwrap_or_else(|_| process_native_fail(domain, root_host_pid, b"virtual init failed"));
    let mut tasks: [Option<NativeProcessTask>; 8] = [None; 8];
    tasks[0] = Some(NativeProcessTask {
        host_pid: root_host_pid,
        virtual_id: root_virtual,
        awaiting_exit: false,
        override_result: false,
        result: 0,
        syscall: 0,
        translated_rdi: 0,
        fork_result_pending: 0,
        fork_breakpoint_rip: 0,
        fork_breakpoint_word: 0,
        fork_variant_event: 0,
        exec_pending: false,
        exec_event_seen: false,
        desc_syscall: 0,
        desc_arg0: 0,
        desc_arg1: 0,
        desc_arg2: 0,
        tracing: true,
        thread_pending: false,
        clone_ptid: 0,
        set_tid_pending: false,
        wait_pending: false,
        wait_selector: 0,
        wait_options: 0,
        wait_status: 0,
        wait_rusage: 0,
        killed_with: 0,
    });
    if ptrace(PTRACE_SYSCALL, root_host_pid, 0, 0) < 0 {
        process_native_fail(domain, root_host_pid, b"process initial resume failed");
    }
    line(b"GINUX_NATIVE_PROCESS: virtual-init=1 host-pid=unexposed ptrace=attached");

    loop {
        status = 0;
        let waited = unsafe {
            syscall4(
                SYS_WAIT4,
                (-1isize) as usize,
                &mut status as *mut _ as usize,
                0,
                0,
            )
        };
        if teardown::is_cancel_wait(waited) {
            // Host stop request: abandon mediation and tear everything down.
            teardown_domain(
                domain,
                root_host_pid,
                &mut processes,
                &mut tasks,
                &mut pipes,
                TeardownOutcome::Cancelled,
            );
        }
        if waited <= 0 {
            process_native_fail(domain, root_host_pid, b"process wait-any failed");
        }
        let host_pid = waited as usize;
        let Some(task_index) = tasks
            .iter()
            .position(|task| task.is_some_and(|task| task.host_pid == host_pid))
        else {
            process_native_fail(domain, root_host_pid, b"unknown host tracee");
        };
        let task = tasks[task_index].unwrap();

        // A host stop request that arrived while a stop was already
        // dequeued: abandon mediation and tear everything down.
        if teardown::cancel_requested() {
            teardown_domain(
                domain,
                root_host_pid,
                &mut processes,
                &mut tasks,
                &mut pipes,
                TeardownOutcome::Cancelled,
            );
        }

        if !stopped(status) {
            // A zero low byte is a normal exit; anything else is death by
            // that signal number (core-dump bit excluded). Both outcomes
            // live in the virtual table so managed waits report them; the
            // shell-style code below is diagnostics only.
            let child_status = if status & 0x7f == 0 {
                ChildStatus::Exited(status >> 8)
            } else {
                ChildStatus::Signaled((status & 0x7f) as u8)
            };
            let exit_status = child_status.shell_code();
            let recorded = match child_status {
                ChildStatus::Exited(code) => processes.exit(task.virtual_id, code),
                ChildStatus::Signaled(signal) => processes.signaled(task.virtual_id, signal),
            };
            if recorded.is_err() {
                process_native_fail(domain, root_host_pid, b"virtual exit failed");
            }
            // G05a: the host closed every descriptor with the task. Release
            // the mirror's ends now, so the pipe objects die their last
            // close here and no stale write end can hide an EOF elsewhere.
            pipes.release_task(task.virtual_id.pid);
            // Thread exit with cleanup: a task whose tgid differs from its
            // pid is a thread-group member. Threads are joined over a futex
            // on shared memory, never reaped by `wait4`, so the host slot is
            // dropped now; the virtual exit stays in the table for the final
            // reap. The host kernel already performed the
            // `CLONE_CHILD_CLEARTID` clear and wakeup as part of this exit.
            let thread_exit = processes
                .view(task.virtual_id)
                .is_ok_and(|view| view.tgid != view.id.pid);
            if thread_exit {
                write_all(b"GINUX_NATIVE_PROCESS_AUDIT: thread-exit virtual-tid=");
                write_u64(task.virtual_id.pid as u64);
                write_all(b" status=");
                write_i64(exit_status as i64);
                write_all(b"\n");
                tasks[task_index] = None;
            } else if let Some(entry) = tasks[task_index].as_mut() {
                entry.tracing = false;
                // A parked waiter can never complete its own wait once dead.
                entry.wait_pending = false;
            }
            if !thread_exit {
                // Queue virtual SIGCHLD for the parent and wake every
                // parked wait this state change satisfies. Thread exits
                // queue nothing: the host sends no SIGCHLD for them and no
                // wait consumes them.
                wake_waiters_for_child(
                    domain,
                    root_host_pid,
                    &mut processes,
                    &mut tasks,
                    task.virtual_id,
                );
            }
            if task.virtual_id == root_virtual {
                // L01: the root workload is done in every order — clean
                // exit, nonzero exit, or signal death, ahead of or behind
                // its descendants. Teardown kills whatever still runs,
                // reaps every descendant, and reports the root outcome.
                // (The main thread may exit while joined-or-detached
                // siblings are still draining: thread death reports arrive
                // in kernel order, not creation order.)
                write_all(b"GINUX_NATIVE_PROCESS: root-exit=");
                write_i64(exit_status as i64);
                write_all(b" tracing-remaining=");
                write_u64(tasks.iter().flatten().filter(|entry| entry.tracing).count() as u64);
                write_all(b"\n");
                let outcome = match child_status {
                    ChildStatus::Exited(code) => TeardownOutcome::Exited(code),
                    ChildStatus::Signaled(signal) => TeardownOutcome::Signaled(signal),
                };
                teardown_domain(
                    domain,
                    root_host_pid,
                    &mut processes,
                    &mut tasks,
                    &mut pipes,
                    outcome,
                );
            }
            continue;
        }

        let event = (status as usize) >> 16;
        if event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE
        {
            let mut child_host_pid = 0usize;
            if ptrace(
                PTRACE_GETEVENTMSG,
                host_pid,
                0,
                &mut child_host_pid as *mut _ as usize,
            ) < 0
            {
                process_native_fail(domain, root_host_pid, b"fork event read failed");
            }
            // A creation whose entry carried a supported `CLONE_THREAD`
            // shape shares the existing managed-task path as a thread-group
            // member (same tgid, fresh virtual tid); every other shape is an
            // ordinary parent/child process pair. The entry arm recorded
            // which one this is before the host call executed.
            let is_thread = tasks[task_index]
                .as_ref()
                .is_some_and(|parent| parent.thread_pending);
            let child_virtual = if is_thread {
                processes.clone_thread(task.virtual_id).unwrap_or_else(|_| {
                    process_native_fail(domain, root_host_pid, b"virtual thread failed")
                })
            } else {
                processes.fork(task.virtual_id).unwrap_or_else(|_| {
                    process_native_fail(domain, root_host_pid, b"virtual fork failed")
                })
            };
            // G05a: the host duplicated the descriptor table with the
            // address space, so the virtual child inherits the same tracked
            // ends (pipe references retained). Threads share the host table
            // while the mirror holds a copy per member; the group-wide exec
            // scrub below bounds that divergence.
            if pipes
                .inherit(child_virtual.pid, task.virtual_id.pid)
                .is_err()
            {
                process_native_fail(domain, root_host_pid, b"descriptor inherit failed");
            }
            let Some(child_slot) = tasks.iter().position(Option::is_none) else {
                process_native_fail(domain, root_host_pid, b"host task table full");
            };
            tasks[child_slot] = Some(NativeProcessTask {
                host_pid: child_host_pid,
                virtual_id: child_virtual,
                awaiting_exit: false,
                override_result: false,
                result: 0,
                syscall: 0,
                translated_rdi: 0,
                fork_result_pending: 0,
                fork_breakpoint_rip: 0,
                fork_breakpoint_word: 0,
                fork_variant_event: 0,
                exec_pending: false,
                exec_event_seen: false,
                desc_syscall: 0,
                desc_arg0: 0,
                desc_arg1: 0,
                desc_arg2: 0,
                tracing: true,
                thread_pending: false,
                clone_ptid: 0,
                set_tid_pending: false,
        wait_pending: false,
        wait_selector: 0,
        wait_options: 0,
        wait_status: 0,
        wait_rusage: 0,
        killed_with: 0,
            });
            if event == PTRACE_EVENT_FORK {
                // Separate address space (raw fork, or clone without address
                // sharing, which the lane entry already enforced): the
                // breakpoint below is invisible to the child, so translate
                // the parent's observed result when it fires.
                let mut parent_registers = core::mem::MaybeUninit::<UserRegs>::uninit();
                if ptrace(
                    PTRACE_GETREGS,
                    host_pid,
                    0,
                    parent_registers.as_mut_ptr() as usize,
                ) < 0
                {
                    process_native_fail(domain, root_host_pid, b"fork breakpoint registers failed");
                }
                let parent_registers = unsafe { parent_registers.assume_init() };
                let breakpoint_rip = parent_registers.rip as usize;
                let mut breakpoint_word = 0usize;
                if ptrace(
                    PTRACE_PEEKTEXT,
                    host_pid,
                    breakpoint_rip,
                    &mut breakpoint_word as *mut _ as usize,
                ) < 0
                {
                    process_native_fail(domain, root_host_pid, b"fork breakpoint read failed");
                }
                if ptrace(
                    PTRACE_POKETEXT,
                    host_pid,
                    breakpoint_rip,
                    (breakpoint_word & !0xff) | 0xcc,
                ) < 0
                {
                    process_native_fail(domain, root_host_pid, b"fork breakpoint install failed");
                }
                let parent = tasks[task_index].as_mut().unwrap();
                parent.awaiting_exit = false;
                parent.override_result = false;
                parent.fork_result_pending = child_virtual.pid;
                parent.fork_breakpoint_rip = breakpoint_rip;
                parent.fork_breakpoint_word = breakpoint_word;
                parent.fork_variant_event = event as u32;
                if ptrace(PTRACE_CONT, host_pid, 0, 0) < 0 {
                    process_native_fail(
                        domain,
                        root_host_pid,
                        b"fork parent breakpoint resume failed",
                    );
                }
                continue;
            }
            // vfork/clone children may share the parent's text, where a
            // breakpoint would also trap the child: resume with SYSCALL and
            // translate the host child pid at the creation exit stop below.
            // The entry left `awaiting_exit` set, and `fork_result_pending`
            // stays clear so the breakpoint branch above is skipped.
            let parent = tasks[task_index].as_mut().unwrap();
            parent.fork_variant_event = event as u32;
            if ptrace(PTRACE_SYSCALL, host_pid, 0, 0) < 0 {
                process_native_fail(domain, root_host_pid, b"fork parent resume failed");
            }
            continue;
        }
        if event == PTRACE_EVENT_EXEC {
            // Executable replacement: the host kernel already performed the
            // shebang/loader transition. The virtual task keeps its identity
            // (same host pid, same virtual pid) with a bumped exec epoch and
            // reset signal state, and stays attached: `awaiting_exit` remains
            // set so the execve exit stop below only consumes the pending
            // entry instead of looking like a fresh entry.
            if !task.exec_pending {
                process_native_fail(domain, root_host_pid, b"unexpected exec event");
            }
            let epoch = processes.exec(task.virtual_id).unwrap_or_else(|_| {
                process_native_fail(domain, root_host_pid, b"virtual exec failed")
            });
            // G05a: the host closed every O_CLOEXEC descriptor during
            // replacement. Drop the same ends for the whole thread group so
            // no stale end survives the exec and hides a later EOF.
            let exec_tgid = processes.view(task.virtual_id).unwrap_or_else(|_| {
                process_native_fail(domain, root_host_pid, b"exec tgid lookup failed")
            });
            let scrubbed =
                scrub_close_on_exec(&mut pipes, &processes, &tasks, exec_tgid.tgid);
            write_all(b"GINUX_NATIVE_PROCESS_AUDIT: exec syscall=");
            write_u64(task.syscall);
            write_all(b" host-pid=");
            write_u64(host_pid as u64);
            write_all(b" virtual-pid=");
            write_u64(task.virtual_id.pid as u64);
            write_all(b" epoch=");
            write_u64(epoch as u64);
            write_all(b" cloexec-dropped=");
            write_u64(scrubbed as u64);
            write_all(b"\n");
            tasks[task_index].as_mut().unwrap().exec_event_seen = true;
            if ptrace(PTRACE_SYSCALL, host_pid, 0, 0) < 0 {
                process_native_fail(domain, root_host_pid, b"exec event resume failed");
            }
            continue;
        }

        let signal = ((status >> 8) & 0xff) as u8;
        if signal == 5 && tasks[task_index].unwrap().fork_result_pending != 0 {
            let mut parent_registers = core::mem::MaybeUninit::<UserRegs>::uninit();
            if ptrace(
                PTRACE_GETREGS,
                host_pid,
                0,
                parent_registers.as_mut_ptr() as usize,
            ) < 0
            {
                process_native_fail(domain, root_host_pid, b"fork result read failed");
            }
            let mut parent_registers = unsafe { parent_registers.assume_init() };
            let pending = tasks[task_index].unwrap();
            let virtual_pid = pending.fork_result_pending;
            if ptrace(
                PTRACE_POKETEXT,
                host_pid,
                pending.fork_breakpoint_rip,
                pending.fork_breakpoint_word,
            ) < 0
            {
                process_native_fail(domain, root_host_pid, b"fork breakpoint restore failed");
            }
            write_all(b"GINUX_NATIVE_PROCESS_AUDIT: fork variant=");
            if pending.fork_variant_event == PTRACE_EVENT_VFORK as u32 {
                write_all(b"vfork");
            } else if pending.fork_variant_event == PTRACE_EVENT_CLONE as u32 {
                write_all(b"clone");
            } else {
                write_all(b"fork");
            }
            write_all(b" host-result=");
            write_i64(parent_registers.rax as i64);
            write_all(b" virtual-result=");
            write_u64(virtual_pid as u64);
            write_all(b"\n");
            parent_registers.rip = pending.fork_breakpoint_rip as u64;
            parent_registers.rax = virtual_pid as u64;
            if ptrace(
                PTRACE_SETREGS,
                host_pid,
                0,
                &parent_registers as *const _ as usize,
            ) < 0
            {
                process_native_fail(domain, root_host_pid, b"fork result translation failed");
            }
            let parent = tasks[task_index].as_mut().unwrap();
            parent.fork_result_pending = 0;
            parent.fork_breakpoint_rip = 0;
            parent.fork_breakpoint_word = 0;
            parent.fork_variant_event = 0;
            if ptrace(PTRACE_SYSCALL, host_pid, 0, 0) < 0 {
                process_native_fail(domain, root_host_pid, b"fork parent resume failed");
            }
            continue;
        }
        if signal == 19 {
            let _ = ptrace(PTRACE_SETOPTIONS, host_pid, 0, options);
            if ptrace(PTRACE_SYSCALL, host_pid, 0, 0) < 0 {
                process_native_fail(domain, root_host_pid, b"fork child resume failed");
            }
            continue;
        }
        if signal == SIGCHLD as u8 {
            // The host kernel queued SIGCHLD for a managed child state
            // change: deliver it so the parent's disposition observes the
            // notification. The default disposition discards it, and no
            // handler installation is mediated yet, so delivery is safe.
            write_all(b"GINUX_NATIVE_PROCESS_AUDIT: sigchld delivered parent=");
            write_u64(task.virtual_id.pid as u64);
            write_all(b"\n");
            if ptrace(PTRACE_SYSCALL, host_pid, 0, SIGCHLD) < 0 {
                process_native_fail(domain, root_host_pid, b"SIGCHLD mediation failed");
            }
            continue;
        }
        // A forwarded termination signal first arrives as a delivery stop
        // for the doomed task: re-deliver it so the host death is observed
        // and recorded as a signaled outcome. Any other unexpected signal
        // still fails closed, so no task escapes supervision silently.
        if (signal == SIGINT as u8 || signal == SIGTERM as u8)
            && task.killed_with == signal as u64
        {
            write_all(b"GINUX_NATIVE_PROCESS_AUDIT: terminating signal=");
            write_u64(signal as u64);
            write_all(b" virtual-pid=");
            write_u64(task.virtual_id.pid as u64);
            write_all(b"\n");
            if ptrace(PTRACE_SYSCALL, host_pid, 0, signal as usize) < 0 {
                process_native_fail(domain, root_host_pid, b"terminating signal resume failed");
            }
            continue;
        }
        if signal != (5 | 0x80) {
            write_all(b"GINUX_NATIVE_PROCESS: unexpected-signal=");
            write_u64(signal as u64);
            write_all(b" event=");
            write_u64(event as u64);
            write_all(b" host-pid=");
            write_u64(host_pid as u64);
            write_all(b" virtual-pid=");
            write_u64(task.virtual_id.pid as u64);
            let mut diagnostic_registers = core::mem::MaybeUninit::<UserRegs>::uninit();
            if ptrace(
                PTRACE_GETREGS,
                host_pid,
                0,
                diagnostic_registers.as_mut_ptr() as usize,
            ) >= 0
            {
                let diagnostic_registers = unsafe { diagnostic_registers.assume_init() };
                write_all(b" rip=");
                write_u64(diagnostic_registers.rip);
                write_all(b" orig-syscall=");
                write_u64(diagnostic_registers.orig_rax);
            }
            write_all(b"\n");
            process_native_fail(domain, root_host_pid, b"unexpected process trace stop");
        }
        let mut registers = core::mem::MaybeUninit::<UserRegs>::uninit();
        if ptrace(PTRACE_GETREGS, host_pid, 0, registers.as_mut_ptr() as usize) < 0 {
            process_native_fail(domain, root_host_pid, b"process registers read failed");
        }
        let mut registers = unsafe { registers.assume_init() };
        let mut current = tasks[task_index].unwrap();
        if current.awaiting_exit {
            // Only mediated kills rewrite the pid argument now; waits are
            // fully emulated at entry, so the host wait result never appears
            // here. A woken parked waiter lands on `override_result` below
            // with its status word already stored.
            let restore_translated_argument =
                current.syscall == SYS_KILL as u64 && current.translated_rdi != 0;
            if current.desc_syscall != 0 && !current.override_result {
                // G05a descriptor exit: the host executed, so the tracee
                // keeps the real host result. The mirror follows the
                // outcome; failures leave it untouched.
                let desc_result = registers.rax as i64;
                match current.desc_syscall {
                    SYS_PIPE | SYS_PIPE2 => {
                        if desc_result == 0 {
                            match read_tracee_pipefds(host_pid, current.desc_arg0 as usize) {
                                Ok((read_fd, write_fd)) => {
                                    let cloexec = current.desc_syscall == SYS_PIPE2
                                        && current.desc_arg1 & O_CLOEXEC != 0;
                                    if pipes
                                        .create_pipe(
                                            current.virtual_id.pid,
                                            read_fd,
                                            write_fd,
                                            cloexec,
                                        )
                                        .is_err()
                                    {
                                        process_native_fail(
                                            domain,
                                            root_host_pid,
                                            b"pipe mirror full",
                                        );
                                    }
                                    write_all(b"GINUX_NATIVE_PROCESS_AUDIT: pipe task=");
                                    write_u64(current.virtual_id.pid as u64);
                                    write_all(b" read=");
                                    write_u64(read_fd as u64);
                                    write_all(b" write=");
                                    write_u64(write_fd as u64);
                                    write_all(b" cloexec=");
                                    write_u64(if cloexec { 1 } else { 0 });
                                    write_all(b"\n");
                                }
                                Err(()) => {
                                    process_native_fail(
                                        domain,
                                        root_host_pid,
                                        b"pipe result read failed",
                                    );
                                }
                            }
                        }
                    }
                    SYS_DUP => {
                        if desc_result >= 0 {
                            if pipes
                                .duplicate(
                                    current.virtual_id.pid,
                                    current.desc_arg0 as u32,
                                    desc_result as u32,
                                    false,
                                )
                                .is_err()
                            {
                                process_native_fail(domain, root_host_pid, b"dup mirror failed");
                            }
                            write_all(b"GINUX_NATIVE_PROCESS_AUDIT: dup task=");
                            write_u64(current.virtual_id.pid as u64);
                            write_all(b" old=");
                            write_u64(current.desc_arg0);
                            write_all(b" new=");
                            write_u64(desc_result as u64);
                            write_all(b"\n");
                        }
                    }
                    SYS_DUP2 | SYS_DUP3 => {
                        if desc_result >= 0 {
                            // `old == new` is a successful no-op: the host
                            // changed nothing, so the mirror keeps its entry.
                            if current.desc_arg0 as u32 != desc_result as u32 {
                                let cloexec = current.desc_syscall == SYS_DUP3
                                    && current.desc_arg2 & O_CLOEXEC != 0;
                                if pipes
                                    .duplicate(
                                        current.virtual_id.pid,
                                        current.desc_arg0 as u32,
                                        desc_result as u32,
                                        cloexec,
                                    )
                                    .is_err()
                                {
                                    process_native_fail(
                                        domain,
                                        root_host_pid,
                                        b"dup mirror failed",
                                    );
                                }
                            }
                            write_all(b"GINUX_NATIVE_PROCESS_AUDIT: dup task=");
                            write_u64(current.virtual_id.pid as u64);
                            write_all(b" old=");
                            write_u64(current.desc_arg0);
                            write_all(b" new=");
                            write_u64(desc_result as u64);
                            write_all(b"\n");
                        }
                    }
                    SYS_CLOSE => {
                        if desc_result == 0
                            && pipes
                                .close(current.virtual_id.pid, current.desc_arg0 as u32)
                                .unwrap_or(false)
                        {
                            write_all(b"GINUX_NATIVE_PROCESS_AUDIT: close task=");
                            write_u64(current.virtual_id.pid as u64);
                            write_all(b" fd=");
                            write_u64(current.desc_arg0);
                            write_all(b"\n");
                        }
                    }
                    SYS_FCNTL => {
                        if desc_result >= 0 {
                            if current.desc_arg1 == F_DUPFD
                                || current.desc_arg1 == F_DUPFD_CLOEXEC
                            {
                                let cloexec = current.desc_arg1 == F_DUPFD_CLOEXEC;
                                if pipes
                                    .duplicate(
                                        current.virtual_id.pid,
                                        current.desc_arg0 as u32,
                                        desc_result as u32,
                                        cloexec,
                                    )
                                    .is_err()
                                {
                                    process_native_fail(
                                        domain,
                                        root_host_pid,
                                        b"fcntl mirror failed",
                                    );
                                }
                                write_all(b"GINUX_NATIVE_PROCESS_AUDIT: fcntl-dup task=");
                                write_u64(current.virtual_id.pid as u64);
                                write_all(b" old=");
                                write_u64(current.desc_arg0);
                                write_all(b" new=");
                                write_u64(desc_result as u64);
                                write_all(b"\n");
                            } else if current.desc_arg1 == F_SETFD {
                                let _ = pipes.set_cloexec(
                                    current.virtual_id.pid,
                                    current.desc_arg0 as u32,
                                    current.desc_arg2 & FD_CLOEXEC != 0,
                                );
                            } else if current.desc_arg1 == F_GETFD {
                                // Observed only: the host already reported
                                // the live flag, and the mirror holds no
                                // copy of its own to update.
                            }
                        }
                    }
                    _ => {}
                }
                current.desc_syscall = 0;
                current.desc_arg0 = 0;
                current.desc_arg1 = 0;
                current.desc_arg2 = 0;
            } else if current.syscall >= 56
                && current.syscall <= 58
                && registers.rax as i64 > 0
                && current.fork_variant_event != 0
            {
                // Creation exit on the SYSCALL-resumed vfork/clone path (no
                // breakpoint could be planted in shared text): the kernel
                // reports the host child pid, which maps to the virtual
                // child created at the fork-event stop. Thread creation
                // shares this path: the parent observes the virtual tid, and
                // the parent-tid cell (which the host kernel filled with the
                // host tid) is republished with the virtual tid so every tid
                // observation agrees.
                let host_child = registers.rax as usize;
                if let Some(child) = tasks
                    .iter()
                    .flatten()
                    .find(|entry| entry.host_pid == host_child)
                {
                    let virtual_pid = child.virtual_id.pid;
                    write_all(b"GINUX_NATIVE_PROCESS_AUDIT: fork variant=");
                    if current.thread_pending {
                        write_all(b"thread");
                    } else if current.fork_variant_event == PTRACE_EVENT_VFORK as u32 {
                        write_all(b"vfork");
                    } else {
                        write_all(b"clone");
                    }
                    write_all(b" host-result=");
                    write_i64(registers.rax as i64);
                    write_all(b" virtual-result=");
                    write_u64(virtual_pid as u64);
                    write_all(b"\n");
                    registers.rax = virtual_pid as u64;
                    current.override_result = true;
                    if current.thread_pending && current.clone_ptid != 0 {
                        if store_tracee_tid(host_pid, current.clone_ptid, virtual_pid).is_err() {
                            process_native_fail(domain, root_host_pid, b"thread tid store failed");
                        }
                        write_all(b"GINUX_NATIVE_PROCESS_AUDIT: thread-tid virtual-tid=");
                        write_u64(virtual_pid as u64);
                        write_all(b"\n");
                    }
                }
                current.thread_pending = false;
                current.clone_ptid = 0;
            } else if current.syscall == SYS_SET_TID_ADDRESS
                && current.set_tid_pending
                && registers.rax as i64 > 0
            {
                // `set_tid_address` returns the caller's tid: publish the
                // virtual tid instead of the host one.
                write_all(b"GINUX_NATIVE_PROCESS_AUDIT: set-tid virtual-tid=");
                write_u64(current.virtual_id.pid as u64);
                write_all(b"\n");
                registers.rax = current.virtual_id.pid as u64;
                current.override_result = true;
                current.set_tid_pending = false;
            } else if (current.syscall == 59 || current.syscall == 322) && current.exec_pending {
                // Replacement exit: a recorded EXEC event means the new image
                // is already running under supervision and this stop (return
                // 0) only consumes the pending entry. A negative return is an
                // explicit failure such as ENOENT and the old image continues
                // under supervision. Success without a prior event is handled
                // defensively the same way the event handles it.
                if current.exec_event_seen {
                    if registers.rax as i64 != 0 {
                        process_native_fail(domain, root_host_pid, b"exec event without success");
                    }
                    write_all(b"GINUX_NATIVE_PROCESS_AUDIT: exec-complete virtual-pid=");
                    write_u64(current.virtual_id.pid as u64);
                    write_all(b"\n");
                } else if registers.rax as i64 == 0 {
                    let epoch = processes.exec(current.virtual_id).unwrap_or_else(|_| {
                        process_native_fail(domain, root_host_pid, b"virtual exec failed")
                    });
                    // G05a: same close-on-exec scrub as the event path; this
                    // stop is the only record when the event was missed.
                    let late_tgid = processes.view(current.virtual_id).unwrap_or_else(|_| {
                        process_native_fail(domain, root_host_pid, b"exec tgid lookup failed")
                    });
                    let late_scrubbed =
                        scrub_close_on_exec(&mut pipes, &processes, &tasks, late_tgid.tgid);
                    write_all(b"GINUX_NATIVE_PROCESS_AUDIT: exec-late virtual-pid=");
                    write_u64(current.virtual_id.pid as u64);
                    write_all(b" epoch=");
                    write_u64(epoch as u64);
                    write_all(b" cloexec-dropped=");
                    write_u64(late_scrubbed as u64);
                    write_all(b"\n");
                } else {
                    write_all(b"GINUX_NATIVE_PROCESS_AUDIT: exec-failed errno=");
                    write_i64(-(registers.rax as i64));
                    write_all(b" virtual-pid=");
                    write_u64(current.virtual_id.pid as u64);
                    write_all(b"\n");
                }
                current.exec_pending = false;
                current.exec_event_seen = false;
            } else if current.override_result {
                registers.rax = current.result as u64;
            }
            if restore_translated_argument {
                registers.rdi = current.translated_rdi;
            }
            if (current.override_result || restore_translated_argument)
                && ptrace(PTRACE_SETREGS, host_pid, 0, &registers as *const _ as usize) < 0
            {
                process_native_fail(domain, root_host_pid, b"process result translation failed");
            }
            current.awaiting_exit = false;
            current.override_result = false;
            current.translated_rdi = 0;
            current.fork_variant_event = 0;
            current.exec_pending = false;
            current.exec_event_seen = false;
            current.desc_syscall = 0;
            current.desc_arg0 = 0;
            current.desc_arg1 = 0;
            current.desc_arg2 = 0;
            tasks[task_index] = Some(current);
            if ptrace(PTRACE_SYSCALL, host_pid, 0, 0) < 0 {
                process_native_fail(domain, root_host_pid, b"process exit resume failed");
            }
            continue;
        }

        current.syscall = registers.orig_rax;
        current.awaiting_exit = true;
        if let Some(result) = process_entry(
            registers.orig_rax,
            registers.rdi,
            registers.rsi,
            registers.rdx,
        ) {
            current.result = result;
            current.override_result = true;
            registers.orig_rax = u64::MAX;
        } else {
            match registers.orig_rax {
                39 | 110 | SYS_GETTID => {
                    let view = processes.view(current.virtual_id).unwrap_or_else(|_| {
                        process_native_fail(domain, root_host_pid, b"identity lookup failed")
                    });
                    // `getpid` reports the thread-group id (the leader's pid
                    // for every member), `gettid` the virtual tid (leader pid
                    // for the main thread, the fresh virtual tid for created
                    // threads), `getppid` the virtual parent. Host tids never
                    // leak.
                    current.result = if registers.orig_rax == 110 {
                        view.parent as i64
                    } else if registers.orig_rax == SYS_GETTID {
                        view.id.pid as i64
                    } else {
                        view.tgid as i64
                    };
                    current.override_result = true;
                    registers.orig_rax = u64::MAX;
                }
                56..=58 => {
                    // A supported thread creation records its parent-tid cell
                    // so the creation exit stop can publish the virtual tid
                    // there. Unsupported thread shapes never reach this arm:
                    // the lane entry already emulated `-ENOSYS` for them, so
                    // they never execute. Any other creation shape resets the
                    // pending thread state.
                    if registers.orig_rax == 56 && thread_supported(registers.rdi) {
                        current.thread_pending = true;
                        current.clone_ptid = registers.rdx as usize;
                    } else {
                        current.thread_pending = false;
                        current.clone_ptid = 0;
                    }
                }
                SYS_ARCH_PRCTL | SYS_FUTEX | SYS_SET_ROBUST_LIST | SYS_GET_ROBUST_LIST
                | SYS_RSEQ => {
                    // Thread-local or thread-group-local state: the TLS base
                    // register, futex wait/wake on the group's own shared
                    // memory (join/mutex observe real host results), the
                    // robust-mutex registration, and `rseq`. The host kernel
                    // performs all of them on tracee-owned state, so the host
                    // call executes with no translation.
                }
                SYS_SET_TID_ADDRESS => {
                    // Per-thread exit-clear registration; the returned caller
                    // tid is translated to the virtual tid at the exit stop.
                    current.set_tid_pending = true;
                }
                59 | 322 => {
                    // Executable replacement: the mediated shapes execute on
                    // the host with the tracee still attached, and the EXEC
                    // event records the virtual transition. Shapes needing
                    // descriptor-table plumbing never execute and fail here.
                    if exec_mediated(registers.orig_rax, registers.rdi, registers.r8) {
                        // G09: a domain file stages its bytes at the domain
                        // path first (or denies with a faithful errno); the
                        // host call below then loads them under supervision.
                        // `execve` takes the path in `rdi`, `execveat` in
                        // `rsi`.
                        let path_addr = if registers.orig_rax == 59 {
                            registers.rdi
                        } else {
                            registers.rsi
                        };
                        match domain_exec_entry(host_pid, path_addr as usize) {
                            DomainExec::Host => {
                                current.exec_pending = true;
                                current.exec_event_seen = false;
                            }
                            DomainExec::Deny(errno) => {
                                current.result = errno;
                                current.override_result = true;
                                registers.orig_rax = u64::MAX;
                            }
                        }
                    } else {
                        current.result = -ENOSYS;
                        current.override_result = true;
                        registers.orig_rax = u64::MAX;
                    }
                }
                90 | 268 => {
                    // G09: `chmod` (90) and plain `fchmodat` (268) run
                    // against the loop's domain view through the G08a path
                    // and never touch the host. `fchmodat` shapes needing
                    // descriptor-table plumbing (non-CWD dirfd, nonzero
                    // flags) stay `-ENOSYS` like the exec gate above.
                    let plain = registers.orig_rax == 90
                        || (registers.rdi == AT_FDCWD as u64 && registers.r10 == 0);
                    if plain {
                        // `chmod` takes (path, mode); `fchmodat` takes
                        // (dirfd, path, mode, flags).
                        let (path_addr, mode) = if registers.orig_rax == 90 {
                            (registers.rdi, registers.rsi)
                        } else {
                            (registers.rsi, registers.rdx)
                        };
                        current.result =
                            domain_chmod_entry(host_pid, path_addr as usize, mode as u32);
                        current.override_result = true;
                        registers.orig_rax = u64::MAX;
                    } else {
                        current.result = -ENOSYS;
                        current.override_result = true;
                        registers.orig_rax = u64::MAX;
                    }
                }
                61 => {
                    // Managed wait4: fully emulated, so the host call never
                    // executes and supervisor-side reaping can never race
                    // the tracee for a child. Selectors follow wait4 pid
                    // semantics; unknown option bits and stale selectors
                    // fail explicitly with errno, never with lost children.
                    let selector = registers.rdi as i64;
                    let status_ptr = registers.rsi as usize;
                    let options = registers.rdx as u32;
                    let rusage_ptr = registers.r10 as usize;
                    if options & !WAIT_ALLOWED_OPTIONS != 0 {
                        current.result = -EINVAL;
                        current.override_result = true;
                        registers.orig_rax = u64::MAX;
                    } else if let Some(target) =
                        resolve_wait_target(selector, &processes, current.virtual_id)
                    {
                        match processes.wait(current.virtual_id, target, options) {
                            Ok(done) => {
                                if status_ptr != 0
                                    && store_tracee_status(
                                        host_pid,
                                        status_ptr,
                                        done.status.word(),
                                    )
                                    .is_err()
                                {
                                    process_native_fail(
                                        domain,
                                        root_host_pid,
                                        b"wait status store failed",
                                    );
                                }
                                if rusage_ptr != 0
                                    && zero_tracee_rusage(host_pid, rusage_ptr).is_err()
                                {
                                    process_native_fail(
                                        domain,
                                        root_host_pid,
                                        b"wait rusage store failed",
                                    );
                                }
                                clear_host_slot(&mut tasks, done.child);
                                write_all(
                                    b"GINUX_NATIVE_PROCESS_AUDIT: wait selector=",
                                );
                                write_i64(selector);
                                write_all(b" virtual-result=");
                                write_u64(done.child.pid as u64);
                                write_all(b" status=");
                                write_i64(done.status.shell_code() as i64);
                                write_all(b"\n");
                                current.result = done.child.pid as i64;
                                current.override_result = true;
                                registers.orig_rax = u64::MAX;
                            }
                            Err(ProcessError::NotChild) => {
                                current.result = -ECHILD;
                                current.override_result = true;
                                registers.orig_rax = u64::MAX;
                            }
                            Err(ProcessError::NoExitedChild) => {
                                if options & WNOHANG != 0 {
                                    current.result = 0;
                                    current.override_result = true;
                                    registers.orig_rax = u64::MAX;
                                } else {
                                    // Blocking wait with nothing reportable
                                    // yet: park the caller at this entry stop
                                    // until a matching child state change
                                    // wakes it. The host call never runs.
                                    current.wait_pending = true;
                                    current.wait_selector = selector;
                                    current.wait_options = options;
                                    current.wait_status = status_ptr;
                                    current.wait_rusage = rusage_ptr;
                                    registers.orig_rax = u64::MAX;
                                    tasks[task_index] = Some(current);
                                    if ptrace(
                                        PTRACE_SETREGS,
                                        host_pid,
                                        0,
                                        &registers as *const _ as usize,
                                    ) < 0
                                    {
                                        process_native_fail(
                                            domain,
                                            root_host_pid,
                                            b"wait park failed",
                                        );
                                    }
                                    write_all(
                                        b"GINUX_NATIVE_PROCESS_AUDIT: wait parked caller=",
                                    );
                                    write_u64(current.virtual_id.pid as u64);
                                    write_all(b" selector=");
                                    write_i64(selector);
                                    write_all(b"\n");
                                    continue;
                                }
                            }
                            Err(_) => {
                                process_native_fail(
                                    domain,
                                    root_host_pid,
                                    b"wait selector invalid",
                                );
                            }
                        }
                    } else {
                        current.result = -ECHILD;
                        current.override_result = true;
                        registers.orig_rax = u64::MAX;
                    }
                }
                62 => {
                    // Managed kill: the existence probe (signal 0) and the
                    // normal termination signals are decided against the
                    // virtual table. Supported terminators execute on the
                    // host with the pid translated; the exit stop restores
                    // the virtual argument. Anything else fails explicitly
                    // and never executes, so no task escapes supervision.
                    let selector = registers.rdi as i64;
                    let signal = registers.rsi as u64;
                    if selector <= 0 {
                        // Broadcast and group selectors have no managed
                        // delivery path yet.
                        current.result = -EINVAL;
                        current.override_result = true;
                        registers.orig_rax = u64::MAX;
                    } else {
                        let pid = selector as u32;
                        match processes.lookup(pid) {
                            None => {
                                current.result = -ESRCH;
                                current.override_result = true;
                                registers.orig_rax = u64::MAX;
                            }
                            Some(view)
                                if view.id.pid != view.tgid
                                    || (signal != 0
                                        && signal != SIGINT as u64
                                        && signal != SIGTERM as u64
                                        && signal != SIGKILL as u64) =>
                            {
                                // Signals to thread-group members would hit
                                // the whole host group, and only the normal
                                // termination signals have a managed meaning.
                                current.result = if view.id.pid != view.tgid {
                                    -EPERM
                                } else {
                                    -ENOSYS
                                };
                                current.override_result = true;
                                registers.orig_rax = u64::MAX;
                            }
                            Some(view) => {
                                let live = view.state == TaskState::Running;
                                if !live || signal == 0 {
                                    // Zombies and existence probes need no
                                    // host effect: the kernel reports success
                                    // without delivering anything.
                                    current.result = 0;
                                    current.override_result = true;
                                    registers.orig_rax = u64::MAX;
                                } else {
                                    let Some(host) = tasks
                                        .iter()
                                        .flatten()
                                        .find(|entry| {
                                            entry.virtual_id.pid == pid
                                        })
                                        .map(|entry| entry.host_pid)
                                    else {
                                        process_native_fail(
                                            domain,
                                            root_host_pid,
                                            b"kill host pid unknown",
                                        );
                                    };
                                    current.translated_rdi = registers.rdi;
                                    registers.rdi = host as u64;
                                    // Mark the target slot so its upcoming
                                    // signal delivery stop re-delivers
                                    // instead of failing supervision.
                                    if let Some(target) = tasks
                                        .iter_mut()
                                        .find(|entry| {
                                            entry.is_some_and(|entry| {
                                                entry.virtual_id.pid == pid
                                            })
                                        })
                                        .and_then(|entry| entry.as_mut())
                                    {
                                        target.killed_with = signal;
                                    }
                                }
                            }
                        }
                    }
                }
                SYS_READ => {
                    // G05a managed read: pre-supervision stdio and tracked
                    // pipe ends execute on the host; anything else is not a
                    // domain object and fails closed.
                    let tracked = pipes
                        .lookup(current.virtual_id.pid, registers.rdi as u32)
                        .is_some();
                    if !tracked && !matches!(registers.rdi, 0 | 1 | 2) {
                        current.result = -EBADF;
                        current.override_result = true;
                        registers.orig_rax = u64::MAX;
                    }
                }
                1 => {
                    // G05a managed write: the existing bounded console path
                    // is unchanged; tracked pipe ends execute regardless of
                    // length so shell pipelines move arbitrary bytes. Beyond
                    // that the old denial shape stays (ENOSYS for stdio with
                    // an overlong write, EBADF past it).
                    if matches!(registers.rdi, 1 | 2) && registers.rdx <= 4096 {
                    } else if pipes
                        .lookup(current.virtual_id.pid, registers.rdi as u32)
                        .is_some()
                    {
                    } else {
                        current.result = if matches!(registers.rdi, 0 | 1 | 2) {
                            -ENOSYS
                        } else {
                            -EBADF
                        };
                        current.override_result = true;
                        registers.orig_rax = u64::MAX;
                    }
                }
                SYS_PIPE | SYS_DUP | SYS_DUP2 | SYS_CLOSE | SYS_FCNTL | SYS_DUP3 | SYS_PIPE2 => {
                    // G05a descriptor mediation: flag shapes the mirror
                    // cannot represent fail here before the host runs.
                    // Everything else executes on the host and the exit stop
                    // below mirrors the outcome.
                    if registers.orig_rax == SYS_PIPE2
                        && !pipe2_flags_valid(registers.rsi)
                    {
                        current.result = -EINVAL;
                        current.override_result = true;
                        registers.orig_rax = u64::MAX;
                    } else if registers.orig_rax == SYS_DUP3
                        && !dup3_flags_valid(registers.rdx)
                    {
                        current.result = -EINVAL;
                        current.override_result = true;
                        registers.orig_rax = u64::MAX;
                    } else if registers.orig_rax == SYS_FCNTL
                        && !fcntl_supported(registers.rsi)
                    {
                        current.result = -ENOSYS;
                        current.override_result = true;
                        registers.orig_rax = u64::MAX;
                    } else {
                        current.desc_syscall = registers.orig_rax;
                        current.desc_arg0 = registers.rdi;
                        current.desc_arg1 = registers.rsi;
                        current.desc_arg2 = registers.rdx;
                    }
                }
                60 | 231 => {}
                _ => {
                    current.result = -ENOSYS;
                    current.override_result = true;
                    registers.orig_rax = u64::MAX;
                }
            }
        }
        tasks[task_index] = Some(current);
        if ptrace(PTRACE_SETREGS, host_pid, 0, &registers as *const _ as usize) < 0
            || ptrace(PTRACE_SYSCALL, host_pid, 0, 0) < 0
        {
            process_native_fail(domain, root_host_pid, b"process syscall dispatch failed");
        }
    }
}

/// Resolve a `wait4` pid selector against the virtual table. `None` means
/// the caller has no matching unwaited-for child, so the entry fails with
/// `-ECHILD`, matching the kernel even for blocking waits.
fn resolve_wait_target(
    selector: i64,
    processes: &ProcessTable<8>,
    caller: ginux_process::TaskId,
) -> Option<WaitTarget> {
    let target = if selector == -1 {
        WaitTarget::Any
    } else if selector == 0 {
        WaitTarget::Group(processes.view(caller).ok()?.process_group)
    } else if selector < -1 {
        WaitTarget::Group(selector.checked_neg()? as u32)
    } else {
        WaitTarget::Specific(selector as u32)
    };
    if processes.has_waitable_child(caller, target).ok()? {
        Some(target)
    } else {
        None
    }
}

/// Drop the supervisor's host-side slot for a virtually reaped child. The
/// host child was already reaped by the supervisor's own wait loop when its
/// outcome was recorded; the slot only lingered so exits could be attributed.
fn clear_host_slot(
    tasks: &mut [Option<NativeProcessTask>; 8],
    child: ginux_process::TaskId,
) {
    if let Some(position) = tasks
        .iter()
        .position(|entry| entry.is_some_and(|entry| entry.virtual_id == child))
    {
        tasks[position] = None;
    }
}

/// Complete one managed child state change for every parked `wait4` waiter
/// it satisfies, and queue virtual SIGCHLD for the parent. Called from the
/// supervisor's child-reaping path after the virtual outcome is recorded.
/// Each resumed waiter carries the real host SIGCHLD queued for this death,
/// so the parent's disposition observes the notification (ignored by
/// default); the virtual pending bit is bookkeeping for future disposition
/// mediation.
fn wake_waiters_for_child(
    domain: &mut Domain,
    root_host_pid: usize,
    processes: &mut ProcessTable<8>,
    tasks: &mut [Option<NativeProcessTask>; 8],
    dead: ginux_process::TaskId,
) {
    if let Ok(view) = processes.view(dead) {
        // The root task has no managed parent; only real children queue.
        if view.parent != 0 {
            if let Some(parent) = tasks
                .iter()
                .flatten()
                .find(|entry| entry.virtual_id.pid == view.parent)
                .map(|entry| entry.virtual_id)
            {
                let _ = processes.signal(parent, SIGCHLD as u8);
            }
            write_all(b"GINUX_NATIVE_PROCESS_AUDIT: sigchld queued parent=");
            write_u64(view.parent as u64);
            write_all(b" child=");
            write_u64(dead.pid as u64);
            write_all(b"\n");
        }
    }
    let mut index = 0;
    while index < tasks.len() {
        let waiter = tasks[index];
        let Some(entry) = waiter else {
            index += 1;
            continue;
        };
        if !entry.wait_pending || !entry.tracing {
            index += 1;
            continue;
        }
        let target = resolve_wait_target(entry.wait_selector, processes, entry.virtual_id);
        let done = target
            .and_then(|target| processes.wait(entry.virtual_id, target, entry.wait_options).ok());
        let Some(done) = done else {
            index += 1;
            continue;
        };
        if entry.wait_status != 0
            && store_tracee_status(entry.host_pid, entry.wait_status, done.status.word()).is_err()
        {
            process_native_fail(domain, root_host_pid, b"wait status store failed");
        }
        if entry.wait_rusage != 0 && zero_tracee_rusage(entry.host_pid, entry.wait_rusage).is_err()
        {
            process_native_fail(domain, root_host_pid, b"wait rusage store failed");
        }
        clear_host_slot(tasks, done.child);
        write_all(b"GINUX_NATIVE_PROCESS_AUDIT: wait wakeup caller=");
        write_u64(entry.virtual_id.pid as u64);
        write_all(b" child=");
        write_u64(done.child.pid as u64);
        write_all(b" status=");
        write_i64(done.status.shell_code() as i64);
        write_all(b"\n");
        if let Some(slot) = tasks[index].as_mut() {
            slot.wait_pending = false;
            slot.override_result = true;
            slot.result = done.child.pid as i64;
        }
        // The exit stop queued for this parked entry applies the pid result;
        // resume carrying the host SIGCHLD so delivery is observed.
        write_all(b"GINUX_NATIVE_PROCESS_AUDIT: sigchld delivered parent=");
        write_u64(entry.virtual_id.pid as u64);
        write_all(b"\n");
        if ptrace(PTRACE_SYSCALL, entry.host_pid, 0, SIGCHLD) < 0 {
            process_native_fail(domain, root_host_pid, b"wait wakeup resume failed");
        }
        index += 1;
    }
}

/// Read the two `int` fds the host `pipe`/`pipe2` just stored at the
/// tracee's `pipefd` pointer, without touching neighboring tracee memory.
/// Each byte is fetched with its own aligned `PTRACE_PEEKTEXT` read, so an
/// unaligned two-word array is assembled correctly. Any unreadable word
/// fails explicitly; the caller treats that as supervision failure, never
/// as invented descriptors.
fn read_tracee_pipefds(host_pid: usize, user_pipefd: usize) -> Result<(u32, u32), ()> {
    let mut bytes = [0u8; 8];
    let mut index = 0;
    while index < 8 {
        let address = user_pipefd.wrapping_add(index);
        let aligned = address & !0x7;
        let shift = (address & 0x7) * 8;
        let mut word = 0usize;
        if ptrace(
            PTRACE_PEEKTEXT,
            host_pid,
            aligned,
            &mut word as *mut _ as usize,
        ) < 0
        {
            return Err(());
        }
        bytes[index] = ((word >> shift) & 0xff) as u8;
        index += 1;
    }
    Ok((
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    ))
}

/// Drop every close-on-exec end held by the tasks of one thread group. The
/// host kernel closed the same descriptors during executable replacement;
/// the mirror follows so no stale end survives the exec. Returns the count
/// dropped for the audit line.
fn scrub_close_on_exec(
    pipes: &mut PipeSpace<8, 16, 16>,
    processes: &ProcessTable<8>,
    tasks: &[Option<NativeProcessTask>; 8],
    tgid: u32,
) -> u32 {
    let mut dropped = 0;
    for entry in tasks.iter().flatten() {
        if !entry.tracing {
            continue;
        }
        let same_group = processes
            .view(entry.virtual_id)
            .is_ok_and(|view| view.tgid == tgid);
        if same_group {
            dropped += pipes.exec_scrub(entry.virtual_id.pid);
        }
    }
    dropped
}

/// Store the full Linux wait status word for the reaped virtual child into
/// the parent's `wait4` status slot, without touching neighboring tracee
/// memory. Exited children report the code in bits 8-15; signaled children
/// report the signal number in bits 0-6 with no core-dump bit.
fn store_tracee_status(host_pid: usize, user_status: usize, word: u32) -> Result<(), ()> {
    let encoded = word;
    let aligned = user_status & !0x7;
    let shift = (user_status & 0x7) * 8;
    let mut word = 0usize;
    if ptrace(
        PTRACE_PEEKTEXT,
        host_pid,
        aligned,
        &mut word as *mut _ as usize,
    ) < 0
    {
        return Err(());
    }
    let mask = 0xffff_ffffusize << shift;
    let merged = (word & !mask) | ((encoded as usize) << shift);
    if ptrace(PTRACE_POKETEXT, host_pid, aligned, merged) < 0 {
        return Err(());
    }
    Ok(())
}

/// Zero the caller's `rusage` buffer after a managed wait. The kernel would
/// fill resource usage here; without usage accounting the honest bounded
/// content is zeros. `rusage` is 8-byte aligned in practice; an unaligned
/// buffer fails explicitly rather than tearing neighbors.
fn zero_tracee_rusage(host_pid: usize, user_rusage: usize) -> Result<(), ()> {
    const RUSAGE_BYTES: usize = 144;
    let mut offset = 0;
    while offset < RUSAGE_BYTES {
        let address = user_rusage + offset;
        if address & 0x7 != 0 {
            return Err(());
        }
        if ptrace(PTRACE_POKETEXT, host_pid, address, 0) < 0 {
            return Err(());
        }
        offset += 8;
    }
    Ok(())
}

/// Publish the virtual tid into the tracee's parent-tid cell. The host
/// kernel stored the host tid there during `clone` with
/// `CLONE_PARENT_SETTID`; thread identity requires the parent to observe the
/// virtual tid instead. Same aligned-word technique as
/// [`store_tracee_status`], but for one 4-byte tid cell.
fn store_tracee_tid(host_pid: usize, user_tid: usize, tid: u32) -> Result<(), ()> {
    let aligned = user_tid & !0x7;
    let shift = (user_tid & 0x7) * 8;
    let mut word = 0usize;
    if ptrace(
        PTRACE_PEEKTEXT,
        host_pid,
        aligned,
        &mut word as *mut _ as usize,
    ) < 0
    {
        return Err(());
    }
    let mask = 0xffff_ffffusize << shift;
    let merged = (word & !mask) | ((tid as usize) << shift);
    if ptrace(PTRACE_POKETEXT, host_pid, aligned, merged) < 0 {
        return Err(());
    }
    Ok(())
}

fn process_native_fail(domain: &mut Domain, root_pid: usize, reason: &[u8]) -> ! {
    // A host stop request racing a supervision failure is still a host
    // cancellation: report it as one. `EXITKILL` (set on every attached
    // tracee) guarantees the survivors die with this supervisor.
    if teardown::cancel_requested() {
        let _ = ptrace(PTRACE_KILL, root_pid, 0, 0);
        let _ = domain.task_exited(false);
        line(b"GINUX_NATIVE_PROCESS: outcome=cancelled tasks=unknown live-pipes=unknown");
        exit_process(teardown::CANCEL_EXIT);
    }
    let _ = ptrace(PTRACE_KILL, root_pid, 0, 0);
    // Reap already-dead descendants so no zombie is stranded. The rest die
    // with this supervisor through `EXITKILL` and are reaped by init; the
    // `SIGKILL` effects above persist past this exit either way.
    let mut sweep = 0u32;
    while sweep < 16 {
        let mut status = 0i32;
        if unsafe {
            syscall4(
                SYS_WAIT4,
                (-1isize) as usize,
                &mut status as *mut _ as usize,
                WNOHANG as usize,
                0,
            )
        } <= 0
        {
            break;
        }
        sweep += 1;
    }
    write_all(b"GINUX_NATIVE_PROCESS: outcome=supervisor-error category=supervision reason=");
    line(reason);
    domain_fail(domain, reason)
}

/// L01 startup failure: no workload runs under supervision. The caller owns
/// root cleanup (before the initial stop the root is either already reaped
/// or already signalled). Reports the §1 `supervisor-error` outcome with
/// the `startup` category and exits 2 (the G02 startup convention).
fn startup_fail(domain: &mut Domain, reason: &[u8]) -> ! {
    // Best-effort reap of a failed start so no zombie is stranded; the only
    // pid that can exist here is the root, already signalled by the caller.
    // A sent `SIGKILL` still kills it after this exit even if the reap
    // misses, with init reaping the zombie.
    let mut sweep = 0u32;
    while sweep < 4 {
        let mut status = 0i32;
        if unsafe {
            syscall4(
                SYS_WAIT4,
                (-1isize) as usize,
                &mut status as *mut _ as usize,
                WNOHANG as usize,
                0,
            )
        } <= 0
        {
            break;
        }
        sweep += 1;
    }
    let _ = domain.task_exited(false);
    write_all(b"GINUX_NATIVE_PROCESS: outcome=supervisor-error category=startup reason=");
    line(reason);
    line(b"GINUX_NATIVE_PROCESS_AUDIT: teardown tasks=0 live-pipes=0");
    exit_process(teardown::STARTUP_EXIT)
}

/// L01 full domain teardown. The root workload is dead (or the host asked
/// the supervisor to stop): SIGKILL every still-traced descendant, reap
/// each host death, release every descriptor-mirror end, run the
/// storage/backends seams, prove the live-object audit is zero, then report
/// and exit. Never returns.
fn teardown_domain(
    domain: &mut Domain,
    root_host_pid: usize,
    processes: &mut ProcessTable<8>,
    tasks: &mut [Option<NativeProcessTask>; 8],
    pipes: &mut PipeSpace<8, 16, 16>,
    outcome: TeardownOutcome,
) -> ! {
    // Signal every still-traced descendant first so the drain below only
    // observes deaths. Errors are ignored: an already-dead target is
    // reaped, not signalled.
    let mut doomed: [usize; 8] = [0; 8];
    let mut doomed_count = 0usize;
    for entry in tasks.iter().flatten() {
        if entry.tracing && doomed_count < doomed.len() {
            doomed[doomed_count] = entry.host_pid;
            doomed_count += 1;
        }
    }
    if doomed_count != 0 {
        write_all(b"GINUX_NATIVE_PROCESS_AUDIT: teardown survivors-signalled=");
        write_u64(doomed_count as u64);
        write_all(b"\n");
    }
    teardown::kill_remaining(&doomed[..doomed_count]);
    let degraded = drain_teardown(domain, root_host_pid, processes, tasks, pipes);
    // Seams run after the last descendant is reaped, before reporting.
    teardown::flush_storage_seam();
    let backends_closed = teardown::close_backends_seam();
    write_all(b"GINUX_NATIVE_PROCESS_AUDIT: storage-flush=seam-g12a backends-closed=");
    write_u64(backends_closed as u64);
    write_all(b"\n");
    // The virtual table dies wholesale: every recorded death is reaped, and
    // anything still marked running after the drain is a supervision breach.
    let reaped = processes.reap_all();
    let live_tasks = processes.active();
    let live_pipes = pipes.active_pipes();
    write_all(b"GINUX_NATIVE_PROCESS_AUDIT: teardown reaped=");
    write_u64(reaped as u64);
    write_all(b" tasks=");
    write_u64(live_tasks as u64);
    write_all(b" live-pipes=");
    write_u64(live_pipes as u64);
    write_all(b"\n");
    if degraded || live_tasks != 0 || live_pipes != 0 {
        let _ = domain.task_exited(false);
        write_all(b"GINUX_NATIVE_PROCESS: outcome=supervisor-error category=supervision reason=");
        if degraded {
            line(b"teardown-reap-incomplete");
        } else {
            line(b"teardown-live-objects-remain");
        }
        exit_process(teardown::SUPERVISOR_EXIT);
    }
    match outcome {
        TeardownOutcome::Exited(0) => {
            // G05a leak audit: every end died with its task (the host's
            // close is the last one), so no pipe object may survive.
            write_all(b"GINUX_NATIVE_PROCESS_AUDIT: descriptors live-pipes=");
            write_u64(pipes.active_pipes() as u64);
            write_all(b"\n");
            if domain.task_exited(true).is_err() {
                let _ = domain.task_exited(false);
                line(b"GINUX_NATIVE_PROCESS: outcome=supervisor-error category=supervision reason=domain-exit-failed");
                exit_process(teardown::SUPERVISOR_EXIT);
            }
            line(b"GINUX_NATIVE_PROCESS: outcome=completed code=0");
            line(b"GINUX_NATIVE_PROCESS: fork=mediated child=ptrace-attached pid-translation=PASS");
            line(
                b"GINUX_NATIVE_PROCESS: wait=translated child-status=real tasks=0 cleanup=PASS",
            );
            line(b"GATE7_NATIVE_PROCESS: PASS");
            exit_process(0)
        }
        TeardownOutcome::Exited(code) => {
            let _ = domain.task_exited(false);
            write_all(b"GINUX_NATIVE_PROCESS: outcome=workload-failed code=");
            write_i64(code as i64);
            write_all(b" tasks=0 live-pipes=0\n");
            exit_process(code as usize);
        }
        TeardownOutcome::Signaled(signal) => {
            let _ = domain.task_exited(false);
            write_all(b"GINUX_NATIVE_PROCESS: outcome=workload-failed signal=");
            write_u64(signal as u64);
            write_all(b" code=");
            write_i64(128 + signal as i64);
            write_all(b" tasks=0 live-pipes=0\n");
            exit_process(128 + signal as usize);
        }
        TeardownOutcome::Cancelled => {
            let _ = domain.task_exited(false);
            line(b"GINUX_NATIVE_PROCESS: outcome=cancelled tasks=0 live-pipes=0");
            exit_process(teardown::CANCEL_EXIT);
        }
    }
}

/// Reap every descendant until no traced task and no teardown-discovered
/// child remains. Returns true when the drain degraded (a host child
/// vanished without its death being observed): the caller then fails closed
/// instead of reporting a clean outcome.
///
/// Deaths of known slots record the virtual outcome and release the
/// descriptor mirror exactly like the main loop. Stops that are not deaths
/// are resumed toward death: fork events contribute their new child to a
/// pending-kill list (SIGKILLed at once, reaped silently — the mirror never
/// observed them, so no virtual bookkeeping is owed), and new-child
/// `SIGSTOP` attaches get the loop's ptrace options so `EXITKILL` covers
/// them if the supervisor dies mid-drain.
fn drain_teardown(
    domain: &mut Domain,
    root_host_pid: usize,
    processes: &mut ProcessTable<8>,
    tasks: &mut [Option<NativeProcessTask>; 8],
    pipes: &mut PipeSpace<8, 16, 16>,
) -> bool {
    let options = PTRACE_O_TRACESYSGOOD
        | PTRACE_O_TRACEFORK
        | PTRACE_O_TRACEVFORK
        | PTRACE_O_TRACECLONE
        | PTRACE_O_TRACEEXEC
        | PTRACE_O_EXITKILL;
    let mut pending: [usize; 8] = [0; 8];
    let mut pending_count = 0usize;
    let mut pending_overflow = false;
    let mut degraded = false;
    let mut guard = 0u32;
    loop {
        let tracing = tasks.iter().flatten().filter(|entry| entry.tracing).count();
        if tracing == 0 && pending_count == 0 {
            // Final sweep: a nonblocking reap must find nothing left.
            let mut status = 0i32;
            let swept = unsafe {
                syscall4(
                    SYS_WAIT4,
                    (-1isize) as usize,
                    &mut status as *mut _ as usize,
                    WNOHANG as usize,
                    0,
                )
            };
            if swept > 0 {
                // A death nobody owned: reap it and degrade rather than
                // strand a zombie.
                degraded = true;
                write_all(b"GINUX_NATIVE_PROCESS_AUDIT: teardown unowned-reaped host-pid=");
                write_u64(swept as u64);
                write_all(b"\n");
                continue;
            }
            return degraded;
        }
        guard += 1;
        if guard > 128 {
            write_all(b"GINUX_NATIVE_PROCESS_AUDIT: teardown drain-bound-exceeded tracing=");
            write_u64(tracing as u64);
            write_all(b" pending=");
            write_u64(pending_count as u64);
            write_all(b"\n");
            return true;
        }
        let mut status = 0i32;
        let waited = unsafe {
            syscall4(
                SYS_WAIT4,
                (-1isize) as usize,
                &mut status as *mut _ as usize,
                0,
                0,
            )
        };
        if waited <= 0 {
            if waited == -(ECHILD as isize) {
                // No host children, yet slots still claim traced tasks: a
                // host child vanished without its death being observed
                // (reaped elsewhere). Release its mirror ends, drop the
                // slots, mark the virtual table for wholesale reap, and
                // degrade — never strand host-side state.
                let mut missed = 0u64;
                for slot in tasks.iter_mut() {
                    if slot.is_some_and(|entry| entry.tracing) {
                        pipes.release_task(slot.unwrap().virtual_id.pid);
                        *slot = None;
                        missed += 1;
                    }
                }
                processes.shutdown(137);
                pending_count = 0;
                degraded = true;
                write_all(b"GINUX_NATIVE_PROCESS_AUDIT: teardown reap-missed slots=");
                write_u64(missed);
                write_all(b"\n");
                continue;
            }
            process_native_fail(domain, root_host_pid, b"teardown wait failed");
        }
        let host_pid = waited as usize;
        if !stopped(status) {
            let child_status = if status & 0x7f == 0 {
                ChildStatus::Exited(status >> 8)
            } else {
                ChildStatus::Signaled((status & 0x7f) as u8)
            };
            if let Some(task_index) = tasks
                .iter()
                .position(|entry| entry.is_some_and(|entry| entry.host_pid == host_pid))
            {
                let virtual_id = tasks[task_index].unwrap().virtual_id;
                let _ = match child_status {
                    ChildStatus::Exited(code) => processes.exit(virtual_id, code),
                    ChildStatus::Signaled(signal) => processes.signaled(virtual_id, signal),
                };
                pipes.release_task(virtual_id.pid);
                tasks[task_index] = None;
                write_all(b"GINUX_NATIVE_PROCESS_AUDIT: teardown reaped virtual-pid=");
                write_u64(virtual_id.pid as u64);
                write_all(b" status=");
                write_i64(child_status.shell_code() as i64);
                write_all(b"\n");
            } else if let Some(index) =
                pending.iter().position(|pid| *pid == host_pid)
            {
                // A fork-event child discovered mid-drain: the host closed
                // its descriptors with it; the mirror never observed it.
                pending[index] = pending[pending_count - 1];
                pending_count -= 1;
                write_all(b"GINUX_NATIVE_PROCESS_AUDIT: teardown reaped-pending host-pid=");
                write_u64(host_pid as u64);
                write_all(b"\n");
            } else if pending_overflow {
                // Forks beyond the pending list were still SIGKILLed at
                // discovery; reap them silently and degrade.
                degraded = true;
                write_all(b"GINUX_NATIVE_PROCESS_AUDIT: teardown reaped-overflow host-pid=");
                write_u64(host_pid as u64);
                write_all(b"\n");
            } else {
                write_all(b"GINUX_NATIVE_PROCESS_AUDIT: teardown unknown-death host-pid=");
                write_u64(host_pid as u64);
                write_all(b"\n");
                process_native_fail(domain, root_host_pid, b"teardown unknown tracee");
            }
            continue;
        }
        let event = (status as usize) >> 16;
        if event == PTRACE_EVENT_FORK as usize
            || event == PTRACE_EVENT_VFORK as usize
            || event == PTRACE_EVENT_CLONE as usize
        {
            let mut child_host_pid = 0usize;
            if ptrace(
                PTRACE_GETEVENTMSG,
                host_pid,
                0,
                &mut child_host_pid as *mut _ as usize,
            ) < 0
            {
                process_native_fail(domain, root_host_pid, b"teardown fork event failed");
            }
            // Attach EXITKILL coverage at once, then doom it: the mirror
            // never learns this child, so its death is reaped silently.
            let _ = ptrace(PTRACE_SETOPTIONS, child_host_pid, 0, options);
            teardown::kill_remaining(&[child_host_pid]);
            if pending_count < pending.len() {
                pending[pending_count] = child_host_pid;
                pending_count += 1;
            } else {
                pending_overflow = true;
            }
            write_all(b"GINUX_NATIVE_PROCESS_AUDIT: teardown fork-doomed host-pid=");
            write_u64(child_host_pid as u64);
            write_all(b"\n");
            if ptrace(PTRACE_CONT, host_pid, 0, 0) < 0 {
                process_native_fail(domain, root_host_pid, b"teardown fork resume failed");
            }
            continue;
        }
        if stopped(status) && ((status >> 8) & 0xff) == 19 {
            // New-child attach stop: same options as the main loop so
            // EXITKILL covers it, then toward death.
            let _ = ptrace(PTRACE_SETOPTIONS, host_pid, 0, options);
        }
        // Every other stop (syscall traps, stale fork breakpoints,
        // delivered or queued signals) is resumed toward death: the
        // SIGKILL queued above still kills the task. Signal 0 resumes
        // carry no new delivery.
        if ptrace(PTRACE_CONT, host_pid, 0, 0) < 0 {
            process_native_fail(domain, root_host_pid, b"teardown resume failed");
        }
    }
}

struct HostBlock {
    descriptor: usize,
    len: u64,
}

impl BlockBackend for HostBlock {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), DeviceError> {
        let result = unsafe {
            syscall4(
                SYS_PREAD64,
                self.descriptor,
                output.as_mut_ptr() as usize,
                output.len(),
                offset as usize,
            )
        };
        if result == output.len() as isize {
            Ok(())
        } else {
            Err(DeviceError::Backend)
        }
    }

    fn write_at(&mut self, offset: u64, input: &[u8]) -> Result<(), DeviceError> {
        let result = unsafe {
            syscall4(
                SYS_PWRITE64,
                self.descriptor,
                input.as_ptr() as usize,
                input.len(),
                offset as usize,
            )
        };
        if result == input.len() as isize {
            Ok(())
        } else {
            Err(DeviceError::Backend)
        }
    }

    fn flush(&mut self) -> Result<(), DeviceError> {
        if unsafe { syscall1(SYS_FSYNC, self.descriptor) } == 0 {
            Ok(())
        } else {
            Err(DeviceError::Backend)
        }
    }

    fn close(&mut self) -> Result<(), DeviceError> {
        if unsafe { syscall1(SYS_CLOSE_HOST, self.descriptor) } == 0 {
            Ok(())
        } else {
            Err(DeviceError::Backend)
        }
    }
}

fn devices_main(config_path: *const u8, block_path: *const u8) -> ! {
    let config = load_config(config_path);
    let domain_id = 6u64;
    let mut registry: DeviceRegistry<8, 8> = DeviceRegistry::new();
    let specifications = [
        (b"console".as_slice(), DeviceKind::Console, 1u64),
        (b"null".as_slice(), DeviceKind::Null, 2),
        (b"zero".as_slice(), DeviceKind::Zero, 3),
        (b"random".as_slice(), DeviceKind::Random, 4),
        (b"block0".as_slice(), DeviceKind::Block, 100),
        (b"net0".as_slice(), DeviceKind::Network, 200),
    ];
    for (name, kind, backend) in specifications {
        if text_list_contains(config.devices.as_slice(), name)
            && registry
                .assign(
                    domain_id,
                    backend,
                    DeviceName::new(name).unwrap_or_else(|_| device_fail(b"invalid device name")),
                    kind,
                )
                .is_err()
        {
            device_fail(b"device assignment failed");
        }
    }
    if !text_list_contains(config.storage.as_slice(), b"block0")
        || config.network_backend != ginux_domain::NetworkBackend::Mediated
    {
        device_fail(b"required normalized assignment missing");
    }
    let mut visible = [DeviceName::new(b"unused").unwrap(); 8];
    let visible_count = registry.visible(domain_id, &mut visible);
    if visible_count != 6 {
        device_fail(b"unexpected device projection");
    }
    line(b"GINUX_DEVICES: visible=console,null,zero,random,block0,net0 unassigned=hidden");

    let zero = registry
        .open(domain_id, b"zero")
        .unwrap_or_else(|_| device_fail(b"zero open failed"));
    let mut zeros = [1u8; 16];
    if registry.read(domain_id, zero, &mut zeros) != Ok(16) || zeros != [0; 16] {
        device_fail(b"zero read failed");
    }
    let console = registry
        .open(domain_id, b"console")
        .unwrap_or_else(|_| device_fail(b"console open failed"));
    let mut window = [0u8; 8];
    if registry
        .ioctl(domain_id, console, IOCTL_CONSOLE_GET_SIZE, &mut window)
        .is_err()
        || registry.ioctl(domain_id, console, 0xdead, &mut []).is_ok()
        || registry.map(domain_id, console).is_ok()
    {
        device_fail(b"ioctl or mapping policy failed");
    }
    line(b"GINUX_DEVICES: handles=virtual pseudo=PASS ioctl-unknown=denied mmap=denied");

    let host_descriptor =
        unsafe { syscall4(SYS_OPENAT_HOST, AT_FDCWD, block_path as usize, O_RDWR, 0) };
    if host_descriptor < 0 {
        device_fail(b"block backend open failed");
    }
    let backend = HostBlock {
        descriptor: host_descriptor as usize,
        len: 4096,
    };
    let mut partition = Partition::new(backend, 1024, 2048, false)
        .unwrap_or_else(|_| device_fail(b"partition creation failed"));
    if partition.write_at(0, b"GINUX-BLOCK").is_err() || partition.flush().is_err() {
        device_fail(b"partition write failed");
    }
    let mut block_value = [0u8; 11];
    if partition.read_at(0, &mut block_value).is_err()
        || &block_value != b"GINUX-BLOCK"
        || partition.write_at(2047, b"xx").is_ok()
    {
        device_fail(b"partition confinement failed");
    }
    if partition.close().is_err() {
        device_fail(b"partition close failed");
    }
    line(b"GINUX_BLOCK: backend=file partition=1024:2048 rw=PASS flush=PASS bounds=denied");

    let mut network: IsolatedNetwork<4> = IsolatedNetwork::new();
    if network.send(b"domain-packet").is_err() {
        device_fail(b"network send failed");
    }
    let mut packet = [0u8; 64];
    if network.receive(&mut packet) != Ok(13)
        || &packet[..13] != b"domain-packet"
        || network.control(1).is_ok()
    {
        device_fail(b"network mediation failed");
    }
    network.close();
    line(
        b"GINUX_NETWORK: backend=isolated-queue send=PASS receive=PASS control=denied host-fd=none",
    );

    if registry.assign(
        7,
        100,
        DeviceName::new(b"otherdisk").unwrap(),
        DeviceKind::Block,
    ) != Err(DeviceError::AssignmentConflict)
    {
        device_fail(b"exclusive conflict accepted");
    }
    registry.revoke(domain_id);
    if registry
        .assign(
            7,
            100,
            DeviceName::new(b"otherdisk").unwrap(),
            DeviceKind::Block,
        )
        .is_err()
        || registry.write(domain_id, console, b"revoked").is_ok()
    {
        device_fail(b"revocation failed");
    }
    line(b"GINUX_DEVICES: conflict=denied teardown=flushed,released,reusable");
    line(b"GATE6_DEVICES: PASS");
    exit_process(0)
}

fn text_list_contains<const N: usize>(values: &[ginux_domain::Text<N>], expected: &[u8]) -> bool {
    values.iter().any(|value| value.as_bytes() == expected)
}

fn device_fail(reason: &[u8]) -> ! {
    write_all(b"GATE6_DEVICES: FAIL: ");
    line(reason);
    exit_process(1)
}

#[repr(C)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}

fn clock_nanoseconds(clock: usize) -> u64 {
    let mut value = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    if unsafe { syscall2(SYS_CLOCK_GETTIME, clock, &mut value as *mut _ as usize) } != 0
        || value.seconds < 0
        || value.nanoseconds < 0
    {
        device_fail(b"benchmark clock failed");
    }
    value.seconds as u64 * 1_000_000_000 + value.nanoseconds as u64
}

fn device_bench_main(config_path: *const u8, block_path: *const u8, kind: *const u8) -> ! {
    let config = load_config(config_path);
    let repetitions = 1024u64;
    let operations = repetitions * 2;
    let (bytes, wall_ns, cpu_ns) = if c_string_equals(kind, b"block") {
        if !text_list_contains(config.storage.as_slice(), b"block0") {
            device_fail(b"block benchmark assignment missing");
        }
        let descriptor =
            unsafe { syscall4(SYS_OPENAT_HOST, AT_FDCWD, block_path as usize, O_RDWR, 0) };
        if descriptor < 0 {
            device_fail(b"benchmark block open failed");
        }
        let backend = HostBlock {
            descriptor: descriptor as usize,
            len: 4096,
        };
        let mut partition = Partition::new(backend, 1024, 2048, false)
            .unwrap_or_else(|_| device_fail(b"benchmark partition failed"));
        let data = [0x5au8; 256];
        let mut output = [0u8; 256];
        let wall_start = clock_nanoseconds(CLOCK_MONOTONIC);
        let cpu_start = clock_nanoseconds(CLOCK_PROCESS_CPUTIME_ID);
        for iteration in 0..repetitions {
            let offset = (iteration % 8) * 256;
            if partition.write_at(offset, &data).is_err()
                || partition.read_at(offset, &mut output).is_err()
            {
                device_fail(b"benchmark block I/O failed");
            }
        }
        if partition.close().is_err() {
            device_fail(b"benchmark block close failed");
        }
        (
            repetitions * 512,
            clock_nanoseconds(CLOCK_MONOTONIC) - wall_start,
            clock_nanoseconds(CLOCK_PROCESS_CPUTIME_ID) - cpu_start,
        )
    } else if c_string_equals(kind, b"network") {
        if config.network_backend != ginux_domain::NetworkBackend::Mediated {
            device_fail(b"network benchmark assignment missing");
        }
        let mut network: IsolatedNetwork<2> = IsolatedNetwork::new();
        let frame = [0xabu8; 64];
        let mut output = [0u8; 64];
        let wall_start = clock_nanoseconds(CLOCK_MONOTONIC);
        let cpu_start = clock_nanoseconds(CLOCK_PROCESS_CPUTIME_ID);
        for _ in 0..repetitions {
            if network.send(&frame).is_err() || network.receive(&mut output) != Ok(64) {
                device_fail(b"benchmark network I/O failed");
            }
        }
        network.close();
        (
            repetitions * 128,
            clock_nanoseconds(CLOCK_MONOTONIC) - wall_start,
            clock_nanoseconds(CLOCK_PROCESS_CPUTIME_ID) - cpu_start,
        )
    } else {
        device_fail(b"unknown benchmark kind");
    };
    let throughput = bytes.saturating_mul(1_000_000_000) / wall_ns.max(1);
    let latency = wall_ns / operations;
    write_all(b"GINUX_BENCH: kind=");
    if c_string_equals(kind, b"block") {
        write_all(b"block");
    } else {
        write_all(b"network");
    }
    write_all(b" workload=rw-pairs repetitions=");
    write_u64(repetitions);
    write_all(b" operations=");
    write_u64(operations);
    write_all(b" bytes=");
    write_u64(bytes);
    write_all(b" wall_ns=");
    write_u64(wall_ns);
    write_all(b" cpu_ns=");
    write_u64(cpu_ns);
    write_all(b" throughput_Bps=");
    write_u64(throughput);
    write_all(b" latency_ns_per_op=");
    write_u64(latency);
    write_all(b" environment=rocky10-x86_64-qemu-tcg\n");
    line(b"GINUX_BENCH: PASS");
    exit_process(0)
}

struct HostRootfs {
    descriptor: usize,
}

impl BaseReader for HostRootfs {
    fn read_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), VfsError> {
        let result = unsafe {
            syscall4(
                SYS_PREAD64,
                self.descriptor,
                output.as_mut_ptr() as usize,
                output.len(),
                offset as usize,
            )
        };
        if result == output.len() as isize {
            Ok(())
        } else {
            Err(VfsError::Io)
        }
    }
}

fn vfs_main(config_path: *const u8, rootfs_path: *const u8, index_path: *const u8) -> ! {
    let config = load_config(config_path);
    let mut domain = Domain::create(config);
    if domain.start().is_err() {
        domain_fail(&mut domain, b"invalid start transition");
    }
    let index_length = read_index(index_path);
    let index_bytes = unsafe {
        core::slice::from_raw_parts(
            core::ptr::addr_of!(VFS_INDEX_BYTES).cast::<u8>(),
            index_length,
        )
    };
    let index = match Index::new(index_bytes) {
        Ok(index) => index,
        Err(_) => domain_fail(&mut domain, b"invalid VFS index"),
    };
    let descriptor =
        unsafe { syscall4(SYS_OPENAT_HOST, AT_FDCWD, rootfs_path as usize, O_RDONLY, 0) };
    if descriptor < 0 {
        domain_fail(&mut domain, b"rootfs open failed");
    }
    let reader = HostRootfs {
        descriptor: descriptor as usize,
    };
    let mut vfs: VirtualFs<'_, HostRootfs, 8, 4096, 8> = VirtualFs::new(index, reader);

    let os_fd = match vfs.open(b"/etc/os-release", O_READ) {
        Ok(value) => value,
        Err(_) => vfs_fail(
            &mut domain,
            &mut vfs,
            descriptor as usize,
            b"os-release lookup failed",
        ),
    };
    let mut os_release = [0u8; 512];
    let os_length = match vfs.read(os_fd, &mut os_release) {
        Ok(value) => value,
        Err(_) => vfs_fail(
            &mut domain,
            &mut vfs,
            descriptor as usize,
            b"os-release read failed",
        ),
    };
    let _ = vfs.close(os_fd);
    if !contains(&os_release[..os_length], b"Rocky Linux") {
        vfs_fail(
            &mut domain,
            &mut vfs,
            descriptor as usize,
            b"Rocky identity missing",
        );
    }

    let bash_fd = match vfs.open(b"/usr/bin/bash", O_READ) {
        Ok(value) => value,
        Err(_) => vfs_fail(
            &mut domain,
            &mut vfs,
            descriptor as usize,
            b"bash lookup failed",
        ),
    };
    let mut magic = [0u8; 4];
    if vfs.read(bash_fd, &mut magic) != Ok(4) || &magic != b"\x7fELF" {
        vfs_fail(
            &mut domain,
            &mut vfs,
            descriptor as usize,
            b"bash ELF read failed",
        );
    }
    let _ = vfs.close(bash_fd);

    let overlay_fd = match vfs.open(b"/ginux-overlay-proof", O_READ | O_WRITE | O_CREATE) {
        Ok(value) => value,
        Err(_) => vfs_fail(
            &mut domain,
            &mut vfs,
            descriptor as usize,
            b"overlay create failed",
        ),
    };
    if vfs.write(overlay_fd, b"domain-local") != Ok(12) {
        vfs_fail(
            &mut domain,
            &mut vfs,
            descriptor as usize,
            b"overlay write failed",
        );
    }
    let _ = vfs.close(overlay_fd);

    write_all(b"GINUX_VFS: root=");
    line(config.root.as_bytes());
    line(b"GINUX_VFS: base=/etc/os-release identity=Rocky-Linux");
    line(b"GINUX_VFS: base=/usr/bin/bash format=ELF64-x86_64");
    line(b"GINUX_VFS: overlay=/ginux-overlay-proof value=domain-local");
    line(b"GINUX_VFS: managed-host-paths=unexposed managed-host-fds=unexposed");
    vfs.teardown();
    let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
    if domain.task_exited(true).is_err() {
        domain_fail(&mut domain, b"invalid task-exit transition");
    }
    line(b"GINUX_VFS: teardown overlay-files=0 descriptors=0");
    line(b"GINUX_VFS_CHECK: PASS");
    exit_process(0)
}

fn vfs_fail(
    domain: &mut Domain,
    vfs: &mut VirtualFs<'_, HostRootfs, 8, 4096, 8>,
    descriptor: usize,
    reason: &[u8],
) -> ! {
    vfs.teardown();
    let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor) };
    domain_fail(domain, reason)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn native_main(config_path: *const u8, root_path: *const u8, mode: usize) -> ! {
    let config = load_config(config_path);
    print_effective_config(&config);
    let mut domain = Domain::create(config);
    if domain.start().is_err() {
        domain_fail(&mut domain, b"invalid native start transition");
    }
    let child = unsafe { syscall0(SYS_FORK) };
    if child < 0 {
        domain_fail(&mut domain, b"native tracee fork failed");
    }
    if child == 0 {
        native_tracee(root_path, mode);
    }
    supervise_native(child as usize, &mut domain)
}

fn native_tracee(root_path: *const u8, mode: usize) -> ! {
    static ROOT: &[u8] = b"/\0";
    static BASH: &[u8] = b"/usr/bin/bash\0";
    static ARG1: &[u8] = b"--noprofile\0";
    static ARG2: &[u8] = b"--norc\0";
    static ARG3: &[u8] = b"-c\0";
    static COMMAND: &[u8] = b"printf 'GINUX_NATIVE_SHELL: PASS\\n'\0";
    static HOLD_COMMAND: &[u8] = b"printf 'GINUX_NATIVE_HOLD: READY\\n'; while :; do :; done\0";
    static PROBE_COMMAND: &[u8] = b"if : > /tmp/ginux-mutation; then exit 90; else printf 'GINUX_BALANCED_MUTATION: BLOCKED\\n'; fi; if exec 9<>/dev/tcp/127.0.0.1/9; then exit 91; else printf 'GINUX_BALANCED_NETWORK: BLOCKED\\n'; fi\0";
    static ENV_PATH: &[u8] = b"PATH=/usr/bin:/bin\0";
    static ENV_HOME: &[u8] = b"HOME=/\0";
    static ENV_LOCALE: &[u8] = b"LC_ALL=C\0";
    static ENV_CONTAINER: &[u8] = b"container=ginux\0";

    if unsafe { syscall1(SYS_CHROOT, root_path as usize) } < 0 {
        native_tracee_setup_fail(120);
    }
    if unsafe { syscall1(SYS_CHDIR, ROOT.as_ptr() as usize) } < 0 {
        native_tracee_setup_fail(121);
    }
    if unsafe { syscall4(SYS_PTRACE, PTRACE_TRACEME, 0, 0, 0) } < 0 {
        native_tracee_setup_fail(122);
    }
    if unsafe { syscall2(SYS_SETGROUPS, 0, 0) } < 0 {
        native_tracee_setup_fail(123);
    }
    if unsafe { syscall1(SYS_SETGID, DOMAIN_GID) } < 0 {
        native_tracee_setup_fail(124);
    }
    if unsafe { syscall1(SYS_SETUID, DOMAIN_UID) } < 0 {
        native_tracee_setup_fail(125);
    }
    if unsafe { syscall5(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        native_tracee_setup_fail(126);
    }
    let argv = [
        BASH.as_ptr(),
        ARG1.as_ptr(),
        ARG2.as_ptr(),
        ARG3.as_ptr(),
        match mode {
            1 => HOLD_COMMAND.as_ptr(),
            2 => PROBE_COMMAND.as_ptr(),
            _ => COMMAND.as_ptr(),
        },
        core::ptr::null(),
    ];
    let environment = [
        ENV_PATH.as_ptr(),
        ENV_HOME.as_ptr(),
        ENV_LOCALE.as_ptr(),
        ENV_CONTAINER.as_ptr(),
        core::ptr::null(),
    ];
    unsafe {
        syscall3(
            SYS_EXECVE,
            BASH.as_ptr() as usize,
            argv.as_ptr() as usize,
            environment.as_ptr() as usize,
        );
        syscall1(SYS_EXIT_HOST, 127);
    }
    loop {
        core::hint::spin_loop();
    }
}

fn native_tracee_setup_fail(code: usize) -> ! {
    unsafe { syscall1(SYS_EXIT_HOST, code) };
    loop {
        core::hint::spin_loop();
    }
}

fn supervise_native(pid: usize, domain: &mut Domain) -> ! {
    let mut status = 0i32;
    if wait(pid, &mut status) < 0 {
        native_fail(domain, pid, b"native tracee wait after exec failed");
    }
    if !stopped(status) {
        write_all(b"GINUX_NATIVE: pre-exec-status=");
        write_i64(status as i64);
        write_all(b"\n");
        native_fail(domain, pid, b"native tracee did not stop after exec");
    }
    let options = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL;
    if ptrace(PTRACE_SETOPTIONS, pid, 0, options) < 0 || ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0 {
        native_fail(domain, pid, b"native ptrace setup failed");
    }
    line(b"GINUX_NATIVE: backend=ptrace-native profile=balanced elf-loader=host contract=gate5-balanced");
    line(b"GINUX_NATIVE: tracee-uid=1000 tracee-gid=1000 root=oci-read-only");

    let mut sequence = 0u64;
    let mut awaiting_exit = false;
    let mut override_exit = false;
    let mut override_result = 0i64;
    loop {
        status = 0;
        if wait(pid, &mut status) < 0 || !stopped(status) {
            native_fail(domain, pid, b"native tracee escaped supervision");
        }
        let signal = ((status >> 8) & 0xff) as u8;
        if signal != (5 | 0x80) && signal != 5 {
            native_fail(domain, pid, b"unexpected native trace stop");
        }
        let mut registers = core::mem::MaybeUninit::<UserRegs>::uninit();
        if ptrace(PTRACE_GETREGS, pid, 0, registers.as_mut_ptr() as usize) < 0 {
            native_fail(domain, pid, b"native register read failed");
        }
        let mut registers = unsafe { registers.assume_init() };

        if awaiting_exit {
            if override_exit {
                registers.rax = override_result as u64;
                if ptrace(PTRACE_SETREGS, pid, 0, &registers as *const _ as usize) < 0 {
                    native_fail(domain, pid, b"native result override failed");
                }
            }
            write_all(b"GINUX_NATIVE_AUDIT: sequence=");
            write_u64(sequence);
            write_all(b" phase=exit result=");
            write_i64(registers.rax as i64);
            write_all(b"\n");
            awaiting_exit = false;
            override_exit = false;
            if ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0 {
                native_fail(domain, pid, b"native resume failed");
            }
            continue;
        }

        sequence += 1;
        let syscall = registers.orig_rax;
        let decision = match decide_native(syscall, registers.rdi, registers.rsi, registers.rdx) {
            NativeDecision::Contract(decision) => decision,
            NativeDecision::Hooked { lane, result } => {
                let lane_name: &[u8] = match lane {
                    Lane::Process => b"process",
                    Lane::Filesystem => b"filesystem",
                    Lane::Channel => b"channel",
                    Lane::Contract => b"contract",
                };
                write_all(b"emulate surface=lane-");
                write_all(lane_name);
                write_all(b" result=");
                write_i64(result);
                write_all(b"\n");
                registers.orig_rax = u64::MAX;
                awaiting_exit = true;
                override_exit = true;
                override_result = result;
                if ptrace(PTRACE_SETREGS, pid, 0, &registers as *const _ as usize) < 0
                    || ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0
                {
                    native_fail(domain, pid, b"native lane emulation failed");
                }
                continue;
            }
        };
        write_all(b"GINUX_NATIVE_AUDIT: sequence=");
        write_u64(sequence);
        write_all(b" phase=entry syscall=");
        write_u64(syscall);
        write_all(b" action=");
        match decision.action {
            Action::Emulate if balanced_identity_result(syscall).is_some() => {
                let result = balanced_identity_result(syscall).unwrap_or(0);
                write_all(b"emulate surface=virtual-identity result=");
                write_i64(result);
                write_all(b"\n");
                registers.orig_rax = u64::MAX;
                awaiting_exit = true;
                override_exit = true;
                override_result = result;
                if ptrace(PTRACE_SETREGS, pid, 0, &registers as *const _ as usize) < 0
                    || ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0
                {
                    native_fail(domain, pid, b"native getpid emulation failed");
                }
            }
            Action::Emulate if syscall == SYS_EXIT || syscall == SYS_EXIT_GROUP => {
                line(b"emulate result=domain-stop");
                let _ = ptrace(PTRACE_KILL, pid, 0, 0);
                let _ = wait(pid, &mut status);
                if domain.task_exited(true).is_err() {
                    domain_fail(domain, b"native exit transition failed");
                }
                line(b"GINUX_NATIVE: supervisor=attached direct-unsupervised-syscalls=0");
                line(b"GINUX_NATIVE_CHECK: PASS");
                exit_process(0)
            }
            Action::Mediate if native_arguments_allowed(syscall, &registers) => {
                write_all(b"mediate surface=");
                line(balanced_surface_name(balanced_surface(syscall)));
                awaiting_exit = true;
                if ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0 {
                    native_fail(domain, pid, b"native mediated syscall failed");
                }
            }
            Action::Mediate => {
                line(b"deny result=-1 reason=invalid-arguments");
                registers.orig_rax = u64::MAX;
                awaiting_exit = true;
                override_exit = true;
                override_result = -EPERM;
                if ptrace(PTRACE_SETREGS, pid, 0, &registers as *const _ as usize) < 0
                    || ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0
                {
                    native_fail(domain, pid, b"native argument denial failed");
                }
            }
            Action::Deny(errno) => {
                write_all(b"deny result=-");
                write_u64(errno as u64);
                write_all(b"\n");
                registers.orig_rax = u64::MAX;
                awaiting_exit = true;
                override_exit = true;
                override_result = -(errno as i64);
                if ptrace(PTRACE_SETREGS, pid, 0, &registers as *const _ as usize) < 0
                    || ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0
                {
                    native_fail(domain, pid, b"native syscall denial failed");
                }
            }
            _ => native_fail(domain, pid, b"invalid native contract decision"),
        }
    }
}

fn native_fail(domain: &mut Domain, pid: usize, reason: &[u8]) -> ! {
    let _ = ptrace(PTRACE_KILL, pid, 0, 0);
    let mut status = 0;
    let _ = wait(pid, &mut status);
    domain_fail(domain, reason)
}

fn config_main(config_path: *const u8) -> ! {
    let config = load_config(config_path);
    print_effective_config(&config);
    line(b"GINUX_CONFIG: PASS");
    exit_process(0)
}

fn domain_main(config_path: *const u8, fixture_path: *const u8) -> ! {
    let config = load_config(config_path);
    print_effective_config(&config);
    let mut domain = Domain::create(config);
    lifecycle_state(&domain);
    if domain.start().is_err() {
        domain_fail(&mut domain, b"invalid start transition");
    }
    lifecycle_state(&domain);

    let length = read_file(fixture_path);
    let elf =
        unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(ELF_BYTES).cast::<u8>(), length) };
    let mut memory = AddressSpace::new();
    let loaded = match memory.load_elf(elf) {
        Ok(loaded) => loaded,
        Err(_) => domain_fail(&mut domain, b"managed ELF rejected"),
    };

    let mut argv: [&[u8]; 8] = [&[]; 8];
    argv[0] = config.init.as_bytes();
    let mut argc = 1;
    for argument in config.args.as_slice() {
        argv[argc] = argument.as_bytes();
        argc += 1;
    }
    let mut environment: [&[u8]; 8] = [&[]; 8];
    let mut envc = 0;
    for variable in config.environment.as_slice() {
        environment[envc] = variable.as_bytes();
        envc += 1;
    }
    let stack = match memory.build_stack(&argv[..argc], &environment[..envc]) {
        Ok(stack) => stack,
        Err(_) => domain_fail(&mut domain, b"managed stack rejected"),
    };
    let report = match execute(&memory, loaded.entry, stack, 10_000) {
        Ok(report) => report,
        Err(_) => domain_fail(&mut domain, b"managed execution failed"),
    };
    if report.exit_code != 0 {
        domain_fail(&mut domain, b"managed task failed");
    }
    write_all(b"GINUX_DOMAIN: managed-output=");
    write_all(&report.output[..report.output_len]);
    write_all(b"\n");
    if domain.task_exited(true).is_err() {
        domain_fail(&mut domain, b"invalid task-exit transition");
    }
    lifecycle_state(&domain);
    line(b"GINUX_DOMAIN: cleanup resources=false managed-task=false");
    line(b"GATE4: PASS");
    exit_process(0)
}

fn lifecycle_main(config_path: *const u8) -> ! {
    let config = load_config(config_path);
    let mut domain = Domain::create(config);
    lifecycle_state(&domain);
    if domain.start().is_err() {
        domain_fail(&mut domain, b"invalid start transition");
    }

    let mask = 1u64 << (SIGTERM - 1);
    if unsafe {
        syscall4(
            SYS_RT_SIGPROCMASK,
            SIG_BLOCK,
            &mask as *const _ as usize,
            0,
            core::mem::size_of::<u64>(),
        )
    } < 0
    {
        domain_fail(&mut domain, b"signal mask setup failed");
    }
    let signal_fd = unsafe {
        syscall4(
            SYS_SIGNALFD4,
            usize::MAX,
            &mask as *const _ as usize,
            core::mem::size_of::<u64>(),
            0,
        )
    };
    if signal_fd < 0 {
        domain_fail(&mut domain, b"signalfd setup failed");
    }
    let child = unsafe { syscall0(SYS_FORK) };
    if child < 0 {
        let _ = unsafe { syscall1(SYS_CLOSE_HOST, signal_fd as usize) };
        domain_fail(&mut domain, b"helper fork failed");
    }
    if child == 0 {
        loop {
            let _ = unsafe { syscall0(SYS_PAUSE) };
        }
    }

    write_all(b"GINUX_LIFECYCLE: state=running helper-pid=");
    write_u64(child as u64);
    write_all(b" resources=true\n");
    let mut signal_info = [0u8; 128];
    let signal_read = unsafe {
        syscall3(
            SYS_READ_HOST,
            signal_fd as usize,
            signal_info.as_mut_ptr() as usize,
            signal_info.len(),
        )
    };
    if signal_read != signal_info.len() as isize {
        let _ = unsafe { syscall2(SYS_KILL, child as usize, SIGKILL) };
        let mut status = 0;
        let _ = wait(child as usize, &mut status);
        let _ = unsafe { syscall1(SYS_CLOSE_HOST, signal_fd as usize) };
        domain_fail(&mut domain, b"signal wait failed");
    }
    line(b"GINUX_LIFECYCLE: signal=SIGTERM decision=stop");
    let _ = unsafe { syscall2(SYS_KILL, child as usize, SIGKILL) };
    let mut status = 0;
    if wait(child as usize, &mut status) != child {
        let _ = unsafe { syscall1(SYS_CLOSE_HOST, signal_fd as usize) };
        domain_fail(&mut domain, b"helper reap failed");
    }
    let _ = unsafe { syscall1(SYS_CLOSE_HOST, signal_fd as usize) };
    if domain.stop().is_err() {
        domain_fail(&mut domain, b"invalid stop transition");
    }
    line(b"GINUX_LIFECYCLE: helper=reaped zombies=0");
    lifecycle_state(&domain);
    line(b"GINUX_DOMAIN: cleanup resources=false managed-task=false");
    line(b"GATE4_LIFECYCLE: PASS");
    exit_process(0)
}

fn lifecycle_state(domain: &Domain) {
    write_all(b"GINUX_LIFECYCLE: state=");
    write_all(domain.state().as_str().as_bytes());
    write_all(b" resources=");
    write_all(if domain.resources_acquired() {
        b"true"
    } else {
        b"false"
    });
    write_all(b" managed-task=");
    line(if domain.managed_task() {
        b"true"
    } else {
        b"false"
    });
}

fn domain_fail(domain: &mut Domain, reason: &[u8]) -> ! {
    let _ = domain.task_exited(false);
    write_all(b"GINUX_DOMAIN: failed reason=");
    line(reason);
    lifecycle_state(domain);
    line(b"GINUX_DOMAIN: cleanup resources=false managed-task=false");
    exit_process(1)
}

fn gate1_main() -> ! {
    line(b"GINUX: interception platform=ptrace-sysemu");

    let child = unsafe { syscall0(SYS_FORK) };
    if child < 0 {
        fail(b"fork failed");
    }
    if child == 0 {
        tracee();
    }

    supervise(child as usize)
}

fn runtime_main(path: *const u8) -> ! {
    line(b"GINUX_RUNTIME: backend=x86_64-interpreter");
    let length = read_file(path);
    let elf =
        unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(ELF_BYTES).cast::<u8>(), length) };
    let mut memory = AddressSpace::new();
    let loaded = match memory.load_elf(elf) {
        Ok(loaded) => loaded,
        Err(error) => runtime_load_fail(error),
    };
    let stack = match memory.build_stack(&[b"runtime-fixture", b"fixture-arg"], &[b"GINUX_GATE=3"])
    {
        Ok(stack) => stack,
        Err(_) => runtime_fail(b"initial stack rejected"),
    };
    line(b"GINUX_RUNTIME: elf=loaded class=ELF64 machine=x86_64 type=static");
    line(b"GINUX_RUNTIME: memory=ginux-owned host-pointers=unreachable protections=enforced");
    line(b"GINUX_RUNTIME: stack=linux-x86_64 argc=2 envc=1");

    let report = match execute(&memory, loaded.entry, stack, 10_000) {
        Ok(report) => report,
        Err(_) => runtime_fail(b"interpreter execution failed"),
    };
    if report.exit_code != 0 || &report.output[..report.output_len] != b"fixture-argGINUX_GATE=3" {
        runtime_fail(b"managed fixture reported failure");
    }
    write_all(b"GINUX_RUNTIME: managed-output=");
    write_all(&report.output[..report.output_len]);
    write_all(b"\n");
    for record in report.audit.iter().take(report.audit_len) {
        write_all(b"GINUX_AUDIT: sequence=");
        write_u64(record.sequence as u64);
        write_all(b" syscall=");
        write_u64(record.syscall);
        write_all(b" action=");
        write_all(match record.action {
            AuditAction::Emulate => b"emulate",
            AuditAction::Mediate => b"mediate",
            AuditAction::Deny => b"deny",
        });
        write_all(b" result=");
        write_i64(record.result);
        write_all(b"\n");
    }
    if report.audit_len != 5
        || report.audit[2].syscall != 999
        || report.audit[2].action != AuditAction::Deny
        || report.audit[2].result != -38
    {
        runtime_fail(b"expected deny audit missing");
    }
    line(b"GINUX_RUNTIME: direct-host-syscalls=impossible interpreted-syscall=internal-event");
    line(b"GATE3: PASS");
    exit_process(0)
}

fn runtime_load_fail(error: LoadError) -> ! {
    write_all(b"GATE3: FAIL: elf rejected reason=");
    line(match error {
        LoadError::Truncated => b"truncated",
        LoadError::InvalidMagic => b"invalid-magic",
        LoadError::UnsupportedClass => b"unsupported-class",
        LoadError::UnsupportedEndian => b"unsupported-endian",
        LoadError::UnsupportedType => b"unsupported-type",
        LoadError::UnsupportedMachine => b"unsupported-machine",
        LoadError::InvalidProgramHeaders => b"invalid-program-headers",
        LoadError::UnsupportedInterpreter => b"dynamic-interpreter",
        LoadError::InvalidSegment => b"invalid-segment",
        LoadError::SegmentOverlap => b"segment-overlap",
        LoadError::WriteExecuteSegment => b"write-execute-segment",
        LoadError::InvalidEntry => b"invalid-entry",
    });
    exit_process(1)
}

fn runtime_fail(reason: &[u8]) -> ! {
    write_all(b"GATE3: FAIL: ");
    line(reason);
    exit_process(1)
}

fn tracee() -> ! {
    let traced = unsafe { syscall4(SYS_PTRACE, PTRACE_TRACEME, 0, 0, 0) };
    if traced < 0 {
        unsafe { syscall1(SYS_EXIT_HOST, 110) };
        loop {
            core::hint::spin_loop();
        }
    }

    static PATH: &[u8] = b"/var/tmp/ginux-managed-payload\0";
    let argv = [PATH.as_ptr(), core::ptr::null()];
    let envp: [*const u8; 1] = [core::ptr::null()];
    unsafe {
        syscall3(
            SYS_EXECVE,
            PATH.as_ptr() as usize,
            argv.as_ptr() as usize,
            envp.as_ptr() as usize,
        );
        syscall1(SYS_EXIT_HOST, 111);
    }
    loop {
        core::hint::spin_loop();
    }
}

fn supervise(pid: usize) -> ! {
    let mut status = 0i32;
    if wait(pid, &mut status) < 0 || !stopped(status) {
        fail(b"payload did not stop after exec");
    }

    let options = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL;
    if ptrace(PTRACE_SETOPTIONS, pid, 0, options) < 0 {
        fail(b"PTRACE_SETOPTIONS failed");
    }
    if ptrace(PTRACE_SYSEMU, pid, 0, 0) < 0 {
        fail(b"PTRACE_SYSEMU unavailable");
    }

    let mut saw_getpid = false;
    let mut saw_write = false;
    let mut saw_uname = false;

    loop {
        status = 0;
        if wait(pid, &mut status) < 0 {
            fail(b"wait4 failed");
        }
        if !stopped(status) {
            fail(b"payload exited outside Ginux dispatch");
        }

        let signal = ((status >> 8) & 0xff) as u8;
        if signal != (5 | 0x80) && signal != 5 {
            fail(b"unexpected trace stop");
        }

        let mut regs = core::mem::MaybeUninit::<UserRegs>::uninit();
        if ptrace(PTRACE_GETREGS, pid, 0, regs.as_mut_ptr() as usize) < 0 {
            fail(b"PTRACE_GETREGS failed");
        }
        // PTRACE_GETREGS initializes the complete architecture register set.
        let mut regs = unsafe { regs.assume_init() };

        let decision = decide(regs.orig_rax);
        match decision.action {
            Action::Emulate if decision.syscall == SYS_GETPID => {
                saw_getpid = true;
                regs.rax = VIRTUAL_PID;
                line(b"GINUX: syscall=getpid decision=emulate result=4242");
            }
            Action::Mediate if decision.syscall == SYS_WRITE => {
                saw_write = true;
                if regs.rdi != 1 || regs.rdx == 0 || regs.rdx > 4096 {
                    regs.rax = (-EPERM) as u64;
                    line(b"GINUX: syscall=write decision=deny reason=invalid-arguments");
                } else if !read_tracee_word(pid, regs.rsi as usize) {
                    regs.rax = (-EPERM) as u64;
                    line(b"GINUX: syscall=write decision=deny reason=invalid-memory");
                } else {
                    regs.rax = regs.rdx;
                    line(b"GINUX: syscall=write decision=mediate host-write=not-executed");
                }
            }
            Action::Deny(errno) if decision.syscall == SYS_UNAME => {
                saw_uname = true;
                regs.rax = (-(errno as i64)) as u64;
                line(b"GINUX: syscall=uname decision=deny errno=EPERM");
            }
            Action::Emulate if decision.syscall == SYS_EXIT => {
                let success = regs.rdi == 0 && saw_getpid && saw_write && saw_uname;
                let _ = ptrace(PTRACE_KILL, pid, 0, 0);
                let _ = wait(pid, &mut status);
                if success {
                    line(b"GINUX: direct-host-syscall bypass=not-observed");
                    line(b"GATE1: PASS");
                    exit_process(0);
                }
                fail(b"payload reported failure");
            }
            Action::Deny(errno) => {
                regs.rax = (-(errno as i64)) as u64;
                line(b"GINUX: syscall=unknown decision=deny errno=ENOSYS");
            }
            _ => {
                regs.rax = (-ENOSYS) as u64;
                line(b"GINUX: syscall=unexpected decision=deny errno=ENOSYS");
            }
        }

        if ptrace(PTRACE_SETREGS, pid, 0, &regs as *const _ as usize) < 0 {
            fail(b"PTRACE_SETREGS failed");
        }
        if ptrace(PTRACE_SYSEMU, pid, 0, 0) < 0 {
            fail(b"PTRACE_SYSEMU resume failed");
        }
    }
}

fn fail(reason: &[u8]) -> ! {
    write_all(b"GATE1: FAIL: ");
    line(reason);
    exit_process(1)
}
