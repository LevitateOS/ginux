//! Launch-config handling for the native supervisor.
//!
//! Owner: G-launch. Initial-stack command parsing plus instance-config and
//! input-file staging. Workload definitions stay with the entry points in
//! `main.rs`; `launch` runs the executable and arguments from instance config.

use ginux_contract::{
    configured_semantic_operation, syscall_semantic_operation, EffectiveContract, EffectiveRule,
    Kind, Provenance, Status,
};
use ginux_instance::{
    AuditMode, ConfigError, ExecutionBackend, ExecutionProfile, Instance, InstanceConfig,
};

use crate::supervisor::{
    exit_process, line, managed_host_identity, ptrace, standard_stream_refusal, syscall0, syscall1,
    syscall2, syscall3, syscall4, syscall5, write_all, AT_FDCWD, O_RDONLY, PR_SET_NO_NEW_PRIVS,
    PTRACE_SEIZE, SYS_CHDIR, SYS_CHROOT, SYS_CLOSE_HOST, SYS_EXECVE, SYS_EXIT_HOST, SYS_FORK,
    SYS_FSYNC, SYS_KILL, SYS_OPENAT_HOST, SYS_PRCTL, SYS_READ_HOST, SYS_SETGID, SYS_SETGROUPS,
    SYS_SETUID, SYS_WRITE_HOST,
};

pub const MAX_ELF_SIZE: usize = 64 * 1024;
pub const MAX_CONFIG_SIZE: usize = 16 * 1024;
pub const MAX_VFS_INDEX_SIZE: usize = 8 * 1024 * 1024;

pub static mut ELF_BYTES: [u8; MAX_ELF_SIZE] = [0; MAX_ELF_SIZE];
pub static mut CONFIG_BYTES: [u8; MAX_CONFIG_SIZE] = [0; MAX_CONFIG_SIZE];
pub static mut VFS_INDEX_BYTES: [u8; MAX_VFS_INDEX_SIZE] = [0; MAX_VFS_INDEX_SIZE];

/// Entry-point command decoded from the initial process stack.
pub enum Command {
    Runtime(*const u8),
    Config(*const u8),
    ConfigMerge(*const u8, usize, *const usize),
    InstancePlan(*const u8),
    InstanceValidate(*const u8),
    InstanceExplain(*const u8, *const u8),
    InstanceDiff(*const u8, *const u8),
    InstanceInspect(*const u8),
    HookPlan(*const u8),
    Lifecycle(*const u8),
    Vfs(*const u8, *const u8, *const u8),
    Native(*const u8, *const u8, usize),
    NativeHook(*const u8, *const u8, usize),
    Instance(*const u8, *const u8),
    Process(*const u8),
    ProcessNative(*const u8, *const u8),
    Devices(*const u8, *const u8),
    DeviceBench(*const u8, *const u8, *const u8),
    KernelViews(*const u8),
    Launch(
        *const u8,
        *const u8,
        *const u8,
        *const u8,
        Option<usize>,
        *const u8,
    ),
    LaunchUsage,
    Usage,
}

/// Decode `argv`. `None` (no arguments) selects the default interception
/// demonstration; an unknown or incomplete command is a usage error and never
/// falls through to the demonstration.
pub fn parse_argv(argc: usize, argv: *const usize) -> Option<Command> {
    if argc < 2 {
        return None;
    }
    let command = unsafe { *argv.add(1) as *const u8 };
    if c_string_equals(command, b"launch") && argc < 4 {
        return Some(Command::LaunchUsage);
    }
    if argc < 3 {
        return Some(Command::Usage);
    }
    if c_string_equals(command, b"runtime") {
        let path = unsafe { *argv.add(2) as *const u8 };
        Some(Command::Runtime(path))
    } else if c_string_equals(command, b"config") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        Some(Command::Config(config_path))
    } else if c_string_equals(command, b"config-merge") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        Some(Command::ConfigMerge(config_path, argc - 3, unsafe {
            argv.add(3)
        }))
    } else if c_string_equals(command, b"instance-plan") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        Some(Command::InstancePlan(config_path))
    } else if c_string_equals(command, b"instance-validate") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        Some(Command::InstanceValidate(config_path))
    } else if argc >= 4 && c_string_equals(command, b"instance-explain") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        let operation = unsafe { *argv.add(3) as *const u8 };
        Some(Command::InstanceExplain(config_path, operation))
    } else if argc >= 4 && c_string_equals(command, b"instance-diff") {
        let left = unsafe { *argv.add(2) as *const u8 };
        let right = unsafe { *argv.add(3) as *const u8 };
        Some(Command::InstanceDiff(left, right))
    } else if c_string_equals(command, b"instance-inspect") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        Some(Command::InstanceInspect(config_path))
    } else if c_string_equals(command, b"hook-plan") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        Some(Command::HookPlan(config_path))
    } else if c_string_equals(command, b"lifecycle") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        Some(Command::Lifecycle(config_path))
    } else if argc >= 5 && c_string_equals(command, b"vfs") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        let rootfs_path = unsafe { *argv.add(3) as *const u8 };
        let index_path = unsafe { *argv.add(4) as *const u8 };
        Some(Command::Vfs(config_path, rootfs_path, index_path))
    } else if argc >= 4 && c_string_equals(command, b"native") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        let root_path = unsafe { *argv.add(3) as *const u8 };
        let mode = if argc >= 5 && c_string_equals(unsafe { *argv.add(4) as *const u8 }, b"hold") {
            1
        } else if argc >= 5 && c_string_equals(unsafe { *argv.add(4) as *const u8 }, b"probe") {
            2
        } else if argc >= 5 && c_string_equals(unsafe { *argv.add(4) as *const u8 }, b"configured")
        {
            3
        } else {
            0
        };
        Some(Command::Native(config_path, root_path, mode))
    } else if argc >= 5 && c_string_equals(command, b"native-hook") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        let root_path = unsafe { *argv.add(3) as *const u8 };
        let index = parse_decimal_c_string(unsafe { *argv.add(4) as *const u8 })?;
        Some(Command::NativeHook(config_path, root_path, index))
    } else if argc >= 4 && c_string_equals(command, b"instance") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        let fixture_path = unsafe { *argv.add(3) as *const u8 };
        Some(Command::Instance(config_path, fixture_path))
    } else if c_string_equals(command, b"process") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        Some(Command::Process(config_path))
    } else if argc >= 4 && c_string_equals(command, b"process-native") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        let fixture_path = unsafe { *argv.add(3) as *const u8 };
        Some(Command::ProcessNative(config_path, fixture_path))
    } else if argc >= 4 && c_string_equals(command, b"devices") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        let block_path = unsafe { *argv.add(3) as *const u8 };
        Some(Command::Devices(config_path, block_path))
    } else if argc >= 5 && c_string_equals(command, b"device-bench") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        let block_path = unsafe { *argv.add(3) as *const u8 };
        let kind = unsafe { *argv.add(4) as *const u8 };
        Some(Command::DeviceBench(config_path, block_path, kind))
    } else if c_string_equals(command, b"kernel-views") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        Some(Command::KernelViews(config_path))
    } else if argc >= 4 && c_string_equals(command, b"launch") {
        let config_path = unsafe { *argv.add(2) as *const u8 };
        let root_path = unsafe { *argv.add(3) as *const u8 };
        let mut result_path: *const u8 = core::ptr::null();
        let mut export_path: *const u8 = core::ptr::null();
        let mut control_fd = None;
        let mut restore_path: *const u8 = core::ptr::null();
        let mut i = 4;
        while i < argc {
            if i + 1 >= argc {
                return Some(Command::LaunchUsage);
            }
            let option = unsafe { *argv.add(i) as *const u8 };
            let value = unsafe { *argv.add(i + 1) as *const u8 };
            if unsafe { *value } == 0 {
                return Some(Command::LaunchUsage);
            }
            if c_string_equals(option, b"--result-file") && result_path.is_null() {
                result_path = value;
            } else if c_string_equals(option, b"--export-file") && export_path.is_null() {
                export_path = value;
            } else if c_string_equals(option, b"--control-fd") && control_fd.is_none() {
                control_fd = parse_control_fd(value);
                if control_fd.is_none() {
                    return Some(Command::LaunchUsage);
                }
            } else if c_string_equals(option, b"--restore-file") && restore_path.is_null() {
                restore_path = value;
            } else {
                return Some(Command::LaunchUsage);
            }
            i += 2;
        }
        Some(Command::Launch(
            config_path,
            root_path,
            result_path,
            export_path,
            control_fd,
            restore_path,
        ))
    } else {
        Some(Command::Usage)
    }
}

fn parse_control_fd(value: *const u8) -> Option<usize> {
    let mut fd = 0usize;
    for i in 0..6 {
        let byte = unsafe { core::ptr::read_volatile(value.add(i)) };
        if byte == 0 {
            return (i != 0 && (3..=65535).contains(&fd)).then_some(fd);
        }
        if !byte.is_ascii_digit() {
            return None;
        }
        fd = fd * 10 + (byte - b'0') as usize;
    }
    None
}

fn parse_decimal_c_string(value: *const u8) -> Option<usize> {
    let bytes = c_string_bytes(value, 20).ok()?;
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut result = 0usize;
    for byte in bytes {
        result = result
            .checked_mul(10)?
            .checked_add(usize::from(*byte - b'0'))?;
    }
    Some(result)
}

pub fn load_config(path: *const u8) -> InstanceConfig {
    let length = read_config(path);
    let bytes = unsafe {
        core::slice::from_raw_parts(core::ptr::addr_of!(CONFIG_BYTES).cast::<u8>(), length)
    };
    match InstanceConfig::parse(bytes) {
        Ok(config) => config,
        Err(error) => config_rejected(error),
    }
}

pub fn print_effective_config(config: &InstanceConfig) {
    let normalized = match config.normalized() {
        Ok(normalized) => normalized,
        Err(error) => config_rejected(error),
    };
    line(b"GINUX_CONFIG: accepted format=toml schema=1");
    line(b"GINUX_CONFIG_EFFECTIVE_BEGIN");
    write_all(normalized.as_bytes());
    line(b"GINUX_CONFIG_EFFECTIVE_END");
}

pub fn config_rejected(error: ConfigError) -> ! {
    write_all(b"GINUX_CONFIG: rejected reason=");
    write_all(error.as_str().as_bytes());
    line(b" managed-started=false");
    exit_process(2)
}

pub fn read_file(path: *const u8) -> Result<usize, &'static [u8]> {
    use crate::supervisor::{syscall1, syscall3, syscall4};
    let descriptor = unsafe { syscall4(SYS_OPENAT_HOST, AT_FDCWD, path as usize, O_RDONLY, 0) };
    if descriptor < 0 {
        return Err(b"fixture open failed");
    }
    let mut length = 0usize;
    while length < MAX_ELF_SIZE {
        let result = unsafe {
            syscall3(
                SYS_READ_HOST,
                descriptor as usize,
                core::ptr::addr_of_mut!(ELF_BYTES).cast::<u8>().add(length) as usize,
                MAX_ELF_SIZE - length,
            )
        };
        if result < 0 {
            let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
            return Err(b"fixture read failed");
        }
        if result == 0 {
            break;
        }
        length += result as usize;
    }
    let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
    if length == 0 || length == MAX_ELF_SIZE {
        return Err(b"fixture size invalid");
    }
    Ok(length)
}

pub fn read_config(path: *const u8) -> usize {
    use crate::supervisor::{syscall1, syscall3, syscall4};
    let descriptor = unsafe { syscall4(SYS_OPENAT_HOST, AT_FDCWD, path as usize, O_RDONLY, 0) };
    if descriptor < 0 {
        config_rejected(ConfigError::InvalidValue);
    }
    let mut length = 0usize;
    while length < MAX_CONFIG_SIZE {
        let result = unsafe {
            syscall3(
                SYS_READ_HOST,
                descriptor as usize,
                core::ptr::addr_of_mut!(CONFIG_BYTES)
                    .cast::<u8>()
                    .add(length) as usize,
                MAX_CONFIG_SIZE - length,
            )
        };
        if result < 0 {
            let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
            config_rejected(ConfigError::InvalidValue);
        }
        if result == 0 {
            break;
        }
        length += result as usize;
    }
    let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
    if length == 0 || length == MAX_CONFIG_SIZE {
        config_rejected(ConfigError::ValueTooLong);
    }
    length
}

pub fn read_index(path: *const u8) -> Result<usize, &'static [u8]> {
    use crate::supervisor::{syscall1, syscall3, syscall4};
    let descriptor = unsafe { syscall4(SYS_OPENAT_HOST, AT_FDCWD, path as usize, O_RDONLY, 0) };
    if descriptor < 0 {
        return Err(b"VFS index open failed");
    }
    let mut length = 0usize;
    while length < MAX_VFS_INDEX_SIZE {
        let result = unsafe {
            syscall3(
                SYS_READ_HOST,
                descriptor as usize,
                core::ptr::addr_of_mut!(VFS_INDEX_BYTES)
                    .cast::<u8>()
                    .add(length) as usize,
                MAX_VFS_INDEX_SIZE - length,
            )
        };
        if result < 0 {
            let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
            return Err(b"VFS index read failed");
        }
        if result == 0 {
            break;
        }
        length += result as usize;
    }
    let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
    if length == 0 || length == MAX_VFS_INDEX_SIZE {
        return Err(b"VFS index size invalid");
    }
    Ok(length)
}

pub fn c_string_equals(value: *const u8, expected: &[u8]) -> bool {
    for (index, byte) in expected.iter().enumerate() {
        if unsafe { *value.add(index) } != *byte {
            return false;
        }
    }
    unsafe { *value.add(expected.len()) == 0 }
}

pub fn c_string_bytes(value: *const u8, limit: usize) -> Result<&'static [u8], ConfigError> {
    let mut length = 0usize;
    while length < limit {
        if unsafe { *value.add(length) } == 0 {
            return Ok(unsafe { core::slice::from_raw_parts(value, length) });
        }
        length += 1;
    }
    Err(ConfigError::ValueTooLong)
}

// ---- G01: configured native launch ----
//
// General path that executes the configured instance init with its configured
// arguments, environment, and working directory under the existing balanced
// ptrace-native supervision. The fixed Bash-only `native` demonstration is
// untouched; this path is additive behind the `launch` command.
//
// Supported bootstrap: privileged chroot into the given host rootfs path,
// then privilege drop to the instance UID/GID. Recipe never requires host
// root: when the mechanism is unavailable the launcher reports an explicit
// startup failure instead of falling back to host execution.

pub const MAX_LAUNCH_ARG_LEN: usize = 128;
pub const MAX_LAUNCH_ENV_LEN: usize = 256;
pub const MAX_LAUNCH_PATH_LEN: usize = 128;

const SYS_MKDIRAT: usize = 258;

static mut LAUNCH_EXEC: [u8; 129] = [0; 129];
static mut LAUNCH_ARGS: [u8; 7 * 129] = [0; 7 * 129];
static mut LAUNCH_ENV: [u8; 8 * 257] = [0; 8 * 257];
static mut LAUNCH_WORKDIR: [u8; 129] = [0; 129];
static mut LAUNCH_ARGV: [*const u8; 9] = [core::ptr::null(); 9];
static mut LAUNCH_ENVP: [*const u8; 9] = [core::ptr::null(); 9];

pub fn launch_main(
    config_path: *const u8,
    root_path: *const u8,
    result_path: *const u8,
    export_path: *const u8,
    control_fd: Option<usize>,
    restore_path: *const u8,
) -> ! {
    stage_result_path(result_path);
    close_undeclared_inherited_descriptors(control_fd)
        .unwrap_or_else(|reason| launch_startup_fail(reason));
    crate::storage_export::prepare(export_path)
        .unwrap_or_else(|reason| launch_startup_fail(reason));
    crate::checkpoint_control::prepare(control_fd)
        .unwrap_or_else(|reason| launch_startup_fail(reason));
    let config = launch_load_config(config_path);
    launch_validate(&config);
    let contract = config
        .effective_contract()
        .unwrap_or_else(|error| launch_rejected(error.as_str()));
    if let Some(rule) = contract
        .rules()
        .iter()
        .find(|rule| launch_cannot_enforce(rule))
    {
        write_stderr(b"ginux: launch config rejected reason=unenforced-deny operation=");
        line_stderr(rule.operation.id.as_bytes());
        write_completion_result(OUTCOME_SUPERVISOR_ERROR, false, 0, false, 0);
        exit_process(2);
    }
    unsafe {
        AUDIT_DISABLED = config.audit_mode == AuditMode::Disabled;
    }
    if let Some(reason) = standard_stream_refusal() {
        launch_startup_fail(reason);
    }
    let mut devices = crate::device_hooks::LaunchDevices::prepare(&config)
        .unwrap_or_else(|reason| launch_startup_fail(reason));
    // Capture the public operator limit before reserving private backing FDs.
    let descriptors = crate::descriptors::DescriptorTable::new()
        .unwrap_or_else(|reason| launch_startup_fail(reason));
    let mut filesystem = crate::launch_storage::LaunchFs::prepare(&config)
        .unwrap_or_else(|reason| launch_startup_fail(reason));
    filesystem
        .check_image(root_path)
        .unwrap_or_else(|reason| launch_startup_fail(reason));
    if config.storage_archive_import {
        filesystem
            .grant_archive_import(&contract)
            .unwrap_or_else(|reason| launch_startup_fail(reason));
    }
    if let Err(reason) = crate::storage_restore::restore(restore_path, &mut filesystem) {
        filesystem
            .teardown()
            .unwrap_or_else(|cleanup| launch_startup_fail(cleanup));
        launch_startup_fail(reason);
    }
    let mut channels = crate::channel_hooks::LaunchChannels::new();
    print_launch_config(&config);
    write_stderr(b"ginux: launch contract instance=");
    write_stderr(config.id.as_bytes());
    write_stderr(b" digest=");
    line_stderr(contract.digest());
    let mut instance = Instance::create(config);
    if instance.start().is_err() {
        launch_instance_fail(&mut instance, b"invalid launch start transition");
    }
    stage_launch(&config);
    if unsafe { syscall5(SYS_PRCTL, 36, 1, 0, 0, 0) } < 0 {
        launch_instance_fail(&mut instance, b"instance subreaper setup failed");
    }
    // The child waits for this private token before any guest code can run.
    // Seize it first so every descendant can be interrupted without signals.
    let mut gate = [0i32; 2];
    if unsafe { syscall2(293, gate.as_mut_ptr() as usize, 0x80000) } < 0 {
        launch_instance_fail(&mut instance, b"launch tracee gate unavailable");
    }
    let child = unsafe { syscall0(SYS_FORK) };
    if child < 0 {
        unsafe {
            syscall1(SYS_CLOSE_HOST, gate[0] as usize);
            syscall1(SYS_CLOSE_HOST, gate[1] as usize);
        }
        launch_instance_fail(&mut instance, b"launch tracee fork failed");
    }
    if child == 0 {
        unsafe {
            syscall1(SYS_CLOSE_HOST, gate[1] as usize);
        }
        launch_tracee(root_path, &config, descriptors.capacity(), gate[0] as usize);
    }
    unsafe {
        syscall1(SYS_CLOSE_HOST, gate[0] as usize);
    }
    if ptrace(
        PTRACE_SEIZE,
        child as usize,
        0,
        crate::launch_tasks::OPTIONS,
    ) < 0
    {
        unsafe {
            syscall1(SYS_CLOSE_HOST, gate[1] as usize);
            syscall2(SYS_KILL, child as usize, 9);
        }
        launch_instance_fail(&mut instance, b"launch ptrace seize failed");
    }
    let token = b'G';
    if unsafe {
        syscall3(
            SYS_WRITE_HOST,
            gate[1] as usize,
            &token as *const _ as usize,
            1,
        )
    } != 1
    {
        unsafe {
            syscall1(SYS_CLOSE_HOST, gate[1] as usize);
            syscall2(SYS_KILL, child as usize, 9);
        }
        launch_instance_fail(&mut instance, b"launch tracee gate release failed");
    }
    unsafe {
        syscall1(SYS_CLOSE_HOST, gate[1] as usize);
    }
    supervise_launch(
        child as usize,
        &mut instance,
        &mut filesystem,
        &mut devices,
        &mut channels,
        descriptors,
        &contract,
    )
}

/// Only the coordinator channel is an inherited supervisor resource. Drop all
/// other nonstandard descriptors before reserving bounded private backing FDs.
/// The result descriptor was opened here and must survive startup failures.
fn close_undeclared_inherited_descriptors(control: Option<usize>) -> Result<(), &'static [u8]> {
    let control = match control {
        Some(fd) if fd <= i32::MAX as usize => Some(fd as u32),
        Some(_) => return Err(b"control fd exceeds host descriptor range"),
        None => None,
    };
    let mut retained = [control, u32::try_from(unsafe { RESULT_FD }).ok()];
    retained.sort_unstable();
    let mut first = 3u32;
    for fd in retained.into_iter().flatten() {
        if fd < first {
            continue;
        }
        if first < fd && unsafe { syscall3(436, first as usize, fd as usize - 1, 0) } < 0 {
            return Err(b"inherited supervisor descriptor cleanup failed");
        }
        first = fd + 1;
    }
    if unsafe { syscall3(436, first as usize, u32::MAX as usize, 0) } < 0 {
        return Err(b"inherited supervisor descriptor cleanup failed");
    }
    Ok(())
}

fn launch_validate(config: &InstanceConfig) {
    // These are accepted instance fields, but their owners are the systemd
    // backend. Never silently launch with a requested restriction or hook ignored.
    // Hierarchical native policies have separate enforcement owners. The
    // configured lane must reject requested controls it cannot implement.
    if !config.filesystem_read.as_slice().is_empty()
        || !config.filesystem_write.as_slice().is_empty()
        || !config.filesystem_create.as_slice().is_empty()
        || !config.privilege_setuid.as_slice().is_empty()
        || !config.privilege_setgid.as_slice().is_empty()
        || !config.device_read.as_slice().is_empty()
        || !config.device_write.as_slice().is_empty()
        || !config.device_create.as_slice().is_empty()
        || config.process_max_processes != 4096
        || config.process_max_threads != 4096
        || !config.process_signals.as_slice().is_empty()
        || config.process_ptrace
        || !config.process_namespace_create.as_slice().is_empty()
        || !config.process_namespace_join.as_slice().is_empty()
        || !config.kernel_proc_read.as_slice().is_empty()
        || !config.kernel_proc_write.as_slice().is_empty()
        || !config.kernel_sys_read.as_slice().is_empty()
        || !config.kernel_sys_write.as_slice().is_empty()
    {
        launch_startup_fail(b"launch does not implement native hierarchical resource policy");
    }
    if !config.filesystem_write_deny.as_slice().is_empty()
        || !config.pre_boot_hooks.as_slice().is_empty()
    {
        launch_startup_fail(
            b"launch does not support filesystem write-deny rules or pre-boot hooks",
        );
    }
    if !config.ingress_allow.as_slice().is_empty()
        || !config.ingress_deny.as_slice().is_empty()
        || !config.egress_allow.as_slice().is_empty()
        || !config.egress_deny.as_slice().is_empty()
        || !config.port_forwards.as_slice().is_empty()
    {
        launch_startup_fail(
            b"launch requires numeric mediated endpoints, not shared-network policy",
        );
    }

    if config.execution_profile != ExecutionProfile::Balanced
        || config.execution_backend != ExecutionBackend::PtraceNative
    {
        launch_startup_fail(b"launch requires profile=balanced backend=ptrace-native");
    }
    if config.id.as_bytes().is_empty() || config.id.as_bytes().len() > 64 {
        launch_startup_fail(b"instance id length invalid");
    }
    if config.root.as_bytes().is_empty() || config.root.as_bytes().len() > 128 {
        launch_startup_fail(b"instance root length invalid");
    }
    launch_validate_path(
        config.init.as_bytes(),
        b"instance init must be an absolute confined path",
    );
    launch_validate_path(
        config.workdir.as_bytes(),
        b"instance workdir must be an absolute confined path",
    );
    if config.args.as_slice().len() > 7 {
        launch_startup_fail(b"instance args exceed 7 entries");
    }
    for argument in config.args.as_slice() {
        if argument.as_bytes().len() > MAX_LAUNCH_ARG_LEN || argument.as_bytes().contains(&0) {
            launch_startup_fail(b"instance arg exceeds 128 bytes");
        }
    }
    if config.environment.as_slice().len() > 8 {
        launch_startup_fail(b"instance environment exceeds 8 entries");
    }
    for variable in config.environment.as_slice() {
        let bytes = variable.as_bytes();
        let equals = bytes.iter().position(|byte| *byte == b'=');
        if bytes.len() > MAX_LAUNCH_ENV_LEN
            || bytes.contains(&0)
            || equals == Some(0)
            || equals.is_none()
        {
            launch_startup_fail(b"instance environment entry must be NAME=value within 256 bytes");
        }
    }
}

fn launch_validate_path(path: &[u8], reason: &[u8]) {
    if path.is_empty()
        || path.len() > MAX_LAUNCH_PATH_LEN
        || path[0] != b'/'
        || path.contains(&0)
        || contains_dotdot(path)
    {
        launch_startup_fail(reason);
    }
}

fn contains_dotdot(path: &[u8]) -> bool {
    path.split(|byte| *byte == b'/').any(|part| part == b"..")
}

fn stage_launch(config: &InstanceConfig) {
    let exec = stage_nul(
        core::ptr::addr_of_mut!(LAUNCH_EXEC).cast::<u8>(),
        129,
        config.init.as_bytes(),
        b"instance init staging failed",
    );
    unsafe {
        core::ptr::addr_of_mut!(LAUNCH_ARGV[0]).write(exec);
    }
    let mut argc = 1usize;
    for argument in config.args.as_slice() {
        let slot = unsafe { core::ptr::addr_of_mut!(LAUNCH_ARGS[(argc - 1) * 129]).cast::<u8>() };
        let staged = stage_nul(
            slot,
            129,
            argument.as_bytes(),
            b"instance arg staging failed",
        );
        unsafe {
            core::ptr::addr_of_mut!(LAUNCH_ARGV[argc]).write(staged);
        }
        argc += 1;
    }
    unsafe {
        core::ptr::addr_of_mut!(LAUNCH_ARGV[argc]).write(core::ptr::null());
    }
    let mut envc = 0usize;
    for variable in config.environment.as_slice() {
        let slot = unsafe { core::ptr::addr_of_mut!(LAUNCH_ENV[envc * 257]).cast::<u8>() };
        let staged = stage_nul(
            slot,
            257,
            variable.as_bytes(),
            b"instance environment staging failed",
        );
        unsafe {
            core::ptr::addr_of_mut!(LAUNCH_ENVP[envc]).write(staged);
        }
        envc += 1;
    }
    unsafe {
        core::ptr::addr_of_mut!(LAUNCH_ENVP[envc]).write(core::ptr::null());
    }
    stage_nul(
        core::ptr::addr_of_mut!(LAUNCH_WORKDIR).cast::<u8>(),
        129,
        config.workdir.as_bytes(),
        b"instance workdir staging failed",
    );
}

fn stage_nul(buffer: *mut u8, capacity: usize, value: &[u8], reason: &[u8]) -> *const u8 {
    if value.len() + 1 > capacity || value.contains(&0) {
        launch_startup_fail(reason);
    }
    unsafe {
        core::ptr::copy_nonoverlapping(value.as_ptr(), buffer, value.len());
        *buffer.add(value.len()) = 0;
    }
    buffer as *const u8
}

// ---- G02: faithful workload completion and streams ----
//
// `--result-file <fresh host path>` (Ginux-owned): after teardown the
// supervisor writes exactly one JSON object to that host-side path:
// {"version":1,"outcome":"exited|signaled|supervisor-error",
//  "code":<i64|null>,"signal":<u64|null>,"generation":null}.
// `generation` is null until retained-storage generations exist. The launcher exit code
// mirrors the workload exit code when the supervisor is healthy (low 8 bits,
// as wait reports it); a terminating signal exits 128+signo (classic shell
// convention); supervisor failure exits 1; startup failure exits 2. The
// result file is authoritative; a missing or malformed result file is a
// protocol failure, never success. The file is created with O_CREAT|O_EXCL
// before launch, so a non-fresh path fails before executing a workload.
// Write, fsync, or close failure exits 1, even if the workload succeeded.
//
// Streams: workload stdout is the tracee's own fd 1, never written by the
// supervisor (the effective-config echo moved to stderr on this path, and
// every audit/diagnostic line below carries the `ginux:` prefix on fd 2).
// Audit volume is bounded (see AUDIT_BYTE_BUDGET).
//
// Startup-failure choice (stated): when --result-file was supplied, startup
// failures (bad config, invalid args, bootstrap unavailable) also write
// outcome=supervisor-error and exit 2. Without the flag no file is created.

pub const MAX_RESULT_PATH_LEN: usize = 512;
pub const AUDIT_BYTE_BUDGET: usize = 64 * 1024;

static mut RESULT_FD: isize = -1;

static mut AUDIT_BYTES: usize = 0;
static mut AUDIT_CAPPED: bool = false;
static mut AUDIT_DISABLED: bool = false;
// One audit record is staged here and written whole once its newline
// arrives, so the budget never splits a record and the truncation notice
// always starts its own line.
const AUDIT_RECORD_CAPACITY: usize = 256;
static mut AUDIT_RECORD: [u8; AUDIT_RECORD_CAPACITY] = [0; AUDIT_RECORD_CAPACITY];
static mut AUDIT_RECORD_LEN: usize = 0;

const OUTCOME_EXITED: u8 = 0;
const OUTCOME_SIGNALED: u8 = 1;
const OUTCOME_SUPERVISOR_ERROR: u8 = 2;

fn c_string_len(value: *const u8) -> usize {
    // Volatile reads: keep LLVM from folding this NUL scan into a `strlen`
    // call, which the freestanding `-nostdlib -static` link does not provide
    // (see the volatile shims in `main.rs`).
    let mut length = 0usize;
    while unsafe { core::ptr::read_volatile(value.add(length)) } != 0 {
        length += 1;
    }
    length
}

fn stage_result_path(path: *const u8) {
    if path.is_null() {
        return;
    }
    let length = c_string_len(path);
    if length == 0 || length > MAX_RESULT_PATH_LEN {
        launch_startup_fail(b"result-file path length invalid");
    }
    // Reserve the result before starting any workload. O_EXCL prevents a
    // stale result being mistaken for this invocation's completion.
    const OPEN_FLAGS: usize = 1 | 64 | 128 | 0o2000000;
    let mut descriptor =
        unsafe { syscall4(SYS_OPENAT_HOST, AT_FDCWD, path as usize, OPEN_FLAGS, 0o600) };
    if descriptor < 0 {
        launch_startup_fail(b"result-file path is not fresh or not creatable");
    }
    if descriptor < 3 {
        // Keep the result separate from even closed stdin/stdout/stderr.
        const SYS_FCNTL: usize = 72;
        const F_DUPFD_CLOEXEC: usize = 1030;
        let duplicate = unsafe { syscall3(SYS_FCNTL, descriptor as usize, F_DUPFD_CLOEXEC, 3) };
        let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
        if duplicate < 0 {
            launch_startup_fail(b"result-file descriptor reservation failed");
        }
        descriptor = duplicate;
    }
    unsafe {
        RESULT_FD = descriptor;
    }
}

fn launch_rejected(reason: &str) -> ! {
    write_stderr(b"ginux: launch config rejected reason=");
    write_stderr(reason.as_bytes());
    write_stderr(b"\n");
    write_completion_result(OUTCOME_SUPERVISOR_ERROR, false, 0, false, 0);
    exit_process(2)
}

fn launch_read_config(path: *const u8) -> usize {
    let descriptor = unsafe { syscall4(SYS_OPENAT_HOST, AT_FDCWD, path as usize, O_RDONLY, 0) };
    if descriptor < 0 {
        launch_rejected("config open failed");
    }
    let mut length = 0usize;
    while length < MAX_CONFIG_SIZE {
        let result = unsafe {
            syscall3(
                SYS_READ_HOST,
                descriptor as usize,
                core::ptr::addr_of_mut!(CONFIG_BYTES)
                    .cast::<u8>()
                    .add(length) as usize,
                MAX_CONFIG_SIZE - length,
            )
        };
        if result < 0 {
            let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
            launch_rejected("config read failed");
        }
        if result == 0 {
            break;
        }
        length += result as usize;
    }
    let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
    if length == 0 || length == MAX_CONFIG_SIZE {
        launch_rejected("config size invalid");
    }
    length
}

fn launch_load_config(path: *const u8) -> InstanceConfig {
    let length = launch_read_config(path);
    let bytes = unsafe {
        core::slice::from_raw_parts(core::ptr::addr_of!(CONFIG_BYTES).cast::<u8>(), length)
    };
    match InstanceConfig::parse(bytes) {
        Ok(config) => config,
        Err(error) => launch_rejected(error.as_str()),
    }
}

fn print_launch_config(config: &InstanceConfig) {
    let normalized = match config.normalized() {
        Ok(normalized) => normalized,
        Err(error) => launch_rejected(error.as_str()),
    };
    line_stderr(b"ginux: config accepted format=toml schema=1");
    line_stderr(b"ginux: effective config begin");
    for line in normalized.as_bytes().split(|byte| *byte == b'\n') {
        if !line.is_empty() {
            write_stderr(b"ginux: ");
            line_stderr(line);
        }
    }
    line_stderr(b"ginux: effective config end");
}

pub fn usage() -> ! {
    line_stderr(b"ginux: usage: ginux (no arguments: interception demonstration)");
    line_stderr(
        b"ginux: usage: ginux config|instance-plan|instance-validate|instance-inspect|lifecycle|process|kernel-views <config>",
    );
    line_stderr(b"ginux: usage: ginux instance-explain <config> <operation>");
    line_stderr(b"ginux: usage: ginux instance-diff <left-config> <right-config>");
    line_stderr(b"ginux: usage: ginux runtime <elf>");
    line_stderr(b"ginux: usage: ginux instance|process-native <config> <fixture>");
    line_stderr(b"ginux: usage: ginux native <config> <root> [configured|hold|probe]");
    line_stderr(b"ginux: usage: ginux devices <config> <block>");
    line_stderr(b"ginux: usage: ginux device-bench <config> <block> <kind>");
    line_stderr(b"ginux: usage: ginux vfs <config> <rootfs> <index>");
    line_stderr(b"ginux: usage: ginux launch <config> <root> [--result-file <fresh host path>] [--export-file <fresh tar path>] [--control-fd <inherited socket>] [--restore-file <snapshot tar>]");
    exit_process(2)
}

pub fn launch_usage() -> ! {
    line_stderr(b"ginux: launch usage: launch <config> <root> [--result-file <fresh host path>] [--export-file <fresh tar path>] [--control-fd <inherited socket>] [--restore-file <snapshot tar>]");
    exit_process(2)
}

pub(crate) fn audit_enabled() -> bool {
    unsafe { !AUDIT_DISABLED }
}

/// Whether per-syscall audit records are still written: auditing is enabled
/// and its byte budget has not run out. Every native syscall exit then
/// records its result.
pub(crate) fn audit_tracing() -> bool {
    unsafe { !AUDIT_DISABLED && !AUDIT_CAPPED }
}

/// Fixed-size summaries bypass only the syscall trace budget. Callers bound
/// their records by the configured endpoint or compiled operation table.
pub(crate) fn audit_summary(arguments: core::fmt::Arguments<'_>) {
    if !audit_enabled() {
        return;
    }
    struct Writer;
    impl core::fmt::Write for Writer {
        fn write_str(&mut self, value: &str) -> core::fmt::Result {
            write_stderr(value.as_bytes());
            Ok(())
        }
    }
    let _ = core::fmt::write(&mut Writer, arguments);
}

pub(crate) fn audit_write(bytes: &[u8]) {
    let record = unsafe {
        if AUDIT_DISABLED || AUDIT_CAPPED {
            return;
        }
        let start = AUDIT_RECORD_LEN;
        if start + bytes.len() > AUDIT_RECORD_CAPACITY {
            // No record is this long; stop auditing rather than split one.
            audit_cap();
            return;
        }
        let record = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(AUDIT_RECORD).cast::<u8>(),
            AUDIT_RECORD_CAPACITY,
        );
        record[start..start + bytes.len()].copy_from_slice(bytes);
        AUDIT_RECORD_LEN = start + bytes.len();
        if bytes.last() != Some(&b'\n') {
            return;
        }
        let length = AUDIT_RECORD_LEN;
        AUDIT_RECORD_LEN = 0;
        if AUDIT_BYTES + length > AUDIT_BYTE_BUDGET {
            audit_cap();
            return;
        }
        AUDIT_BYTES += length;
        &record[..length]
    };
    write_stderr(record);
}

/// One complete record written beside the record being staged, charged to
/// the same budget. An owner that finishes work outside its own syscall's
/// result (an archive import closed by its last reference) records it here.
pub(crate) fn audit_record(arguments: core::fmt::Arguments<'_>) {
    struct Record {
        bytes: [u8; AUDIT_RECORD_CAPACITY],
        len: usize,
    }
    impl core::fmt::Write for Record {
        fn write_str(&mut self, value: &str) -> core::fmt::Result {
            let end = self.len + value.len();
            self.bytes
                .get_mut(self.len..end)
                .ok_or(core::fmt::Error)?
                .copy_from_slice(value.as_bytes());
            self.len = end;
            Ok(())
        }
    }
    let mut record = Record {
        bytes: [0; AUDIT_RECORD_CAPACITY],
        len: 0,
    };
    unsafe {
        if AUDIT_DISABLED || AUDIT_CAPPED {
            return;
        }
        // No record is this long; stop auditing rather than split one.
        if core::fmt::write(&mut record, arguments).is_err()
            || record.bytes[..record.len].last() != Some(&b'\n')
            || AUDIT_BYTES + record.len > AUDIT_BYTE_BUDGET
        {
            audit_cap();
            return;
        }
        AUDIT_BYTES += record.len;
    }
    write_stderr(&record.bytes[..record.len]);
}

fn audit_cap() {
    unsafe {
        AUDIT_CAPPED = true;
        AUDIT_RECORD_LEN = 0;
    }
    write_stderr(b"ginux: audit truncated budget=65536\n");
}

pub(crate) fn audit_u64(mut value: u64) {
    let mut buffer = [0u8; 20];
    let mut index = buffer.len();
    if value == 0 {
        audit_write(b"0");
        return;
    }
    while value != 0 {
        index -= 1;
        buffer[index] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    audit_write(&buffer[index..]);
}

pub(crate) fn audit_i64(value: i64) {
    if value < 0 {
        audit_write(b"-");
        audit_u64(value.unsigned_abs());
    } else {
        audit_u64(value as u64);
    }
}

fn push_u64(buffer: &mut [u8], mut position: usize, mut value: u64) -> usize {
    let mut digits = [0u8; 20];
    let mut count = 0usize;
    if value == 0 {
        digits[0] = b'0';
        count = 1;
    } else {
        while value != 0 {
            digits[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
        }
    }
    let mut index = count;
    while index > 0 {
        index -= 1;
        if position < buffer.len() {
            buffer[position] = digits[index];
            position += 1;
        }
    }
    position
}

fn push_bytes(buffer: &mut [u8], mut position: usize, bytes: &[u8]) -> usize {
    for byte in bytes {
        if position < buffer.len() {
            buffer[position] = *byte;
            position += 1;
        }
    }
    position
}

fn write_completion_result(outcome: u8, has_code: bool, code: u64, has_signal: bool, signal: u64) {
    if crate::storage_export::cancel().is_err() {
        line_stderr(b"ginux: export staging cleanup failed");
    }

    if crate::checkpoint_control::close().is_err() {
        line_stderr(b"ginux: checkpoint control close failed");
    }
    let descriptor = unsafe { RESULT_FD };
    if descriptor < 0 {
        return;
    }
    unsafe {
        RESULT_FD = -1;
    }
    let mut record = [0u8; 160];
    let mut position = 0usize;
    position = push_bytes(&mut record, position, b"{\"version\":1,\"outcome\":\"");
    position = push_bytes(
        &mut record,
        position,
        match outcome {
            OUTCOME_SIGNALED => b"signaled",
            OUTCOME_SUPERVISOR_ERROR => b"supervisor-error",
            _ => b"exited",
        },
    );
    position = push_bytes(&mut record, position, b"\",\"code\":");
    if has_code {
        position = push_u64(&mut record, position, code);
    } else {
        position = push_bytes(&mut record, position, b"null");
    }
    position = push_bytes(&mut record, position, b",\"signal\":");
    if has_signal {
        position = push_u64(&mut record, position, signal);
    } else {
        position = push_bytes(&mut record, position, b"null");
    }
    position = push_bytes(&mut record, position, b",\"generation\":null}\n");
    let mut offset = 0usize;
    while offset < position {
        let written = unsafe {
            syscall3(
                SYS_WRITE_HOST,
                descriptor as usize,
                record.as_ptr().add(offset) as usize,
                position - offset,
            )
        };
        if written == -4 {
            continue;
        }
        if written <= 0 {
            let _ = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
            line_stderr(b"ginux: result-file write failed");
            exit_process(1);
        }
        offset += written as usize;
    }
    let synced = loop {
        let result = unsafe { syscall1(SYS_FSYNC, descriptor as usize) };
        if result != -4 {
            break result;
        }
    };
    let closed = unsafe { syscall1(SYS_CLOSE_HOST, descriptor as usize) };
    if synced < 0 || closed < 0 {
        line_stderr(b"ginux: result-file sync or close failed");
        exit_process(1);
    }
}

pub(crate) fn finish_exited(code: u64) {
    line_stderr(b"ginux: launch supervisor=attached direct-unsupervised-syscalls=0");
    write_stderr(b"ginux: launch complete workload-exit-code=");
    write_stderr_u64(code);
    write_stderr(b"\n");
    write_completion_result(OUTCOME_EXITED, true, code, false, 0);
    exit_process(code as usize)
}

pub(crate) fn finish_signaled(signal: u64) {
    line_stderr(b"ginux: launch supervisor=attached direct-unsupervised-syscalls=0");
    write_stderr(b"ginux: launch complete workload-signal=");
    write_stderr_u64(signal);
    write_stderr(b"\n");
    write_completion_result(OUTCOME_SIGNALED, false, 0, true, signal);
    exit_process(128 + signal as usize)
}

// Limits apply only to this child, before its exec. Kernel inheritance keeps
// them on descendants; no cgroup mounts or host-global policy are modified.
fn restrict_tracee_resources(config: &InstanceConfig) -> bool {
    let mut limits = [0usize; 2];
    if unsafe { syscall4(302, 0, 9, 0, limits.as_mut_ptr() as usize) } != 0 {
        return false;
    }
    let Some(bytes) = usize::try_from(config.memory_mib)
        .ok()
        .and_then(|mib| mib.checked_mul(1024 * 1024))
    else {
        return false;
    };
    let bound = bytes.min(limits[0]).min(limits[1]);
    limits = [bound, bound];
    if unsafe { syscall4(302, 0, 9, limits.as_ptr() as usize, 0) } != 0 {
        return false;
    }
    let mut mask = [0u8; 1024];
    let size = unsafe { syscall3(204, 0, mask.len(), mask.as_mut_ptr() as usize) };
    if size <= 0 || size as usize > mask.len() {
        return false;
    }
    let mut remaining = config.vcpus;
    for byte in &mut mask[..size as usize] {
        for bit in 0..8 {
            if *byte & (1 << bit) != 0 {
                if remaining == 0 {
                    *byte &= !(1 << bit);
                } else {
                    remaining -= 1;
                }
            }
        }
    }
    unsafe { syscall3(203, 0, size as usize, mask.as_ptr() as usize) == 0 }
}

fn launch_tracee(
    root_path: *const u8,
    config: &InstanceConfig,
    descriptor_limit: usize,
    gate: usize,
) -> ! {
    static ROOT: &[u8] = b"/\0";
    let mut token = 0u8;
    loop {
        let n = unsafe { syscall3(SYS_READ_HOST, gate, &mut token as *mut _ as usize, 1) };
        if n == -4 {
            continue;
        }
        if n != 1 || token != b'G' {
            tracee_setup_fail(
                b"ginux: launch bootstrap failed: ptrace startup gate failed\n",
                122,
            );
        }
        break;
    }
    unsafe {
        syscall1(SYS_CLOSE_HOST, gate);
    }
    if !restrict_tracee_resources(config) {
        tracee_setup_fail(
            b"ginux: launch bootstrap failed: resource bounds unavailable\n",
            132,
        );
    }
    // Host descriptors (including the result file) must not grant the
    // workload authority outside the supplied root. Only stdio is shared.
    const SYS_CLOSE_RANGE: usize = 436;
    if !crate::tracee_io::reserve_native_descriptors(descriptor_limit) {
        tracee_setup_fail(
            b"ginux: launch bootstrap failed: descriptor namespace unavailable\n",
            130,
        );
    }
    if unsafe { syscall3(SYS_CLOSE_RANGE, 3, u32::MAX as usize, 0) } < 0 {
        tracee_setup_fail(
            b"ginux: launch bootstrap failed: descriptor cleanup failed\n",
            129,
        );
    }
    // A caller's ignored SIGCHLD must not silently enable native auto-reap
    // in a instance whose child lifetime is owned by the virtual process table.
    let default_sigchld = [0u64; 4];
    if unsafe { syscall4(13, 17, default_sigchld.as_ptr() as usize, 0, 8) } < 0 {
        tracee_setup_fail(
            b"ginux: launch bootstrap failed: child signal setup failed\n",
            131,
        );
    }
    // The caller's blocked signals are process state, not workload policy.
    // Start the tracee with an empty mask before its first exec.
    let empty_mask = 0u64;
    if unsafe {
        syscall4(
            crate::supervisor::SYS_RT_SIGPROCMASK,
            2,
            &empty_mask as *const _ as usize,
            0,
            8,
        )
    } < 0
    {
        tracee_setup_fail(
            b"ginux: launch bootstrap failed: child signal setup failed\n",
            131,
        );
    }
    if unsafe { syscall1(SYS_CHROOT, root_path as usize) } < 0 {
        tracee_setup_fail(
            b"ginux: launch bootstrap unavailable: chroot failed (host privilege required)\n",
            120,
        );
    }
    if unsafe { syscall1(SYS_CHDIR, ROOT.as_ptr() as usize) } < 0 {
        tracee_setup_fail(
            b"ginux: launch bootstrap failed: root directory unavailable\n",
            121,
        );
    }
    let workdir = core::ptr::addr_of!(LAUNCH_WORKDIR).cast::<u8>();
    let _ = unsafe { syscall3(SYS_MKDIRAT, AT_FDCWD, workdir as usize, 0o755) };
    let host_identity = managed_host_identity();
    if host_identity.drop_root {
        if unsafe { syscall2(SYS_SETGROUPS, 0, 0) } < 0 {
            tracee_setup_fail(
                b"ginux: launch bootstrap failed: supplementary groups drop failed\n",
                123,
            );
        }
        if unsafe { syscall1(SYS_SETGID, host_identity.gid) } < 0 {
            tracee_setup_fail(
                b"ginux: launch bootstrap failed: group privilege drop failed\n",
                124,
            );
        }
        if unsafe { syscall1(SYS_SETUID, host_identity.uid) } < 0 {
            tracee_setup_fail(
                b"ginux: launch bootstrap failed: user privilege drop failed\n",
                125,
            );
        }
    }
    if unsafe { syscall5(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        tracee_setup_fail(
            b"ginux: launch bootstrap failed: no-new-privileges failed\n",
            126,
        );
    }
    if unsafe { syscall1(SYS_CHDIR, workdir as usize) } < 0 {
        tracee_setup_fail(
            b"ginux: launch startup failure: configured instance workdir unavailable\n",
            128,
        );
    }
    // From here every syscall stops in the supervisor at its entry as a
    // seccomp event, the exec below first. A kernel that refuses the filter
    // leaves the workload on syscall-entry stops instead: the supervisor
    // sees the exec event without a seccomp event before it and keeps
    // resuming every task with PTRACE_SYSCALL.
    let _ = crate::supervisor::install_launch_filter();
    unsafe {
        syscall3(
            SYS_EXECVE,
            core::ptr::addr_of!(LAUNCH_EXEC) as usize,
            core::ptr::addr_of!(LAUNCH_ARGV) as usize,
            core::ptr::addr_of!(LAUNCH_ENVP) as usize,
        );
        write_stderr(b"ginux: launch startup failure: exec of configured instance init failed\n");
        syscall1(SYS_EXIT_HOST, 127);
    }
    loop {
        core::hint::spin_loop();
    }
}

fn tracee_setup_fail(message: &[u8], code: usize) -> ! {
    write_stderr(message);
    unsafe { syscall1(SYS_EXIT_HOST, code) };
    loop {
        core::hint::spin_loop();
    }
}

fn supervise_launch(
    pid: usize,
    instance: &mut Instance,
    filesystem: &mut crate::launch_storage::LaunchFs,
    devices: &mut crate::device_hooks::LaunchDevices,
    channels: &mut crate::channel_hooks::LaunchChannels,
    descriptors: crate::descriptors::DescriptorTable,
    contract: &EffectiveContract,
) -> ! {
    let mut refs = crate::descriptors::ObjectReferences::new();
    let objects = crate::descriptors::Backends {
        filesystem,
        devices,
        channels,
        refs: &mut refs,
    };
    crate::launch_tasks::supervise(pid, instance, objects, descriptors, contract)
}

pub(crate) fn launch_exit_reason(code: i32) -> &'static [u8] {
    match code {
        120 => b"bootstrap unavailable: chroot failed (host privilege required)",
        121 => b"bootstrap failed: root directory unavailable",
        122 => b"bootstrap failed: ptrace startup gate failed",
        123 => b"bootstrap failed: supplementary groups drop failed",
        124 => b"bootstrap failed: group privilege drop failed",
        125 => b"bootstrap failed: user privilege drop failed",
        126 => b"bootstrap failed: no-new-privileges failed",
        127 => b"exec of configured instance init failed",
        128 => b"configured instance workdir unavailable",
        129 => b"descriptor cleanup failed",
        130 => b"descriptor namespace unavailable",
        131 => b"child signal setup failed",
        _ => b"tracee exited before supervision",
    }
}

pub(crate) fn launch_early_fail(instance: &mut Instance, reason: &[u8]) -> ! {
    let _ = instance.task_exited(false);
    launch_startup_fail(reason)
}

fn launch_instance_fail(instance: &mut Instance, reason: &[u8]) -> ! {
    let _ = instance.task_exited(false);
    launch_startup_fail(reason)
}

pub(crate) fn supervision_error(instance: &mut Instance, reason: &[u8]) -> ! {
    let _ = instance.task_exited(false);
    write_stderr(b"ginux: launch supervision failure: ");
    write_stderr(reason);
    write_stderr(b"\n");
    write_completion_result(OUTCOME_SUPERVISOR_ERROR, false, 0, false, 0);
    exit_process(1)
}

fn launch_startup_fail(reason: &[u8]) -> ! {
    write_stderr(b"ginux: launch startup failure: ");
    write_stderr(reason);
    write_stderr(b"\n");
    write_completion_result(OUTCOME_SUPERVISOR_ERROR, false, 0, false, 0);
    exit_process(2)
}

pub(crate) fn write_stderr(bytes: &[u8]) {
    let mut offset = 0;
    while offset < bytes.len() {
        let result = unsafe {
            syscall3(
                SYS_WRITE_HOST,
                2,
                bytes.as_ptr().add(offset) as usize,
                bytes.len() - offset,
            )
        };
        if result <= 0 {
            return;
        }
        offset += result as usize;
    }
}

pub(crate) fn line_stderr(message: &[u8]) {
    write_stderr(message);
    write_stderr(b"\n");
}

fn write_stderr_u64(mut value: u64) {
    let mut buffer = [0u8; 20];
    let mut index = buffer.len();
    if value == 0 {
        write_stderr(b"0");
        return;
    }
    while value != 0 {
        index -= 1;
        buffer[index] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    write_stderr(&buffer[index..]);
}

// Host vDSO reads and synthetic /proc,/sys/cgroup views cannot currently be
// withheld by configured launch. Refuse explicit denials instead of promising
// confinement the backend cannot provide. Implicit absence is documented.
fn launch_cannot_enforce(rule: &EffectiveRule) -> bool {
    let explicit = matches!(
        rule.provenance,
        Provenance::InstanceDeny | Provenance::RecipeDeny | Provenance::ExactDeny
    );
    explicit
        && matches!(rule.operation.status, Status::Complete | Status::Partial)
        && match rule.operation.kind {
            Kind::Syscall => rule
                .operation
                .abi_number
                .is_some_and(|n| [96, 201, 228, 229, 309].contains(&n)),
            _ => ![
                "filesystem.path.read",
                "filesystem.path.write",
                "device.console.read",
                "device.console.write",
                "ioctl.tty.get_winsize",
                "memory.virtual.manage",
                "signal.virtual.deliver",
                "credential.virtual.set",
                "network.inet.tcp.bind",
                "network.inet.tcp.connect",
                "network.inet.udp.bind",
                "network.inet.udp.connect",
            ]
            .contains(&rule.operation.id),
        }
}

pub(crate) fn audit_rule(rule: Option<&EffectiveRule>) {
    audit_write(b" operation=");
    audit_write(rule.map_or(b"unknown".as_slice(), |r| r.operation.id.as_bytes()));
    audit_write(b" policy-source=");
    if let Some(rule) = rule {
        audit_write(rule.source.as_bytes());
        audit_write(b" policy-rule=");
        audit_u64(rule.source_rule as u64);
    } else {
        audit_write(b"default-deny");
    }
}

/// Classify the original public call before any register translation or hook
/// effects. The descriptor owner preserves console and TCP identity on aliases.
pub(crate) fn launch_semantic_operation(
    r: &crate::supervisor::UserRegs,
    table: &crate::descriptors::DescriptorTable,
) -> Option<&'static str> {
    let path = |flags: u64| {
        if flags as u32 & (3 | 0o100 | 0o1000 | 0o2000 | 0o20000000) != 0 {
            "filesystem.path.write"
        } else {
            "filesystem.path.read"
        }
    };
    match r.orig_rax {
        0 | 19 if table.console_descriptor(r.rdi) => Some("device.console.read"),
        1 | 20 if table.console_descriptor(r.rdi) => Some("device.console.write"),
        0 | 1 | 19 | 20 | 42 | 44..=48 | 51 | 52 | 54 | 55 if table.network_descriptor(r.rdi) => {
            Some("network.inet.tcp.connect")
        }
        41 if r.rdi as u32 == 2 || r.rdi as u32 == 10 => Some("network.inet.tcp.connect"),
        2 => Some(path(r.rsi)),
        257 => Some(path(r.rdx)),
        0 | 4 | 5 | 6 | 17 | 19 | 21 | 78 | 79 | 80 | 81 | 89 | 217 | 262 | 267 | 269 | 332
        | 439 => Some("filesystem.path.read"),
        1
        | 18
        | 20
        | 76
        | 77
        | 82..=88
        | 90..=94
        | 132
        | 133
        | 258
        | 259
        | 260
        | 263..=266
        | 268
        | 280
        | 316
        | 452 => Some("filesystem.path.write"),
        // A transfer writes its output descriptor; its input is decided too,
        // by `launch_transfer_input_operation`.
        40 => Some(descriptor_write_operation(r.rdi, table)),
        326 => Some(descriptor_write_operation(r.rdx, table)),
        n => match configured_semantic_operation(n) {
            Some(operation) => Some(operation),
            None => syscall_semantic_operation(n, r.rsi),
        },
    }
}

/// The family a write to public descriptor `fd` is decided by.
fn descriptor_write_operation(
    fd: u64,
    table: &crate::descriptors::DescriptorTable,
) -> &'static str {
    if table.console_descriptor(fd) {
        "device.console.write"
    } else if table.network_descriptor(fd) {
        "network.inet.tcp.connect"
    } else {
        "filesystem.path.write"
    }
}

/// `sendfile` and `copy_file_range` read one descriptor and write another.
/// `launch_semantic_operation` decides the write; this is the family of the
/// read, decided as `read` on that descriptor would be. Both must be granted,
/// so a transfer never moves bytes a plain `read` and `write` could not.
pub(crate) fn launch_transfer_input_operation(
    r: &crate::supervisor::UserRegs,
    table: &crate::descriptors::DescriptorTable,
) -> Option<&'static str> {
    let fd = match r.orig_rax {
        40 => r.rsi,
        326 => r.rdi,
        _ => return None,
    };
    Some(if table.console_descriptor(fd) {
        "device.console.read"
    } else if table.network_descriptor(fd) {
        "network.inet.tcp.connect"
    } else {
        "filesystem.path.read"
    })
}
