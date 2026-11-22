//! Shared native-syscall dispatch wiring.
//!
//! Classifies syscall entries and applies hook validation before the shared
//! balanced contract. The process-native loop uses `process_entry` directly
//! and mediates supported process calls through its own event loop.

use ginux_core::{
    configured_arguments_allowed, configured_vectors_allowed, decide_balanced, decide_configured,
    Action, BalancedSurface, Decision, SYS_FORK, SYS_PREADV, SYS_READV,
};
use ginux_fs_policy::CallContext;

use crate::supervisor::UserRegs;

/// Lane a syscall number is routed to once its owning lane implements it.
pub enum Lane {
    Process,
    Filesystem,
    Device,
    Channel,
    Contract,
}

/// Route process entries to their hook and unclaimed entries to the contract.
pub const fn classify(syscall: u64) -> Lane {
    if crate::process_hooks::claims(syscall) {
        Lane::Process
    } else if crate::fs_hooks::claims(syscall) {
        Lane::Filesystem
    } else if crate::channel_hooks::claims(syscall) {
        Lane::Channel
    } else {
        Lane::Contract
    }
}

/// Outcome of dispatching one native entry.
pub enum NativeDecision {
    /// Retain an owned syscall entry until peer progress; wake peers when
    /// this attempt published bytes before filling its bounded buffer.
    Park { fd: u32, progressed: bool },
    /// A public-descriptor query waits for object readiness or a deadline.
    ParkPoll,
    /// Kernel signal-mask arbitration with zero FDs and a zero timeout.
    SignalWait { retry: bool },
    /// A lane hook claimed the entry; emulate it with this result.
    Hooked { lane: Lane, result: i64 },
    /// No hook claimed the entry; apply the shared contract decision.
    Contract(Decision),
}

/// Dispatch one native supervision entry through lane hooks first, then the
/// existing balanced-contract decision. `classify` is the single routing
/// table: each lane arm gives its hook the first chance, and anything no
/// hook claims falls through to `decide_balanced` byte-identically. The one
/// exception is fork, which both callers (`launch` and `native`) deny
/// although the balanced contract lists it in the task surface.
pub fn decide_native(context: &CallContext) -> NativeDecision {
    if let ginux_fs_policy::ContractAuthorization::Deny(errno) = context.contract {
        return NativeDecision::Contract(Decision {
            syscall: context.syscall,
            action: Action::Deny(errno),
        });
    }
    decide_lanes(context, decide_balanced)
}

/// The lane hooks, then `contract` for anything no hook claims: the balanced
/// decision natively, the configured one in configured launch.
fn decide_lanes(context: &CallContext, contract: fn(u64) -> Decision) -> NativeDecision {
    let syscall = context.syscall;
    // Neither caller traces children, so a host fork would leave the child
    // running unsupervised.
    if syscall == SYS_FORK {
        return NativeDecision::Contract(Decision {
            syscall,
            action: Action::Deny(38),
        });
    }
    match classify(syscall) {
        Lane::Process => match crate::process_hooks::claim(
            syscall,
            context.arguments[0],
            context.arguments[1],
            context.arguments[2],
        ) {
            Some(result) => NativeDecision::Hooked {
                lane: Lane::Process,
                result,
            },
            None => NativeDecision::Contract(contract(syscall)),
        },
        Lane::Filesystem => match crate::fs_hooks::claim(context, true) {
            crate::fs_hooks::Claim::Denied(result) => NativeDecision::Hooked {
                lane: Lane::Filesystem,
                result,
            },
            crate::fs_hooks::Claim::Unclaimed => NativeDecision::Contract(contract(syscall)),
        },
        Lane::Channel => match crate::channel_hooks::claim(
            syscall,
            context.arguments[0],
            context.arguments[1],
            context.arguments[2],
        ) {
            Some(result) => NativeDecision::Hooked {
                lane: Lane::Channel,
                result,
            },
            None => NativeDecision::Contract(contract(syscall)),
        },
        Lane::Device | Lane::Contract => NativeDecision::Contract(contract(syscall)),
    }
}

/// Resolve registered backend objects before the immutable native contract.
pub fn decide_objects(
    pid: usize,
    signal_tgid: usize,
    registers: &UserRegs,
    filesystem: &mut crate::launch_storage::LaunchFs,
    devices: &mut crate::device_hooks::LaunchDevices,
    channels: &mut crate::channel_hooks::LaunchChannels,
    progress: &mut crate::channel_hooks::WriteProgress,
) -> NativeDecision {
    if let Some(result) = crate::stack_view::metadata(pid, registers) {
        NativeDecision::Hooked {
            lane: Lane::Filesystem,
            result: result.unwrap_or_else(|error| error),
        }
    } else if let Some(result) = channels.claim(pid, signal_tgid, registers, progress) {
        match result {
            crate::channel_hooks::ChannelResult::Ready(result) => NativeDecision::Hooked {
                lane: Lane::Channel,
                result,
            },
            crate::channel_hooks::ChannelResult::Blocked { fd, progressed } => {
                NativeDecision::Park { fd, progressed }
            }
        }
    } else if let Some(result) = devices.network.claim(pid, signal_tgid, registers) {
        match result {
            crate::network_hooks::Result::Ready(result) => NativeDecision::Hooked {
                lane: Lane::Device,
                result,
            },
            crate::network_hooks::Result::Blocked => NativeDecision::Park {
                fd: registers.rdi as u32,
                progressed: false,
            },
        }
    } else if let Some(result) = devices.claim(pid, registers, filesystem) {
        NativeDecision::Hooked {
            lane: Lane::Device,
            result,
        }
    } else if let Some(result) = filesystem.claim(pid, registers) {
        NativeDecision::Hooked {
            lane: Lane::Filesystem,
            result,
        }
    } else {
        // Only the configured descriptor owner reaches here: a descriptor
        // argument is already its registered native handle.
        decide_lanes(&configured_call_context(pid, registers), decide_configured)
    }
}

/// The filesystem-lane call context of a configured-launch entry. Configured
/// launch owns paths through its own storage (`launch_storage`), not through
/// Gate 31 capabilities, so root, cwd and descriptor-table authority are
/// explicitly unavailable: should the filesystem lane ever claim a call here,
/// its shared guard denies it before any host effect. The resolved contract
/// already denied what it denies before this point, so what reaches it is
/// admitted (`Mediate`).
fn configured_call_context(pid: usize, registers: &UserRegs) -> CallContext {
    use ginux_fs_policy::{
        identity_token, AuthorityContext, Capability, CapabilityKind, ContractAuthorization,
        InstanceContext, TaskContext,
    };
    const INSTANCE: u64 = identity_token(b"configured-launch");
    let lifetime = (INSTANCE ^ pid as u64).max(1);
    let unavailable = |kind| Capability::unavailable(kind, INSTANCE, lifetime);
    CallContext::x86_64(
        registers.orig_rax,
        [
            registers.rdi,
            registers.rsi,
            registers.rdx,
            registers.r10,
            registers.r8,
            registers.r9,
        ],
        TaskContext {
            host: pid as u64,
            virtual_id: 1,
            generation: 1,
        },
        InstanceContext {
            identity: INSTANCE,
            lifetime,
            root_generation: 0,
        },
        AuthorityContext {
            root: unavailable(CapabilityKind::Root),
            cwd: unavailable(CapabilityKind::WorkingDirectory),
            descriptor_table: unavailable(CapabilityKind::DescriptorTable),
            cwd_generation: 0,
            descriptor_generation: 0,
        },
        ContractAuthorization::Mediate,
    )
}

/// Configured launch resolves the public descriptor ABI before backend handles.
/// `shared`: another task uses the same descriptor table.
pub fn decide_launch(
    pid: usize,
    signal_tgid: usize,
    registers: &mut UserRegs,
    descriptors: &mut crate::descriptors::DescriptorTable,
    backends: &mut crate::descriptors::Backends,
    call: &mut crate::descriptors::DescriptorCall,
    shared: bool,
) -> NativeDecision {
    descriptors.enter(pid, signal_tgid, registers, backends, call, shared)
}

/// Dispatch one process-supervision entry through the process-lane hook.
/// `None` keeps the existing entry match in the supervision loop.
pub fn process_entry(syscall: u64, rdi: u64, rsi: u64, rdx: u64) -> Option<i64> {
    crate::process_hooks::claim(syscall, rdi, rsi, rdx)
}

/// `pid` is the stopped caller, whose `readv` or `preadv` vector array is
/// summed for the image read bound. The sum is a snapshot: a peer that
/// rewrites its own array before the kernel reads it can only enlarge its own
/// read of a read-only descriptor into its own memory, as further calls could.
pub fn launch_arguments_allowed(pid: usize, syscall: u64, registers: &UserRegs) -> bool {
    if syscall == SYS_READV || syscall == SYS_PREADV {
        return configured_vectors_allowed(crate::tracee_io::vector_total(
            pid,
            registers.rsi,
            registers.rdx,
        ));
    }
    configured_arguments_allowed(syscall, registers.rdi, registers.rsi, registers.rdx)
}

pub fn balanced_surface_name(surface: BalancedSurface) -> &'static [u8] {
    match surface {
        BalancedSurface::ImageRead => b"immutable-image result=pending",
        BalancedSurface::Memory => b"memory result=pending",
        BalancedSurface::Task => b"task result=pending",
        BalancedSurface::Console => b"bootstrap-console result=pending",
        BalancedSurface::Random => b"random result=pending",
        BalancedSurface::InstanceWrite => b"disposable-instance-write result=pending",
        BalancedSurface::Network => b"shared-network result=pending",
        BalancedSurface::VirtualIdentity | BalancedSurface::Lifecycle | BalancedSurface::Denied => {
            b"invalid result=denied"
        }
    }
}
