//! Shared native-syscall dispatch wiring.
//!
//! Single owner for entry classification and the contract decision used by
//! the supervision loops. Lane hooks live in disjoint files
//! (`process_hooks`, `fs_hooks`, `channel_hooks`). Stateless demonstration hooks
//! retain their balanced-contract fallback. Configured launch first resolves
//! its domain-owned filesystem and device objects in `decide_launch`.

use ginux_core::{balanced_arguments_allowed, decide_balanced, BalancedSurface, Decision};

use crate::supervisor::UserRegs;

/// Lane a syscall number is routed to once its owning lane implements it.
pub enum Lane {
    Process,
    Filesystem,
    Device,
    Channel,
    Contract,
}

/// Classify an entry by number for future lane wiring. All lanes decline
/// today, so this always returns `Lane::Contract`.
pub fn classify(syscall: u64) -> Lane {
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
    /// An owned channel cannot progress yet. Keep this task at entry.
    Park { fd: u32 },
    /// A lane hook claimed the entry; emulate it with this result.
    Hooked { lane: Lane, result: i64 },
    /// No hook claimed the entry; apply the shared contract decision.
    Contract(Decision),
}

/// Dispatch one native supervision entry through lane hooks first, then the
/// existing balanced-contract decision. `classify` is the single routing
/// table: each lane arm gives its hook the first chance, and anything no
/// hook claims falls through to `decide_balanced` byte-identically.
pub fn decide_native(syscall: u64, rdi: u64, rsi: u64, rdx: u64) -> NativeDecision {
    match classify(syscall) {
        Lane::Process => match crate::process_hooks::claim(syscall, rdi, rsi, rdx) {
            Some(result) => NativeDecision::Hooked {
                lane: Lane::Process,
                result,
            },
            None => NativeDecision::Contract(decide_balanced(syscall)),
        },
        Lane::Filesystem => match crate::fs_hooks::claim(syscall, rdi, rsi, rdx) {
            Some(result) => NativeDecision::Hooked {
                lane: Lane::Filesystem,
                result,
            },
            None => NativeDecision::Contract(decide_balanced(syscall)),
        },
        Lane::Channel => match crate::channel_hooks::claim(syscall, rdi, rsi, rdx) {
            Some(result) => NativeDecision::Hooked {
                lane: Lane::Channel,
                result,
            },
            None => NativeDecision::Contract(decide_balanced(syscall)),
        },
        Lane::Device | Lane::Contract => NativeDecision::Contract(decide_balanced(syscall)),
    }
}

/// Resolve configured domain objects before the immutable native contract.
/// Device descriptors have a separate reserved range and must resolve before
/// the filesystem rejects unknown virtual descriptors.
pub fn decide_objects(
    pid: usize,
    registers: &UserRegs,
    filesystem: &mut crate::fs_hooks::LaunchFs,
    devices: &mut crate::device_hooks::LaunchDevices,
    channels: &mut crate::channel_hooks::LaunchChannels,
) -> NativeDecision {
    if let Some(result) = channels.claim(pid, registers) {
        match result {
            crate::channel_hooks::ChannelResult::Ready(result) => NativeDecision::Hooked {
                lane: Lane::Channel,
                result,
            },
            crate::channel_hooks::ChannelResult::Blocked { fd } => NativeDecision::Park { fd },
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
        decide_native(
            registers.orig_rax,
            registers.rdi,
            registers.rsi,
            registers.rdx,
        )
    }
}

/// Configured launch resolves the public descriptor ABI before backend handles.
pub fn decide_launch(
    pid: usize,
    registers: &mut UserRegs,
    descriptors: &mut crate::descriptors::DescriptorTable,
    backends: &mut crate::descriptors::Backends,
    call: &mut crate::descriptors::DescriptorCall,
) -> NativeDecision {
    descriptors.enter(pid, registers, backends, call)
}

/// Dispatch one process-supervision entry through the process-lane hook.
/// `None` keeps the existing entry match in the supervision loop.
pub fn process_entry(syscall: u64, rdi: u64, rsi: u64, rdx: u64) -> Option<i64> {
    crate::process_hooks::claim(syscall, rdi, rsi, rdx)
}

pub fn native_arguments_allowed(pid: usize, syscall: u64, registers: &UserRegs) -> bool {
    if syscall == ginux_core::SYS_POLL
        && !crate::channel_hooks::bootstrap_poll_allowed(pid, registers.rdi, registers.rsi)
    {
        return false;
    }
    balanced_arguments_allowed(syscall, registers.rdi, registers.rsi, registers.rdx)
}

pub fn balanced_surface_name(surface: BalancedSurface) -> &'static [u8] {
    match surface {
        BalancedSurface::ImageRead => b"immutable-image result=pending",
        BalancedSurface::Memory => b"memory result=pending",
        BalancedSurface::Task => b"task result=pending",
        BalancedSurface::Console => b"bootstrap-console result=pending",
        BalancedSurface::Random => b"random result=pending",
        BalancedSurface::VirtualIdentity | BalancedSurface::Lifecycle | BalancedSurface::Denied => {
            b"invalid result=denied"
        }
    }
}
