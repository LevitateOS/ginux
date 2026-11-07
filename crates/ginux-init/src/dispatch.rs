//! Shared native-syscall dispatch wiring.
//!
//! Classifies syscall entries and applies hook validation before the shared
//! balanced contract. The process-native loop uses `process_entry` directly
//! and mediates supported process calls through its own event loop.

use ginux_core::{
    balanced_arguments_allowed, decide_balanced, Action, BalancedSurface, Decision, SYS_FORK,
};

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
    /// An owned channel cannot progress yet; retain its syscall-entry stop.
    Park { fd: u32 },
    /// A public-descriptor query waits for object readiness or a deadline.
    ParkPoll,
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
pub fn decide_native(syscall: u64, rdi: u64, rsi: u64, rdx: u64) -> NativeDecision {
    // Neither caller traces children, so a host fork would leave the child
    // running unsupervised.
    if syscall == SYS_FORK {
        return NativeDecision::Contract(Decision {
            syscall,
            action: Action::Deny(38),
        });
    }
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

/// Resolve registered backend objects before the immutable native contract.
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
    } else if let Some(result) = devices.network.claim(pid, registers) {
        match result {
            crate::network_hooks::Result::Ready(result) => NativeDecision::Hooked {
                lane: Lane::Device,
                result,
            },
            crate::network_hooks::Result::Blocked => NativeDecision::Park {
                fd: registers.rdi as u32,
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

pub fn native_arguments_allowed(syscall: u64, registers: &UserRegs) -> bool {
    balanced_arguments_allowed(syscall, registers.rdi, registers.rsi, registers.rdx)
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
