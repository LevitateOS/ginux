//! Native filesystem-lane dispatch hooks.
//!
//! Owner: G-files lane. G06 claims domain directory creation and enumeration
//! (`mkdir`/`mkdirat`/`getdents64`) so no directory operation reaches the
//! host: faithful emulation needs tracee-memory path reads owned by later
//! lanes (G06a/G07), so every claimed entry is explicitly denied until
//! VFS-backed emulation lands. Everything else declines and the supervisor
//! keeps its existing balanced-contract behavior byte-identical.

/// `mkdir(2)`: domain directory creation. Claimed for G06.
pub const SYS_MKDIR: u64 = 83;
/// `mkdirat(2)`: domain directory creation relative to a directory fd.
/// Claimed for G06.
pub const SYS_MKDIRAT: u64 = 258;
/// `getdents64(2)`: domain directory enumeration. Claimed for G06: the
/// balanced contract would mediate it to the host, exposing host directory
/// contents as managed results.
pub const SYS_GETDENTS64: u64 = 217;

/// Lane membership by syscall number: directory creation and enumeration.
pub fn claims(syscall: u64) -> bool {
    matches!(syscall, SYS_MKDIR | SYS_MKDIRAT | SYS_GETDENTS64)
}

/// Emulated result when this lane handles the entry. `Some(-EPERM)` denies
/// the entry explicitly: confinement first — escape is denial, never host
/// effect. `None` falls through to the shared balanced-contract decision.
pub fn claim(syscall: u64, rdi: u64, rsi: u64, rdx: u64) -> Option<i64> {
    let _ = (rdi, rsi, rdx);
    if claims(syscall) {
        Some(-1)
    } else {
        None
    }
}
