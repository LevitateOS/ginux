//! Private coordinator socket for serialized owned-filesystem snapshots.
//! Requests: GXS1, u64 LE sequence, u16 LE pathname length, pathname bytes.
//! Replies: GXA1, matching u64 sequence, u64 zero status. A reply follows file
//! fsync/close; the coordinator must sync its directory and matching state before
//! acknowledging the workload. Invalid requests or storage failures stop launch.
use crate::fs_hooks::LaunchFs;
use crate::supervisor::{syscall3, syscall5, syscall6};

type Error = &'static [u8];
const HEADER: usize = 14;
const PATH: usize = crate::launch::MAX_RESULT_PATH_LEN;
struct Control {
    fd: Option<usize>,
    bytes: [u8; HEADER + PATH],
    used: usize,
    wanted: usize,
    last: u64,
    reply: [u8; 20],
    sent: usize,
}
static mut CONTROL: Control = Control {
    fd: None,
    bytes: [0; HEADER + PATH],
    used: 0,
    wanted: HEADER,
    last: 0,
    reply: [0; 20],
    sent: 20,
};

pub fn prepare(fd: Option<usize>) -> Result<(), Error> {
    let Some(fd) = fd else {
        return Ok(());
    };
    let mut kind = 0i32;
    let mut length = 4u32;
    let mut address = [0u8; 128];
    let mut address_length = address.len() as u32;
    if unsafe {
        syscall5(
            55,
            fd,
            1,
            3,
            &mut kind as *mut _ as usize,
            &mut length as *mut _ as usize,
        )
    } != 0
        || kind != 1
        || length != 4
        || unsafe {
            syscall3(
                51,
                fd,
                address.as_mut_ptr() as usize,
                &mut address_length as *mut _ as usize,
            )
        } != 0
        || address_length < 2
        || u16::from_ne_bytes([address[0], address[1]]) != 1
    {
        return Err(b"control fd must be an inherited Unix stream socket");
    }
    let flags = unsafe { syscall3(72, fd, 3, 0) };
    if flags < 0
        || unsafe { syscall3(72, fd, 4, flags as usize | 0x800) } < 0
        || unsafe { syscall3(72, fd, 2, 1) } < 0
    {
        return Err(b"control fd setup failed");
    }
    unsafe {
        CONTROL.fd = Some(fd);
    }
    Ok(())
}

/// Readiness interest for the supervisor's private event wait.
pub fn readiness() -> (i32, i16) {
    let state = unsafe { &*core::ptr::addr_of!(CONTROL) };
    (
        state.fd.map_or(-1, |fd| fd as i32),
        if state.sent < state.reply.len() { 4 } else { 1 },
    )
}

pub fn poll(files: &LaunchFs) -> Result<(), Error> {
    // Only the single supervisor event loop accesses this owner. The tracee
    // closes all inherited descriptors above stdio before running guest code.
    let state = unsafe { &mut *core::ptr::addr_of_mut!(CONTROL) };
    let Some(fd) = state.fd else {
        return Ok(());
    };
    if state.sent < state.reply.len() {
        let reply = &state.reply[state.sent..];
        let count = unsafe { syscall6(44, fd, reply.as_ptr() as usize, reply.len(), 0x4000, 0, 0) };
        if count == -4 || count == -11 {
            return Ok(());
        }
        if count <= 0 {
            return Err(b"checkpoint control reply failed");
        }
        state.sent += count as usize;
        return Ok(());
    }
    loop {
        let count = unsafe {
            syscall3(
                0,
                fd,
                state.bytes.as_mut_ptr().add(state.used) as usize,
                state.wanted - state.used,
            )
        };
        if count == -4 || count == -11 {
            return Ok(());
        }
        if count <= 0 {
            return Err(b"checkpoint control peer closed");
        }
        state.used += count as usize;
        if state.used < state.wanted {
            return Ok(());
        }
        if state.wanted == HEADER {
            let length = u16::from_le_bytes(state.bytes[12..14].try_into().unwrap()) as usize;
            let sequence = u64::from_le_bytes(state.bytes[4..12].try_into().unwrap());
            if &state.bytes[..4] != b"GXS1"
                || length == 0
                || length > PATH
                || sequence <= state.last
            {
                return Err(b"invalid checkpoint control request");
            }
            state.wanted += length;
            continue;
        }
        let mut path = [0u8; PATH + 1];
        let length = state.wanted - HEADER;
        path[..length].copy_from_slice(&state.bytes[HEADER..state.wanted]);
        if path[..length].contains(&0) {
            return Err(b"invalid checkpoint destination");
        }
        // The event loop cannot mediate another owned write during this call.
        // Shared writable mappings and native writable backing fds are denied.
        files.snapshot(path.as_ptr())?;
        state.last = u64::from_le_bytes(state.bytes[4..12].try_into().unwrap());
        state.reply[..4].copy_from_slice(b"GXA1");
        state.reply[4..12].copy_from_slice(&state.last.to_le_bytes());
        state.sent = 0;
        state.used = 0;
        state.wanted = HEADER;
        return Ok(());
    }
}

pub fn close() -> Result<(), Error> {
    let state = unsafe { &mut *core::ptr::addr_of_mut!(CONTROL) };
    let Some(fd) = state.fd.take() else {
        return Ok(());
    };
    if unsafe { crate::supervisor::syscall1(3, fd) } != 0 {
        return Err(b"checkpoint control close failed");
    }
    Ok(())
}
