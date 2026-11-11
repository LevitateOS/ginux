//! Private mapping transaction for an owned file. The existing descriptor owner
//! validates the public fd and mapping access; a backing reference crosses an internal
//! socket only while the task is stopped. All three temporary native descriptors
//! and the scratch stack bytes are retired before user code can resume.
use crate::supervisor::{syscall1, syscall2, syscall3, syscall4, UserRegs};
use crate::tracee_io::copy_memory;

#[derive(Clone, Copy)]
enum Stage {
    Pair,
    Receive,
    Map,
    Close(usize),
}

pub enum Progress {
    Run(UserRegs),
    Done(UserRegs),
}

pub struct MappingCall {
    original: UserRegs,
    scratch: u64,
    saved: [u8; 256],
    native: [Option<u32>; 3],
    backing: usize,
    existing: [bool; crate::descriptors::LIMIT],
    stage: Stage,
    result: i64,
}

impl Drop for MappingCall {
    fn drop(&mut self) {
        unsafe {
            syscall1(3, self.backing);
        }
    }
}

impl MappingCall {
    /// Takes ownership of the supervisor's validated backing reference.
    pub fn new(
        host: usize,
        original: UserRegs,
        backing: usize,
        existing: [bool; crate::descriptors::LIMIT],
    ) -> Result<Self, &'static [u8]> {
        let mut call = Self {
            original,
            scratch: original.rsp.saturating_sub(512),
            saved: [0; 256],
            native: [None; 3],
            backing,
            existing,
            stage: Stage::Pair,
            result: -5,
        };
        let mut instruction = [0u8; 2];
        if original.rsp < 512
            || original.rip < 2
            || copy_memory(host, original.rip - 2, &mut instruction, false) != Ok(2)
            || instruction != [0x0f, 0x05]
            || copy_memory(host, call.scratch, &mut call.saved, false) != Ok(256)
        {
            return Err(b"mapping injection requires a readable syscall frame");
        }
        let mut frame = [0u8; 256];
        put(&mut frame, 48, call.scratch + 96); // msghdr.msg_iov
        put(&mut frame, 56, 1);
        put(&mut frame, 64, call.scratch + 128); // msg_control
        put(&mut frame, 72, 24);
        put(&mut frame, 96, call.scratch + 112); // iovec
        put(&mut frame, 104, 1);
        if copy_memory(host, call.scratch, &mut frame, true) != Ok(256) {
            // The caller fails the instance: a partial scratch write cannot be
            // returned as an ordinary mmap error while peer threads survive.
            return Err(b"mapping injection scratch copy failed");
        }
        Ok(call)
    }

    pub fn entry(&self, r: &UserRegs) -> Result<UserRegs, &'static [u8]> {
        if r.orig_rax != 9 || r.rip != self.original.rip {
            return Err(b"mapping replay left its syscall instruction");
        }
        let mut next = self.original;
        match self.stage {
            Stage::Pair => {
                next.orig_rax = 53;
                next.rdi = 1;
                next.rsi = 0x80005;
                next.rdx = 0;
                next.r10 = self.scratch;
            }
            Stage::Receive => {
                next.orig_rax = 47;
                next.rdi = self.native[1].unwrap() as u64;
                next.rsi = self.scratch + 32;
                next.rdx = 0x40000000;
            }
            Stage::Map => {
                next.r8 = self.native[2].unwrap() as u64;
            }
            Stage::Close(i) => {
                next.orig_rax = 3;
                next.rdi = self.native[i].unwrap() as u64;
            }
        }
        next.rax = next.orig_rax;
        Ok(next)
    }

    pub fn exit(&mut self, host: usize, r: &UserRegs) -> Result<Progress, &'static [u8]> {
        let expected = match self.stage {
            Stage::Pair => 53,
            Stage::Receive => 47,
            Stage::Map => 9,
            Stage::Close(_) => 3,
        };
        if r.orig_rax != expected {
            return Err(b"mapping transaction lost its syscall");
        }
        match self.stage {
            Stage::Pair => {
                if (r.rax as i64) < 0 {
                    self.result = r.rax as i64;
                    return self.done(host);
                }
                let mut bytes = [0u8; 8];
                if r.rax != 0 || copy_memory(host, self.scratch, &mut bytes, false) != Ok(8) {
                    return Err(b"mapping socket pair copy failed");
                }
                for i in 0..2 {
                    let fd = u32::from_ne_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
                    if fd >= crate::descriptors::LIMIT as u32 || self.existing[fd as usize] {
                        return Err(b"mapping private fd exceeds bound");
                    }
                    self.native[i] = Some(fd);
                }
                if self.native[0] == self.native[1] {
                    return Err(b"mapping socket pair aliases itself");
                }
                if send_backing(host, self.native[0].unwrap(), self.backing).is_err() {
                    self.result = -95;
                    self.stage = Stage::Close(0);
                } else {
                    self.stage = Stage::Receive;
                }
            }
            Stage::Receive => {
                let mut frame = [0u8; 256];
                if r.rax != 1
                    || copy_memory(host, self.scratch, &mut frame, false) != Ok(256)
                    || get(&frame, 72) != 24
                    || frame[112] != b'G'
                    || get(&frame, 128) != 20
                    || u32::from_ne_bytes(frame[136..140].try_into().unwrap()) != 1
                    || u32::from_ne_bytes(frame[140..144].try_into().unwrap()) != 1
                    || u32::from_ne_bytes(frame[80..84].try_into().unwrap()) & !0x40000000 != 0
                {
                    return Err(b"mapping backing receipt failed");
                }
                let fd = u32::from_ne_bytes(frame[144..148].try_into().unwrap());
                if fd >= crate::descriptors::LIMIT as u32
                    || self.existing[fd as usize]
                    || self.native[..2].contains(&Some(fd))
                {
                    return Err(b"mapping received invalid private descriptor");
                }
                self.native[2] = Some(fd);
                self.stage = Stage::Map;
            }
            Stage::Map => {
                self.result = r.rax as i64;
                self.stage = Stage::Close(0);
            }
            Stage::Close(i) => {
                if r.rax != 0 {
                    return Err(b"mapping private descriptor close failed");
                }
                self.native[i] = None;
                if let Some(next) = (i + 1..3).find(|&n| self.native[n].is_some()) {
                    self.stage = Stage::Close(next);
                } else {
                    return self.done(host);
                }
            }
        }
        let mut replay = self.original;
        replay.rip -= 2;
        replay.rax = replay.orig_rax;
        Ok(Progress::Run(replay))
    }

    fn done(&mut self, host: usize) -> Result<Progress, &'static [u8]> {
        if copy_memory(host, self.scratch, &mut self.saved, true) != Ok(256) {
            return Err(b"mapping scratch restoration failed");
        }
        let mut result = self.original;
        result.rax = self.result as u64;
        Ok(Progress::Done(result))
    }
}

fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_ne_bytes());
}
fn get(bytes: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap())
}

#[repr(C)]
struct IoVec {
    address: usize,
    length: usize,
}
#[repr(C)]
struct Message {
    name: usize,
    name_len: u64,
    iov: usize,
    iov_len: usize,
    control: usize,
    control_len: usize,
    flags: u64,
}

fn send_backing(host: usize, socket: u32, backing: usize) -> Result<(), ()> {
    // The stopped caller may be a nonleader thread, including after its leader
    // exited. Address that task's live fd table rather than the process leader.
    let mut pidfd = unsafe { syscall2(434, host, 0x80) }; // PIDFD_THREAD
    if pidfd == -22 {
        // Older kernels can still support mappings by process leaders.
        pidfd = unsafe { syscall2(434, host, 0) };
    }
    if pidfd < 0 {
        return Err(());
    }
    let endpoint = unsafe { syscall3(438, pidfd as usize, socket as usize, 0) };
    unsafe {
        syscall1(3, pidfd as usize);
    }
    if endpoint < 0 {
        return Err(());
    }
    let mut control = [0u64; 3];
    control[0] = 20;
    control[1] = 1 | (1u64 << 32);
    control[2] = backing as u64;
    let marker = b'G';
    let iov = IoVec {
        address: &marker as *const _ as usize,
        length: 1,
    };
    let message = Message {
        name: 0,
        name_len: 0,
        iov: &iov as *const _ as usize,
        iov_len: 1,
        control: control.as_ptr() as usize,
        control_len: 24,
        flags: 0,
    };
    let result = loop {
        let result =
            unsafe { syscall3(46, endpoint as usize, &message as *const _ as usize, 0x4000) };
        if result != -4 {
            break result;
        }
    };
    unsafe {
        syscall1(3, endpoint as usize);
    }
    if result == 1 {
        Ok(())
    } else {
        Err(())
    }
}

/// Obtain a reference with checked mapping access to a supervisor fd, never
/// a guest-supplied path. The transfer transaction retires it before userspace.
pub fn backing_reference(fd: i32, writable: bool) -> Result<usize, i64> {
    let mut path = [0u8; 64];
    path[..14].copy_from_slice(b"/proc/self/fd/");
    let mut digits = [0u8; 10];
    let mut value = fd as u32;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for n in 0..count {
        path[14 + n] = digits[count - n - 1];
    }
    let result = unsafe {
        syscall4(
            257,
            (-100isize) as usize,
            path.as_ptr() as usize,
            0x80000 | if writable { 2 } else { 0 },
            0,
        )
    };
    if result < 0 {
        Err(result as i64)
    } else {
        Ok(result as usize)
    }
}

/// Inspect only a registered stopped task's kernel mapping table. Conservatively
/// refuse exec while any shared reference exists, including one currently
/// protected read-only that could later regain write permission with mprotect.
pub fn has_shared_mapping(host: usize, backing: i32) -> Result<bool, i64> {
    let mut stat = [0u64; 18];
    if unsafe { syscall2(5, backing as usize, stat.as_mut_ptr() as usize) } < 0 {
        return Err(-5);
    }
    let device = stat[0];
    let major = ((device >> 8) & 0xfff) | ((device >> 32) & 0xfffff000);
    let minor = (device & 0xff) | ((device >> 12) & 0xffffff00);
    let inode = stat[1];
    let mut path = [0u8; 64];
    path[..6].copy_from_slice(b"/proc/");
    let mut digits = [0u8; 20];
    let mut value = host;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for n in 0..count {
        path[6 + n] = digits[count - n - 1];
    }
    path[6 + count..11 + count].copy_from_slice(b"/maps");
    let fd = unsafe {
        syscall4(
            257,
            (-100isize) as usize,
            path.as_ptr() as usize,
            0x80000,
            0,
        )
    };
    if fd == -2 || fd == -3 {
        return Ok(false);
    }
    if fd < 0 {
        return Err(-95);
    }
    let result = (|| {
        let mut bytes = [0u8; 4096];
        let mut line = [0u8; 128];
        let mut used = 0;
        let mut total = 0;
        loop {
            let read =
                unsafe { syscall3(0, fd as usize, bytes.as_mut_ptr() as usize, bytes.len()) };
            if read == -4 {
                continue;
            }
            if read < 0 {
                return Err(-95);
            }
            if read == 0 {
                return Ok(false);
            }
            total += read as usize;
            if total > 4 * 1024 * 1024 {
                return Err(-95);
            }
            for byte in &bytes[..read as usize] {
                if *byte == b'\n' {
                    if shared_line(&line[..used], major, minor, inode) {
                        return Ok(true);
                    }
                    used = 0;
                } else if used < line.len() {
                    line[used] = *byte;
                    used += 1;
                }
            }
        }
    })();
    let closed = unsafe { syscall1(3, fd as usize) };
    if closed < 0 {
        return Err(-5);
    }
    result
}

fn shared_line(line: &[u8], major: u64, minor: u64, inode: u64) -> bool {
    let mut fields = line
        .split(|b| b.is_ascii_whitespace())
        .filter(|f| !f.is_empty());
    let _range = fields.next();
    let Some(permissions) = fields.next() else {
        return false;
    };
    let _offset = fields.next();
    let Some(device) = fields.next() else {
        return false;
    };
    let Some(number) = fields.next() else {
        return false;
    };
    let Some(colon) = device.iter().position(|b| *b == b':') else {
        return false;
    };
    permissions.get(3) == Some(&b's')
        && parsed_number(&device[..colon], 16) == Some(major)
        && parsed_number(&device[colon + 1..], 16) == Some(minor)
        && parsed_number(number, 10) == Some(inode)
}

fn parsed_number(bytes: &[u8], radix: u64) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            _ => return None,
        };
        if digit >= radix {
            return None;
        }
        value = value.checked_mul(radix)?.checked_add(digit)?;
    }
    Some(value)
}
