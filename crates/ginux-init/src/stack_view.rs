//! Configured process-local stack metadata. Read only a registered stopped
//! tracee's maps, then emit one canonical stack range without any mapped paths.
use crate::supervisor::{syscall1, syscall3, syscall4};
use ginux_instance::Text;

pub const PATH: &[u8] = b"/proc/self/maps";
const MAX_MAP_BYTES: usize = 1024 * 1024;

pub fn stat(pid: usize, address: u64, statx: bool) -> Result<i64, i64> {
    crate::tracee_io::write_stat(
        pid,
        address,
        crate::tracee_io::Stat {
            accessed: ginux_vfs::Timestamp::ZERO,
            modified: ginux_vfs::Timestamp::ZERO,
            inode: 0x7fff_ffff,
            mode: 0o100444,
            size: 0,
            links: 1,
            device_major: 0,
            device_minor: 0,
        },
        statx,
    )
}

pub fn metadata(pid: usize, r: &crate::supervisor::UserRegs) -> Option<Result<i64, i64>> {
    let address = match r.orig_rax {
        4 | 6 | 21 | 89 => r.rdi,
        262 | 267 | 269 | 332 | 439 => r.rsi,
        _ => return None,
    };
    if !crate::tracee_io::read_path(pid, address).is_ok_and(|path| path.as_bytes() == PATH) {
        return None;
    }
    Some((|| {
        if matches!(r.orig_rax, 89 | 267) {
            return Err(-22);
        }
        if matches!(r.orig_rax, 21 | 269 | 439) {
            let mode = if r.orig_rax == 21 { r.rsi } else { r.rdx };
            if mode & !7 != 0 || r.orig_rax == 439 && r.r10 & !0x300 != 0 {
                return Err(-22);
            }
            return if mode & 3 != 0 { Err(-13) } else { Ok(0) };
        }
        if r.orig_rax == 262 && r.r10 & !0x1900 != 0
            || r.orig_rax == 332 && !crate::launch_storage::valid_statx(r.rdx, r.r10)
        {
            return Err(-22);
        }
        stat(
            pid,
            match r.orig_rax {
                4 | 6 => r.rsi,
                262 => r.rdx,
                _ => r.r8,
            },
            r.orig_rax == 332,
        )
    })())
}

pub fn snapshot(pid: usize) -> Result<Text<128>, i64> {
    let mut name = [0; 64];
    name[..6].copy_from_slice(b"/proc/");
    let mut end = 6;
    number(pid as u64, 10, &mut name, &mut end);
    name[end..end + 5].copy_from_slice(b"/maps");
    let fd = unsafe {
        syscall4(
            257,
            (-100isize) as usize,
            name.as_ptr() as usize,
            0o2400000,
            0,
        )
    };
    if fd < 0 {
        return Err(fd as i64);
    }
    let result = read(fd as usize);
    let closed = unsafe { syscall1(3, fd as usize) };
    if closed != 0 {
        return Err(-5);
    }
    result
}

fn read(fd: usize) -> Result<Text<128>, i64> {
    let mut buffer = [0; 4096];
    let mut line = [0; 512];
    let (mut length, mut total, mut overlong) = (0, 0, false);
    let mut found = None;
    loop {
        let count = unsafe { syscall3(0, fd, buffer.as_mut_ptr() as usize, buffer.len()) };
        if count == -4 {
            continue;
        }
        if count < 0 {
            return Err(count as i64);
        }
        if count == 0 {
            break;
        }
        total += count as usize;
        if total > MAX_MAP_BYTES {
            return Err(-75);
        }
        for byte in &buffer[..count as usize] {
            if *byte == b'\n' {
                if !overlong && line[..length].ends_with(b" [stack]") {
                    if found.is_some() {
                        return Err(-5);
                    }
                    found = Some(parse(&line[..length])?);
                }
                length = 0;
                overlong = false;
            } else if length < line.len() {
                line[length] = *byte;
                length += 1;
            } else {
                overlong = true;
            }
        }
    }
    found.ok_or(-2)
}

fn parse(line: &[u8]) -> Result<Text<128>, i64> {
    let dash = line.iter().position(|b| *b == b'-').ok_or(-5)?;
    let space = line.iter().position(|b| *b == b' ').ok_or(-5)?;
    if dash >= space || space + 5 > line.len() {
        return Err(-5);
    }
    let hex = |bytes: &[u8]| -> Result<u64, i64> {
        if bytes.is_empty() || bytes.len() > 16 {
            return Err(-5);
        }
        bytes.iter().try_fold(0u64, |value, digit| {
            let digit = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                _ => return Err(-5),
            };
            value
                .checked_mul(16)
                .and_then(|v| v.checked_add(digit as u64))
                .ok_or(-5)
        })
    };
    let (low, high) = (hex(&line[..dash])?, hex(&line[dash + 1..space])?);
    let permissions = &line[space + 1..space + 5];
    if low == 0
        || low >= high
        || low & 4095 != 0
        || high & 4095 != 0
        || !matches!(permissions[0], b'r' | b'-')
        || !matches!(permissions[1], b'w' | b'-')
        || !matches!(permissions[2], b'x' | b'-')
        || !matches!(permissions[3], b'p' | b's')
    {
        return Err(-5);
    }
    let mut output = [0; 128];
    let mut end = 0;
    number(low, 16, &mut output, &mut end);
    output[end] = b'-';
    end += 1;
    number(high, 16, &mut output, &mut end);
    output[end] = b' ';
    end += 1;
    output[end..end + 4].copy_from_slice(permissions);
    end += 4;
    let tail = b" 00000000 00:00 0 [stack]\n";
    output[end..end + tail.len()].copy_from_slice(tail);
    end += tail.len();
    Text::from_bytes(&output[..end]).map_err(|_| -5)
}

fn number(mut value: u64, radix: u64, output: &mut [u8], end: &mut usize) {
    let mut digits = [0; 20];
    let mut count = 0;
    loop {
        digits[count] = b"0123456789abcdef"[(value % radix) as usize];
        count += 1;
        value /= radix;
        if value == 0 {
            break;
        }
    }
    for digit in digits[..count].iter().rev() {
        output[*end] = *digit;
        *end += 1;
    }
}
