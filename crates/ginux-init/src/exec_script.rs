//! Restore the domain script name after kernel binfmt dispatch. Only the new
//! exec stack is changed: fork/vfork's old address space is never used as scratch.
use crate::supervisor::UserRegs;
use crate::tracee_io::{copy_memory, read_path};
use ginux_domain::Text;
use ginux_vfs::MAX_PATH;

const ARGUMENTS: usize = 4096;
const AUX_PAIRS: usize = 64;
const STACK_WORDS: usize = 2 * ARGUMENTS + 2 * AUX_PAIRS + 32;

#[derive(Clone, Copy)]
pub struct Script {
    path: Text<MAX_PATH>,
    original_argc: usize,
}

fn word(host: usize, address: u64) -> Result<u64, i64> {
    let mut bytes = [0u8; 8];
    if copy_memory(host, address, &mut bytes, false) != Ok(8) {
        return Err(-14);
    }
    Ok(u64::from_ne_bytes(bytes))
}

fn count(host: usize, address: u64) -> Result<usize, i64> {
    if address == 0 {
        return Ok(0);
    }
    for n in 0..=ARGUMENTS {
        if word(host, address.checked_add((n * 8) as u64).ok_or(-14)?)? == 0 {
            return Ok(n);
        }
    }
    Err(-7)
}

impl Script {
    pub fn prepare(host: usize, r: &UserRegs) -> Result<Self, i64> {
        let (path, argv, env) = if r.orig_rax == 59 {
            (r.rdi, r.rsi, r.rdx)
        } else {
            (r.rsi, r.rdx, r.r10)
        };
        let mut path = read_path(host, path)?;
        if r.orig_rax == 322
            && (path.is_empty() || (path.as_bytes()[0] != b'/' && r.rdi as i32 != -100))
        {
            // The interpreter reopens a public descriptor name, never the
            // private memfd or the filesystem backend's integer handle.
            let mut bytes = [0u8; MAX_PATH];
            bytes[..8].copy_from_slice(b"/dev/fd/");
            let mut digits = [0u8; 10];
            let mut n = r.rdi as u32;
            let mut length = 0;
            loop {
                digits[length] = b'0' + (n % 10) as u8;
                length += 1;
                n /= 10;
                if n == 0 {
                    break;
                }
            }
            let mut end = 8;
            for digit in digits[..length].iter().rev() {
                bytes[end] = *digit;
                end += 1;
            }
            if !path.is_empty() {
                bytes[end] = b'/';
                end += 1;
                let next = end
                    .checked_add(path.as_bytes().len())
                    .filter(|end| *end < MAX_PATH)
                    .ok_or(-36)?;
                bytes[end..next].copy_from_slice(path.as_bytes());
                end = next;
            }
            path = Text::from_bytes(&bytes[..end]).map_err(|_| -36)?;
        }
        let original_argc = count(host, argv)?.max(1);
        count(host, env)?;
        Ok(Self {
            path,
            original_argc,
        })
    }

    pub fn restore(self, host: usize, fd: u32, r: &mut UserRegs) -> Result<(), i64> {
        let argc = word(host, r.rsp)? as usize;
        // Linux replaces argv[0] with an interpreter prefix. With recursive
        // image interpreters the original script name is the last prefix entry.
        let script = argc.checked_sub(self.original_argc).ok_or(-5)?;
        if script == 0 || argc > ARGUMENTS + 16 {
            return Err(-5);
        }
        let mut words = [0u64; STACK_WORDS];
        words[0] = argc as u64;
        let mut used = 1;
        while used <= argc + 1 {
            words[used] = word(host, r.rsp.checked_add((used * 8) as u64).ok_or(-14)?)?;
            used += 1;
        }
        if words[argc + 1] != 0 {
            return Err(-5);
        }
        let actual = read_path(host, words[1 + script])?;
        let mut expected = [0u8; 32];
        expected[..8].copy_from_slice(b"/dev/fd/");
        let mut end = 8;
        let mut digits = [0u8; 10];
        let mut n = fd;
        let mut len = 0;
        loop {
            digits[len] = b'0' + (n % 10) as u8;
            len += 1;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        for byte in digits[..len].iter().rev() {
            expected[end] = *byte;
            end += 1;
        }
        if actual.as_bytes() != &expected[..end] {
            return Err(-5);
        }
        let mut envc = 0;
        loop {
            if envc > ARGUMENTS || used >= STACK_WORDS {
                return Err(-7);
            }
            let value = word(host, r.rsp.checked_add((used * 8) as u64).ok_or(-14)?)?;
            words[used] = value;
            used += 1;
            if value == 0 {
                break;
            }
            envc += 1;
        }
        let aux = used;
        for n in 0..AUX_PAIRS {
            if used + 2 > STACK_WORDS {
                return Err(-7);
            }
            words[used] = word(host, r.rsp.checked_add((used * 8) as u64).ok_or(-14)?)?;
            words[used + 1] = word(host, r.rsp.checked_add(((used + 1) * 8) as u64).ok_or(-14)?)?;
            used += 2;
            if words[used - 2] == 0 {
                break;
            }
            if n + 1 == AUX_PAIRS {
                return Err(-7);
            }
        }
        // Shift only the pointer block down. Put the pathname above its new
        // end so ordinary downward stack growth cannot overwrite argv strings.
        let shift = (self.path.as_bytes().len() + 1).next_multiple_of(16) as u64;
        let start = r.rsp.checked_sub(shift).ok_or(-14)?;
        let name = start.checked_add((used * 8) as u64).ok_or(-14)?;
        words[1 + script] = name;
        for pair in words[aux..used].as_chunks_mut::<2>().0 {
            if pair[0] == 31 {
                pair[1] = name;
            } // AT_EXECFN
        }
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), used * 8) };
        if copy_memory(host, start, bytes, true) != Ok(bytes.len() as i64) {
            return Err(-14);
        }
        let mut path = [0u8; MAX_PATH];
        let length = self.path.as_bytes().len();
        path[..length].copy_from_slice(self.path.as_bytes());
        if copy_memory(host, name, &mut path[..length + 1], true) != Ok((length + 1) as i64) {
            return Err(-14);
        }
        r.rsp = start;
        Ok(())
    }
}
