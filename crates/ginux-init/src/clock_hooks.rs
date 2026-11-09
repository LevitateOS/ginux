//! Configured-launch global clocks and bounded, interruptible sleeps.
//!
//! Sleep requests are copied once, then implemented with scalar poll timeouts.
//! The kernel never rereads a mutable guest timespec or holds shared peers.
use crate::supervisor::{syscall2, write_tracee_bytes_strict, UserRegs};
use crate::tracee_io::copy_memory;

const SECOND: u64 = 1_000_000_000;
const MAX_SLEEP: u64 = 300 * SECOND;

fn now(clock: u32) -> Result<u64, i64> {
    let mut value = [0u64; 2];
    let result = unsafe { syscall2(228, clock as usize, value.as_mut_ptr() as usize) };
    if result < 0 {
        return Err(result as i64);
    }
    value[0]
        .checked_mul(SECOND)
        .and_then(|n| n.checked_add(value[1]))
        .ok_or(-5)
}

pub fn read(pid: usize, r: &UserRegs) -> Option<i64> {
    if !matches!(r.orig_rax, 228 | 229) {
        return None;
    }
    Some(
        (|| {
            // Linux clockid_t is a signed 32-bit scalar.
            if !matches!(r.rdi as u32, 0 | 1) {
                return Err(-1);
            }
            let mut value = [0u64; 2];
            let result = unsafe {
                syscall2(
                    r.orig_rax as usize,
                    r.rdi as u32 as usize,
                    value.as_mut_ptr() as usize,
                )
            };
            if result < 0 {
                return Err(result as i64);
            }
            // clock_getres permits a NULL result.
            if r.orig_rax == 228 || r.rsi != 0 {
                let bytes = unsafe { core::slice::from_raw_parts(value.as_ptr().cast::<u8>(), 16) };
                write_tracee_bytes_strict(pid, r.rsi as usize, bytes)?;
            }
            Ok(0)
        })()
        .unwrap_or_else(|error| error),
    )
}

#[derive(Clone, Copy)]
pub struct Sleep {
    original: UserRegs,
    clock: u32,
    deadline: u64,
    limit: u64,
    remaining: u64,
}

impl Sleep {
    pub fn restore(&self, r: &mut UserRegs, result: i64) {
        *r = self.original;
        r.rax = result as u64;
    }
    pub fn begin(pid: usize, r: &UserRegs) -> Result<Self, i64> {
        let (clock, flags, request, remaining) = if r.orig_rax == 35 {
            (1, 0, r.rdi, r.rsi)
        } else {
            (r.rdi as u32, r.rsi as u32, r.rdx, r.r10)
        };
        if !matches!(clock, 0 | 1) {
            return Err(-1);
        }
        if flags & !1 != 0 {
            return Err(-22);
        }
        let mut bytes = [0u8; 16];
        if copy_memory(pid, request, &mut bytes, false)? != 16 {
            return Err(-14);
        }
        let seconds = i64::from_ne_bytes(bytes[..8].try_into().unwrap());
        let nanos = i64::from_ne_bytes(bytes[8..].try_into().unwrap());
        if seconds < 0 || !(0..SECOND as i64).contains(&nanos) {
            return Err(-22);
        }
        let requested = (seconds as u64)
            .checked_mul(SECOND)
            .and_then(|n| n.checked_add(nanos as u64))
            .ok_or(-22)?;
        let clock = if flags == 0 { 1 } else { clock };
        let current = now(clock)?;
        let duration = if flags == 0 {
            requested
        } else {
            requested.saturating_sub(current)
        };
        if duration > MAX_SLEEP {
            return Err(-22);
        }
        Ok(Self {
            original: *r,
            clock,
            deadline: if flags == 0 {
                current.checked_add(duration).ok_or(-22)?
            } else {
                requested
            },
            limit: now(1)?.checked_add(MAX_SLEEP).ok_or(-22)?,
            remaining: if flags == 0 { remaining } else { 0 },
        })
    }

    pub fn enter(&self, r: &mut UserRegs) -> Result<(), i64> {
        let remaining = self.deadline.saturating_sub(now(self.clock)?);
        // Recheck absolute realtime deadlines after clock adjustments. Millisecond
        // rounding only delays completion; it never returns before the deadline.
        let millis = remaining.div_ceil(1_000_000).min(100);
        r.orig_rax = 7;
        r.rax = 7;
        r.rdi = 0;
        r.rsi = 0;
        r.rdx = millis;
        Ok(())
    }

    /// True requests another kernel poll; false completes the original sleep.
    /// An interrupted quantum is not an interrupted sleep: a supervisor stop
    /// or an ignored signal ends the poll early too. The sleep continues
    /// until its deadline; a handled signal ends it through `interrupt`.
    pub fn finish(&self, r: &mut UserRegs) -> Result<bool, i64> {
        let remaining = self.deadline.saturating_sub(now(self.clock)?);
        let mut result = r.rax as i64;
        if result == 0 || matches!(result, -514..=-512 | -516 | -4) {
            if remaining != 0 && now(1)? < self.limit {
                r.rip = r.rip.checked_sub(2).ok_or(-5)?;
                r.rax = 7;
                return Ok(true);
            }
            result = if remaining != 0 { -110 } else { 0 };
        }
        self.restore(r, result);
        Ok(false)
    }

    /// Complete the sleep for a signal whose handler is about to run.
    pub fn interrupt(&self, pid: usize, r: &mut UserRegs) -> Result<(), i64> {
        let remaining = self.deadline.saturating_sub(now(self.clock)?);
        self.restore(r, -4);
        if self.remaining != 0 {
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&(remaining / SECOND).to_ne_bytes());
            bytes[8..].copy_from_slice(&(remaining % SECOND).to_ne_bytes());
            write_tracee_bytes_strict(pid, self.remaining as usize, &bytes)?;
        }
        Ok(())
    }
}
