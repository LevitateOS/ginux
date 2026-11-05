//! Populate a freshly injected tracee memfd from pinned VFS bytes. The host
//! proc path is constructed only from a registered stopped task and its kernel
//! memfd result, never a guest path or public descriptor. No named output file
//! is created. The tracee cannot run until this backing is sealed and the host
//! fd is closed. Script backings retire before the interpreter's first syscall.

use crate::fs_hooks::LaunchFs;
use crate::supervisor::{syscall1, syscall2, syscall3, syscall4};
use ginux_vfs::Executable;

pub fn populate(host: usize, descriptor: u32, fs: &LaunchFs, image: Executable) -> Result<(), i64> {
    let mut path = [0u8; 64];
    path[..6].copy_from_slice(b"/proc/");
    let mut end = 6;
    number(&mut path, &mut end, host);
    path[end..end + 4].copy_from_slice(b"/fd/");
    end += 4;
    number(&mut path, &mut end, descriptor as usize);
    let fd = unsafe {
        syscall4(
            257,
            (-100isize) as usize,
            path.as_ptr() as usize,
            0x80002,
            0,
        )
    };
    if fd < 0 {
        return Err(fd as i64);
    }
    let fd = fd as usize;
    let result = (|| {
        let mut buffer = [0u8; 4096];
        let mut offset = 0;
        while offset < image.size {
            let count = fs.read_executable(image, offset, &mut buffer)?;
            if count == 0 {
                return Err(-5);
            }
            let mut written = 0;
            while written < count {
                let result = unsafe {
                    syscall3(1, fd, buffer[written..].as_ptr() as usize, count - written)
                };
                if result == -4 {
                    continue;
                }
                if result <= 0 {
                    return Err(if result == 0 { -5 } else { result as i64 });
                }
                written += result as usize;
            }
            offset += count;
        }
        let mode = unsafe { syscall2(91, fd, 0o500) };
        if mode < 0 {
            return Err(mode as i64);
        }
        // Old kernels do not know F_SEAL_EXEC. The write/grow/shrink seals
        // remain mandatory; the descriptor stays private until the exec owner
        // closes it (at commit for ELF, before the first syscall for scripts).
        let mut seals = 0x2f;
        let mut result = unsafe { syscall3(72, fd, 1033, seals) };
        if result == -22 {
            seals = 0xf;
            result = unsafe { syscall3(72, fd, 1033, seals) };
        }
        if result < 0 {
            return Err(result as i64);
        }
        let actual = unsafe { syscall3(72, fd, 1034, 0) };
        if actual < 0 || actual as usize & seals != seals {
            return Err(-5);
        }
        Ok(())
    })();
    let closed = unsafe { syscall1(3, fd) };
    if closed < 0 {
        return Err(closed as i64);
    }
    result
}

fn number(output: &mut [u8], end: &mut usize, mut value: usize) {
    let mut reverse = [0u8; 20];
    let mut count = 0;
    loop {
        reverse[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for byte in reverse[..count].iter().rev() {
        output[*end] = *byte;
        *end += 1;
    }
}
