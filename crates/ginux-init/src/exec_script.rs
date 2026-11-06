//! Restore the domain script name after kernel binfmt dispatch. Only the new
//! exec stack is changed: fork/vfork's old address space is never used as scratch.
use crate::fs_hooks::LaunchFs;
use crate::supervisor::UserRegs;
use crate::tracee_io::{copy_memory, read_path};
use ginux_domain::Text;
use ginux_vfs::{Executable, MAX_PATH};

const ARGUMENTS: usize = 4096;
const AUX_PAIRS: usize = 64;
const STACK_WORDS: usize = 2 * ARGUMENTS + 2 * AUX_PAIRS + 32;
const SCRIPTS: usize = 4;
type Path = Text<MAX_PATH>;

#[derive(Clone, Copy)]
struct Segment {
    path: Path,
    argument: Option<Path>,
}

#[derive(Clone, Copy)]
struct Header {
    interpreter: Path,
    argument: Option<Path>,
    payload: usize,
}

impl Header {
    fn read(fs: &LaunchFs, image: Executable) -> Result<Option<Self>, i64> {
        let mut bytes = [0u8; 256];
        fs.read_executable(image, 0, &mut bytes)?;
        if !bytes.starts_with(b"#!") {
            return Ok(None);
        }
        let newline = bytes.iter().position(|b| *b == b'\n');
        let mut end = newline.unwrap_or(255);
        while end > 2 && matches!(bytes[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        let start = (2..end)
            .find(|n| !matches!(bytes[*n], b' ' | b'\t'))
            .ok_or(-8)?;
        let separator = (start..end)
            .find(|n| matches!(bytes[*n], 0 | b' ' | b'\t'))
            .unwrap_or(end);
        if separator == start || (separator == end && newline.is_none()) {
            return Err(-8);
        }
        let interpreter = Path::from_bytes(&bytes[start..separator]).map_err(|_| -36)?;
        let argument = if separator < end && bytes[separator] != 0 {
            let first = (separator..end).find(|n| !matches!(bytes[*n], b' ' | b'\t'));
            match first {
                Some(first) if bytes[first] != 0 => {
                    let last = (first..end).find(|n| bytes[*n] == 0).unwrap_or(end);
                    Some(Path::from_bytes(&bytes[first..last]).map_err(|_| -36)?)
                }
                _ => None,
            }
        } else {
            None
        };
        Ok(Some(Self {
            interpreter,
            argument,
            payload: newline.map_or(image.size, |n| n + 1),
        }))
    }
}

#[derive(Clone, Copy)]
pub struct Script {
    path: Text<MAX_PATH>,
    original_argc: usize,
    segments: [Segment; SCRIPTS],
    count: usize,
    leaf: Path,
    pub kernel_script: bool,
    held: [Option<Executable>; SCRIPTS],
    native_header: Option<Header>,
    native_name: Option<Path>,
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
            segments: [Segment {
                path: Path::empty(),
                argument: None,
            }; SCRIPTS],
            count: 0,
            leaf: Path::empty(),
            native_header: None,
            native_name: None,
            kernel_script: false,
            held: [None; SCRIPTS],
        })
    }

    /// Consumes the initial executable reference, including on failure. Keep
    /// every owned script pinned until commit; only the actual ELF keeps its
    /// execution lifetime after the interpreter starts.
    pub fn resolve(
        fs: &mut LaunchFs,
        host: usize,
        r: &UserRegs,
        image: Executable,
    ) -> Result<(Executable, Option<Self>), i64> {
        let mut images = [None; SCRIPTS + 1];
        images[0] = Some(image);
        let mut used = 1;
        let result = (|| {
            let Some(mut header) = Header::read(fs, image)? else {
                return Ok(None);
            };
            let mut script = Self::prepare(host, r)?;
            let mut name = script.path;
            loop {
                if script.count == SCRIPTS {
                    return Err(-40);
                }
                script.segments[script.count] = Segment {
                    path: name,
                    argument: header.argument,
                };
                script.count += 1;
                match fs.exec_interpreter(host, header.interpreter.as_bytes())? {
                    Some(next) => {
                        images[used] = Some(next);
                        used += 1;
                        name = header.interpreter;
                        match Header::read(fs, next)? {
                            Some(next) => header = next,
                            None => {
                                script.leaf = name;
                                break;
                            }
                        }
                    }
                    None => {
                        let resolved = fs.interpreter_path(host, header.interpreter.as_bytes())?;
                        if resolved != header.interpreter {
                            script.native_name = Some(header.interpreter);
                            script.native_header = Some(Header {
                                interpreter: resolved,
                                ..header
                            });
                        }
                        script.kernel_script = true;
                        break;
                    }
                }
            }
            Ok(Some(script))
        })();
        match result {
            Ok(mut script) => {
                let image = images[used - 1].take().unwrap();
                if let Some(script) = script.as_mut() {
                    script.held.copy_from_slice(&images[..SCRIPTS]);
                }
                Ok((image, script))
            }
            Err(error) => {
                for image in images.into_iter().flatten() {
                    fs.release_executable(image)
                        .expect("interpreter resolution pin release");
                }
                Err(error)
            }
        }
    }

    /// Canonicalize only the sealed private copy passed to binfmt. Owned
    /// script bytes and the interpreter name reported in argv remain intact.
    pub fn private_header(&self, output: &mut [u8; 256]) -> Result<Option<(usize, usize)>, i64> {
        let Some(header) = self.native_header else {
            return Ok(None);
        };
        let interpreter = header.interpreter.as_bytes();
        let argument = header.argument.as_ref().map_or(&[][..], |p| p.as_bytes());
        let length = 2
            + interpreter.len()
            + if argument.is_empty() {
                0
            } else {
                1 + argument.len()
            }
            + 1;
        if length > 255 {
            return Err(-7);
        }
        output[..2].copy_from_slice(b"#!");
        output[2..2 + interpreter.len()].copy_from_slice(interpreter);
        let mut end = 2 + interpreter.len();
        if !argument.is_empty() {
            output[end] = b' ';
            end += 1;
            output[end..end + argument.len()].copy_from_slice(argument);
            end += argument.len();
        }
        output[end] = b'\n';
        Ok(Some((end + 1, header.payload)))
    }

    pub fn release_held(self, fs: &mut LaunchFs) -> Result<(), i64> {
        for image in self.held.into_iter().flatten() {
            fs.release_executable(image)?;
        }
        Ok(())
    }

    pub fn restore(self, host: usize, fd: u32, r: &mut UserRegs) -> Result<(), i64> {
        let argc = word(host, r.rsp)? as usize;
        if argc > ARGUMENTS + 16 {
            return Err(-7);
        }
        let prefix = if self.kernel_script {
            let prefix = argc
                .checked_sub(self.original_argc)
                .filter(|n| *n > 0)
                .ok_or(-5)?;
            let actual = read_path(host, word(host, r.rsp + ((prefix + 1) * 8) as u64)?)?;
            let mut expected = [0u8; 32];
            expected[..8].copy_from_slice(b"/dev/fd/");
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
            for (i, digit) in digits[..len].iter().rev().enumerate() {
                expected[8 + i] = *digit;
            }
            if actual.as_bytes() != &expected[..8 + len] {
                return Err(-5);
            }
            prefix
        } else {
            if argc != self.original_argc {
                return Err(-5);
            }
            0
        };
        let mut words = [0u64; STACK_WORDS];
        let mut strings = [0u8; (2 * SCRIPTS + 1) * MAX_PATH];
        let mut strings_len: usize = 0;
        let mut patched = [0usize; 2 * SCRIPTS + 1];
        let mut patches = 0;
        let mut used = 1;
        // The kernel may have expanded further immutable script headers.
        // Replace the requested leaf interpreter at its known prefix position,
        // retaining the final interpreter and any intermediate argument pairs.
        let replaced = self
            .native_header
            .and_then(|header| prefix.checked_sub(1 + usize::from(header.argument.is_some())));
        for n in 0..prefix {
            if Some(n) == replaced {
                let name = self.native_name.ok_or(-5)?;
                let bytes = name.as_bytes();
                strings[..bytes.len()].copy_from_slice(bytes);
                strings_len = bytes.len() + 1;
                words[used] = 0;
                patched[patches] = used;
                patches += 1;
                used += 1;
            } else {
                words[used] = word(host, r.rsp + ((n + 1) * 8) as u64)?;
                used += 1;
            }
        }
        let mut append = |path: Path| -> Result<(), i64> {
            let bytes = path.as_bytes();
            let end = strings_len
                .checked_add(bytes.len() + 1)
                .filter(|n| *n <= strings.len())
                .ok_or(-7)?;
            strings[strings_len..end - 1].copy_from_slice(bytes);
            words[used] = strings_len as u64;
            patched[patches] = used;
            patches += 1;
            used += 1;
            strings_len = end;
            Ok(())
        };
        if !self.kernel_script {
            append(self.leaf)?;
        }
        for index in (0..self.count).rev() {
            // The kernel already supplied the last owned script's shebang arg.
            if !(self.kernel_script && index + 1 == self.count) {
                if let Some(argument) = self.segments[index].argument {
                    append(argument)?;
                }
            }
            append(self.segments[index].path)?;
        }
        // The last inserted string is always the originally invoked script.
        let execfn = words[patched[patches - 1]];
        for n in prefix + 1..argc {
            words[used] = word(host, r.rsp + ((n + 1) * 8) as u64)?;
            used += 1;
        }
        words[0] = (used - 1) as u64;
        used += 1; // argv terminator
        if word(host, r.rsp + ((argc + 1) * 8) as u64)? != 0 {
            return Err(-5);
        }
        let mut cursor = argc + 2;
        let mut envc = 0;
        loop {
            if envc > ARGUMENTS || used >= STACK_WORDS {
                return Err(-7);
            }
            let value = word(host, r.rsp.checked_add((cursor * 8) as u64).ok_or(-14)?)?;
            cursor += 1;
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
            words[used] = word(host, r.rsp.checked_add((cursor * 8) as u64).ok_or(-14)?)?;
            words[used + 1] = word(
                host,
                r.rsp.checked_add(((cursor + 1) * 8) as u64).ok_or(-14)?,
            )?;
            cursor += 2;
            used += 2;
            if words[used - 2] == 0 {
                break;
            }
            if n + 1 == AUX_PAIRS {
                return Err(-7);
            }
        }
        // Place the expanded pointers and new strings entirely below the old
        // pointer block. Existing argv/env/aux data stay intact above it.
        let bytes = (used * 8 + strings_len).next_multiple_of(16) as u64;
        let start = r.rsp.checked_sub(bytes).ok_or(-14)?;
        let names = start + (used * 8) as u64;
        for &index in &patched[..patches] {
            words[index] += names;
        }
        for pair in words[aux..used].as_chunks_mut::<2>().0 {
            if pair[0] == 31 {
                pair[1] = names + execfn;
            }
        }
        let pointers =
            unsafe { core::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), used * 8) };
        if copy_memory(host, start, pointers, true) != Ok(pointers.len() as i64)
            || copy_memory(host, names, &mut strings[..strings_len], true) != Ok(strings_len as i64)
        {
            return Err(-14);
        }
        r.rsp = start;
        Ok(())
    }
}
