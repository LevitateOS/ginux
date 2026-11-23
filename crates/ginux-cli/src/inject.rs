//! `ginux inject`: read a tar archive with the caller's own rights and stream
//! it to the helper's standard input, so the privileged helper never opens a
//! caller-named host path. The archive's members are validated by the image
//! tool, not here.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

/// A rejected input: the CLI exit status and its diagnostic.
pub type Rejection = (i32, String);

fn reject(code: i32, path: &Path, reason: &str) -> Rejection {
    (code, format!("inject: {}: {reason}", path.display()))
}

/// Open `path` for streaming. Only a regular file is accepted: a symbolic
/// link (also as the final component), directory, FIFO, socket or device is
/// refused with 65, a missing file with 66, and a gzip-compressed archive
/// with 65. The open never follows a link and never blocks on a FIFO.
pub fn open_input(path: &Path) -> Result<File, Rejection> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(libc::ELOOP) => reject(65, path, "not a regular file (symbolic link)"),
            _ if error.kind() == io::ErrorKind::NotFound => reject(66, path, &error.to_string()),
            _ => reject(74, path, &error.to_string()),
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| reject(74, path, &error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(reject(65, path, "not a regular file"));
    }
    let mut magic = [0_u8; 2];
    let mut filled = 0;
    while filled < magic.len() {
        match file.read_at(&mut magic[filled..], filled as u64) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(reject(74, path, &error.to_string())),
        }
    }
    if filled == 2 && magic == [0x1f, 0x8b] {
        return Err((
            65,
            "inject: compressed archives are not supported".to_owned(),
        ));
    }
    Ok(file)
}

fn send(file: &File, output: impl Write) -> io::Result<()> {
    let mut output = output;
    let mut input = file;
    io::copy(&mut input, &mut output)?;
    output.flush()
}

/// Run `command` (the `sudo` helper `inject` invocation) with the archive on
/// its standard input. The helper's standard output is discarded and its
/// standard error relayed. Returns the exit status, an optional local
/// diagnostic and the helper's standard error.
pub fn run(command: &mut Command, file: &File) -> (i32, Option<String>, Vec<u8>) {
    let spawned = crate::spawn_relaying_stderr(command.stdin(Stdio::piped()).stdout(Stdio::null()));
    let (mut child, relay) = match spawned {
        Ok(spawned) => spawned,
        Err(error) => {
            return (
                1,
                Some(format!("unable to run command: {error}")),
                Vec::new(),
            )
        }
    };
    let sent = match child.stdin.take() {
        Some(stdin) => send(file, stdin),
        None => Err(io::Error::other("helper standard input is unavailable")),
    };
    let waited = child.wait();
    let stderr = relay.join().unwrap_or_default();
    let code = match waited {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            return (
                1,
                Some(format!("unable to wait for command: {error}")),
                stderr,
            )
        }
    };
    match sent {
        // The helper's own status explains an early exit (it closed its input).
        Err(_) if code != 0 => (code, None, stderr),
        Err(error) => (74, Some(format!("inject: {error}")), stderr),
        Ok(()) => (code, None, stderr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn scratch(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ginux-cli-inject-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn only_a_plain_uncompressed_regular_file_is_accepted() {
        let root = scratch("input");
        let plain = root.join("in.tar");
        fs::write(&plain, b"archive").unwrap();
        assert!(open_input(&plain).is_ok());
        let empty = root.join("empty.tar");
        fs::write(&empty, b"").unwrap();
        assert!(open_input(&empty).is_ok());

        assert_eq!(open_input(&root.join("absent")).unwrap_err().0, 66);
        assert_eq!(open_input(&root).unwrap_err().0, 65);

        let link = root.join("link.tar");
        std::os::unix::fs::symlink(&plain, &link).unwrap();
        assert_eq!(open_input(&link).unwrap_err().0, 65);
        let dangling = root.join("dangling.tar");
        std::os::unix::fs::symlink(root.join("nowhere"), &dangling).unwrap();
        assert_eq!(open_input(&dangling).unwrap_err().0, 65);

        let fifo = root.join("fifo.tar");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert_eq!(open_input(&fifo).unwrap_err().0, 65);

        assert_eq!(open_input(Path::new("/dev/null")).unwrap_err().0, 65);

        let gzip = root.join("in.tar.gz");
        fs::write(&gzip, [0x1f, 0x8b, 0x08, 0x00]).unwrap();
        let (code, message) = open_input(&gzip).unwrap_err();
        assert_eq!(code, 65);
        assert!(message.contains("compressed archives are not supported"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_file_bytes_reach_the_helper_unchanged() {
        let root = scratch("stream");
        let input = root.join("in.tar");
        let bytes: Vec<u8> = (0..300_000_u32).map(|value| (value % 251) as u8).collect();
        fs::write(&input, &bytes).unwrap();
        let received = root.join("received");
        let file = open_input(&input).unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", "cat >\"$1\"", "sh"]).arg(&received);
        let (code, message, _) = run(&mut command, &file);
        assert_eq!((code, message), (0, None));
        assert_eq!(fs::read(&received).unwrap(), bytes);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_helper_that_stops_reading_reports_its_own_status() {
        let root = scratch("early");
        let input = root.join("in.tar");
        fs::write(&input, vec![7_u8; 4 << 20]).unwrap();
        let file = open_input(&input).unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", "exit 76"]);
        let (code, message, _) = run(&mut command, &file);
        assert_eq!((code, message), (76, None));
        // Success without reading the whole archive is an I/O failure.
        let mut quiet = Command::new("sh");
        quiet.args(["-c", "exit 0"]);
        assert_eq!(run(&mut quiet, &file).0, 74);
        fs::remove_dir_all(&root).unwrap();
    }
}
