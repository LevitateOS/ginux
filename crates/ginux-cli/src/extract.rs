//! `ginux extract`: path rules and all-or-nothing publication of the tar
//! stream the helper writes.

use crate::sys;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const DEFAULT_MAX_BYTES: u64 = 68_719_476_736;
pub const DEFAULT_MAX_MEMBERS: u64 = 1_000_000;
pub const DEFAULT_MAX_PATH: u64 = 4096;

/// Parse one requested instance path: absolute, no empty, `.` or `..`
/// component, no NUL. `/` itself is allowed.
pub fn parse_instance_path(value: &str) -> Result<String, String> {
    if !value.starts_with('/') {
        return Err("instance paths must be absolute".into());
    }
    if value.contains('\0') {
        return Err("instance paths must not contain NUL".into());
    }
    if value != "/"
        && value[1..]
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err("instance paths must not contain empty, '.' or '..' components".into());
    }
    Ok(value.into())
}

/// Parse a non-zero bound.
pub fn parse_bound(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("bounds must be positive decimal integers".into());
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|bound| *bound != 0)
        .ok_or_else(|| "bounds must be positive decimal integers".into())
}

/// Check every path against `--max-path`.
pub fn check_path_lengths(paths: &[String], max_path: u64) -> Result<(), String> {
    for path in paths {
        if path.len() as u64 > max_path {
            return Err(format!("instance path is longer than --max-path: {path}"));
        }
    }
    Ok(())
}

fn is_below(path: &str, ancestor: &str) -> bool {
    ancestor == "/"
        || path
            .strip_prefix(ancestor)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Drop duplicates and paths below another requested path, then sort the rest
/// bytewise.
pub fn normalize_paths(paths: &[String]) -> Vec<String> {
    let mut sorted = paths.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut kept: Vec<String> = Vec::new();
    for path in sorted {
        if !kept.iter().any(|ancestor| is_below(&path, ancestor)) {
            kept.push(path);
        }
    }
    kept
}

/// Where the archive is written before it gets its final name.
enum Staging {
    /// An unnamed inode; nothing is left behind on any failure.
    Unnamed(File),
    /// A named dot-file for filesystems without unnamed files; a kill at the
    /// wrong moment can leave it behind.
    Partial(File, PathBuf),
}

impl Staging {
    fn file(&self) -> &File {
        match self {
            Staging::Unnamed(file) | Staging::Partial(file, _) => file,
        }
    }

    fn discard(self) {
        if let Staging::Partial(_, path) = self {
            let _ = fs::remove_file(path);
        }
    }

    fn publish(self, output: &Path) -> io::Result<()> {
        self.file().sync_all()?;
        match self {
            Staging::Unnamed(file) => sys::link_unnamed(&file, output),
            Staging::Partial(_, path) => {
                let result = fs::hard_link(&path, output);
                let _ = fs::remove_file(&path);
                result
            }
        }
    }
}

fn parent_directory(output: &Path) -> PathBuf {
    match output.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn open_staging(output: &Path) -> io::Result<Staging> {
    let directory = parent_directory(output);
    match sys::open_unnamed(&directory) {
        Ok(file) => Ok(Staging::Unnamed(file)),
        Err(error) if sys::unnamed_unsupported(&error) => {
            let name = output
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let path = directory.join(format!(".{name}.ginux-partial.{}", std::process::id()));
            use std::os::unix::fs::OpenOptionsExt;
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            Ok(Staging::Partial(file, path))
        }
        Err(error) => Err(error),
    }
}

/// The outcome of one extract run, already mapped to the CLI exit status.
pub enum Outcome {
    Done,
    /// A local failure with its diagnostic.
    Failed(i32, String),
    /// The helper failed; its status and what it wrote to standard error
    /// (already relayed to this process's standard error).
    Helper(i32, Vec<u8>),
}

/// Run `command` (the `sudo` helper `extract` invocation) with its standard
/// output connected to a staging file, then publish the file as `output` only
/// if the helper succeeded.
pub fn run(command: &mut Command, output: &Path) -> Outcome {
    if fs::symlink_metadata(output).is_ok() {
        return Outcome::Failed(74, format!("extract: output exists: {}", output.display()));
    }
    let staging = match open_staging(output) {
        Ok(staging) => staging,
        Err(error) => {
            return Outcome::Failed(
                74,
                format!(
                    "extract: cannot create output beside {}: {error}",
                    output.display()
                ),
            )
        }
    };
    let stdout = match staging.file().try_clone() {
        Ok(file) => file,
        Err(error) => {
            staging.discard();
            return Outcome::Failed(74, format!("extract: {error}"));
        }
    };
    let finished = crate::spawn_relaying_stderr(command.stdout(Stdio::from(stdout))).and_then(
        |(mut child, relay)| {
            let status = child.wait()?;
            Ok((status, relay.join().unwrap_or_default()))
        },
    );
    let (code, stderr) = match finished {
        Ok((status, stderr)) => (status.code().unwrap_or(1), stderr),
        Err(error) => {
            staging.discard();
            return Outcome::Failed(1, format!("unable to run command: {error}"));
        }
    };
    if code != 0 {
        staging.discard();
        return Outcome::Helper(code, stderr);
    }
    match staging.publish(output) {
        Ok(()) => Outcome::Done,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            Outcome::Failed(74, format!("extract: output exists: {}", output.display()))
        }
        Err(error) => Outcome::Failed(
            74,
            format!("extract: cannot write {}: {error}", output.display()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_paths_must_be_clean_and_absolute() {
        for good in ["/", "/out", "/a/b.c/d-e"] {
            assert_eq!(parse_instance_path(good).unwrap(), good);
        }
        for bad in [
            "", "out", "./out", "/out/", "//out", "/a/./b", "/a/../b", "/..", "/a\0b",
        ] {
            assert!(parse_instance_path(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn bounds_are_positive_decimal() {
        assert_eq!(parse_bound("1").unwrap(), 1);
        assert_eq!(parse_bound("68719476736").unwrap(), DEFAULT_MAX_BYTES);
        for bad in ["", "0", "-1", "+1", "1k", "0x10", "99999999999999999999999"] {
            assert!(parse_bound(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn nested_and_duplicate_paths_collapse_and_sort() {
        let paths: Vec<String> = ["/b", "/a/x", "/a", "/b", "/ab", "/a/y/z"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(normalize_paths(&paths), ["/a", "/ab", "/b"]);
        let with_root: Vec<String> = ["/x", "/"].into_iter().map(String::from).collect();
        assert_eq!(normalize_paths(&with_root), ["/"]);
    }

    #[test]
    fn path_length_bound_is_checked() {
        let paths = vec!["/abcd".to_owned()];
        assert!(check_path_lengths(&paths, 5).is_ok());
        assert!(check_path_lengths(&paths, 4).is_err());
    }

    #[test]
    fn failed_helper_leaves_nothing_and_success_publishes() {
        let directory = std::env::temp_dir().join(format!(
            "ginux-cli-extract-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let output = directory.join("result.tar");

        let mut failing = Command::new("sh");
        failing.args(["-c", "printf partial; exit 75"]);
        assert!(matches!(run(&mut failing, &output), Outcome::Helper(75, _)));
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);

        let mut working = Command::new("sh");
        working.args(["-c", "printf archive"]);
        assert!(matches!(run(&mut working, &output), Outcome::Done));
        assert_eq!(fs::read(&output).unwrap(), b"archive");

        let mut again = Command::new("sh");
        again.args(["-c", "printf other"]);
        assert!(matches!(run(&mut again, &output), Outcome::Failed(74, _)));
        assert_eq!(fs::read(&output).unwrap(), b"archive");
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);

        fs::remove_dir_all(&directory).unwrap();
    }
}
