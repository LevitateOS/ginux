//! `ginux import-image`: read an OCI image layout with the caller's own rights
//! and stream it to the helper as one tar archive on standard input, so the
//! privileged helper never opens a caller-named host path.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// A layout member that will be sent: its archive name and, for regular
/// files, its source path and size.
#[derive(Debug, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub source: Option<(PathBuf, u64)>,
}

/// A rejected input, already mapped to the CLI exit status.
#[derive(Debug)]
pub struct Rejection {
    pub code: i32,
    pub message: String,
}

fn reject(code: i32, message: String) -> Rejection {
    Rejection { code, message }
}

fn is_blob_name(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn regular(path: &Path, name: &str) -> Result<Member, Rejection> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        let code = if error.kind() == io::ErrorKind::NotFound {
            65
        } else {
            74
        };
        reject(code, format!("import-image: {}: {error}", path.display()))
    })?;
    if !metadata.file_type().is_file() {
        return Err(reject(
            65,
            format!(
                "import-image: not a regular file in the image layout: {}",
                path.display()
            ),
        ));
    }
    Ok(Member {
        name: name.into(),
        source: Some((path.to_path_buf(), metadata.len())),
    })
}

fn directory(path: &Path) -> Result<Vec<String>, Rejection> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| reject(66, format!("import-image: {}: {error}", path.display())))?;
    if !metadata.file_type().is_dir() {
        return Err(reject(
            65,
            format!(
                "import-image: not a directory in the image layout: {}",
                path.display()
            ),
        ));
    }
    let mut entries = Vec::new();
    let listing = fs::read_dir(path)
        .map_err(|error| reject(66, format!("import-image: {}: {error}", path.display())))?;
    for entry in listing {
        let entry = entry
            .map_err(|error| reject(74, format!("import-image: {}: {error}", path.display())))?;
        let name = entry.file_name().into_string().map_err(|name| {
            reject(
                65,
                format!(
                    "import-image: unexpected path in the image layout: {}",
                    path.join(name).display()
                ),
            )
        })?;
        entries.push(name);
    }
    entries.sort();
    Ok(entries)
}

/// List the members of an image-layout directory. Only `oci-layout`,
/// `index.json`, `blobs/`, `blobs/sha256/` and `blobs/sha256/<64 lowercase
/// hex>` are allowed; anything else, including symbolic links, is rejected.
pub fn layout_members(root: &Path) -> Result<Vec<Member>, Rejection> {
    let unexpected = |path: PathBuf| {
        reject(
            65,
            format!(
                "import-image: unexpected path in the image layout: {}",
                path.display()
            ),
        )
    };
    let mut seen_blobs = false;
    for name in directory(root)? {
        match name.as_str() {
            "oci-layout" | "index.json" => {}
            "blobs" => seen_blobs = true,
            _ => return Err(unexpected(root.join(name))),
        }
    }
    let mut members = vec![
        regular(&root.join("oci-layout"), "oci-layout")?,
        regular(&root.join("index.json"), "index.json")?,
    ];
    if !seen_blobs {
        return Ok(members);
    }
    let blobs = root.join("blobs");
    let mut seen_sha256 = false;
    for name in directory(&blobs)? {
        if name != "sha256" {
            return Err(unexpected(blobs.join(name)));
        }
        seen_sha256 = true;
    }
    members.push(Member {
        name: "blobs/".into(),
        source: None,
    });
    if !seen_sha256 {
        return Ok(members);
    }
    let sha256 = blobs.join("sha256");
    let entries = directory(&sha256)?;
    members.push(Member {
        name: "blobs/sha256/".into(),
        source: None,
    });
    for name in entries {
        if !is_blob_name(&name) {
            return Err(unexpected(sha256.join(name)));
        }
        members.push(regular(
            &sha256.join(&name),
            &format!("blobs/sha256/{name}"),
        )?);
    }
    Ok(members)
}

/// What will be sent on the helper's standard input.
pub enum Input {
    Layout(Vec<Member>),
    Archive(PathBuf),
}

/// Decide how `path` is sent, rejecting it before any privileged call.
pub fn prepare(path: &Path) -> Result<Input, Rejection> {
    let metadata = fs::metadata(path)
        .map_err(|error| reject(66, format!("import-image: {}: {error}", path.display())))?;
    if metadata.is_dir() {
        return layout_members(path).map(Input::Layout);
    }
    if !metadata.is_file() {
        return Err(reject(
            65,
            format!(
                "import-image: not an image layout directory or archive: {}",
                path.display()
            ),
        ));
    }
    let mut magic = [0_u8; 2];
    let mut file = File::open(path)
        .map_err(|error| reject(66, format!("import-image: {}: {error}", path.display())))?;
    let mut filled = 0;
    while filled < magic.len() {
        match file.read(&mut magic[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(reject(
                    74,
                    format!("import-image: {}: {error}", path.display()),
                ))
            }
        }
    }
    if filled == 2 && magic == [0x1f, 0x8b] {
        return Err(reject(
            65,
            "import-image: compressed layout archives are not supported".into(),
        ));
    }
    Ok(Input::Archive(path.to_path_buf()))
}

/// Reads exactly `remaining` bytes and fails if the source is shorter, so a
/// file that shrinks while it is sent cannot produce a malformed archive.
struct Exact<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let limit = buffer
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let count = self.inner.read(&mut buffer[..limit])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "file changed while it was read",
            ));
        }
        self.remaining -= count as u64;
        Ok(count)
    }
}

/// Write the layout members as a tar archive with normalized headers.
pub fn write_layout<W: Write>(members: &[Member], output: W) -> io::Result<()> {
    let mut builder = tar::Builder::new(output);
    for member in members {
        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        match &member.source {
            None => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(0o755);
                header.set_size(0);
                builder.append_data(&mut header, &member.name, io::empty())?;
            }
            Some((path, size)) => {
                let file = File::open(path)?;
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(0o644);
                header.set_size(*size);
                builder.append_data(
                    &mut header,
                    &member.name,
                    Exact {
                        inner: file,
                        remaining: *size,
                    },
                )?;
            }
        }
    }
    builder.into_inner()?.flush()
}

fn send(input: &Input, output: impl Write) -> io::Result<()> {
    match input {
        Input::Layout(members) => write_layout(members, output),
        Input::Archive(path) => {
            let mut output = output;
            io::copy(&mut File::open(path)?, &mut output)?;
            output.flush()
        }
    }
}

/// Run `command` (the `sudo` helper `import-image` invocation) with `input`
/// streamed to its standard input. Its standard output, the manifest digest,
/// is inherited and its standard error relayed. Returns the exit status, an
/// optional local diagnostic and the helper's standard error.
pub fn run(command: &mut Command, input: &Input) -> (i32, Option<String>, Vec<u8>) {
    let (mut child, relay) = match crate::spawn_relaying_stderr(command.stdin(Stdio::piped())) {
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
        Some(stdin) => send(input, stdin),
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
        Err(error) => (74, Some(format!("import-image: {error}")), stderr),
        Ok(()) => (code, None, stderr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ginux-cli-image-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn layout(root: &Path) {
        fs::write(
            root.join("oci-layout"),
            b"{\"imageLayoutVersion\":\"1.0.0\"}",
        )
        .unwrap();
        fs::write(root.join("index.json"), b"{}").unwrap();
        fs::create_dir_all(root.join("blobs/sha256")).unwrap();
        fs::write(root.join("blobs/sha256").join(HEX), b"blob").unwrap();
    }

    #[test]
    fn layout_streams_only_allowed_members() {
        let root = scratch("ok");
        layout(&root);
        let members = layout_members(&root).unwrap();
        let names: Vec<_> = members.iter().map(|member| member.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "oci-layout".to_owned(),
                "index.json".to_owned(),
                "blobs/".to_owned(),
                "blobs/sha256/".to_owned(),
                format!("blobs/sha256/{HEX}"),
            ]
        );
        let mut archive = Vec::new();
        write_layout(&members, &mut archive).unwrap();
        let mut reader = tar::Archive::new(archive.as_slice());
        let mut read = Vec::new();
        for entry in reader.entries().unwrap() {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().into_owned();
            assert_eq!(entry.header().uid().unwrap(), 0);
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            read.push((name, bytes));
        }
        assert_eq!(
            read[0],
            (
                "oci-layout".into(),
                b"{\"imageLayoutVersion\":\"1.0.0\"}".to_vec()
            )
        );
        assert_eq!(read[4], (format!("blobs/sha256/{HEX}"), b"blob".to_vec()));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn unexpected_paths_and_links_are_rejected() {
        for (label, make) in [
            (
                "extra",
                (|root: &Path| fs::write(root.join("extra"), b"x").unwrap()) as fn(&Path),
            ),
            ("upper", |root: &Path| {
                fs::write(root.join("blobs/sha256").join(HEX.to_uppercase()), b"x").unwrap()
            }),
            ("short", |root: &Path| {
                fs::write(root.join("blobs/sha256/abc"), b"x").unwrap()
            }),
            ("other-algorithm", |root: &Path| {
                fs::create_dir(root.join("blobs/sha512")).unwrap()
            }),
            ("link", |root: &Path| {
                fs::remove_file(root.join("index.json")).unwrap();
                std::os::unix::fs::symlink("/etc/passwd", root.join("index.json")).unwrap();
            }),
            ("blob-link", |root: &Path| {
                let blob = root.join("blobs/sha256").join(HEX);
                fs::remove_file(&blob).unwrap();
                std::os::unix::fs::symlink("/etc/passwd", blob).unwrap();
            }),
        ] {
            let root = scratch(label);
            layout(&root);
            make(&root);
            let rejection = layout_members(&root).unwrap_err();
            assert_eq!(rejection.code, 65, "{label}: {}", rejection.message);
            fs::remove_dir_all(&root).unwrap();
        }
    }

    #[test]
    fn missing_input_and_gzip_archives_are_rejected() {
        let root = scratch("archive");
        assert_eq!(prepare(&root.join("absent")).err().unwrap().code, 66);
        let gzip = root.join("layout.tar.gz");
        fs::write(&gzip, [0x1f, 0x8b, 0x08, 0x00]).unwrap();
        assert_eq!(prepare(&gzip).err().unwrap().code, 65);
        let plain = root.join("layout.tar");
        fs::write(&plain, b"plain").unwrap();
        assert!(matches!(prepare(&plain), Ok(Input::Archive(_))));
        fs::remove_dir_all(&root).unwrap();
    }
}
