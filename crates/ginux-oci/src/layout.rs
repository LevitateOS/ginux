//! `import-layout`: commit one image from an OCI image layout, read as a tar stream, into the
//! content-addressed blob cache.
//!
//! The stream is fully caller-controlled. Member names select nothing on disk: only the fixed
//! layout paths are accepted, blobs are written under their validated hex name into a fresh
//! 0700 staging directory, and nothing reaches `blobs/sha256` before the whole image
//! (manifest, config, every layer) is present and verified. The commit goes layers, then
//! config, then manifest, so an interrupted commit never leaves a manifest whose dependencies
//! are missing; a failure removes the manifest this run added (verified layers and config
//! stay: a concurrent import may already rely on them).

use crate::export::escaped;
use crate::{cached_blob, descriptor, exit, read_json, select_manifest, validate_digest};
use crate::{Descriptor, ToolError};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage: ginux-image import-layout CACHE_ROOT";
const MAX_MEMBERS: usize = 4096;
const MAX_LAYOUT_FILE: u64 = 4 * 1024;
const MAX_INDEX: u64 = 4 * 1024 * 1024;
const MAX_MANIFEST: u64 = 4 * 1024 * 1024;
const MAX_CONFIG: u64 = 16 * 1024 * 1024;
const COPY_BUFFER: usize = 64 * 1024;

const INDEX_TYPES: [&str; 2] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];
const MANIFEST_TYPES: [&str; 2] = [
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];
/// The layer types the expander handles (`apply_layer`), without its empty-string fallback.
const LAYER_TYPES: [&str; 4] = [
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.docker.image.rootfs.diff.tar",
];
const UNCOMPRESSED_LAYER_TYPES: [&str; 2] = [
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.docker.image.rootfs.diff.tar",
];

/// Runs `import-layout` with the layout tar on descriptor 0 and the manifest digest written
/// to descriptor 1; returns the exit code.
pub fn run(arguments: &[OsString]) -> u8 {
    let [cache_root] = arguments else {
        eprintln!("{USAGE}");
        return exit::USAGE;
    };
    let result = crate::export::standard_output().and_then(|mut output| {
        let digest = import_layout(Path::new(cache_root), io::stdin().lock())?;
        let output: &mut File = &mut output;
        writeln!(output, "{digest}")
            .and_then(|()| output.flush())
            .map_err(|error| {
                ToolError::new(exit::OUTPUT, format!("unable to write the digest: {error}"))
            })
    });
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("ginux-image: import-layout: {}", error.message);
            error.code
        }
    }
}

/// Imports the layout read from `input` into `cache_root` (which holds `blobs/sha256`) and
/// returns the manifest digest `sha256:HEX`.
pub fn import_layout(cache_root: &Path, input: impl Read) -> Result<String, ToolError> {
    let input = refuse_compressed(input)?;
    let staging = Staging::create(cache_root)?;
    let received = receive(input, &staging.path)?;
    let plan = validate(&received, &staging.path)?;
    commit(cache_root, &staging.path, &plan)?;
    Ok(plan.manifest.digest)
}

fn invalid(message: impl Into<String>) -> ToolError {
    ToolError::new(exit::INVALID, message)
}

fn malformed(error: io::Error) -> ToolError {
    invalid(format!("layout archive is malformed: {error}"))
}

fn write_failed(context: &str, error: io::Error) -> ToolError {
    ToolError::new(exit::OUTPUT, format!("{context}: {error}"))
}

/// Peeks at the first two bytes: gzip input is refused, everything else is passed on whole.
fn refuse_compressed(mut input: impl Read) -> Result<impl Read, ToolError> {
    let mut head = [0u8; 2];
    let mut filled = 0;
    while filled < head.len() {
        match input.read(&mut head[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(malformed(error)),
        }
    }
    if filled == 2 && head == [0x1f, 0x8b] {
        return Err(invalid("compressed layout archives are not supported"));
    }
    Ok(io::Cursor::new(head[..filled].to_vec()).chain(input))
}

/// A root-only directory inside the cache root (same filesystem as `blobs/sha256`, so the
/// commit is a rename), removed on every exit path.
struct Staging {
    path: PathBuf,
}

impl Staging {
    fn create(cache_root: &Path) -> Result<Self, ToolError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let path = cache_root.join(format!(".import-{}-{nonce:x}", std::process::id()));
        // create, not create_all: an existing name is never reused.
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| {
                ToolError::new(
                    exit::INTERNAL,
                    format!(
                        "unable to create staging directory {}: {error}",
                        path.display()
                    ),
                )
            })?;
        Ok(Self { path })
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Default)]
struct Received {
    layout: Option<Vec<u8>>,
    index: Option<Vec<u8>>,
    /// Staged blobs: lowercase hex digest to size in bytes.
    blobs: BTreeMap<String, u64>,
}

enum Member {
    Directory,
    OciLayout,
    Index,
    Blob(String),
}

fn is_lower_hex_digest(value: &[u8]) -> bool {
    value.len() == 64
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

/// Maps a member path to one of the accepted layout paths. Returns the normalized path (the
/// duplicate-detection key) and its role.
fn classify(raw: &[u8], is_dir: bool) -> Result<(Vec<u8>, Member), ToolError> {
    let shown = escaped(raw);
    let mut path = raw.strip_prefix(b"./").unwrap_or(raw);
    if is_dir {
        path = path.strip_suffix(b"/").unwrap_or(path);
    }
    let member = match path {
        // The archive's own top directory, as `tar -C layout .` writes it.
        b"" | b"." if is_dir => Member::Directory,
        b"blobs" | b"blobs/sha256" if is_dir => Member::Directory,
        b"oci-layout" if !is_dir => Member::OciLayout,
        b"index.json" if !is_dir => Member::Index,
        _ => match path.strip_prefix(b"blobs/sha256/") {
            Some(hex) if !is_dir && is_lower_hex_digest(hex) => {
                Member::Blob(String::from_utf8_lossy(hex).into_owned())
            }
            _ => return Err(invalid(format!("unsupported layout member: {shown}"))),
        },
    };
    let key: &[u8] = if path == b"." { b"" } else { path };
    Ok((key.to_vec(), member))
}

fn receive(input: impl Read, staging: &Path) -> Result<Received, ToolError> {
    let mut archive = tar::Archive::new(input);
    let mut seen = BTreeSet::new();
    let mut received = Received::default();
    let mut count = 0usize;
    // Raw iteration: tar's default iterator reads every GNU long name/link and PAX header body
    // fully into memory, with no cap, before any check here runs. Raw entries leave those
    // headers as ordinary entries, which are refused below before their body is touched.
    for entry in archive.entries().map_err(malformed)?.raw(true) {
        let mut entry = entry.map_err(malformed)?;
        count += 1;
        if count > MAX_MEMBERS {
            return Err(invalid(format!(
                "layout archive has more than {MAX_MEMBERS} members"
            )));
        }
        let raw = entry.path_bytes().into_owned();
        let shown = escaped(&raw);
        // Regular files and directories only: symlinks, hard links, devices, FIFOs, GNU
        // sparse entries and the extension headers all have other entry types.
        let kind = entry.header().entry_type();
        if kind.is_gnu_longname()
            || kind.is_gnu_longlink()
            || kind.is_pax_local_extensions()
            || kind.is_pax_global_extensions()
            || kind.is_gnu_sparse()
        {
            return Err(invalid(format!(
                "layout archive uses an extended header ({kind:?}); every layout path is shorter than 100 bytes: {shown}"
            )));
        }
        if !kind.is_file() && !kind.is_dir() {
            return Err(invalid(format!(
                "unsupported layout member type {kind:?}: {shown}"
            )));
        }
        let (key, member) = classify(&raw, kind.is_dir())?;
        if !seen.insert(key) {
            return Err(invalid(format!("duplicate layout member: {shown}")));
        }
        match member {
            Member::Directory => {}
            Member::OciLayout => {
                received.layout = Some(read_small(&mut entry, MAX_LAYOUT_FILE, "oci-layout")?)
            }
            Member::Index => {
                received.index = Some(read_small(&mut entry, MAX_INDEX, "index.json")?)
            }
            Member::Blob(hex) => {
                let size = stage_blob(&mut entry, staging, &hex)?;
                received.blobs.insert(hex, size);
            }
        }
    }
    Ok(received)
}

fn read_small(entry: &mut impl Read, limit: u64, label: &str) -> Result<Vec<u8>, ToolError> {
    let mut bytes = Vec::new();
    entry
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(malformed)?;
    if bytes.len() as u64 > limit {
        return Err(invalid(format!("{label} is larger than {limit} bytes")));
    }
    Ok(bytes)
}

fn stage_blob(entry: &mut impl Read, staging: &Path, hex: &str) -> Result<u64, ToolError> {
    let path = staging.join(hex);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| write_failed("unable to stage blob", error))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; COPY_BUFFER];
    let mut size = 0u64;
    loop {
        let count = match entry.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(malformed(error)),
        };
        file.write_all(&buffer[..count])
            .map_err(|error| write_failed("unable to stage blob", error))?;
        hasher.update(&buffer[..count]);
        size += count as u64;
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != hex {
        return Err(invalid(format!(
            "blob digest mismatch: blobs/sha256/{hex} has sha256:{actual}"
        )));
    }
    Ok(size)
}

struct Plan {
    manifest: Descriptor,
    config: Descriptor,
    layers: Vec<Descriptor>,
}

fn validate(received: &Received, staging: &Path) -> Result<Plan, ToolError> {
    let layout = received
        .layout
        .as_deref()
        .ok_or_else(|| invalid("layout has no oci-layout file"))?;
    let layout: Value = serde_json::from_slice(layout)
        .map_err(|error| invalid(format!("oci-layout is not JSON: {error}")))?;
    if layout.get("imageLayoutVersion").and_then(Value::as_str) != Some("1.0.0") {
        return Err(invalid("oci-layout imageLayoutVersion is not 1.0.0"));
    }
    let index = received
        .index
        .as_deref()
        .ok_or_else(|| invalid("layout has no index.json"))?;
    let index: Value = serde_json::from_slice(index)
        .map_err(|error| invalid(format!("index.json is not JSON: {error}")))?;
    let mut chosen = choose(&index, "index.json")?;
    if INDEX_TYPES.contains(&chosen.media_type.as_str()) {
        let nested = staged_json(received, staging, &chosen, "image index", MAX_INDEX)?;
        chosen = choose(&nested, "nested image index")?;
        if INDEX_TYPES.contains(&chosen.media_type.as_str()) {
            return Err(invalid("image index nesting is deeper than one level"));
        }
    }
    if !MANIFEST_TYPES.contains(&chosen.media_type.as_str()) {
        return Err(invalid(format!(
            "unsupported manifest media type: {:?}",
            chosen.media_type
        )));
    }
    let manifest = staged_json(received, staging, &chosen, "manifest", MAX_MANIFEST)?;
    if manifest.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
        return Err(invalid("manifest schemaVersion is not 2"));
    }
    let config = descriptor(manifest.get("config"), "config").map_err(invalid)?;
    let layers = manifest
        .get("layers")
        .and_then(Value::as_array)
        .filter(|layers| !layers.is_empty())
        .ok_or_else(|| invalid("manifest has no layers"))?
        .iter()
        .map(|layer| descriptor(Some(layer), "layer").map_err(invalid))
        .collect::<Result<Vec<_>, _>>()?;
    for layer in &layers {
        if !LAYER_TYPES.contains(&layer.media_type.as_str()) {
            return Err(invalid(format!(
                "unsupported layer media type: {:?}",
                layer.media_type
            )));
        }
        staged_size(received, layer, "layer")?;
    }
    let config_document = staged_json(received, staging, &config, "config", MAX_CONFIG)?;
    if !config_document.is_object() {
        return Err(invalid("image config is not a JSON object"));
    }
    if config_document.get("os").and_then(Value::as_str) != Some("linux")
        || config_document.get("architecture").and_then(Value::as_str) != Some("amd64")
    {
        return Err(invalid("image config is not linux/amd64"));
    }
    if let Some(diff_ids) = config_document
        .get("rootfs")
        .and_then(|rootfs| rootfs.get("diff_ids"))
        .and_then(Value::as_array)
        .filter(|diff_ids| diff_ids.len() == layers.len())
    {
        for (layer, diff_id) in layers.iter().zip(diff_ids) {
            if UNCOMPRESSED_LAYER_TYPES.contains(&layer.media_type.as_str())
                && diff_id.as_str() != Some(layer.digest.as_str())
            {
                return Err(invalid(format!(
                    "uncompressed layer {} does not match its diff_id",
                    layer.digest
                )));
            }
        }
    }
    Ok(Plan {
        manifest: chosen,
        config,
        layers,
    })
}

/// One descriptor from an index: the only entry, or the linux/amd64 one among several.
fn choose(index: &Value, label: &str) -> Result<Descriptor, ToolError> {
    let manifests = index
        .get("manifests")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("{label} has no manifests array")))?;
    match manifests.as_slice() {
        [] => Err(invalid(format!("{label} lists no manifests"))),
        [only] => descriptor(Some(only), "manifest").map_err(invalid),
        _ => select_manifest(index)
            .map_err(invalid)?
            .ok_or_else(|| invalid(format!("{label} lists no linux/amd64 manifest"))),
    }
}

/// The staged hex name of a descriptor whose blob is present with exactly its stated size.
fn staged_size<'a>(
    received: &Received,
    descriptor: &'a Descriptor,
    label: &str,
) -> Result<(&'a str, u64), ToolError> {
    validate_digest(&descriptor.digest).map_err(invalid)?;
    let hex = descriptor.digest.trim_start_matches("sha256:");
    if !is_lower_hex_digest(hex.as_bytes()) {
        return Err(invalid(format!(
            "{label} digest is not lowercase: {}",
            descriptor.digest
        )));
    }
    let actual = *received.blobs.get(hex).ok_or_else(|| {
        invalid(format!(
            "{label} blob {} is missing from the layout",
            descriptor.digest
        ))
    })?;
    let expected = descriptor
        .size
        .ok_or_else(|| invalid(format!("{label} descriptor has no size")))?;
    if actual != expected {
        return Err(invalid(format!(
            "{label} blob {} has {actual} bytes, its descriptor says {expected}",
            descriptor.digest
        )));
    }
    Ok((hex, actual))
}

fn staged_json(
    received: &Received,
    staging: &Path,
    descriptor: &Descriptor,
    label: &str,
    limit: u64,
) -> Result<Value, ToolError> {
    let (hex, size) = staged_size(received, descriptor, label)?;
    if size > limit {
        return Err(invalid(format!("{label} is larger than {limit} bytes")));
    }
    read_json(&staging.join(hex)).map_err(invalid)
}

fn commit(cache_root: &Path, staging: &Path, plan: &Plan) -> Result<(), ToolError> {
    // Layers, then config, then manifest last; each digest once.
    let mut order: Vec<&Descriptor> = Vec::new();
    for descriptor in plan.layers.iter().chain([&plan.config]) {
        if descriptor.digest != plan.manifest.digest
            && !order.iter().any(|seen| seen.digest == descriptor.digest)
        {
            order.push(descriptor);
        }
    }
    order.push(&plan.manifest);

    let blobs = cache_root.join("blobs/sha256");
    let mut created = Vec::new();
    let mut missing = blobs.as_path();
    while !missing.exists() {
        created.push(missing.to_path_buf());
        match missing.parent() {
            Some(parent) if parent != cache_root => missing = parent,
            _ => break,
        }
    }
    let mut added: Vec<PathBuf> = Vec::new();
    let result = (|| {
        fs::create_dir_all(&blobs)
            .map_err(|error| write_failed("unable to create the blob directory", error))?;
        for descriptor in &order {
            let hex = descriptor.digest.trim_start_matches("sha256:");
            let staged = staging.join(hex);
            if cached_blob(cache_root, &descriptor.digest)
                .map_err(|error| ToolError::new(exit::INTERNAL, error))?
                .is_some()
            {
                // Already present and verified: keep the cached copy.
                fs::remove_file(&staged)
                    .map_err(|error| ToolError::new(exit::INTERNAL, error.to_string()))?;
                continue;
            }
            File::open(&staged)
                .and_then(|file| file.sync_all())
                .map_err(|error| write_failed("unable to sync a staged blob", error))?;
            let target = blobs.join(hex);
            fs::rename(&staged, &target)
                .map_err(|error| write_failed("unable to commit a blob", error))?;
            added.push(target);
        }
        File::open(&blobs)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| write_failed("unable to sync the blob directory", error))
    })();
    if result.is_err() {
        // Only the manifest blob this run added is removed. Layers and config are
        // content-addressed and verified, so a leftover one is harmless, and a concurrent
        // import may have found it cached and committed its own manifest on top of it.
        // Without this run's manifest nothing refers to them from here.
        if let Some(manifest) = added.last().filter(|target| {
            target.file_name().and_then(|name| name.to_str())
                == Some(plan.manifest.digest.trim_start_matches("sha256:"))
        }) {
            let _ = fs::remove_file(manifest);
        }
        for directory in &created {
            let _ = fs::remove_dir(directory);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ginux-oci-layout-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(path.join("cache/blobs/sha256")).unwrap();
            Self(path)
        }

        fn cache(&self) -> PathBuf {
            self.0.join("cache")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sha(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    /// Entries of a layout archive: path, entry type, body.
    struct Layout {
        entries: Vec<(String, tar::EntryType, Vec<u8>)>,
        manifest: String,
    }

    impl Layout {
        fn push_blob(&mut self, body: &[u8]) -> String {
            let hex = sha(body);
            self.entries.push((
                format!("blobs/sha256/{hex}"),
                tar::EntryType::Regular,
                body.to_vec(),
            ));
            hex
        }

        fn remove(&mut self, path: &str) {
            self.entries.retain(|(name, _, _)| name != path);
        }

        fn tar(&self) -> Vec<u8> {
            let mut builder = tar::Builder::new(Vec::new());
            for (path, kind, body) in &self.entries {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(*kind);
                header.set_mode(0o644);
                if *kind == tar::EntryType::Symlink {
                    header.set_size(0);
                    builder.append_link(&mut header, path, "target").unwrap();
                } else {
                    header.set_size(body.len() as u64);
                    builder
                        .append_data(&mut header, path, body.as_slice())
                        .unwrap();
                }
            }
            builder.into_inner().unwrap()
        }
    }

    fn layer_tar() -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(6);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, "hello.txt", &b"hello\n"[..])
            .unwrap();
        builder.into_inner().unwrap()
    }

    struct Options {
        layer_type: &'static str,
        layer_size_delta: i64,
        nested_indexes: usize,
    }

    const DEFAULT: Options = Options {
        layer_type: "application/vnd.oci.image.layer.v1.tar",
        layer_size_delta: 0,
        nested_indexes: 0,
    };

    fn layout(options: Options) -> Layout {
        let mut layout = Layout {
            entries: vec![
                ("blobs/".into(), tar::EntryType::Directory, Vec::new()),
                (
                    "blobs/sha256/".into(),
                    tar::EntryType::Directory,
                    Vec::new(),
                ),
                (
                    "oci-layout".into(),
                    tar::EntryType::Regular,
                    br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec(),
                ),
            ],
            manifest: String::new(),
        };
        let layer = layer_tar();
        let layer_hex = layout.push_blob(&layer);
        let config = format!(
            r#"{{"architecture":"amd64","os":"linux","rootfs":{{"type":"layers","diff_ids":["sha256:{layer_hex}"]}},"config":{{}}}}"#
        );
        let config_hex = layout.push_blob(config.as_bytes());
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{config_hex}","size":{}}},"layers":[{{"mediaType":"{}","digest":"sha256:{layer_hex}","size":{}}}]}}"#,
            config.len(),
            options.layer_type,
            layer.len() as i64 + options.layer_size_delta
        );
        let manifest_hex = layout.push_blob(manifest.as_bytes());
        layout.manifest = format!("sha256:{manifest_hex}");
        let mut top = (
            "application/vnd.oci.image.manifest.v1+json".to_owned(),
            manifest_hex,
            manifest.len(),
        );
        for _ in 0..options.nested_indexes {
            let index = format!(
                r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"{}","digest":"sha256:{}","size":{},"platform":{{"architecture":"amd64","os":"linux"}}}}]}}"#,
                top.0, top.1, top.2
            );
            let hex = layout.push_blob(index.as_bytes());
            top = (
                "application/vnd.oci.image.index.v1+json".to_owned(),
                hex,
                index.len(),
            );
        }
        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"{}","digest":"sha256:{}","size":{},"platform":{{"architecture":"amd64","os":"linux"}}}}]}}"#,
            top.0, top.1, top.2
        );
        layout.entries.push((
            "index.json".into(),
            tar::EntryType::Regular,
            index.into_bytes(),
        ));
        layout
    }

    fn listing(root: &Path) -> Vec<(PathBuf, u64)> {
        let mut found = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory).unwrap() {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                let relative = entry.path().strip_prefix(root).unwrap().to_path_buf();
                found.push((relative, metadata.len()));
                if metadata.is_dir() {
                    pending.push(entry.path());
                }
            }
        }
        found.sort();
        found
    }

    fn refused(bytes: Vec<u8>) {
        let directory = TempDir::new("refused");
        let cache = directory.cache();
        // A blob already cached must stay untouched too.
        fs::write(cache.join("blobs/sha256").join(sha(b"kept")), b"kept").unwrap();
        let before = listing(&cache);
        let error = import_layout(&cache, bytes.as_slice()).unwrap_err();
        assert_eq!(error.code, exit::INVALID, "{}", error.message);
        assert_eq!(listing(&cache), before, "{}", error.message);
    }

    #[test]
    fn one_layer_layout_is_committed_and_materializes_offline() {
        let directory = TempDir::new("import");
        let cache = directory.cache();
        let layout = layout(DEFAULT);
        let digest = import_layout(&cache, layout.tar().as_slice()).unwrap();
        assert_eq!(digest, layout.manifest);
        let committed: Vec<_> = listing(&cache.join("blobs/sha256"))
            .into_iter()
            .map(|(path, _)| path)
            .collect();
        assert_eq!(committed.len(), 3);
        // No staging directory is left behind.
        assert_eq!(fs::read_dir(&cache).unwrap().count(), 1);
        // A second import of the same layout keeps the cached blobs and prints the same digest.
        assert_eq!(
            import_layout(&cache, layout.tar().as_slice()).unwrap(),
            digest
        );
        // Fully cached: materialize makes no request. The registry name cannot resolve, so any
        // network attempt would fail this call.
        let destination = directory.0.join("root");
        crate::materialize(
            &format!("invalid.invalid/t@{digest}"),
            &cache,
            &destination,
            io::sink(),
        )
        .unwrap();
        assert_eq!(fs::read(destination.join("hello.txt")).unwrap(), b"hello\n");
    }

    #[test]
    fn index_nested_one_level_is_resolved() {
        let directory = TempDir::new("nested");
        let layout = layout(Options {
            nested_indexes: 1,
            ..DEFAULT
        });
        let digest = import_layout(&directory.cache(), layout.tar().as_slice()).unwrap();
        assert_eq!(digest, layout.manifest);
    }

    #[test]
    fn index_nested_two_levels_is_refused() {
        refused(
            layout(Options {
                nested_indexes: 2,
                ..DEFAULT
            })
            .tar(),
        );
    }

    #[test]
    fn tampered_blob_is_refused() {
        let mut layout = layout(DEFAULT);
        let entry = layout
            .entries
            .iter_mut()
            .find(|(path, _, body)| path.starts_with("blobs/sha256/") && body.len() > 1000)
            .unwrap();
        entry.2[600] ^= 1;
        refused(layout.tar());
    }

    #[test]
    fn wrong_descriptor_size_is_refused() {
        refused(
            layout(Options {
                layer_size_delta: 1,
                ..DEFAULT
            })
            .tar(),
        );
    }

    #[test]
    fn symlink_member_is_refused() {
        let mut layout = layout(DEFAULT);
        layout.entries.push((
            format!("blobs/sha256/{}", "0".repeat(64)),
            tar::EntryType::Symlink,
            Vec::new(),
        ));
        refused(layout.tar());
    }

    #[test]
    fn extra_path_is_refused() {
        let mut layout = layout(DEFAULT);
        layout
            .entries
            .push(("extra.txt".into(), tar::EntryType::Regular, b"x".to_vec()));
        refused(layout.tar());
        let mut layout = self::layout(DEFAULT);
        layout.push_blob(b"x");
        let last = layout.entries.last_mut().unwrap();
        last.0 = last
            .0
            .to_uppercase()
            .replace("BLOBS/SHA256", "blobs/sha256");
        refused(layout.tar());
    }

    #[test]
    fn duplicate_member_is_refused() {
        let mut layout = layout(DEFAULT);
        let index = layout
            .entries
            .iter()
            .find(|(path, _, _)| path == "index.json")
            .unwrap()
            .clone();
        layout.entries.push(index);
        refused(layout.tar());
        let mut layout = self::layout(DEFAULT);
        layout
            .entries
            .push(("./blobs".into(), tar::EntryType::Directory, Vec::new()));
        refused(layout.tar());
    }

    #[test]
    fn missing_config_is_refused() {
        let mut layout = layout(DEFAULT);
        let config = layout
            .entries
            .iter()
            .find(|(path, _, body)| {
                path.starts_with("blobs/sha256/") && body.starts_with(br#"{"architecture""#)
            })
            .unwrap()
            .0
            .clone();
        layout.remove(&config);
        refused(layout.tar());
    }

    #[test]
    fn unsupported_layer_media_type_is_refused() {
        refused(
            layout(Options {
                layer_type: "application/vnd.oci.image.layer.v1.tar+zstd",
                ..DEFAULT
            })
            .tar(),
        );
    }

    /// A 512-byte header with a valid checksum, a type flag and a size field, no body.
    fn bare_header(name: &[u8], kind: u8, size: u64) -> Vec<u8> {
        let mut header = vec![0u8; 512];
        header[..name.len()].copy_from_slice(name);
        header[100..107].copy_from_slice(b"0000644");
        header[108..115].copy_from_slice(b"0000000");
        header[116..123].copy_from_slice(b"0000000");
        // GNU base-256 size: the octal field only reaches 8 GiB.
        header[124] = 0x80;
        header[125..136].copy_from_slice(&u128::from(size).to_be_bytes()[5..]);
        header[136..147].copy_from_slice(b"00000000000");
        header[156] = kind;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        header
    }

    #[test]
    fn extension_headers_are_refused_without_reading_their_body() {
        // 100 GiB declared, nothing follows: the default iterator would try to allocate it.
        for kind in *b"LKxgS" {
            let start = std::time::Instant::now();
            let directory = TempDir::new("extension");
            let bytes = bare_header(b"././@LongLink", kind, 100 << 30);
            let error = import_layout(&directory.cache(), bytes.as_slice()).unwrap_err();
            assert_eq!(error.code, exit::INVALID, "{}", error.message);
            assert!(
                error.message.contains("extended header"),
                "{}",
                error.message
            );
            assert!(start.elapsed() < std::time::Duration::from_secs(5));
        }
    }

    #[test]
    fn hostile_member_name_is_escaped_in_the_error() {
        let mut layout = layout(DEFAULT);
        layout.entries.push((
            "x\x1b]52;c;x\x07".into(),
            tar::EntryType::Regular,
            b"x".to_vec(),
        ));
        let directory = TempDir::new("escape");
        let error = import_layout(&directory.cache(), layout.tar().as_slice()).unwrap_err();
        assert_eq!(error.code, exit::INVALID);
        assert!(
            error.message.contains("x\\x1b]52;c;x\\x07"),
            "{}",
            error.message
        );
        assert!(!error.message.chars().any(char::is_control));
    }

    #[test]
    fn failed_commit_removes_only_its_own_manifest() {
        let directory = TempDir::new("rollback");
        let cache = directory.cache();
        let layout = layout(DEFAULT);
        // The manifest's target is an empty directory, so its rename (the last step) fails
        // after the layer and config were committed.
        let manifest_hex = layout.manifest.trim_start_matches("sha256:").to_owned();
        let blobs = cache.join("blobs/sha256");
        fs::create_dir(blobs.join(&manifest_hex)).unwrap();
        let error = import_layout(&cache, layout.tar().as_slice()).unwrap_err();
        assert_eq!(error.code, exit::OUTPUT, "{}", error.message);
        // No committed manifest; the verified layer and config stay.
        assert!(!blobs.join(&manifest_hex).is_file());
        let files = listing(&blobs)
            .into_iter()
            .filter(|(path, _)| path != Path::new(&manifest_hex))
            .count();
        assert_eq!(files, 2);
    }

    #[test]
    fn gzip_archive_is_refused() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&layout(DEFAULT).tar()).unwrap();
        refused(encoder.finish().unwrap());
    }

    #[test]
    fn missing_layout_files_are_refused() {
        let mut layout = layout(DEFAULT);
        layout.remove("oci-layout");
        refused(layout.tar());
        let mut layout = self::layout(DEFAULT);
        layout.remove("index.json");
        refused(layout.tar());
        refused(Vec::new());
    }
}
