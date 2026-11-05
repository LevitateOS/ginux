//! Confined export of a verified durable generation into host staging.
//!
//! Owner: G-storage (G13). [`VirtualFs::export_generation`] recovers one
//! generation that [`VirtualFs::verify_published`] accepts — anything else
//! is refused before a byte is staged — and copies a selected subtree of the
//! merged domain view (base image plus overlay, tombstones included) into a
//! fresh host staging directory through the caller-provided [`ExportStore`].
//!
//! Confinement is structural, not advisory:
//!
//! * The walk never follows symlinks below the export root (links are
//!   recorded, never traversed), so a link can never pull the walk outside
//!   the selected tree.
//! * Absolute symlink targets and relative targets that resolve outside the
//!   export root are rejected per file, never written.
//! * Every staged host path derives from one validated relative component
//!   at a time (`.`/`..`/separators/NUL rejected), so the core can only name
//!   paths strictly inside the staging root. The host joins those relatives
//!   onto its fresh staging directory and must still reject absolute or
//!   `..`-bearing input defensively.
//! * Tombstone markers live under the reserved [`TOMBSTONE_MARKER_DIR`]
//!   subtree of the staging directory, never at a domain-derived path, so a
//!   marker cannot clobber an exported file.
//!
//! Bounds are explicit: [`ExportLimits::max_files`] caps emitted records
//! (hitting it stops the walk with `exhausted` set — the tree is truncated,
//! never silently), and [`ExportLimits::max_bytes`] caps total file-data
//! bytes (an oversized file is skipped per file and the walk continues).
//! Every skipped entry lands in the caller's failure buffer with its domain
//! path and reason; the batch completes and the coordinator decides from the
//! [`ExportSummary`] (`failed == 0 && !exhausted`) whether the staging tree
//! may be published. An export failure is never reported as a publishable
//! tree.
//!
//! The caller sizes two scratch buffers: `verify_scratch` must fit the
//! largest publishable image (size it from [`RetainedLimits`], exactly like
//! the G12 flush scratch), and `data_scratch` must fit the largest file
//! (`FILE_SIZE`; the entry check fails closed otherwise).

use super::{
    is_canonical_path, BaseReader, DirEntry, DurableStore, FlushError, MergedKind, NodeKind,
    RetainedLimits, VirtualFs, O_READ, MAX_LINK, MAX_PATH,
};

/// Bounds for one export batch. Hitting `max_files` stops the walk with an
/// explicit `exhausted` summary; hitting `max_bytes` skips the oversized
/// file per entry and continues.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportLimits {
    /// Maximum emitted records: created directories (the root itself is
    /// free) plus files plus symlinks plus tombstone markers.
    pub max_files: usize,
    /// Maximum total file-data bytes across the batch. Symlink targets and
    /// tombstone markers do not count.
    pub max_bytes: usize,
}

impl ExportLimits {
    /// Small-workload bounds: room for a transform output tree beside its
    /// deletion markers.
    pub const fn defaults() -> Self {
        Self {
            max_files: 64,
            max_bytes: 64 * 1024,
        }
    }

    /// Explicit caller-chosen bounds.
    pub const fn bounded(max_files: usize, max_bytes: usize) -> Self {
        Self {
            max_files,
            max_bytes,
        }
    }
}

/// Reserved staging subtree holding one marker file per exported tombstone.
/// Markers live at `<staging>/.ginux-tombstones/<rel>` with the deleted
/// domain path as content; a selected tree containing a live entry under
/// that name shares the namespace, and a marker write that collides with it
/// fails per file on the host side.
pub const TOMBSTONE_MARKER_DIR: &[u8] = b".ginux-tombstones";

/// Host-side confined staging hook: the coordinator implements this over a
/// fresh per-invocation staging directory (mode `0700`, see the interfaces
/// §3 host staging rule). Every `rel` is a confined relative path built by
/// the core from validated single components — never empty, never absolute,
/// never containing `..`, `/`, or NUL — and `marker` additionally starts
/// with [`TOMBSTONE_MARKER_DIR`] plus `/`. The host joins these onto the
/// staging root and rejects anything else; it never interprets domain
/// paths, follows staged symlinks, or writes outside the staging root.
pub trait ExportStore {
    /// Host failure type. Per-file staging failures are reported through
    /// [`ExportFileError::Host`]; log the value on the host side first.
    type Error;
    /// Create staging directory `rel` with permission bits `mode`.
    /// Missing parents must be created; an existing directory takes the
    /// mode update and succeeds.
    fn create_dir(&mut self, rel: &[u8], mode: u32) -> Result<(), Self::Error>;
    /// Write staging file `rel` with exactly `data` and permission bits
    /// `mode`, creating missing parents. An existing file is replaced.
    fn write_file(&mut self, rel: &[u8], mode: u32, data: &[u8]) -> Result<(), Self::Error>;
    /// Recreate staging symlink `rel` with the exact raw target `target`
    /// (already validated confined), creating missing parents. An existing
    /// entry is replaced. The host must not resolve the target.
    fn write_symlink(&mut self, rel: &[u8], target: &[u8]) -> Result<(), Self::Error>;
    /// Record a deletion marker at staging path `marker` holding the
    /// deleted domain path `origin`, creating missing parents.
    fn record_tombstone(&mut self, marker: &[u8], origin: &[u8]) -> Result<(), Self::Error>;
}

/// Why one domain entry was skipped. Every variant is a partial batch
/// failure: the walk continues (except [`ExportFileError::TooManyFiles`],
/// which stops the walk and sets `exhausted`) and the summary reports it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportFileError {
    /// Absolute symlink target, NUL-bearing or unresolvable target, target
    /// resolving outside the export root, or a `..`/`.`/separator-bearing
    /// enumerated name.
    Escape,
    /// The `max_files` entry budget is spent; the walk stops here and the
    /// summary reports `exhausted`.
    TooManyFiles,
    /// One file is larger than the whole `max_bytes` budget (or larger than
    /// the caller data buffer) and could never fit.
    TooLarge,
    /// One file does not fit the remaining `max_bytes` budget.
    NoSpace,
    /// The subtree below this directory is deeper than the bounded walk.
    TooDeep,
    /// The domain entry could not be read (metadata, link target, or file
    /// content).
    Read,
    /// The host staging hook failed for this entry.
    Host,
}

impl ExportFileError {
    /// Stable machine-readable name for logs and error propagation.
    pub const fn as_str(self) -> &'static str {
        match self {
            ExportFileError::Escape => "escape",
            ExportFileError::TooManyFiles => "too-many-files",
            ExportFileError::TooLarge => "too-large",
            ExportFileError::NoSpace => "no-space",
            ExportFileError::TooDeep => "too-deep",
            ExportFileError::Read => "read",
            ExportFileError::Host => "host",
        }
    }
}

/// Why an export batch never started. Per-entry problems never surface here;
/// they land in the failure buffer and the summary instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportError {
    /// The publish path does not hold a [`VirtualFs::verify_published`]
    /// accepted image: nothing was recovered and nothing was staged.
    /// Carries the verification failure.
    Unverified(FlushError),
    /// The accepted image could not be recovered after verification (the
    /// store changed between the two reads). Nothing was staged; the live
    /// view was already replaced, so re-verify before retrying.
    Store(FlushError),
    /// The export root is not an existing merged-view directory.
    InvalidRoot,
    /// The caller data buffer is smaller than `FILE_SIZE` and cannot hold
    /// the largest file.
    SmallScratch,
}

impl ExportError {
    /// Stable machine-readable name for logs and error propagation.
    pub const fn as_str(self) -> &'static str {
        match self {
            ExportError::Unverified(error) => error.as_str(),
            ExportError::Store(error) => error.as_str(),
            ExportError::InvalidRoot => "invalid-root",
            ExportError::SmallScratch => "small-scratch",
        }
    }
}

/// One skipped domain entry: its full domain path plus the reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportFailure {
    /// Full domain path bytes (`/out/sub/evil`); exactly `path_len` bytes
    /// are meaningful.
    pub path: [u8; MAX_PATH],
    /// Meaningful bytes in `path`.
    pub path_len: usize,
    /// Why the entry was skipped.
    pub error: ExportFileError,
}

impl ExportFailure {
    /// The failed domain path.
    pub const fn path_bytes(&self) -> &[u8] {
        // `path_len` is set only by the core, always within bounds.
        let (head, _) = self.path.split_at(self.path_len);
        head
    }
}

/// What [`VirtualFs::export_generation`] staged. Publish the staging tree
/// only when `failed == 0 && !exhausted`; anything else is a storage failure
/// with an accurate per-file report, never a complete output tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportSummary {
    /// Files written.
    pub files: usize,
    /// Directories created (the staging root itself is free).
    pub dirs: usize,
    /// Symlinks recreated.
    pub symlinks: usize,
    /// Tombstone markers recorded.
    pub tombstones: usize,
    /// Total file-data bytes written.
    pub bytes: usize,
    /// Total per-file failures (recorded plus dropped).
    pub failed: usize,
    /// Failures not recorded because the caller buffer was too small.
    /// Nonzero means the buffer understates the report; `failed` is exact.
    pub dropped: usize,
    /// The `max_files` budget stopped the walk: the staging tree is
    /// truncated and must not be published.
    pub exhausted: bool,
    /// The verified and recovered durable generation this tree came from.
    pub generation: u32,
}

/// Per-directory listing cap: a directory with more children is skipped with
/// [`ExportFileError::TooManyFiles`] and stops the walk, so one huge
/// directory cannot wedge the bounded batch.
const MAX_EXPORT_CHILDREN: usize = 64;
/// Walk depth cap below the export root: deeper subtrees are skipped with
/// [`ExportFileError::TooDeep`]. Domain paths are at most `MAX_PATH` bytes,
/// so no legitimate shallow tree can hit this.
const MAX_EXPORT_DEPTH: u32 = 64;

/// Per-file report sink: counts every failure, records what fits.
struct Reporter<'x> {
    buf: &'x mut [ExportFailure],
    filled: usize,
    failed: usize,
    dropped: usize,
}

impl<'x> Reporter<'x> {
    fn push(&mut self, path: &[u8], error: ExportFileError) {
        self.failed += 1;
        if self.filled < self.buf.len() {
            let mut failure = ExportFailure {
                path: [0u8; MAX_PATH],
                path_len: path.len().min(MAX_PATH),
                error,
            };
            failure.path[..failure.path_len].copy_from_slice(&path[..failure.path_len]);
            self.buf[self.filled] = failure;
            self.filled += 1;
        } else {
            self.dropped += 1;
        }
    }
}

/// Batch counters plus the stop flag for entry-budget exhaustion.
struct WalkState {
    files: usize,
    dirs: usize,
    symlinks: usize,
    tombstones: usize,
    bytes: usize,
    stop: bool,
}

impl WalkState {
    const fn entries(&self) -> usize {
        self.files + self.dirs + self.symlinks + self.tombstones
    }
}

/// One enumerated child with its name owned, so the `&mut` domain reads
/// below never overlap the listing borrow.
struct Kid {
    kind: NodeKind,
    mode: u32,
    len: usize,
    name: [u8; MAX_PATH],
}

impl<'a, R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>
    VirtualFs<'a, R, FILES, FILE_SIZE, FDS>
{
    /// Export a selected subtree of one verified durable generation.
    ///
    /// `final_path` must name a publish path whose image
    /// [`VirtualFs::verify_published`] accepts for `instance`/`limits`;
    /// otherwise [`ExportError::Unverified`] is returned before anything is
    /// staged. On acceptance the live view is replaced with that generation
    /// (overlay and descriptors cleared first, exactly like a fresh
    /// [`VirtualFs::recover_retained`]), so the walked content provably is
    /// the verified generation — call this on a dedicated or teardown-safe
    /// view, never on a live workload view holding uncheckpointed writes.
    /// `root` names the exported subtree (`/out` per the interfaces stable
    /// paths); a root symlink pointing at a directory exports the target
    /// tree, anything but an existing directory is
    /// [`ExportError::InvalidRoot`].
    ///
    /// `verify_scratch` doubles as the recover buffer and must fit the
    /// largest publishable image (size it from `limits`, as with the G12
    /// flush scratch); `data_scratch` must fit the largest file
    /// (`FILE_SIZE`). `failures` collects one [`ExportFailure`] per skipped
    /// entry; overflow counts as `dropped` without failing the batch.
    #[allow(clippy::too_many_arguments)]
    pub fn export_generation<S: DurableStore, E: ExportStore>(
        &mut self,
        instance: u64,
        limits: &RetainedLimits,
        store: &mut S,
        final_path: &[u8],
        verify_scratch: &mut [u8],
        root: &[u8],
        elimits: &ExportLimits,
        estate: &mut E,
        data_scratch: &mut [u8],
        failures: &mut [ExportFailure],
    ) -> Result<ExportSummary, ExportError> {
        if data_scratch.len() < FILE_SIZE {
            return Err(ExportError::SmallScratch);
        }
        if !is_canonical_path(root) {
            return Err(ExportError::InvalidRoot);
        }
        let generation = self
            .verify_published(instance, limits, store, final_path, verify_scratch)
            .map_err(ExportError::Unverified)?;
        // Replace the live view with the verified generation, so the walk
        // below cannot mix verified bytes with older overlay state.
        self.teardown();
        self.recover_retained(instance, limits, store, final_path, verify_scratch)
            .map_err(ExportError::Store)?;
        match self.stat_merged(root) {
            Ok((NodeKind::Directory, _, _)) => {}
            _ => return Err(ExportError::InvalidRoot),
        }
        let mut reporter = Reporter {
            buf: failures,
            filled: 0,
            failed: 0,
            dropped: 0,
        };
        let mut state = WalkState {
            files: 0,
            dirs: 0,
            symlinks: 0,
            tombstones: 0,
            bytes: 0,
            stop: false,
        };
        let mut rel = [0u8; MAX_PATH];
        self.walk_dir(
            root,
            root,
            &mut rel,
            0,
            0,
            elimits,
            estate,
            data_scratch,
            &mut reporter,
            &mut state,
        );
        Ok(ExportSummary {
            files: state.files,
            dirs: state.dirs,
            symlinks: state.symlinks,
            tombstones: state.tombstones,
            bytes: state.bytes,
            failed: reporter.failed,
            dropped: reporter.dropped,
            exhausted: state.stop,
            generation,
        })
    }

    /// Copy the merged-view subtree at canonical domain path `dir`, whose
    /// staging-relative path is `rel[..rel_len]`. The root itself is free;
    /// every record below it spends the entry budget and may stop the walk.
    /// Symlinks are recorded, never descended into.
    #[allow(clippy::too_many_arguments)]
    fn walk_dir<E: ExportStore>(
        &mut self,
        dir: &[u8],
        root: &[u8],
        rel: &mut [u8; MAX_PATH],
        rel_len: usize,
        depth: u32,
        elimits: &ExportLimits,
        estate: &mut E,
        data: &mut [u8],
        reporter: &mut Reporter<'_>,
        state: &mut WalkState,
    ) {
        let total = match self.list_dir(dir, &mut []) {
            Ok(total) => total,
            Err(_) => {
                reporter.push(dir, ExportFileError::Read);
                return;
            }
        };
        if total > MAX_EXPORT_CHILDREN {
            reporter.push(dir, ExportFileError::TooManyFiles);
            state.stop = true;
            return;
        }
        for index in 0..total {
            if state.stop {
                break;
            }
            // One full listing per child: the listing borrow ends before
            // any `&mut` domain read below, and the single-threaded view
            // cannot change between the probe and these reads.
            let kid = match self.list_child(dir, index) {
                Some(kid) => kid,
                None => {
                    reporter.push(dir, ExportFileError::Read);
                    return;
                }
            };
            if !valid_name(&kid.name[..kid.len]) {
                // `..`/`.`/separator-bearing names can only come from a
                // corrupt base image; they must never become host paths.
                let mut path = [0u8; MAX_PATH];
                let path_len = join_domain(&mut path, dir, &kid.name[..kid.len]);
                reporter.push(&path[..path_len.min(MAX_PATH)], ExportFileError::Escape);
                continue;
            }
            let mut child = [0u8; MAX_PATH];
            let child_len = join_domain(&mut child, dir, &kid.name[..kid.len]);
            if child_len > MAX_PATH {
                reporter.push(&child[..MAX_PATH.min(child_len)], ExportFileError::Escape);
                continue;
            }
            let child = &child[..child_len];
            let mut child_rel = [0u8; MAX_PATH];
            let child_rel_len = join_rel(&mut child_rel, rel, rel_len, &kid.name[..kid.len]);
            if child_rel_len > MAX_PATH {
                reporter.push(child, ExportFileError::Escape);
                continue;
            }
            let child_rel = &child_rel[..child_rel_len];
            match kid.kind {
                NodeKind::Directory => self.export_subdir(
                    child, root, child_rel, depth, elimits, estate, data, reporter, state,
                    kid.mode,
                ),
                NodeKind::File => {
                    self.export_file(child, child_rel, elimits, estate, data, reporter, state)
                }
                NodeKind::Symlink => self.export_symlink(
                    dir, root, child, child_rel, elimits, estate, reporter, state,
                ),
            }
        }
        if !state.stop {
            self.export_tombstones(dir, rel, rel_len, elimits, estate, reporter, state);
        }
    }

    /// Fetch one enumerated child with its name owned. Returns `None` when
    /// the view changed mid-walk, which cannot happen single-threaded.
    fn list_child(&self, dir: &[u8], index: usize) -> Option<Kid> {
        let mut buf = [DirEntry {
            name: b"",
            kind: NodeKind::File,
            mode: 0,
        }; MAX_EXPORT_CHILDREN];
        let total = self.list_dir(dir, &mut buf).ok()?;
        let entry = buf.get(index)?;
        if index >= total {
            return None;
        }
        let mut kid = Kid {
            kind: entry.kind,
            mode: entry.mode,
            len: entry.name.len().min(MAX_PATH),
            name: [0u8; MAX_PATH],
        };
        kid.name[..kid.len].copy_from_slice(&entry.name[..kid.len]);
        Some(kid)
    }

    /// Spend one entry-budget record. False means the budget is spent: the
    /// failure is recorded and the whole walk stops with `exhausted` set.
    fn spend_entry(
        path: &[u8],
        elimits: &ExportLimits,
        reporter: &mut Reporter<'_>,
        state: &mut WalkState,
    ) -> bool {
        if state.entries() >= elimits.max_files {
            reporter.push(path, ExportFileError::TooManyFiles);
            state.stop = true;
            return false;
        }
        true
    }

    /// Create one staging subdirectory and walk it. A host failure records
    /// the directory and skips its subtree (its children would fail the
    /// same way); budget exhaustion stops the whole walk instead.
    #[allow(clippy::too_many_arguments)]
    fn export_subdir<E: ExportStore>(
        &mut self,
        child: &[u8],
        root: &[u8],
        child_rel: &[u8],
        depth: u32,
        elimits: &ExportLimits,
        estate: &mut E,
        data: &mut [u8],
        reporter: &mut Reporter<'_>,
        state: &mut WalkState,
        mode: u32,
    ) {
        if depth + 1 > MAX_EXPORT_DEPTH {
            reporter.push(child, ExportFileError::TooDeep);
            return;
        }
        if !Self::spend_entry(child, elimits, reporter, state) {
            return;
        }
        if estate.create_dir(child_rel, mode).is_err() {
            reporter.push(child, ExportFileError::Host);
            return;
        }
        state.dirs += 1;
        let mut sub_rel = [0u8; MAX_PATH];
        sub_rel[..child_rel.len()].copy_from_slice(child_rel);
        self.walk_dir(
            child,
            root,
            &mut sub_rel,
            child_rel.len(),
            depth + 1,
            elimits,
            estate,
            data,
            reporter,
            state,
        );
    }

    /// Copy one merged-view file into staging. Oversized files are skipped
    /// per entry; the batch continues.
    #[allow(clippy::too_many_arguments)]
    fn export_file<E: ExportStore>(
        &mut self,
        child: &[u8],
        child_rel: &[u8],
        elimits: &ExportLimits,
        estate: &mut E,
        data: &mut [u8],
        reporter: &mut Reporter<'_>,
        state: &mut WalkState,
    ) {
        let meta = match self.metadata_merged(child) {
            Ok(meta) if meta.kind == NodeKind::File => meta,
            _ => {
                reporter.push(child, ExportFileError::Read);
                return;
            }
        };
        let size = usize::try_from(meta.size).unwrap_or(usize::MAX);
        // The entry check also pins `size <= FILE_SIZE` (the caller buffer
        // fits the largest file), so the single read below is exact.
        if size > data.len() || size > elimits.max_bytes {
            reporter.push(child, ExportFileError::TooLarge);
            return;
        }
        if state.bytes + size > elimits.max_bytes {
            reporter.push(child, ExportFileError::NoSpace);
            return;
        }
        if !Self::spend_entry(child, elimits, reporter, state) {
            return;
        }
        let fd = match self.open(child, O_READ) {
            Ok(fd) => fd,
            Err(_) => {
                reporter.push(child, ExportFileError::Read);
                return;
            }
        };
        let mut filled = 0usize;
        let mut broken = false;
        while filled < size {
            match self.read(fd, &mut data[filled..size]) {
                Ok(0) => {
                    broken = true;
                    break;
                }
                Ok(n) => filled += n,
                Err(_) => {
                    broken = true;
                    break;
                }
            }
        }
        let _ = self.close(fd);
        if broken || filled != size {
            reporter.push(child, ExportFileError::Read);
            return;
        }
        if estate.write_file(child_rel, meta.mode, &data[..size]).is_err() {
            reporter.push(child, ExportFileError::Host);
            return;
        }
        state.files += 1;
        state.bytes += size;
    }

    /// Recreate one merged-view symlink in staging without following it.
    /// Absolute targets and targets resolving outside the export root are
    /// rejected: they would point at host paths or out-of-tree content at
    /// consumption time.
    #[allow(clippy::too_many_arguments)]
    fn export_symlink<E: ExportStore>(
        &self,
        dir: &[u8],
        root: &[u8],
        child: &[u8],
        child_rel: &[u8],
        elimits: &ExportLimits,
        estate: &mut E,
        reporter: &mut Reporter<'_>,
        state: &mut WalkState,
    ) {
        let mut raw = [0u8; MAX_LINK];
        let target = match self.readlink(child, &mut raw) {
            Ok(n) if n > 0 && n <= MAX_LINK => &raw[..n],
            _ => {
                reporter.push(child, ExportFileError::Read);
                return;
            }
        };
        if target.contains(&0) || !Self::target_confined(dir, target, root) {
            reporter.push(child, ExportFileError::Escape);
            return;
        }
        if !Self::spend_entry(child, elimits, reporter, state) {
            return;
        }
        if estate.write_symlink(child_rel, target).is_err() {
            reporter.push(child, ExportFileError::Host);
            return;
        }
        state.symlinks += 1;
    }

    /// Whether a raw symlink target stays confined: relative, and resolving
    /// (lexically, against the containing domain directory) strictly inside
    /// `root`. Lexical resolution cannot be redirected by links the walk
    /// never follows; absolute targets are refused outright.
    fn target_confined(containing: &[u8], target: &[u8], root: &[u8]) -> bool {
        if target.is_empty() || target.first() == Some(&b'/') {
            return false;
        }
        let mut joined = [0u8; MAX_PATH + MAX_LINK + 2];
        let mut len = 0usize;
        for part in [containing, b"/".as_slice(), target] {
            if len + part.len() > joined.len() {
                return false;
            }
            joined[len..len + part.len()].copy_from_slice(part);
            len += part.len();
        }
        let canon = match super::normalize(&joined[..len]) {
            Ok(path) => path,
            Err(_) => return false,
        };
        let resolved = canon.as_bytes();
        resolved == root
            || (resolved.len() > root.len()
                && resolved.starts_with(root)
                && (root == b"/" || resolved[root.len()] == b'/'))
    }

    /// Record deletion markers for tombstoned names directly inside `dir`.
    /// Tombstones hide their exact path only (directories are never
    /// tombstoned), so one overlay scan per visited directory is complete.
    /// A live entry at the same path always wins and suppresses the marker.
    #[allow(clippy::too_many_arguments)]
    fn export_tombstones<E: ExportStore>(
        &self,
        dir: &[u8],
        rel: &[u8; MAX_PATH],
        rel_len: usize,
        elimits: &ExportLimits,
        estate: &mut E,
        reporter: &mut Reporter<'_>,
        state: &mut WalkState,
    ) {
        let mut link = [0u8; MAX_LINK];
        for slot in self.overlay.iter() {
            if state.stop {
                break;
            }
            if slot.state != 2 {
                continue;
            }
            let path = slot.path.as_bytes();
            let name = match super::child_name(dir, path) {
                Some(name) if valid_name(name) => name,
                _ => continue,
            };
            if self.classify_merged(path, &mut link) != MergedKind::Missing {
                continue;
            }
            let mut marker = [0u8; MAX_PATH + 32];
            let marker_len = join_marker(&mut marker, rel, rel_len, name);
            if marker_len > marker.len() {
                reporter.push(path, ExportFileError::Escape);
                continue;
            }
            if !Self::spend_entry(path, elimits, reporter, state) {
                break;
            }
            if estate
                .record_tombstone(&marker[..marker_len], path)
                .is_err()
            {
                reporter.push(path, ExportFileError::Host);
                continue;
            }
            state.tombstones += 1;
        }
    }
}

/// One validated path component: nonempty, without separators, dots, or NUL.
/// Base-image entries are trusted only after this check, so a corrupt image
/// can never mint a host escape.
fn valid_name(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/') && !name.contains(&0)
}

/// Join `dir + "/" + name` into `out`, returning the joined length (which
/// may exceed `out` — the caller treats overflow as a per-file rejection).
/// The root `/` joins without a doubled slash.
fn join_domain(out: &mut [u8; MAX_PATH], dir: &[u8], name: &[u8]) -> usize {
    let total = dir.len() + (dir != b"/") as usize + name.len();
    let mut len = 0usize;
    for part in dir.iter() {
        if len >= out.len() {
            break;
        }
        out[len] = *part;
        len += 1;
    }
    if dir != b"/" && len < out.len() {
        out[len] = b'/';
        len += 1;
    }
    for part in name.iter() {
        if len >= out.len() {
            break;
        }
        out[len] = *part;
        len += 1;
    }
    // Report the true length even when the buffer clipped it.
    if total > out.len() {
        total
    } else {
        len
    }
}

/// Join `rel + "/" + name` into `out`, returning the true joined length.
fn join_rel(out: &mut [u8; MAX_PATH], rel: &[u8], rel_len: usize, name: &[u8]) -> usize {
    let total = rel_len + (rel_len > 0) as usize + name.len();
    let usable = rel_len.min(rel.len()).min(out.len());
    out[..usable].copy_from_slice(&rel[..usable]);
    let mut len = usable;
    if rel_len > 0 && len < out.len() {
        out[len] = b'/';
        len += 1;
    }
    for part in name.iter() {
        if len >= out.len() {
            break;
        }
        out[len] = *part;
        len += 1;
    }
    if total > out.len() {
        total
    } else {
        len
    }
}

/// Build a marker staging path `TOMBSTONE_MARKER_DIR/rel/name`.
fn join_marker(
    out: &mut [u8; MAX_PATH + 32],
    rel: &[u8; MAX_PATH],
    rel_len: usize,
    name: &[u8],
) -> usize {
    let prefix = TOMBSTONE_MARKER_DIR;
    let total = prefix.len() + 1 + rel_len + (rel_len > 0) as usize + name.len();
    let mut len = 0usize;
    for part in prefix.iter().chain(b"/".iter()) {
        if len >= out.len() {
            break;
        }
        out[len] = *part;
        len += 1;
    }
    let usable = rel_len.min(rel.len());
    if usable > 0 {
        let room = out.len().saturating_sub(len + 1 + name.len());
        let take = usable.min(room);
        out[len..len + take].copy_from_slice(&rel[..take]);
        len += take;
        if len < out.len() {
            out[len] = b'/';
            len += 1;
        }
    }
    for part in name.iter() {
        if len >= out.len() {
            break;
        }
        out[len] = *part;
        len += 1;
    }
    if total > out.len() {
        total
    } else {
        len
    }
}
