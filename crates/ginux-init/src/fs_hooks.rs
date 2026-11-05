#![allow(dead_code)]
//! Native filesystem-lane dispatch hooks.
//!
//! Note: `dead_code` is allowed module-wide because G06a introduces the
//! working-directory/resolution surface (`DomainCwd`, `resolve_at`, …) ahead
//! of its consumer: the supervisor tracee-memory/fd-table wiring owned by a
//! named follow-up (see G07). Re-enable the lint once that wiring calls it.
//!
//! Owner: G-files lane. G06 claims domain directory creation and enumeration
//! (`mkdir`/`mkdirat`/`getdents64`) so no directory operation reaches the
//! host: faithful emulation needs tracee-memory path reads owned by later
//! lanes (G06a/G07), so every claimed entry is explicitly denied until
//! VFS-backed emulation lands. G06a keeps those denials byte-identical and
//! adds the domain working-directory state plus the shared relative-path
//! resolver used by subsequent filesystem operations:
//!
//! * [`DomainCwd`] tracks the managed working directory. It starts at the
//!   configured workdir (default `/work`, see `docs/ginux-recipe-interfaces.md`
//!   §2–§3) and only moves through [`DomainCwd::chdir`], which resolves the
//!   request inside the domain and refuses escapes.
//! * [`resolve_at`] joins `AT_FDCWD`-relative and absolute paths, normalizes
//!   `.`/`..` with root confinement, and expands symlinks through a
//!   caller-supplied [`DomainView`] with a bounded follow count. A non-`AT_FDCWD`
//!   dirfd has no backing table until G07 owns descriptors, so it fails
//!   closed with [`ResolveError::DirFdUnsupported`] instead of naming a host
//!   descriptor.
//!
//! Everything here is pure `core` logic over caller buffers: no host calls,
//! so a denial has zero host effect by construction. The supervision
//! loop cannot feed tracee path bytes or persist per-task cwd through the
//! `claim(syscall, rdi, rsi, rdx) -> Option<i64>` channel yet (that needs
//! tracee-memory read/write plumbing in the supervisor, owned by a later
//! task), so `claim` keeps returning the explicit `-EPERM` denial for every
//! claimed entry, including the newly claimed `chdir`/`fchdir`/`getcwd`.
//! [`ResolveError::errno`] already maps each failure to its faithful errno
//! for that wiring.

/// `mkdir(2)`: domain directory creation. Claimed for G06.
pub const SYS_MKDIR: u64 = 83;
/// `mkdirat(2)`: domain directory creation relative to a directory fd.
/// Claimed for G06.
pub const SYS_MKDIRAT: u64 = 258;
/// `getdents64(2)`: domain directory enumeration. Claimed for G06: the
/// balanced contract would mediate it to the host, exposing host directory
/// contents as managed results.
pub const SYS_GETDENTS64: u64 = 217;
/// `getcwd(2)`: report the domain working directory. Claimed for G06a: the
/// balanced contract denies it with `-ENOSYS` (this is why `/bin/pwd`
/// currently exits 1). Faithful emulation must copy the cwd into tracee
/// memory, which needs supervisor plumbing owned by a later task; until
/// then the entry is explicitly denied and [`DomainCwd::getcwd_into`]
/// carries the reporting logic.
pub const SYS_GETCWD: u64 = 79;
/// `chdir(2)`: change the domain working directory. Claimed for G06a for
/// the same reason: the target path lives in tracee memory, so the entry
/// is denied until the supervisor can hand the bytes to [`DomainCwd::chdir`].
pub const SYS_CHDIR: u64 = 80;
/// `fchdir(2)`: change to a directory named by a file descriptor. Claimed
/// for G06a: dirfd values are meaningless without the G07 descriptor table,
/// so the entry is denied and [`resolve_at`] fails non-`AT_FDCWD` dirfds
/// closed with [`ResolveError::DirFdUnsupported`].
pub const SYS_FCHDIR: u64 = 81;

/// `AT_FDCWD`: a relative path resolves against the domain working
/// directory. Matches the Linux `AT_FDCWD` value (`-100`).
pub const AT_FDCWD: i64 = -100;

/// Domain path capacity, matching `ginux-vfs` `MAX_PATH`.
pub const MAX_CWD: usize = 256;
/// Symlink target capacity, matching `ginux-vfs` `MAX_LINK`.
pub const MAX_LINK: usize = 128;
/// Maximum path components per resolution, matching `ginux-vfs` normalize.
pub const MAX_COMPONENTS: usize = 64;
/// Maximum symlink expansions per resolution, matching `ginux-vfs` resolve.
pub const MAX_FOLLOW: usize = 16;

/// Default domain working directory (`docs/ginux-recipe-interfaces.md` §2:
/// optional `[domain] workdir`, default `/work`).
pub const DEFAULT_CWD: &[u8] = b"/work";

/// Negative errno constants returned by [`ResolveError::errno`].
pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const EBADF: i64 = 9;
pub const ENOTDIR: i64 = 20;
pub const EINVAL: i64 = 22;
pub const ERANGE: i64 = 34;
pub const ENAMETOOLONG: i64 = 36;
pub const ELOOP: i64 = 40;

/// Lane membership by syscall number: directory creation, enumeration, and
/// working-directory operations.
pub fn claims(syscall: u64) -> bool {
    matches!(
        syscall,
        SYS_MKDIR | SYS_MKDIRAT | SYS_GETDENTS64 | SYS_GETCWD | SYS_CHDIR | SYS_FCHDIR
    )
}

/// Emulated result when this lane handles the entry. `Some(-EPERM)` denies
/// the entry explicitly: confinement first — escape is denial, never host
/// effect. `None` falls through to the shared balanced-contract decision.
pub fn claim(syscall: u64, rdi: u64, rsi: u64, rdx: u64) -> Option<i64> {
    let _ = (rdi, rsi, rdx);
    if claims(syscall) {
        Some(-EPERM)
    } else {
        None
    }
}

/// How a resolution step classified one absolute domain path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvedKind {
    File,
    Directory,
    /// Final component only, and only when the caller passes
    /// `follow_final = false` (e.g. `lstat`-style queries owned by G07b).
    Symlink,
}

/// Why a working-directory operation or path resolution failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveError {
    /// Empty path, embedded NUL, or zero-length `getcwd` buffer.
    Malformed,
    /// `..` above the domain root, or an absolute symlink target escaping
    /// the root. Confinement denial, never a host effect.
    Escape,
    /// Canonical path exceeds [`MAX_CWD`], a symlink target exceeds
    /// [`MAX_LINK`], or a path holds more than [`MAX_COMPONENTS`].
    TooLong,
    /// No live domain entry at the resolved path.
    NotFound,
    /// Traversal through a non-directory, or a non-directory `chdir` target.
    NotDirectory,
    /// More than [`MAX_FOLLOW`] symlink expansions.
    SymlinkLoop,
    /// Relative path with a dirfd other than [`AT_FDCWD`]: no descriptor
    /// table exists until G07, so the request fails closed.
    DirFdUnsupported,
    /// `getcwd` buffer too small for the cwd plus its NUL terminator.
    BufferTooSmall,
}

impl ResolveError {
    /// Faithful negative errno for supervisor wiring. Confinement failures
    /// ([`ResolveError::Escape`]) map to `-EPERM`, matching the G06 claim
    /// denials.
    pub const fn errno(self) -> i64 {
        match self {
            ResolveError::Malformed => -EINVAL,
            ResolveError::Escape => -EPERM,
            ResolveError::TooLong => -ENAMETOOLONG,
            ResolveError::NotFound => -ENOENT,
            ResolveError::NotDirectory => -ENOTDIR,
            ResolveError::SymlinkLoop => -ELOOP,
            ResolveError::DirFdUnsupported => -EBADF,
            ResolveError::BufferTooSmall => -ERANGE,
        }
    }
}

/// What a caller's domain view reports for one absolute normalized prefix.
///
/// Overlay-aware callers (G07, backed by the VFS merged view) report the
/// merged answer: live overlay entries win, tombstones read as [`Lookup::Missing`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lookup {
    Missing,
    File,
    Directory,
    /// Symlink whose raw target was copied into the caller's buffer; the
    /// value is the target length.
    Symlink(usize),
    /// Symlink target did not fit the caller's [`MAX_LINK`] buffer.
    TargetTooLong,
}

/// Domain backing store consulted by [`resolve_at`] for every path prefix,
/// including the root `/`. Callers pass `&mut` access so a shared VFS handle
/// can serve lookups without reborrowing.
pub trait DomainView {
    /// Classify absolute normalized `path`. For symlinks copy the raw target
    /// (absolute or relative, uninterpreted) into `link` and return
    /// [`Lookup::Symlink`] with its length, or [`Lookup::TargetTooLong`]
    /// when it does not fit.
    fn classify(&mut self, path: &[u8], link: &mut [u8; MAX_LINK]) -> Lookup;
}

/// Managed working directory: an absolute confined domain path.
///
/// The value always starts with `/`, never ends with `/` (except the root
/// itself), and contains no `.`/`..`/empty components.
#[derive(Clone, Copy)]
pub struct DomainCwd {
    len: usize,
    bytes: [u8; MAX_CWD],
}

impl DomainCwd {
    /// Working directory from launch configuration: default `/work`.
    pub const fn new() -> Self {
        let mut bytes = [0u8; MAX_CWD];
        bytes[0] = b'/';
        bytes[1] = b'w';
        bytes[2] = b'o';
        bytes[3] = b'r';
        bytes[4] = b'k';
        Self { len: 5, bytes }
    }

    /// Validate a configured absolute workdir shape (lexical only: absolute,
    /// confined, fits). Existence is checked on first use, not here.
    pub fn from_absolute(path: &[u8]) -> Result<Self, ResolveError> {
        if path.is_empty() || path[0] != b'/' || path.contains(&0) {
            return Err(ResolveError::Malformed);
        }
        let mut out = [0u8; MAX_CWD];
        let len = normalize_lexical(path, &mut out)?;
        let mut cwd = Self {
            len,
            bytes: [0u8; MAX_CWD],
        };
        cwd.bytes[..len].copy_from_slice(&out[..len]);
        Ok(cwd)
    }

    /// Current absolute domain path.
    pub fn path(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Change directory: resolve `path` (absolute, or relative to the
    /// current directory per `AT_FDCWD` semantics) through `view` and move
    /// there. The target must be a live directory; anything else — missing,
    /// non-directory, escape, loop — leaves the cwd unchanged and reports
    /// the denial.
    pub fn chdir<V: DomainView>(&mut self, path: &[u8], view: &mut V) -> Result<(), ResolveError> {
        let mut out = [0u8; MAX_CWD];
        let (len, kind) = resolve_at(self.path(), AT_FDCWD, path, view, &mut out)?;
        if kind != ResolvedKind::Directory {
            return Err(ResolveError::NotDirectory);
        }
        self.bytes[..len].copy_from_slice(&out[..len]);
        self.len = len;
        Ok(())
    }

    /// Report the cwd into `buf` NUL-terminated, `pwd`-equivalent style.
    /// Returns the bytes stored including the NUL, matching the raw
    /// `getcwd(2)` return convention. Fails with [`ResolveError::Malformed`]
    /// for a zero-length buffer and [`ResolveError::BufferTooSmall`]
    /// (`-ERANGE`) when the path plus NUL does not fit.
    pub fn getcwd_into(&self, buf: &mut [u8]) -> Result<usize, ResolveError> {
        if buf.is_empty() {
            return Err(ResolveError::Malformed);
        }
        let need = self.len.checked_add(1).ok_or(ResolveError::TooLong)?;
        if need > buf.len() {
            return Err(ResolveError::BufferTooSmall);
        }
        buf[..self.len].copy_from_slice(self.path());
        buf[self.len] = 0;
        Ok(need)
    }
}

/// Resolve `path` to a canonical absolute domain path in `out`.
///
/// * Absolute paths ignore `dirfd`. Relative paths join the caller's `cwd`
///   when `dirfd == AT_FDCWD`; any other dirfd fails closed with
///   [`ResolveError::DirFdUnsupported`] (no descriptor table until G07).
/// * `.` and duplicate slashes collapse; `..` pops lexically and fails with
///   [`ResolveError::Escape`] above the root, so resolution can never name
///   anything outside the domain — same rule as `ginux-vfs` normalize.
/// * Every prefix is classified through `view`; symlinks expand (absolute
///   targets restart at `/`, relative targets restart at the containing
///   directory) up to [`MAX_FOLLOW`] follow steps, then
///   [`ResolveError::SymlinkLoop`].
/// * With `follow_final = true` (open/chdir style) a final symlink expands;
///   with `false` (`lstat` style) it resolves as [`ResolvedKind::Symlink`].
///   Intermediate symlinks always expand.
/// * Returns the canonical length (`out[..len]`) and the final kind. Like
///   `ginux-vfs` normalize, a trailing slash carries no meaning.
///
/// `cwd` must be absolute; `out` must be `[u8; MAX_CWD]`.
pub fn resolve_at<V: DomainView>(
    cwd: &[u8],
    dirfd: i64,
    path: &[u8],
    view: &mut V,
    out: &mut [u8; MAX_CWD],
) -> Result<(usize, ResolvedKind), ResolveError> {
    resolve_at_full(cwd, dirfd, path, true, view, out)
}

/// [`resolve_at`] with caller-chosen final-symlink behavior.
pub fn resolve_at_full<V: DomainView>(
    cwd: &[u8],
    dirfd: i64,
    path: &[u8],
    follow_final: bool,
    view: &mut V,
    out: &mut [u8; MAX_CWD],
) -> Result<(usize, ResolvedKind), ResolveError> {
    if path.is_empty() || path.contains(&0) {
        return Err(ResolveError::Malformed);
    }
    let mut cur = [0u8; MAX_CWD];
    let mut cur_len = if path[0] == b'/' {
        append_all(&mut cur, 0, path)?
    } else {
        if dirfd != AT_FDCWD {
            return Err(ResolveError::DirFdUnsupported);
        }
        if cwd.is_empty() || cwd[0] != b'/' || cwd.contains(&0) {
            return Err(ResolveError::Malformed);
        }
        let mut len = append_all(&mut cur, 0, cwd)?;
        if len != 1 {
            len = append_all(&mut cur, len, b"/")?;
        }
        append_all(&mut cur, len, path)?
    };

    let mut link = [0u8; MAX_LINK];
    let mut follows = 0usize;
    loop {
        match walk_once(&cur[..cur_len], follow_final, view, &mut link, out)? {
            WalkOutcome::Done(len, kind) => return Ok((len, kind)),
            WalkOutcome::Expand { next_len } => {
                follows += 1;
                if follows > MAX_FOLLOW {
                    return Err(ResolveError::SymlinkLoop);
                }
                cur[..next_len].copy_from_slice(&out[..next_len]);
                cur_len = next_len;
            }
        }
    }
}

enum WalkOutcome {
    Done(usize, ResolvedKind),
    /// `out` holds the expanded absolute path to re-walk; length inline.
    Expand {
        next_len: usize,
    },
}

/// One symlink-expansion pass over absolute `cur`, writing either the final
/// canonical path (`Done`) or the next path to walk (`Expand`) into `out`.
///
/// `..` is applied during the classified walk (not lexically up front), so
/// `..` after a symlink pops the symlink's expansion — the same order the
/// VFS merged view resolves in. `..` above the root is
/// [`ResolveError::Escape`].
fn walk_once<V: DomainView>(
    cur: &[u8],
    follow_final: bool,
    view: &mut V,
    link: &mut [u8; MAX_LINK],
    out: &mut [u8; MAX_CWD],
) -> Result<WalkOutcome, ResolveError> {
    // Component spans over `cur`, skipping empty/`.` parts lexically but
    // keeping `..` for the classified walk below.
    let mut starts = [0usize; MAX_COMPONENTS];
    let mut ends = [0usize; MAX_COMPONENTS];
    let mut count = 0usize;
    let mut index = 0usize;
    while index < cur.len() {
        while index < cur.len() && cur[index] == b'/' {
            index += 1;
        }
        if index >= cur.len() {
            break;
        }
        let mut end = index;
        while end < cur.len() && cur[end] != b'/' {
            end += 1;
        }
        if &cur[index..end] == b"." {
            // Collapse.
        } else {
            if count >= MAX_COMPONENTS {
                return Err(ResolveError::TooLong);
            }
            starts[count] = index;
            ends[count] = end;
            count += 1;
        }
        index = end;
    }

    // Rebuild the canonical path prefix by prefix, classifying each.
    // `work` never carries a trailing slash (except the root itself).
    let mut work_len = 1usize;
    out[0] = b'/';
    // Classify the root itself: views must report `/` as a directory.
    match view.classify(b"/", link) {
        Lookup::Directory => {}
        Lookup::Missing => return Err(ResolveError::NotFound),
        Lookup::TargetTooLong => return Err(ResolveError::TooLong),
        _ => return Err(ResolveError::NotDirectory),
    }
    if count == 0 {
        return Ok(WalkOutcome::Done(1, ResolvedKind::Directory));
    }
    // Restore points for `..`: `lens[d]` is the work length before the
    // `d`-th pushed component was appended.
    let mut lens = [0usize; MAX_COMPONENTS];
    let mut depth = 0usize;
    let mut cursor = 0usize;
    while cursor < count {
        let part = &cur[starts[cursor]..ends[cursor]];
        if part == b".." {
            if depth == 0 {
                return Err(ResolveError::Escape);
            }
            depth -= 1;
            work_len = lens[depth];
            cursor += 1;
            continue;
        }
        lens[depth] = work_len;
        depth += 1;
        if work_len > 1 {
            work_len = append_all(out, work_len, b"/")?;
        }
        work_len = append_all(out, work_len, part)?;
        let last = cursor + 1 == count;
        match view.classify(&out[..work_len], link) {
            Lookup::Missing => return Err(ResolveError::NotFound),
            Lookup::TargetTooLong => return Err(ResolveError::TooLong),
            Lookup::File => {
                if !last {
                    return Err(ResolveError::NotDirectory);
                }
                return Ok(WalkOutcome::Done(work_len, ResolvedKind::File));
            }
            Lookup::Directory => {
                if last {
                    return Ok(WalkOutcome::Done(work_len, ResolvedKind::Directory));
                }
            }
            Lookup::Symlink(target_len) => {
                if last && !follow_final {
                    return Ok(WalkOutcome::Done(work_len, ResolvedKind::Symlink));
                }
                let target = &link[..target_len];
                if target.is_empty() || target.contains(&0) {
                    return Err(ResolveError::Malformed);
                }
                // Expansion base: absolute targets restart at `/`,
                // relative targets restart at the containing directory.
                let mut next = [0u8; MAX_CWD];
                let mut next_len = 1usize;
                next[0] = b'/';
                if target[0] != b'/' {
                    if work_len > 1 {
                        // Strip the symlink's own name, keep `/a` from `/a/link`.
                        let mut dir_end = work_len;
                        while dir_end > 0 && out[dir_end - 1] != b'/' {
                            dir_end -= 1;
                        }
                        // `dir_end` is at least 1 (the leading slash).
                        if dir_end > 1 {
                            next_len = append_all(&mut next, next_len, &out[1..dir_end])?;
                            next_len = append_all(&mut next, next_len, b"/")?;
                        }
                    }
                    next_len = append_all(&mut next, next_len, target)?;
                } else {
                    next_len = append_all(&mut next, 0, target)?;
                }
                // Append the still-unprocessed suffix verbatim; the next
                // pass re-walks it (normalizes `.`/`..`, classifies, follows).
                for rest in cursor + 1..count {
                    next_len = append_all(&mut next, next_len, b"/")?;
                    next_len = append_all(&mut next, next_len, &cur[starts[rest]..ends[rest]])?;
                }
                out[..next_len].copy_from_slice(&next[..next_len]);
                return Ok(WalkOutcome::Expand { next_len });
            }
        }
        cursor += 1;
    }
    // The walk consumed every component without landing on a final entry:
    // the path ends in `..` pops, so `work` is a classified directory.
    Ok(WalkOutcome::Done(work_len, ResolvedKind::Directory))
}

/// Lexically normalize absolute `path` into `out` (`.` collapse, `..` pop,
/// `..` above root is [`ResolveError::Escape`]). No view lookups: shape
/// check only, for configured workdirs.
fn normalize_lexical(path: &[u8], out: &mut [u8; MAX_CWD]) -> Result<usize, ResolveError> {
    let mut len = 1usize;
    out[0] = b'/';
    let mut components = 0usize;
    let mut index = 0usize;
    while index < path.len() {
        while index < path.len() && path[index] == b'/' {
            index += 1;
        }
        if index >= path.len() {
            break;
        }
        let mut end = index;
        while end < path.len() && path[end] != b'/' {
            end += 1;
        }
        let part = &path[index..end];
        if part == b"." {
            // Collapse.
        } else if part == b".." {
            if components == 0 {
                return Err(ResolveError::Escape);
            }
            components -= 1;
            // Pop to the previous separator.
            while len > 1 && out[len - 1] != b'/' {
                len -= 1;
            }
            if len > 1 {
                len -= 1;
            }
        } else {
            if components >= MAX_COMPONENTS {
                return Err(ResolveError::TooLong);
            }
            if len > 1 {
                len = append_all(out, len, b"/")?;
            }
            len = append_all(out, len, part)?;
            components += 1;
        }
        index = end;
    }
    Ok(len)
}

/// Copy `src` into `dst` at `len`; bounds-checked against [`MAX_CWD`].
/// `dst` may be `out` or a scratch buffer of the same capacity.
fn append_all(dst: &mut [u8; MAX_CWD], len: usize, src: &[u8]) -> Result<usize, ResolveError> {
    let end = len.checked_add(src.len()).ok_or(ResolveError::TooLong)?;
    if end > MAX_CWD {
        return Err(ResolveError::TooLong);
    }
    dst[len..end].copy_from_slice(src);
    Ok(end)
}
