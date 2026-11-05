//! Native filesystem-lane dispatch hooks.
//!
//! Owner: G-files lane. G06 claims domain directory creation and enumeration
//! (`mkdir`/`mkdirat`/`getdents64`) so no directory operation reaches the
//! host: faithful emulation needs tracee-memory path reads owned by later
//! lanes (G06a/G07), so every claimed entry is explicitly denied until
//! VFS-backed emulation lands. G06a keeps those denials byte-identical and
//! adds the domain working-directory state plus the shared relative-path
//! resolver used by subsequent filesystem operations:
//!
//! * Narrow `#[allow(dead_code)]` marks only the surface still waiting for
//!   supervisor tracee-memory/fd-table wiring (`DomainCwd::chdir`,
//!   `getcwd_into`, `resolve_at_full`); everything else is called by the
//!   G07 open path below.
//!
//! * [`DomainCwd`] tracks the managed working directory. It starts at the
//!   configured workdir (default `/work`, see `docs/ginux-recipe-interfaces.md`
//!   §2–§3) and only moves through [`DomainCwd::chdir`], which resolves the
//!   request inside the domain and refuses escapes.
//! * [`resolve_at`] joins `AT_FDCWD`-relative and absolute paths, normalizes
//!   `.`/`..` with root confinement, and expands symlinks through a
//!   caller-supplied [`DomainView`] with a bounded follow count. A non-`AT_FDCWD`
//!   dirfd has no backing table until supervisor fd-table wiring exists, so
//!   it fails closed with [`ResolveError::DirFdUnsupported`] instead of
//!   naming a host descriptor.
//!
//! G07 consumes that surface for the descriptor/file-open path: [`open_at`]
//! resolves an `open`/`openat` request through [`resolve_at`] against the
//! merged domain view ([`VfsDomainView`], backed by
//! `ginux-vfs` `classify_merged`), maps native access flags onto the VFS
//! open flags, and allocates a bounded VFS descriptor. Read-only opens
//! reference the immutable base image; writable opens copy the file into
//! the writable overlay first, so a denied write — and even a permitted
//! one — can never mutate the immutable base. [`close_fd`] releases a
//! descriptor. Created files take the VFS-default mode; creation-mode/umask
//! fidelity belongs to G08a with the rest of permission handling.
//!
//! G07a adds the data path through the same descriptor table:
//! [`read_fd`]/[`write_fd`] move bytes at the descriptor offset with
//! short-I/O and bounded-transfer semantics, and [`lseek_fd`] repositions
//! the offset (`SEEK_SET`/`SEEK_CUR`/`SEEK_END`). `O_APPEND` opens position
//! every write at end-of-file. Failures map to faithful errnos through
//! [`IoError::errno`].
//!
//! G07b adds the stat family through the merged view: [`stat_at`] follows
//! a final symlink, [`lstat_at`] reports it, [`fstat_fd`] reports the
//! object an open descriptor pinned, and [`statat`] covers `newfstatat`
//! with flags `0` (stat-style) or [`AT_SYMLINK_NOFOLLOW`] (lstat-style) —
//! any other flag fails explicitly with [`StatError::Invalid`]. Modes add
//! the `S_IFMT` file-type bits to the stored permission bits, sizes count
//! domain bytes (link-target bytes for a final symlink), and inode numbers
//! are deterministic path hashes: no host metadata leaks. [`stat_write`]
//! serializes the Linux x86-64 `struct stat` layout (`fstat`/`newfstatat`
//! write-back) and [`old_stat_write`] the legacy layout (`stat`/`lstat`
//! write-back); both layouts were verified byte-for-byte against raw
//! host syscalls.
//!
//! G08 adds rename and removal over the same merged view: [`rename_at`]
//! moves a file or symlink onto a new name with atomic replace semantics
//! (an existing file or symlink at the target is replaced in the same
//! step), and [`unlink_at`] removes a file or symlink behind a tombstone.
//! Directories never move and `rmdir` stays an explicitly unsupported
//! follow-up: the `rmdir` entry stays denied, and [`unlink_at`] with
//! [`AT_REMOVEDIR`] fails with [`RemoveError::Unsupported`] instead of
//! touching the host. Failures map to faithful errnos through
//! [`StatError::errno`].
//!
//! G08a adds installation permissions and link operations over the same
//! merged view: [`chmod_at`]/[`fchmod_at`]/[`fchmod_fd`] set plain
//! permission bits (including the executable bit) on files and directories,
//! following a final symlink like `chmod(2)`; setuid/setgid/sticky requests
//! fail with [`PermError::NotPermitted`] and the chown family stays
//! claimed-but-denied with no emulation (ownership stays root — there is no
//! privilege model to grant it). [`link_at`] hard-links a file within the
//! domain (content copy; the pair shares no later writes, a stated bound),
//! [`symlink_at`] plants a symlink whose raw target stays uninterpreted
//! until resolution, and [`readlink_at`] reports that raw target without
//! following. Directories never link, links never replace, and confinement,
//! nofollow, tombstone, and base-immutability rules carry over from G08.
//! Failures map to faithful errnos through [`PermError::errno`],
//! [`LinkError::errno`], [`SymlinkError::errno`], and
//! [`ReadlinkError::errno`].
//!
//! Everything here is pure `core` logic over caller buffers: no host calls,
//! so a denial has zero host effect by construction. The supervision loop
//! cannot feed tracee path/memory bytes or persist per-task cwd/fd tables
//! through the `claim(syscall, rdi, rsi, rdx) -> Option<i64>` channel yet
//! (that needs tracee-memory read/write plumbing in the supervisor, owned
//! by a later task), so `claim` keeps returning the explicit `-EPERM`
//! denial for every claimed domain-fd entry, including the newly claimed
//! `read`/`write`/`lseek`. Standard I/O (`read` on fd 0–2, `write` on fd
//! 1–2) keeps falling through to the existing balanced-contract mediation
//! byte-identically — only the domain descriptor range (fd ≥ 3, the VFS
//! numbering base) is closed against host mediation. [`ResolveError::errno`],
//! [`OpenError::errno`], and [`IoError::errno`] already map each failure to
//! its faithful errno for that wiring.

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
/// for G06a: dirfd values stay meaningless because the VFS descriptor table
/// records no paths and directories cannot be opened into descriptors (see
/// [`open_at`]), so the entry stays denied and [`resolve_at`] fails
/// non-`AT_FDCWD` dirfds closed with [`ResolveError::DirFdUnsupported`].
/// Lifting this needs per-task fd-to-path wiring in the supervisor, owned
/// by a later task.
pub const SYS_FCHDIR: u64 = 81;
/// `open(2)`: domain file open. Claimed for G07: the balanced contract
/// would mediate it to the host, so claiming closes that host path. The
/// register channel carries no path bytes, so the entry is denied until
/// the supervisor can hand the bytes to [`open_at`].
pub const SYS_OPEN: u64 = 2;
/// `openat(2)`: domain file open relative to a directory fd. Claimed for
/// G07 for the same reason; `open` is `openat` with `AT_FDCWD`.
pub const SYS_OPENAT: u64 = 257;
/// `close(2)`: release a domain descriptor. Claimed for G07: without the
/// claim the balanced contract would hand a domain fd number to the host
/// `close`, closing an unrelated supervisor descriptor. Denied until the
/// supervisor can route the number to [`close_fd`].
pub const SYS_CLOSE: u64 = 3;
/// `read(2)`: move bytes from a domain descriptor at its offset. Claimed
/// for G07a: the balanced contract would mediate a domain fd to the host,
/// reading unrelated supervisor bytes. The register channel carries no
/// tracee buffer, so the domain-fd entry is denied until the supervisor
/// can hand the bytes to [`read_fd`]; fds below the domain numbering base
/// (stdio) fall through byte-identically.
pub const SYS_READ: u64 = 0;
/// `write(2)`: move bytes to a domain descriptor at its offset. Claimed
/// for G07a for the same reason; console writes (fd 1–2) fall through to
/// the existing console mediation byte-identically (see [`SYS_READ`]).
pub const SYS_WRITE: u64 = 1;
/// `lseek(2)`: reposition a domain descriptor offset. Claimed for G07a:
/// the balanced contract would mediate the number to the host. Denied on
/// domain fds until the supervisor can route it to [`lseek_fd`].
pub const SYS_LSEEK: u64 = 8;
/// `stat(2)`: legacy domain file metadata query. Claimed for G07b: the
/// balanced contract would mediate the domain path to the host, reporting
/// host metadata as managed results. The register channel carries no path
/// bytes, so the entry is denied until the supervisor can hand the bytes
/// to [`stat_at`] and write back the legacy layout via [`old_stat_write`].
pub const SYS_STAT: u64 = 4;
/// `fstat(2)`: domain descriptor metadata query. Claimed for G07b for the
/// same reason; numbers at or above [`DOMAIN_FD_BASE`] are denied until
/// the supervisor can route them to [`fstat_fd`], while stdio falls
/// through to the existing mediation byte-identically (see [`SYS_READ`]).
pub const SYS_FSTAT: u64 = 5;
/// `lstat(2)`: legacy domain file metadata query without final-symlink
/// following. Claimed for G07b on the same terms as [`SYS_STAT`], backing
/// onto [`lstat_at`] plus [`old_stat_write`].
pub const SYS_LSTAT: u64 = 6;
/// `newfstatat(2)` (aka `fstatat`): domain file metadata query relative to
/// a directory fd, with or without [`AT_SYMLINK_NOFOLLOW`]. Claimed for
/// G07b: this is the syscall the domain libc actually emits for
/// `stat`/`lstat`/`fstatat` (verified with `strace`), and the balanced
/// contract would mediate the domain path to the host. Denied until the
/// supervisor can hand the bytes to [`statat`] and write back via
/// [`stat_write`].
pub const SYS_NEWFSTATAT: u64 = 262;
/// `rename(2)`: domain file/symlink rename. Claimed for G08: the balanced
/// contract would mediate both domain paths to the host, renaming unrelated
/// supervisor files. `rename` is `renameat` with `AT_FDCWD`. The register
/// channel carries no path bytes, so the entry is denied until the
/// supervisor can hand the bytes to [`rename_at`].
pub const SYS_RENAME: u64 = 82;
/// `rmdir(2)`: domain directory removal. Claimed for G08 as an explicit
/// denial with no emulation yet: there is no VFS `rmdir` (stated follow-up),
/// and leaving the entry unclaimed would mediate the domain path to the
/// host. Denied; [`unlink_at`] reports the same refusal explicitly for
/// `unlinkat` with `AT_REMOVEDIR`.
pub const SYS_RMDIR: u64 = 84;
/// `unlink(2)`: domain file/symlink removal. Claimed for G08 for the same
/// reason as [`SYS_RENAME`]: `unlink` is `unlinkat` with `AT_FDCWD` and no
/// flags. Denied until the supervisor can hand the bytes to [`unlink_at`].
pub const SYS_UNLINK: u64 = 87;
/// `unlinkat(2)`: domain file/symlink removal relative to a directory fd,
/// or directory removal with `AT_REMOVEDIR`. Claimed for G08 on the same
/// terms as [`SYS_RENAME`]; the `AT_REMOVEDIR` form stays explicitly
/// unsupported (see [`RemoveError::Unsupported`]). Denied until the
/// supervisor can hand the bytes to [`unlink_at`].
pub const SYS_UNLINKAT: u64 = 263;
/// `renameat(2)`: domain file/symlink rename with independent directory fds
/// for the source and target. Claimed for G08 on the same terms as
/// [`SYS_RENAME`]. Denied until the supervisor can hand the bytes to
/// [`rename_at`].
pub const SYS_RENAMEAT: u64 = 264;
/// `link(2)`: domain file hard link. Claimed for G08a: the balanced
/// contract would mediate both domain paths to the host, linking unrelated
/// supervisor files. `link` is `linkat` with `AT_FDCWD` and no flags.
/// Denied until the supervisor can hand the bytes to [`link_at`].
pub const SYS_LINK: u64 = 86;
/// `symlink(2)`: domain symlink creation. Claimed for G08a on the same
/// terms as [`SYS_LINK`]: `symlink` is `symlinkat` with `AT_FDCWD`.
/// Denied until the supervisor can hand the bytes to [`symlink_at`].
pub const SYS_SYMLINK: u64 = 88;
/// `readlink(2)`: domain symlink target query. Claimed for G08a: the
/// balanced contract would mediate the domain path to the host (syscall 89
/// sits on its image-read surface), reporting host link contents as managed
/// results. Denied until the supervisor can hand the bytes to
/// [`readlink_at`].
pub const SYS_READLINK: u64 = 89;
/// `chmod(2)`: domain permission-bit change. Claimed for G08a on the same
/// terms as [`SYS_LINK`]. `chmod` is `fchmodat` with `AT_FDCWD` and no
/// flags. Denied until the supervisor can hand the bytes to [`chmod_at`].
pub const SYS_CHMOD: u64 = 90;
/// `fchmod(2)`: domain permission-bit change on a descriptor. Claimed for
/// G08a: without the claim the balanced contract would hand a domain fd
/// number to the host `fchmod`. Denied until the supervisor can route the
/// number to [`fchmod_fd`].
pub const SYS_FCHMOD: u64 = 91;
/// `chown(2)`: domain ownership change. Claimed for G08a as an explicit
/// denial with no emulation: the domain has no privilege model, so
/// ownership stays root and there is no [`chmod_at`]-style counterpart.
/// Leaving the entry unclaimed would mediate the domain path to the host.
pub const SYS_CHOWN: u64 = 92;
/// `fchown(2)`: domain ownership change on a descriptor. Claimed for G08a
/// as an explicit denial on the same terms as [`SYS_CHOWN`].
pub const SYS_FCHOWN: u64 = 93;
/// `lchown(2)`: domain ownership change without following. Claimed for
/// G08a as an explicit denial on the same terms as [`SYS_CHOWN`].
pub const SYS_LCHOWN: u64 = 94;
/// `fchownat(2)`: domain ownership change relative to a directory fd.
/// Claimed for G08a as an explicit denial on the same terms as
/// [`SYS_CHOWN`].
pub const SYS_FCHOWNAT: u64 = 260;
/// `linkat(2)`: domain file hard link with independent directory fds for
/// the source and target. Claimed for G08a on the same terms as
/// [`SYS_LINK`]. Only flags `0` is emulated ([`link_at`]); the rest fail
/// explicitly. Denied until the supervisor can hand the bytes over.
pub const SYS_LINKAT: u64 = 265;
/// `symlinkat(2)`: domain symlink creation relative to a directory fd.
/// Claimed for G08a on the same terms as [`SYS_LINK`]. Denied until the
/// supervisor can hand the bytes to [`symlink_at`].
pub const SYS_SYMLINKAT: u64 = 266;
/// `readlinkat(2)`: domain symlink target query relative to a directory
/// fd. Claimed for G08a on the same terms as [`SYS_READLINK`]. Denied
/// until the supervisor can hand the bytes to [`readlink_at`].
pub const SYS_READLINKAT: u64 = 267;
/// `fchmodat(2)`: domain permission-bit change relative to a directory fd.
/// Claimed for G08a on the same terms as [`SYS_CHMOD`]. Only flags `0` is
/// emulated ([`fchmod_at`]); the rest fail explicitly. Denied until the
/// supervisor can hand the bytes over.
pub const SYS_FCHMODAT: u64 = 268;

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
/// optional `[domain] workdir`, default `/work`). Referenced by
/// [`DomainCwd::new`]; allowed until supervisor launch wiring calls it.
#[allow(dead_code)]
pub const DEFAULT_CWD: &[u8] = b"/work";

/// Negative errno constants returned by [`ResolveError::errno`] and
/// [`OpenError::errno`].
///
/// Only `EPERM` is referenced by live in-crate code (`claim`); the rest
/// are consumed through the `errno` mappers, which the supervisor
/// tracee-memory/fd-table wiring calls once it lands — hence the scoped
/// allows below, matching the G07 API surface.
pub const EPERM: i64 = 1;
#[allow(dead_code)]
pub const ENOENT: i64 = 2;
#[allow(dead_code)]
pub const EIO: i64 = 5;
#[allow(dead_code)]
pub const EBADF: i64 = 9;
#[allow(dead_code)]
pub const EACCES: i64 = 13;
#[allow(dead_code)]
pub const EEXIST: i64 = 17;
#[allow(dead_code)]
pub const ENOTDIR: i64 = 20;
#[allow(dead_code)]
pub const EISDIR: i64 = 21;
#[allow(dead_code)]
pub const EINVAL: i64 = 22;
#[allow(dead_code)]
pub const EMFILE: i64 = 24;
#[allow(dead_code)]
pub const EFBIG: i64 = 27;
#[allow(dead_code)]
pub const ENOSPC: i64 = 28;
#[allow(dead_code)]
pub const ERANGE: i64 = 34;
#[allow(dead_code)]
pub const ENAMETOOLONG: i64 = 36;
#[allow(dead_code)]
pub const ELOOP: i64 = 40;
/// Linux errno `ENOSYS` (38): reported by [`RenameError::Unsupported`] and
/// [`RemoveError::Unsupported`] for the explicitly unsupported directory
/// forms. The value collides numerically with no claimed syscall number in
/// this lane (`SYS_LSEEK` is 8); it names an errno, never a syscall.
#[allow(dead_code)]
pub const ENOSYS: i64 = 38;

/// Native open flag values (Linux x86-64). Only the access mode plus
/// `O_CREAT`/`O_EXCL`/`O_TRUNC`/`O_APPEND`/`O_CLOEXEC` are supported by
/// [`open_at`]; anything else fails with [`OpenError::Invalid`].
/// `O_APPEND` positions every [`write_fd`] at end-of-file (G07a).
///
/// Consumed by [`open_at`], which the supervisor wiring calls once it
/// lands — hence the scoped allows.
#[allow(dead_code)]
pub const O_ACCMODE: u32 = 0o3;
#[allow(dead_code)]
pub const O_RDONLY: u32 = 0o0;
#[allow(dead_code)]
pub const O_WRONLY: u32 = 0o1;
#[allow(dead_code)]
pub const O_RDWR: u32 = 0o2;
#[allow(dead_code)]
pub const O_CREAT: u32 = 0o100;
#[allow(dead_code)]
pub const O_EXCL: u32 = 0o200;
#[allow(dead_code)]
pub const O_TRUNC: u32 = 0o1000;
#[allow(dead_code)]
pub const O_APPEND: u32 = 0o2000;
#[allow(dead_code)]
pub const O_CLOEXEC: u32 = 0o2000000;

/// Native `lseek` positioning bases (Linux x86-64), matching the
/// `ginux-vfs` `SEEK_*` values consumed by [`lseek_fd`].
#[allow(dead_code)]
pub const SEEK_SET: u32 = 0;
#[allow(dead_code)]
pub const SEEK_CUR: u32 = 1;
#[allow(dead_code)]
pub const SEEK_END: u32 = 2;

/// `AT_SYMLINK_NOFOLLOW` for [`statat`]: lstat-style query. The only
/// accepted non-zero `newfstatat` flag; `AT_EMPTY_PATH`/`AT_NO_AUTOMOUNT`
/// and the rest fail explicitly with [`StatError::Invalid`] until an
/// observed follow-up implements them.
///
/// Consumed by [`statat`], which the supervisor wiring calls once it
/// lands — hence the scoped allows below, matching the G07 API surface.
#[allow(dead_code)]
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
/// `AT_REMOVEDIR` for [`unlink_at`]: remove a directory instead of
/// unlinking a file/symlink. The only accepted non-zero `unlinkat` flag;
/// the directory form fails explicitly with [`RemoveError::Unsupported`]
/// until VFS `rmdir` support lands as an observed follow-up.
///
/// Consumed by [`unlink_at`], which the supervisor wiring calls once it
/// lands — hence the scoped allows below, matching the G07 API surface.
#[allow(dead_code)]
pub const AT_REMOVEDIR: u32 = 0x200;

/// Synthetic `st_mode` file-type bits (Linux x86-64). The index packs
/// permission bits only, so [`stat_from_meta`] adds these from the
/// resolved kind. Allowed until supervisor wiring calls [`statat`].
#[allow(dead_code)]
pub const S_IFREG: u32 = 0o100000;
#[allow(dead_code)]
pub const S_IFDIR: u32 = 0o040000;
#[allow(dead_code)]
pub const S_IFLNK: u32 = 0o120000;

/// Single synthetic device number reported in `st_dev`: the domain is one
/// filesystem, so a constant keeps every entry on it without naming any
/// host device. Allowed until supervisor wiring calls [`stat_write`].
#[allow(dead_code)]
pub const STAT_DEV: u64 = 1;
/// Conventional block size reported in `st_blksize` (a preferred-I/O
/// width, not a measured host value). Allowed with [`STAT_DEV`].
#[allow(dead_code)]
pub const STAT_BLKSIZE: u64 = 4096;
/// Linux x86-64 `struct stat` size: the [`stat_write`] write-back buffer
/// for `fstat`/`newfstatat`. Allowed with [`STAT_DEV`].
#[allow(dead_code)]
pub const STAT_SIZE: usize = 144;
/// Legacy `struct __old_kernel_stat` size: the [`old_stat_write`]
/// write-back buffer for `stat`/`lstat`. Allowed with [`STAT_DEV`].
#[allow(dead_code)]
pub const OLD_STAT_SIZE: usize = 80;

/// First domain descriptor number: the VFS allocates from 3, so fds below
/// it are process stdio, never domain objects.
pub const DOMAIN_FD_BASE: u64 = 3;

/// Lane membership by syscall number: directory creation, enumeration,
/// working-directory operations, descriptor open/close (G07), descriptor
/// data I/O (G07a), file metadata queries (G07b), rename/removal (G08),
/// and permissions/links (G08a).
pub fn claims(syscall: u64) -> bool {
    matches!(
        syscall,
        SYS_MKDIR
            | SYS_MKDIRAT
            | SYS_GETDENTS64
            | SYS_GETCWD
            | SYS_CHDIR
            | SYS_FCHDIR
            | SYS_OPEN
            | SYS_OPENAT
            | SYS_CLOSE
            | SYS_READ
            | SYS_WRITE
            | SYS_LSEEK
            | SYS_STAT
            | SYS_FSTAT
            | SYS_LSTAT
            | SYS_NEWFSTATAT
            | SYS_RENAME
            | SYS_RMDIR
            | SYS_UNLINK
            | SYS_UNLINKAT
            | SYS_RENAMEAT
            | SYS_LINK
            | SYS_SYMLINK
            | SYS_READLINK
            | SYS_CHMOD
            | SYS_FCHMOD
            | SYS_CHOWN
            | SYS_FCHOWN
            | SYS_LCHOWN
            | SYS_FCHOWNAT
            | SYS_LINKAT
            | SYS_SYMLINKAT
            | SYS_READLINKAT
            | SYS_FCHMODAT
    )
}

/// Emulated result when this lane handles the entry. `Some(-EPERM)` denies
/// the entry explicitly: confinement first — escape is denial, never host
/// effect. `None` falls through to the shared balanced-contract decision.
///
/// G07 keeps every claimed open-path entry denied here, including
/// `open`/`openat`/`close`: this channel sees only registers, while
/// emulation needs the tracee path bytes plus per-task cwd/fd-table state
/// (see [`open_at`]). G07a keeps the data path denied on the same terms —
/// emulation needs the tracee data buffers plus the per-task fd table
/// (see [`read_fd`]/[`write_fd`]/[`lseek_fd`]) — except below the domain
/// numbering base: stdio (`read` on fd 0–2, `write`/`lseek` on fd 0–2)
/// falls through to the existing balanced-contract mediation
/// byte-identically, so console I/O keeps working. G07b keeps the stat
/// family denied on the same terms — emulation needs the tracee path
/// bytes plus per-task cwd/VFS state (see [`stat_at`]/[`lstat_at`]/
/// [`fstat_fd`]/[`statat`]) — with the same stdio fallthrough for
/// `fstat` on fd 0–2, so console metadata queries keep working. G08 keeps
/// the rename/removal entries denied on the same terms — emulation needs
/// the tracee path bytes plus per-task cwd/VFS state (see [`rename_at`]/
/// [`unlink_at`]) — with no fd-based fallthrough: every claimed rename or
/// removal names domain paths, never host descriptors. G08a keeps the
/// permission/link entries denied on the same terms — emulation needs the
/// tracee path bytes (plus data buffers for `readlink`, plus per-task
/// cwd/VFS state) for [`chmod_at`]/[`fchmod_at`]/[`link_at`]/[`symlink_at`]/
/// [`readlink_at`], and the descriptor number for
/// [`fchmod_fd`] — again with no fd-based fallthrough for the path entries
/// (the chown family has no emulation at all: ownership stays root).
/// Claiming still matters — it stops the balanced contract from mediating
/// domain paths and descriptor numbers to the host (which would report
/// host metadata as managed results, or rename and unlink host files) —
/// and every other syscall behaves byte-identically to before.
pub fn claim(syscall: u64, rdi: u64, rsi: u64, rdx: u64) -> Option<i64> {
    let _ = (rsi, rdx);
    if !claims(syscall) {
        return None;
    }
    match syscall {
        SYS_READ | SYS_WRITE | SYS_LSEEK | SYS_FSTAT if rdi < DOMAIN_FD_BASE => None,
        _ => Some(-EPERM),
    }
}

/// How a resolution step classified one absolute domain path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvedKind {
    File,
    Directory,
    /// Final component only, and only when the caller passes
    /// `follow_final = false` (`lstat`-style queries owned by G07b, and
    /// G08 rename/unlink sources, which move the link itself).
    /// G07 opens always follow the final link, so only [`resolve_at_full`]
    /// constructs this; it is wired when supervisor memory plumbing lands.
    #[allow(dead_code)]
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
    /// denials. Allowed until that wiring (via [`OpenError::errno`]) lands.
    #[allow(dead_code)]
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
///
/// Variants are constructed by [`DomainView`] adapters (in-crate:
/// [`VfsDomainView`]); allowed until supervisor wiring calls them.
#[allow(dead_code)]
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
    /// Constructed by supervisor launch wiring once per-task cwd
    /// persistence lands; [`open_at`] only borrows the value.
    #[allow(dead_code)]
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
    /// Called by supervisor launch wiring; kept until that lands.
    #[allow(dead_code)]
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
    /// the denial. Wired to the supervisor `chdir` entry once tracee path
    /// bytes reach this lane; kept until then.
    #[allow(dead_code)]
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
    /// (`-ERANGE`) when the path plus NUL does not fit. Wired to the
    /// supervisor `getcwd` entry once tracee memory writes land; kept
    /// until then.
    #[allow(dead_code)]
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
/// G07 opens always follow the final link; `lstat`-style queries owned by
/// G07b will call this. Kept until supervisor wiring lands.
#[allow(dead_code)]
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

// ─── G07: native open and descriptor lifetime ────────────────────────────

use ginux_vfs::{BaseReader, FileMetadata, MergedKind, RetainedError, VfsError, VirtualFs};

/// Why an [`open_at`]/[`close_fd`] emulation failed.
///
/// Returned to the supervisor wiring once tracee-memory/fd-table plumbing
/// lands; allowed until then.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenError {
    /// Path resolution failed (escape, missing entry, loop, bad dirfd…).
    Resolve(ResolveError),
    /// `O_CREAT | O_EXCL` on an entry that already resolves.
    Exists,
    /// The resolved target is a directory: the VFS holds no directory
    /// descriptors, so opens (including `O_CREAT` under a trailing slash)
    /// fail instead of handing out a directory fd.
    IsDirectory,
    /// A VFS-level traversal met a non-directory (the pre-open resolution
    /// usually reports this first as [`ResolveError::NotDirectory`]).
    NotDirectory,
    /// A VFS-level lookup missed (same note as above).
    NotFound,
    /// Write access to a base file whose mode denies it, or any other VFS
    /// permission refusal. The immutable base is never modified.
    Permission,
    /// `close` of a number the bounded table has not allocated.
    BadDescriptor,
    /// No free slot in the bounded descriptor table.
    TooManyOpen,
    /// No free slot for the writable copy in the overlay.
    NoSpace,
    /// The writable copy would exceed the overlay file capacity.
    TooLarge,
    /// Bad access mode, an unsupported flag (`O_APPEND` and the rest
    /// outside the [`open_at`] mask), or a malformed create name.
    Invalid,
    /// Corrupt image index or a backing-store failure.
    Io,
}

impl OpenError {
    /// Faithful negative errno for supervisor wiring. Permission refusals
    /// map to `-EACCES`, matching Linux `open(2)` on a mode-denied file;
    /// confinement escapes keep the lane's `-EPERM` via [`ResolveError`].
    /// Allowed until that wiring lands.
    #[allow(dead_code)]
    pub const fn errno(self) -> i64 {
        match self {
            OpenError::Resolve(error) => error.errno(),
            OpenError::Exists => -EEXIST,
            OpenError::IsDirectory => -EISDIR,
            OpenError::NotDirectory => -ENOTDIR,
            OpenError::NotFound => -ENOENT,
            OpenError::Permission => -EACCES,
            OpenError::BadDescriptor => -EBADF,
            OpenError::TooManyOpen => -EMFILE,
            OpenError::NoSpace => -ENOSPC,
            OpenError::TooLarge => -EFBIG,
            OpenError::Invalid => -EINVAL,
            OpenError::Io => -EIO,
        }
    }
}

/// [`DomainView`] over the merged domain view: live overlay entries win,
/// tombstones read as absent. The supervisor builds one per open from its
/// per-task VFS handle; see [`open_at`]. Allowed until that wiring lands.
#[allow(dead_code)]
pub struct VfsDomainView<'v, 'i, R, const FILES: usize, const FILE_SIZE: usize, const FDS: usize> {
    vfs: &'v mut VirtualFs<'i, R, FILES, FILE_SIZE, FDS>,
}

impl<'v, 'i, R, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>
    VfsDomainView<'v, 'i, R, FILES, FILE_SIZE, FDS>
{
    /// Borrow the VFS handle for one resolution pass.
    pub fn new(vfs: &'v mut VirtualFs<'i, R, FILES, FILE_SIZE, FDS>) -> Self {
        Self { vfs }
    }
}

impl<'v, 'i, R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize> DomainView
    for VfsDomainView<'v, 'i, R, FILES, FILE_SIZE, FDS>
{
    fn classify(&mut self, path: &[u8], link: &mut [u8; MAX_LINK]) -> Lookup {
        match self.vfs.classify_merged(path, link) {
            MergedKind::Missing => Lookup::Missing,
            MergedKind::File => Lookup::File,
            MergedKind::Directory => Lookup::Directory,
            MergedKind::Symlink(len) => Lookup::Symlink(len),
            MergedKind::TargetTooLong => Lookup::TargetTooLong,
        }
    }
}

/// Emulate `open(path, flags)` / `openat(dirfd, path, flags)` against the
/// domain: resolve through [`resolve_at`] over the merged view, map native
/// access flags onto the VFS, and allocate a bounded descriptor.
///
/// * Absolute paths ignore `dirfd`; relative paths resolve against `cwd`
///   when `dirfd == AT_FDCWD` and fail with `-EBADF` otherwise — VFS
///   descriptors record no paths and directories cannot be opened, so
///   there is nothing a dirfd could name yet (likewise `fchdir` stays
///   denied; both need supervisor fd-to-path wiring).
/// * The final symlink expands (`open`-style); intermediate symlinks
///   always do.
/// * `O_CREAT` on a missing final entry resolves the parent and creates in
///   the overlay with the VFS-default mode; `O_CREAT | O_EXCL` on an
///   existing entry fails with [`OpenError::Exists`]. A trailing slash on
///   a missing entry fails with [`OpenError::IsDirectory`].
/// * Opening a directory fails with [`OpenError::IsDirectory`]: the VFS
///   holds file descriptors only; directory enumeration stays with G06
///   until supervised `getdents` emulation lands.
/// * Read-only opens reference the immutable base image; any writable open
///   copies the file into the overlay first, so neither denied nor
///   permitted writes can mutate the base.
/// * Flags outside the access mode plus
///   `O_CREAT`/`O_EXCL`/`O_TRUNC`/`O_APPEND`/`O_CLOEXEC` fail with
///   [`OpenError::Invalid`]; `O_TRUNC` without write access is ignored,
///   matching Linux, and can only ever truncate the overlay copy.
///   `O_APPEND` positions every [`write_fd`] at end-of-file.
///
/// Returns the allocated domain descriptor number (VFS numbering from 3).
/// Pure `core` logic: the supervisor calls this once tracee path bytes and
/// per-task `cwd`/VFS handles are plumbed through. Allowed until then.
#[allow(dead_code)]
pub fn open_at<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    dirfd: i64,
    path: &[u8],
    flags: u32,
) -> Result<i32, OpenError> {
    if path.is_empty() || path.contains(&0) {
        return Err(OpenError::Resolve(ResolveError::Malformed));
    }
    let accmode = flags & O_ACCMODE;
    if accmode != O_RDONLY && accmode != O_WRONLY && accmode != O_RDWR {
        return Err(OpenError::Invalid);
    }
    if flags & !(O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND | O_CLOEXEC) != 0 {
        return Err(OpenError::Invalid);
    }
    let vfs_flags = open_vfs_flags(accmode, flags);
    let mut canonical = [0u8; MAX_CWD];
    match resolve_at(
        cwd.path(),
        dirfd,
        path,
        &mut VfsDomainView::new(vfs),
        &mut canonical,
    ) {
        Ok((len, kind)) => {
            if kind == ResolvedKind::Directory {
                return Err(OpenError::IsDirectory);
            }
            if flags & O_CREAT != 0 && flags & O_EXCL != 0 {
                return Err(OpenError::Exists);
            }
            vfs.open(&canonical[..len], vfs_flags).map_err(map_vfs_error)
        }
        Err(ResolveError::NotFound) if flags & O_CREAT != 0 => {
            create_at(vfs, cwd, dirfd, path, vfs_flags)
        }
        Err(error) => Err(OpenError::Resolve(error)),
    }
}

/// Emulate `close(fd)` against the domain: release the descriptor number
/// previously allocated by [`open_at`]. Unknown numbers — including the
/// process stdio range below the VFS numbering base — fail with
/// [`OpenError::BadDescriptor`]. Allowed until supervisor wiring lands.
#[allow(dead_code)]
pub fn close_fd<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    fd: i32,
) -> Result<(), OpenError> {
    vfs.close(fd).map_err(|error| match error {
        VfsError::InvalidDescriptor => OpenError::BadDescriptor,
        _ => OpenError::Io,
    })
}

/// `O_CREAT` slow path for [`open_at`]: the full path missed, so resolve
/// the parent and create the final entry in the overlay via the VFS.
/// Reached only through [`open_at`]; allowed with it.
#[allow(dead_code)]
fn create_at<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    dirfd: i64,
    path: &[u8],
    vfs_flags: u32,
) -> Result<i32, OpenError> {
    // A trailing slash requires a directory; creating there is refused.
    if path.len() > 1 && path[path.len() - 1] == b'/' {
        return Err(OpenError::IsDirectory);
    }
    let dot: &[u8] = b".";
    let (parent, name) = match path.iter().rposition(|byte| *byte == b'/') {
        Some(0) => (&path[..1], &path[1..]),
        Some(index) => (&path[..index], &path[index + 1..]),
        None => (dot, path),
    };
    if name.is_empty() || name == b"." || name == b".." {
        return Err(OpenError::Invalid);
    }
    let mut parent_out = [0u8; MAX_CWD];
    let (parent_len, parent_kind) = resolve_at(
        cwd.path(),
        dirfd,
        parent,
        &mut VfsDomainView::new(vfs),
        &mut parent_out,
    )
    .map_err(OpenError::Resolve)?;
    if parent_kind != ResolvedKind::Directory {
        return Err(OpenError::Resolve(ResolveError::NotDirectory));
    }
    let mut canonical = [0u8; MAX_CWD];
    let mut len = append_all(&mut canonical, 0, &parent_out[..parent_len])
        .map_err(OpenError::Resolve)?;
    if len > 1 {
        len = append_all(&mut canonical, len, b"/").map_err(OpenError::Resolve)?;
    }
    len = append_all(&mut canonical, len, name).map_err(OpenError::Resolve)?;
    vfs.open(&canonical[..len], vfs_flags).map_err(map_vfs_error)
}

/// Map native access/creation flags onto `ginux-vfs` open flags. The caller
/// ([`open_at`]) already validated the mask; `O_EXCL` needs no VFS bit
/// because existence is decided during resolution. Allowed with [`open_at`].
#[allow(dead_code)]
fn open_vfs_flags(accmode: u32, flags: u32) -> u32 {
    let mut vfs_flags = 0u32;
    if accmode != O_WRONLY {
        vfs_flags |= ginux_vfs::O_READ;
    }
    if accmode != O_RDONLY {
        vfs_flags |= ginux_vfs::O_WRITE;
    }
    if flags & O_CREAT != 0 {
        vfs_flags |= ginux_vfs::O_CREATE;
    }
    if flags & O_TRUNC != 0 {
        vfs_flags |= ginux_vfs::O_TRUNC;
    }
    if flags & O_APPEND != 0 {
        vfs_flags |= ginux_vfs::O_APPEND;
    }
    if flags & O_CLOEXEC != 0 {
        vfs_flags |= ginux_vfs::O_CLOEXEC;
    }
    vfs_flags
}

/// Why a [`read_fd`]/[`write_fd`]/[`lseek_fd`] emulation failed.
/// Returned to the supervisor wiring once tracee-memory/fd-table plumbing
/// lands; allowed until then.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoError {
    /// Unknown or closed descriptor number. Also covers reads on a
    /// write-only descriptor and writes on a read-only one: the VFS
    /// reports those direction violations as permission refusals, while
    /// Linux reports `-EBADF`.
    BadDescriptor,
    /// The descriptor names a directory (unreachable through [`open_at`],
    /// which refuses directories, but mapped faithfully regardless).
    IsDirectory,
    /// A write that could store nothing past overlay capacity.
    TooLarge,
    /// No free overlay slot for the writable copy.
    NoSpace,
    /// Unknown `lseek` base or a resulting negative offset.
    Invalid,
    /// Corrupt image index, a backing-store failure, or a lookup that a
    /// live descriptor should have pinned at open.
    Io,
}

impl IoError {
    /// Faithful negative errno for supervisor wiring. Allowed until that
    /// wiring lands.
    #[allow(dead_code)]
    pub const fn errno(self) -> i64 {
        match self {
            IoError::BadDescriptor => -EBADF,
            IoError::IsDirectory => -EISDIR,
            IoError::TooLarge => -EFBIG,
            IoError::NoSpace => -ENOSPC,
            IoError::Invalid => -EINVAL,
            IoError::Io => -EIO,
        }
    }
}

/// Map a VFS failure onto the faithful [`OpenError`]. `NotFound` and
/// `NotDirectory` only escape the pre-open [`resolve_at`] pass on bugs,
/// never on well-formed input. Allowed with [`open_at`].
#[allow(dead_code)]
fn map_vfs_error(error: VfsError) -> OpenError {
    match error {
        VfsError::NotFound => OpenError::NotFound,
        VfsError::NotDirectory => OpenError::NotDirectory,
        VfsError::IsDirectory => OpenError::IsDirectory,
        VfsError::PermissionDenied => OpenError::Permission,
        VfsError::InvalidDescriptor => OpenError::BadDescriptor,
        VfsError::DescriptorLimit => OpenError::TooManyOpen,
        VfsError::OverlayLimit => OpenError::NoSpace,
        VfsError::FileTooLarge => OpenError::TooLarge,
        VfsError::AlreadyExists => OpenError::Exists,
        VfsError::InvalidPath => OpenError::Invalid,
        VfsError::InvalidOffset => OpenError::Invalid,
        VfsError::SymlinkLoop => OpenError::Resolve(ResolveError::SymlinkLoop),
        VfsError::InvalidIndex | VfsError::Io => OpenError::Io,
    }
}

// ─── G07a: file data I/O and offsets ─────────────────────────────────────

/// Emulate `read(fd, buf, count)` against the domain: copy up to
/// `out.len()` bytes at the descriptor offset into `out`, advancing the
/// offset by the count returned. Reads at or past end-of-file return a
/// short count (`Ok(0)` when nothing remains), matching Linux. Pure `core`
/// logic: the supervisor calls this once tracee data buffers and the
/// per-task fd table are plumbed through. Allowed until then.
#[allow(dead_code)]
pub fn read_fd<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    fd: i32,
    out: &mut [u8],
) -> Result<usize, IoError> {
    vfs.read(fd, out).map_err(map_io_error)
}

/// Emulate `write(fd, buf, count)` against the domain: store `input` at
/// the descriptor offset (`O_APPEND` descriptors write at end-of-file),
/// advancing the offset by the count returned. Oversized writes store what
/// fits and return that short count; only a write that stores nothing
/// fails. Pure `core` logic, wired like [`read_fd`]. Allowed until then.
#[allow(dead_code)]
pub fn write_fd<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    fd: i32,
    input: &[u8],
) -> Result<usize, IoError> {
    vfs.write(fd, input).map_err(map_io_error)
}

/// Emulate `lseek(fd, offset, whence)` against the domain, returning the
/// new offset. `whence` is one of [`SEEK_SET`]/[`SEEK_CUR`]/[`SEEK_END`];
/// anything else fails with [`IoError::Invalid`], as does a negative
/// result. Offsets past end-of-file are allowed: reads there return
/// short and later writes zero-fill the gap. Pure `core` logic, wired
/// like [`read_fd`]. Allowed until then.
#[allow(dead_code)]
pub fn lseek_fd<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    fd: i32,
    offset: i64,
    whence: u32,
) -> Result<u64, IoError> {
    let base = match whence {
        SEEK_SET => ginux_vfs::SEEK_SET,
        SEEK_CUR => ginux_vfs::SEEK_CUR,
        SEEK_END => ginux_vfs::SEEK_END,
        _ => return Err(IoError::Invalid),
    };
    vfs.seek(fd, offset, base).map_err(map_io_error)
}

/// Map a VFS failure onto the faithful [`IoError`]. Direction violations
/// surface as [`VfsError::PermissionDenied`] but read as `-EBADF`, matching
/// Linux `read` on a write-only descriptor (and the `write` converse).
/// `NotFound`/`NotDirectory`/`AlreadyExists`/`SymlinkLoop` cannot escape a
/// live descriptor — the open path pinned the object — so they read as
/// backing-store failures. Allowed with the G07a emulations.
#[allow(dead_code)]
fn map_io_error(error: VfsError) -> IoError {
    match error {
        VfsError::InvalidDescriptor | VfsError::PermissionDenied => IoError::BadDescriptor,
        VfsError::IsDirectory => IoError::IsDirectory,
        VfsError::FileTooLarge => IoError::TooLarge,
        VfsError::OverlayLimit | VfsError::DescriptorLimit => IoError::NoSpace,
        VfsError::InvalidPath | VfsError::InvalidOffset => IoError::Invalid,
        VfsError::NotFound
        | VfsError::NotDirectory
        | VfsError::AlreadyExists
        | VfsError::SymlinkLoop
        | VfsError::InvalidIndex
        | VfsError::Io => IoError::Io,
    }
}

// ─── G07b: file metadata queries ────────────────────────────────────────

/// Domain file metadata for one stat-family query.
///
/// Built from the merged domain view only: `mode` already carries the
/// `S_IFMT` file-type bits, `size` counts domain bytes (link-target bytes
/// for a final symlink), and `ino` is a deterministic path hash — never
/// host metadata. Times stay zero at write-back: index records carry no
/// timestamps, and a zero clock leaks nothing. Returned to the supervisor
/// wiring once tracee-memory write-back lands; allowed until then.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stat {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub ino: u64,
    pub nlink: u64,
}

/// Why a [`stat_at`]/[`lstat_at`]/[`fstat_fd`]/[`statat`] emulation failed.
/// Returned to the supervisor wiring once tracee-memory write-back lands;
/// allowed until then.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatError {
    /// Path resolution failed (escape, missing entry, loop, bad dirfd…).
    Resolve(ResolveError),
    /// `fstat` of a number the bounded table has not allocated. Direct
    /// calls also fail closed on the stdio range: live stdio queries fall
    /// through at the [`claim`] entry, never here.
    BadDescriptor,
    /// A `newfstatat` flag outside `0` / [`AT_SYMLINK_NOFOLLOW`]
    /// (`AT_EMPTY_PATH`, `AT_NO_AUTOMOUNT`, garbage): explicit failure
    /// until an observed follow-up implements the variant.
    Invalid,
    /// Backing-store inconsistency, or a directory slot where only a file
    /// slot can stand (unreachable through [`open_at`], which refuses
    /// directories). A metadata miss after a successful resolution of the
    /// same view falls here: nothing mutates between the two reads, so a
    /// miss is inconsistency, never a fresh lookup failure.
    Io,
}

impl StatError {
    /// Faithful negative errno for supervisor wiring. Allowed until that
    /// wiring lands.
    #[allow(dead_code)]
    pub const fn errno(self) -> i64 {
        match self {
            StatError::Resolve(error) => error.errno(),
            StatError::BadDescriptor => -EBADF,
            StatError::Invalid => -EINVAL,
            StatError::Io => -EIO,
        }
    }
}

/// Emulate `stat(path)` against the domain: resolve with final-symlink
/// following and report the merged-view metadata. Pure `core` logic: the
/// supervisor calls this once tracee path bytes and per-task `cwd`/VFS
/// handles are plumbed through. Allowed until then.
#[allow(dead_code)]
pub fn stat_at<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    dirfd: i64,
    path: &[u8],
) -> Result<Stat, StatError> {
    statat(vfs, cwd, dirfd, path, 0)
}

/// Emulate `lstat(path)` against the domain: like [`stat_at`] but a final
/// symlink reports itself instead of its target. Pure `core` logic, wired
/// like [`stat_at`]. Allowed until then.
#[allow(dead_code)]
pub fn lstat_at<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    dirfd: i64,
    path: &[u8],
) -> Result<Stat, StatError> {
    statat(vfs, cwd, dirfd, path, AT_SYMLINK_NOFOLLOW)
}

/// Emulate `fstat(fd)` against the domain: report the object the open path
/// pinned, at its live size. Pure `core` logic, wired like [`stat_at`].
/// Allowed until then.
#[allow(dead_code)]
pub fn fstat_fd<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    fd: i32,
) -> Result<Stat, StatError> {
    Ok(stat_from_meta(&vfs.fstat(fd).map_err(map_stat_error)?))
}

/// Emulate `newfstatat(dirfd, path, flags)` (`fstatat`) against the domain:
/// `flags == 0` stats like [`stat_at`], `flags ==
/// AT_SYMLINK_NOFOLLOW` stats like [`lstat_at`]; any other flag fails
/// explicitly with [`StatError::Invalid`]. A trailing slash addresses a
/// directory: an lstat-style final link re-follows (Linux does), then a
/// non-directory final fails with `ENOTDIR`. Pure `core` logic, wired like
/// [`stat_at`]. Allowed until then.
#[allow(dead_code)]
pub fn statat<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    dirfd: i64,
    path: &[u8],
    flags: u32,
) -> Result<Stat, StatError> {
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
        return Err(StatError::Invalid);
    }
    if path.is_empty() || path.contains(&0) {
        return Err(StatError::Resolve(ResolveError::Malformed));
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let trailing_slash = path.len() > 1 && path[path.len() - 1] == b'/';
    let mut canonical = [0u8; MAX_CWD];
    let (mut len, mut kind) = resolve_at_full(
        cwd.path(),
        dirfd,
        path,
        follow,
        &mut VfsDomainView::new(vfs),
        &mut canonical,
    )
    .map_err(StatError::Resolve)?;
    if trailing_slash && kind != ResolvedKind::Directory {
        if kind == ResolvedKind::Symlink && !follow {
            (len, kind) = resolve_at_full(
                cwd.path(),
                dirfd,
                path,
                true,
                &mut VfsDomainView::new(vfs),
                &mut canonical,
            )
            .map_err(StatError::Resolve)?;
        }
        if kind != ResolvedKind::Directory {
            return Err(StatError::Resolve(ResolveError::NotDirectory));
        }
    }
    Ok(stat_from_meta(
        &vfs.metadata_merged(&canonical[..len])
            .map_err(map_stat_error)?,
    ))
}

/// Assemble a [`Stat`] from merged-view metadata: the `S_IFMT` file-type
/// bits join the stored permission bits, directories link twice (`.`),
/// everything else once. Reached only through the stat emulations above;
/// allowed with them.
#[allow(dead_code)]
fn stat_from_meta(meta: &FileMetadata) -> Stat {
    let file_type = match meta.kind {
        ginux_vfs::NodeKind::File => S_IFREG,
        ginux_vfs::NodeKind::Directory => S_IFDIR,
        ginux_vfs::NodeKind::Symlink => S_IFLNK,
    };
    Stat {
        mode: file_type | (meta.mode & 0o7777),
        uid: meta.uid,
        gid: meta.gid,
        size: meta.size,
        ino: meta.ino,
        nlink: if meta.kind == ginux_vfs::NodeKind::Directory {
            2
        } else {
            1
        },
    }
}

/// Map a VFS failure onto the faithful [`StatError`]. Only
/// [`VfsError::InvalidDescriptor`] (unknown `fstat` number) is a caller
/// error; everything else off the metadata path is a backing-store
/// inconsistency (see [`StatError::Io`]). Allowed with the stat
/// emulations.
#[allow(dead_code)]
fn map_stat_error(error: VfsError) -> StatError {
    match error {
        VfsError::InvalidDescriptor => StatError::BadDescriptor,
        _ => StatError::Io,
    }
}

/// Serialize [`Stat`] into the Linux x86-64 `struct stat` layout for the
/// supervisor's `fstat`/`newfstatat` tracee-memory write-back. Offsets
/// verified against raw `fstat(5)` bytes on the build host: dev@0 ino@8
/// nlink@16 mode@24 uid@28 gid@32 rdev@40 size@48 blksize@56 blocks@64,
/// then time pairs (atime@72/80 mtime@88/96 ctime@104/112) plus 24
/// reserved zero bytes. `st_blocks` counts 512-byte units; times stay
/// zero (the index carries no timestamps). Pure `core`, wired with the
/// supervisor entries; allowed until then.
#[allow(dead_code)]
pub fn stat_write(stat: &Stat, out: &mut [u8; STAT_SIZE]) {
    out.fill(0);
    write_u64_le(out, 0, STAT_DEV);
    write_u64_le(out, 8, stat.ino);
    write_u64_le(out, 16, stat.nlink);
    write_u32_le(out, 24, stat.mode);
    write_u32_le(out, 28, stat.uid);
    write_u32_le(out, 32, stat.gid);
    write_u64_le(out, 48, stat.size);
    write_u64_le(out, 56, STAT_BLKSIZE);
    write_u64_le(out, 64, stat.size.saturating_add(511) / 512);
}

/// Serialize [`Stat`] into the legacy `struct __old_kernel_stat` layout
/// for the supervisor's `stat`/`lstat` write-back. Offsets verified
/// against raw `syscall(4)` bytes on the build host: dev@0 ino@8 nlink@16
/// mode@24 uid@28 gid@32 pad@36 rdev@40 size@48, then seconds-only
/// atime@56 mtime@64 ctime@72 (zeroed, as above). Pure `core`, wired with
/// the supervisor entries; allowed until then.
#[allow(dead_code)]
pub fn old_stat_write(stat: &Stat, out: &mut [u8; OLD_STAT_SIZE]) {
    out.fill(0);
    write_u64_le(out, 0, STAT_DEV);
    write_u64_le(out, 8, stat.ino);
    write_u64_le(out, 16, stat.nlink);
    write_u32_le(out, 24, stat.mode);
    write_u32_le(out, 28, stat.uid);
    write_u32_le(out, 32, stat.gid);
    write_u64_le(out, 48, stat.size);
}

/// Little-endian stores for the stat serializers above. `off` is a
/// compile-time-known layout offset; the caller guarantees room.
/// Allowed with the serializers.
#[allow(dead_code)]
fn write_u32_le(out: &mut [u8], off: usize, value: u32) {
    out[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

/// Little-endian stores for the stat serializers above. `off` is a
/// compile-time-known layout offset; the caller guarantees room.
/// Allowed with the serializers.
#[allow(dead_code)]
fn write_u64_le(out: &mut [u8], off: usize, value: u64) {
    out[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

// ─── G08: rename and removal ────────────────────────────────────────────

/// Why a [`rename_at`] emulation failed.
///
/// Returned to the supervisor wiring once tracee-memory/fd-table plumbing
/// lands; allowed until then.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameError {
    /// Path resolution failed (escape, missing entry, loop, bad dirfd…).
    Resolve(ResolveError),
    /// The target parent is not a directory, or a trailing slash addressed
    /// a non-directory.
    NotDirectory,
    /// The target names an existing directory: only files and symlinks are
    /// replaced, never directories.
    IsDirectory,
    /// The source names a directory: directory moves need VFS directory
    /// support, an observed follow-up.
    Unsupported,
    /// Malformed target name (`.`/`..`/empty final component).
    Invalid,
    /// No free slot for the moved copy or its tombstones in the overlay.
    NoSpace,
    /// A moved base file is larger than the overlay file capacity.
    TooLarge,
    /// Corrupt image index or a backing-store failure.
    Io,
}

impl RenameError {
    /// Faithful negative errno for supervisor wiring. Unsupported directory
    /// moves report `-ENOSYS`: renaming a directory is valid Linux, so the
    /// refusal names the missing emulation, not the request. Allowed until
    /// that wiring lands.
    #[allow(dead_code)]
    pub const fn errno(self) -> i64 {
        match self {
            RenameError::Resolve(error) => error.errno(),
            RenameError::NotDirectory => -ENOTDIR,
            RenameError::IsDirectory => -EISDIR,
            RenameError::Unsupported => -ENOSYS,
            RenameError::Invalid => -EINVAL,
            RenameError::NoSpace => -ENOSPC,
            RenameError::TooLarge => -EFBIG,
            RenameError::Io => -EIO,
        }
    }
}

// ─── G11: retained writable backing ──────────────────────────────────────
//
// The retained image carries the overlay across a domain stop/reopen while
// the VFS open/read/write/seek/close shape stays unchanged. Staging and
// recovery live on `VirtualFs` (`checkpoint_retained`/`restore_retained`);
// these mappers are the only backend-hook addition, so exhaustion and
// corrupt-image failures reach the supervisor wiring with faithful errnos.
// Durable publish of the staged bytes is the G12 flush seam, not this lane.

/// Map a retained-backing failure onto the faithful [`OpenError`]: the
/// open/restore path reports exhaustion as no-space/too-large and a foreign
/// or corrupt image as a backing-store failure. Allowed until supervisor
/// wiring calls it.
#[allow(dead_code)]
fn map_retained_error(error: RetainedError) -> OpenError {
    match error {
        RetainedError::TooManyFiles | RetainedError::NoSpace => OpenError::NoSpace,
        RetainedError::TooLarge => OpenError::TooLarge,
        RetainedError::InvalidPath => OpenError::Invalid,
        RetainedError::InvalidRecord | RetainedError::WrongInstance | RetainedError::Io => {
            OpenError::Io
        }
    }
}

/// Why an [`unlink_at`] emulation failed.
///
/// Returned to the supervisor wiring once tracee-memory/fd-table plumbing
/// lands; allowed until then.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoveError {
    /// Path resolution failed (escape, missing entry, loop, bad dirfd…).
    Resolve(ResolveError),
    /// A trailing slash addressed a non-directory, or `AT_REMOVEDIR`
    /// addressed one.
    NotDirectory,
    /// The path names a directory: removing one needs `rmdir` support, an
    /// observed follow-up.
    IsDirectory,
    /// `AT_REMOVEDIR` on a directory: explicit until VFS `rmdir` lands.
    Unsupported,
    /// An `unlinkat` flag outside `AT_REMOVEDIR`.
    Invalid,
    /// No free slot for the tombstone in the overlay.
    NoSpace,
    /// Corrupt image index or a backing-store failure.
    Io,
}

impl RemoveError {
    /// Faithful negative errno for supervisor wiring. Allowed until that
    /// wiring lands.
    #[allow(dead_code)]
    pub const fn errno(self) -> i64 {
        match self {
            RemoveError::Resolve(error) => error.errno(),
            RemoveError::NotDirectory => -ENOTDIR,
            RemoveError::IsDirectory => -EISDIR,
            RemoveError::Unsupported => -ENOSYS,
            RemoveError::Invalid => -EINVAL,
            RemoveError::NoSpace => -ENOSPC,
            RemoveError::Io => -EIO,
        }
    }
}

/// Emulate `rename(old_path, new_path)` /
/// `renameat(old_dirfd, old_path, new_dirfd, new_path)` against the domain:
/// resolve both sides through [`resolve_at_full`] over the merged view and
/// move the entry with [`VirtualFs::rename`].
///
/// * Absolute paths ignore their dirfd; relative paths resolve against
///   `cwd` when their dirfd is `AT_FDCWD` and fail with `-EBADF` otherwise.
/// * The source resolves without following a final symlink, so renaming a
///   link moves the link itself; a source directory fails explicitly with
///   [`RenameError::Unsupported`]. A trailing slash on a non-directory
///   source fails with `-ENOTDIR`, matching Linux.
/// * The target joins its resolved parent with the final name; an existing
///   file or symlink at the target is replaced atomically, while an
///   existing directory fails with [`RenameError::IsDirectory`]. A
///   trailing slash demands an existing directory: a missing target fails
///   with `-ENOENT`, a present non-directory with `-ENOTDIR`.
/// * Denied mutations change nothing: confinement failures return before
///   the VFS call, and the VFS move itself is atomic.
///
/// Pure `core` logic: the supervisor calls this once tracee path bytes and
/// per-task `cwd`/VFS handles are plumbed through. Allowed until then.
#[allow(dead_code)]
pub fn rename_at<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    old_dirfd: i64,
    old_path: &[u8],
    new_dirfd: i64,
    new_path: &[u8],
) -> Result<(), RenameError> {
    if old_path.is_empty()
        || old_path.contains(&0)
        || new_path.is_empty()
        || new_path.contains(&0)
    {
        return Err(RenameError::Resolve(ResolveError::Malformed));
    }
    let old_trailing = old_path.len() > 1 && old_path[old_path.len() - 1] == b'/';
    let mut old_canon = [0u8; MAX_CWD];
    let (old_len, old_kind) = resolve_at_full(
        cwd.path(),
        old_dirfd,
        old_path,
        false,
        &mut VfsDomainView::new(vfs),
        &mut old_canon,
    )
    .map_err(RenameError::Resolve)?;
    if old_trailing && old_kind != ResolvedKind::Directory {
        return Err(RenameError::Resolve(ResolveError::NotDirectory));
    }
    if old_kind == ResolvedKind::Directory {
        return Err(RenameError::Unsupported);
    }
    let new_trailing = new_path.len() > 1 && new_path[new_path.len() - 1] == b'/';
    let mut new_abs = [0u8; MAX_CWD];
    let new_len = if new_trailing {
        let (len, kind) = resolve_at_full(
            cwd.path(),
            new_dirfd,
            new_path,
            true,
            &mut VfsDomainView::new(vfs),
            &mut new_abs,
        )
        .map_err(RenameError::Resolve)?;
        if kind != ResolvedKind::Directory {
            return Err(RenameError::Resolve(ResolveError::NotDirectory));
        }
        len
    } else {
        build_rename_target(vfs, cwd, new_dirfd, new_path, &mut new_abs)?
    };
    vfs.rename(&old_canon[..old_len], &new_abs[..new_len])
        .map_err(map_rename_error)
}

/// Emulate `unlink(path)` / `unlinkat(dirfd, path, flags)` against the
/// domain: resolve through [`resolve_at_full`] without following a final
/// symlink, then remove with [`VirtualFs::unlink`].
///
/// * `flags == 0` unlinks a file or symlink, including a dangling link or
///   one pointing at a directory: the link itself goes, the target stays.
/// * `flags == AT_REMOVEDIR` on a directory fails explicitly with
///   [`RemoveError::Unsupported`]; on anything else with `-ENOTDIR`. Any
///   other flag fails with [`RemoveError::Invalid`].
/// * Unlinking a directory without the flag fails with
///   [`RemoveError::IsDirectory`], and a trailing slash on a non-directory
///   with `-ENOTDIR`, both matching Linux.
///
/// Pure `core` logic, wired like [`rename_at`]. Allowed until then.
#[allow(dead_code)]
pub fn unlink_at<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    dirfd: i64,
    path: &[u8],
    flags: u32,
) -> Result<(), RemoveError> {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(RemoveError::Invalid);
    }
    if path.is_empty() || path.contains(&0) {
        return Err(RemoveError::Resolve(ResolveError::Malformed));
    }
    let trailing = path.len() > 1 && path[path.len() - 1] == b'/';
    let mut canon = [0u8; MAX_CWD];
    let (len, kind) = resolve_at_full(
        cwd.path(),
        dirfd,
        path,
        false,
        &mut VfsDomainView::new(vfs),
        &mut canon,
    )
    .map_err(RemoveError::Resolve)?;
    if trailing && kind != ResolvedKind::Directory {
        return Err(RemoveError::Resolve(ResolveError::NotDirectory));
    }
    if flags & AT_REMOVEDIR != 0 {
        if kind == ResolvedKind::Directory {
            return Err(RemoveError::Unsupported);
        }
        return Err(RemoveError::Resolve(ResolveError::NotDirectory));
    }
    if kind == ResolvedKind::Directory {
        return Err(RemoveError::IsDirectory);
    }
    vfs.unlink(&canon[..len]).map_err(map_remove_error)
}

/// Join the resolved target parent with the final name for [`rename_at`]:
/// the stored target path is canonical, never hiding an unexpanded link in
/// the parent. Mirrors the [`create_at`] slow path: the parent resolves
/// with following (it must be a live directory) while the name itself stays
/// uninterpreted. Reached only through [`rename_at`]; allowed with it.
#[allow(dead_code)]
fn build_rename_target<
    R: BaseReader,
    const FILES: usize,
    const FILE_SIZE: usize,
    const FDS: usize,
>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    dirfd: i64,
    path: &[u8],
    out: &mut [u8; MAX_CWD],
) -> Result<usize, RenameError> {
    let dot: &[u8] = b".";
    let (parent, name) = match path.iter().rposition(|byte| *byte == b'/') {
        Some(0) => (&path[..1], &path[1..]),
        Some(index) => (&path[..index], &path[index + 1..]),
        None => (dot, path),
    };
    if name.is_empty() || name == b"." || name == b".." {
        return Err(RenameError::Invalid);
    }
    let mut parent_out = [0u8; MAX_CWD];
    let (parent_len, parent_kind) = resolve_at(
        cwd.path(),
        dirfd,
        parent,
        &mut VfsDomainView::new(vfs),
        &mut parent_out,
    )
    .map_err(RenameError::Resolve)?;
    if parent_kind != ResolvedKind::Directory {
        return Err(RenameError::Resolve(ResolveError::NotDirectory));
    }
    let mut len =
        append_all(out, 0, &parent_out[..parent_len]).map_err(RenameError::Resolve)?;
    if len > 1 {
        len = append_all(out, len, b"/").map_err(RenameError::Resolve)?;
    }
    len = append_all(out, len, name).map_err(RenameError::Resolve)?;
    Ok(len)
}

/// Map a VFS failure onto the faithful [`RenameError`]. `NotFound` after a
/// successful pre-resolution is unreachable through [`rename_at`] — the
/// view cannot change between the two reads — so it reports the missing
/// name rather than an inconsistency. Allowed with [`rename_at`].
#[allow(dead_code)]
fn map_rename_error(error: VfsError) -> RenameError {
    match error {
        VfsError::NotFound => RenameError::Resolve(ResolveError::NotFound),
        VfsError::NotDirectory => RenameError::NotDirectory,
        VfsError::IsDirectory => RenameError::IsDirectory,
        VfsError::SymlinkLoop => RenameError::Resolve(ResolveError::SymlinkLoop),
        VfsError::InvalidPath => RenameError::Invalid,
        VfsError::OverlayLimit => RenameError::NoSpace,
        VfsError::FileTooLarge => RenameError::TooLarge,
        VfsError::PermissionDenied
        | VfsError::InvalidDescriptor
        | VfsError::DescriptorLimit
        | VfsError::AlreadyExists
        | VfsError::InvalidOffset
        | VfsError::InvalidIndex
        | VfsError::Io => RenameError::Io,
    }
}

/// Map a VFS failure onto the faithful [`RemoveError`]. Only the name and
/// directory errors escape the pre-resolved [`unlink_at`] path; the rest is
/// backing-store inconsistency. Allowed with [`unlink_at`].
#[allow(dead_code)]
fn map_remove_error(error: VfsError) -> RemoveError {
    match error {
        VfsError::NotFound => RemoveError::Resolve(ResolveError::NotFound),
        VfsError::NotDirectory => RemoveError::NotDirectory,
        VfsError::IsDirectory => RemoveError::IsDirectory,
        VfsError::SymlinkLoop => RemoveError::Resolve(ResolveError::SymlinkLoop),
        VfsError::InvalidPath => RemoveError::Invalid,
        VfsError::OverlayLimit => RemoveError::NoSpace,
        VfsError::PermissionDenied
        | VfsError::InvalidDescriptor
        | VfsError::DescriptorLimit
        | VfsError::FileTooLarge
        | VfsError::AlreadyExists
        | VfsError::InvalidOffset
        | VfsError::InvalidIndex
        | VfsError::Io => RemoveError::Io,
    }
}

// ─── G08a: installation permissions and link operations ───────────────────

/// Why a [`chmod_at`]/[`fchmod_at`]/[`fchmod_fd`] emulation failed.
///
/// Returned to the supervisor wiring once tracee-memory/fd-table plumbing
/// lands; allowed until then.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermError {
    /// Path resolution failed (escape, missing entry, loop, bad dirfd…).
    Resolve(ResolveError),
    /// A trailing slash addressed a non-directory.
    NotDirectory,
    /// A setuid/setgid/sticky bit request: the domain keeps root ownership
    /// with plain permission bits, so anything outside `0o777` is refused.
    NotPermitted,
    /// `fchmod` of a number the bounded table has not allocated.
    BadDescriptor,
    /// A `fchmodat` flag outside `0`.
    Invalid,
    /// No free slot for the materialized overlay copy.
    NoSpace,
    /// A materialized base file is larger than the overlay file capacity.
    TooLarge,
    /// Corrupt image index or a backing-store failure.
    Io,
}

impl PermError {
    /// Faithful negative errno for supervisor wiring. Bit-policy refusals
    /// report `-EPERM`, matching the lane's denial convention. Allowed
    /// until that wiring lands.
    #[allow(dead_code)]
    pub const fn errno(self) -> i64 {
        match self {
            PermError::Resolve(error) => error.errno(),
            PermError::NotDirectory => -ENOTDIR,
            PermError::NotPermitted => -EPERM,
            PermError::BadDescriptor => -EBADF,
            PermError::Invalid => -EINVAL,
            PermError::NoSpace => -ENOSPC,
            PermError::TooLarge => -EFBIG,
            PermError::Io => -EIO,
        }
    }
}

/// Why a [`link_at`] emulation failed.
///
/// Returned to the supervisor wiring once tracee-memory/fd-table plumbing
/// lands; allowed until then.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkError {
    /// Path resolution failed (escape, missing entry, loop, bad dirfd…).
    Resolve(ResolveError),
    /// The target parent is not a directory, or a trailing slash addressed
    /// a non-directory.
    NotDirectory,
    /// The source is a directory: Linux refuses directory hard links with
    /// `EPERM`, and this lane has no directory-link support to offer.
    NotPermitted,
    /// The target name already resolves to a live entry: links never
    /// replace, whatever the existing kind.
    Exists,
    /// Malformed target name (`.`/`..`/empty final component) or a `linkat`
    /// flag outside `0` (`AT_SYMLINK_FOLLOW`/`AT_EMPTY_PATH` stay explicitly
    /// unsupported: following is the only behavior, empty paths never link).
    Invalid,
    /// No free slot for the linked copy in the overlay.
    NoSpace,
    /// A linked base file is larger than the overlay file capacity.
    TooLarge,
    /// Corrupt image index or a backing-store failure.
    Io,
}

impl LinkError {
    /// Faithful negative errno for supervisor wiring. Allowed until that
    /// wiring lands.
    #[allow(dead_code)]
    pub const fn errno(self) -> i64 {
        match self {
            LinkError::Resolve(error) => error.errno(),
            LinkError::NotDirectory => -ENOTDIR,
            LinkError::NotPermitted => -EPERM,
            LinkError::Exists => -EEXIST,
            LinkError::Invalid => -EINVAL,
            LinkError::NoSpace => -ENOSPC,
            LinkError::TooLarge => -EFBIG,
            LinkError::Io => -EIO,
        }
    }
}

/// Why a [`symlink_at`] emulation failed.
///
/// Returned to the supervisor wiring once tracee-memory/fd-table plumbing
/// lands; allowed until then.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymlinkError {
    /// Path resolution failed (escape, missing entry, loop, bad dirfd…),
    /// or the link target is empty, NUL-bearing, or overlong.
    Resolve(ResolveError),
    /// The new parent is not a directory, or a trailing slash addressed a
    /// non-directory.
    NotDirectory,
    /// The new name already resolves to a live entry: links never replace.
    Exists,
    /// Malformed new name (`.`/`..`/empty final component).
    Invalid,
    /// No free slot for the planted link in the overlay.
    NoSpace,
    /// The link target is larger than the overlay file capacity.
    TooLarge,
    /// Corrupt image index or a backing-store failure.
    Io,
}

impl SymlinkError {
    /// Faithful negative errno for supervisor wiring. Allowed until that
    /// wiring lands.
    #[allow(dead_code)]
    pub const fn errno(self) -> i64 {
        match self {
            SymlinkError::Resolve(error) => error.errno(),
            SymlinkError::NotDirectory => -ENOTDIR,
            SymlinkError::Exists => -EEXIST,
            SymlinkError::Invalid => -EINVAL,
            SymlinkError::NoSpace => -ENOSPC,
            SymlinkError::TooLarge => -EFBIG,
            SymlinkError::Io => -EIO,
        }
    }
}

/// Why a [`readlink_at`] emulation failed.
///
/// Returned to the supervisor wiring once tracee-memory plumbing lands;
/// allowed until then.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadlinkError {
    /// Path resolution failed (escape, missing entry, loop, bad dirfd…).
    Resolve(ResolveError),
    /// A trailing slash addressed a non-directory.
    NotDirectory,
    /// The final entry is not a symlink (Linux `EINVAL`).
    Invalid,
    /// Corrupt image index or a backing-store failure.
    Io,
}

impl ReadlinkError {
    /// Faithful negative errno for supervisor wiring. Allowed until that
    /// wiring lands.
    #[allow(dead_code)]
    pub const fn errno(self) -> i64 {
        match self {
            ReadlinkError::Resolve(error) => error.errno(),
            ReadlinkError::NotDirectory => -ENOTDIR,
            ReadlinkError::Invalid => -EINVAL,
            ReadlinkError::Io => -EIO,
        }
    }
}

/// Emulate `chmod(path, mode)` against the domain: `chmod` is `fchmodat`
/// with `AT_FDCWD` and flags `0`. Pure `core` logic, wired like
/// [`rename_at`]. Allowed until then.
#[allow(dead_code)]
pub fn chmod_at<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    dirfd: i64,
    path: &[u8],
    mode: u32,
) -> Result<(), PermError> {
    fchmod_at(vfs, cwd, dirfd, path, mode, 0)
}

/// Emulate `fchmodat(dirfd, path, mode, flags)` against the domain:
/// resolve with final-symlink following and set plain permission bits with
/// [`VirtualFs::chmod`]. Only flags `0` is emulated; anything else
/// (`AT_SYMLINK_NOFOLLOW` included) fails explicitly with
/// [`PermError::Invalid`], a bounded G08a cut. A trailing slash addresses
/// a directory: a present non-directory fails with `-ENOTDIR`, matching
/// Linux. Pure `core` logic, wired like [`rename_at`]. Allowed until then.
#[allow(dead_code)]
pub fn fchmod_at<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    dirfd: i64,
    path: &[u8],
    mode: u32,
    flags: u32,
) -> Result<(), PermError> {
    if flags != 0 {
        return Err(PermError::Invalid);
    }
    if path.is_empty() || path.contains(&0) {
        return Err(PermError::Resolve(ResolveError::Malformed));
    }
    let trailing = path.len() > 1 && path[path.len() - 1] == b'/';
    let mut canonical = [0u8; MAX_CWD];
    let (len, kind) = resolve_at(
        cwd.path(),
        dirfd,
        path,
        &mut VfsDomainView::new(vfs),
        &mut canonical,
    )
    .map_err(PermError::Resolve)?;
    if trailing && kind != ResolvedKind::Directory {
        return Err(PermError::NotDirectory);
    }
    vfs.chmod(&canonical[..len], mode).map_err(map_perm_error)
}

/// Emulate `fchmod(fd, mode)` against the domain: set plain permission
/// bits on the object the open path pinned. Unknown numbers — including
/// the process stdio range — fail with [`PermError::BadDescriptor`].
/// Pure `core` logic, wired like [`rename_at`]. Allowed until then.
#[allow(dead_code)]
pub fn fchmod_fd<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    fd: i32,
    mode: u32,
) -> Result<(), PermError> {
    vfs.chmod_fd(fd, mode).map_err(map_perm_error)
}

/// Emulate `link(old_path, new_path)` /
/// `linkat(old_dirfd, old_path, new_dirfd, new_path, flags)` against the
/// domain: resolve the source with final-symlink following (a link names
/// the target file, never the link) and plant the target name with
/// [`VirtualFs::link`].
///
/// * Only flags `0` is emulated; any `linkat` flag fails explicitly with
///   [`LinkError::Invalid`], a bounded G08a cut.
/// * A directory source fails with [`LinkError::NotPermitted`], matching
///   Linux `EPERM`; the target side never replaces (see [`LinkError::Exists`]).
/// * A trailing slash on a non-directory source fails with `-ENOTDIR`,
///   matching Linux; a trailing slash on the target side demands an
///   existing directory, which then blocks the link with `EEXIST`.
/// * Denied mutations change nothing: confinement failures return before
///   the VFS call, and the VFS link itself consumes at most one slot after
///   all fallible checks.
///
/// Pure `core` logic: the supervisor calls this once tracee path bytes and
/// per-task `cwd`/VFS handles are plumbed through. Allowed until then.
#[allow(dead_code)]
pub fn link_at<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    old_dirfd: i64,
    old_path: &[u8],
    new_dirfd: i64,
    new_path: &[u8],
    flags: u32,
) -> Result<(), LinkError> {
    if flags != 0 {
        return Err(LinkError::Invalid);
    }
    if old_path.is_empty()
        || old_path.contains(&0)
        || new_path.is_empty()
        || new_path.contains(&0)
    {
        return Err(LinkError::Resolve(ResolveError::Malformed));
    }
    let old_trailing = old_path.len() > 1 && old_path[old_path.len() - 1] == b'/';
    let mut old_canon = [0u8; MAX_CWD];
    let (old_len, old_kind) = resolve_at(
        cwd.path(),
        old_dirfd,
        old_path,
        &mut VfsDomainView::new(vfs),
        &mut old_canon,
    )
    .map_err(LinkError::Resolve)?;
    if old_trailing && old_kind != ResolvedKind::Directory {
        return Err(LinkError::Resolve(ResolveError::NotDirectory));
    }
    if old_kind == ResolvedKind::Directory {
        return Err(LinkError::NotPermitted);
    }
    let new_trailing = new_path.len() > 1 && new_path[new_path.len() - 1] == b'/';
    let mut new_abs = [0u8; MAX_CWD];
    let new_len = if new_trailing {
        let (len, kind) = resolve_at(
            cwd.path(),
            new_dirfd,
            new_path,
            &mut VfsDomainView::new(vfs),
            &mut new_abs,
        )
        .map_err(LinkError::Resolve)?;
        if kind != ResolvedKind::Directory {
            return Err(LinkError::Resolve(ResolveError::NotDirectory));
        }
        len
    } else {
        build_link_target(vfs, cwd, new_dirfd, new_path, &mut new_abs)?
    };
    if new_trailing {
        // A trailing slash resolved to an existing directory, which blocks
        // the link exactly like any other live entry.
        return Err(LinkError::Exists);
    }
    vfs.link(&old_canon[..old_len], &new_abs[..new_len])
        .map_err(map_link_error)
}

/// Emulate `symlink(target, path)` / `symlinkat(dirfd, target, path)`
/// against the domain: join the resolved parent with the final name and
/// plant the raw target with [`VirtualFs::symlink`]. The target is never
/// resolved here — dangling and absolute targets plant fine, and
/// confinement applies when the link resolves, not when it is created.
/// Pure `core` logic, wired like [`link_at`]. Allowed until then.
#[allow(dead_code)]
pub fn symlink_at<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    dirfd: i64,
    target: &[u8],
    path: &[u8],
) -> Result<(), SymlinkError> {
    if target.is_empty() || target.contains(&0) {
        return Err(SymlinkError::Resolve(ResolveError::Malformed));
    }
    if target.len() > MAX_LINK {
        return Err(SymlinkError::Resolve(ResolveError::TooLong));
    }
    if path.is_empty() || path.contains(&0) {
        return Err(SymlinkError::Resolve(ResolveError::Malformed));
    }
    if path.len() > 1 && path[path.len() - 1] == b'/' {
        let mut probe = [0u8; MAX_CWD];
        match resolve_at(
            cwd.path(),
            dirfd,
            path,
            &mut VfsDomainView::new(vfs),
            &mut probe,
        ) {
            Ok((_, kind)) if kind == ResolvedKind::Directory => {
                return Err(SymlinkError::Exists);
            }
            Ok(_) => return Err(SymlinkError::Resolve(ResolveError::NotDirectory)),
            Err(error) => return Err(SymlinkError::Resolve(error)),
        }
    }
    let mut canonical = [0u8; MAX_CWD];
    let len = build_link_target(vfs, cwd, dirfd, path, &mut canonical).map_err(map_link_target)?;
    vfs.symlink(target, &canonical[..len])
        .map_err(map_symlink_error)
}

/// Emulate `readlink(path, out)` / `readlinkat(dirfd, path, out)` against
/// the domain: resolve without following a final symlink and report the
/// raw target into `out`, returning the placed count. A non-symlink final
/// fails with [`ReadlinkError::Invalid`]; a target longer than `out`
/// truncates like Linux. Pure `core` logic, wired like [`link_at`].
/// Allowed until then.
#[allow(dead_code)]
pub fn readlink_at<R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    dirfd: i64,
    path: &[u8],
    out: &mut [u8],
) -> Result<usize, ReadlinkError> {
    if path.is_empty() || path.contains(&0) {
        return Err(ReadlinkError::Resolve(ResolveError::Malformed));
    }
    let trailing = path.len() > 1 && path[path.len() - 1] == b'/';
    let mut canonical = [0u8; MAX_CWD];
    let (len, kind) = resolve_at_full(
        cwd.path(),
        dirfd,
        path,
        false,
        &mut VfsDomainView::new(vfs),
        &mut canonical,
    )
    .map_err(ReadlinkError::Resolve)?;
    if trailing && kind != ResolvedKind::Directory {
        return Err(ReadlinkError::Resolve(ResolveError::NotDirectory));
    }
    if kind == ResolvedKind::Directory {
        return Err(ReadlinkError::Invalid);
    }
    vfs.readlink(&canonical[..len], out)
        .map_err(map_readlink_error)
}

/// Join the resolved target parent with the final name for [`link_at`]
/// (and, through [`map_link_target`], [`symlink_at`]): the stored path is
/// canonical, never hiding an unexpanded link in the parent. Mirrors the
/// [`create_at`] slow path: the parent resolves with following (it must be
/// a live directory) while the name itself stays uninterpreted. Reached
/// only through [`link_at`]/[`symlink_at`]; allowed with them.
#[allow(dead_code)]
fn build_link_target<
    R: BaseReader,
    const FILES: usize,
    const FILE_SIZE: usize,
    const FDS: usize,
>(
    vfs: &mut VirtualFs<'_, R, FILES, FILE_SIZE, FDS>,
    cwd: &DomainCwd,
    dirfd: i64,
    path: &[u8],
    out: &mut [u8; MAX_CWD],
) -> Result<usize, LinkError> {
    let dot: &[u8] = b".";
    let (parent, name) = match path.iter().rposition(|byte| *byte == b'/') {
        Some(0) => (&path[..1], &path[1..]),
        Some(index) => (&path[..index], &path[index + 1..]),
        None => (dot, path),
    };
    if name.is_empty() || name == b"." || name == b".." {
        return Err(LinkError::Invalid);
    }
    let mut parent_out = [0u8; MAX_CWD];
    let (parent_len, parent_kind) = resolve_at(
        cwd.path(),
        dirfd,
        parent,
        &mut VfsDomainView::new(vfs),
        &mut parent_out,
    )
    .map_err(LinkError::Resolve)?;
    if parent_kind != ResolvedKind::Directory {
        return Err(LinkError::Resolve(ResolveError::NotDirectory));
    }
    let mut len =
        append_all(out, 0, &parent_out[..parent_len]).map_err(LinkError::Resolve)?;
    if len > 1 {
        len = append_all(out, len, b"/").map_err(LinkError::Resolve)?;
    }
    len = append_all(out, len, name).map_err(LinkError::Resolve)?;
    Ok(len)
}

/// Map a VFS failure onto the faithful [`PermError`]. `NotFound` after a
/// successful pre-resolution is unreachable through [`chmod_at`] — the view
/// cannot change between the two reads — so it reports the missing name
/// rather than an inconsistency. Allowed with the chmod emulations.
#[allow(dead_code)]
fn map_perm_error(error: VfsError) -> PermError {
    match error {
        VfsError::NotFound => PermError::Resolve(ResolveError::NotFound),
        VfsError::NotDirectory => PermError::NotDirectory,
        VfsError::PermissionDenied => PermError::NotPermitted,
        VfsError::InvalidDescriptor => PermError::BadDescriptor,
        VfsError::InvalidPath => PermError::Invalid,
        VfsError::OverlayLimit => PermError::NoSpace,
        VfsError::FileTooLarge => PermError::TooLarge,
        VfsError::SymlinkLoop => PermError::Resolve(ResolveError::SymlinkLoop),
        VfsError::IsDirectory
        | VfsError::InvalidOffset
        | VfsError::DescriptorLimit
        | VfsError::AlreadyExists
        | VfsError::InvalidIndex
        | VfsError::Io => PermError::Io,
    }
}

/// Map a VFS failure onto the faithful [`LinkError`]. A directory report
/// can only name the source here — the target side never replaces, so any
/// live target already failed with `AlreadyExists` inside the VFS.
/// Allowed with [`link_at`].
#[allow(dead_code)]
fn map_link_error(error: VfsError) -> LinkError {
    match error {
        VfsError::NotFound => LinkError::Resolve(ResolveError::NotFound),
        VfsError::NotDirectory => LinkError::NotDirectory,
        VfsError::IsDirectory => LinkError::NotPermitted,
        VfsError::AlreadyExists => LinkError::Exists,
        VfsError::SymlinkLoop => LinkError::Resolve(ResolveError::SymlinkLoop),
        VfsError::InvalidPath => LinkError::Invalid,
        VfsError::OverlayLimit => LinkError::NoSpace,
        VfsError::FileTooLarge => LinkError::TooLarge,
        VfsError::PermissionDenied
        | VfsError::InvalidDescriptor
        | VfsError::DescriptorLimit
        | VfsError::InvalidOffset
        | VfsError::InvalidIndex
        | VfsError::Io => LinkError::Io,
    }
}

/// Map a [`build_link_target`] failure onto the faithful [`SymlinkError`].
/// The builder only produces resolution, directory, and name errors, so
/// the mapping is total. Allowed with [`symlink_at`].
#[allow(dead_code)]
fn map_link_target(error: LinkError) -> SymlinkError {
    match error {
        LinkError::Resolve(error) => SymlinkError::Resolve(error),
        LinkError::NotDirectory => SymlinkError::NotDirectory,
        LinkError::Invalid => SymlinkError::Invalid,
        LinkError::Exists => SymlinkError::Exists,
        LinkError::NotPermitted
        | LinkError::NoSpace
        | LinkError::TooLarge
        | LinkError::Io => SymlinkError::Io,
    }
}

/// Map a VFS failure onto the faithful [`SymlinkError`]. Allowed with
/// [`symlink_at`].
#[allow(dead_code)]
fn map_symlink_error(error: VfsError) -> SymlinkError {
    match error {
        VfsError::NotFound => SymlinkError::Resolve(ResolveError::NotFound),
        VfsError::NotDirectory => SymlinkError::NotDirectory,
        VfsError::AlreadyExists => SymlinkError::Exists,
        VfsError::SymlinkLoop => SymlinkError::Resolve(ResolveError::SymlinkLoop),
        VfsError::InvalidPath => SymlinkError::Invalid,
        VfsError::OverlayLimit => SymlinkError::NoSpace,
        VfsError::FileTooLarge => SymlinkError::TooLarge,
        VfsError::PermissionDenied
        | VfsError::InvalidDescriptor
        | VfsError::DescriptorLimit
        | VfsError::IsDirectory
        | VfsError::InvalidOffset
        | VfsError::InvalidIndex
        | VfsError::Io => SymlinkError::Io,
    }
}

/// Map a VFS failure onto the faithful [`ReadlinkError`]. A non-symlink
/// final surfaces as [`VfsError::InvalidPath`] and reads as `EINVAL`,
/// matching Linux. Allowed with [`readlink_at`].
#[allow(dead_code)]
fn map_readlink_error(error: VfsError) -> ReadlinkError {
    match error {
        VfsError::NotFound => ReadlinkError::Resolve(ResolveError::NotFound),
        VfsError::NotDirectory => ReadlinkError::NotDirectory,
        VfsError::InvalidPath => ReadlinkError::Invalid,
        VfsError::SymlinkLoop => ReadlinkError::Resolve(ResolveError::SymlinkLoop),
        VfsError::PermissionDenied
        | VfsError::InvalidDescriptor
        | VfsError::DescriptorLimit
        | VfsError::IsDirectory
        | VfsError::FileTooLarge
        | VfsError::AlreadyExists
        | VfsError::OverlayLimit
        | VfsError::InvalidOffset
        | VfsError::InvalidIndex
        | VfsError::Io => ReadlinkError::Io,
    }
}
/// Map a retained-backing failure onto the faithful [`IoError`] for the
/// data path, mirroring [`map_retained_error`]. Allowed until supervisor
/// wiring calls it.
#[allow(dead_code)]
fn map_retained_io_error(error: RetainedError) -> IoError {
    match error {
        RetainedError::TooManyFiles | RetainedError::NoSpace => IoError::NoSpace,
        RetainedError::TooLarge => IoError::TooLarge,
        RetainedError::InvalidPath => IoError::Invalid,
        RetainedError::InvalidRecord | RetainedError::WrongInstance | RetainedError::Io => {
            IoError::Io
        }
    }
}
