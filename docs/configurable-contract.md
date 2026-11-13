# Self-contained userspace contract

Every Ginux instance carries its complete kernel/userspace contract in the
same TOML recipe as its image, resources, identity, and hooks. The recipe is
portable: host interface attachment and port translation are deployment state,
not contract policy.

Configured launch also supports explicit downstream catalog 1002 containing its additional
implemented syscall forms. Select `[contract] version = 1` and `catalog = 1002`
in the upstream hierarchical format. Legacy profiles and `[userspace.*]` sections
are rejected. Upstream Gate 11 owns catalog 2;
the former local catalog 2 is retired to avoid a version collision. See the README's configured-launch section for
the operation list, enforcement order, audit behavior and backend limitations.

Configured `readlink` and absolute-path `readlinkat` additionally recognize
`/proc/self/fd/N` for a live public filesystem descriptor owned by the caller.
Names come from the image/chroot or owned-filesystem owner, never from treating
`N` as a host descriptor. Aliases, fork and close-on-exec follow the public table.
The owned view reports a currently tracked name for the inode; unlinked or
replaced names, closed descriptors and non-filesystem objects return ENOENT.
Decimal path components are bounded names and do not wrap to a low-32-bit FD.
Output truncates to the supplied size without a NUL terminator; a zero size is
invalid. This is a configured metadata view, not a procfs mount: it adds no
directory enumeration, host-process view or proc-path open authority, and does
not change native policy. Explicit contract denial still precedes the view.

Configured `readv` on an image descriptor, and `faccessat` and `readlinkat` on
an image path, are image reads like `read`, `access` and `readlink`. Only a
registered native image or inherited console descriptor reaches the kernel;
`O_PATH` references and closed numbers return EBADF, and image descriptors stay
unwritable. An image path is first resolved to its canonical form, so hidden
subtrees, `/proc`, `/sys`, `/dev` and owned storage keep the answers of the
plain forms; `readlinkat` on `/dev` returns EINVAL as `readlink` does. A
`readv` shares the 64 MiB request bound of one image read, summed over a
snapshot of the caller's vectors; an array Linux itself rejects (more than
1024 entries, a negative length or an unreadable array) keeps the kernel's
EINVAL or EFAULT. Native policy and catalog membership are unchanged.

Catalog 1002 also serves `preadv`, `preadv2`, `readahead`, `fadvise64`,
`sendfile`, `copy_file_range` and every xattr call, each with no authority
beyond a call the instance already has on the same descriptor or path, and the
same errno for the same refusal. Every catalog 1002 digest changed with them.

- `preadv` (295) and `preadv2` (327) are the `preadv` or `readv` they name: a
  negative offset other than `preadv2`'s -1 is EINVAL before the descriptor is
  looked up; -1 reads at, and advances, the shared offset as `readv`; any
  `preadv2` flag is EOPNOTSUPP once the descriptor is known to be open. The
  plain form then takes its ordinary descriptor path: owned files read at the
  offset with `readv`'s 4096-byte and 16-vector bounds, devices read as
  `pread64`, channels and the console answer ESPIPE as `pread64` does, and an
  image descriptor reads in the kernel under `readv`'s 64 MiB vector bound.
  They are `filesystem.path.read`, as `pread64` is.
- `readahead` (187) and `fadvise64` (221) answer for the descriptor as Linux
  does and have no host effect: no read, no page-cache change. `readahead` is
  EBADF for a closed, `O_PATH` or write-only descriptor, EINVAL for anything
  but a regular file, otherwise 0. `fadvise64` is EBADF for a closed or
  `O_PATH` descriptor, ESPIPE for a pipe or FIFO, EINVAL for a negative length
  or an advice outside 0..5, otherwise 0; like Linux, sockets, event objects,
  directories and devices accept the advice. An image descriptor's kind and
  access mode come from the supervisor's `pidfd_getfd` duplicate of it.
- The confined filesystem has no extended attributes, and host attributes,
  security labels included, are never read, listed, set, removed or revealed.
  `getxattr`, `lgetxattr`, `listxattr`, `llistxattr`, `setxattr`, `lsetxattr`,
  `removexattr` and `lremovexattr` first check the name (ERANGE when empty or
  unterminated within 256 bytes, EFAULT when unreadable) and, for the set
  forms, the flags (EINVAL), size (E2BIG above 65536) and value (EFAULT), as
  Linux 6.13 and later order them. The path then resolves exactly as `stat`
  (or `lstat` for the `l` forms) resolves it, as the `faccessat2(AT_FDCWD,
  path, F_OK[, AT_SYMLINK_NOFOLLOW])` it is rewritten to through every backend
  and the shared image path mediation, so ENOENT, ENOTDIR, ELOOP, EACCES and
  EFAULT are the `stat` answers; registers return at the exit. A path that
  resolves gives ENODATA for a read, 0 (an empty list, the buffer untouched)
  for a list and ENOTSUP for a change. `fgetxattr`, `flistxattr`,
  `fsetxattr` and `fremovexattr` check the descriptor first (EBADF for a
  closed number and, as Linux's `fdget`, an `O_PATH` reference), then the
  name, and answer the same way for every open descriptor. Reads and lists
  are `filesystem.path.read`; changes are `filesystem.path.write`.
- `sendfile` (40) and `copy_file_range` (326) are a read of the input as
  `pread64` composed with a write of the output as `write` (or `pwrite64` for
  an explicit `copy_file_range` output offset), a 4096-byte chunk at a time,
  at most 1 MiB per call and 4096 bytes into the console or a device; a short
  count is legal and callers loop. The input must be a regular owned or image
  file; the output an owned file, and for `sendfile` also an assigned device
  or the inherited console. Owned channel endpoints (pipes, FIFOs, local
  sockets, event objects) and TCP sockets are EINVAL outputs without consuming
  input, as configured `splice` is; callers fall back to `read` and `write`.
  No host `sendfile`, `splice` or `copy_file_range` runs: image bytes are read
  through the supervisor's `pidfd_getfd` duplicate of the image descriptor
  (the same open file description, so nothing the workload could not read
  itself), owned bytes through the owned backends, and console bytes are
  written to the console's own open file description, which the supervisor
  shares. A console output that has no room parks the call (EAGAIN when the
  console is nonblocking); a console reader that has gone away gives EPIPE and
  SIGPIPE to the caller, never to the supervisor. Offsets follow Linux: a null
  offset uses and advances the descriptor's shared offset; `sendfile` reads
  its offset pointer first and always stores the result back (EFAULT if it
  cannot), `copy_file_range` stores offsets only after moving bytes. Linux's
  checks keep their order and errno: EBADF for closed, `O_PATH`, unreadable
  input or unwritable output descriptors; ESPIPE for an explicit `sendfile`
  offset on a pipe; EINVAL for a non-regular `sendfile` input, an append-mode
  output, a bad position or count, nonzero `copy_file_range` flags or
  overlapping ranges of one file; EISDIR and EINVAL for non-regular
  `copy_file_range` files; EOVERFLOW for a wrapping range. A
  `copy_file_range` between an image file and owned storage is served, as
  Linux 5.3 to 5.18 served cross-filesystem copies; later kernels answer EXDEV
  there. The output is decided as a `write` of its descriptor
  (`filesystem.path.write`, `device.console.write` or
  `network.inet.tcp.connect`) and the input as a `read` of its descriptor;
  either denial refuses the call.

Configured `/proc/self/maps` is a read-only stack projection. An exact-path
read open snapshots only the registered process's `[stack]` range and mapping
permissions; it contains no other mappings, inode/device identities or file
paths. The supervisor scans at most 1 MiB of its stopped tracee's maps with a
512-byte line bound and fails closed on missing/invalid stack metadata or an
exceeded bound. Stat/access identify a deterministic read-only regular file.
The anonymous snapshot uses existing VFS byte/object/descriptor quotas and the
public FD table, including lower operator limits. Read, pread, readv, seek,
aliases and fork/exec use the existing descriptor owner; a fresh open takes a
new snapshot. It is never a writable namespace or export entry. Construction
temporarily needs an extra VFS descriptor. Mmap, descriptor-path reopen and
metadata mutation are unsupported. Broader proc paths, directory enumeration
and host process access remain unavailable; explicit denial precedes all view
effects. This supplies libc initial-stack discovery without a general procfs
or complete memory-map ABI.

Configured filesystem opens additionally accept bounded `O_PATH` references.
They follow the confined pathname and retain an immutable metadata-only kind in
the public descriptor table. Supported accompanying flags are `O_DIRECTORY`,
`O_CLOEXEC`, `O_LARGEFILE` and `O_NOCTTY`; other combinations, including
`O_NOFOLLOW`, return EOPNOTSUPP. Stat, relative stat/access/readlink metadata,
the owned FD-name view, duplication, descriptor flags, close and fork/exec
lifetime are supported. `F_GETFL` reports `O_PATH` and requested `O_DIRECTORY`.
Data I/O, directory enumeration, seek, mapping, descriptor execution, fchdir,
status mutation and descriptor-path reopen are denied. An `O_PATH` directory
can be the base of a relative open, exec or pathname mutation, subject to the same
contract and storage checks as an absolute pathname. `fchmodat` and `fchmodat2`
change modes in writable storage; the latter also accepts `AT_EMPTY_PATH`
on an owned reference. Direct `fchmod` on `O_PATH` still returns EBADF.
Poll reports POLLNVAL and
epoll does not watch filesystem references. References consume the existing
public and filesystem descriptor quotas, including lower operator limits.
Explicit contract denial precedes allocation and metadata effects. This is a
configured subset, with native policy and catalog membership unchanged.

Configured `pselect6` snapshots up to 256 public descriptor bits per set and
accepts zero, finite timeouts up to 300 seconds, or an infinite wait. Owned
files, devices and channels supply readiness; inherited console descriptors
are polled through their registered handles. Other native/image descriptors
return EOPNOTSUPP and `O_PATH` references return EBADF. Readable EOF and writable
error conditions follow the Linux select masks. Timeouts retain their deadline
while parked and report the remaining time on completion or interruption.

An optional 8-byte signal mask is snapshotted with the input sets. Ready
descriptors take priority over pending signals. A no-ready completion uses a
zero-descriptor, zero-timeout native `pselect6` solely for Linux to deliver a
pending signal and restore the original mask, including after the handler's
`sigreturn`; no workload file descriptor is passed to the host. Exact contract
denials still precede these effects. This supports ordinary parallel make's
pipe and named FIFO jobservers.

Configured `mknod`/`mknodat` create FIFOs in assigned writable storage, with
normal umask, permissions, inode metadata, links, rename and unlink behavior.
FIFO opens join the existing bounded channel owner: blocking readers and
writers rendezvous, nonblocking writers without a reader return ENXIO, and
`O_RDWR` opens both directions. Each open has independent status flags; aliases
share them. `O_PATH` opens only an inode reference. Open endpoints retain their
inode across unlink, and the final close discards buffered bytes. Export/restore
preserves FIFO names and hardlinks, without saving live channels or their data.
Character and block device creation remains denied.

Configured `splice` validates the public descriptors and returns EINVAL for
unsupported transfer endpoints without consuming input. Programs can use their
normal read/write fallback; invalid descriptors and `O_PATH` references return
EBADF. This does not provide zero-copy transfers or expose host descriptors.

Configured launch implements `eventfd2`, `epoll_create1`, `epoll_ctl`,
`epoll_wait` and bounded `epoll_pwait` through the public descriptor table.
Counters and epoll instances share the bounded 32-object channel pool with
pipes and local socket pairs. Each epoll instance has at most 32 registrations,
independent of the 16-socket and 32-channel object limits;
the existing public descriptor limit (including a lower operator limit) applies.
No host eventfd or epoll descriptor is exposed; the only host eventfds are the
inert number placeholders the descriptor table places, which no workload call
reaches. Counters support
8-byte scalar transfers, semaphore/nonblocking modes, overflow backpressure,
shared status flags and per-descriptor close-on-exec. Vector/socket transfers
on counters are unsupported.

Epoll watches already-owned counters, pipes, local socket pair endpoints and granted TCP
sockets. Image/native descriptors, filesystem files and nested epoll instances
are unsupported. Registrations retain object identity and the registered public
number: aliases may be registered separately, survive closure of the original
number while an alias remains, and never retarget a reused object or descriptor.
Level readiness, edge transitions, event-counter read/write notifications,
one-shot rearming and
round-robin delivery of ready registrations are bounded by this set.
Successful counter writes notify IN even when the counter stays nonzero, so
edge-triggered wakeup loops may intentionally leave it unread; reads notify OUT.
Other edge-triggered I/O still requires draining until EAGAIN. ERR/HUP
are always reported; RDHUP observes actual TCP or local socket pair peer
write-half closure and is not synthesized from pipe HUP. Events carry the caller's snapshotted 64-bit data.

Waits support zero, finite timeouts up to 300000 ms and negative infinite waits.
`maxevents` is output capacity and may exceed the 32 registrations. A parked
wait pins its epoll object; copyout failure does not consume pending delivery.
`epoll_pwait` accepts a null signal-mask pointer or an 8-byte kernel mask equal
to the calling task's current mask (ignoring unmaskable KILL/STOP bits). Other
temporary masks return EOPNOTSUPP. A parked wait ends with EINTR for a signal
that runs a handler; ignored signals leave it parked. An interrupted admitted futex exposing the kernel's internal
ERESTART_RESTARTBLOCK returns EINTR for userspace retry; `restart_syscall` is
not granted. Native policy, catalog membership and explicit-deny precedence
are unchanged. These are configured facilities, not a general Linux ABI claim.

```toml
[contract]
version = 1
catalog = 2
default = "deny"
allow = ["filesystem.*", "proc.*", "sys.*", "time.*"]
deny = ["device.mmio.direct", "device.dma.direct", "network.packet.raw"]

[contract.syscalls]
control = "selective"
default = "deny"
allow = ["read*", "write*", "open*", "close", "mmap", "futex", "sched_yield"]
deny = ["ptrace"]

[contract.filesystem]
default = "deny"
read = ["/"]
write = ["/run", "/tmp", "/var"]
create = ["/run", "/tmp", "/var"]
deny = ["/ginux-demo/read-only"]

[contract.network]
default = "deny"
inbound = ["tcp:*"]
outbound = ["tcp:*", "udp:53"]

[contract.devices]
default = "deny"
read = ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/console"]
write = ["/dev/null", "/dev/console"]
create = []

[contract.privileges]
default = "deny"
setuid = []
setgid = []

[contract.process]
default = "deny"
max_processes = 4096
max_threads = 16384
signals = ["*"]
ptrace = "deny"
namespace_create = []
namespace_join = []

[contract.kernel]
default = "deny"
proc_read = ["/"]
proc_write = []
sys_read = ["/"]
sys_write = []
```

Every subsection default is deliberately `deny`. Explicit deny wins over
allow. Runtime enforcement receives the compiled operation table and
deterministic digest; it never expands globs while managed code is running.

## Matching and precedence

`[contract].allow` and `[contract].deny` select canonical catalog operations.
Their component-aware selectors use `*` for one dot-separated component and
`**` recursively. Every selector must match the pinned catalog.

`[contract.syscalls]` uses shell-style `*` over syscall names. For example,
`open*` matches the cataloged `open` and `openat` syscalls. Every
syscall selector must match at least one syscall. Expansion occurs against the
declared catalog version, so a catalog update requires explicit revalidation
and cannot silently enlarge an existing normalized contract.

Filesystem, device, and virtual-kernel paths are absolute and component-aware.
A directory selector covers that directory and its descendants; `/private`
does not match `/private-other`. Invalid normalization and path escape fail
closed. Resolution is deterministic:

1. start at default deny;
2. apply broad grants;
3. apply surface-specific grants; and
4. apply explicit denies last.

The normalized digest includes every final action and its provenance.

## Syscall control

`control = "selective"` is the default. It permits direct host execution only
when the contract allows the syscall and the pinned catalog independently
classifies it as transparent and direct-safe. Denied, virtualized, inspected,
translated, or emulated operations remain Ginux-controlled.

`control = "paranoid"` sends every syscall through the Ginux userspace
dispatcher before completion. This provides the strongest observation point
at a substantial performance cost.

There is deliberately no `none` syscall-control value. Performance reports use
ordinary native Rocky execution as the no-Ginux control, but that control does
not provide an instance contract or containment boundary. The reproducible
native/selective/paranoid comparison is documented in
[performance.md](performance.md).

## Filesystem, devices, and privilege elevation

Filesystem and device sections use consistent `read`, `write`, and `create`
lists. A filesystem `deny` entry recursively blocks mutation below that path,
including link-based bypasses. Device `create = []` prevents character and
block device creation while ordinary FIFO creation remains governed by the
filesystem and syscall rules.

`setuid` and `setgid` are executable-path allow lists. Empty arrays permit no
set-ID execution. Existing set-ID bits do not grant virtual or host authority
unless the corresponding executable path is allowed.

## Synthetic kernel views

`/proc` and `/sys` are always synthetic, Ginux-owned views. The
`[contract.kernel]` rules control which virtual paths are visible or writable;
they never enable passthrough to the host trees.

## Network policy and deployment

`[contract.network]` defines what an instance may do. It does not select a host
interface or claim external ports. Those host-specific settings are repeatable
CLI flags, persisted separately from `config.toml`:

```sh
ginux import web recipe.toml \
    --network eth0:1 \
    --forward protocol=tcp,external_port=8080,instance_port=80 \
    --forward protocol=tcp,external_port=8443,instance_port=443

ginux set web \
    --network default \
    --forward protocol=tcp,external_port=9080,instance_port=80
```

Omitting `--network` selects the host default. `--network default` clears an
explicit attachment and `--forward none` clears forwarding. One command may
change the attachment and several forwards; Ginux validates the complete
candidate and commits it atomically. Invalid syntax, unavailable attachments,
or conflicting external ports leave the prior deployment unchanged.

## Operator workflow

```sh
ginux validate recipe.toml
ginux inspect recipe.toml
ginux explain recipe.toml filesystem.path.write
ginux diff strict.toml recipe.toml
ginux import rocky recipe.toml --network default
ginux set rocky --network eth0:1 \
    --forward protocol=tcp,external_port=8080,instance_port=80
```

`validate` parses and compiles without launching an instance. `inspect`
summarizes final decisions and the digest. `explain` identifies the winning
rule and limitation for one catalog operation. `diff` reports authority
changes between two complete recipes. There is no top-level `ginux contract`
command and the replaced `[userspace.*]` syntax fails closed.

## Bootstrap and host execution boundary

Distribution customization belongs in `[hooks].pre_boot`. Pre-boot commands
execute through Ginux mediation inside the instance root. Final contract
restrictions activate after hooks finish, allowing a recipe to prepare state
and then lock it down.

Use ordinary strings for short commands and triple-quoted strings for readable
multiline scripts. Each array item remains one ordered hook:

```toml
[hooks]
pre_boot = [
  """
  /usr/bin/mkdir -p /workspace
  /usr/bin/chown 1000:1000 /workspace
  """,
]
timeout_seconds = 10
failure = "stop"
```

The script is stored in the recipe and executes only inside the instance; it
does not grant access to a host-side script. See the validated recipes under
[`config/examples/`](../config/examples/README.md).

Instance-visible credentials are virtual Ginux state. Independently, every
native managed process sets `PR_SET_NO_NEW_PRIVS` before executing workload
code. A root-launched runtime drops managed host execution to UID/GID 65534; a
non-root runtime retains the caller's host identity, and configured launch runs
it in a private user namespace with no capabilities. Virtual root therefore
does not imply host root.

Runtime audit records contain the instance, contract digest, canonical
operation, winning source rule, action, and result. The generated catalog
inventory is [`abi-contract-coverage.md`](abi-contract-coverage.md).
The default Rocky recipe uses `[audit] enabled = false`. `ginux start NAME
--audit` enables auditing for that run and records it in the instance's
`audit.log` without mixing audit records into the attached console. Set
`enabled = true` in the recipe to audit every start. Audit configuration
controls enablement only; the controller always owns the log destination.
Legacy `mode = "stderr"` and `mode = "disabled"` recipes remain readable and
normalize to `enabled = true` and `enabled = false`, respectively.

## Launch enforcement

`ginux launch` checks the resolved contract before workload effects. Explicit
denials take precedence over allowances. Allowances remain limited by the
balanced implementation. Audit entries identify the winning operation and
rule; `[audit] enabled = false` suppresses decision records while keeping config
and completion diagnostics. A semantic denial wins, except an explicit syscall denial takes precedence
over a semantic family that is merely not granted.

Launch rejects explicit denials it cannot enforce, including host vDSO clock
reads and proc/sys access; configured launch owns console input, so a
`device.console.read` denial is enforced. It rejects native-only hierarchical
filesystem, device, process and kernel controls, filesystem `write_deny` rules,
pre-boot hooks and shared-network policy rather than pretending to enforce
them. Configured launch applies `[resources]` limits and its own storage,
device, network and process lanes as the README describes. The root remains a
host-path chroot bootstrap: privileged for a root caller, in a private user
namespace otherwise.
