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
pipes and packet channels. Each epoll instance has at most 32 registrations,
independent of the 16-socket and 32-channel object limits;
the existing public descriptor limit (including a lower operator limit) applies.
No host eventfd or epoll descriptor is created or exposed. Counters support
8-byte scalar transfers, semaphore/nonblocking modes, overflow backpressure,
shared status flags and per-descriptor close-on-exec. Vector/socket transfers
on counters are unsupported.

Epoll watches already-owned counters, pipes, packet endpoints and granted TCP
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
are always reported; RDHUP observes actual TCP peer write-half closure and is
not synthesized from pipe HUP. Events carry the caller's snapshotted 64-bit data.

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

Instance-visible credentials are virtual Ginux state. Independently, every
native managed process sets `PR_SET_NO_NEW_PRIVS` before executing workload
code. A root-launched runtime drops managed host execution to UID/GID 65534; a
non-root runtime retains the caller's host identity. Virtual root therefore
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
