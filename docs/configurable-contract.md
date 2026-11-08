# Self-contained userspace contract

Every Ginux instance can carry its complete kernel/userspace contract in the
same TOML file as its image, resources, devices, and networking. Runtime
enforcement receives only the compiled operation table and deterministic
digest; it never interprets globs while managed code is running.

Configured launch also supports explicit downstream catalog 1002 containing its additional
implemented syscall forms. Select `[contract] profile = "configured-balanced-v2"`
or `catalog = 1002` in a self-contained contract. Upstream Gate 11 owns catalog 2;
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

Configured launch implements `eventfd2`, `epoll_create1`, `epoll_ctl`,
`epoll_wait` and bounded `epoll_pwait` through the public descriptor table.
Counters and epoll instances share the existing 16-object channel pool with
pipes and packet channels. Each epoll instance has at most 32 registrations,
covering the existing 16 TCP sockets and 16 channel objects together;
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
temporary masks return EOPNOTSUPP: general signal interruption/restart semantics
are not promised. An interrupted admitted futex exposing the kernel's internal
ERESTART_RESTARTBLOCK returns EINTR for userspace retry; `restart_syscall` is
not granted. Native policy, catalog membership and explicit-deny precedence
are unchanged. These are configured facilities, not a general Linux ABI claim.

```toml
[userspace.contract]
version = 1
catalog = 2
default = "deny"
read = ["fs.**", "proc.**", "sys.**", "time.**"]
write = ["fs.**", "dev.console.write"]
execute = ["syscall.execve"]
connect = ["network.**"]
listen = []
process = ["signal.**", "credential.**"]
system = ["memory.**", "cgroup.**"]
deny = ["dev.mmio.direct", "dev.dma.direct", "network.packet.raw"]
exact_allow = []
exact_deny = []
```

`default` is deliberately limited to `deny`. The access groups are grants;
`deny` always wins. `exact_allow` and `exact_deny` are an advanced escape hatch
for one canonical catalog operation and do not accept globs. No grant can
promote an operation marked denied, planned, or out of scope by the catalog.

## Selectors and resources

Selectors are expanded against the pinned catalog during configuration
validation. `*` matches exactly one dot-separated component and `**` matches
recursively. A wildcard must occupy its complete component, and every rule
must match at least one operation. `fs` aliases `filesystem`; `dev` aliases
`device`. Other roots use the catalog names directly:

- `fs`, `proc`, `sys`, `cgroup`, and `dev`;
- `network`, `signal`, `credential`, `time`, and `memory`; and
- `syscall` and `ioctl` for lower-level authority that lacks a higher-level
  resource representation.

Each catalog operation belongs to one human access group. This makes broad
rules such as `read = ["proc.**"]` understandable while retaining an explicit,
reviewable operation table beneath them. Provenance records the access group
and zero-based source-rule index that produced every decision.

## Resolution and migration

Resolution is deterministic:

1. deny every catalog operation;
2. apply `read`, `write`, `execute`, `connect`, `listen`, `process`, and
   `system` grants;
3. apply `exact_allow`;
4. apply `deny`; and
5. apply `exact_deny`.

The derived digest includes every final action and its provenance. Catalog
version changes require explicit revalidation, so a saved recipe cannot
silently acquire a newly cataloged operation.

Gate 10 `[contract]` profiles and templates remain accepted internally for
migration and regression comparison, but they cannot be mixed with
`[userspace.contract]`. New saved examples use the self-contained form. Copy a
complete example instance recipe as the starting point; Ginux does not create
or manage a separate contract object or generate detached contract fragments.

## Operator workflow

```sh
ginux instance validate /etc/ginux/examples/rocky-systemd.toml
ginux instance inspect /etc/ginux/examples/rocky-systemd.toml
ginux instance explain /etc/ginux/examples/rocky-systemd.toml filesystem.path.write
ginux instance diff strict.toml rocky-systemd.toml
```

`validate` parses and compiles the complete recipe without launching an
instance. `inspect` summarizes its final decisions and digest. `explain`
connects one operation to its winning human rule, constraint, and limitation.
`diff` reports authority changes between two complete instance files. The old
top-level `ginux contract` command is intentionally unsupported.

## Typed resource constraints and audit

Contract grants never bypass the typed instance fields that constrain network
addresses and ports, volume targets, assigned devices, virtual credentials,
or operation-specific syscall and ioctl arguments. Those checks still run
before any host effect.

Runtime audit records contain the instance, contract digest, canonical
operation, winning policy source, source-rule index, action, and result. Audit
detail remains bounded to 8,192 records with logarithmic dropped-event
reporting. The generated catalog inventory is
[`abi-contract-coverage.md`](abi-contract-coverage.md).

Configured launch additionally records `network-endpoint` and `egress` on
connect attempts, using the address decoded by the network owner. On teardown,
`ginux: network-summary version=1 endpoints=N` is followed by at most eight
numeric endpoint records with `attempted` and `connected` booleans. The summary
has a fixed size bound and remains available after the configured syscall audit
reaches its 64 KiB cap. `attempted` records use of an eligible endpoint, including
a failed backend connection; `connected` requires observed handshake completion.
A missing summary (for example after supervisor termination) is unknown usage,
not evidence that a grant was unused. Disabled audit emits neither summary nor
endpoint detail. This changes configured diagnostics only, not contract authority
or native policy. A separate `ginux: denial-summary` records first occurrence,
count, errno and winning rule for each denied catalog operation (at most
`MAX_OPERATIONS`, plus one unknown-operation bucket), independently of the trace
cap. Absence after interrupted teardown remains unobserved. Disabled auditing
suppresses both summaries. `instance-validate` advertises
`configured-network-audit=1 configured-denial-audit=1` so consumers can reject a
runtime that lacks these diagnostics before launch.

## Filesystem and elevation constraints

The same instance recipe can impose final workload constraints that are more
specific than broad contract grants:

```toml
[userspace.filesystem]
write_deny = ["/ginux-demo/read-only"]
setid = "deny"
device_nodes = "deny"
```

Each `write_deny` entry is an absolute, normalized path. A directory entry
covers that path and every descendant on a component boundary, so
`/ginux-demo/read-only/child` is denied while
`/ginux-demo/read-only-other` is unaffected. Ginux resolves confined symlinks
before comparing the target, preventing a writable alias from bypassing the
rule. Relative paths, `..`, duplicate separators, trailing separators, and
paths outside the instance root fail validation or enforcement closed.

`setid = "deny"` prevents managed code from adding set-user-ID or set-group-ID
mode bits. Existing set-ID bits do not confer virtual or host authority.
`device_nodes = "deny"` blocks new character and block device nodes while
ordinary FIFO creation remains available when the compiled contract permits
it. Link creation inside a denied tree is blocked, including hard links and
symbolic links. These controls default to `allow` when omitted for
compatibility with older recipes; security-focused recipes should state them
explicitly.

## Bootstrap and host execution boundary

Distribution customization belongs in `[hooks].pre_boot`, not in the host
helper. Pre-boot commands execute through Ginux mediation inside the instance
root. Final `write_deny`, set-ID, and device-node restrictions activate after
all hooks finish, allowing a recipe to prepare state and then lock it down.
The Rocky example uses this phase to configure its temporary test password,
systemd compatibility, and policy demonstration paths.

Instance-visible credentials are virtual Ginux state. Independently, every
native managed process sets `PR_SET_NO_NEW_PRIVS` before executing workload
code. When the runtime starts as host root, the managed process drops to host
UID/GID 65534; when started by a non-root caller, it retains that caller's host
UID/GID. Virtual root therefore does not imply host root. Operations such as
console ownership changes are emulated inside the instance rather than
recovering host privilege.
