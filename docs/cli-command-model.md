# Ginux CLI command model

Status: Gate 25 design checkpoint. This document inventories the current
command surfaces and proposes the operator CLI that must be approved before
implementation begins.

## Executable boundary

The installed system has four command layers:

1. `/usr/bin/ginux` is the compiled public operator command built from
   `crates/ginux-cli`; its declarative parser and generated help are the only
   supported operator interface.
2. `/usr/libexec/ginux/ginux-helper` is the privileged instance-state
   helper. It is not an operator command even where internal protocol verbs
   share names with public commands.
3. `/usr/libexec/ginux/ginux-runtime` is the freestanding `no_std` workload
   runtime built from `crates/ginux-init`. Its selectors are backend, fixture,
   and component-test entry points, not operator commands.
4. `/usr/libexec/ginux/ginux-image` is the compiled OCI acquisition and
   direct layer-expansion tool built from `crates/ginux-oci`; it is invoked by
   the helper and has no public command alias.

Gate 25 replaces only the public parser with a normal Rust host binary using
`clap`. It does not link `clap` into the freestanding runtime and does not make
the helper or runtime public.

The following inventory records are machine-checked against generated public
help and the private dispatch tables:

<!-- cli-inventory:public attach create delete edit explain export extract help import import-image inject inspect list lock set start status stop unlock validate -->
<!-- cli-inventory:helper attach authorize-attach create delete export extract import import-image inject list lock prepare-root resize resolve-network run-runtime set start status stop supervise unlock -->
<!-- cli-inventory:runtime config config-merge device-bench devices hook-plan instance instance-diff instance-explain instance-inspect instance-plan instance-validate kernel-views launch lifecycle native native-hook process process-native runtime vfs -->

## Current public command inventory

The following are the complete commands accepted by
`scripts/ginux-host-controller.sh`. “Callers” lists executable repository
callers; README and `docs/` references are documentation rather than callers.

| Command | Current operands and options | Route | Known executable callers | Proposed disposition |
|---|---|---|---|---|
| `create` | `NAME`, repeatable `--set KEY=VALUE`, one `--network ATTACHMENT`, repeatable `--forward SPEC` | privileged helper | `gate12-cli-guest.sh` | retain public |
| `import` | `NAME FILE`, same deployment options as `create` | privileged helper | `gate11-guest-setup.sh`, `gate12-cli-guest.sh`, `gate125-lock-guest.sh`, `test-gate19-native-examples.sh`, `test-systemd-interactive.exp` | retain public |
| `set` | `NAME` and at least one repeatable `--set`, `--network`, or repeatable `--forward` | privileged helper | `gate12-cli-guest.sh` | retain public |
| `edit` | `NAME` | unprivileged editor around privileged export/import | `gate12-cli-guest.sh` | retain public |
| `export` | `NAME` | privileged helper, output on stdout | `gate12-cli-guest.sh` | retain public |
| `list` | no operands | privileged helper | `gate12-cli-guest.sh`, `gate125-lock-guest.sh`, `test-systemd-interactive.exp` | retain public |
| `status` | `NAME` | privileged helper | `gate125-lock-guest.sh`, `test-systemd-interactive.exp` | retain public |
| `start` | `NAME`, flags `--attach` and `--audit` | privileged start followed by unprivileged attach when requested | `gate125-lock-guest.sh`, `expect-gate19-native-login.exp`, `test-systemd-interactive.exp` | retain public |
| `attach` | `NAME` | privileged endpoint authorization followed by unprivileged terminal relay | `test-systemd-interactive.exp` | retain public |
| `stop` | `NAME` | privileged helper | `gate125-lock-guest.sh`, `test-gate19-native-examples.sh`, `test-systemd-interactive.exp` | retain public |
| `lock` | `NAME` | privileged helper | `gate125-lock-guest.sh`, `test-systemd-interactive.exp` | retain public |
| `unlock` | `NAME` | privileged helper | `gate125-lock-guest.sh`, `test-systemd-interactive.exp` | retain public |
| `validate` | `FILE` | runtime `instance-validate` | no public-CLI test; documented workflow only | retain public; move behind normal host-library API |
| `inspect` | `FILE` | runtime `instance-inspect` | no public-CLI test; documented workflow only | retain public; move behind normal host-library API |
| `explain` | `FILE OPERATION` | runtime `instance-explain` | no public-CLI test; documented workflow only | retain public; move behind normal host-library API |
| `diff` | `LEFT RIGHT` | runtime `instance-diff` | no public-CLI test; documented workflow only | remove from the public CLI; retain runtime coverage only where needed by component tests |

The public script also accepts no global options. `--help`, `help`, and
`--version` are currently usage errors. Gate 25 adds generated global and
per-command help, `help [COMMAND]`, and version output.

The public taxonomy remains flat. A redundant `ginux instance ...` group would
reverse the accepted Gate 12.25 interface and add no disambiguation: every
public lifecycle command already operates on an instance. Help output will
group the flat commands under configuration, inspection, lifecycle,
maintenance, and recipe-diagnostic headings.

## Current privileged-helper inventory

This installed `libexec` program is entered only by the compiled public CLI,
its own supervised lifecycle, or controlled maintainer tests. Operators and
documentation must not treat its verbs as supported syntax.

| Helper command | Caller | Classification | Proposed disposition |
|---|---|---|---|
| `create`, `import`, `set`, `export`, `list`, `lock`, `unlock`, `start`, `status`, `stop` | public controller | private privileged protocol | retain behind typed public commands |
| `authorize-attach` | public controller before attach | private privilege transition | retain; fixed arity and numeric identity validation |
| `attach` | public controller after authorization | private unprivileged transport | retain until its terminal relay is moved into Rust |
| `resize` | private attach transport | private privileged terminal operation | retain |
| `prepare-root` | `stage-systemd-instance.sh`, Gate 17 setup | maintainer/test setup | retain private; not installed operator syntax |
| `resolve-network` | `test-gate975-network.sh` | component-test helper | retain test-only |
| `supervise` | helper self-invocation from `start` | private lifecycle protocol | retain |
| `run-runtime` | helper self-invocation from `supervise`; systemd/hook/benchmark probes | private lifecycle protocol | retain |

The helper keeps a strict allowlist and exact arity for every verb. Gate 25
will add a protocol version selected by the compiled CLI and helper
self-invocations so accidental invocation by an incompatible client fails
before state changes. The helper remains the only route to root-owned state.

## Current runtime command inventory

These selectors are accepted by `crates/ginux-init/src/launch.rs`. None is a
public `ginux` command after Gate 25.

| Runtime selector | Known production or test callers | Classification | Proposed disposition |
|---|---|---|---|
| no arguments | `test-intercept.sh`, Gate 1 setup tests | test-only interception fixture | retain test-only |
| `runtime ELF` | `test-runtime.sh` | component test | retain test-only |
| `config FILE` | `test-config.sh` | component test | retain test-only |
| `config-merge FILE OVERRIDE...` | instance helper; Gate 17 setup; `test-config.sh` | private production config service | retain private |
| `instance-plan FILE` | `test-config.sh` | component test | retain test-only |
| `instance-validate FILE` | current public `validate`; `test-launch.py` | transitional public bridge | remove bridge after public host implementation; retain only if a runtime regression still needs it |
| `instance-inspect FILE` | current public `inspect`; `test-launch.py` | transitional public bridge | same as `instance-validate` |
| `instance-explain FILE OPERATION` | current public `explain`; `test-launch.py` | transitional public bridge | same as `instance-validate` |
| `instance-diff LEFT RIGHT` | current public `diff`; `test-launch.py` | transitional public bridge | same as `instance-validate` |
| `hook-plan FILE` | instance helper; `test-launch.py` | private production protocol | retain private |
| `lifecycle FILE` | `test-instance.sh` | component test | retain test-only |
| `vfs FILE ROOTFS INDEX` | `test-vfs.sh` | component test | retain test-only |
| `native FILE ROOT [configured\|hold\|probe]` | instance helper; native VFS, contract, failure, and supervision tests | private production backend plus component modes | retain private; never public |
| `native-hook FILE ROOT INDEX` | instance helper; parser tests | private production backend | retain private; never public |
| `instance FILE FIXTURE` | `test-instance.sh` | component test | retain test-only |
| `process FILE` | `test-process.sh` | component test | retain test-only |
| `process-native FILE FIXTURE` | process/supervision/tracee-kill tests | component test | retain test-only |
| `devices FILE BLOCK` | `test-devices.sh` | component test | retain test-only |
| `device-bench FILE BLOCK KIND` | `bench-devices.sh` | benchmark-only | retain benchmark-only |
| `kernel-views FILE` | `test-kernel-views.sh` | component test | retain test-only |
| `launch FILE ROOT [--result-file PATH]` | `test-launch.py`; maintainer documentation | maintainer/component diagnostic | retain under `ginux-runtime`; remove operator-style `ginux launch` documentation |

The runtime will continue exact-arity validation and fail closed for unknown
selectors. It will not provide operator-oriented help, aliases, completion, or
configuration discovery.

## Other executable surfaces

These are outside the operator CLI and remain explicitly classified:

| Executable | Interface | Classification and caller |
|---|---|---|
| `ginux-vfs-index` | `ROOTFS.tar OUTPUT.index` or `assemble OUTPUT.tar OUTPUT.index LAYER...` | private image-build tool used by OCI preparation and VFS tests |
| `contract-doc` | `--write PATH` or `--check PATH` | maintainer documentation generator used by Make targets |
| `security-fuzzer` | `TARGET SECONDS ARTIFACT_DIRECTORY` | bounded test-only fuzzer used by `fuzz-security.sh` |
| `baseline-runner` | no arguments | benchmark fixture used by baseline targets |
| `managed-payload`, `runtime-fixture`, `process-native-fixture` | fixture-specific arguments | test payloads, never control-plane commands |
| `/usr/libexec/ginux/ginux-image` | digest-qualified image reference, OCI cache, and destination root | compiled private image acquisition and direct layer-expansion tool called by the instance helper |

## Proposed public command specification

The compiled `ginux` binary will use `clap` derive declarations as the single
source for parsing, validation, help, and version metadata.

```text
Usage: ginux <COMMAND>

Configure instances:
  create    Create an instance from the installed default recipe
  import    Create or replace an instance from a recipe
  set       Atomically change recipe overrides or host deployment settings
  edit      Edit, validate, and atomically apply an instance recipe
  export    Write an instance recipe to standard output

Inspect instances:
  list      List instances
  status    Show instance state and paths

Run instances:
  start     Start an instance
  attach    Attach to a running instance console
  stop      Stop an instance

Maintain instances:
  lock      Enforce the configured contract for a stopped instance
  unlock    Enable bounded maintenance access for a stopped instance

Inspect recipes:
  validate  Validate and compile a recipe without changing state
  inspect   Show a recipe's normalized effective contract
  explain   Explain one operation's effective contract decision
Options:
  -h, --help       Print help
  -V, --version    Print version
```

Exact command shapes remain:

```text
ginux create NAME [--set KEY=TOML_VALUE]... [--network ATTACHMENT]
                  [--forward SPEC]...
ginux import NAME FILE [--set KEY=TOML_VALUE]... [--network ATTACHMENT]
                       [--forward SPEC]...
ginux set NAME (--set KEY=TOML_VALUE | --network ATTACHMENT |
                --forward SPEC)...
ginux edit NAME
ginux export NAME
ginux list
ginux status NAME
ginux start NAME [--attach] [--audit]
ginux attach NAME
ginux stop NAME
ginux lock NAME
ginux unlock NAME
ginux validate FILE
ginux inspect FILE
ginux explain FILE OPERATION
```

`--set` and `--forward` preserve command-line order. `--network` occurs at
most once. `--forward none` conflicts with every other `--forward` value.
`set` requires at least one change. `NAME`, `FILE`, and `OPERATION` remain
positional. No compatibility alias using `--config` or an `instance` command
group is added.

## Errors, output, and compatibility

- `--help`, `help [COMMAND]`, and `--version` write to stdout and return 0.
- Public parse errors write one concise diagnostic plus relevant usage to
  stderr and return 2. This intentionally standardizes the shell controller's
  current generic exit 64 for malformed public syntax.
- Operational failures preserve the helper or runtime result; Gate 25 does not
  collapse not-found, unavailable, invalid-state, or software-failure results
  into parser errors.
- A rejected invocation performs no sudo call and no state mutation.
- Existing instance recipes, deployment state, image caches, locks, roots,
  console state, and lifecycle semantics are unchanged.
- Existing public command names and successful argument forms remain valid.
  Internal selectors receive no public compatibility aliases.
- Commands not present today—such as `delete`, `restart`, `logs`, image
  management, or shell-completion generation—are outside Gate 25 rather than
  being silently invented during the parser migration.

## Proposed implementation boundary

1. Add a normal host `ginux-cli` Rust binary using `clap`; keep the existing
   freestanding binary installed only as `ginux-runtime`.
2. Put the public command enum, arguments, conflicts, help headings, and
   version in one declarative module tested without root or QEMU.
3. Route recipe diagnostics through reusable host-side library functions, not
   through public knowledge of runtime selectors.
4. Route state-changing commands through the versioned private helper
   protocol. Parse and reject malformed input before invoking sudo.
5. Preserve the current attach privilege transition and terminal behavior;
   move its public orchestration into Rust while leaving only narrow endpoint
   authorization and resize operations in the helper.
6. Install the Rust CLI at `/usr/bin/ginux`; install the freestanding runtime,
   compiled image tool, and privileged helper under `/usr/libexec/ginux/`.
7. Add generated-help snapshots, parser/negative-state tests, command-inventory
   consistency checks, installation assertions, and the existing lifecycle
   and systemd regressions before removing the shell public controller.

## Design decisions requiring approval

Implementation must not begin until the human approves these points:

1. Keep the accepted flat top-level command taxonomy; do not reintroduce
   `ginux instance ...`.
2. Retain every currently successful public command shape, while adding
   generated help/version behavior and standardizing public parse failures to
   exit 2, except for the explicitly removed `diff` command.
3. Keep production backend selectors such as `native`, `native-hook`,
   `config-merge`, and `hook-plan` only in the private runtime protocol.
4. Keep component and benchmark selectors available only through the private
   runtime binary for deterministic tests; do not expose them in public help.
5. Do not add compatibility aliases or new product commands in this gate.
6. Version the private CLI/helper protocol so an incompatible caller fails
   before any privileged state change.

The human approved this design on 2026-11-13 with one correction: remove
`diff` from the public operator CLI.

## Interim lifecycle commands

The commands and options in this section were added after the Gate 25
design above, which stays as approved. They let a non-interactive program
drive the instance lifecycle without private selectors. Every addition is
additive: no existing command changes its arguments, output, exit status or
helper argument vector when none of these forms is used, and the helper keeps
protocol version 1. The inventory records at the top of this document include
them.

### Shapes

```text
ginux [--state-root DIR [--run-root DIR]] COMMAND ...
ginux start NAME [--audit] --wait [--stream-console [--full-audit]]
ginux status NAME [--format text|json]
ginux extract NAME --output FILE [--max-bytes N] [--max-members N]
                  [--max-path N] PATH...
ginux delete NAME
ginux inject NAME --input FILE --into PATH [--max-bytes N] [--max-members N]
                  [--max-path N]
ginux import-image PATH
```

| Command | Behaviour | Help heading |
|---|---|---|
| `start --wait` | Foreground start tied to the calling process; stdout stays empty; conflicts with `--attach` | Run instances |
| `start --wait --stream-console` | As `start --wait`, and stdout carries exactly the instance console output as it appears; requires `--wait`, conflicts with `--attach` | Run instances |
| `start --wait --stream-console --full-audit` | As `start --wait --stream-console`, and every run, including one that exits 0, ends with the whole audit log (its last 16 MiB) on stderr; requires `--stream-console` | Run instances |
| `status --format json` | One JSON object on one line; `text` (the default) is the existing output | Inspect instances |
| `extract` | Writes named absolute directories of a stopped instance as one tar archive to a new `FILE` | Inspect instances |
| `delete` | Removes a stopped instance and all of its state | Configure instances |
| `inject` | Unpacks an uncompressed tar archive into one directory of a stopped instance; prints nothing | Configure instances |
| `import-image` | Adds an OCI image layout (directory or uncompressed tar of one) to the image cache; prints the manifest digest | Manage images |
| `--state-root`, `--run-root` | Global options; select another persistent and transient state root | all commands |

Parse rules (violations exit 2 before any sudo call):

- `--stream-console` requires `--wait` and conflicts with `--attach`.
- `--full-audit` requires `--stream-console`.
- `--state-root` and `--run-root` are absolute, contain only
  `[A-Za-z0-9_./-]`, have no empty, `.` or `..` component and are at most 256
  bytes. `--run-root` requires `--state-root`; `--state-root` alone implies
  `--run-root DIR/run`. Either may appear before or after the command name.
- `extract` paths are absolute with no empty, `.` or `..` component and no
  longer than `--max-path` bytes; `/` is allowed. Duplicates and paths below
  another listed path are dropped and the rest are sorted bytewise.
  `--output` is required. Bounds are positive decimal integers; defaults are
  `--max-bytes 68719476736` (64 GiB), `--max-members 1000000` and
  `--max-path 4096`. The directory depth bound is fixed at 256.
- `inject` takes `--input FILE` and `--into PATH`, both required. `--into` is
  one absolute directory path inside the instance (`/` allowed) with no empty,
  `.` or `..` component, no NUL and no more than `--max-path` bytes. Bounds are
  positive decimal integers with the same defaults as `extract`. `FILE` is read
  with the caller's own rights and must be a regular file: a symbolic link
  (also as the final component), directory, FIFO, socket or device exits 65
  before sudo, a missing file exits 66 and a gzip-compressed archive exits 65.
  The archive is streamed unchanged to the helper's standard input; members
  are validated by the image tool, not by the CLI. The privileged helper never
  opens `FILE`.
- `import-image` reads `PATH` with the caller's own rights. A directory may
  contain only `oci-layout`, `index.json`, `blobs/`, `blobs/sha256/` and
  regular files named `blobs/sha256/<64 lowercase hex>`; anything else,
  including a symbolic link, exits 65 before sudo. A gzip-compressed archive
  exits 65. The privileged helper never opens `PATH`.

### `inject`

`ginux inject NAME --input FILE --into PATH` unpacks the archive `FILE` into
the directory `PATH` of the instance `NAME`. It prints nothing on success and
writes one `ginux: inject: ...` diagnostic to standard error on failure.

- State requirement: the instance must be stopped. A running instance exits
  73 and nothing is changed.
- The CLI sends the archive to the helper's standard input; the image tool
  validates every member (types, names, modes, bounds) and writes beneath the
  instance root without following links. Member types and names the image
  tool refuses, and a `PATH` that exists but is not a directory, are reported
  with the exit codes below. `inject` creates `PATH` and any missing parents
  inside the instance root; it does not require them to exist.
- Existing directories are left untouched: their mode and modification time do
  not change. Only directories the command creates get the mode and
  modification time recorded in the archive.
- Member names must be relative and must not start with `./`. After the
  end-of-archive marker, any remaining data must be all zero bytes; anything
  else exits 65.
- The memory used to hold member names is bounded: a hostile archive of many
  long names exits 76.
- Before the first write the image tool probes `openat2`; a kernel without it
  exits 69 and nothing is changed.
- Not atomic: the archive is applied member by member. After any failure
  other than a refusal before the first write (usage, 66, 69, 73), the
  instance may hold part of the archive; delete the instance and create it
  again rather than starting it.

### Helper protocol additions

```text
ginux-helper --protocol 1 [--state-root DIR --run-root DIR] VERB ARG...
  delete NAME
  extract NAME --max-bytes N --max-members N --max-path N PATH...   (tar on stdout)
  inject NAME --max-bytes N --max-members N --max-path N PATH       (tar on stdin)
  import-image                                                      (tar on stdin, digest on stdout)
  start NAME [--audit] --wait CALLER_PID CALLER_START [--stream-console [--full-audit]]
  status NAME --format json
```

The CLI forwards the roots after `--protocol 1` in every helper call,
including the unprivileged attach transport and both halves of `edit`, and
forwards nothing when no root option is given. It always sends the three
`extract` and `inject` bounds, in that order. An older helper rejects each addition with usage status 64
before any state change. When a state or run root is passed, every verb
(including the privileged halves of `edit` and `attach`) maps a helper exit 64
without a root refusal to `ginux: the installed helper does not support
--state-root` and exit 69. Without roots, `delete`, `extract`, `inject`, `import-image`
and `status --format json` map a 64 to `ginux: the installed helper does not
support FEATURE` and exit 69. A current helper also exits 64 when it refuses a
root (`untrusted state root:` or `untrusted run root:` on its standard error,
which the CLI relays); that status is passed through unchanged. For
`start --wait` a 64 cannot be told from a workload exit status and is passed
through unchanged, together with the helper's own usage message.

Helper standard error is relayed to the terminal with control bytes (every
C0 and C1 control except newline and tab, DEL) and invalid UTF-8 replaced by
visible `\xNN` escapes, so workload-controlled names cannot drive the
terminal. Instance names must not start with `.`.

### Exit codes

| Code | Meaning | Used by |
|---|---|---|
| 0 | success | all |
| 2 | parse error, no sudo call | all |
| 64 | helper usage passed through: `start --wait`, or an untrusted state or run root | helper |
| 65 | invalid state, invalid layout or digest, unsupported member type, path not a directory; for `inject` also an invalid archive or a `FILE` that is not an uncompressed regular file | delete, extract, import-image, inject |
| 66 | instance, extract path, `inject` input file or import input not found; for `inject`, also an instance whose root is missing (`PATH` itself is created, never reported missing) | all |
| 69 | unsupported: older helper (any verb when a root is passed, else `delete`, `extract`, `inject`, `import-image`, `status --format json`), missing image tool, `openat2` unavailable | all |
| 70 | internal failure; for `start --wait`, outcome `supervisor-error` | all |
| 73 | instance running or already running | delete, extract, inject, start |
| 74 | output I/O error, including an existing `--output` file; for `inject`, an input read or helper write error | extract, import-image, inject |
| 75 | member changed during export (retryable); for `inject`, changed during injection | extract, inject |
| 76 | extract or inject bound exceeded (bytes, members, path length, depth, link length) | extract, inject |
| 0-255 | `start --wait` only: workload exit status, or 128+signal | start --wait |

`start --wait` statuses overlap by nature; a caller disambiguates them with
`status --format json`. An older helper rejects `--stream-console` and
`--full-audit` with usage status 64, passed through like every `start --wait` status.

### Foreground start and the outcome record

`start --wait` passes the calling process's PID and start time (field 22 of
`/proc/PID/stat`) to the helper, which stops the instance when that process
disappears. The CLI does not exec sudo, so it stays alive as that process; it
relays `SIGINT`, `SIGTERM`, `SIGHUP` and `SIGQUIT` to sudo and returns the
helper's status. sudo does not relay a signal sent from its own process group,
so if the helper has not finished one second after a relayed signal, the CLI
exits on that signal itself; the helper then sees its caller gone and stops
the instance within about 7.5 seconds. Stopping by caller death, signal or a
force-escalated `stop` records `supervisor-error`. Callers should read the
outcome with `status --format json` rather than from the CLI's own exit status.

The outcome of the last run is one line in exactly this form:

```text
{"version":1,"outcome":"exited","code":3,"signal":null,"generation":null}
{"version":1,"outcome":"signaled","code":null,"signal":9,"generation":null}
{"version":1,"outcome":"supervisor-error","code":null,"signal":null,"generation":null}
```

`status --format json` prints:

```text
{"version":1,"name":"N","state":"running|stopped","contract":"locked|unlocked",
 "pid":123|null,"outcome":<record>|null,"paths":{"config":"...","deployment":"...",
 "console_log":"...","audit_log":"...","root":"..."}}
```

on one line. `outcome` is null before the first start, while running, after a
start that failed its checks, and after a run whose record could not be
written. The log paths name root-only files (see below); a caller that is not
root receives console output through `start --wait --stream-console`.

### Console streaming

With `--stream-console` the helper copies the bytes appended to the
instance's console log to its own standard output while the run lasts: it
opens the log once, as root, refusing anything but a regular file and never
following a symbolic link, polls it every 100 ms from the offset it reached,
and writes each chunk as it reads it. When the run ends, including by caller
death, a relayed signal or teardown, it copies the remainder exactly once, so
no tail is lost. Standard output carries nothing else. The CLI inherits that
standard output to its own, so the bytes reach the caller unchanged and
unbuffered; they are workload output and are not sanitized. Helper standard
error goes through the sanitizing relay described above.

When the run does not end with exit code 0 (a non-zero code, `signaled`,
`supervisor-error` or no valid record), the helper then writes to standard
error the line `ginux: audit log (last N bytes):` followed by the last N bytes
of the audit log, N at most 65536 (`ginux: the audit log is empty` when N is
0), then three summary lines: `ginux: supervisor exit status: S`, `ginux:
runtime command exit status: S` (or `none recorded` when the supervisor ended
before the runtime command did) and `ginux: runtime outcome record: present`,
`empty` or `missing`. The supervisor's own standard error is appended to the
audit log, so an error that ends it before the runtime starts is in that
tail. A run that exits 0 never prints the audit log, unless `--full-audit` is
given. The exit status and the outcome record are the same as without the
option.

With `--full-audit` the helper writes the same marker line, audit log and
summary lines after every run, including one that exits 0, and N is at most
16777216 (16 MiB) instead of 65536, so a log of up to 16 MiB is delivered
whole. When the log is longer, the last 16 MiB are written and the marker line
is followed by `ginux: audit log truncated: the first M of T bytes are left
out`. A caller separates the audit log from the console output as before:
everything after the first marker line on standard error is the audit log and
the summary (the audit log itself may contain a line that looks like a
marker, so only the first one counts).

### State layout

| Path (default roots) | Content |
|---|---|
| `/run/ginux/instances/NAME/outcome` | Last outcome record, root 0600; removed by the next `start` and by `delete` |
| `/run/ginux/instances/NAME/result.runtime` | Record written by the runtime, validated before it becomes `outcome`; created empty when the run starts and filled only at the runtime's normal exit, so an empty or incomplete file means `supervisor-error` |
| `/var/lib/ginux/instances/NAME` | Root-owned, mode 0700 whatever the helper's umask (set at create and import, and again at every `start`); holds the recipe, deployment state, root, `console.log` and `audit.log` (both 0600, recreated by every `start`) |
| `/var/lib/ginux/work/instance.NAME.lock` | Per-instance lock taken by import, create, start, delete, extract and inject |
| `/var/lib/ginux/instances/.delete:*` | Trash of an interrupted delete; swept after one hour |
| `/var/lib/ginux/cache/roots/sha256/HEX` | Pristine expansion reused by reflink copy, only on reflink-capable filesystems |

With `--state-root DIR --run-root RDIR` the same layout lives under `DIR` and
`RDIR`. Each existing component of either root must be a root-owned directory
that is not group- or other-writable; otherwise the helper refuses it with
`untrusted state root: DIR (REASON)`.
