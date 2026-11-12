# Launch-mode performance and overhead

`make bench` and `make bench-modes` (Gates 11 and 15) run sysbench compute
loops inside a QEMU Rocky host, in instance modes. Those loops make almost no
syscalls, so they say nothing about `ginux launch`, which runs a real workload
on the host under ptrace and is bound by syscalls: path reads, stat calls,
file creation, process creation. `make bench-launch` measures that case.

## What it measures

For every row the same freestanding static fixture
(`benchmarks/launch/launch-bench-fixture.c`) runs twice, in alternating order:

- **Native:** `chroot` of the benchmark root with a fresh tmpfs mounted at
  `/work`, as uid 1000, pinned to one CPU (`taskset`), as root through
  `sudo -n`.
- **Ginux:** `ginux launch <instance.toml> <root>` with the same root, the
  configured launch mode (`config/instance-configured.toml`: profile
  `balanced`, backend `ptrace-native`, paranoid syscall control, audit on
  stderr), `memory:/work` owned storage, one vCPU, tracee uid 1000.

The root holds the fixture in `/bin`, an image tree under `/img` (a 3,072-file
tree of 16x16x12 files, a 64-entry directory, a 4 KiB file, a ustar archive of
a quarter of the tree) and an empty `/work`. Everything outside `/work` is the
read-only image; `/work` is owned storage under Ginux and tmpfs natively. The
fixture times only the loop of the class with `clock_gettime`, so process
start, launch setup and owned-file setup are excluded; the in-fixture clock
under launch tracks the real clock, which the Ginux clock row also shows.

| Row | One operation |
|---|---|
| `stat_image`, `statx_image` | `newfstatat` / `statx` of an image file |
| `openread_image` | open, read 4 KiB, close of an image file |
| `getdents_image` | open, `getdents64` to the end, close of a 64-entry image directory |
| `stat_owned`, `statx_owned`, `openread_owned`, `getdents_owned` | the same on owned storage |
| `create_owned` | create a new owned file, write 64 bytes, close (the unlink is not timed) |
| `seekread_image`, `seekread_owned` | `lseek` plus `pread64` on an open fd |
| `fork_exec_wait` | `fork`, `execve` of the tiny static `/bin/fixture noop`, `wait4` |
| `mmap_munmap` | anonymous `mmap` and `munmap` of one page |
| `clock_gettime`, `getpid` | one call through the `syscall` instruction (virtual state under launch) |
| `futex_pair` | one futex wake/wait round trip between two threads |
| `pipe_pingpong` | one byte through two pipes between a parent and a forked child |
| `walk_lstat` | find-style walk of the image tree: `getdents64` and `lstat` per entry |
| `tar_unpack` | read the archive from the image and unpack it into owned storage |
| `hash_walk` | walk the tree, read and hash every file |
| `cc_hello` | `gcc` compile and link of a tiny C file; the compiler comes from the host root (`/`, read-only image) with `/tmp` owned. Skipped with a note if no compiler is available |

Rows are reported as median ns per operation (the workload rows per tree entry,
`cc_hello` per run including launch startup) with the spread
(max-min)/median, and the ratio ginux/native.

## Supervisor cost

For every ginux row the harness also traces the supervisor itself with
`strace`, twice (P and 2P passes) so that startup and setup cancel out of the
difference, and reports per supervised workload syscall: stops
(`wait4` returning a stopped tracee), ptrace calls, and the supervisor's own
syscalls (`strace -c` total). Supervised syscalls are the ones that reach the
supervisor (entry and seccomp stops); the table also gives them per operation.
These columns show why a row moved: halving the stops per syscall or removing
per-call `/proc` opens appears here even when wall time is noisy. The trace is
slow, so counted passes are half of the timing passes.

## Why the 4% native budget does not apply here

Gate 11 holds compute-bound work to 4% of native because such work almost
never leaves user space. Under ptrace each supervised syscall costs at least a
tracee stop, a supervisor wake-up, register reads and a resume, which is
microseconds against tens of nanoseconds natively. A ratio of 20x on a stat
loop is therefore normal and says nothing about compute-bound work. These rows
are regression guards: they compare Ginux with itself over time (accepted
baseline) or with another binary (A/B), and give a per-class picture of where
the supervisor spends its time. They make no parity claim.

## Running

```sh
make build                        # the ginux binary
make bench-launch                 # all rows, 5 repetitions, writes build/bench-launch/<timestamp>/
make bench-launch BENCH_REPS=3 BENCH_SCALE=0.2 BENCH_ROWS=stat_image,walk_lstat
GINUX_BENCH_BINARY=/path/to/ginux make bench-launch
make bench-launch-compare         # latest run against benchmarks/launch/baseline.json
make bench-launch-compare RUN=build/bench-launch/<timestamp>
make bench-launch-compare BENCH_A=old=/path/ginux-old BENCH_B=new=/path/ginux-new
make test-bench-launch            # selftest of the comparison logic, no root
```

`BENCH_SCALE` multiplies each row's pass count (the full counts take a few
seconds per row on an idle machine). `LABEL=PATH@DESCRIBE` names a binary and
overrides the recorded `git describe`. The run needs passwordless `sudo -n`,
`strace`, `taskset`, `unshare` and a C compiler for the fixture.

Run it on an otherwise idle machine. The harness records the load average at
start and end, and a run whose load exceeded nproc/2 is marked **unreliable**
in the report and comparison: it is reported, never failed, and cannot be
accepted as a baseline without `--force`.

## Output

Each run writes `build/bench-launch/<timestamp>/` (and a `latest` symlink):

| File | Contents |
|---|---|
| `samples.jsonl` | One JSON line per sample (row, subject, repetition, ns, ops, ns per op, wall time, load, errors) and one per supervisor-cost measurement |
| `metadata.json` | Kernel, CPU, CPU count, load average at start and end, reliability, fixture and config hashes, root layout, and per ginux binary its path, sha256 and `git describe` |
| `results.json` | Median, min, max, spread, ratio to native and supervisor cost per row and subject |
| `report.md` | The Markdown tables |

## Reading and comparing results

`make bench-launch-compare` prints, per row, the change against the reference,
the allowed regression and the verdict, then `LAUNCH_COMPARE: PASS`, `FAIL`,
or `SKIP`.

- **Baseline mode** (one binary): median against `benchmarks/launch/baseline.json`.
  A row regresses when its median is more than its `regression_pct` slower
  (default 10%, `benchmarks/launch/budgets.conf`) or misses an optional
  absolute target (`max_ns_per_op`, `max_ratio_to_native`). If the environment
  differs from the one the baseline was accepted on (kernel, CPU model, CPU
  count, fixture, root layout, config, scale) the result is reported as
  `LAUNCH_ENVIRONMENT: INCOMPATIBLE` and no regression verdict is given, as in
  `make bench-compare`.
- **A/B mode** (two binaries): runs alternate between A and B inside each
  repetition and the rotation changes every repetition, so slow drift hits
  both. B against A is `faster` or `within noise` when the difference is
  inside the larger of the two spreads, `slower, within budget` up to the row's
  allowance, and `REGRESSION` beyond it. Supervisor stops, ptrace calls and
  supervisor syscalls per syscall are tabulated for both.

Judge a change with several repetitions: the spread column is the evidence for
whether a difference is real.

## Accepting a baseline

There is deliberately no baseline in the repository until one is taken on a
quiet machine. To accept one:

```sh
make build
make bench-launch                 # idle machine, default 5 repetitions
cat build/bench-launch/latest/report.md   # check: reliable, no FAILED rows, small spreads
make bench-launch-accept          # or RUN=build/bench-launch/<timestamp>
git add benchmarks/launch/baseline.json   # commit it deliberately, with the binary's commit
```

`bench-launch-accept` refuses unreliable runs and runs with failed rows. The
baseline records the median per row and the environment keys that must match
later. Accept a new baseline when a change is meant to move the numbers, when
the host or kernel changes, or when the fixture or root layout changes
(`ROOT_LAYOUT` in `scripts/bench-launch.py`).

## Limits

- One fixture process per sample: rows measure steady-state loops, not
  start-up. Launch start-up cost is only present in `cc_hello`.
- Owned storage is bounded by `max_objects` (set to 16384 here); the fixture
  stays far below it.
- The native chroot shares the page cache and file system with the image
  root, so image reads are warm in both runs.
- Supervisor counts depend on `strace` being able to trace the supervisor
  process; they are not compared across `strace` versions.
