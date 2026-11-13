SHELL := /bin/sh

X86_TARGET := x86_64-unknown-linux-gnu
BUILD_DIR := build
GINUX := target/$(X86_TARGET)/release/ginux
PAYLOAD := target/$(X86_TARGET)/release/managed-payload
BASELINE := target/$(X86_TARGET)/release/baseline-runner
RUNTIME_FIXTURE := target/$(X86_TARGET)/release/runtime-fixture
PROCESS_NATIVE_FIXTURE := target/$(X86_TARGET)/release/process-native-fixture

.PHONY: doctor host-image-fetch host-image-verify host-boot-test host-run host-reset test-host-lifecycle image-helper-fetch image-prepare instance-image-fetch instance-image-verify instance-image-prepare systemd-image-fetch systemd-image-verify systemd-image-prepare test-image test-oci-image test-generic-oci test-oci-layers test-vfs test-native-vfs image-cache-clean build check-name check-instance-terminology check test-ci-changes contract-doc test-contract test-contract-runtime test test-unit test-intercept test-runtime test-config test-instance test-instance-terminology test-process build-process-fixtures test-process-native test-devices test-kernel-views test-systemd test-systemd-live test-systemd-interactive test-multi-instance test-gate19-native-examples test-gate975-network test-gate975-hooks test-gate125-lock test-cgroup test-block test-network test-security test-recovery check-architecture-doc check-security-doc fuzz-security test-bench-compare test-gate15-report bench-prepare bench bench-baseline bench-compare bench-systemd bench-report bench-block bench-network bench-modes-prepare bench-modes bench-modes-report build-bench-launch-fixture bench-launch bench-launch-compare bench-launch-accept test-bench-launch demo-gate-1 demo-gate-2 demo-gate-3 demo-gate-4 demo-gate-5 demo-gate-6 demo-gate-7 demo-gate-8 demo-gate-9 demo-gate-9.5 demo-gate-9.75 demo-gate-10 demo-gate-10.25 demo-gate-10.5 demo-gate-11 demo-gate-12 demo-gate-12.1 demo-gate-12.25 demo-gate-12.5 demo-gate-13 demo-gate-15 demo-gate-17 demo-gate-19 clean

doctor:
	@./scripts/doctor.sh

host-image-fetch:
	@./scripts/fetch-rocky-host.sh

host-image-verify:
	@./scripts/verify-rocky-host.sh

host-boot-test: build
	@./scripts/with-rocky-host.sh ./scripts/check-rocky-host.sh

image-helper-fetch:
	@./scripts/fetch-rocky-instance-helper.sh

image-prepare:
	@./scripts/prepare-rocky-instance.sh

instance-image-fetch:
	@./scripts/fetch-rocky-oci.sh

instance-image-verify:
	@./scripts/verify-rocky-oci.sh

instance-image-prepare:
	@./scripts/prepare-rocky-oci.sh

systemd-image-fetch:
	@GINUX_OCI_CONFIG_FILE=./config/rocky-systemd-oci.env ./scripts/fetch-rocky-oci.sh

systemd-image-verify:
	@GINUX_OCI_CONFIG_FILE=./config/rocky-systemd-oci.env ./scripts/verify-rocky-oci.sh

systemd-image-prepare:
	@GINUX_OCI_CONFIG_FILE=./config/rocky-systemd-oci.env ./scripts/prepare-rocky-oci.sh

test-image:
	@./scripts/test-rocky-instance.sh

test-oci-image:
	@./scripts/test-rocky-oci.sh

test-oci-layers:
	@./scripts/test-oci-layers.sh

image-cache-clean:
	rm -rf build/cache/instance

build:
	cargo build -p ginux-init --target $(X86_TARGET) --release
	cargo build -p managed-payload --target $(X86_TARGET) --release
	cargo build -p baseline-runner --target $(X86_TARGET) --release
	cargo build -p runtime-fixture --target $(X86_TARGET) --release
	cargo build -p process-native-fixture --target $(X86_TARGET) --release

build-process-fixtures:
	mkdir -p .artifacts/process
	@for scenario in syscall_abi untraced_clone shared_pipe wait_status thread_reuse denied_host_memory inherited_fds thread_exec unused_parent_tid exec_failure copied_files shared_exec clone_tid child_signal nonblocking_wait vfork concurrent_wait remaining_wait sigpipe segv kill_badsig thread_segv thread_term parked_kill parked_term ro_status bad_status bad_rusage straddle_status alias_writes; do \
		$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -DCASE_$$scenario tests/fixtures/process-review-fixture.c -o .artifacts/process/$$scenario || exit; \
	done
	$(CC) -nostdlib -static tests/fixtures/process-exec-target.S -o .artifacts/process/process-exec-target

test-process-native: build build-process-fixtures
	python3 scripts/test-process-native.py $(GINUX) .artifacts/process $(PROCESS_NATIVE_FIXTURE) $(SCENARIO)

check-name:
	@./scripts/check-name.sh

check-instance-terminology:
	@./scripts/check-instance-terminology.sh

test-ci-changes:
	@./scripts/test-ci-changes.sh

check: check-name check-instance-terminology
	cargo fmt --check
	cargo clippy -p ginux-contract --all-targets -- -D warnings
	cargo clippy -p ginux-core --all-targets -- -D warnings
	cargo clippy -p ginux-instance --all-targets -- -D warnings
	cargo clippy -p ginux-devices --all-targets -- -D warnings
	cargo clippy -p ginux-init --bin ginux --target $(X86_TARGET) --release -- -D warnings
	cargo clippy -p ginux-kernel-views --all-targets -- -D warnings
	cargo clippy -p ginux-process --all-targets -- -D warnings
	cargo clippy -p managed-payload --bin managed-payload --target $(X86_TARGET) --release -- -D warnings
	cargo clippy -p baseline-runner --bin baseline-runner --target $(X86_TARGET) --release -- -D warnings
	cargo clippy -p ginux-runtime --all-targets -- -D warnings
	cargo clippy -p ginux-vfs --all-targets -- -D warnings
	cargo clippy -p ginux-vfs-index --all-targets -- -D warnings
	cargo clippy -p security-fuzzer --all-targets -- -D warnings
	cargo clippy -p runtime-fixture --bin runtime-fixture --target $(X86_TARGET) --release -- -D warnings
	cargo clippy -p process-native-fixture --bin process-native-fixture --target $(X86_TARGET) --release -- -D warnings

contract-doc:
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo run -q -p ginux-contract --bin contract-doc -- --write docs/abi-contract-coverage.md

test-contract:
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-contract -p ginux-instance
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo run -q -p ginux-contract --bin contract-doc -- --check docs/abi-contract-coverage.md

test-contract-runtime: build instance-image-prepare
	@./scripts/with-rocky-host.sh ./scripts/test-contract-runtime.sh

test-unit:
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-core
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-contract
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-instance
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-devices
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-runtime
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-process
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-vfs
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-kernel-views

test-intercept: build
	@./scripts/with-rocky-host.sh ./scripts/test-intercept.sh

.PHONY: build-gate1-fixture test-gate1-setup
build-gate1-fixture:
	mkdir -p .artifacts/gate1
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror -DDENY_PTRACE tests/fixtures/gate1-setup-fixture.c -o .artifacts/gate1/deny-ptrace
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/gate1-setup-fixture.c -o .artifacts/gate1/payload

test-gate1-setup:
	python3 scripts/test-gate1-setup.py $(GINUX) .artifacts/gate1/deny-ptrace .artifacts/gate1/payload

test-runtime: build
	@./scripts/with-rocky-host.sh ./scripts/test-runtime.sh

test-config: build
	@./scripts/with-rocky-host.sh ./scripts/test-config.sh

test-instance: build
	@./scripts/with-rocky-host.sh ./scripts/test-instance-suite.sh

test-instance-terminology:
	@./scripts/test-instance-terminology.sh

test-process: build
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-process
	@./scripts/with-rocky-host.sh ./scripts/test-process.sh

test-devices: build
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-devices registry
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-devices pseudo_devices
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-devices conflicts_ioctls
	@./scripts/with-rocky-host.sh ./scripts/test-devices.sh

test-kernel-views: build
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-kernel-views
	@./scripts/with-rocky-host.sh ./scripts/test-kernel-views.sh

test-systemd: build systemd-image-prepare
	@ROCKY_NETWORK_RESTRICT=on ./scripts/with-rocky-host.sh ./scripts/test-systemd.sh

test-gate19-native-examples: build
	@ROCKY_NETWORK_RESTRICT=off ROCKY_SSH_PORT=22419 ROCKY_PID_FILE=build/rocky-gate19-host.pid ROCKY_SERIAL_LOG=build/rocky-gate19-host-serial.log ROCKY_OVERLAY_DISK=build/rocky-gate19-host-overlay.qcow2 ./scripts/with-rocky-host.sh ./scripts/test-gate19-native-examples.sh

test-generic-oci:
	@./scripts/test-generic-oci.sh

test-systemd-live: build systemd-image-prepare
	@ROCKY_NETWORK_RESTRICT=off ./scripts/with-rocky-host.sh ./scripts/test-systemd-live.sh

test-systemd-interactive: build
	@./scripts/test-systemd-interactive.exp

test-multi-instance: build systemd-image-prepare
	@ROCKY_SSH_PORT=22417 ROCKY_PID_FILE=build/rocky-gate17-host.pid ROCKY_SERIAL_LOG=build/rocky-gate17-host-serial.log ROCKY_OVERLAY_DISK=build/rocky-gate17-host-overlay.qcow2 ROCKY_NETWORK_RESTRICT=on ROCKY_VCPUS=4 ROCKY_MEMORY_MIB=4096 ./scripts/with-rocky-host.sh ./scripts/test-multi-instance.sh

test-gate975-network: build systemd-image-prepare
	@ROCKY_NETWORK_RESTRICT=on ./scripts/with-rocky-host.sh ./scripts/test-gate975-network.sh

test-gate975-hooks: build systemd-image-prepare
	@ROCKY_NETWORK_RESTRICT=on ./scripts/with-rocky-host.sh ./scripts/test-gate975-hooks.sh

test-gate125-lock: build
	@ROCKY_NETWORK_RESTRICT=on ./scripts/with-rocky-host.sh ./scripts/test-gate125-lock.sh

test-cgroup:
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-kernel-views cgroup::

test-block:
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-devices block_

test-network:
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/unit cargo test -p ginux-devices network_

host-run: build
	@./scripts/run-host.sh

host-reset:
	@./scripts/reset-rocky-host.sh

test-host-lifecycle:
	@./scripts/test-host-lifecycle.sh

test-vfs: build instance-image-prepare
	@./scripts/with-rocky-host.sh ./scripts/test-vfs.sh

test-native-vfs: build instance-image-prepare
	@./scripts/with-rocky-host.sh ./scripts/test-native-vfs.sh

test: check test-gate15-report test-host-lifecycle test-unit test-intercept test-runtime test-config test-instance test-image test-devices test-process test-kernel-views

fuzz-security:
	./scripts/fuzz-security.sh

check-architecture-doc:
	@./scripts/check-architecture-doc.sh

check-security-doc: check-architecture-doc
	@./scripts/check-security-boundary.sh

test-security: check-security-doc
	RUSTFLAGS='' CARGO_TARGET_DIR=.artifacts/security cargo test -p ginux-contract -p ginux-instance -p ginux-devices -p ginux-runtime -p ginux-vfs -p ginux-kernel-views
	@$(MAKE) fuzz-security
	@$(MAKE) test-native-vfs
	@$(MAKE) test-contract-runtime
	@$(MAKE) test-devices
	@$(MAKE) test-kernel-views
	@printf '%s\n' 'test-security: PASS (malformed input, fuzz, authority, denial, host-view, range, exhaustion, teardown)'

test-recovery:
	@$(MAKE) test-native-vfs
	@$(MAKE) test-contract-runtime
	@$(MAKE) test-systemd
	@printf '%s\n' 'test-recovery: PASS (startup failure, supervisor loss, forced stop, audit bound, controlled shutdown)'

bench-prepare: build
	@ROCKY_NETWORK_RESTRICT=off ./scripts/with-gate11-host.sh ./scripts/prepare-gate11-benchmark.sh

bench-baseline: build
	@./scripts/with-gate11-host.sh ./scripts/collect-gate11-baseline.sh

bench-block: build
	@./scripts/with-rocky-host.sh ./scripts/bench-devices.sh block

bench-network: build
	@./scripts/with-rocky-host.sh ./scripts/bench-devices.sh network

bench: bench-baseline bench-compare

bench-compare:
	@./scripts/bench-compare.sh

test-bench-compare:
	@./scripts/test-bench-compare.sh

bench-systemd: build systemd-image-prepare
	@ROCKY_NETWORK_RESTRICT=on ./scripts/with-rocky-host.sh ./scripts/bench-systemd.sh

bench-report:
	@./scripts/bench-report.sh

test-gate15-report:
	@./scripts/test-gate15-report.sh

bench-modes-prepare: bench-prepare

bench-modes: build
	@./scripts/with-gate11-host.sh ./scripts/collect-gate15-matrix.sh

bench-modes-report:
	@./scripts/gate15-report.sh

# Launch-mode overhead: `ginux launch` against a native chroot of the same
# root, per syscall class and build-shaped workload. See docs/launch-performance.md.
BENCH_LAUNCH_FIXTURE := $(BUILD_DIR)/bench-launch/launch-bench-fixture

build-bench-launch-fixture:
	mkdir -p $(BUILD_DIR)/bench-launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror benchmarks/launch/launch-bench-fixture.c -o $(BENCH_LAUNCH_FIXTURE)

# Variables: GINUX_BENCH_BINARY (default $(GINUX)), BENCH_REPS, BENCH_SCALE, BENCH_ROWS.
bench-launch: build-bench-launch-fixture
	@python3 scripts/bench-launch.py run --ginux "current=$${GINUX_BENCH_BINARY:-$(GINUX)}" \
		--reps "$${BENCH_REPS:-5}" --scale "$${BENCH_SCALE:-1}" $${BENCH_ROWS:+--rows "$$BENCH_ROWS"}

# Without BENCH_A and BENCH_B: compare build/bench-launch/latest (or RUN=dir) with
# benchmarks/launch/baseline.json. With both (LABEL=PATH): run the two binaries
# alternately and compare them.
bench-launch-compare: build-bench-launch-fixture
	@if test -n "$${BENCH_A:-}" && test -n "$${BENCH_B:-}"; then \
		python3 scripts/bench-launch.py ab --a "$$BENCH_A" --b "$$BENCH_B" \
			--reps "$${BENCH_REPS:-5}" --scale "$${BENCH_SCALE:-1}" $${BENCH_ROWS:+--rows "$$BENCH_ROWS"}; \
	else python3 scripts/bench-launch.py compare $${RUN:-}; fi

bench-launch-accept:
	@python3 scripts/bench-launch.py accept $${RUN:-}

test-bench-launch:
	@python3 scripts/bench-launch.py selftest

demo-gate-11: doctor build
	@./scripts/demo-gate-11.sh

demo-gate-1: doctor build
	@./scripts/with-rocky-host.sh ./scripts/demo-gate-1.sh

demo-gate-2: doctor
	@./scripts/demo-gate-2.sh

demo-gate-3: doctor build
	@./scripts/with-rocky-host.sh ./scripts/demo-gate-3.sh

demo-gate-4: doctor build
	@./scripts/with-rocky-host.sh ./scripts/demo-gate-4.sh

demo-gate-5: doctor build instance-image-prepare
	@./scripts/with-rocky-host.sh ./scripts/demo-gate-5.sh

demo-gate-6: doctor build
	@./scripts/with-rocky-host.sh ./scripts/demo-gate-6.sh

demo-gate-7: doctor build
	@./scripts/with-rocky-host.sh ./scripts/demo-gate-7.sh

demo-gate-9.5: doctor build
	@./scripts/test-systemd-interactive.exp
	@printf '%s\n' 'GATE9.5: PASS (create-time OCI cache, configured init, job control, procfs, attach lifecycle, shutdown)'

demo-gate-9.75: doctor build systemd-image-prepare
	@ROCKY_NETWORK_RESTRICT=on ./scripts/with-rocky-host.sh ./scripts/demo-gate975.sh

demo-gate-8: doctor build
	@./scripts/with-rocky-host.sh ./scripts/demo-gate-8.sh

demo-gate-9: doctor build systemd-image-prepare
	@./scripts/demo-gate-9.sh

demo-gate-10: doctor
	@$(MAKE) test-contract
	@$(MAKE) test-config
	@$(MAKE) test-contract-runtime
	@$(MAKE) test-systemd
	@./scripts/demo-gate-10.sh

demo-gate-10.25: doctor check-instance-terminology
	@$(MAKE) test-config
	@./scripts/test-systemd-interactive.exp
	@printf '%s\n' 'GATE10.25: PASS (instance CLI, schema, persistence, lifecycle, and clean-break rejection)'

demo-gate-10.5: doctor
	@$(MAKE) test-contract
	@$(MAKE) test-config
	@$(MAKE) test-contract-runtime
	@$(MAKE) test-systemd
	@./scripts/demo-gate-10.5.sh

demo-gate-12: doctor
	@$(MAKE) test-contract
	@$(MAKE) test-config
	@$(MAKE) test-instance
	@$(MAKE) test-contract-runtime
	@./scripts/demo-gate-12.sh

demo-gate-12.1: doctor build systemd-image-prepare
	@ROCKY_NETWORK_RESTRICT=on ./scripts/with-rocky-host.sh ./scripts/demo-gate-12.1.sh

demo-gate-12.25: doctor build
	@ROCKY_NETWORK_RESTRICT=on ./scripts/with-rocky-host.sh ./scripts/test-gate12-cli.sh
	@./scripts/demo-gate-12.25.sh

demo-gate-12.5: doctor build
	@ROCKY_NETWORK_RESTRICT=on ./scripts/with-rocky-host.sh ./scripts/test-gate125-lock.sh
	@./scripts/demo-gate-12.5.sh

demo-gate-13: doctor check-security-doc build instance-image-prepare
	@GINUX_FUZZ_SECONDS=1 $(MAKE) fuzz-security
	@$(MAKE) test-native-vfs
	@$(MAKE) test-contract-runtime
	@./scripts/demo-gate-13.sh

demo-gate-15: doctor build
	@./scripts/demo-gate-15.sh

demo-gate-17: doctor build systemd-image-prepare
	@printf '%s\n' 'Gate 17: boot two Rocky systemd instances concurrently and verify isolation.'
	@printf '%s\n' 'Expected: independent state, overlays, virtual kernel views, contracts, lifecycle, and translated ports.'
	@printf '%s\n' 'Expected networking: one ordinary shared-port winner/conflict pair; both translated binds succeed.'
	@ROCKY_SSH_PORT=22417 ROCKY_PID_FILE=build/rocky-gate17-host.pid ROCKY_SERIAL_LOG=build/rocky-gate17-host-serial.log ROCKY_OVERLAY_DISK=build/rocky-gate17-host-overlay.qcow2 ROCKY_NETWORK_RESTRICT=on ROCKY_VCPUS=4 ROCKY_MEMORY_MIB=4096 ./scripts/with-rocky-host.sh ./scripts/test-multi-instance.sh

demo-gate-19:
	@printf '%s\n' 'Gate 19: validate readable hooks and five operator-facing instance recipes.'
	@cargo test -q -p ginux-instance
	@printf '%s\n' '  minimal Rocky systemd: config/instance-rocky-systemd.toml'
	@printf '%s\n' '  constrained agent:    config/examples/agent-workspace.toml'
	@printf '%s\n' '  Ubuntu blank CMS:     config/examples/network-service.toml'
	@printf '%s\n' '  paranoid shell:       config/examples/paranoid-shell.toml'
	@printf '%s\n' '  Alpine native init:   config/examples/alpine-native.toml'
	@printf '%s\n' 'Gate 19 example validation: PASS'

clean:
	cargo clean
	@./scripts/clean-build.sh

.PHONY: build-launch-fixture test-launch test-native-supervision build-launch-storage-fixture test-launch-storage
build-launch-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-fixture.c -o .artifacts/launch/launch-fixture
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/native-fixture.c -o .artifacts/launch/native-fixture
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-contract-fixture.c -o .artifacts/launch/launch-contract-fixture

.PHONY: test-launch-contract
test-launch-contract:
	python3 scripts/test-launch-contract.py $(GINUX) .artifacts/launch/launch-contract-fixture .artifacts/launch/contract-evidence

test-launch:
	python3 scripts/test-launch.py $(GINUX) .artifacts/launch/launch-fixture

test-native-supervision:
	python3 scripts/test-native-supervision.py $(GINUX) .artifacts/launch/native-fixture

build-launch-storage-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-storage-fixture.c -o .artifacts/launch/launch-storage-fixture

test-launch-storage:
	python3 scripts/test-launch-storage.py $(GINUX) .artifacts/launch/launch-storage-fixture

.PHONY: build-launch-device-fixture test-launch-devices
build-launch-device-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-device-fixture.c -o .artifacts/launch/launch-device-fixture

test-launch-devices:
	python3 scripts/test-launch-devices.py $(GINUX) .artifacts/launch/launch-device-fixture

.PHONY: build-launch-pipe-fixture test-launch-pipes
build-launch-pipe-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-pipe-fixture.c -o .artifacts/launch/launch-pipe-fixture

test-launch-pipes:
	python3 scripts/test-launch-pipes.py $(GINUX) .artifacts/launch/launch-pipe-fixture

.PHONY: build-launch-fifo-fixture test-launch-fifos
build-launch-fifo-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-fifo-fixture.c -o .artifacts/launch/launch-fifo-fixture

test-launch-fifos:
	python3 scripts/test-launch-fifos.py $(GINUX) .artifacts/launch/launch-fifo-fixture

.PHONY: build-launch-fd-fixture test-launch-fds
build-launch-fd-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-fd-fixture.c -o .artifacts/launch/launch-fd-fixture
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-fd-path-fixture.c -o .artifacts/launch/launch-fd-path-fixture
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-stack-fixture.c -o .artifacts/launch/launch-stack-fixture
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-opath-fixture.c -o .artifacts/launch/launch-opath-fixture

test-launch-fds:
	python3 scripts/test-launch-fds.py $(GINUX) .artifacts/launch/launch-fd-fixture
	python3 scripts/test-launch-fd-paths.py $(GINUX) .artifacts/launch/launch-fd-path-fixture
	python3 scripts/test-launch-stack.py $(GINUX) .artifacts/launch/launch-stack-fixture
	python3 scripts/test-launch-opath.py $(GINUX) .artifacts/launch/launch-opath-fixture

.PHONY: build-launch-task-fixture test-launch-tasks
build-launch-task-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-task-fixture.c -o .artifacts/launch/launch-task-fixture

test-launch-tasks:
	python3 scripts/test-launch-tasks.py $(GINUX) .artifacts/launch/launch-task-fixture

.PHONY: build-launch-exec-fixture test-launch-exec
build-launch-exec-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-exec-fixture.c -o .artifacts/launch/launch-exec-fixture
	$(CC) -nostdlib -pie -Wl,--dynamic-linker=/work/hidden tests/fixtures/launch-interpreter-fixture.S -o .artifacts/launch/launch-interpreter-fixture
	$(CC) -nostdlib -pie -Wl,--dynamic-linker=/bin/second tests/fixtures/launch-interpreter-fixture.S -o .artifacts/launch/launch-interpreter-allowed-fixture

test-launch-exec:
	python3 scripts/test-launch-exec.py $(GINUX) .artifacts/launch/launch-exec-fixture .artifacts/launch/launch-interpreter-fixture .artifacts/launch/launch-interpreter-allowed-fixture

.PHONY: build-launch-poll-fixture test-launch-poll
build-launch-poll-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-poll-fixture.c -o .artifacts/launch/launch-poll-fixture
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-event-fixture.c -o .artifacts/launch/launch-event-fixture

test-launch-poll:
	python3 scripts/test-launch-poll.py $(GINUX) .artifacts/launch/launch-poll-fixture
	python3 scripts/test-launch-events.py $(GINUX) .artifacts/launch/launch-event-fixture

.PHONY: build-launch-directory-fixture test-launch-directories
build-launch-directory-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-directory-fixture.c -o .artifacts/launch/launch-directory-fixture

test-launch-directories:
	python3 scripts/test-launch-directories.py $(GINUX) .artifacts/launch/launch-directory-fixture

.PHONY: build-launch-owned-exec-fixture test-launch-owned-exec
build-launch-owned-exec-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-owned-exec-fixture.c -o .artifacts/launch/launch-owned-exec-fixture

test-launch-owned-exec:
	python3 scripts/test-launch-owned-exec.py $(GINUX) .artifacts/launch/launch-owned-exec-fixture

.PHONY: build-launch-script-fixture test-launch-scripts
build-launch-script-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-script-fixture.c -o .artifacts/launch/launch-script-fixture

test-launch-scripts:
	python3 scripts/test-launch-scripts.py $(GINUX) .artifacts/launch/launch-script-fixture

.PHONY: test-launch-checkpoints
test-launch-checkpoints:
	python3 scripts/test-launch-checkpoints.py $(GINUX) .artifacts/launch/launch-storage-fixture

.PHONY: test-launch-restore
test-launch-restore:
	python3 scripts/test-launch-restore.py $(GINUX) .artifacts/launch/launch-storage-fixture

.PHONY: build-launch-network-fixture test-launch-network
build-launch-network-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-network-fixture.c -o .artifacts/launch/launch-network-fixture

test-launch-network:
	python3 scripts/test-launch-network.py $(GINUX) .artifacts/launch/launch-network-fixture

.PHONY: build-launch-thread-fixture test-launch-threads
build-launch-thread-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-thread-fixture.c -o .artifacts/launch/launch-thread-fixture

test-launch-threads:
	python3 scripts/test-launch-threads.py $(GINUX) .artifacts/launch/launch-thread-fixture

.PHONY: build-launch-signal-fixture test-launch-signals
build-launch-signal-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-signal-fixture.c -o .artifacts/launch/launch-signal-fixture

test-launch-signals:
	python3 scripts/test-launch-signals.py $(GINUX) .artifacts/launch/launch-signal-fixture

.PHONY: build-launch-image-io-fixture test-launch-image-io
build-launch-image-io-fixture:
	mkdir -p .artifacts/launch
	$(CC) -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror tests/fixtures/launch-image-io-fixture.c -o .artifacts/launch/launch-image-io-fixture

test-launch-image-io:
	python3 scripts/test-launch-image-io.py $(GINUX) .artifacts/launch/launch-image-io-fixture
