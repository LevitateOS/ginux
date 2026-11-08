#!/usr/bin/env python3
"""Check `ginux native` supervision edges with a fixture as /usr/bin/bash (Linux/root)."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) not in (3, 4) or os.geteuid() != 0:
        sys.exit("usage (as root): test-native-supervision.py <ginux binary> <native fixture>")
    binary, fixture = (str(Path(arg).resolve()) for arg in sys.argv[1:3])
    config = Path(__file__).resolve().parent.parent / "config/instance-gate5.toml"
    with tempfile.TemporaryDirectory(prefix="ginux-native-") as directory:
        work = Path(directory)
        # The tracee drops to UID 1000 and must be able to execute the copies.
        shutil.copyfile(binary, work / "ginux")
        (work / "ginux").chmod(0o755)
        root = work / "root"
        (root / "usr/bin").mkdir(parents=True)
        shutil.copyfile(fixture, root / "usr/bin/bash")
        (root / "usr/bin/bash").chmod(0o755)
        work.chmod(0o755)
        # The systemd profile supervises fork; derive it from the same instance.
        systemd_config = work / "systemd.toml"
        systemd_config.write_text(config.read_text().replace(
            'profile = "gate5-balanced-v1"', 'profile = "gate9-systemd-v1"'))

        def run(scenario, instance=config, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **options):
            (root / "scenario").write_text(scenario)
            proc = subprocess.run([str(work / "ginux"), "native", str(instance), str(root)],
                                  stdin=stdin, stdout=stdout, stderr=stderr, timeout=20, **options)
            output = (proc.stdout or b"") + (proc.stderr or b"")
            return proc.returncode, output.decode(errors="replace")

        def check(name, ok, code, output):
            if not ok:
                raise RuntimeError(f"{name}: exit={code}\n{output}")
            print(f"PASS native {name}")

        # Gate 11 direct dispatch must preserve explicit denial in both modes.
        for dispatch in ("selective", "paranoid"):
            for denied in (False, True):
                instance = work / f"yield-{dispatch}-{denied}.toml"
                text = config.read_text().replace('dispatch = "paranoid"',
                                                  f'dispatch = "{dispatch}"')
                if denied:
                    text = text.replace('profile = "gate5-balanced-v1"',
                                        'profile = "gate5-balanced-v1"\ndeny = ["syscall.sched_yield"]')
                instance.write_text(text)
                code, out = run("yield", instance)
                expected = -1 if denied else 0
                check(f"{dispatch} yield {'denied' if denied else 'allowed'}",
                      code == 0 and f"GINUX_FIXTURE: yield={expected}\n" in out,
                      code, out)
        if len(sys.argv) == 4 and sys.argv[3] == "dispatch":
            print("test-native-dispatch: PASS")
            return

        # Host directories must not reach the chrooted workload: as a
        # standard stream the instance does not start, and every other
        # inherited descriptor is closed. A closed stream starts as before.
        outside = work / "outside"
        outside.mkdir()
        directory = os.open(outside, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for stream, reason in (("stdin", "input"), ("stdout", "output"), ("stderr", "error")):
                code, out = run("fork", **{stream: directory})
                # With stdout a directory the refusal has nowhere to print.
                check(f"directory {stream} refused", code == 1
                      and "GINUX_FIXTURE" not in out
                      and (stream == "stdout" or f"standard {reason} is a directory" in out),
                      code, out)
            for number in (239, 242, 300):
                os.dup2(directory, number, inheritable=True)
            try:
                code, out = run("descriptors", pass_fds=(239, 242, 300))
            finally:
                for number in (239, 242, 300):
                    os.close(number)
            check("inherited descriptors closed", code == 0
                  and all(f"GINUX_FIXTURE: fd-{number}=-9\n" in out for number in (239, 242, 300))
                  and "GINUX_FIXTURE: fd-240=0\n" in out and "GINUX_FIXTURE: fd-241=0\n" in out,
                  code, out)
        finally:
            os.close(directory)
        code, out = run("fork", preexec_fn=lambda: os.close(0))
        check("closed stdin starts", code == 0 and "GINUX_FIXTURE: fork=-38\n" in out, code, out)

        # Without child supervision a host fork would run unsupervised.
        code, out = run("fork")
        check("fork denied", code == 0 and "GINUX_FIXTURE: fork=-38\n" in out
              and "unsupervised child ran" not in out and "GINUX_NATIVE_CHECK: PASS" in out, code, out)

        # fcntl cannot make the host kernel signal another process.
        code, out = run("owner")
        check("signal-driven I/O refused", code == 0
              and all(f"GINUX_FIXTURE: {name}=-1\n" in out
                      for name in ("setown", "setown-ex", "setsig", "async"))
              and "GINUX_FIXTURE: nonblock=0\n" in out, code, out)

        # The thread identity matches the virtual pid: set_tid_address returns
        # it instead of the host tid, and PI futexes, which would store the
        # host tid in the futex word, are denied.
        code, out = run("virtual-tid")
        fixture = [line for line in out.splitlines() if line.startswith("GINUX_FIXTURE: ")]
        check("thread identity is virtual", code == 0 and fixture == [
            "GINUX_FIXTURE: set_tid_address=4242", "GINUX_FIXTURE: getpid=4242",
            "GINUX_FIXTURE: gettid=-38", "GINUX_FIXTURE: futex_lock_pi=-1",
            "GINUX_FIXTURE: pi_word=0", "GINUX_FIXTURE: futex_lock_pi_flags=-1",
            "GINUX_FIXTURE: pi_flags_word=0"] and "GINUX_NATIVE_CHECK: PASS" in out, code, out)

        # A plain SIGTRAP stop is not a syscall stop; supervision must fail
        # closed instead of treating the next syscall entry as an exit.
        code, out = run("trap")
        check("signal stop fails closed", code == 1 and "GINUX_FIXTURE: uname-before=-38\n" in out
              and "uname-after" not in out
              and "GINUX_INSTANCE: failed reason=unexpected native trace stop" in out, code, out)
        # int 0x80 selects the i386 table; supervision must stop instead of
        # classifying i386 fork (2) as x86-64 open. Without IA32 emulation the
        # host raises SIGSEGV on int 0x80, which ends supervision as an
        # unexpected stop instead.
        code, out = run("int80")
        check("i386 syscall ABI fails closed", code == 1 and "unsupervised child ran" not in out
              and "int80-fork" not in out
              and ("GINUX_INSTANCE: failed reason=native requires the x86-64 syscall ABI" in out
                   or "GINUX_INSTANCE: failed reason=unexpected native trace stop" in out),
              code, out)
        # A parent that catches SIGCHLD with a handler, as OpenRC, busybox and
        # shells do, must get it: the supervisor resumes the SIGCHLD stop with
        # the signal instead of discarding it.
        # The systemd profile execs /bin/bash and materializes /proc identity.
        (root / "bin").symlink_to("usr/bin")
        (root / "proc/1").mkdir(parents=True)
        (root / "proc/sys/kernel").mkdir(parents=True)
        code, out = run("sigchld", systemd_config)
        fixture = [line for line in out.splitlines() if line.startswith("GINUX_FIXTURE: ")]
        check("SIGCHLD reaches a handler", code == 0 and fixture == [
            "GINUX_FIXTURE: sigaction=0", "GINUX_FIXTURE: fork-ok=1",
            "GINUX_FIXTURE: sigchld-poll=1", "GINUX_FIXTURE: sigchld-handled=1",
            "GINUX_FIXTURE: wait-ok=1", "GINUX_FIXTURE: child-status=7"], code, out)
    print("test-native-supervision: PASS")


if __name__ == "__main__":
    main()
