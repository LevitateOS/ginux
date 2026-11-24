#!/usr/bin/env python3
"""Check `ginux native CONFIG ROOT configured --result-file PATH` (Linux/root).

The runtime creates the result file before it drops privileges (results live
in a root-owned 0700 directory the dropped supervisor cannot write to) and
writes one version-1 outcome record through the kept descriptor after the
workload is gone: `exited` with the exit code, or `signaled` with the signal.
The descriptor is held by the supervisor alone, never by the workload or the
supervisor's broker children. A supervisor killed before the end leaves the
file empty, which readers take as a supervisor error. An existing path fails
before any workload runs, and without the option nothing is written and every
exit code stays as before.
"""
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time

RECORD = re.compile(
    r'^\{"version":1,"outcome":"(exited|signaled|supervisor-error)",'
    r'"code":(null|[0-9]{1,3}),"signal":(null|[0-9]{1,2}),"generation":null\}$')


def tiny_elf(code):
    """A static x86-64 ELF with one loadable segment running `code`."""
    base = 0x400000
    header_size, program_header_size = 64, 56
    entry = base + header_size + program_header_size
    size = header_size + program_header_size + len(code)
    header = (b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
              + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, entry, header_size, 0, 0,
                            header_size, program_header_size, 1, 0, 0, 0))
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, size, size, 0x1000)
    return header + program + code


# mov edi, 3; mov eax, 231 (exit_group); syscall
EXIT_THREE = tiny_elf(b"\xbf\x03\x00\x00\x00\xb8\xe7\x00\x00\x00\x0f\x05")
# jmp . (spins without a system call until killed)
SPIN = tiny_elf(b"\xeb\xfe")


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit("usage (as root): test-native-result.py <ginux binary> <native fixture>")
    binary, fixture = (str(Path(arg).resolve()) for arg in sys.argv[1:3])
    config = Path(__file__).resolve().parent.parent / "config/instance-gate5.toml"
    with tempfile.TemporaryDirectory(prefix="ginux-native-result-") as directory:
        work = Path(directory)
        # The tracee drops to UID 65534 and must be able to execute the copies.
        shutil.copyfile(binary, work / "ginux")
        (work / "ginux").chmod(0o755)
        root = work / "root"
        (root / "usr/bin").mkdir(parents=True)
        workload = root / "usr/bin/bash"
        work.chmod(0o755)
        # Result files live in a root-owned 0700 directory outside the root.
        results = work / "results"
        results.mkdir(mode=0o700)
        configured = work / "configured.toml"
        configured.write_text(config.read_text().replace(
            'init = "/bin/bash"', 'init = "/usr/bin/bash"') + """
[contract.filesystem]
read = ["/"]
write = ["/"]
create = ["/"]
[contract.kernel]
proc_read = ["/"]
sys_read = ["/"]
""")

        def install(content=None):
            if workload.exists():
                workload.unlink()
            if content is None:
                shutil.copyfile(fixture, workload)
            else:
                workload.write_bytes(content)
            workload.chmod(0o755)

        def start(extra):
            (root / "scenario").write_text("w-yield")
            return subprocess.Popen(
                [str(work / "ginux"), "native", str(configured), str(root)] + extra,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        def finish(proc):
            try:
                stdout, stderr = proc.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                raise RuntimeError(f"timeout\n{(stdout + stderr).decode(errors='replace')}")
            return proc.returncode, (stdout + stderr).decode(errors="replace")

        def run(extra):
            return finish(start(extra))

        def check(name, ok, code, output):
            if not ok:
                raise RuntimeError(f"{name}: exit={code}\n{output}")
            print(f"PASS native-result {name}")

        def record_ok(path, expected):
            info = os.lstat(path)
            text = path.read_text()
            return (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_uid == 0 and text == expected + "\n"
                    and RECORD.match(text.rstrip("\n")) is not None)

        def descendants(top):
            """Every live process below `top`."""
            children = {}
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    stat_text = Path(f"/proc/{entry}/stat").read_text()
                except OSError:
                    continue
                parent = int(stat_text[stat_text.rindex(")") + 2:].split()[1])
                children.setdefault(parent, []).append(int(entry))
            found, pending = [], [top]
            while pending:
                for child in children.get(pending.pop(), []):
                    found.append(child)
                    pending.append(child)
            return found

        def holders(pid, path):
            """Descriptors of `pid` (all its threads share them) open on `path`."""
            identity = os.stat(path)
            held = []
            for entry in os.listdir(f"/proc/{pid}/fd"):
                try:
                    info = os.stat(f"/proc/{pid}/fd/{entry}")
                except OSError:
                    continue
                if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
                    held.append(int(entry))
            return held

        def wait_workload(proc):
            deadline = time.monotonic() + 20
            pid = None
            while pid is None and time.monotonic() < deadline and proc.poll() is None:
                pid = workload_pid(proc.pid)
                if pid is None:
                    time.sleep(0.05)
            if pid is None:
                proc.kill()
                code, out = finish(proc)
                raise RuntimeError(f"workload not found: exit={code}\n{out}")
            return pid

        def workload_pid(supervisor):
            """The traced workload: a child of the supervisor running SPIN."""
            target = os.path.realpath(workload)
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    stat_text = Path(f"/proc/{entry}/stat").read_text()
                    parent = int(stat_text[stat_text.rindex(")") + 2:].split()[1])
                    executable = os.readlink(f"/proc/{entry}/exe")
                except (OSError, ValueError):
                    continue
                if parent == supervisor and executable == target:
                    return int(entry)
            return None

        # Workload exits 0.
        install()
        path = results / "exit-0"
        code, out = run(["configured", "--result-file", str(path)])
        check("exit 0 recorded", code == 0 and "GINUX_FIXTURE: yield=" in out
              and record_ok(path, '{"version":1,"outcome":"exited","code":0,'
                                  '"signal":null,"generation":null}'), code, out)

        # Workload exits 3.
        install(EXIT_THREE)
        path = results / "exit-3"
        code, out = run(["configured", "--result-file", str(path)])
        check("exit 3 recorded", code == 3
              and record_ok(path, '{"version":1,"outcome":"exited","code":3,'
                                  '"signal":null,"generation":null}'), code, out)

        # Workload killed by SIGKILL from outside.
        install(SPIN)
        path = results / "sigkill"
        proc = start(["configured", "--result-file", str(path)])
        pid = wait_workload(proc)
        # The workload runs its own image (so the privilege drop is done): the
        # file exists, empty and root's, and only the supervisor holds it.
        info = os.lstat(path)
        supervisor_fds = holders(proc.pid, path)
        others = {child: holders(child, path) for child in descendants(proc.pid)}
        if not (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == 0 and info.st_size == 0 and len(supervisor_fds) == 1
                and pid in others and not any(others.values())):
            proc.kill()
            code, out = finish(proc)
            raise RuntimeError(f"result descriptor: supervisor={supervisor_fds} others={others} "
                               f"mode={oct(info.st_mode)} uid={info.st_uid} "
                               f"size={info.st_size}\nexit={code}\n{out}")
        print(f"PASS native-result descriptor held by the supervisor only "
              f"(fd {supervisor_fds[0]}; {len(others)} other processes checked)")
        os.kill(pid, signal.SIGKILL)
        code, out = finish(proc)
        check("SIGKILL recorded", code == 128 + 9
              and record_ok(path, '{"version":1,"outcome":"signaled","code":null,'
                                  '"signal":9,"generation":null}'), code, out)

        # A supervisor killed before the end leaves the file empty (a supervisor
        # error to every reader), and its workload dies with it.
        install(SPIN)
        path = results / "supervisor-killed"
        proc = start(["configured", "--result-file", str(path)])
        pid = wait_workload(proc)
        os.kill(proc.pid, signal.SIGKILL)
        code, out = finish(proc)
        deadline = time.monotonic() + 10
        while os.path.exists(f"/proc/{pid}") and time.monotonic() < deadline:
            time.sleep(0.05)
        info = os.lstat(path)
        check("killed supervisor leaves an empty file", code == -signal.SIGKILL
              and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
              and info.st_uid == 0 and info.st_size == 0
              and not os.path.exists(f"/proc/{pid}"), code, out)

        # An existing path fails before any workload runs and is left alone.
        install()
        path = results / "existing"
        path.write_text("keep\n")
        code, out = run(["configured", "--result-file", str(path)])
        check("existing file refused", code == 1 and "GINUX_FIXTURE" not in out
              and "GINUX_NATIVE" not in out and "ginux: result-file" in out
              and path.read_text() == "keep\n", code, out)

        # A dangling symlink counts as existing; nothing is created through it.
        path = results / "link"
        target = results / "link-target"
        path.symlink_to(target)
        code, out = run(["configured", "--result-file", str(path)])
        check("symlink refused", code == 1 and "GINUX_FIXTURE" not in out
              and path.is_symlink() and not target.exists(), code, out)

        # Without the option nothing is written and exit codes are unchanged.
        before = sorted(os.listdir(results))
        install()
        code, out = run(["configured"])
        check("no option exit 0", code == 0 and "GINUX_FIXTURE: yield=" in out, code, out)
        install(EXIT_THREE)
        code, out = run(["configured"])
        check("no option exit 3", code == 3, code, out)

        # Incomplete or different forms stay usage errors and write nothing.
        install()
        path = results / "usage"
        for name, extra in (
                ("missing path", ["configured", "--result-file"]),
                ("other mode", ["hold", "--result-file", str(path)]),
                ("other option", ["configured", "--output-file", str(path)]),
                ("empty path", ["configured", "--result-file", ""])):
            code, out = run(extra)
            check(f"usage {name}", code == 2 and "ginux: usage:" in out
                  and "GINUX_FIXTURE" not in out, code, out)
        check("no stray files", sorted(os.listdir(results)) == before, 0, "")
    print("test-native-result: PASS")


if __name__ == "__main__":
    main()
