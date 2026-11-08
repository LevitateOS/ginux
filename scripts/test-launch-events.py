#!/usr/bin/env python3
"""Actual configured eventfd/epoll ABI and public-descriptor lifetime controls."""
import json
import os
import resource
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit("usage (as root): test-launch-events.py <ginux> <fixture>")
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent / "config/instance-configured.toml").read_text()
    with tempfile.TemporaryDirectory(prefix="ginux-events-") as directory:
        work = Path(directory)
        root = work / "root"
        (root / "bin").mkdir(parents=True)
        shutil.copyfile(fixture, root / "bin/fixture")
        (root / "bin/fixture").chmod(0o755)
        template = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
        template = template.replace('assignments = []', 'assignments = ["memory:/work"]', 1)
        for mode in ("basic", "level", "edge", "oneshot", "aliases", "pipes", "fork", "read", "write", "time", "capacity", "keep-exec", "deny", "network", "v-limit", "g-copy"):
            with socket.socket() as server:
                server.bind(("127.0.0.1", 0))
                server.listen()
                server.settimeout(5)
                port = server.getsockname()[1]
                errors, observed = [], []
                def peer():
                    try:
                        stream, _ = server.accept()
                        with stream:
                            stream.settimeout(5)
                            stream.sendall(b"N")
                            stream.shutdown(socket.SHUT_WR)
                            observed.append(stream.recv(1))
                    except Exception as error:
                        errors.append(repr(error))
                thread = None
                text = template.replace('args = []', 'args = ' + json.dumps([mode, str(port)]))
                if mode == "network":
                    text = text.replace('backend = "none"', f'backend = "mediated"\nendpoints = ["127.0.0.1:{port}"]\nmax_connections = 1\nmax_bytes = 1024')
                    thread = threading.Thread(target=peer, daemon=True)
                    thread.start()
                if mode == "deny":
                    text = text.replace('[contract]', '[contract]\ndeny = ["syscall.eventfd2", "syscall.epoll_create1", "syscall.epoll_ctl", "syscall.epoll_wait", "syscall.epoll_pwait"]')
                config, result = work / (mode + ".toml"), work / (mode + ".json")
                config.write_text(text)
                start = time.monotonic()
                def low_limit():
                    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                    resource.setrlimit(resource.RLIMIT_NOFILE, (8, hard))
                run = subprocess.run([binary, "launch", str(config), str(root), "--result-file", str(result)], capture_output=True, timeout=15, preexec_fn=low_limit if mode == "v-limit" else None)
                record = json.loads(result.read_text())
                assert run.returncode == 0 and record["code"] == 0, (mode, run.returncode, record, run.stdout, run.stderr.decode())
                assert run.stdout == b"owned-events: PASS\n", (mode, run.stdout)
                assert b"teardown tasks=0 owned-handles=0" in run.stderr, run.stderr.decode()
                if mode == "time":
                    assert .025 < time.monotonic() - start < 2
                if thread:
                    thread.join(6)
                    assert not thread.is_alive() and not errors and observed == [b"A"], (errors, observed)
                print(f"test-launch-events: {mode} PASS", flush=True)


if __name__ == "__main__":
    main()
