#!/usr/bin/env python3
"""Real own-stack snapshot: bounded content, aliases, reuse, fork/exec, denial."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit("usage (as root): test-launch-stack.py <ginux> <fixture>")
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent / "config/instance-configured.toml").read_text()
    with tempfile.TemporaryDirectory(prefix="ginux-stack-") as directory:
        work = Path(directory)
        root = work / "root"
        (root / "bin").mkdir(parents=True)
        shutil.copyfile(fixture, root / "bin/fixture")
        (root / "bin/fixture").chmod(0o755)
        template = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
        for mode in ("snapshot", "deny"):
            config = template
            if mode == "deny":
                config = config.replace('args = []', 'args = ["deny"]')
                config = config.replace('[contract]', '[contract]\ndeny = ["filesystem.path.read"]')
            path, result = work / (mode + ".toml"), work / (mode + ".json")
            path.write_text(config)
            run = subprocess.run([binary, "launch", str(path), str(root), "--result-file", str(result)], capture_output=True, timeout=20)
            record = json.loads(result.read_text())
            assert run.returncode == 0 and record["code"] == 0, (mode, record, run.stderr.decode())
            if mode == "deny":
                assert run.stdout == b"stack-deny: PASS\n", run.stdout
            else:
                assert re.fullmatch(rb"[0-9a-f]+-[0-9a-f]+ rw-p 00000000 00:00 0 \[stack\]\nstack-exec: PASS\n", run.stdout), run.stdout
            assert b"teardown tasks=0 owned-handles=0" in run.stderr
            print(f"test-launch-stack: {mode} PASS", flush=True)


if __name__ == "__main__":
    main()
