#!/usr/bin/env python3
"""Real configured filesystem-descriptor names and explicit deny precedence."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit("usage (as root): test-launch-fd-paths.py <ginux> <fixture>")
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent / "config/instance-configured.toml").read_text()
    with tempfile.TemporaryDirectory(prefix="ginux-fd-paths-") as directory:
        work = Path(directory)
        root = work / "root"
        (root / "bin").mkdir(parents=True)
        (root / "image").mkdir()
        (root / "image/item").write_text("immutable image input")
        shutil.copyfile(fixture, root / "bin/fixture")
        (root / "bin/fixture").chmod(0o755)
        config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
        config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
        for mode in ("names", "deny"):
            text = config
            if mode == "deny":
                text = text.replace('args = []', 'args = ["deny"]')
                text = text.replace('deny = ["device.mmio.direct"', 'deny = ["syscall.readlink", "syscall.readlinkat", "device.mmio.direct"', 1)
            path = work / (mode + ".toml")
            result = work / (mode + ".json")
            path.write_text(text)
            run = subprocess.run([binary, "launch", str(path), str(root), "--result-file", str(result)], capture_output=True, timeout=30)
            expected = b"fd-path: PASS\n" if mode == "names" else b"fd-path-deny: PASS\n"
            record = json.loads(result.read_text())
            assert run.returncode == 0 and record["code"] == 0, (mode, run.returncode, record, run.stderr)
            assert run.stdout == expected, (mode, run.stdout)
        print("test-launch-fd-paths: PASS (image/owned paths, aliases, rename/unlink, fork/exec, bounded names, truncation, deny)")


if __name__ == "__main__":
    main()
