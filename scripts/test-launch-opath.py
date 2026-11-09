#!/usr/bin/env python3
"""Configured metadata references and the common-subset native ABI oracle."""
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit("usage (as root): test-launch-opath.py <ginux> <fixture>")
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent / "config/instance-configured.toml").read_text()
    with tempfile.TemporaryDirectory(prefix="ginux-opath-") as directory:
        work = Path(directory)
        for mode in ("native", "configured", "deny", "lower"):
            root = work / mode
            (root / "bin").mkdir(parents=True)
            (root / "image").mkdir()
            (root / "work").mkdir()
            (root / "image/item").write_text("payload")
            (root / "image/sealed").write_text("payload")
            (root / "image/sealed").chmod(0)
            shutil.copyfile(fixture, root / "bin/fixture")
            (root / "bin/fixture").chmod(0o755)
            # Native oracle needs only its own proc FD view, in this disposable namespace.
            if mode == "native":
                (root / "proc").mkdir()
                run = subprocess.run(["unshare", "-m", "--propagation", "private", "sh", "-c",
                    'mount -t proc proc "$1/proc" && chroot "$1" /bin/fixture native', "sh", str(root)], capture_output=True, timeout=20)
                assert run.returncode == 0 and run.stdout == b"opath: PASS\n", (mode, run.returncode, run.stdout, run.stderr)
            else:
                config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
                config = config.replace('args = []', 'args = ' + json.dumps([mode]))
                config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
                if mode == "deny":
                    config = config.replace('deny = ["device.mmio.direct"', 'deny = ["syscall.open", "device.mmio.direct"', 1)
                path, result = work / (mode + ".toml"), work / (mode + ".json")
                path.write_text(config)
                def lower():
                    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                    resource.setrlimit(resource.RLIMIT_NOFILE, (8, hard))
                run = subprocess.run([binary, "launch", str(path), str(root), "--result-file", str(result)], capture_output=True, timeout=20, preexec_fn=lower if mode == "lower" else None)
                record = json.loads(result.read_text())
                assert run.returncode == 0 and record["code"] == 0, (mode, run.returncode, record, run.stdout, run.stderr.decode())
                assert run.stdout == b"opath: PASS\n", (mode, run.stdout)
                assert b"teardown tasks=0 owned-handles=0" in run.stderr, run.stderr.decode()
            print(f"test-launch-opath: {mode} PASS", flush=True)


if __name__ == "__main__":
    main()
