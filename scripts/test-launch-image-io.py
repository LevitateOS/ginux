#!/usr/bin/env python3
"""Actual configured large reads, virtual filesystem stats and credential drops."""
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-image-io.py <ginux> <fixture>')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent / 'config/instance-configured.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-image-io-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)
        (root / 'image').write_bytes(b'Q' * (2 * 1024 * 1024 + 32))
        config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
        config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
        (work / 'instance.toml').write_text(config)
        with (work / 'audit').open('wb') as audit:
            proc = subprocess.Popen([binary, 'launch', str(work / 'instance.toml'), str(root),
                                     '--result-file', str(work / 'result.json')],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=audit)
            try:
                assert select.select([proc.stdout], [], [], 15)[0], (work / 'audit').read_text()
                assert proc.stdout.readline() == b'drop-ready\n', (proc.poll(), (work / 'audit').read_text())
                def children(pid):
                    return [int(p) for p in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()]
                def identity(pid):
                    return [line for line in Path(f'/proc/{pid}/status').read_text().splitlines()
                            if line.startswith(('Uid:', 'Gid:'))]
                parent = children(proc.pid)
                assert len(parent) == 1, parent
                child = children(parent[0])
                assert len(child) == 1, child
                assert identity(parent[0]) == identity(child[0]), 'virtual drop changed host identity'
                assert '\t12345\t' not in '\n'.join(identity(child[0]))
                stdout, _ = proc.communicate(b'G', timeout=15)
                assert proc.returncode == 0 and stdout == b'image-io: PASS\n', (proc.returncode, stdout, (work / 'audit').read_text())
                assert json.loads((work / 'result.json').read_text())['code'] == 0
                assert b'teardown tasks=0 owned-handles=0' in (work / 'audit').read_bytes()
                assert list((root / 'work').iterdir()) == []
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate(timeout=5)
    print('PASS configured large image reads, virtual statfs and credentials', flush=True)


if __name__ == '__main__':
    main()
