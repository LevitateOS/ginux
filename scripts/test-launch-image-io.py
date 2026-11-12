#!/usr/bin/env python3
"""Actual configured large reads, virtual filesystem stats, credential drops and
legacy stat/lstat on the read-only image root."""
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
        (root / 'image-dir').mkdir()
        (root / 'image-link').symlink_to('image')
        (root / 'image-dangling').symlink_to('missing')
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
        legacy_stat(binary, work, root, config)
    print('PASS legacy stat and lstat as newfstatat on the read-only image root', flush=True)


def legacy_stat(binary, work, root, config):
    # musl issues stat(4) and lstat(6) where glibc uses newfstatat or statx.
    config = config.replace('[devices]\nassignments = []', '[devices]\nassignments = ["null"]')
    image = (root / 'image').read_bytes()
    for scenario, policy, expected in [
            ('L', config, b'legacy-stat: PASS\n'),
            ('P', config.replace('allow = ["*"]\ndeny = []', 'allow = ["*"]\ndeny = ["lstat"]'),
             b'legacy-stat-policy: PASS\n')]:
        assert policy.count('args = []') == 1 and policy.count('assignments = ["null"]') == 1
        policy = policy.replace('args = []', f'args = ["{scenario}"]')
        if scenario == 'P':
            assert 'deny = ["lstat"]' in policy
        (work / 'legacy.toml').write_text(policy)
        result = work / f'legacy-{scenario}.json'
        proc = subprocess.run([binary, 'launch', str(work / 'legacy.toml'), str(root),
                               '--result-file', str(result)], capture_output=True, timeout=30)
        audit = proc.stderr.decode()
        assert proc.returncode == 0 and proc.stdout == expected, (scenario, proc.returncode, proc.stdout, audit)
        assert json.loads(result.read_text())['code'] == 0
        assert 'teardown tasks=0 owned-handles=0' in audit
        lines = [line for line in audit.splitlines() if ' phase=entry syscall=' in line]
        stats = [line for line in lines if ' syscall=4 ' in line]
        lstats = [line for line in lines if ' syscall=6 ' in line]
        assert stats and all(' operation=syscall.stat ' in line and ' action=deny' not in line
                             for line in stats), stats
        if scenario == 'L':
            # Their own operation names; the image surface is the newfstatat one.
            assert lstats and all(' operation=syscall.lstat ' in line and ' action=deny' not in line
                                  for line in lstats), lstats
            for number in ('4', '6'):
                assert any(f' syscall={number} ' in line
                           and ' action=mediate surface=immutable-image ' in line for line in lines)
        else:
            assert len(lstats) == 2 and all(
                ' operation=syscall.lstat policy-source=exact-deny ' in line
                and line.endswith(' action=deny result=-1') for line in lstats), lstats
        assert sorted(p.name for p in (root / 'work').iterdir()) == []
        assert (root / 'image').read_bytes() == image


if __name__ == '__main__':
    main()
