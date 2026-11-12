#!/usr/bin/env python3
"""Actual configured large reads, virtual filesystem stats, credential drops,
legacy stat/lstat, readv, faccessat and readlinkat on the read-only image
root, and preadv/preadv2, readahead, fadvise64, sendfile, copy_file_range and
the xattr calls on image, owned, device, channel and console descriptors."""
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
        (root / 'image-dir/inner').write_bytes(b'inner')
        # The same bytes the fixture writes to owned storage for comparison.
        (root / 'image-text').write_bytes(bytes((i * 7 + i // 256) & 0xff for i in range(5120)))
        (root / 'image-link').symlink_to('image')
        (root / 'image-dangling').symlink_to('missing')
        (root / 'image-ascii').write_bytes(b'console-transfer\n')
        # Host attributes the instance must never see: a user attribute and,
        # where the host allows it, a security one (an SELinux host labels
        # every file anyway).
        (root / 'image-labelled').write_bytes(b'labelled')
        os.setxattr(root / 'image-labelled', 'user.ginux', b'host-secret')
        try:
            os.setxattr(root / 'image-labelled', 'security.ginux', b'host-label')
        except OSError:
            pass
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
        image_read_forms(binary, work, root, config)
        print('PASS readv, faccessat and readlinkat on the image as read, access and readlink', flush=True)
        file_calls(binary, work, root, config)
    print('PASS preadv/preadv2, readahead, fadvise64, sendfile, copy_file_range and xattrs', flush=True)


def file_calls(binary, work, root, config):
    # Catalog-1002 file calls answered as their plain counterparts: vectored
    # reads at an offset, advisory calls without effect, transfers composed
    # of a read and a write, and a filesystem without extended attributes.
    config = config.replace('[devices]\nassignments = []', '[devices]\nassignments = ["null"]')
    image = {path: path.read_bytes() for path in root.iterdir() if path.is_file() and not path.is_symlink()}
    labelled = root / 'image-labelled'
    labels = {name: os.getxattr(labelled, name) for name in os.listxattr(labelled)}
    assert labels.get('user.ginux') == b'host-secret', labels
    deny = 'allow = ["*"]\ndeny = ["preadv2", "readahead", "fadvise64", "getxattr", "flistxattr", ' \
        '"lsetxattr", "sendfile", "copy_file_range"]'
    console = 'deny = ["device.mmio.direct", "device.dma.direct", "network.packet.raw", "device.console.read"]'
    for scenario, policy, expected in [
            ('R', config, b'vectored-at: PASS\n'),
            ('T', config, b'console-transfer\ntransfer: PASS\n'),
            ('X', config, b'xattr: PASS\n'),
            ('Y', config.replace('allow = ["*"]\ndeny = []', deny), b'file-calls-policy: PASS\n'),
            ('Z', config.replace('deny = ["device.mmio.direct", "device.dma.direct", "network.packet.raw"]',
                                 console), b'ole-transfer\ntransfer-policy: PASS\n')]:
        assert policy.count('args = []') == 1 and policy.count('assignments = ["null"]') == 1
        policy = policy.replace('args = []', f'args = ["{scenario}"]')
        if scenario == 'Y':
            assert deny in policy
        if scenario == 'Z':
            assert console in policy
        (work / 'calls.toml').write_text(policy)
        result = work / f'calls-{scenario}.json'
        proc = subprocess.run([binary, 'launch', str(work / 'calls.toml'), str(root),
                               '--result-file', str(result)], input=b'console\n',
                              capture_output=True, timeout=120)
        audit = proc.stderr.decode()
        assert proc.returncode == 0 and proc.stdout == expected, (scenario, proc.returncode, proc.stdout, audit[-4000:])
        assert json.loads(result.read_text())['code'] == 0
        assert 'teardown tasks=0 owned-handles=0' in audit
        lines = [line for line in audit.splitlines() if ' phase=entry syscall=' in line]
        def calls(number):
            return [line for line in lines if f' syscall={number} ' in line]
        numbers = {'R': ('295', '327', '187', '221'), 'T': ('40', '326'),
                   'X': tuple(str(n) for n in range(188, 200))}
        if scenario in numbers:
            # Served, never the ENOSYS of an uncatalogued call.
            for number in numbers[scenario]:
                assert calls(number), number
                assert not any(line.endswith(' result=-38') for line in calls(number)), calls(number)
        if scenario == 'R':
            # preadv on an image descriptor reads in the kernel, bounded and
            # mediated as readv is.
            assert any(' action=mediate surface=immutable-image ' in line for line in calls('295'))
        if scenario == 'Y':
            for number, name in (('327', 'preadv2'), ('187', 'readahead'), ('221', 'fadvise64'),
                                 ('191', 'getxattr'), ('196', 'flistxattr'), ('189', 'lsetxattr'),
                                 ('40', 'sendfile'), ('326', 'copy_file_range')):
                assert calls(number) and all(
                    f' operation=syscall.{name} policy-source=exact-deny ' in line
                    and line.endswith(' action=deny result=-1') for line in calls(number)), calls(number)
            for number in ('295', '192', '194', '188'):
                assert calls(number) and not any(' action=deny' in line for line in calls(number))
        if scenario == 'Z':
            # The input read decides a transfer from the console.
            for number in ('40', '326'):
                denied = [line for line in calls(number) if ' operation=device.console.read ' in line]
                assert denied and all(line.endswith(' action=deny result=-1') for line in denied), calls(number)
            # A transfer into the console, from an image file, is admitted.
            assert any(line.endswith(' operation=syscall.sendfile policy-source=exact-allow '
                                     'policy-rule=0 action=emulate result=13') for line in calls('40')), calls('40')
        assert sorted(p.name for p in (root / 'work').iterdir()) == []
        assert {path: path.read_bytes() for path in image} == image
        # Nothing read, changed or removed a host attribute.
        assert {name: os.getxattr(labelled, name) for name in os.listxattr(labelled)} == labels


def image_read_forms(binary, work, root, config):
    # musl stdio reads with readv; faccessat and readlinkat are the *at forms
    # of access and readlink. Each must answer as its plain form does.
    config = config.replace('[devices]\nassignments = []', '[devices]\nassignments = ["null"]')
    image = {path: path.read_bytes() for path in root.iterdir() if path.is_file() and not path.is_symlink()}
    deny = 'allow = ["*"]\ndeny = ["readv", "faccessat", "readlinkat"]'
    for scenario, policy, expected in [
            ('V', config, b'vectored: PASS\n'),
            ('A', config, b'metadata-at: PASS\n'),
            ('Q', config.replace('allow = ["*"]\ndeny = []', deny), b'vectored-policy: PASS\n')]:
        assert policy.count('args = []') == 1 and policy.count('assignments = ["null"]') == 1
        policy = policy.replace('args = []', f'args = ["{scenario}"]')
        if scenario == 'Q':
            assert deny in policy
        (work / 'forms.toml').write_text(policy)
        result = work / f'forms-{scenario}.json'
        proc = subprocess.run([binary, 'launch', str(work / 'forms.toml'), str(root),
                               '--result-file', str(result)], input=b'console\n',
                              capture_output=True, timeout=60)
        audit = proc.stderr.decode()
        assert proc.returncode == 0 and proc.stdout == expected, (scenario, proc.returncode, proc.stdout, audit[-4000:])
        assert json.loads(result.read_text())['code'] == 0
        assert 'teardown tasks=0 owned-handles=0' in audit
        lines = [line for line in audit.splitlines() if ' phase=entry syscall=' in line]
        def calls(number):
            return [line for line in lines if f' syscall={number} ' in line]
        if scenario == 'Q':
            for number, name in (('19', 'readv'), ('269', 'faccessat'), ('267', 'readlinkat')):
                assert calls(number) and all(
                    f' operation=syscall.{name} policy-source=exact-deny ' in line
                    and line.endswith(' action=deny result=-1') for line in calls(number)), calls(number)
        else:
            # The image forms take the immutable-image surface, never ENOSYS.
            number = {'V': ('19',), 'A': ('269', '267')}[scenario]
            for n in number:
                assert any(' action=mediate surface=immutable-image ' in line for line in calls(n)), n
                assert not any(line.endswith(' result=-38') for line in calls(n)), calls(n)
        assert sorted(p.name for p in (root / 'work').iterdir()) == []
        assert {path: path.read_bytes() for path in image} == image


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
