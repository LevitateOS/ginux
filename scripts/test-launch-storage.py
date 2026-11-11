#!/usr/bin/env python3
"""Real configured-launch storage checks against explicit existing binaries."""
import json
import os
import resource
from pathlib import Path
import shutil
import select
import subprocess
import sys
import tempfile
import tarfile
import io


def add_member(tar, name, kind=tarfile.REGTYPE, data=b'', mode=0o644, mtime=1234, link='', pax=None):
    info = tarfile.TarInfo(name)
    info.type, info.mode, info.mtime, info.linkname = kind, mode, mtime, link
    if pax:
        info.pax_headers = pax
    info.size = len(data) if kind == tarfile.REGTYPE else 0
    tar.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)


LONG_NAME = 'tree/' + 'a' * 120 + '/' + 'b' * 60
GNU_NAME = 'gnu/' + 'g' * 150
BIG = bytes(i % 251 for i in range(20000))


def write_import_archives(root):
    """Archives the archive-import scenario writes into owned storage."""
    with tarfile.open(root / 'import.tar', 'w', format=tarfile.PAX_FORMAT) as tar:
        add_member(tar, 'xattr-file', data=b'cap', mode=0o755,
                   pax={'SCHILY.xattr.user.origin': 'archive'})
        add_member(tar, '.', tarfile.DIRTYPE, mode=0o755)
        add_member(tar, 'tree', tarfile.DIRTYPE, mode=0o750, mtime=1000)
        add_member(tar, 'tree/file', data=b'hello', mode=0o640, mtime=2000)
        add_member(tar, 'tree/link', tarfile.SYMTYPE, link='file', mtime=3000)
        add_member(tar, 'tree/hard', tarfile.LNKTYPE, link='tree/file')
        add_member(tar, LONG_NAME, data=b'long')
        add_member(tar, 'big', data=BIG, mode=0o600)
        add_member(tar, 'pipe', tarfile.FIFOTYPE, mode=0o600)
    with tarfile.open(root / 'gnu.tar', 'w', format=tarfile.GNU_FORMAT) as tar:
        add_member(tar, 'gnu', tarfile.DIRTYPE, mode=0o700)
        add_member(tar, GNU_NAME, data=b'gnu', mtime=4000)
        add_member(tar, 'gnu/alias', tarfile.LNKTYPE, link=GNU_NAME)
    with tarfile.open(root / 'escape.tar', 'w', format=tarfile.USTAR_FORMAT) as tar:
        add_member(tar, 'kept', data=b'kept')
        add_member(tar, 'link', tarfile.SYMTYPE, link='/out')
        add_member(tar, 'link/through', data=b'escaped')
    with tarfile.open(root / 'absolute.tar', 'w', format=tarfile.USTAR_FORMAT) as tar:
        add_member(tar, '/out/absolute', data=b'escaped')


def check_import_export(tar, stderr):
    """What archive-import left in storage, and one audit record per stream."""
    member = tar.getmember
    assert member('out/tree').isdir() and member('out/tree').mode == 0o750
    assert member('out/tree/file').mode == 0o640 and member('out/tree/file').mtime == 2000
    assert member('out/tree/link').issym() and member('out/tree/link').linkname == 'file'
    assert member('out/tree/link').mtime == 3000
    pair = sorted((member(n) for n in ('out/tree/file', 'out/tree/hard')), key=lambda m: m.islnk())
    assert pair[0].isfile() and pair[1].islnk() and pair[1].linkname == pair[0].name, pair
    assert tar.extractfile(pair[0]).read() == b'hello'
    assert tar.extractfile('out/' + LONG_NAME).read() == b'long'
    assert member('out/xattr-file').mode == 0o755
    assert tar.extractfile('out/xattr-file').read() == b'cap'
    assert member('out/big').mode == 0o600 and tar.extractfile('out/big').read() == BIG
    assert member('out/pipe').isfifo() and member('out/pipe').mode == 0o600
    assert tar.extractfile('out/' + GNU_NAME).read() == b'gnu'
    assert member('out/' + GNU_NAME).mtime == 4000 and member('out/gnu').mode == 0o700
    assert tar.extractfile('work/kept').read() == b'kept'
    assert member('work/link').issym() and member('work/link').linkname == '/out'
    names = tar.getnames()
    assert 'out/through' not in names and 'out/absolute' not in names, names
    assert 'work/gnu' in names and not any(n.startswith('work/gnu/') for n in names), names
    records = [line.split(b' ', 3)[3] for line in stderr.split(b'\n')
               if line.startswith(b'ginux: audit archive-import ')]
    outcomes = [b' '.join(r.split(b' ')[-2:]) for r in records]
    assert outcomes == [b'outcome=complete result=0', b'outcome=complete result=0',
                        b'outcome=failed result=-95', b'outcome=failed result=-40',
                        b'outcome=failed result=-22', b'outcome=incomplete result=-5'], records
    assert b'members=9 directories=1 bytes=20012' in records[0], records


def main():
    if len(sys.argv) < 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-storage.py <ginux> <storage-fixture> [scenario ...]')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:3]]
    template = (Path(__file__).resolve().parent.parent / 'config/instance-configured.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-storage-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        (root / 'work/existing').write_bytes(b'hidden immutable work file')
        (root / 'image').write_bytes(b'immutable image')
        (root / 'image-link').symlink_to('/work')
        (root / 'shadow/nest').mkdir(parents=True)
        (root / 'shadow/image').write_bytes(b'incorrect hidden path')
        (root / 'virtual').symlink_to('/shadow/nest')
        write_import_archives(root)
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)

        def invoke(assignments, args, expected=0, memory=256, export=False):
            config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
            config = config.replace('args = []', 'args = ' + json.dumps(args))
            config = config.replace('memory_mib = 256', 'memory_mib = ' + str(memory))
            config = config.replace('assignments = []', 'assignments = ' + json.dumps(assignments), 1)
            if args == ['namespace']:
                config = config.replace('[storage]\n', '[storage]\nmax_objects = 5003\n')
            if args == ['bounds']:
                config = config.replace('[storage]\n', '[storage]\nmax_bytes = 16777216\n')
            if args in (['archive-import'], ['archive-import-denied']):
                config = config.replace('[storage]\n', '[storage]\narchive_import = true\n')
            if args == ['archive-import-denied']:
                config = config.replace('deny = ["device.mmio.direct"', 'deny = ["syscall.symlinkat", "device.mmio.direct"', 1)
            config = config.replace('id = "gate5-demo"', 'id = "storage-fixture"\nworkdir = "/work"')
            if args == ['invalid-export-config']:
                config += '\n[not_a_section]\n'
            path = work / 'launch.toml'
            path.write_text(config)
            result = work / 'result.json'
            result.unlink(missing_ok=True)
            command = [binary, 'launch', str(path), str(root), '--result-file', str(result)]
            archive = work / 'export.tar'
            if export:
                archive.unlink(missing_ok=True)
                command += ['--export-file', str(archive)]
            if args == ['export-wait']:
                proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    assert select.select([proc.stdout], [], [], 5)[0], 'export readiness missing'
                    assert proc.stdout.readline() == b'export-ready\n'
                    assert not archive.exists(), 'archive published before workload completed'
                    stdout, stderr = proc.communicate(b'G', timeout=10)
                    proc.stdout, proc.stderr = stdout, stderr
                finally:
                    if proc.poll() is None:
                        proc.kill(); proc.communicate(timeout=5)
            elif args == ['mapping']:
                with (work / 'mapping.audit').open('wb') as audit:
                    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=audit)
                    try:
                        assert select.select([proc.stdout], [], [], 10)[0], 'mapping workload did not become ready'
                        assert proc.stdout.readline() == b'mapping-ready\n'
                        children = Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split()
                        assert len(children) == 1, children
                        native = sorted(p.name for p in Path(f'/proc/{children[0]}/fd').iterdir())
                        assert native == ['0', '1', '2'], ('mapping leaked native fds', native)
                        stdout, _ = proc.communicate(b'G', timeout=10)
                    finally:
                        if proc.poll() is None:
                            proc.kill()
                            proc.communicate(timeout=5)
                proc.stdout = stdout
                proc.stderr = (work / 'mapping.audit').read_bytes()
            else:
                def bounded_host_fds():
                    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                    resource.setrlimit(resource.RLIMIT_NOFILE, (min(64, hard), hard))
                proc = subprocess.run(command, capture_output=True, timeout=20,
                                      preexec_fn=bounded_host_fds if args == ['namespace'] else None)
            record = json.loads(result.read_text())
            if proc.returncode != expected:
                sys.exit(f'launch failed: {proc.returncode}\n{proc.stderr.decode()}\n{record}')
            assert record['outcome'] == ('exited' if expected in (0, 7) else 'supervisor-error'), record
            if expected == 0:
                assert record['code'] == 0 and record['generation'] is None, record
                assert proc.stdout == (b'' if args else b'memory-storage: PASS\n'), proc.stdout
            assert (root / 'image').read_bytes() == b'immutable image'
            assert (root / 'work/existing').read_bytes() == b'hidden immutable work file'
            assert sorted(p.name for p in (root / 'work').iterdir()) == ['existing']
            assert not (root / 'out').exists()
            if expected == 7: assert record['code'] == 7
            if export:
                assert not list(work.glob('.ginux-export-*')), 'staging output retained'
                if expected != 0:
                    assert not archive.exists(), 'failed workload published an archive'
                else:
                    with tarfile.open(archive) as tar:
                        names = tar.getnames()
                        assert len(names) == len(set(names)), names
                        if args == ['archive-import']:
                            check_import_export(tar, proc.stderr)
                            return
                        if args in (['timestamps'], ['ordinary-times']):
                            assert tar.getmember('work/time-alias').mtime == 123456789
                            assert tar.getmember('work/time-link').mtime == 222
                            return
                        assert 'out/deleted' not in names and 'image' not in names
                        assert tar.extractfile('out/product').read() == b'result\0data'
                        assert tar.getmember('out/product').mode == 0o700
                        assert tar.getmember('out/empty').isdir()
                        assert tar.extractfile('out/empty-file').read() == b''
                        assert tar.extractfile('out/' + 'a'*120 + '/' + 'b'*80).read() == b'long'
                        if args == ['child-export']:
                            assert tar.extractfile('out/child').read() == b'settled'
                            assert 'out/late' not in names
                    result.unlink()
                    refused = subprocess.run(command, capture_output=True, timeout=10)
                    assert refused.returncode == 2 and b'not fresh' in refused.stderr
                    with tarfile.open(archive) as tar:
                        assert tar.extractfile('out/product').read() == b'result\0data'


        def publication_parent_swap():
            config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
            config = config.replace('args = []', 'args = ["export-wait"]')
            config = config.replace('assignments = []', 'assignments = ["memory:/out"]', 1)
            path = work / 'publication-race.toml'
            path.write_text(config)
            parent = work / 'publication-parent'
            parent.mkdir()
            parked = work / 'publication-parked'
            redirected = work / 'publication-redirected'
            redirected.mkdir()
            archive = parent / 'final.tar'
            result = work / 'publication-result.json'
            command = [binary, 'launch', str(path), str(root), '--result-file', str(result),
                       '--export-file', str(archive)]
            proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            try:
                assert select.select([proc.stdout], [], [], 5)[0], 'export readiness missing'
                assert proc.stdout.readline() == b'export-ready\n'
                assert not list(parent.glob('.ginux-export-*')), 'named staging file is replaceable'
                parent.rename(parked)
                parent.symlink_to(redirected, target_is_directory=True)
                fake_stage = redirected / '.ginux-export-host-marker'
                fake_stage.write_bytes(b'host marker')
                _, stderr = proc.communicate(b'G', timeout=10)
            finally:
                if proc.poll() is None:
                    proc.kill(); proc.communicate(timeout=5)
            record = json.loads(result.read_text())
            assert proc.returncode == 1 and record['outcome'] == 'supervisor-error', (record, stderr)
            assert b'export-file parent changed' in stderr, stderr
            assert not archive.exists() and not (parked / 'final.tar').exists()
            assert fake_stage.read_bytes() == b'host marker'

        if sys.argv[3:]:
            for mode in sys.argv[3:]:
                if mode == 'publication-parent-swap':
                    publication_parent_swap()
                    print('PASS launch storage: publication-parent-swap')
                    continue
                if mode == 'bad-export-config':
                    invoke(['disk0'], ['export'], expected=2, export=True)
                    print('PASS launch storage: bad-export-config')
                    continue
                if mode not in ('growth', 'bounds', 'quota', 'view-probes', 'mapping', 'ordinary-mapping', 'ordinary-unlinked-mapping', 'symlinks', 'ordinary-symlinks', 'namespace', 'positioned', 'ownership', 'ordinary-ownership', 'ordinary-vectors', 'ordinary-large-io', 'timestamps', 'ordinary-times', 'build-metadata', 'flush', 'export', 'export-wait', 'failed-export', 'child-export', 'bad-export-config', 'invalid-export-config', 'archive-import', 'archive-import-disabled', 'archive-import-denied'):
                    sys.exit('unknown selected storage scenario')
                invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], [mode],
                       expected=2 if mode == 'invalid-export-config' else (7 if mode == 'failed-export' else 0),
                       memory=32 if mode == 'bounds' else (64 if mode == 'namespace' else 256),
                       export=mode in ('export', 'export-wait', 'failed-export', 'child-export', 'invalid-export-config', 'timestamps', 'ordinary-times', 'archive-import'))
                print(f'PASS launch storage: {mode}')
            return
        invoke(['memory:/work'], ['view-probes'])
        invoke(['memory:/work'], ['build-metadata'])
        invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], ['growth'])
        for mode in ['path-owned', 'missing-owned', 'image-parent', 'alias-shadow']:
            invoke(['memory:/work'], [mode])
        invoke(['memory:/work', 'memory:/virtual'], ['cross-boundary'])
        invoke(['memory:/work', 'memory:/virtual'], ['scratch-restoration'])
        invoke(['memory:/work'], ['type-flags'])
        for _ in range(2):
            invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], [])
        invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], ['quota'])
        invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], ['bounds'], memory=32)
        invoke(['memory:/work', 'memory:/out'], ['mapping'])
        invoke(['memory:/work', 'memory:/out'], ['ordinary-mapping'])
        invoke(['memory:/work', 'memory:/out'], ['ordinary-unlinked-mapping'])
        invoke(['memory:/work', 'memory:/out'], ['timestamps'], export=True)
        invoke(['memory:/work', 'memory:/out'], ['symlinks'])
        invoke(['memory:/work', 'memory:/out'], ['ordinary-symlinks'])
        invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], ['namespace'], memory=64)
        invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], ['positioned'])
        invoke(['memory:/work', 'memory:/out'], ['flush'])
        invoke(['memory:/work', 'memory:/out'], ['export'], export=True)
        invoke(['memory:/work', 'memory:/out'], ['export-wait'], export=True)
        publication_parent_swap()
        invoke(['memory:/work', 'memory:/out'], ['child-export'], export=True)
        invoke(['memory:/work', 'memory:/out'], ['failed-export'], expected=7, export=True)
        invoke(['memory:/work', 'memory:/out'], ['invalid-export-config'], expected=2, export=True)
        invoke(['disk0'], ['export'], expected=2, export=True)
        for mode in ['ordinary-vectors', 'ordinary-large-io']:
            invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], [mode])
        invoke(['memory:/work'], ['ownership'])
        invoke(['memory:/work', 'memory:/out'], ['archive-import'], export=True)
        invoke(['memory:/work', 'memory:/out'], ['archive-import-disabled'])
        invoke(['memory:/work', 'memory:/out'], ['archive-import-denied'])
        invoke([], ['no-storage'])
        for assignment in ['disk0', 'memory:/', 'memory:/proc', 'memory:/sys/x', 'memory:/dev',
                           'memory:/bin', 'memory:/work/../out', 'memory:/work/', 'memory:work']:
            invoke([assignment], [], 2)
        invoke(['memory:/work', 'memory:/work'], [], 2)
        print('test-launch-storage: PASS (isolation, data, metadata, copy protections, bounds, fresh launch)')


if __name__ == '__main__':
    main()
