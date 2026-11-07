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


def main():
    if len(sys.argv) < 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-storage.py <ginux> <storage-fixture> [scenario ...]')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:3]]
    template = (Path(__file__).resolve().parent.parent / 'config/instance-gate5.toml').read_text()
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


        if sys.argv[3:]:
            for mode in sys.argv[3:]:
                if mode == 'bad-export-config':
                    invoke(['disk0'], ['export'], expected=2, export=True)
                    print('PASS launch storage: bad-export-config')
                    continue
                if mode not in ('growth', 'bounds', 'quota', 'view-probes', 'mapping', 'ordinary-mapping', 'ordinary-unlinked-mapping', 'symlinks', 'ordinary-symlinks', 'namespace', 'positioned', 'ownership', 'ordinary-ownership', 'ordinary-vectors', 'ordinary-large-io', 'timestamps', 'ordinary-times', 'flush', 'export', 'export-wait', 'failed-export', 'child-export', 'bad-export-config', 'invalid-export-config'):
                    sys.exit('unknown selected storage scenario')
                invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], [mode],
                       expected=2 if mode == 'invalid-export-config' else (7 if mode == 'failed-export' else 0),
                       memory=32 if mode == 'bounds' else (64 if mode == 'namespace' else 256),
                       export=mode in ('export', 'export-wait', 'failed-export', 'child-export', 'invalid-export-config', 'timestamps', 'ordinary-times'))
                print(f'PASS launch storage: {mode}')
            return
        invoke(['memory:/work'], ['view-probes'])
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
        invoke(['memory:/work', 'memory:/out'], ['child-export'], export=True)
        invoke(['memory:/work', 'memory:/out'], ['failed-export'], expected=7, export=True)
        invoke(['memory:/work', 'memory:/out'], ['invalid-export-config'], expected=2, export=True)
        invoke(['disk0'], ['export'], expected=2, export=True)
        for mode in ['ordinary-vectors', 'ordinary-large-io']:
            invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], [mode])
        invoke(['memory:/work'], ['ownership'])
        invoke([], ['no-storage'])
        for assignment in ['disk0', 'memory:/', 'memory:/proc', 'memory:/sys/x', 'memory:/dev',
                           'memory:/bin', 'memory:/work/../out', 'memory:/work/', 'memory:work']:
            invoke([assignment], [], 2)
        invoke(['memory:/work', 'memory:/work'], [], 2)
        print('test-launch-storage: PASS (isolation, data, metadata, copy protections, bounds, fresh launch)')


if __name__ == '__main__':
    main()
