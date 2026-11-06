#!/usr/bin/env python3
"""Real configured-launch storage checks against explicit existing binaries."""
import json
import os
from pathlib import Path
import shutil
import select
import resource
import subprocess
import sys
import tempfile
import tarfile


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-storage.py <ginux> <storage-fixture>')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent / 'config/domain-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-storage-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        (root / 'work/existing').write_bytes(b'hidden immutable work file')
        (root / 'image').write_bytes(b'immutable image')
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)

        def invoke(assignments, args, expected=0, memory=256, export=False):
            config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
            config = config.replace('args = []', 'args = ' + json.dumps(args))
            config = config.replace('memory_mib = 256', 'memory_mib = ' + str(memory))
            config = config.replace('assignments = []', 'assignments = ' + json.dumps(assignments), 1)
            if args == ['quota']:
                config = config.replace('[storage]\n', '[storage]\nmax_objects = 8192\n')
            if args == ['bounds']:
                config = config.replace('[storage]\n', '[storage]\nmax_bytes = 16777216\n')
            config = config.replace('id = "gate5-demo"' , 'id = "storage-fixture"\nworkdir = "/work"')
            path = work / 'launch.toml'
            path.write_text(config)
            result = work / 'result.json'
            result.unlink(missing_ok=True)
            command = [binary, 'launch', str(path), str(root), '--result-file', str(result)]
            archive = work / 'export.tar'
            if export:
                archive.unlink(missing_ok=True)
                command += ['--export-file', str(archive)]
            if args == ['mapping']:
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
                    resource.setrlimit(resource.RLIMIT_NOFILE, (min(1024, hard), hard))
                proc = subprocess.run(command, capture_output=True, timeout=90 if args == ['quota'] else 20,
                                      preexec_fn=bounded_host_fds if args == ['quota'] else None)
            record = json.loads(result.read_text())
            if proc.returncode != expected:
                sys.exit(f'launch failed: {proc.returncode}\n{proc.stderr.decode()}\n{record}')
            assert record['outcome'] == ('supervisor-error' if expected == 2 else 'exited'), record
            if expected == 0:
                assert record['code'] == 0 and record['generation'] is None, record
                assert proc.stdout == (b'' if args else b'memory-storage: PASS\n'), proc.stdout
            assert (root / 'image').read_bytes() == b'immutable image'
            assert (root / 'work/existing').read_bytes() == b'hidden immutable work file'
            assert sorted(p.name for p in (root / 'work').iterdir()) == ['existing']
            assert not (root / 'out').exists()
            assert not (root / 'escape').exists()
            if export:
                if expected != 0:
                    assert archive.read_bytes() == b'', 'failed workload exported files'
                else:
                    with tarfile.open(archive) as tar:
                        names = tar.getnames()
                        assert len(names) == len(set(names)), names
                        if args == ['timestamps']:
                            assert tar.getmember('work/time').mtime == 123456789
                            assert tar.getmember('work/time-alias').islnk()
                            assert tar.getmember('work/time-alias').mtime == 123456789
                            assert tar.getmember('work/time-link').mtime == 222
                            return
                        assert 'out/deleted' not in names and 'image' not in names
                        assert tar.extractfile('out/product').read() == b'result\0data'
                        assert tar.getmember('out/product').mode == 0o700
                        assert tar.getmember('out/empty').isdir()
                        assert tar.getmember('out/product-link').issym()
                        assert tar.getmember('out/product-link').linkname == 'product'
                        assert tar.getmember('out/long-link').linkname == '/out/' + 'a'*120 + '/' + 'b'*80
                        assert tar.extractfile('out/' + 'a'*120 + '/' + 'b'*80).read() == b'long'
                    # The same destination must fail before starting the workload.
                    result.unlink()
                    refused = subprocess.run(command, capture_output=True, timeout=10)
                    assert refused.returncode == 2 and b'not fresh' in refused.stderr
                    with tarfile.open(archive) as tar:
                        assert tar.extractfile('out/product').read() == b'result\0data'

        for _ in range(2):
            invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], [])
        invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], ['quota'])
        invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], ['bounds'], memory=32)
        invoke(['memory:/work', 'memory:/out'], ['timestamps'], export=True)
        invoke(['memory:/work', 'memory:/out'], ['symlinks'])
        invoke(['memory:/work', 'memory:/out'], ['mapping'])
        invoke(['memory:/work', 'memory:/out'], ['export'], export=True)
        invoke(['memory:/work', 'memory:/out'], ['failed-export'], expected=7, export=True)
        invoke([], ['no-storage'])
        for assignment in ['disk0', 'memory:/', 'memory:/proc', 'memory:/sys/x', 'memory:/dev',
                           'memory:/bin', 'memory:/work/../out', 'memory:/work/', 'memory:work']:
            invoke([assignment], [], 2)
        invoke(['memory:/work', 'memory:/work'], [], 2)
        print('test-launch-storage: PASS (isolation, data, metadata, copy protections, bounds, fresh launch)')


if __name__ == '__main__':
    main()
