#!/usr/bin/env python3
"""Exercise private snapshot control against a real configured workload."""
import json
import os
from pathlib import Path
import select
import shutil
import signal
import time
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile


def receive(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        assert chunk, 'control socket closed before acknowledgement'
        data.extend(chunk)
    return bytes(data)


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-checkpoints.py <ginux> <storage-fixture>')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent / 'config/domain-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-checkpoints-') as folder:
        work = Path(folder)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)
        config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
        config = config.replace('args = []', 'args = ["checkpoint"]')
        config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
        config_path = work / 'config.toml'
        config_path.write_text(config)
        for failure in (None, 'replay', 'existing'):
            client, server = socket.socketpair()
            client.settimeout(5)
            result = work / f'result-{failure}.json'
            with (work / f'audit-{failure}').open('wb') as audit:
                proc = subprocess.Popen([binary, 'launch', str(config_path), str(root),
                    '--result-file', str(result), '--control-fd', str(server.fileno())],
                    pass_fds=(server.fileno(),), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=audit)
                server.close()
                try:
                    for sequence, expected in ((1, b'first'), (2, b'second')):
                        assert select.select([proc.stdout], [], [], 5)[0]
                        assert proc.stdout.readline() == b'checkpoint-ready\n'
                        children = Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split()
                        assert len(children) == 1
                        assert sorted(p.name for p in Path(f'/proc/{children[0]}/fd').iterdir()) == ['0', '1', '2']
                        archive = work / f'snapshot-{failure}-{sequence}.tar'
                        if sequence == 2 and failure == 'existing':
                            archive.write_bytes(b'preserve')
                        request_id = 1 if sequence == 2 and failure == 'replay' else sequence
                        path = os.fsencode(archive)
                        frame = b'GXS1' + struct.pack('<QH', request_id, len(path)) + path
                        client.sendall(frame[:5])
                        assert not select.select([client], [], [], .02)[0], 'partial request acknowledged'
                        client.sendall(frame[5:])
                        if sequence == 2 and failure:
                            stdout, _ = proc.communicate(timeout=5)
                            assert proc.returncode == 1 and not stdout
                            assert json.loads(result.read_text())['outcome'] == 'supervisor-error'
                            if failure == 'existing': assert archive.read_bytes() == b'preserve'
                            else: assert not archive.exists()
                            break
                        assert receive(client, 20) == b'GXA1' + struct.pack('<QQ', sequence, 0)
                        with tarfile.open(archive) as tar:
                            assert tar.extractfile('work/checkpoint').read() == expected
                        proc.stdin.write(b'G')
                        proc.stdin.flush()
                    if failure is None:
                        stdout, _ = proc.communicate(timeout=5)
                        assert proc.returncode == 0 and not stdout
                        with tarfile.open(work / 'snapshot-None-1.tar') as tar:
                            assert tar.extractfile('work/checkpoint').read() == b'first'
                        assert json.loads(result.read_text())['code'] == 0
                finally:
                    client.close()
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
        # An idle control socket must not impose a timer tick per syscall stop.
        # Also cover callers that ignore SIGCHLD: the private event wait must
        # establish its own signal disposition without changing guest semantics.
        config_path.write_text(config.replace('args = ["checkpoint"]', 'args = ["latency"]'))
        for controlled in (False, True):
            client, server = socket.socketpair()
            try:
                command = [binary, 'launch', str(config_path), str(root)]
                if controlled:
                    command += ['--control-fd', str(server.fileno())]
                start = time.monotonic()
                proc = subprocess.run(command, pass_fds=(server.fileno(),) if controlled else (),
                    preexec_fn=lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN),
                    capture_output=True, timeout=10)
                assert proc.returncode == 0, proc.stderr.decode()
                assert proc.stdout == b'events: PASS\n', proc.stdout
                print(f'10000 syscalls, control={controlled}: {time.monotonic()-start:.3f}s')
            finally:
                client.close()
                server.close()
        def restore(archive, expected='first', failure=False, assignments='memory:/work'):
            result = work / 'restore-result.json'
            result.unlink(missing_ok=True)
            config_path.write_text(config.replace('args = ["checkpoint"]', 'args = ' + json.dumps(['restore', expected])).replace('memory:/work', assignments))
            proc = subprocess.run([binary, 'launch', str(config_path), str(root), '--result-file', str(result),
                                   '--restore-file', str(archive)], capture_output=True, timeout=5)
            assert proc.returncode == (2 if failure else 0), proc.stderr.decode()
            assert proc.stdout == (b'' if failure else b'restored: PASS\n'), proc.stdout
            assert json.loads(result.read_text())['outcome'] == ('supervisor-error' if failure else 'exited')

        for sequence, expected in ((1, 'first'), (2, 'second')):
            archive = work / f'snapshot-None-{sequence}.tar'
            original = archive.read_bytes()
            restore(archive, expected)
            assert archive.read_bytes() == original, 'restore mutated its snapshot'
        restore(work / 'snapshot-None-1.tar', failure=True, assignments='memory:/out')
        snapshot = (work / 'snapshot-None-1.tar').read_bytes()
        for name, data in (('truncated', snapshot[:-512]), ('checksum', b'x' + snapshot[1:])):
            archive = work / f'{name}.tar'
            archive.write_bytes(data)
            restore(archive, failure=True)
        for kind in ('traversal', 'symlink', 'hardlink', 'duplicate'):
            archive = work / f'{kind}.tar'
            with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as tar:
                entry = tarfile.TarInfo('work/../../escaped' if kind == 'traversal' else 'work')
                entry.mode = 0o700
                entry.type = {'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE}.get(kind, tarfile.DIRTYPE)
                entry.linkname = '/outside' if kind in ('symlink', 'hardlink') else ''
                tar.addfile(entry)
                if kind == 'duplicate': tar.addfile(entry)
            restore(archive, failure=True)
        link = work / 'snapshot-link.tar'
        link.symlink_to(work / 'snapshot-None-1.tar')
        restore(link, failure=True)
        assert not (work / 'escaped').exists()
        print('test-launch-checkpoints: PASS (capture, restore, long paths, isolation, private fds, malformed inputs)')


if __name__ == '__main__':
    main()
