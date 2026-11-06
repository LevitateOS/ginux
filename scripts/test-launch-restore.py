#!/usr/bin/env python3
"""Startup filesystem reconstruction against explicit existing binaries."""
import io
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile


def main():
    if len(sys.argv) not in (3, 4) or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-restore.py <ginux> <storage-fixture> [ordinary]')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:3]]
    ordinary = len(sys.argv) == 4
    if ordinary and sys.argv[3] != 'ordinary':
        sys.exit('unknown restore selection')
    template = (Path(__file__).resolve().parent.parent / 'config/domain-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-restore-') as folder:
        work = Path(folder)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'out').mkdir()
        (root / 'out/image').write_bytes(b'immutable image')
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)
        config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
        config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/out"]')
        config_path = work / 'config.toml'
        result = work / 'result.json'

        def launch(mode, archive=None, exported=None, failure=False, assignments='memory:/out', objects=None, memory=256):
            effective = config.replace('args = []', 'args = ' + json.dumps([mode])).replace('memory:/out', assignments)
            effective = effective.replace('memory_mib = 256', 'memory_mib = ' + str(memory))
            if objects is not None:
                effective = effective.replace('[storage]\n', '[storage]\nmax_objects = ' + str(objects) + '\n')
            config_path.write_text(effective)
            result.unlink(missing_ok=True)
            command = [binary, 'launch', str(config_path), str(root), '--result-file', str(result)]
            if archive is not None:
                command += ['--restore-file', str(archive)]
            if exported is not None:
                command += ['--export-file', str(exported)]
            proc = subprocess.run(command, capture_output=True, timeout=120)
            assert proc.returncode == (2 if failure else 0), proc.stderr.decode()
            assert proc.stdout == (b'restored: PASS\n' if mode.startswith('restore') and not failure else b''), proc.stdout
            record = json.loads(result.read_text())
            assert record['outcome'] == ('supervisor-error' if failure else 'exited'), record
            if not failure:
                assert record['code'] == 0
            if failure and exported is not None:
                assert not exported.exists()
            assert not list(work.glob('.ginux-export-*'))
            assert (root / 'out/image').read_bytes() == b'immutable image'
            assert sorted(p.name for p in (root / 'out').iterdir()) == ['image']

        snapshot = work / 'snapshot.tar'
        launch('export', exported=snapshot)
        original = snapshot.read_bytes()
        # Each restart is a fresh memory view; mutations must not alter its source.
        for n in range(2):
            exported = work / f'restored-{n}.tar'
            launch('restore', snapshot, exported)
            assert snapshot.read_bytes() == original, 'restore mutated its snapshot'
            with tarfile.open(exported) as tar:
                assert tar.extractfile('out/product').read() == b'changed'
                assert tar.extractfile('out/' + 'a'*120 + '/' + 'b'*80).read() == b'long'
                assert tar.getmember('out/product').mode == 0o700

        # A valid child entry may precede its directory in the exported slot order.
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            data = bytes(n % 251 for n in range(8193))
            entry = tarfile.TarInfo('out/nested/data')
            entry.mode, entry.size = 0o640, len(data)
            tar.addfile(entry, io.BytesIO(data))
            entry = tarfile.TarInfo('out/nested')
            entry.type, entry.mode = tarfile.DIRTYPE, 0o700
            tar.addfile(entry)
            size = tar.offset
        large = work / 'large.tar'
        large.write_bytes(stream.getvalue()[:size+1024])
        launch('restore-large', large)

        linked = work/'links.tar'
        launch('archive-create', exported=linked)
        linked_original = linked.read_bytes()
        with tarfile.open(linked) as tar:
            assert tar.getmember('out/product-alias').islnk()
            assert tar.getmember('out/product-alias').linkname == 'out/product'
            assert tar.getmember('out/product').mtime == 123456789
            assert tar.getmember('out/product-alias').mtime == 123456789
            assert tar.getmember('out/product-link').mtime == 222
            assert tar.getmember('out/long-alias').linkname == 'out/' + 'a'*120 + '/' + 'b'*80
            assert tar.getmember('out/product-link').issym()
            assert tar.getmember('out/product-link').linkname == 'product'
            assert tar.getmember('out/long-link').linkname == '/out/' + 'a'*120 + '/' + 'b'*80
            assert tar.extractfile('out/surviving').read() == b'orphan'
            assert 'out/temporary' not in tar.getnames()
        updated = work/'links-updated.tar'
        launch('restore-links', linked, updated)
        assert linked.read_bytes() == linked_original
        with tarfile.open(updated) as tar:
            assert tar.extractfile('out/product-alias').read() == b'changed'
            assert tar.getmember('out/product-alias').islnk()

        namespace = work/'namespace.tar'
        launch('namespace', exported=namespace, objects=5001, memory=64)
        with tarfile.open(namespace) as tar:
            assert sum(member.isfile() for member in tar.getmembers()) == 5000
        launch('restore-namespace', namespace, objects=5001, memory=64)

        # A complete valid payload crosses the old2 GiB ceiling. Sparse host
        # construction avoids writing the source's zero bytes twice.
        big, big_export = work/'big.tar', work/'big-export.tar'
        entry = tarfile.TarInfo('out/big')
        entry.mode, entry.size = 0o600, 2*1024*1024*1024+1
        with big.open('wb') as stream:
            stream.write(entry.tobuf(format=tarfile.USTAR_FORMAT))
            stream.seek(512+entry.size-1)
            stream.write(b'Z')
            stream.write(bytes((-entry.size)%512+1024))
        launch('restore-big', big, big_export, memory=4096)
        with tarfile.open(big_export) as tar:
            member = tar.getmember('out/big')
            assert member.size == entry.size
            contents = tar.extractfile(member)
            assert contents.read(1) == b'\0'
            contents.seek(entry.size-2)
            assert contents.read(2) == b'\0Z'
            contents.seek(0)
            actual, expected = hashlib.sha256(), hashlib.sha256()
            for chunk in iter(lambda: contents.read(1024*1024), b''):
                actual.update(chunk)
            zeros = bytes(1024*1024)
            for _ in range(2048):
                expected.update(zeros)
            expected.update(b'Z')
            assert actual.digest() == expected.digest(), 'large payload bytes changed'
        big.unlink(); big_export.unlink()

        if not ordinary:
            launch('restore', snapshot, work/'outside.tar', failure=True, assignments='memory:/work')
            for name, data in (('truncated', original[:-512]), ('checksum', b'x' + original[1:])):
                archive = work / f'{name}.tar'
                archive.write_bytes(data)
                launch('restore', archive, work/f'{name}-export.tar', failure=True)
            for kind in ('traversal', 'symlink', 'hardlink', 'duplicate'):
                archive = work / f'{kind}.tar'
                with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as tar:
                    entry = tarfile.TarInfo('out/../../escaped' if kind == 'traversal' else 'out')
                    entry.mode = 0o700
                    entry.type = {'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE}.get(kind, tarfile.DIRTYPE)
                    entry.linkname = '/outside' if kind in ('symlink', 'hardlink') else ''
                    tar.addfile(entry)
                    if kind == 'duplicate':
                        tar.addfile(entry)
                launch('restore', archive, work/f'{kind}-export.tar', failure=True)
            for name, target, target_type, extra in (
                    ('forward-hardlink', 'out/future', None, None),
                    ('absolute-hardlink', '/out/product', None, None),
                    ('traversing-hardlink', 'out/../product', None, None),
                    ('directory-hardlink', 'out/dir', tarfile.DIRTYPE, None),
                    ('symlink-hardlink', 'out/sym', tarfile.SYMTYPE, None),
                    ('hardlink-mode', 'out/source', tarfile.REGTYPE, 0o700),
                    ('hardlink-mtime', 'out/source', tarfile.REGTYPE, None)):
                archive = work/(name+'.tar')
                with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as tar:
                    if target_type is not None:
                        entry = tarfile.TarInfo(target)
                        entry.type, entry.mode = target_type, 0o600
                        if target_type == tarfile.SYMTYPE:
                            entry.linkname, entry.mode = '/out/source', 0o777
                        tar.addfile(entry)
                    entry = tarfile.TarInfo('out/bad-alias')
                    entry.type, entry.linkname, entry.mode = tarfile.LNKTYPE, target, extra or 0o600
                    if name == 'hardlink-mtime': entry.mtime = 1
                    tar.addfile(entry)
                launch('restore', archive, failure=True)
            link = work / 'snapshot-link.tar'
            link.symlink_to(snapshot)
            launch('restore', link, failure=True)
            assert not (work / 'escaped').exists()
        print('test-launch-restore: PASS (' + ('ordinary roundtrip, links,5000 nonempty files and complete >2 GiB payload' if ordinary else 'roundtrip, startup isolation, parent ordering and malformed inputs') + ')')


if __name__ == '__main__':
    main()
