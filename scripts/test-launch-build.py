#!/usr/bin/env python3
"""Build ncurses and htop using supplied sources and a compiler rootfs archive.

This test downloads nothing and never invokes a package manager. The root must
contain a C compiler, development headers, make, cmp, pkg-config, and ordinary
shell build tools.
All source/build/install files live in the launcher's assigned memory storage.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tarfile
import time

BUILD = r'''#!/bin/sh
set -eu
report_failure() {
    status=$?
    if [ "$status" -ne 0 ]; then
        printf '\nBUILD FAILED: status=%s directory=%s\n' "$status" "$PWD"
        for log in /work/ncurses/config.log /work/htop/config.log; do
            if [ -f "$log" ]; then
                printf '\n===== %s =====\n' "$log"
                cat "$log"
            fi
        done
    fi
    exit "$status"
}
trap report_failure EXIT
for tool in sh gcc make install sed awk grep cmp pkg-config; do command -v "$tool"; done
cd /work/ncurses
./configure --prefix=/usr --enable-widec --with-normal --without-shared \
    --without-debug --without-cxx --without-cxx-binding --without-ada \
    --without-manpages --without-progs --without-tests --disable-db-install \
    --with-default-terminfo-dir=/usr/share/terminfo \
    --with-terminfo-dirs=/usr/share/terminfo:/usr/lib/terminfo:/etc/terminfo
make -j4
make install DESTDIR=/work/ncurses-stage
cd /work/htop
CURSES_CFLAGS='-I/work/ncurses-stage/usr/include -I/work/ncurses-stage/usr/include/ncursesw' \
CURSES_LIBS='-L/work/ncurses-stage/usr/lib -lncursesw' \
    ./configure --prefix=/usr
make -j4
make install DESTDIR=/work/htop-stage
/work/htop-stage/usr/bin/htop --version
printf '\nGINUX HTOP BUILD: PASS\n'
'''


def source_entries(output, archive_path, destination):
    """Retain source bytes, modes and times while normalizing one top directory."""
    with tarfile.open(archive_path) as source:
        members = source.getmembers()
        roots = {Path(member.name).parts[0] for member in members}
        if len(roots) != 1:
            raise ValueError(f'{archive_path}: expected one source directory')
        root = roots.pop()
        for original in members:
            path = Path(original.name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError(f'{archive_path}: unsafe member {original.name}')
            member = copy.copy(original)
            member.name = str(Path(destination).joinpath(*path.parts[1:]))
            if member.islnk():
                target = Path(member.linkname)
                if target.is_absolute() or '..' in target.parts or target.parts[0] != root:
                    raise ValueError(f'{archive_path}: unsafe hardlink {member.linkname}')
                member.linkname = str(Path(destination).joinpath(*target.parts[1:]))
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError(f'{archive_path}: unsupported member {original.name}')
            output.addfile(member, source.extractfile(original) if member.isfile() else None)


def main():
    if len(sys.argv) not in (5, 6) or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-build.py <ginux> <compiler-rootfs.tar> '
                 '<ncurses.tar.gz> <htop.tar.xz> [fresh-output-directory]')
    binary, rootfs, ncurses, htop = [Path(arg).resolve() for arg in sys.argv[1:5]]
    output = (Path(sys.argv[5]).resolve() if len(sys.argv) == 6 else
              Path(__file__).resolve().parent.parent/'.artifacts'/
              ('launch-build-' + time.strftime('%Y%m%d-%H%M%S', time.gmtime())))
    output.mkdir(parents=True)
    root = output/'root'
    root.mkdir()
    subprocess.run(['tar', '-xf', str(rootfs), '-C', str(root), '--no-same-owner',
                    '--anchored', '--exclude=dev/*', '--exclude=proc/*', '--exclude=sys/*'],
                   check=True)
    started = time.monotonic()
    manifest = {'ginux_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'compiler_rootfs': str(rootfs), 'sources': {
                    str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in [ncurses, htop]}}
    restore = output/'sources.tar'
    with tarfile.open(restore, 'w', format=tarfile.USTAR_FORMAT) as archive:
        for name in ['work', 'tmp']:
            member = tarfile.TarInfo(name)
            member.type, member.mode = tarfile.DIRTYPE, 0o777
            archive.addfile(member)
        source_entries(archive, ncurses, 'work/ncurses')
        source_entries(archive, htop, 'work/htop')
        script = BUILD.encode()
        member = tarfile.TarInfo('work/build.sh')
        member.mode, member.size = 0o755, len(script)
        archive.addfile(member, io.BytesIO(script))
        end = archive.offset
    # The restore format ends with exactly two zero blocks, without tarfile's
    # optional padding to a 10 KiB record boundary.
    with restore.open('r+b') as stream:
        stream.truncate(end + 1024)
    template = (Path(__file__).resolve().parent.parent/'config/instance-configured.toml').read_text()
    config = template.replace('id = "gate5-demo"', 'id = "source-build"\nworkdir = "/"')
    config = config.replace('args = []', 'args = ["/work/build.sh"]')
    config = config.replace('environment = ["container=ginux"]', 'environment = ' + json.dumps([
        'PATH=/usr/bin:/bin', 'HOME=/work', 'TMPDIR=/tmp', 'LC_ALL=C', 'CFLAGS=-O2']))
    config = config.replace('vcpus = 1', 'vcpus = 4').replace('memory_mib = 256', 'memory_mib = 2048')
    config = config.replace('[storage]\nassignments = []', '[storage]\n'
                            'assignments = ["memory:/work", "memory:/tmp"]\n'
                            'max_bytes = 1073741824\nmax_objects = 32768')
    config = config.replace('[devices]\nassignments = []', '[devices]\nassignments = ["null"]')
    (output/'launch.toml').write_text(config)
    command = [str(binary), 'launch', str(output/'launch.toml'), str(root),
               '--restore-file', str(restore), '--result-file', str(output/'result.json'),
               '--export-file', str(output/'export.tar')]
    manifest['command'] = command
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(f'Build output: {output}', flush=True)
    with (output/'stdout.log').open('wb') as stdout, (output/'stderr.log').open('wb') as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            status = process.wait(timeout=2400)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            status = 124
    manifest.update(exit=status, seconds=time.monotonic()-started)
    if (output/'result.json').exists():
        try:
            manifest['completion'] = json.loads((output/'result.json').read_text())
        except json.JSONDecodeError:
            manifest['completion'] = None
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    if status != 0:
        sys.exit(f'Build failed ({status}); see {output}/stdout.log and stderr.log')
    with tarfile.open(output/'export.tar') as archive:
        expected = ['work/htop-stage/usr/bin/htop',
                    'work/htop-stage/usr/share/applications/htop.desktop',
                    'work/htop-stage/usr/share/man/man1/htop.1']
        for name in expected:
            member = archive.getmember(name)
            assert member.isfile() and member.size > 0, name
        program = archive.getmember(expected[0])
        assert program.mode & 0o111, 'installed htop is not executable'
        manifest['htop_sha256'] = hashlib.sha256(archive.extractfile(program).read()).hexdigest()
        config_header = archive.extractfile('work/htop/config.h').read().decode()
        assert not re.search(r'^\s*#\s*define\s+uid_t\b', config_header, re.MULTILINE), \
            'configure incorrectly replaced the system uid_t type'
    stdout = (output/'stdout.log').read_text(errors='replace')
    assert 'htop ' in stdout and 'GINUX HTOP BUILD: PASS' in stdout, 'missing htop execution evidence'
    assert 'checking for uid_t in sys/types.h... yes' in stdout, 'uid_t configure probe failed'
    stderr = (output/'stderr.log').read_text(errors='replace')
    assert 'here-document at line' not in stderr, \
        'generated configure script lost a here-document'
    assert 'jobserver mkfifo' not in stderr and '--jobserver-style=pipe' not in stderr, \
        'make could not use its named FIFO jobserver'
    assert not re.search(r'(?:cmp|pkg-config): (?:command )?not found', stdout + stderr), \
        'build image is missing a required tool'
    assert manifest['completion']['outcome'] == 'exited' and manifest['completion']['code'] == 0
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print('test-launch-build: PASS (configure, parallel make, make install, installed htop execution)')


if __name__ == '__main__':
    main()
