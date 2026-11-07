#!/usr/bin/env python3
"""Exercise owned directory descriptions through actual configured launch."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv)<3 or os.geteuid()!=0:
        sys.exit('usage (as root): test-launch-directories.py <ginux> <directory-fixture> [scenario ...]')
    binary,fixture=[str(Path(p).resolve()) for p in sys.argv[1:3]]
    template=(Path(__file__).resolve().parent.parent/'config/instance-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-directories-') as directory:
        work=Path(directory)
        root=work/'root'
        (root/'bin').mkdir(parents=True)
        (root/'work').mkdir()
        (root/'image-dir').mkdir()
        shutil.copyfile(fixture,root/'image-dir/fixture')
        (root/'image-dir/fixture').chmod(0o755)
        (root/'image-dir/input').write_bytes(b'image-child')
        shutil.copyfile(fixture,root/'bin/fixture')
        (root/'bin/fixture').chmod(0o755)
        (root/'image').write_bytes(b'immutable image')
        (root/'image-work').symlink_to('/work')
        (root/'image-cycle').symlink_to('/work/cycle')
        (root/'work/hidden').write_bytes(b'hidden image bytes')
        (root/'private').mkdir(mode=0)
        config=template.replace('init = "/bin/bash"','init = "/bin/fixture"')
        config=config.replace('[storage]\nassignments = []','[storage]\nassignments = ["memory:/work", "memory:/work/seed"]')
        config=config.replace('[devices]\nassignments = []','[devices]\nassignments = ["null"]')
        for mode in (sys.argv[3:] or ['all', 'cwd', 'owned-cwd', 'ordinary-owned-cwd', 'ordinary-cwd-budget', 'hardlinks', 'ordinary-hardlinks', 'ordinary-hardlink-quota', 'ordinary-cross', 'ordinary-cross-exec', 'ordinary-image-dir-exec', 'cross']):
            if mode not in ('all', 'functional', 'cwd', 'owned-cwd', 'ordinary-owned-cwd', 'ordinary-cwd-budget', 'hardlinks', 'ordinary-hardlinks', 'ordinary-hardlink-quota', 'ordinary-cross', 'ordinary-cross-exec', 'ordinary-image-dir-exec', 'cross'):
                sys.exit('unknown directory scenario')
            # Each launch creates fresh instance storage; image cwd stays kernel-owned.
            (work/'launch.toml').write_text(config.replace('args = []', 'args = ' + json.dumps([] if mode == 'all' else [mode])))
            if mode == 'ordinary-hardlink-quota':
                (work/'launch.toml').write_text((work/'launch.toml').read_text().replace('memory_mib = 256', 'memory_mib = 16'))
            for i in range(2):
                result=work/f'{mode}-{i}.json'
                proc=subprocess.run([binary,'launch',str(work/'launch.toml'),str(root),'--result-file',str(result)],capture_output=True,timeout=20)
                record=json.loads(result.read_text())
                assert proc.returncode==0,(proc.returncode,proc.stderr,record)
                assert record['outcome']=='exited' and record['code']==0 and record['generation'] is None,record
                assert proc.stdout==b'owned-directories: PASS\n',proc.stdout
                assert b'ginux: teardown tasks=0 owned-handles=0' in proc.stderr,proc.stderr
                assert sorted(p.name for p in (root/'work').iterdir())==['hidden']
                assert (root/'work/hidden').read_bytes()==b'hidden image bytes'
                assert (root/'image').read_bytes()==b'immutable image'
            print(f'PASS launch directories: {mode}')
        print('test-launch-directories: PASS (' + (', '.join(sys.argv[3:]) if sys.argv[3:] else 'full directory scenarios') + ')')


if __name__=='__main__':
    main()
