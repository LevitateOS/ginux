#!/usr/bin/env python3
"""Check the interim public lifecycle end to end through the CLI (Linux/root, offline).

A private state root holds everything. A one-layer OCI image layout around the
native fixture is imported with `import-image`, instances are imported from a
recipe naming it by digest (no network), and `start --wait`, `status --format
json`, `extract` and `delete` are driven through `sudo` exactly as a caller
would, which also checks that sudo passes binary standard input and output
through unchanged. `inject` is called on the helper directly with its argument
grammar (tar on standard input) and once through the CLI. One instance gets its
init by `inject` after create. Instance directories and logs are root-private
whatever the umask, and `start --wait --stream-console` delivers the console
output on standard output (and the audit log tail on standard error after a
failed run).
"""
import hashlib
import io
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

SUPERVISOR_ERROR = {"version": 1, "outcome": "supervisor-error", "code": None,
                    "signal": None, "generation": None}
DATA = bytes(range(256)) * 64 + b"\r\n\x00\x04\x03\x1a"
HELLO = b"hello from the instance\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, separators=(",", ":")).encode()


def layer_tar(fixture):
    """The root filesystem tar: fixed order, fixed times, root ownership."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        def add(name, kind, mode, data=b"", target=""):
            info = tarfile.TarInfo(name)
            info.type = kind
            info.mode = mode
            info.mtime = 1700000000
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if kind == tarfile.REGTYPE:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                info.linkname = target
                archive.addfile(info)
        for directory in ("bin", "etc", "usr", "usr/bin", "out", "out/sub"):
            add(directory, tarfile.DIRTYPE, 0o755)
        add("usr/bin/bash", tarfile.REGTYPE, 0o755, Path(fixture).read_bytes())
        # `native-hook` runs hooks as `/bin/sh -c COMMAND`. The image has no
        # shell, so the fixture stands in for it: it ignores its arguments and
        # exits with the scenario's code (81 for "Z"), so the hook fails for
        # that reason and not because /bin/sh is missing (127).
        add("bin/sh", tarfile.REGTYPE, 0o755, Path(fixture).read_bytes())
        add("scenario", tarfile.REGTYPE, 0o644, b"w")
        add("out/hello.txt", tarfile.REGTYPE, 0o644, HELLO)
        add("out/link", tarfile.SYMTYPE, 0o777, target="hello.txt")
        add("out/sub/data.bin", tarfile.REGTYPE, 0o600, DATA)
    return buffer.getvalue()


def inject_tar(members):
    """A tar of (name, kind, mode, data-or-target) members, fixed order and times."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, kind, mode, payload in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.mode = mode
            info.mtime = 1700000000
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if kind == tarfile.REGTYPE:
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            else:
                info.linkname = payload if kind == tarfile.SYMTYPE else ""
                archive.addfile(info)
    return buffer.getvalue()


INJECT_NOTE = b"injected note\n"
INJECT_BLOB = bytes(reversed(range(256))) * 32 + b"\x00\r\n"
# Neither /inputs nor /inputs/nested exists in the instance root: inject-tree
# creates the target path and its missing parents.
INJECT_PATH = "/inputs/nested/deep"
CLI_MEMBERS = [
    ("cli", tarfile.DIRTYPE, 0o755, None),
    ("cli/note.txt", tarfile.REGTYPE, 0o644, INJECT_NOTE),
]
INJECT_MEMBERS = [
    ("app", tarfile.DIRTYPE, 0o755, None),
    ("app/note.txt", tarfile.REGTYPE, 0o644, INJECT_NOTE),
    ("app/link", tarfile.SYMTYPE, 0o777, "note.txt"),
    ("app/nested", tarfile.DIRTYPE, 0o750, None),
    ("app/nested/blob.bin", tarfile.REGTYPE, 0o600, INJECT_BLOB),
    ("app/setuid", tarfile.REGTYPE, 0o4755, b"#!/bin/true\n"),
]


def write_layout(directory, fixture):
    """A one-layer OCI image layout; returns the manifest digest."""
    layer = layer_tar(fixture)
    config = canonical({"architecture": "amd64", "os": "linux",
                        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + digest(layer)]},
                        "config": {}})
    manifest = canonical({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": "sha256:" + digest(config), "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": "sha256:" + digest(layer), "size": len(layer)}]})
    index = canonical({"schemaVersion": 2, "manifests": [{
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": "sha256:" + digest(manifest), "size": len(manifest),
        "platform": {"architecture": "amd64", "os": "linux"}}]})
    blobs = directory / "blobs/sha256"
    blobs.mkdir(parents=True)
    (directory / "oci-layout").write_bytes(canonical({"imageLayoutVersion": "1.0.0"}))
    (directory / "index.json").write_bytes(index)
    for blob in (layer, config, manifest):
        (blobs / digest(blob)).write_bytes(blob)
    return digest(manifest)


def reflink_supported(directory):
    source = directory / "reflink-probe"
    source.write_bytes(b"x")
    try:
        return subprocess.run(["cp", "--reflink=always", str(source), str(directory / "reflink-copy")],
                              stderr=subprocess.DEVNULL).returncode == 0
    finally:
        for name in ("reflink-probe", "reflink-copy"):
            (directory / name).unlink(missing_ok=True)


def main():
    if len(sys.argv) != 6 or os.geteuid() != 0:
        sys.exit("usage (as root): test-public-lifecycle.py <ginux runtime> <ginux cli> "
                 "<ginux-image> <helper> <native fixture>")
    runtime, cli, image_tool, helper, fixture = (str(Path(arg).resolve()) for arg in sys.argv[1:6])
    template = (Path(__file__).resolve().parent.parent / "config/instance-gate5.toml").read_text()
    if 'init = "/bin/bash"' not in template or "root = " not in template:
        raise RuntimeError("the native template no longer has the expected root and init lines")

    # Every level of the private state root must be root-owned and not
    # group/other writable, so it lives under /var/lib, not /tmp.
    work = Path(tempfile.mkdtemp(prefix="ginux-public-lifecycle.", dir="/var/lib"))
    work.chmod(0o755)
    state = work / "state"
    run_root = state / "run"
    started = []
    try:
        # The workload drops to UID 65534 and must be able to execute the copies.
        binaries = work / "bin"
        binaries.mkdir(mode=0o755)
        for source, name in ((runtime, "ginux-runtime"), (image_tool, "ginux-image"),
                             (str(helper), "ginux-helper")):
            shutil.copyfile(source, binaries / name)
            (binaries / name).chmod(0o755)
        # sudo resets the environment; the wrapper restores the tool paths.
        wrapper = binaries / "helper-wrapper"
        wrapper.write_text("#!/bin/sh\n"
                           f"GINUX_RUNTIME='{binaries / 'ginux-runtime'}'\n"
                           f"GINUX_IMAGE_TOOL='{binaries / 'ginux-image'}'\n"
                           "export GINUX_RUNTIME GINUX_IMAGE_TOOL\n"
                           f"exec '{binaries / 'ginux-helper'}' \"$@\"\n")
        wrapper.chmod(0o755)
        environment = dict(os.environ, GINUX_INSTANCE_HELPER=str(wrapper))

        def ginux(*arguments, stdin=subprocess.DEVNULL, timeout=120, umask=-1):
            proc = subprocess.run([cli, "--state-root", str(state), *arguments],
                                  stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env=environment, timeout=timeout, umask=umask)
            return proc.returncode, proc.stdout, proc.stderr.decode(errors="replace")

        def inject(instance, data, path=INJECT_PATH, max_bytes=1048576, max_members=100, max_path=512):
            proc = subprocess.run([str(wrapper), "--protocol", "1", "--state-root", str(state),
                                   "inject", instance, "--max-bytes", str(max_bytes),
                                   "--max-members", str(max_members), "--max-path", str(max_path), path],
                                  input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            return proc.returncode, proc.stdout, proc.stderr.decode(errors="replace")

        def start_waiting(name, *options):
            proc = subprocess.Popen([cli, "--state-root", str(state), "start", name, "--wait", *options],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=environment)
            started.append(name)
            return proc

        def check(label, ok, *details):
            if not ok:
                raise RuntimeError(f"{label}:\n" + "\n".join(str(detail) for detail in details))
            print(f"PASS public-lifecycle {label}")

        def status(name):
            code, out, err = ginux("status", name, "--format", "json")
            if code != 0 or out.count(b"\n") != 1:
                raise RuntimeError(f"status {name}: exit={code}\n{out!r}\n{err}")
            return json.loads(out)

        def wait_until(predicate, seconds, label):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if predicate():
                    return
                time.sleep(0.1)
            raise RuntimeError(f"timed out after {seconds} s: {label}")

        def runtime_pid(name):
            try:
                return int((run_root / "instances" / name / "runtime.pid").read_text().split()[0])
            except (OSError, ValueError, IndexError):
                return None

        def running_workload(name):
            """The fixture processes (UID 65534, comm bash) below the instance runtime."""
            top = runtime_pid(name)
            if top is None:
                return []
            children = {}
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    stat = (entry / "stat").read_text()
                    uid = next(line.split()[1] for line in (entry / "status").read_text().splitlines()
                               if line.startswith("Uid:"))
                except (OSError, StopIteration):
                    continue
                comm = stat[stat.index("(") + 1:stat.rindex(")")]
                parent = int(stat[stat.rindex(")") + 2:].split()[1])
                children.setdefault(parent, []).append((int(entry.name), comm, uid))
            found, pending = [], [top]
            while pending:
                for pid, comm, uid in children.get(pending.pop(), []):
                    pending.append(pid)
                    if comm == "bash" and uid == "65534":
                        found.append(pid)
            return found

        def feed_console(name, data):
            descriptor = os.open(run_root / "instances" / name / "console.in",
                                 os.O_WRONLY | os.O_NONBLOCK)
            try:
                os.write(descriptor, data)
            finally:
                os.close(descriptor)

        def set_scenario(name, scenario):
            (state / "instances" / name / "root/scenario").write_text(scenario)

        def private_modes(instance):
            directory = state / "instances" / instance
            return {path.name: path.stat().st_mode & 0o7777 for path in
                    (directory, directory / "console.log", directory / "audit.log")}

        def as_nobody(*command):
            return subprocess.run(list(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  user=65534, group=65534, extra_groups=[], timeout=30)

        def audit_marker(err):
            """The byte count of the audit-tail marker on standard error, or None."""
            for line in err.splitlines():
                if line.startswith("ginux: audit log (last ") and line.endswith(" bytes):"):
                    return int(line[len("ginux: audit log (last "):-len(" bytes):")])
            return None

        # An untrusted root fails before any state change. Checked on the
        # helper itself: the CLI may present the helper's usage code as an
        # unsupported feature.
        untrusted = Path("/tmp") / f"ginux-untrusted-{os.getpid()}"
        proc = subprocess.run([str(wrapper), "--protocol", "1", "--state-root", str(untrusted), "list"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        check("untrusted state root refused", proc.returncode == 64
              and b"untrusted state root" in proc.stderr and not untrusted.exists(),
              proc.returncode, proc.stderr)

        # Offline image import through sudo's standard input.
        layout = work / "layout"
        layout.mkdir()
        manifest = write_layout(layout, fixture)
        layout_tar = work / "layout.tar"
        with tarfile.open(layout_tar, "w", format=tarfile.GNU_FORMAT) as archive:
            for member in ("oci-layout", "index.json", "blobs", "blobs/sha256",
                           *(f"blobs/sha256/{name}" for name in sorted(os.listdir(layout / "blobs/sha256")))):
                archive.add(layout / member, arcname=member, recursive=False)
        for source in (layout, layout_tar):
            code, out, err = ginux("import-image", str(source))
            check(f"import-image prints the manifest digest ({source.name})",
                  code == 0 and out == f"sha256:{manifest}\n".encode(), code, out, err)
        blobs = state / "cache/oci/blobs/sha256"
        check("import-image committed every blob",
              {path.name for path in blobs.iterdir()} >= set(os.listdir(layout / "blobs/sha256")),
              sorted(path.name for path in blobs.iterdir()))

        reference = f"local/public-lifecycle@sha256:{manifest}"
        recipe = work / "recipe.toml"
        recipe.write_text(template.replace('init = "/bin/bash"', 'init = "/usr/bin/bash"')
                          .replace(template.split("root = ", 1)[1].split("\n", 1)[0], f'"{reference}"')
                          + '\n[contract.filesystem]\nread = ["/"]\nwrite = ["/"]\ncreate = ["/"]\n'
                          '[contract.kernel]\nproc_read = ["/"]\nsys_read = ["/"]\n')
        if f'root = "{reference}"' not in recipe.read_text():
            raise RuntimeError("recipe root was not replaced")
        hook_recipe = work / "hook-recipe.toml"
        hook_recipe.write_text(recipe.read_text() + '\n[hooks]\npre_boot = ["/usr/bin/bash"]\n'
                               'timeout_seconds = 5\nfailure = "stop"\n')

        reflink = reflink_supported(work)
        name = "lifecycle"
        code, out, err = ginux("import", name, str(recipe))
        check("import from an imported image (no network)", code == 0, code, out, err)
        base = state / "cache/roots/sha256" / manifest
        check(f"base root {'kept' if reflink else 'absent'} (reflink={reflink})",
              base.is_dir() == reflink, base)
        check("instance lives under the private root",
              (state / "instances" / name / "root/usr/bin/bash").is_file()
              and not Path("/var/lib/ginux/instances", name).exists())

        # start --wait: the workload's code, nothing on stdout.
        for scenario, expected in (("w", 0), ("Z", 81)):
            set_scenario(name, scenario)
            code, out, err = ginux("start", name, "--wait")
            current = status(name)
            check(f"start --wait exits with the workload code {expected}",
                  code == expected and out == b"" and current["state"] == "stopped"
                  and current["pid"] is None and current["outcome"] == {
                      "version": 1, "outcome": "exited", "code": expected,
                      "signal": None, "generation": None}, code, out, err, current)
        check("status --format json names the private paths",
              current["name"] == name and current["contract"] == "locked"
              and current["paths"]["root"] == str(state / "instances" / name / "root")
              and current["paths"]["console_log"] == str(state / "instances" / name / "console.log"),
              current)

        # A long-running workload: the fixture's yield scenario reads three
        # bytes from the console before it exits 0.
        set_scenario(name, "Yield-wait")
        waiting = start_waiting(name)
        wait_until(lambda: status(name)["state"] == "running" and running_workload(name),
                   30, "instance running")
        current = status(name)
        check("status while running has a pid and no outcome",
              isinstance(current["pid"], int) and current["outcome"] is None, current)
        output = work / "while-running.tar"
        code, out, err = ginux("extract", name, "--output", str(output), "/out")
        check("extract while running is refused", code == 73 and not output.exists()
              and not any(entry.name.startswith(".while-running") for entry in work.iterdir()),
              code, err)
        code, out, err = inject(name, inject_tar(INJECT_MEMBERS))
        check("inject while running is refused", code == 73 and out == b""
              and not (state / "instances" / name / "root/inputs").exists(), code, err)
        cli_tar = work / "cli-inject.tar"
        cli_tar.write_bytes(inject_tar(CLI_MEMBERS))
        code, out, err = ginux("inject", name, "--input", str(cli_tar), "--into", "/more")
        check("CLI inject while running is refused", code == 73 and out == b""
              and not (state / "instances" / name / "root/more").exists(), code, err)
        code, out, err = ginux("delete", name)
        check("delete while running is refused", code == 73
              and (state / "instances" / name).is_dir(), code, err)
        feed_console(name, b"\n\n\n")
        out, err = waiting.communicate(timeout=60)
        check("start --wait returns when the workload ends", waiting.returncode == 0 and out == b""
              and status(name)["outcome"]["outcome"] == "exited", waiting.returncode, out, err)

        # A workload killed by a signal: 128+n.
        waiting = start_waiting(name)
        wait_until(lambda: running_workload(name), 30, "workload running")
        for pid in running_workload(name):
            os.kill(pid, signal.SIGKILL)
        out, err = waiting.communicate(timeout=60)
        current = status(name)
        check("killed workload exits 128+9", waiting.returncode == 137 and current["outcome"] == {
            "version": 1, "outcome": "signaled", "code": None, "signal": 9, "generation": None},
              waiting.returncode, err, current)

        # The caller's death tears the instance down.
        waiting = start_waiting(name)
        wait_until(lambda: running_workload(name), 30, "workload running")
        runtime_before = runtime_pid(name)
        waiting.kill()
        waiting.wait()
        wait_until(lambda: status(name)["state"] == "stopped" and not running_workload(name)
                   and not Path(f"/proc/{runtime_before}").exists(), 10, "teardown after caller death")
        check("caller death records supervisor-error", status(name)["outcome"] == SUPERVISOR_ERROR,
              status(name))

        # Extract from the stopped instance through sudo's standard output.
        output = work / "out.tar"
        code, out, err = ginux("extract", name, "--output", str(output), "/out")
        check("extract of a stopped instance", code == 0 and out == b"" and output.is_file(), code, err)
        with tarfile.open(output) as archive:
            members = archive.getmembers()
            listing = [(member.name, member.type) for member in members]
            check("extract listing is deterministic", listing == [
                ("out", tarfile.DIRTYPE), ("out/hello.txt", tarfile.REGTYPE),
                ("out/link", tarfile.SYMTYPE), ("out/sub", tarfile.DIRTYPE),
                ("out/sub/data.bin", tarfile.REGTYPE)], listing)
            by_name = {member.name: member for member in members}
            check("extract bytes, link and headers", archive.extractfile("out/hello.txt").read() == HELLO
                  and archive.extractfile("out/sub/data.bin").read() == DATA
                  and by_name["out/link"].linkname == "hello.txt"
                  and by_name["out/hello.txt"].mode == 0o644
                  and all(member.uid == 0 and member.gid == 0 for member in members),
                  [(member.name, oct(member.mode), member.uid) for member in members])
        first = output.read_bytes()
        code, out, err = ginux("extract", name, "--output", str(output), "/out")
        check("extract refuses an existing output", code == 74 and output.read_bytes() == first, code, err)
        missing = work / "missing.tar"
        code, out, err = ginux("extract", name, "--output", str(missing), "/no-such-directory")
        check("extract of a missing path leaves nothing", code == 66 and not missing.exists()
              and not any(entry.name.startswith(".missing") for entry in work.iterdir()), code, err)

        # inject into the stopped instance: tar on standard input, nothing on
        # standard output; extract reads the result back.
        # Neither /inputs nor /inputs/nested exists: inject creates the path.
        inputs = state / "instances" / name / "root/inputs"
        check("inject target and parents do not exist beforehand", not inputs.exists())
        code, out, err = inject(name, inject_tar(INJECT_MEMBERS))
        check("inject into a stopped instance", code == 0 and out == b"", code, out, err)
        injected = inputs / "nested/deep"
        check("inject clears the setuid bit",
              (injected / "app/setuid").stat().st_mode & 0o7000 == 0, oct((injected / "app/setuid").stat().st_mode))
        output = work / "inputs.tar"
        code, out, err = ginux("extract", name, "--output", str(output), "/inputs")
        check("extract of the injected tree", code == 0 and output.is_file(), code, err)
        with tarfile.open(output) as archive:
            members = archive.getmembers()
            by_name = {member.name: member for member in members}
            deep = "inputs/nested/deep"
            check("injected members read back", [(member.name, member.type) for member in members] == [
                ("inputs", tarfile.DIRTYPE), ("inputs/nested", tarfile.DIRTYPE),
                (deep, tarfile.DIRTYPE), (f"{deep}/app", tarfile.DIRTYPE),
                (f"{deep}/app/link", tarfile.SYMTYPE), (f"{deep}/app/nested", tarfile.DIRTYPE),
                (f"{deep}/app/nested/blob.bin", tarfile.REGTYPE), (f"{deep}/app/note.txt", tarfile.REGTYPE),
                (f"{deep}/app/setuid", tarfile.REGTYPE)], [(member.name, member.type) for member in members])
            check("injected bytes, link and modes",
                  archive.extractfile(f"{deep}/app/note.txt").read() == INJECT_NOTE
                  and archive.extractfile(f"{deep}/app/nested/blob.bin").read() == INJECT_BLOB
                  and archive.extractfile(f"{deep}/app/setuid").read() == b"#!/bin/true\n"
                  and by_name[f"{deep}/app/link"].linkname == "note.txt"
                  and by_name[f"{deep}/app/note.txt"].mode == 0o644
                  and by_name[f"{deep}/app/nested/blob.bin"].mode == 0o600
                  and by_name[f"{deep}/app/setuid"].mode == 0o755,
                  [(member.name, oct(member.mode)) for member in members])
        code, out, err = inject(name, inject_tar(INJECT_MEMBERS))
        check("inject of the same tar again conflicts", code == 65 and out == b"", code, err)
        code, out, err = inject(name, inject_tar([("../escape", tarfile.REGTYPE, 0o644, b"x")]))
        check("inject refuses a .. member", code == 65 and out == b""
              and not (state / "instances" / name / "escape").exists()
              and not (state / "instances" / name / "root/escape").exists(), code, err)
        bounded = inject_tar([("bound", tarfile.DIRTYPE, 0o755, None),
                              ("bound/one", tarfile.REGTYPE, 0o644, b"1"),
                              ("bound/two", tarfile.REGTYPE, 0o644, b"2")])
        code, out, err = inject(name, bounded, max_members=1)
        check("inject past the member bound exits 76", code == 76 and out == b"", code, err)
        code, out, err = inject(name, bounded, max_bytes=1)
        check("inject past the byte bound exits 76", code == 76 and out == b"", code, err)
        code, out, err = inject("no-such-instance", inject_tar(INJECT_MEMBERS))
        check("inject into a missing instance exits 66", code == 66 and out == b"", code, err)

        # inject through the real CLI (sudo, helper, image tool), then read back.
        code, out, err = ginux("inject", name, "--input", str(cli_tar), "--into", "/more")
        check("CLI inject into a stopped instance", code == 0 and out == b"", code, out, err)
        output = work / "more.tar"
        code, out, err = ginux("extract", name, "--output", str(output), "/more")
        check("extract of the CLI-injected tree", code == 0 and output.is_file(), code, err)
        with tarfile.open(output) as archive:
            members = archive.getmembers()
            check("CLI-injected members read back", [(member.name, member.type) for member in members] == [
                ("more", tarfile.DIRTYPE), ("more/cli", tarfile.DIRTYPE),
                ("more/cli/note.txt", tarfile.REGTYPE)], [(member.name, member.type) for member in members])
            check("CLI-injected bytes", archive.extractfile("more/cli/note.txt").read() == INJECT_NOTE)

        # A pre-boot hook that fails with failure = "stop": supervisor-error.
        # The hook shell is the fixture as /bin/sh, which exits 81 for "Z".
        hooked = "lifecycle-hook"
        code, out, err = ginux("import", hooked, str(hook_recipe))
        check("second import of the same image", code == 0, code, out, err)
        check(f"second import {'reuses' if reflink else 'does not keep'} the base root",
              base.is_dir() == reflink
              and os.stat(state / "instances" / hooked / "root/usr/bin/bash").st_ino
              != os.stat(state / "instances" / name / "root/usr/bin/bash").st_ino, base)
        set_scenario(hooked, "Z")
        code, out, err = ginux("start", hooked, "--wait", umask=0o022)
        check("failing stop hook exits 70", code == 70 and out == b""
              and status(hooked)["outcome"] == SUPERVISOR_ERROR, code, err, status(hooked))
        modes = private_modes(hooked)
        check("instance directory 0700 and logs 0600 under umask 022",
              modes == {hooked: 0o700, "console.log": 0o600, "audit.log": 0o600}, modes)
        code, out, err = ginux("start", hooked, "--wait", "--stream-console")
        audit_bytes = (state / "instances" / hooked / "audit.log").read_bytes()
        shown = audit_marker(err)
        check("a failed streamed run prints the audit log tail on stderr", code == 70
              and out == (state / "instances" / hooked / "console.log").read_bytes()
              and shown == min(len(audit_bytes), 65536) and shown > 0
              and status(hooked)["outcome"] == SUPERVISOR_ERROR, code, out, err)

        # An init that inject provides after create: create succeeds, start
        # refuses with 65 until the init is there, then runs. Created and
        # started under umask 077.
        late = "lifecycle-late-init"
        late_recipe = work / "late-recipe.toml"
        late_recipe.write_text(recipe.read_text().replace('init = "/usr/bin/bash"', 'init = "/late/init"'))
        code, out, err = ginux("import", late, str(late_recipe), umask=0o077)
        check("import with the init not yet in the root", code == 0
              and not (state / "instances" / late / "root/late").exists(), code, out, err)
        set_scenario(late, "w")
        code, out, err = ginux("start", late, "--wait", umask=0o077)
        check("start without the init exits 65", code == 65 and out == b""
              and "configured init is missing or not executable: /late/init" in err
              and status(late)["state"] == "stopped" and status(late)["outcome"] is None,
              code, out, err, status(late))
        code, out, err = inject(late, inject_tar([("init", tarfile.REGTYPE, 0o755,
                                                   Path(fixture).read_bytes())]), path="/late")
        check("inject provides the init", code == 0 and out == b"", code, out, err)
        code, out, err = ginux("start", late, "--wait", umask=0o077)
        current = status(late)
        check("start after inject runs the injected init", code == 0 and out == b""
              and current["outcome"] == {"version": 1, "outcome": "exited", "code": 0,
                                         "signal": None, "generation": None}, code, out, err, current)
        modes = private_modes(late)
        check("instance directory 0700 and logs 0600 under umask 077",
              modes == {late: 0o700, "console.log": 0o600, "audit.log": 0o600}, modes)

        # Another uid-65534 process (the workload's host identity) cannot
        # reach the instance directory, the root or the logs.
        late_directory = state / "instances" / late
        for command in (["ls", "-A", "--", str(late_directory)],
                        ["ls", "-A", "--", str(late_directory / "root")],
                        ["cat", "--", current["paths"]["console_log"]],
                        ["cat", "--", current["paths"]["audit_log"]]):
            proc = as_nobody(*command)
            check(f"uid 65534 is refused: {' '.join(command[:1] + command[-1:])}",
                  proc.returncode != 0 and proc.stdout == b"", proc.returncode, proc.stdout)

        # --stream-console: standard output carries exactly the console bytes
        # and nothing else; a run that exits 0 prints no audit log.
        code, out, err = ginux("start", late, "--wait", "--stream-console", umask=0o077)
        console = (late_directory / "console.log").read_bytes()
        check("streamed run prints exactly the console output", code == 0
              and b"GINUX_FIXTURE: yield=" in out and out == console
              and audit_marker(err) is None, code, out, err, console)
        # A failing workload (81 for "Z"): the console bytes, then the audit
        # log tail on standard error.
        set_scenario(late, "Z")
        code, out, err = ginux("start", late, "--wait", "--stream-console")
        audit_bytes = (late_directory / "audit.log").read_bytes()
        check("a failing streamed run keeps its status and adds the audit tail", code == 81
              and out == (late_directory / "console.log").read_bytes()
              and audit_marker(err) == min(len(audit_bytes), 65536), code, out, err)
        # Output arrives while the run lasts: the yield scenario prints one
        # line per byte fed to its console.
        set_scenario(late, "Yield-stream")
        streaming = start_waiting(late, "--stream-console")
        wait_until(lambda: running_workload(late), 30, "streamed workload running")
        feed_console(late, b"\n")
        received = b""
        deadline = time.monotonic() + 30
        while b"yield-before-receive=" not in received and time.monotonic() < deadline:
            ready, _, _ = select.select([streaming.stdout], [], [], 0.5)
            if ready:
                chunk = os.read(streaming.stdout.fileno(), 65536)
                if not chunk:
                    break
                received += chunk
        check("console output is streamed before the run ends",
              b"yield-before-receive=" in received and streaming.poll() is None, received)
        feed_console(late, b"\n\n")
        rest, err = streaming.communicate(timeout=60)
        check("the streamed tail is delivered once", streaming.returncode == 0
              and received + rest == (late_directory / "console.log").read_bytes()
              and audit_marker(err.decode(errors="replace")) is None,
              streaming.returncode, received + rest, err)
        # The flag needs --wait, in the helper too.
        proc = subprocess.run([str(wrapper), "--protocol", "1", "--state-root", str(state),
                               "start", late, "--stream-console"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        check("helper refuses --stream-console without --wait", proc.returncode == 64
              and status(late)["state"] == "stopped", proc.returncode, proc.stderr)

        # delete: refused while running, then atomic and idempotently 66.
        set_scenario(name, "Yield-delete")
        code, out, err = ginux("start", name)
        started.append(name)
        check("detached start", code == 0, code, out, err)
        wait_until(lambda: running_workload(name), 30, "workload running")
        code, out, err = ginux("delete", name)
        check("delete of a running detached instance is refused", code == 73, code, err)
        feed_console(name, b"\n\n\n")
        wait_until(lambda: status(name)["state"] == "stopped", 30, "detached instance stopped")
        for instance in (name, hooked, late):
            code, out, err = ginux("delete", instance)
            check(f"delete {instance}", code == 0 and out == f'Instance "{instance}" deleted.\n'.encode()
                  and not (state / "instances" / instance).exists()
                  and not (run_root / "instances" / instance).exists(), code, out, err)
            code, out, err = ginux("delete", instance)
            check(f"delete {instance} again is not found", code == 66, code, err)
        code, out, err = ginux("list")
        check("list is empty", code == 0 and out.count(b"\n") == 1 and out.startswith(b"NAME"), code, out)
        check("no delete trash remains",
              not any(entry.name.startswith(".") for entry in (state / "instances").iterdir()),
              sorted(entry.name for entry in (state / "instances").iterdir()))
        started.clear()
    finally:
        for name in started:
            subprocess.run([str(work / "bin/helper-wrapper"), "--protocol", "1",
                            "--state-root", str(state), "stop", name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        shutil.rmtree(work, ignore_errors=True)
    print("test-public-lifecycle: PASS")


if __name__ == "__main__":
    main()
