#!/bin/sh
set -eu

cargo build -q -p ginux-cli
cli=target/debug/ginux-cli
test -x "$cli"
mkdir -p build
./scripts/check-cli-command-inventory.sh

test_directory=$(mktemp -d "${TMPDIR:-/tmp}/ginux-cli-test.XXXXXX")
cleanup() {
    rm -rf "$test_directory"
}
trap cleanup 0 HUP INT TERM

"$cli" --help >"$test_directory/help"
"$cli" --version | grep -Eq '^ginux [0-9]+\.[0-9]+\.[0-9]+'
for command in create import set edit export delete inject list status extract start attach stop lock unlock import-image validate inspect explain; do
    grep -Eq "^  $command[[:space:]]" "$test_directory/help"
    "$cli" "$command" --help >"$test_directory/help-$command"
    test -s "$test_directory/help-$command"
done
! grep -Eq '^  (diff|native|native-hook|launch)[[:space:]]' "$test_directory/help"

"$cli" validate config/examples/rocky10-systemd.toml >"$test_directory/validate"
"$cli" inspect config/examples/rocky10-systemd.toml >"$test_directory/inspect"
"$cli" explain config/examples/rocky10-systemd.toml filesystem.path.read \
    >"$test_directory/explain"
grep -Fq 'Contract valid:' "$test_directory/validate"
grep -Fq 'Decisions:' "$test_directory/inspect"
grep -Fq 'Operation: filesystem.path.read' "$test_directory/explain"

mkdir "$test_directory/bin"
printf '%s\n' '#!/bin/sh' ": >'$test_directory/sudo-called'" 'exit 99' \
    >"$test_directory/bin/sudo"
chmod 755 "$test_directory/bin/sudo"
for invocation in \
    'list extra' \
    'status' \
    'set rocky' \
    'start rocky --unknown' \
    'diff left right' \
    'native config root' \
    'start rocky --wait --attach' \
    'start rocky --stream-console' \
    'start rocky --attach --stream-console' \
    'start rocky --wait --stream-console --stream-console' \
    'status rocky --format yaml' \
    'delete' \
    'delete rocky extra' \
    'extract rocky /out' \
    'extract rocky --output out.tar' \
    'extract rocky --output out.tar out' \
    'extract rocky --output out.tar /a/../b' \
    'extract rocky --output out.tar --max-bytes 0 /out' \
    'extract rocky --output out.tar --max-path 3 /out' \
    'import-image' \
    'inject rocky --into /work' \
    'inject rocky --input in.tar' \
    'inject rocky --input in.tar --into work' \
    'inject rocky --input in.tar --into /a/../b' \
    'inject rocky --input in.tar --into /a/' \
    'inject rocky --input in.tar --into /work --max-bytes 0' \
    'inject rocky --input in.tar --into /work --max-members 0' \
    'inject rocky --input in.tar --into /work --max-path 3' \
    'inject bad/name --input in.tar --into /work' \
    '--run-root /run/ginux-a list' \
    '--state-root relative list' \
    '--state-root /var/lib/../tmp list' \
    '--state-root /var/lib/ginux-a/ list'; do
    set +e
    PATH="$test_directory/bin:$PATH" "$cli" $invocation \
        >"$test_directory/rejected.out" 2>"$test_directory/rejected.err"
    status=$?
    set -e
    test "$status" -eq 2
    test ! -e "$test_directory/sudo-called"
done

set +e
PATH="$test_directory/bin:$PATH" "$cli" set rocky \
    --forward none \
    --forward protocol=tcp,external_port=8080,instance_port=80 \
    >"$test_directory/conflict.out" 2>"$test_directory/conflict.err"
status=$?
set -e
test "$status" -eq 2
test ! -e "$test_directory/sudo-called"
grep -Fq -- '--forward none conflicts' "$test_directory/conflict.err"

printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$@" >"$GINUX_TEST_HELPER_ARGS"' 'exit 0' \
    >"$test_directory/bin/sudo"
chmod 755 "$test_directory/bin/sudo"
GINUX_TEST_HELPER_ARGS="$test_directory/helper-args" \
GINUX_INSTANCE_HELPER=/private/ginux-instance-helper \
PATH="$test_directory/bin:$PATH" \
    "$cli" create rocky \
        --set resources.vcpus=2 \
        --network default \
        --forward protocol=tcp,external_port=8080,instance_port=80
cat >"$test_directory/expected-helper-args" <<'EOF'
/private/ginux-instance-helper
--protocol
1
create
rocky
--set
resources.vcpus=2
--network
default
--forward
protocol=tcp,external_port=8080,instance_port=80
EOF
cmp "$test_directory/expected-helper-args" "$test_directory/helper-args"
! grep -Eq '^--(state|run)-root$' "$test_directory/helper-args"

# Interim lifecycle commands. This fake sudo records its arguments, copies its
# standard input when asked, writes $GINUX_TEST_SUDO_OUTPUT to standard output
# and exits with $GINUX_TEST_SUDO_STATUS.
cat >"$test_directory/bin/sudo" <<'SCRIPT'
#!/bin/sh
printf '%s\n' "$@" >"$GINUX_TEST_HELPER_ARGS"
if test -n "${GINUX_TEST_SUDO_STDIN:-}"; then cat >"$GINUX_TEST_SUDO_STDIN"; fi
if test -n "${GINUX_TEST_SUDO_STDERR:-}"; then printf '%s\n' "$GINUX_TEST_SUDO_STDERR" >&2; fi
printf '%s' "${GINUX_TEST_SUDO_OUTPUT:-}"
exit "${GINUX_TEST_SUDO_STATUS:-0}"
SCRIPT
chmod 755 "$test_directory/bin/sudo"
fake() {
    GINUX_TEST_HELPER_ARGS="$test_directory/helper-args" \
    GINUX_INSTANCE_HELPER=/private/ginux-instance-helper \
    PATH="$test_directory/bin:$PATH" \
        "$cli" "$@"
}
expect_args() {
    printf '%s\n' /private/ginux-instance-helper --protocol 1 "$@" \
        >"$test_directory/expected-helper-args"
    cmp "$test_directory/expected-helper-args" "$test_directory/helper-args"
}

fake delete rocky
expect_args delete rocky
fake status rocky
expect_args status rocky
fake status rocky --format json
expect_args status rocky --format json
fake --state-root /var/lib/ginux-a status rocky
expect_args --state-root /var/lib/ginux-a --run-root /var/lib/ginux-a/run status rocky
fake stop rocky --state-root /var/lib/ginux-a --run-root /run/ginux-a
expect_args --state-root /var/lib/ginux-a --run-root /run/ginux-a stop rocky
fake --state-root /var/lib/ginux-a create rocky --set resources.vcpus=2
expect_args --state-root /var/lib/ginux-a --run-root /var/lib/ginux-a/run \
    create rocky --set resources.vcpus=2

# An older helper rejects a new verb with usage status 64.
set +e
GINUX_TEST_SUDO_STATUS=64 fake delete rocky 2>"$test_directory/old-helper.err"
status=$?
set -e
test "$status" -eq 69
grep -Fq 'the installed helper does not support delete' "$test_directory/old-helper.err"
# A current helper's root refusal also exits 64 and keeps its own message.
set +e
GINUX_TEST_SUDO_STATUS=64 \
GINUX_TEST_SUDO_STDERR='untrusted state root: /var/lib/ginux-a (owner)' \
    fake --state-root /var/lib/ginux-a delete rocky 2>"$test_directory/root.err"
status=$?
set -e
test "$status" -eq 64
grep -Fq 'untrusted state root: /var/lib/ginux-a' "$test_directory/root.err"
! grep -Fq 'does not support' "$test_directory/root.err"
# An old helper that does not know the root options exits 64 with a usage
# line, whatever the verb: unsupported.
for verb in "list" "stop rocky" "create rocky" "import rocky /dev/null" "start rocky"; do
    set +e
    GINUX_TEST_SUDO_STATUS=64 \
    GINUX_TEST_SUDO_STDERR='usage: ginux-helper VERB' \
        fake --state-root /var/lib/ginux-a $verb 2>"$test_directory/old-roots.err"
    status=$?
    set -e
    test "$status" -eq 69
    grep -Fq 'the installed helper does not support --state-root' \
        "$test_directory/old-roots.err"
done
# Helper stderr reaches the terminal with control bytes escaped.
set +e
GINUX_TEST_SUDO_STATUS=1 \
GINUX_TEST_SUDO_STDERR="$(printf 'bad \033[31mname')" \
    fake --state-root /var/lib/ginux-a list 2>"$test_directory/escape.err"
set -e
grep -Fq 'bad \x1b[31mname' "$test_directory/escape.err"
! grep -q "$(printf '\033')" "$test_directory/escape.err"

# start --wait sends the caller's PID and start time and prints nothing.
set +e
GINUX_TEST_SUDO_STATUS=3 fake start rocky --audit --wait >"$test_directory/wait.out"
status=$?
set -e
test "$status" -eq 3
test ! -s "$test_directory/wait.out"
sed -n '1,6p' "$test_directory/helper-args" >"$test_directory/wait-head"
printf '%s\n' /private/ginux-instance-helper --protocol 1 start rocky --audit \
    >"$test_directory/expected-helper-args"
cmp "$test_directory/expected-helper-args" "$test_directory/wait-head"
sed -n '7p' "$test_directory/helper-args" | grep -Fxq -- '--wait'
sed -n '8p' "$test_directory/helper-args" | grep -Eq '^[0-9]+$'
sed -n '9p' "$test_directory/helper-args" | grep -Eq '^[0-9]+$'
test "$(wc -l <"$test_directory/helper-args")" -eq 9

# start --wait --stream-console forwards the flag after the caller identity,
# passes the helper's standard output through byte for byte, and relays its
# standard error with control bytes escaped.
cat >"$test_directory/bin/sudo" <<'SCRIPT'
#!/bin/sh
printf '%s\n' "$@" >"$GINUX_TEST_HELPER_ARGS"
cat "$GINUX_TEST_SUDO_CONSOLE"
printf 'ginux: audit log (last 4 bytes):\n\033x\n' >&2
exit 5
SCRIPT
chmod 755 "$test_directory/bin/sudo"
{
    head -c 70000 /dev/urandom
    printf '\000\033[31m\r\nno newline at the end'
} >"$test_directory/console.bytes"
set +e
GINUX_TEST_SUDO_CONSOLE="$test_directory/console.bytes" \
    fake start rocky --wait --stream-console \
    >"$test_directory/stream.out" 2>"$test_directory/stream.err"
status=$?
set -e
test "$status" -eq 5
cmp "$test_directory/console.bytes" "$test_directory/stream.out"
grep -Fxq 'ginux: audit log (last 4 bytes):' "$test_directory/stream.err"
grep -Fq '\x1bx' "$test_directory/stream.err"
! grep -q "$(printf '\033')" "$test_directory/stream.err"
sed -n '1,5p' "$test_directory/helper-args" >"$test_directory/wait-head"
printf '%s\n' /private/ginux-instance-helper --protocol 1 start rocky \
    >"$test_directory/expected-helper-args"
cmp "$test_directory/expected-helper-args" "$test_directory/wait-head"
sed -n '6p' "$test_directory/helper-args" | grep -Fxq -- '--wait'
sed -n '7p' "$test_directory/helper-args" | grep -Eq '^[0-9]+$'
sed -n '8p' "$test_directory/helper-args" | grep -Eq '^[0-9]+$'
sed -n '9p' "$test_directory/helper-args" | grep -Fxq -- '--stream-console'
test "$(wc -l <"$test_directory/helper-args")" -eq 9

# A terminating signal to start --wait reaches the helper's sudo process.
cat >"$test_directory/bin/sudo" <<'SCRIPT'
#!/bin/sh
trap 'exit 7' TERM
: >"$GINUX_TEST_SUDO_READY"
while :; do sleep 0.1; done
SCRIPT
chmod 755 "$test_directory/bin/sudo"
GINUX_TEST_SUDO_READY="$test_directory/sudo-ready" \
GINUX_INSTANCE_HELPER=/private/ginux-instance-helper \
PATH="$test_directory/bin:$PATH" \
    "$cli" start rocky --wait &
waiting=$!
tries=0
while test ! -e "$test_directory/sudo-ready"; do
    tries=$((tries + 1))
    test "$tries" -lt 100 || { kill -KILL "$waiting"; exit 1; }
    sleep 0.1
done
kill -TERM "$waiting"
set +e
wait "$waiting"
status=$?
set -e
test "$status" -eq 7

# extract: bounds are always sent, nested paths collapse, the archive appears
# only on success and an existing output is refused.
cat >"$test_directory/bin/sudo" <<'SCRIPT'
#!/bin/sh
printf '%s\n' "$@" >"$GINUX_TEST_HELPER_ARGS"
printf '%s' "${GINUX_TEST_SUDO_OUTPUT:-}"
exit "${GINUX_TEST_SUDO_STATUS:-0}"
SCRIPT
chmod 755 "$test_directory/bin/sudo"
mkdir "$test_directory/extract"
GINUX_TEST_SUDO_OUTPUT=archive fake extract rocky \
    --output "$test_directory/extract/out.tar" /out/sub /out /b
expect_args extract rocky --max-bytes 68719476736 --max-members 1000000 \
    --max-path 4096 /b /out
test "$(cat "$test_directory/extract/out.tar")" = archive
set +e
GINUX_TEST_SUDO_OUTPUT=other fake extract rocky \
    --output "$test_directory/extract/out.tar" /out 2>/dev/null
status=$?
set -e
test "$status" -eq 74
test "$(cat "$test_directory/extract/out.tar")" = archive
set +e
GINUX_TEST_SUDO_OUTPUT=partial GINUX_TEST_SUDO_STATUS=75 fake extract rocky \
    --output "$test_directory/extract/failed.tar" --max-bytes 9 /out
status=$?
set -e
test "$status" -eq 75
test "$(ls -A "$test_directory/extract")" = out.tar
expect_args extract rocky --max-bytes 9 --max-members 1000000 --max-path 4096 /out

# import-image: the caller's layout is read locally and streamed as a tar.
cat >"$test_directory/bin/sudo" <<'SCRIPT'
#!/bin/sh
printf '%s\n' "$@" >"$GINUX_TEST_HELPER_ARGS"
cat >"$GINUX_TEST_SUDO_STDIN"
printf 'sha256:%064d\n' 0
SCRIPT
chmod 755 "$test_directory/bin/sudo"
layout=$test_directory/layout
blob=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
mkdir -p "$layout/blobs/sha256"
printf '%s' '{"imageLayoutVersion":"1.0.0"}' >"$layout/oci-layout"
printf '%s' '{}' >"$layout/index.json"
printf '%s' blob >"$layout/blobs/sha256/$blob"
GINUX_TEST_SUDO_STDIN="$test_directory/layout.tar" \
    fake import-image "$layout" >"$test_directory/import.out"
expect_args import-image
grep -Eqx 'sha256:0{64}' "$test_directory/import.out"
tar -tf "$test_directory/layout.tar" >"$test_directory/layout.list"
printf '%s\n' oci-layout index.json blobs/ blobs/sha256/ "blobs/sha256/$blob" \
    >"$test_directory/layout.expected"
cmp "$test_directory/layout.expected" "$test_directory/layout.list"
rm -f "$test_directory/helper-args"
ln -s /etc/passwd "$layout/extra"
set +e
GINUX_TEST_SUDO_STDIN="$test_directory/layout.tar" \
    fake import-image "$layout" 2>/dev/null
status=$?
set -e
test "$status" -eq 65
test ! -e "$test_directory/helper-args"

# inject: the caller's file is read locally and its bytes reach the helper's
# standard input unchanged; the three bounds are always sent.
cat >"$test_directory/bin/sudo" <<'SCRIPT'
#!/bin/sh
printf '%s\n' "$@" >"$GINUX_TEST_HELPER_ARGS"
cat >"$GINUX_TEST_SUDO_STDIN"
exit "${GINUX_TEST_SUDO_STATUS:-0}"
SCRIPT
chmod 755 "$test_directory/bin/sudo"
head -c 100000 /dev/urandom >"$test_directory/inject.tar"
GINUX_TEST_SUDO_STDIN="$test_directory/inject.received" \
    fake inject rocky --input "$test_directory/inject.tar" --into /work/sub \
    >"$test_directory/inject.out"
expect_args inject rocky --max-bytes 68719476736 --max-members 1000000 \
    --max-path 4096 /work/sub
cmp "$test_directory/inject.tar" "$test_directory/inject.received"
test ! -s "$test_directory/inject.out"
GINUX_TEST_SUDO_STDIN="$test_directory/inject.received" \
    fake --state-root /var/lib/ginux-a inject rocky \
    --input "$test_directory/inject.tar" --into / --max-bytes 9 \
    --max-members 8 --max-path 7
expect_args --state-root /var/lib/ginux-a --run-root /var/lib/ginux-a/run \
    inject rocky --max-bytes 9 --max-members 8 --max-path 7 /
cmp "$test_directory/inject.tar" "$test_directory/inject.received"
for helper_status in 65 66 73 74 75 76; do
    set +e
    GINUX_TEST_SUDO_STATUS=$helper_status \
    GINUX_TEST_SUDO_STDIN="$test_directory/inject.received" \
        fake inject rocky --input "$test_directory/inject.tar" --into /work \
        2>/dev/null
    status=$?
    set -e
    test "$status" -eq "$helper_status"
done
set +e
GINUX_TEST_SUDO_STATUS=64 \
GINUX_TEST_SUDO_STDIN="$test_directory/inject.received" \
    fake inject rocky --input "$test_directory/inject.tar" --into /work \
    2>"$test_directory/inject-old.err"
status=$?
set -e
test "$status" -eq 69
grep -Fq 'the installed helper does not support inject' "$test_directory/inject-old.err"
# Inputs that are not an uncompressed regular file never reach sudo.
rm -f "$test_directory/helper-args"
ln -s inject.tar "$test_directory/inject-link.tar"
mkdir "$test_directory/inject-directory"
mkfifo "$test_directory/inject-fifo"
printf '\037\213\010\000' >"$test_directory/inject.tar.gz"
for rejected in inject-link.tar inject-directory inject-fifo inject.tar.gz; do
    set +e
    GINUX_TEST_SUDO_STDIN="$test_directory/inject.received" \
        fake inject rocky --input "$test_directory/$rejected" --into /work \
        2>/dev/null
    status=$?
    set -e
    test "$status" -eq 65
    test ! -e "$test_directory/helper-args"
done
set +e
GINUX_TEST_SUDO_STDIN="$test_directory/inject.received" \
    fake inject rocky --input "$test_directory/absent.tar" --into /work 2>/dev/null
status=$?
set -e
test "$status" -eq 66
test ! -e "$test_directory/helper-args"

set +e
./scripts/ginux-host-instance-helper.sh list >/dev/null 2>&1
unversioned_status=$?
./scripts/ginux-host-instance-helper.sh --protocol 99 list >/dev/null 2>&1
unsupported_status=$?
set -e
test "$unversioned_status" -eq 64
test "$unsupported_status" -eq 64

printf '%s\n' 'CLI_TEST: PASS (generated help, approved inventory, parser safety, versioned helper routing)'
