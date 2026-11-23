#!/bin/sh
set -eu

state_root=${GINUX_STATE_ROOT:-/var/lib/ginux}
run_root=${GINUX_RUN_ROOT:-/run/ginux}
runtime=${GINUX_RUNTIME:-/usr/libexec/ginux/ginux-runtime}
image_tool=${GINUX_IMAGE_TOOL:-/usr/libexec/ginux/ginux-image}
default_recipe=${GINUX_DEFAULT_RECIPE:-/etc/ginux/examples/rocky10-systemd.toml}

# Preserve the development fixtures while production installs use only the
# canonical packaged paths above.
if test ! -x "$runtime" && test -x /usr/local/libexec/ginux-runtime; then
    runtime=/usr/local/libexec/ginux-runtime
fi
if test ! -x "$image_tool" && test -x /usr/local/libexec/ginux-image/ensure-oci-image.sh; then
    image_tool=/usr/local/libexec/ginux-image
fi
if test ! -r "$default_recipe" && test -r /etc/ginux/examples/rocky-systemd.toml; then
    default_recipe=/etc/ginux/examples/rocky-systemd.toml
fi

usage() {
    printf '%s\n' 'usage: ginux-instance-helper --protocol 1 COMMAND [ARGUMENT]...' >&2
    exit 64
}

validate_name() {
    # Dot names are reserved: staging and trash directories use them and list
    # ignores them, and . and .. would resolve outside the instance.
    case ${1-} in
        ''|.*|*[!A-Za-z0-9_.-]*)
            printf 'invalid instance name: %s\n' "${1-}" >&2
            exit 64
            ;;
    esac
}

instance_dir() {
    printf '%s/instances/%s' "$state_root" "$1"
}

runtime_dir() {
    printf '%s/instances/%s' "$run_root" "$1"
}

untrusted_root() {
    printf 'untrusted %s root: %s (%s)\n' "$1" "$2" "$3" >&2
    exit 64
}

trusted_root_level() {
    trusted_level_kind=$1
    trusted_level_root=$2
    trusted_level_path=$3
    if test ! -d "$trusted_level_path" || test -L "$trusted_level_path"; then
        untrusted_root "$trusted_level_kind" "$trusted_level_root" \
            "$trusted_level_path is not a directory"
    fi
    trusted_level_owner=$(stat -c %u -- "$trusted_level_path") ||
        untrusted_root "$trusted_level_kind" "$trusted_level_root" \
            "cannot inspect $trusted_level_path"
    test "$trusted_level_owner" = 0 ||
        untrusted_root "$trusted_level_kind" "$trusted_level_root" \
            "$trusted_level_path is not owned by root"
    trusted_level_mode=$(stat -c %a -- "$trusted_level_path") ||
        untrusted_root "$trusted_level_kind" "$trusted_level_root" \
            "cannot inspect $trusted_level_path"
    case $trusted_level_mode in
        ''|*[!0-7]*)
            untrusted_root "$trusted_level_kind" "$trusted_level_root" \
                "cannot inspect $trusted_level_path"
            ;;
    esac
    # 022: group or other write permission lets a non-root user rename or
    # plant entries on the path the helper later resolves by name.
    test "$((0$trusted_level_mode & 18))" -eq 0 ||
        untrusted_root "$trusted_level_kind" "$trusted_level_root" \
            "$trusted_level_path is writable by group or others"
}

# trusted_root KIND DIR CREATE: DIR and every ancestor must be a real
# directory owned by root without group or other write permission. Missing
# levels are created one at a time after their parent passed when CREATE is
# true.
trusted_root() {
    trusted_kind=$1
    trusted_path=$2
    trusted_create=$3
    case $trusted_path in
        /*) ;;
        *) untrusted_root "$trusted_kind" "$trusted_path" 'not an absolute path' ;;
    esac
    case $trusted_path in
        *[!A-Za-z0-9_./-]*)
            untrusted_root "$trusted_kind" "$trusted_path" 'unsupported character'
            ;;
        *//*|*/./*|*/../*|*/.|*/..|*/)
            untrusted_root "$trusted_kind" "$trusted_path" 'empty, "." or ".." component'
            ;;
    esac
    test "${#trusted_path}" -le 256 ||
        untrusted_root "$trusted_kind" "$trusted_path" 'longer than 256 bytes'
    trusted_root_level "$trusted_kind" "$trusted_path" /
    trusted_prefix=
    trusted_rest=${trusted_path#/}/
    while test -n "$trusted_rest"; do
        trusted_prefix=$trusted_prefix/${trusted_rest%%/*}
        trusted_rest=${trusted_rest#*/}
        if test ! -e "$trusted_prefix" && test ! -L "$trusted_prefix"; then
            test "$trusted_create" = true ||
                untrusted_root "$trusted_kind" "$trusted_path" "$trusted_prefix does not exist"
            mkdir -m 0755 -- "$trusted_prefix" ||
                untrusted_root "$trusted_kind" "$trusted_path" "cannot create $trusted_prefix"
        fi
        trusted_root_level "$trusted_kind" "$trusted_path" "$trusted_prefix"
    done
}

# lock_instance NAME: hold the per-instance lock on descriptor 6. The inode
# re-check lets delete unlink the lock file while holding it: a waiter that
# locked the unlinked inode retries on the new file.
lock_instance() {
    mkdir -p "$state_root/work"
    instance_lock=$state_root/work/instance.$1.lock
    while :; do
        exec 6>>"$instance_lock"
        flock -x 6
        lock_path_identity=$(stat -L -c %d:%i -- "$instance_lock" 2>/dev/null || true)
        lock_fd_identity=$(stat -L -c %d:%i "/proc/$$/fd/6" 2>/dev/null || true)
        if test -n "$lock_path_identity" && test "$lock_path_identity" = "$lock_fd_identity"; then
            break
        fi
        exec 6>&-
    done
}

# Release the lock of an instance that does not exist, removing its file.
drop_instance_lock() {
    rm -f -- "$instance_lock"
    exec 6>&-
}

# stat_after_comm PID N: the Nth field of /proc/PID/stat counted after the
# command name, which may itself contain spaces and parentheses (N=1 is the
# state, field 3; N=20 is the start time, field 22).
stat_after_comm() {
    awk -v n="$2" '{ sub(/.*\) /, ""); split($0, field, " "); print field[n] }' \
        "/proc/$1/stat" 2>/dev/null
}

outcome_supervisor_error='{"version":1,"outcome":"supervisor-error","code":null,"signal":null,"generation":null}'
outcome_pattern='^\{"version":1,"outcome":"(exited|signaled|supervisor-error)","code":(null|[0-9]{1,3}),"signal":(null|[0-9]{1,2}),"generation":null\}$'

strip_leading_zeros() {
    strip_value=$1
    while :; do
        case $strip_value in
            0?*) strip_value=${strip_value#0} ;;
            *) break ;;
        esac
    done
    printf '%s' "$strip_value"
}

# read_outcome FILE: set outcome_line, outcome_kind, outcome_code and
# outcome_signal from the first line of FILE when it is a valid record.
read_outcome() {
    test -f "$1" && test ! -L "$1" || return 1
    outcome_line=
    IFS= read -r outcome_line <"$1" || test -n "$outcome_line" || return 1
    printf '%s\n' "$outcome_line" | grep -Eq "$outcome_pattern" || return 1
    outcome_kind=${outcome_line#*\"outcome\":\"}
    outcome_kind=${outcome_kind%%\"*}
    outcome_code=${outcome_line#*\"code\":}
    outcome_code=${outcome_code%%,*}
    outcome_signal=${outcome_line#*\"signal\":}
    outcome_signal=${outcome_signal%%,*}
    case $outcome_kind:$outcome_code:$outcome_signal in
        exited:null:*|exited:*:[0-9]*) return 1 ;;
        signaled:*:null|signaled:[0-9]*:*) return 1 ;;
        supervisor-error:null:null) ;;
        supervisor-error:*) return 1 ;;
    esac
    case $outcome_kind in
        exited)
            outcome_code=$(strip_leading_zeros "$outcome_code")
            test "$outcome_code" -le 255 || return 1
            ;;
        signaled)
            outcome_signal=$(strip_leading_zeros "$outcome_signal")
            test "$outcome_signal" -ge 1 && test "$outcome_signal" -le 64 || return 1
            ;;
    esac
}

# write_outcome RUNTIME_DIRECTORY: publish the runtime's record, or
# supervisor-error when the runtime left none. Never fails.
write_outcome() {
    write_outcome_directory=$1
    write_outcome_line=$outcome_supervisor_error
    if read_outcome "$write_outcome_directory/result.runtime"; then
        write_outcome_line=$outcome_line
    fi
    write_outcome_tmp=$write_outcome_directory/outcome.tmp.$$
    {
        rm -f -- "$write_outcome_tmp" &&
            (umask 077 && printf '%s\n' "$write_outcome_line" >"$write_outcome_tmp") &&
            chmod 600 "$write_outcome_tmp" &&
            mv -f -- "$write_outcome_tmp" "$write_outcome_directory/outcome"
    } 2>/dev/null || rm -f -- "$write_outcome_tmp" 2>/dev/null || true
}

json_text() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

materialize_image() {
    materialize_reference=$1
    materialize_destination=$2
    if test -x "$image_tool" && test ! -d "$image_tool"; then
        "$image_tool" materialize \
            "$materialize_reference" "$state_root/cache/oci" "$materialize_destination"
        return
    fi

    # Test-only compatibility for predecessor fixtures. This directory is not
    # installed by the RPM or the canonical host installer.
    test -x "$image_tool/ensure-oci-image.sh" || return 69
    materialize_result=$(mktemp "$state_root/work/image-result.XXXXXX")
    GINUX_OCI_RESULT_FILE=$materialize_result GINUX_OCI_OUTPUT=human \
        "$image_tool/ensure-oci-image.sh" \
        "$materialize_reference" "$state_root/images" "$state_root/work/oci"
    materialize_tar=$(sed -n '1p' "$materialize_result")
    test -r "$materialize_tar" || {
        rm -f "$materialize_result"
        return 65
    }
    tar -xf "$materialize_tar" -C "$materialize_destination"
    rm -f "$materialize_result"
}

# materialize_root REFERENCE DESTINATION: where the filesystem supports
# reflinks, keep one pristine expansion per image digest under cache/roots
# and give each instance a reflink copy of it; elsewhere expand the image
# into DESTINATION as before and persist nothing.
materialize_root() {
    root_reference=$1
    root_destination=$2
    case $root_reference in
        *@sha256:*) root_hex=${root_reference##*@sha256:} ;;
        *) materialize_image "$root_reference" "$root_destination"; return ;;
    esac
    case $root_hex in
        *[!0-9a-f]*) materialize_image "$root_reference" "$root_destination"; return ;;
    esac
    if test "${#root_hex}" -ne 64; then
        materialize_image "$root_reference" "$root_destination"
        return
    fi
    roots=$state_root/cache/roots
    mkdir -p "$state_root/cache" "$state_root/work"
    install -d -m 700 "$roots" "$roots/sha256"
    root_probe=$(mktemp "$roots/.probe:XXXXXX")
    root_probe_copy=${root_destination%/*}/.reflink-probe.$$
    printf x >"$root_probe"
    root_reflink=false
    if cp --reflink=always -- "$root_probe" "$root_probe_copy" 2>/dev/null; then
        root_reflink=true
    fi
    rm -f -- "$root_probe" "$root_probe_copy"
    if test "$root_reflink" = false; then
        materialize_image "$root_reference" "$root_destination"
        return
    fi
    root_base=$roots/sha256/$root_hex
    exec 5>>"$state_root/work/root.$root_hex.lock"
    flock -x 5
    if test ! -d "$root_base"; then
        root_partial=$(mktemp -d "$roots/.partial:XXXXXX")
        # Also removed by the caller's cleanup if a signal or an unexpected
        # failure ends the process before the explicit removals below.
        mkdir "$root_partial/root" || {
            rm -rf -- "$root_partial"
            root_partial=
            exec 5>&-
            exit 70
        }
        set +e
        (set -e; materialize_image "$root_reference" "$root_partial/root")
        root_status=$?
        set -e
        if test "$root_status" -ne 0; then
            rm -rf -- "$root_partial"
            root_partial=
            exec 5>&-
            exit "$root_status"
        fi
        # The rename is the completeness marker of a base root. It is a
        # same-filesystem rename of a directory onto a path that does not
        # exist, done under the lock. If it fails, the reflink copy below
        # fails too and the image is expanded directly.
        if test ! -e "$root_base" && test ! -L "$root_base"; then
            mv -T -- "$root_partial/root" "$root_base" || true
        fi
        rm -rf -- "$root_partial"
        root_partial=
    fi
    if ! cp -a --reflink=always -- "$root_base/." "$root_destination/"; then
        rm -rf -- "$root_destination"
        mkdir -- "$root_destination"
        exec 5>&-
        materialize_image "$root_reference" "$root_destination"
        return
    fi
    exec 5>&-
}

root_path_is_executable() {
    executable_root=$(realpath -e -- "$1") || return 1
    executable_path=$executable_root$2
    executable_hops=0
    while test "$executable_hops" -lt 16; do
        executable_path=$(realpath -sm -- "$executable_path") || return 1
        case $executable_path in
            "$executable_root"/*) ;;
            *) return 1 ;;
        esac
        if test -L "$executable_path"; then
            executable_target=$(readlink -- "$executable_path") || return 1
            case $executable_target in
                /*) executable_path=$executable_root$executable_target ;;
                *) executable_path=$(dirname -- "$executable_path")/$executable_target ;;
            esac
            executable_hops=$((executable_hops + 1))
            continue
        fi
        test -f "$executable_path" && test -x "$executable_path"
        return
    done
    return 1
}

supervisor_identity() {
    supervisor_directory=$(runtime_dir "$1")
    supervisor_file=$supervisor_directory/supervisor.pid
    test -f "$supervisor_file" || return 1
    supervisor_pid=
    supervisor_start=
    supervisor_extra=
    IFS=' ' read -r supervisor_pid supervisor_start supervisor_extra \
        <"$supervisor_file" || return 1
    test -z "$supervisor_extra" || return 1
    case $supervisor_pid:$supervisor_start in
        *[!0-9:]*|:*) return 1 ;;
    esac
    test -r "/proc/$supervisor_pid/stat" || return 1
    supervisor_state=$(awk '{ print $3 }' "/proc/$supervisor_pid/stat")
    supervisor_actual_start=$(awk '{ print $22 }' "/proc/$supervisor_pid/stat")
    test "$supervisor_state" != Z || return 1
    test "$supervisor_actual_start" = "$supervisor_start" || return 1
    printf '%s\n' "$supervisor_pid"
}

record_supervisor() {
    record_directory=$1
    record_pid=$2
    record_start=$(awk '{ print $22 }' "/proc/$record_pid/stat")
    printf '%s %s\n' "$record_pid" "$record_start" >"$record_directory/supervisor.pid"
}

record_runtime() {
    record_directory=$1
    record_pid=$2
    install -d -m 700 "$record_directory"
    record_start=$(awk '{ print $22 }' "/proc/$record_pid/stat")
    printf '%s %s\n' "$record_pid" "$record_start" >"$record_directory/runtime.pid"
}

runtime_identity() {
    runtime_directory=$(runtime_dir "$1")
    runtime_file=$runtime_directory/runtime.pid
    test -f "$runtime_file" || return 1
    runtime_pid=
    runtime_start=
    runtime_extra=
    IFS=' ' read -r runtime_pid runtime_start runtime_extra <"$runtime_file" || return 1
    test -z "$runtime_extra" || return 1
    case $runtime_pid:$runtime_start in
        *[!0-9:]*|:*) return 1 ;;
    esac
    test -r "/proc/$runtime_pid/stat" || return 1
    runtime_state=$(awk '{ print $3 }' "/proc/$runtime_pid/stat")
    runtime_actual_start=$(awk '{ print $22 }' "/proc/$runtime_pid/stat")
    test "$runtime_state" != Z || return 1
    test "$runtime_actual_start" = "$runtime_start" || return 1
    printf '%s\n' "$runtime_pid"
}

reported_state() {
    if supervisor_identity "$1" >/dev/null; then
        printf '%s' running
    else
        printf '%s' stopped
    fi
}

network_addresses() {
    attachment=$1
    if ip link show dev "$attachment" >/dev/null 2>&1; then
        ip -o -4 addr show dev "$attachment"
    else
        alias_addresses=$(ip -o -4 addr show label "$attachment")
        test -n "$alias_addresses" || return 1
        printf '%s\n' "$alias_addresses"
    fi
}

resolve_network_config() {
    resolve_file=$1
    resolve_interface=$(sed -n 's/^[[:space:]]*interface[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$resolve_file")
    resolve_source=$(sed -n 's/^[[:space:]]*source[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$resolve_file")
    resolve_addresses=
    if test -n "$resolve_interface"; then
        resolve_addresses=$(network_addresses "$resolve_interface") || {
            printf 'configured network attachment is unavailable: %s\n' "$resolve_interface" >&2
            exit 65
        }
        test -n "$resolve_addresses" || {
            printf 'configured network attachment has no IPv4 address: %s\n' "$resolve_interface" >&2
            exit 65
        }
    fi
    if test -z "$resolve_source" && test -n "$resolve_addresses"; then
        resolve_source=$(printf '%s\n' "$resolve_addresses" | awk 'NR == 1 { split($4, address, "/"); print address[1] }')
        resolve_output=$(mktemp "$state_root/work/config.XXXXXX")
        "$runtime" config-merge "$resolve_file" "network.source=\"$resolve_source\"" >"$resolve_output"
        mv "$resolve_output" "$resolve_file"
    fi
    if test -n "$resolve_source"; then
        if test -n "$resolve_addresses"; then
            printf '%s\n' "$resolve_addresses" |
                awk -v expected="$resolve_source" '{ split($4, address, "/"); if (address[1] == expected) found=1 } END { exit !found }' || {
                    printf 'configured source address is not assigned to %s: %s\n' "$resolve_interface" "$resolve_source" >&2
                    exit 65
                }
        else
            ip -o -4 addr show |
                awk -v expected="$resolve_source" '{ split($4, address, "/"); if (address[1] == expected) found=1 } END { exit !found }' || {
                    printf 'configured source address is unavailable: %s\n' "$resolve_source" >&2
                    exit 65
                }
        fi
    fi
}

validate_forward() {
    forward_spec=$1
    forward_protocol=
    forward_external=
    forward_instance=
    old_ifs=$IFS
    IFS=,
    set -- $forward_spec
    IFS=$old_ifs
    test "$#" -eq 3 || return 1
    for forward_field in "$@"; do
        case $forward_field in
            protocol=tcp|protocol=udp)
                test -z "$forward_protocol" || return 1
                forward_protocol=${forward_field#protocol=}
                ;;
            external_port=*)
                test -z "$forward_external" || return 1
                forward_external=${forward_field#external_port=}
                ;;
            instance_port=*)
                test -z "$forward_instance" || return 1
                forward_instance=${forward_field#instance_port=}
                ;;
            *) return 1 ;;
        esac
    done
    for forward_port in "$forward_external" "$forward_instance"; do
        case $forward_port in
            ''|*[!0-9]*) return 1 ;;
        esac
        test "$forward_port" -ge 1 && test "$forward_port" -le 65535 || return 1
    done
    test -n "$forward_protocol"
}

validate_attachment() {
    case ${1-} in
        ''|*[!A-Za-z0-9_.:-]*) return 1 ;;
        *) return 0 ;;
    esac
}

read_deployment() {
    deployment_file=$1
    deployment_network=
    deployment_forwards=
    deployment_contract=locked
    deployment_contract_seen=false
    test -f "$deployment_file" || return 0
    while IFS="$(printf '\t')" read -r deployment_key deployment_value deployment_extra; do
        test -z "$deployment_extra" || return 1
        case $deployment_key in
            network)
                test -z "$deployment_network" || return 1
                deployment_network=$deployment_value
                ;;
            forward)
                validate_forward "$deployment_value" || return 1
                deployment_forwards="$deployment_forwards
$deployment_value"
                ;;
            contract)
                test "$deployment_contract_seen" = false || return 1
                case $deployment_value in
                    locked|unlocked) deployment_contract=$deployment_value ;;
                    *) return 1 ;;
                esac
                deployment_contract_seen=true
                ;;
            '') ;;
            *) return 1 ;;
        esac
    done <"$deployment_file"
}

write_deployment() {
    deployment_file=$1
    deployment_network=$2
    deployment_forwards=$3
    deployment_contract=${4:-locked}
    case $deployment_contract in
        locked|unlocked) ;;
        *) return 1 ;;
    esac
    deployment_tmp=$deployment_file.tmp.$$
    : >"$deployment_tmp"
    if test -n "$deployment_network"; then
        printf 'network\t%s\n' "$deployment_network" >>"$deployment_tmp"
    fi
    old_ifs=$IFS
    IFS='
'
    for deployment_forward in $deployment_forwards; do
        test -n "$deployment_forward" || continue
        printf 'forward\t%s\n' "$deployment_forward" >>"$deployment_tmp"
    done
    IFS=$old_ifs
    printf 'contract\t%s\n' "$deployment_contract" >>"$deployment_tmp"
    chmod 600 "$deployment_tmp"
    mv "$deployment_tmp" "$deployment_file"
}

materialize_runtime_config() {
    materialize_recipe=$1
    materialize_deployment=$2
    materialize_output=$3
    read_deployment "$materialize_deployment" || {
        printf '%s\n' 'invalid persisted instance deployment state' >&2
        return 1
    }
    set --
    if test -n "$deployment_network"; then
        set -- "$@" "network.interface=\"$deployment_network\""
    fi
    forward_list=
    forward_separator=
    old_ifs=$IFS
    IFS='
'
    for materialize_forward in $deployment_forwards; do
        test -n "$materialize_forward" || continue
        validate_forward "$materialize_forward" || return 1
        forward_attachment=${deployment_network:-default}
        forward_value=$forward_protocol/$forward_attachment/$forward_external/$forward_instance
        forward_list=$forward_list$forward_separator\"$forward_value\"
        forward_separator=', '
    done
    IFS=$old_ifs
    if test -n "$forward_list"; then
        set -- "$@" "network.port_forwards=[$forward_list]"
    fi
    if test "$deployment_contract" = unlocked; then
        set -- "$@" \
            'contract.allow=["*"]' \
            'contract.deny=[]' \
            'contract.syscalls.allow=["*"]' \
            'contract.syscalls.deny=[]' \
            'contract.filesystem.read=["/"]' \
            'contract.filesystem.write=["/"]' \
            'contract.filesystem.create=["/"]' \
            'contract.filesystem.deny=[]' \
            'contract.network.inbound=["tcp:*", "udp:*"]' \
            'contract.network.outbound=["tcp:*", "udp:*"]' \
            'contract.devices.read=["/"]' \
            'contract.devices.write=["/"]' \
            'contract.devices.create=["/"]' \
            'contract.privileges.setuid=["/"]' \
            'contract.privileges.setgid=["/"]' \
            'contract.process.signals=["*"]' \
            'contract.process.ptrace="allow"' \
            'contract.process.namespace_create=["*"]' \
            'contract.process.namespace_join=["*"]' \
            'contract.kernel.proc_read=["/"]' \
            'contract.kernel.sys_read=["/"]'
    fi
    if ! "$runtime" config-merge "$materialize_recipe" "$@" >"$materialize_output"; then
        cat "$materialize_output" >&2
        return 1
    fi
    resolve_network_config "$materialize_output"
}

prepare_root() {
    root=$1
    mkdir -p \
        "$root/run" \
        "$root/run/host" \
        "$root/proc" \
        "$root/sys" \
        "$root/dev/shm" \
        "$root/dev/pts" \
        "$root/run/log/journal" \
        "$root/run/systemd/journal" \
        "$root/run/systemd/propagate/.os-release-stage" \
        "$root/usr/local/sbin"
    touch "$root/etc/resolv.conf"
    rm -f "$root/run/initctl"
    if test -e /etc/resolv.conf; then
        cp /etc/resolv.conf "$root/etc/resolv.conf"
    fi
    # procfs and sysfs are Ginux-owned, on-demand object models. Clear any
    # materialized nodes left by an older runtime, retaining only mountpoints.
    find "$root/proc" -mindepth 1 -delete
    find "$root/sys" -mindepth 1 -delete
    for device_spec in 'console 5 0 600' 'null 1 3 666' 'zero 1 5 666' 'random 1 8 666' 'urandom 1 9 666'; do
        device_ifs=$IFS
        IFS=' '
        set -- $device_spec
        IFS=$device_ifs
        test -e "$root/dev/$1" || mknod -m "$4" "$root/dev/$1" c "$2" "$3"
    done
    # The runtime drops root-launched workloads to the host nobody identity.
    # Ginux maintains instance-visible credentials independently.
    chown -R 65534:65534 "$root"
    find "$root" -type d -exec chmod u+w {} +
    test ! -e "$root/etc/shadow" || chmod 600 "$root/etc/shadow"
    allocator_library=${GINUX_ALLOCATOR_LIBRARY:-/usr/lib64/ginux/libginux_allocator.so}
    if test -r "$allocator_library"; then
        install -D -m 0755 "$allocator_library" \
            "$root/usr/lib64/ginux/libginux_allocator.so"
        chown 65534:65534 "$root/usr/lib64/ginux/libginux_allocator.so"
    fi
}

reject_duplicate_instance() {
    printf '%s: already exists\n' "$1" >&2
    exit 73
}

import_instance() {
    test "$#" -ge 2 || usage
    name=$1
    config=$2
    shift 2
    overrides=
    create_network=
    create_network_seen=false
    create_forwards=
    create_forward_mode=
    while test "$#" -gt 0; do
        case $1 in
            --set)
                test "$#" -ge 2 || usage
                case $2 in *=*) ;; *) usage ;; esac
                overrides="$overrides
$2"
                shift 2
                ;;
            --network)
                test "$#" -ge 2 || usage
                test "$create_network_seen" = false || usage
                case $2 in
                    default) create_network= ;;
                    *) validate_attachment "$2" || usage; create_network=$2 ;;
                esac
                create_network_seen=true
                shift 2
                ;;
            --forward)
                test "$#" -ge 2 || usage
                if test "$2" = none; then
                    test -z "$create_forward_mode" || usage
                    create_forward_mode=none
                else
                    test "$create_forward_mode" != none || usage
                    validate_forward "$2" || usage
                    create_forward_mode=list
                    create_forwards="$create_forwards
$2"
                fi
                shift 2
                ;;
            *) usage ;;
        esac
    done
    validate_name "$name"
    test -r "$config" || { printf 'configuration is not readable: %s\n' "$config" >&2; exit 66; }
    test -x "$runtime" || { printf '%s\n' 'Ginux runtime is not installed' >&2; exit 69; }
    test -x "$image_tool" || test -x "$image_tool/ensure-oci-image.sh" || {
        printf '%s\n' 'Ginux image acquisition support is not installed' >&2
        exit 69
    }
    lock_instance "$name"
    directory=$(instance_dir "$name")
    replacing=false
    if test -e "$directory" || test -L "$directory"; then
        if test "$command" = create; then
            reject_duplicate_instance "$name"
        fi
        test -d "$directory" || { printf '%s: invalid instance state\n' "$name" >&2; exit 65; }
        if supervisor_identity "$name" >/dev/null; then
            printf '%s: stop the instance before importing configuration\n' "$name" >&2
            exit 73
        fi
        replacing=true
        read_deployment "$directory/deployment.state" || {
            printf '%s: invalid persisted deployment state\n' "$name" >&2
            exit 65
        }
        test "$create_network_seen" = true || create_network=$deployment_network
        test -n "$create_forward_mode" || create_forwards=$deployment_forwards
    fi

    mkdir -p "$state_root/work"
    effective=$(mktemp "$state_root/work/config.XXXXXX")
    cleanup_effective() {
        rm -f "$effective"
    }
    trap cleanup_effective 0 HUP INT TERM
    set --
    old_ifs=$IFS
    IFS='
'
    for override in $overrides; do
        test -n "$override" || continue
        set -- "$@" "$override"
    done
    IFS=$old_ifs
    "$runtime" config-merge "$config" "$@" "instance.id=\"$name\"" >"$effective"
    configured_root=$(sed -n 's/^[[:space:]]*root[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$effective")
    if test "$replacing" = true; then
        current_root=$(sed -n 's/^[[:space:]]*root[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$directory/config.toml")
        if test "$configured_root" != "$current_root"; then
            printf '%s\n' 'changing an existing instance root image is not supported; create a new instance' >&2
            exit 65
        fi
        candidate_config=$directory/config.toml.candidate.$$
        candidate_deployment=$directory/deployment.state.candidate.$$
        candidate_runtime=$directory/runtime.toml.candidate.$$
        cleanup_candidate() {
            rm -f "$candidate_config" "$candidate_deployment" "$candidate_runtime"
        }
        trap cleanup_candidate 0 HUP INT TERM
        install -m 600 "$effective" "$candidate_config"
        write_deployment "$candidate_deployment" "$create_network" "$create_forwards" \
            "$deployment_contract"
        materialize_runtime_config \
            "$candidate_config" "$candidate_deployment" "$candidate_runtime"
        mv "$candidate_config" "$directory/config.toml"
        mv "$candidate_deployment" "$directory/deployment.state"
        mv "$candidate_runtime" "$directory/runtime.toml"
        trap - 0 HUP INT TERM
        cleanup_effective
        flock -u 6
        exec 6>&-
        printf 'Instance "%s" imported.\n' "$name"
        return
    fi

    if test "$command" = create; then
        printf 'Creating instance "%s" from defaults\n' "$name"
    else
        printf 'Importing instance "%s"\n' "$name"
    fi
    printf '  Preparing instance filesystem\n'
    staging_parent=$(mktemp -d "$state_root/instances/.create:XXXXXX")
    staging=$staging_parent/instance
    cleanup_staging() {
        rm -rf "$staging_parent"
        test -z "${root_partial-}" || rm -rf -- "$root_partial"
        rm -f "$effective"
    }
    trap cleanup_staging 0 HUP INT TERM
    # The instance directory is root-private whatever umask the helper
    # inherited: its root is owned by uid 65534, and any other process of that
    # identity must not reach it, nor read the recipe or the logs.
    install -d -m 0700 "$staging"
    mkdir "$staging/root"
    install -m 600 "$effective" "$staging/config.toml"
    write_deployment "$staging/deployment.state" "$create_network" "$create_forwards" locked
    materialize_runtime_config \
        "$staging/config.toml" "$staging/deployment.state" "$staging/runtime.toml"
    chmod 600 "$staging/runtime.toml"
    materialize_root "$configured_root" "$staging/root"
    # The configured init is checked by start, not here: inject may provide
    # it after the instance exists.
    prepare_root "$staging/root"
    chmod 0700 "$staging"
    mv -T --no-copy --update=none "$staging" "$directory"
    # A skipped rename succeeds and leaves the source in place.
    if test -d "$staging"; then
        reject_duplicate_instance "$name"
    fi
    printf '  Instance filesystem ready\n'
    cleanup_staging
    trap - 0 HUP INT TERM
    flock -u 6
    exec 6>&-
    if test "$command" = create; then
        printf 'Instance "%s" created.\n' "$name"
    else
        printf 'Instance "%s" imported.\n' "$name"
    fi
}

create_instance() {
    test "$#" -ge 1 || usage
    name=$1
    shift
    test -r "$default_recipe" || {
        printf 'default instance recipe is not readable: %s\n' "$default_recipe" >&2
        exit 69
    }
    import_instance "$name" "$default_recipe" "$@"
}

set_instance() {
    test "$#" -ge 3 || usage
    name=$1
    shift
    validate_name "$name"
    directory=$(instance_dir "$name")
    test -d "$directory" || { printf '%s: not found\n' "$name" >&2; exit 66; }
    if supervisor_identity "$name" >/dev/null; then
        printf '%s: stop the instance before changing deployment settings\n' "$name" >&2
        exit 73
    fi
    read_deployment "$directory/deployment.state" || {
        printf '%s: invalid persisted deployment state\n' "$name" >&2
        exit 65
    }
    next_network=$deployment_network
    next_forwards=$deployment_forwards
    set_network_seen=false
    set_forward_seen=false
    set_forward_mode=
    replacement_forwards=
    recipe_overrides=
    recipe_changed=false
    while test "$#" -gt 0; do
        case $1 in
            --set)
                test "$#" -ge 2 || usage
                case $2 in *=*) ;; *) usage ;; esac
                recipe_overrides="$recipe_overrides
$2"
                recipe_changed=true
                shift 2
                ;;
            --network)
                test "$#" -ge 2 || usage
                test "$set_network_seen" = false || usage
                case $2 in
                    default) next_network= ;;
                    ''|*[!A-Za-z0-9_.:-]*) usage ;;
                    *) next_network=$2 ;;
                esac
                set_network_seen=true
                shift 2
                ;;
            --forward)
                test "$#" -ge 2 || usage
                if test "$2" = none; then
                    test -z "$set_forward_mode" || usage
                    replacement_forwards=
                    set_forward_mode=none
                    set_forward_seen=true
                else
                    test "$set_forward_mode" != none || usage
                    validate_forward "$2" || usage
                    set_forward_mode=list
                    replacement_forwards="$replacement_forwards
$2"
                    set_forward_seen=true
                fi
                shift 2
                ;;
            *) usage ;;
        esac
    done
    test "$set_network_seen" = true || test "$set_forward_seen" = true || \
        test "$recipe_changed" = true || usage
    if test "$set_forward_seen" = true; then
        next_forwards=$replacement_forwards
    fi
    candidate_deployment=$directory/deployment.state.candidate.$$
    candidate_config=$directory/config.toml.candidate.$$
    candidate_runtime=$directory/runtime.toml.candidate.$$
    cleanup_candidate() {
        rm -f "$candidate_deployment" "$candidate_config" "$candidate_runtime"
    }
    trap cleanup_candidate 0 HUP INT TERM
    set --
    old_ifs=$IFS
    IFS='
'
    for recipe_override in $recipe_overrides; do
        test -n "$recipe_override" || continue
        set -- "$@" "$recipe_override"
    done
    IFS=$old_ifs
    "$runtime" config-merge "$directory/config.toml" "$@" >"$candidate_config"
    write_deployment "$candidate_deployment" "$next_network" "$next_forwards" \
        "$deployment_contract"
    materialize_runtime_config \
        "$candidate_config" "$candidate_deployment" "$candidate_runtime"
    mv "$candidate_config" "$directory/config.toml"
    mv "$candidate_deployment" "$directory/deployment.state"
    mv "$candidate_runtime" "$directory/runtime.toml"
    trap - 0 HUP INT TERM
    printf 'Instance "%s" updated.\n' "$name"
}

export_instance() {
    test "$#" -eq 1 || usage
    name=$1
    validate_name "$name"
    directory=$(instance_dir "$name")
    test -r "$directory/config.toml" || { printf '%s: not found\n' "$name" >&2; exit 66; }
    cat "$directory/config.toml"
}

list_instances() {
    printf '%-24s %-10s %-10s %s\n' NAME STATE CONTRACT PID
    for list_directory in "$state_root"/instances/*; do
        test -d "$list_directory" || continue
        list_name=${list_directory##*/}
        list_state=$(reported_state "$list_name")
        list_pid=-
        if read_deployment "$list_directory/deployment.state"; then
            list_contract=$deployment_contract
        else
            list_contract=invalid
        fi
        if test "$list_state" = running; then
            list_pid=$(supervisor_identity "$list_name")
        fi
        printf '%-24s %-10s %-10s %s\n' \
            "$list_name" "$list_state" "$list_contract" "$list_pid"
    done
}

status_instance() {
    status_format=text
    case $# in
        1) ;;
        3)
            test "$2" = --format || usage
            case $3 in
                json|text) status_format=$3 ;;
                *) usage ;;
            esac
            ;;
        *) usage ;;
    esac
    name=$1
    validate_name "$name"
    directory=$(instance_dir "$name")
    test -d "$directory" || { printf '%s: not found\n' "$name" >&2; exit 66; }
    state=$(reported_state "$name")
    read_deployment "$directory/deployment.state" || {
        printf '%s: invalid persisted instance deployment state\n' "$name" >&2
        exit 65
    }
    if test "$status_format" = json; then
        status_json
        return
    fi
    printf 'name: %s\nstate: %s\ncontract: %s\n' \
        "$name" "$state" "$deployment_contract"
    if test "$state" = running; then
        printf 'pid: %s\n' "$(supervisor_identity "$name")"
    fi
    printf 'config: %s\ndeployment: %s\nconsole-log: %s\naudit-log: %s\n' \
        "$directory/config.toml" "$directory/deployment.state" \
        "$directory/console.log" "$directory/audit.log"
}

status_json() {
    case $directory in
        *[[:cntrl:]]*)
            printf '%s: instance path cannot be represented in JSON\n' "$name" >&2
            exit 65
            ;;
    esac
    status_pid=null
    status_outcome=null
    if test "$state" = running; then
        status_pid=$(supervisor_identity "$name" || true)
        test -n "$status_pid" || status_pid=null
    elif read_outcome "$(runtime_dir "$name")/outcome"; then
        status_outcome=$outcome_line
    fi
    status_directory=$(json_text "$directory")
    printf '{"version":1,"name":"%s","state":"%s","contract":"%s","pid":%s,"outcome":%s,' \
        "$name" "$state" "$deployment_contract" "$status_pid" "$status_outcome"
    printf '"paths":{"config":"%s","deployment":"%s","console_log":"%s","audit_log":"%s","root":"%s"}}\n' \
        "$status_directory/config.toml" "$status_directory/deployment.state" \
        "$status_directory/console.log" "$status_directory/audit.log" \
        "$status_directory/root"
}

set_contract_lock() {
    test "$#" -eq 2 || usage
    name=$1
    next_contract=$2
    validate_name "$name"
    case $next_contract in
        locked|unlocked) ;;
        *) usage ;;
    esac
    directory=$(instance_dir "$name")
    test -d "$directory" || { printf '%s: not found\n' "$name" >&2; exit 66; }
    if supervisor_identity "$name" >/dev/null; then
        printf '%s: stop the instance before changing the contract lock\n' "$name" >&2
        exit 73
    fi
    read_deployment "$directory/deployment.state" || {
        printf '%s: invalid persisted instance deployment state\n' "$name" >&2
        exit 65
    }
    if test "$deployment_contract" = "$next_contract"; then
        printf 'Instance "%s" contract is already %s.\n' "$name" "$next_contract"
        return
    fi
    candidate_deployment=$directory/deployment.state.candidate.$$
    candidate_runtime=$directory/runtime.toml.candidate.$$
    cleanup_candidate() {
        rm -f "$candidate_deployment" "$candidate_runtime"
    }
    trap cleanup_candidate 0 HUP INT TERM
    write_deployment "$candidate_deployment" "$deployment_network" \
        "$deployment_forwards" "$next_contract"
    materialize_runtime_config \
        "$directory/config.toml" "$candidate_deployment" "$candidate_runtime"
    mv "$candidate_deployment" "$directory/deployment.state"
    mv "$candidate_runtime" "$directory/runtime.toml"
    trap - 0 HUP INT TERM
    printf 'Instance "%s" contract %s.\n' "$name" "$next_contract"
}

start_instance() {
    test "$#" -ge 1 || usage
    name=$1
    shift
    start_mode=detached
    start_audit=false
    start_wait_pid=
    start_wait_start=
    start_stream=false
    while test "$#" -gt 0; do
        case $1 in
            --attach)
                test "$start_mode" = detached || usage
                start_mode=attached
                ;;
            --audit)
                test "$start_audit" = false || usage
                start_audit=true
                ;;
            --wait)
                test -z "$start_wait_pid" || usage
                test "$#" -ge 3 || usage
                case $2 in ''|*[!0-9]*) usage ;; esac
                case $3 in ''|*[!0-9]*) usage ;; esac
                start_wait_pid=$2
                start_wait_start=$3
                shift 2
                ;;
            --stream-console)
                test "$start_stream" = false || usage
                start_stream=true
                ;;
            *) usage ;;
        esac
        shift
    done
    test -z "$start_wait_pid" || test "$start_mode" = detached || usage
    test "$start_stream" = false || test -n "$start_wait_pid" || usage
    validate_name "$name"
    lock_instance "$name"
    directory=$(instance_dir "$name")
    runtime_directory=$(runtime_dir "$name")
    test -d "$directory" || {
        drop_instance_lock
        printf '%s: not found\n' "$name" >&2
        exit 66
    }
    if supervisor_identity "$name" >/dev/null || runtime_identity "$name" >/dev/null; then
        printf '%s: already running\n' "$name" >&2
        exit 73
    fi
    read_deployment "$directory/deployment.state" || {
        printf '%s: invalid persisted instance deployment state\n' "$name" >&2
        exit 65
    }
    # Instances created by an earlier helper may have a traversable directory.
    chmod 0700 "$directory"
    configured_init=$(sed -n 's/^[[:space:]]*init[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$directory/config.toml")
    root_path_is_executable "$directory/root" "$configured_init" || {
        printf '\nconfigured init is missing or not executable: %s\n' "$configured_init" >&2
        exit 65
    }
    if test "$deployment_contract" = unlocked; then
        printf 'WARNING: %s is starting with its contract unlocked for maintenance.\n' \
            "$name" >&2
    fi
    install -d -m 700 "$runtime_directory"
    rm -f \
        "$runtime_directory/supervisor.pid" \
        "$runtime_directory/runtime.pid" \
        "$runtime_directory/exit.status" \
        "$runtime_directory/console.in" \
        "$runtime_directory/control.in" \
        "$runtime_directory/outcome" \
        "$runtime_directory/result.runtime"
    mkfifo -m 600 "$runtime_directory/console.in"
    mkfifo -m 600 "$runtime_directory/control.in"
    : >"$directory/audit.log"
    : >"$directory/console.log"
    # Root-only, like the directory; the caller receives console output
    # through start --wait --stream-console instead.
    chmod 0600 "$directory/audit.log" "$directory/console.log"

    # The supervisor must not inherit the instance lock on descriptor 6.
    nohup "$0" --protocol 1 supervise "$name" "$start_audit" 6>&- >/dev/null 2>&1 </dev/null &
    pid=$!
    record_supervisor "$runtime_directory" "$pid"
    wait_supervisor_start=$record_start
    exec 6>&-
    if test -n "$start_wait_pid"; then
        wait_for_instance
    fi
    sleep 1
    if ! kill -0 "$pid" 2>/dev/null; then
        rm -f "$runtime_directory/supervisor.pid"
        printf '%s: failed to start; inspect %s and %s\n' \
            "$name" "$directory/console.log" "$directory/audit.log" >&2
        exit 70
    fi
    if test "$start_mode" = attached; then
        printf '%s: started (supervisor pid %s); attaching console\n' "$name" "$pid"
    else
        printf '%s: started detached (supervisor pid %s)\n' "$name" "$pid"
    fi
}

# The waiting caller is identified by pid and start time, so a reused pid
# does not keep the instance alive.
caller_alive() {
    caller_state=$(stat_after_comm "$start_wait_pid" 1 || true)
    test -n "$caller_state" && test "$caller_state" != Z || return 1
    test "$(stat_after_comm "$start_wait_pid" 20 || true)" = "$start_wait_start"
}

supervisor_child_running() {
    child_state=$(stat_after_comm "$pid" 1 || true)
    test -n "$child_state" && test "$child_state" != Z || return 1
    test "$(stat_after_comm "$pid" 20 || true)" = "$wait_supervisor_start"
}

# Remove the pid files only while they still name this start's supervisor;
# a later start may already have recorded its own.
remove_waited_pid_files() {
    waited_record=
    IFS= read -r waited_record <"$runtime_directory/supervisor.pid" 2>/dev/null || true
    if test "$waited_record" = "$pid $wait_supervisor_start"; then
        rm -f "$runtime_directory/runtime.pid" "$runtime_directory/supervisor.pid"
    fi
}

exit_for_outcome() {
    if read_outcome "$runtime_directory/outcome"; then
        case $outcome_kind in
            exited) exit "$outcome_code" ;;
            signaled) exit "$((128 + outcome_signal))" ;;
        esac
    fi
    exit 70
}

teardown() {
    trap - HUP INT TERM
    if supervisor_child_running; then
        # The supervisor's TERM trap stops the runtime and records the outcome.
        kill -TERM "$pid" 2>/dev/null || true
        teardown_attempt=0
        while supervisor_child_running && test "$teardown_attempt" -lt 25; do
            teardown_attempt=$((teardown_attempt + 1))
            sleep 0.2
        done
        if supervisor_child_running; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    teardown_runtime=$(runtime_identity "$name" || true)
    if test -n "$teardown_runtime"; then
        kill -KILL "$teardown_runtime" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
    test -f "$runtime_directory/outcome" || write_outcome_supervisor_error
    remove_waited_pid_files
    finish_console_stream
    exit_for_outcome
}

write_outcome_supervisor_error() {
    rm -f -- "$runtime_directory/result.runtime" 2>/dev/null || true
    write_outcome "$runtime_directory"
}

# opened_regular_file PATH FD: descriptor FD of this shell is a regular file
# and the same file that PATH (not followed if it is a link) names.
opened_regular_file() {
    case $(stat -L -c %F "/proc/$$/fd/$2" 2>/dev/null || true) in
        'regular file'|'regular empty file') ;;
        *) return 1 ;;
    esac
    opened_fd_identity=$(stat -L -c %d:%i "/proc/$$/fd/$2" 2>/dev/null || true)
    opened_path_identity=$(stat -c %d:%i -- "$1" 2>/dev/null || true)
    test -n "$opened_fd_identity" && test "$opened_fd_identity" = "$opened_path_identity"
}

# open_console_stream: open console.log once, read-only, on descriptor 3 and
# start the pump that copies what is appended to it to standard output. The
# path must name a regular file, not a link, and the opened descriptor must be
# that same file. The supervisor was started before, so neither it nor the
# workload inherits descriptor 3.
open_console_stream() {
    stream_pid=
    stream_log=$directory/console.log
    if test -f "$stream_log" && test ! -L "$stream_log" && command exec 3<"$stream_log"; then
        if opened_regular_file "$stream_log" 3; then
            stream_parent=$$
            console_stream_pump &
            stream_pid=$!
            return 0
        fi
        exec 3<&-
    fi
    printf '%s: console log is not a regular file: %s\n' "$name" "$stream_log" >&2
    teardown
}

# console_stream_pump: every 100 ms copy what was appended to the console log
# since the last copy (the descriptor's offset, shared with this subshell,
# tracks it) to standard output. On USR1, or when the helper is gone, stop
# polling and copy the remainder exactly once. A write error (the reader went
# away) ends the pump. Terminal signals are left to the helper, which stops
# the pump itself, so a signalled run still delivers its tail. Run only as
# `console_stream_pump &`: the traps must belong to the process whose PID is
# $!, so the body is a brace group, not a subshell of its own.
console_stream_pump() {
    trap '' HUP INT TERM
    stream_stop=false
    trap 'stream_stop=true' USR1
    while test "$stream_stop" = false && kill -0 "$stream_parent" 2>/dev/null; do
        cat <&3 2>/dev/null || exit 0
        sleep 0.1 &
        wait "$!" || true
    done
    cat <&3 2>/dev/null || true
    exit 0
}

# finish_console_stream: after the run has ended, let the pump copy the
# remainder of the console log (bounded: a pump blocked on a reader that no
# longer reads is killed after five seconds), then, unless the workload
# exited 0, write the end of the audit log to standard error.
finish_console_stream() {
    test "$start_stream" = true || return 0
    if test -n "${stream_pid-}"; then
        kill -USR1 "$stream_pid" 2>/dev/null || true
        (sleep 5; kill -KILL "$stream_pid" 2>/dev/null) </dev/null >/dev/null 2>&1 &
        stream_watchdog=$!
        wait "$stream_pid" 2>/dev/null || true
        kill "$stream_watchdog" 2>/dev/null || true
        wait "$stream_watchdog" 2>/dev/null || true
        stream_pid=
    fi
    exec 3<&-
    if read_outcome "$runtime_directory/outcome" &&
        test "$outcome_kind" = exited && test "$outcome_code" -eq 0; then
        return 0
    fi
    report_audit_tail
}

# report_audit_tail: the last 64 KiB of the audit log on standard error after
# a one-line marker giving the byte count, opened like the console log.
report_audit_tail() {
    audit_log=$directory/audit.log
    test -f "$audit_log" && test ! -L "$audit_log" || return 0
    command exec 4<"$audit_log" || return 0
    opened_regular_file "$audit_log" 4 || {
        exec 4<&-
        return 0
    }
    audit_size=$(stat -L -c %s "/proc/$$/fd/4" 2>/dev/null || printf 0)
    test "$audit_size" -le 65536 || audit_size=65536
    printf 'ginux: audit log (last %s bytes):\n' "$audit_size" >&2
    if test "$audit_size" -gt 0; then
        tail -c "$audit_size" <&4 >&2 2>/dev/null || true
    fi
    exec 4<&-
}

# start --wait: stay in the foreground until the instance ends, tear it down
# when the caller dies or this helper is signalled, and exit with the
# workload's code, 128+signal, or 70 for supervisor-error. Prints nothing,
# except with --stream-console: then standard output carries exactly the
# console bytes, and a run that did not exit 0 adds the end of the audit log
# to standard error.
wait_for_instance() {
    trap teardown HUP INT TERM
    test "$start_stream" = false || open_console_stream
    while supervisor_child_running; do
        caller_alive || teardown
        # A background sleep keeps the traps responsive.
        sleep 0.2 &
        wait "$!" || true
    done
    trap - HUP INT TERM
    wait "$pid" 2>/dev/null || true
    test -f "$runtime_directory/outcome" || write_outcome "$runtime_directory"
    remove_waited_pid_files
    finish_console_stream
    exit_for_outcome
}

supervise_instance() {
    test "$#" -eq 2 || usage
    name=$1
    audit_override=$2
    case $audit_override in
        true|false) ;;
        *) usage ;;
    esac
    validate_name "$name"
    directory=$(instance_dir "$name")
    runtime_directory=$(runtime_dir "$name")
    test -d "$directory" || { printf '%s: not found\n' "$name" >&2; exit 66; }
    exec 9<>"$runtime_directory/console.in"
    exec 10<>"$runtime_directory/control.in"
    set +e
    # Let script(1) provide the pseudo-terminal, but record only the runtime
    # stream. Its normal typescript header/footer are implementation details,
    # not instance console output.
    # The marker tells run-runtime it was started by this lifecycle, so it asks
    # the runtime for an outcome record (console.in and control.in persist
    # after a run and cannot identify a lifecycle start).
    GINUX_LIFECYCLE_RESULT=1 script -qefE never -c "$0 --protocol 1 run-runtime $name $audit_override" /dev/null \
        <&9 >>"$directory/console.log" 2>>"$directory/audit.log" &
    console_pid=$!
    terminate_supervisor() {
        trap - HUP INT TERM
        # A record the runtime wrote before this cancellation is the real
        # outcome; one written because of it is not.
        terminate_record=false
        test ! -f "$runtime_directory/result.runtime" || terminate_record=true
        runtime_pid=$(runtime_identity "$name" || true)
        if test -n "$runtime_pid"; then
            kill -TERM "$runtime_pid" 2>/dev/null || true
            terminate_attempt=0
            while kill -0 "$runtime_pid" 2>/dev/null && test "$terminate_attempt" -lt 20; do
                terminate_attempt=$((terminate_attempt + 1))
                sleep 0.1
            done
            kill -KILL "$runtime_pid" 2>/dev/null || true
        fi
        kill -TERM "$console_pid" 2>/dev/null || true
        wait "$console_pid" 2>/dev/null || true
        test "$terminate_record" = true || rm -f "$runtime_directory/result.runtime"
        write_outcome "$runtime_directory"
        rm -f "$runtime_directory/runtime.pid" "$runtime_directory/supervisor.pid"
        exit 143
    }
    trap terminate_supervisor HUP INT TERM
    wait "$console_pid"
    status=$?
    trap - HUP INT TERM
    set -e
    printf '%s\n' "$status" >"$runtime_directory/exit.status"
    write_outcome "$runtime_directory"
    rm -f "$runtime_directory/runtime.pid" "$runtime_directory/supervisor.pid"
    exit "$status"
}

run_runtime() {
    test "$#" -eq 2 || usage
    name=$1
    audit_override=$2
    case $audit_override in
        true|false) ;;
        *) usage ;;
    esac
    validate_name "$name"
    directory=$(instance_dir "$name")
    runtime_directory=$(runtime_dir "$name")
    test -d "$directory" || exit 66
    # Read the lifecycle marker once and keep it out of the environment of
    # everything started below.
    lifecycle_result=${GINUX_LIFECYCLE_RESULT-}
    unset GINUX_LIFECYCLE_RESULT
    # util-linux script(1) does not preserve the supervisor shell's auxiliary
    # descriptors when it starts the PTY command. Open the lifecycle-created
    # FIFO in the runtime command itself so Ginux can receive attached-console
    # signal requests on descriptor 10. Direct benchmark/runtime invocations do
    # not create that FIFO and therefore must not manufacture an empty regular
    # file that Ginux mistakes for a live control channel.
    if test -p "$runtime_directory/control.in"; then
        exec 10<>"$runtime_directory/control.in"
    else
        exec 10>&-
    fi
    record_runtime "$runtime_directory" "$$"
    materialize_runtime_config \
        "$directory/config.toml" "$directory/deployment.state" "$directory/runtime.toml"
    if test "$audit_override" = true; then
        audit_candidate=$directory/runtime.toml.audit.$$
        "$runtime" config-merge "$directory/runtime.toml" 'audit.enabled=true' \
            >"$audit_candidate"
        mv "$audit_candidate" "$directory/runtime.toml"
    fi
    hook_plan=$($runtime hook-plan "$directory/runtime.toml") || exit 65
    hook_count=
    hook_timeout=
    hook_failure=
    hook_extra=
    IFS=' ' read -r hook_count hook_timeout hook_failure hook_extra <<EOF
$hook_plan
EOF
    case $hook_count:$hook_timeout in
        *[!0-9:]*|:*|*:)
            printf '%s\n' 'invalid pre-boot hook plan' >&2
            exit 65
            ;;
    esac
    case $hook_failure:$hook_extra in
        stop:|continue:) ;;
        *) printf '%s\n' 'invalid pre-boot hook plan' >&2; exit 65 ;;
    esac
    hook_index=0
    while test "$hook_index" -lt "$hook_count"; do
        printf 'GINUX_HOOK_AUDIT: action=dispatch index=%s timeout=%s failure=%s context=instance\n' \
            "$hook_index" "$hook_timeout" "$hook_failure" >>"$directory/audit.log"
        set +e
        timeout --signal=TERM --kill-after=2 "$hook_timeout" \
            "$runtime" native-hook "$directory/runtime.toml" "$directory/root" "$hook_index" \
            >>"$directory/audit.log" 2>&1
        hook_status=$?
        set -e
        if test "$hook_status" -eq 0; then
            printf 'GINUX_HOOK_AUDIT: action=complete index=%s result=pass\n' \
                "$hook_index" >>"$directory/audit.log"
        else
            if test "$hook_status" -eq 124 || test "$hook_status" -eq 137; then
                hook_result=timeout
            else
                hook_result=failed
            fi
            printf 'GINUX_HOOK_AUDIT: action=complete index=%s result=%s status=%s\n' \
                "$hook_index" "$hook_result" "$hook_status" >>"$directory/audit.log"
            if test "$hook_failure" = stop; then
                exit "$hook_status"
            fi
        fi
        hook_index=$((hook_index + 1))
    done
    # Only starts launched by supervise (which sets GINUX_LIFECYCLE_RESULT)
    # ask the runtime for an outcome record; direct invocations keep the plain
    # form even when an earlier lifecycle run left control.in behind.
    if test "$lifecycle_result" = 1; then
        rm -f "$runtime_directory/result.runtime"
        exec "$runtime" native "$directory/runtime.toml" "$directory/root" configured \
            --result-file "$runtime_directory/result.runtime" 2>>"$directory/audit.log"
    fi
    exec "$runtime" native "$directory/runtime.toml" "$directory/root" configured \
        2>>"$directory/audit.log"
}

attach_instance() {
    test "$#" -eq 1 || usage
    name=$1
    validate_name "$name"
    directory=$(instance_dir "$name")
    runtime_directory=$(runtime_dir "$name")
    test -d "$directory" || { printf '%s: not found\n' "$name" >&2; exit 66; }
    supervisor_pid=$(supervisor_identity "$name") || {
        printf '%s: not running\n' "$name" >&2
        exit 69
    }
    test -p "$runtime_directory/console.in" || {
        printf '%s: console is unavailable\n' "$name" >&2
        exit 69
    }
    test -p "$runtime_directory/control.in" || {
        printf '%s: control channel is unavailable\n' "$name" >&2
        exit 69
    }

    detach_marker=${TMPDIR:-/tmp}/ginux-$name-attach.$$.detach
    rm -f "$detach_marker"
    saved_tty=$(stty -g)
    exec 7<&0
    exec 8>"$runtime_directory/console.in"
    exec 9>"$runtime_directory/control.in"
    # A terminal-generated SIGINT belongs to the attached foreground process,
    # not to the controller-side attach transport. Background helpers inherit
    # SIGINT ignored; the attach process sends the same interrupt request over
    # Ginux's control channel if its terminal driver emits a signal instead.
    trap '' INT
    (
        trap '' INT TSTP
        exec tail -n 80 -F "$directory/console.log"
    ) &
    tail_pid=$!
    watcher_pid=
    sync_console_size() {
        size=$(stty size 2>/dev/null) || return 0
        rows=
        columns=
        extra=
        IFS=' ' read -r rows columns extra <<EOF
$size
EOF
        case "$rows:$columns:$extra" in
            *[!0-9:]*|0:*|*:0:*|*:*:?*) return 0 ;;
        esac
        if test "$root_options" = true; then
            # sudo resets the environment, so the roots travel as options.
            sudo -n "$0" --protocol 1 --state-root "$state_root" --run-root "$run_root" \
                resize "$name" "$rows" "$columns" </dev/null >/dev/null 2>&1 || true
        else
            sudo -n "$0" --protocol 1 resize "$name" "$rows" "$columns" </dev/null >/dev/null 2>&1 || true
        fi
    }
    cleanup_attach() {
        trap - 0 HUP INT TERM TSTP USR1 WINCH
        kill "$tail_pid" ${watcher_pid:+"$watcher_pid"} 2>/dev/null || true
        wait "$tail_pid" ${watcher_pid:+"$watcher_pid"} 2>/dev/null || true
        exec 8>&-
        exec 9>&-
        exec 7<&-
        stty "$saved_tty"
        rm -f "$detach_marker"
    }
    terminate_attach() {
        cleanup_attach
        exit 129
    }
    restore_raw_tty() {
        sync_console_size
        # sudo may restore the caller's terminal attributes after the bounded
        # resize operation. Reassert byte transport while retaining ISIG so
        # Ctrl-C and Ctrl-Z reach the forwarding traps below.
        stty raw -echo isig
    }
    trap cleanup_attach 0
    trap terminate_attach HUP TERM
    # The private transport owns terminal-generated signal forwarding after
    # the public CLI authorizes the console endpoints.
    trap 'printf I >&9 || true' INT
    trap 'printf S >&9 || true' TSTP
    instance_stopped=false
    trap 'instance_stopped=true' USR1
    trap restore_raw_tty WINCH
    restore_raw_tty
    attach_pid=$$
    (
        trap '' INT TSTP
        while supervisor_identity "$name" >/dev/null && test ! -e "$detach_marker"; do
            sleep 1 || true
        done
        test -e "$detach_marker" || kill -USR1 "$attach_pid" 2>/dev/null || true
    ) &
    watcher_pid=$!

    # Keep input ownership in the attach process itself. A background reader
    # can disappear after a terminal-generated signal or an interrupted read,
    # which leaves the console visible but makes Ctrl-] ineffective. The
    # watcher above terminates this loop if the instance exits.
    detach=$(printf '\035')
    interrupt=$(printf '\003')
    suspend=$(printf '\032')
    while test "$instance_stopped" = false && test ! -e "$detach_marker"; do
        character=
        IFS= read -r -n 1 character <&7 || continue
        if test "$character" = "$detach"; then
            : >"$detach_marker"
            break
        fi
        if test "$character" = "$interrupt"; then
            printf 'I' >&9
            continue
        fi
        if test "$character" = "$suspend"; then
            printf 'S' >&9
            continue
        fi
        if test -n "$character"; then
            printf '%s' "$character" >&8
        else
            printf '\n' >&8
        fi
    done
    detached=false
    test -e "$detach_marker" && detached=true
    cleanup_attach
    trap - 0 HUP INT TERM USR1
    if test "$detached" = true; then
        printf '\n%s: detached; instance remains running\n' "$name"
    else
        status=unknown
        test -r "$runtime_directory/exit.status" && status=$(cat "$runtime_directory/exit.status")
        printf '\n%s: stopped (status %s)\n' "$name" "$status"
    fi
}

authorize_attach() {
    test "$#" -eq 3 || usage
    name=$1
    attach_uid=$2
    attach_gid=$3
    validate_name "$name"
    case $attach_uid:$attach_gid in
        *[!0-9:]*|:*|*:) usage ;;
    esac
    directory=$(instance_dir "$name")
    runtime_directory=$(runtime_dir "$name")
    test -d "$directory" || { printf '%s: not found\n' "$name" >&2; exit 66; }
    supervisor_identity "$name" >/dev/null || {
        printf '%s: not running\n' "$name" >&2
        exit 69
    }
    for attach_endpoint in "$runtime_directory/console.in" "$runtime_directory/control.in"; do
        test -p "$attach_endpoint" || {
            printf '%s: console is unavailable\n' "$name" >&2
            exit 69
        }
        chown "$attach_uid:$attach_gid" "$attach_endpoint"
        chmod 600 "$attach_endpoint"
    done
    printf '%s\n' "$runtime_directory/control.in"
}

resize_instance() {
    test "$#" -eq 3 || usage
    name=$1
    rows=$2
    columns=$3
    validate_name "$name"
    case $rows:$columns in
        *[!0-9:]*|0:*|*:0|:*|*:) usage ;;
    esac
    attached_runtime=$(runtime_identity "$name" || true)
    test -n "$attached_runtime" || exit 69
    runtime_tty=$(readlink "/proc/$attached_runtime/fd/0" 2>/dev/null || true)
    case $runtime_tty in
        /dev/pts/[0-9]*) stty -F "$runtime_tty" rows "$rows" cols "$columns" ;;
        *) exit 69 ;;
    esac
}

stop_instance() {
    test "$#" -eq 1 || usage
    name=$1
    validate_name "$name"
    directory=$(instance_dir "$name")
    runtime_directory=$(runtime_dir "$name")
    test -d "$directory" || { printf '%s: not found\n' "$name" >&2; exit 66; }
    if ! pid=$(supervisor_identity "$name"); then
        rm -f "$runtime_directory/supervisor.pid"
        printf '%s: already stopped\n' "$name"
        return
    fi

    runtime_pid=$(runtime_identity "$name" || true)
    root_pid=
    if test -n "$runtime_pid"; then
        root_pid=$(pgrep -P "$runtime_pid" | sed -n '1p' || true)
    fi
    if test -n "$root_pid"; then
        kill -RTMIN+4 "$root_pid" 2>/dev/null || true
    fi
    attempt=0
    while kill -0 "$pid" 2>/dev/null && test "$attempt" -lt 60; do
        attempt=$((attempt + 1))
        sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        sleep 2
    fi
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
    fi
    # A killed supervisor cannot record the outcome itself.
    test -f "$runtime_directory/outcome" || write_outcome "$runtime_directory"
    rm -f "$runtime_directory/supervisor.pid" "$runtime_directory/runtime.pid"
    printf '%s: stopped\n' "$name"
}

delete_instance() {
    test "$#" -eq 1 || usage
    name=$1
    validate_name "$name"
    lock_instance "$name"
    directory=$(instance_dir "$name")
    runtime_directory=$(runtime_dir "$name")
    if test ! -e "$directory" && test ! -L "$directory"; then
        drop_instance_lock
        printf '%s: not found\n' "$name" >&2
        exit 66
    fi
    if supervisor_identity "$name" >/dev/null || runtime_identity "$name" >/dev/null; then
        printf '%s: stop the instance before deleting it\n' "$name" >&2
        exit 73
    fi
    # One rename inside the instances directory removes the instance
    # atomically; list ignores dot names, and the trash is root-only.
    delete_trash=$(mktemp -d "$state_root/instances/.delete:XXXXXX")
    # Same-filesystem rename onto the fresh, empty trash directory.
    mv -T -- "$directory" "$delete_trash/instance"
    rm -rf -- "$runtime_directory"
    drop_instance_lock
    printf 'Instance "%s" deleted.\n' "$name"
    # A trash directory that is gone afterwards was swept by a concurrent
    # delete (the sweep below goes by the rename time), which is success.
    if ! rm -rf --one-file-system -- "$delete_trash" \
        && test -e "$delete_trash"; then
        printf '%s: removal incomplete; %s remains\n' "$name" "$delete_trash" >&2
        exit 70
    fi
    # Sweep trash left by interrupted deletes; a directory that vanishes
    # meanwhile is not an error.
    find "$state_root/instances" -mindepth 1 -maxdepth 1 -name '.delete:*' -mmin +60 \
        -exec rm -rf --one-file-system -- {} + 2>/dev/null || true
}

extract_instance() {
    test "$#" -ge 8 || usage
    name=$1
    test "$2" = --max-bytes && test "$4" = --max-members && test "$6" = --max-path || usage
    extract_max_bytes=$3
    extract_max_members=$5
    extract_max_path=$7
    for extract_bound in "$extract_max_bytes" "$extract_max_members" "$extract_max_path"; do
        case $extract_bound in
            ''|0*|*[!0-9]*) usage ;;
        esac
    done
    shift 7
    for extract_path in "$@"; do
        case $extract_path in
            /*) ;;
            *) usage ;;
        esac
    done
    validate_name "$name"
    lock_instance "$name"
    directory=$(instance_dir "$name")
    test -d "$directory" || {
        drop_instance_lock
        printf '%s: not found\n' "$name" >&2
        exit 66
    }
    if supervisor_identity "$name" >/dev/null || runtime_identity "$name" >/dev/null; then
        printf '%s: stop the instance before extracting from it\n' "$name" >&2
        exit 73
    fi
    if test ! -x "$image_tool" || test -d "$image_tool"; then
        printf '%s\n' 'extract requires the compiled Ginux image tool' >&2
        exit 69
    fi
    # The lock stays held here (not in the exporter) for the whole export so
    # start, delete and import wait for it. It has no timeout: a stalled
    # exporter (any process that can signal uid 65534 can stop it) holds the
    # lock, and start, delete and create of this instance wait until the
    # exporter continues or is killed.
    set +e
    "$image_tool" export-tree "$directory/root" \
        "$extract_max_bytes" "$extract_max_members" "$extract_max_path" "$@" 6>&-
    extract_status=$?
    set -e
    exit "$extract_status"
}

inject_instance() {
    test "$#" -eq 8 || usage
    name=$1
    test "$2" = --max-bytes && test "$4" = --max-members && test "$6" = --max-path || usage
    inject_max_bytes=$3
    inject_max_members=$5
    inject_max_path=$7
    inject_path=$8
    for inject_bound in "$inject_max_bytes" "$inject_max_members" "$inject_max_path"; do
        case $inject_bound in
            ''|0*|*[!0-9]*) usage ;;
        esac
    done
    case $inject_path in
        /*) ;;
        *) usage ;;
    esac
    validate_name "$name"
    lock_instance "$name"
    directory=$(instance_dir "$name")
    test -d "$directory" || {
        drop_instance_lock
        printf '%s: not found\n' "$name" >&2
        exit 66
    }
    if supervisor_identity "$name" >/dev/null || runtime_identity "$name" >/dev/null; then
        printf '%s: stop the instance before injecting into it\n' "$name" >&2
        exit 73
    fi
    if test ! -x "$image_tool" || test -d "$image_tool"; then
        printf '%s\n' 'inject requires the compiled Ginux image tool' >&2
        exit 69
    fi
    # The injector replaces this shell and inherits the lock (descriptor 6 is
    # not close-on-exec), so the lock lives exactly as long as the injector:
    # if this shell is killed first, the injector still holds it and start,
    # delete and import keep waiting instead of racing its writes. It has no
    # timeout: a stalled injector (any process that can signal uid 65534 can
    # stop it) holds the lock, and start, delete and create of this instance
    # wait until the injector continues or is killed. The injector's exit
    # status is the helper's. Nothing runs after it, and this function sets no
    # trap, so there is no cleanup to keep.
    # Injection is not atomic: a failure can leave part of the archive in the
    # instance root, so the caller discards the instance after a failure.
    exec "$image_tool" inject-tree "$directory/root" \
        "$inject_max_bytes" "$inject_max_members" "$inject_max_path" "$inject_path"
}

import_image() {
    test "$#" -eq 0 || usage
    if test ! -x "$image_tool" || test -d "$image_tool"; then
        printf '%s\n' 'import-image requires the compiled Ginux image tool' >&2
        exit 69
    fi
    mkdir -p "$state_root/cache/oci/blobs/sha256"
    exec "$image_tool" import-layout "$state_root/cache/oci"
}

test "${1-}" = --protocol || usage
test "${2-}" = 1 || {
    printf 'unsupported helper protocol: %s\n' "${2-}" >&2
    exit 64
}
test "$#" -ge 3 || usage
shift 2
root_options=false
if test "$1" = --state-root; then
    test "$#" -ge 3 || usage
    requested_state_root=$2
    requested_run_root=$2/run
    shift 2
    if test "$1" = --run-root; then
        test "$#" -ge 3 || usage
        requested_run_root=$2
        shift 2
    fi
    root_options=true
fi
command=$1
shift
if test "$root_options" = true; then
    # Reject an unknown verb before creating anything.
    case $command in
        attach|authorize-attach|create|delete|export|extract|import|import-image|inject|list|lock|\
        prepare-root|resolve-network|resize|set|start|status|stop|unlock|run-runtime|supervise) ;;
        *) usage ;;
    esac
    # attach runs unprivileged: it checks the roots but never creates them.
    root_create=true
    test "$command" != attach || root_create=false
    trusted_root state "$requested_state_root" "$root_create"
    trusted_root run "$requested_run_root" "$root_create"
    state_root=$requested_state_root
    run_root=$requested_run_root
    if test "$root_create" = true; then
        install -d -m 0755 "$state_root/instances" "$state_root/cache" \
            "$state_root/cache/oci" "$state_root/cache/oci/blobs" \
            "$state_root/cache/oci/blobs/sha256" "$run_root/instances"
        install -d -m 0700 "$state_root/work"
    fi
    # The supervise and run-runtime self-invocations inherit the roots.
    export GINUX_STATE_ROOT="$state_root" GINUX_RUN_ROOT="$run_root"
fi
mkdir -p "$state_root/instances"
case $command in
    attach) attach_instance "$@" ;;
    authorize-attach) authorize_attach "$@" ;;
    create) create_instance "$@" ;;
    delete) delete_instance "$@" ;;
    export) export_instance "$@" ;;
    extract) extract_instance "$@" ;;
    import) import_instance "$@" ;;
    import-image) import_image "$@" ;;
    inject) inject_instance "$@" ;;
    list) test "$#" -eq 0 || usage; list_instances ;;
    lock) test "$#" -eq 1 || usage; set_contract_lock "$1" locked ;;
    prepare-root) test "$#" -eq 1 || usage; prepare_root "$1" ;;
    resolve-network) test "$#" -eq 1 || usage; resolve_network_config "$1" ;;
    resize) resize_instance "$@" ;;
    set) set_instance "$@" ;;
    start) start_instance "$@" ;;
    status) status_instance "$@" ;;
    stop) stop_instance "$@" ;;
    unlock) test "$#" -eq 1 || usage; set_contract_lock "$1" unlocked ;;
    run-runtime) run_runtime "$@" ;;
    supervise) supervise_instance "$@" ;;
    *) usage ;;
esac
