#!/bin/sh
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION

if [ "${1:-}" != --bounded ]; then
    exec timeout -k 2 90 /bin/sh "$0" --bounded "$@"
fi
shift
[ "$#" -eq 3 ] || [ "$#" -eq 4 ] || exit 64
record=$1
operation=$2
cause=$3
fence=${4:-}
case "$cause" in normal|deadline) ;; *) exit 64 ;; esac
case "$fence" in ''|terminal-bash-gate) ;; *) exit 64 ;; esac
[ -z "$fence" ] || [ "$cause" = normal ] || exit 64
case "$operation" in
    *[!0-9a-f-]*|'') exit 64 ;;
esac
[ -d "$record" ] && [ ! -L "$record" ] || exit 65
[ "$(stat -c '%u:%a' "$record")" = 0:700 ] || exit 65
[ ! -L "$record/lock" ] || exit 65
if [ -e "$record/lock" ]; then
    [ -f "$record/lock" ] && [ "$(stat -c '%u:%a' "$record/lock")" = 0:600 ] || exit 65
fi
exec 8>"$record/lock"
flock -x -w 35 8 || exit 75
[ -f "$record/container-id" ] && [ ! -L "$record/container-id" ] || exit 65
[ "$(stat -c '%u:%a' "$record/container-id")" = 0:600 ] || exit 65
IFS= read -r container <"$record/container-id"
[ "${#container}" -eq 64 ] || exit 65
case "$container" in *[!0-9a-f]*) exit 65 ;; esac
for identity in source-digest input-digest; do
    [ -f "$record/$identity" ] && [ ! -L "$record/$identity" ] || exit 65
    [ "$(stat -c '%u:%a' "$record/$identity")" = 0:600 ] || exit 65
done
IFS= read -r source_digest <"$record/source-digest"
IFS= read -r input_digest <"$record/input-digest"
[ "${#source_digest}" -eq 64 ] && [ "${#input_digest}" -eq 64 ] || exit 65
case "$source_digest$input_digest" in *[!0-9a-f]*) exit 65 ;; esac

if [ -n "$fence" ]; then
    [ "$(stat -c '%d:%i' "$record")" = "$FENCE_RECORD_DEVICE:$FENCE_RECORD_INODE" ] || exit 65
    [ -f "$record/journal.json" ] && [ ! -L "$record/journal.json" ] || exit 65
    [ "$(stat -c '%u:%a' "$record/journal.json")" = 0:600 ] || exit 65
    actual=$(sha256sum "$record/journal.json")
    [ "${actual%% *}" = "$FENCE_JOURNAL_DIGEST" ] || exit 65
    [ -d "$record/gate" ] && [ ! -L "$record/gate" ] || exit 65
    [ "$(stat -c '%u:%a:%d:%i' "$record/gate")" = "0:755:$FENCE_GATE_DEVICE:$FENCE_GATE_INODE" ] || exit 65
fi

observe() {
    format='{{.Id}} {{index .Config.Labels "opsctl.operation"}} {{index .Config.Labels "opsctl.source_digest"}} {{index .Config.Labels "opsctl.input_digest"}} {{.State.Running}} {{.State.Pid}}'
    if [ -n "$fence" ]; then
        format="$format {{index .Config.Labels \"opsctl.payload_engine\"}} {{.HostConfig.NetworkMode}}"
    fi
    if observed=$(timeout -k 2 10 docker --host unix:///var/run/docker.sock container inspect \
        --format "$format" \
        "$container" 2>/dev/null); then
        printf '%s\n' "$observed"
        return
    fi
    listed=$(timeout -k 2 10 docker --host unix:///var/run/docker.sock container ls \
        --all --no-trunc --filter "id=$container" --format '{{.ID}}' 2>/dev/null) || return 70
    [ -z "$listed" ] || return 70
    printf 'absent\n'
}

qualify() {
    set -- $1
    [ "$#" -eq 6 ] || { [ -n "$fence" ] && [ "$#" -eq 8 ]; } || return 65
    [ "$1" = "$container" ] && [ "$2" = "$operation" ] &&
        [ "$3" = "$source_digest" ] && [ "$4" = "$input_digest" ] || return 65
    [ "$5" = true ] || [ "$5" = false ] || return 65
    case "$6" in ''|*[!0-9]*) return 65 ;; esac
    if [ -n "$fence" ]; then
        [ "$#" -eq 8 ] && [ "$7" = bash ] && [ "$8" = none ] || return 65
    fi
}

facts=$(observe) || exit 70
decision=exited
if [ -e "$record/close-decision" ]; then
    [ -f "$record/close-decision" ] && [ ! -L "$record/close-decision" ] || exit 65
    [ "$(stat -c '%u:%a' "$record/close-decision")" = 0:600 ] || exit 65
    IFS= read -r decision <"$record/close-decision"
    case "$decision" in normal|deadline|exited|absent) ;; *) exit 65 ;; esac
fi
if [ "$facts" != absent ]; then
    qualify "$facts" || exit 65
    set -- $facts
fi
if [ -n "$fence" ]; then
    for marker in "$record/closed" "$record/close-decision.pending" "$record/gate/closed" "$record/gate/release" "$record/gate/release.pending"; do
        [ ! -L "$marker" ] || exit 65
        if [ -e "$marker" ]; then
            [ -f "$marker" ] && [ "$(stat -c '%u' "$marker")" = 0 ] || exit 65
            case "$marker" in
                "$record/closed"|"$record/close-decision.pending") [ "$(stat -c '%a' "$marker")" = 600 ] || exit 65 ;;
                "$record/gate/closed"|"$record/gate/release") [ "$(stat -c '%a' "$marker")" = 444 ] || exit 65 ;;
                "$record/gate/release.pending") case "$(stat -c '%a' "$marker")" in 600|444) ;; *) exit 65 ;; esac ;;
            esac
        fi
    done
    if [ ! -e "$record/closed" ]; then (set -C; : >"$record/closed"); fi
    if [ ! -e "$record/gate/closed" ]; then
        (set -C; : >"$record/gate/closed")
        chmod 0444 "$record/gate/closed"
    fi
fi
if [ "$facts" != absent ] && { [ "$5" = true ] || [ "$6" != 0 ]; }; then
    if [ "$decision" != deadline ]; then decision=$cause; fi
    umask 077
    printf '%s\n' "$decision" >"$record/close-decision.pending"
    mv "$record/close-decision.pending" "$record/close-decision"
    timeout -k 2 15 docker --host unix:///var/run/docker.sock container stop --time 5 "$container" >/dev/null 2>&1 || true
    facts=$(observe) || exit 70
    if [ "$facts" != absent ]; then
        qualify "$facts" || exit 65
        set -- $facts
        if [ "$5" = true ] || [ "$6" != 0 ]; then
            timeout -k 2 10 docker --host unix:///var/run/docker.sock container kill "$container" >/dev/null 2>&1 || exit 70
        fi
    fi
fi
facts=$(observe) || exit 70
presence=absent
if [ "$facts" != absent ]; then
    qualify "$facts" || exit 65
    set -- $facts
    [ "$5" = false ] && [ "$6" = 0 ] || exit 70
    presence=stopped
elif [ ! -e "$record/close-decision" ]; then
    decision=absent
fi
umask 077
printf '%s\n' "$decision" >"$record/close-decision.pending"
mv "$record/close-decision.pending" "$record/close-decision"
: >"$record/closed"
printf 'process_closed:%s:%s\n' "$decision" "$presence"
