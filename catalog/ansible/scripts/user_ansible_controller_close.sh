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
[ "$#" -eq 3 ] || exit 64
record=$1
operation=$2
cause=$3
case "$cause" in normal|deadline) ;; *) exit 64 ;; esac
case "$operation" in
    *[!0-9a-f-]*|'') exit 64 ;;
esac
[ -d "$record" ] && [ ! -L "$record" ] || exit 65
[ "$(stat -c '%u:%a' "$record")" = 0:700 ] || exit 65
[ ! -L "$record/lock" ] || exit 65
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

observe() {
    if observed=$(timeout -k 2 10 docker --host unix:///var/run/docker.sock container inspect \
        --format '{{.Id}} {{index .Config.Labels "opsctl.operation"}} {{index .Config.Labels "opsctl.source_digest"}} {{index .Config.Labels "opsctl.input_digest"}} {{.State.Running}} {{.State.Pid}}' \
        "$container" 2>/dev/null); then
        printf '%s\n' "$observed"
        return
    fi
    listed=$(timeout -k 2 10 docker --host unix:///var/run/docker.sock container ls \
        --all --no-trunc --filter "id=$container" --format '{{.ID}}' 2>/dev/null) || return 70
    [ -z "$listed" ] || return 70
    printf 'absent\n'
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
    set -- $facts
    [ "$#" -eq 6 ] && [ "$1" = "$container" ] && [ "$2" = "$operation" ] &&
        [ "$3" = "$source_digest" ] && [ "$4" = "$input_digest" ] || exit 65
fi
if [ "$facts" != absent ] && { [ "$5" = true ] || [ "$6" != 0 ]; }; then
    if [ "$decision" != deadline ]; then decision=$cause; fi
    umask 077
    printf '%s\n' "$decision" >"$record/close-decision.pending"
    mv "$record/close-decision.pending" "$record/close-decision"
    timeout -k 2 15 docker --host unix:///var/run/docker.sock container stop --time 5 "$container" >/dev/null 2>&1 || true
    facts=$(observe) || exit 70
    if [ "$facts" != absent ]; then
        set -- $facts
        [ "$#" -eq 6 ] && [ "$1" = "$container" ] && [ "$2" = "$operation" ] &&
            [ "$3" = "$source_digest" ] && [ "$4" = "$input_digest" ] || exit 65
        if [ "$5" = true ] || [ "$6" != 0 ]; then
            timeout -k 2 10 docker --host unix:///var/run/docker.sock container kill "$container" >/dev/null 2>&1 || exit 70
        fi
    fi
fi
facts=$(observe) || exit 70
presence=absent
if [ "$facts" != absent ]; then
    set -- $facts
    [ "$#" -eq 6 ] && [ "$1" = "$container" ] && [ "$2" = "$operation" ] &&
        [ "$3" = "$source_digest" ] && [ "$4" = "$input_digest" ] || exit 65
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
