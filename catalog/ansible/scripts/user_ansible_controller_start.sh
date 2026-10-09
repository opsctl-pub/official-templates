#!/bin/sh
set -eu

# This root-owned helper runs as the payload UID, before any user interpreter.
PATH=/usr/bin:/bin
export PATH
unset ENV BASH_ENV CDPATH

[ "$#" -eq 7 ] || exit 64
gate=$1
shift
[ "$gate" = /run/opsctl-gate ] || exit 64
[ "$1" = /usr/bin/ansible-playbook ] || exit 64
[ "$2" = --inventory ] || exit 64
[ "$3" = /run/opsctl-keys/inventory.json ] || exit 64
case "$4" in /source/*) ;; *) exit 64 ;; esac
[ "$5" = --extra-vars ] || exit 64
[ "$6" = @/run/opsctl-keys/inputs.json ] || exit 64
[ -d "$gate" ] && [ ! -L "$gate" ] || exit 65
[ "$(stat -c '%u:%a' "$gate")" = 0:755 ] || exit 65

while [ ! -f "$gate/release" ]; do
    [ ! -e "$gate/closed" ] || exit 75
    sleep 1
done
[ ! -L "$gate/release" ] || exit 65
[ "$(stat -c '%u:%a' "$gate/release")" = 0:444 ] || exit 65
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
exec "$@"
