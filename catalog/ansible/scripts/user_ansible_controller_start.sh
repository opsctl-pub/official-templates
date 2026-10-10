#!/bin/sh
set -eu

# This root-owned helper runs as the payload UID, before any user interpreter.
PATH=/usr/bin:/bin
export PATH
unset ENV BASH_ENV CDPATH

[ "$#" -eq 6 ] || [ "$#" -eq 7 ] || exit 64
gate=$1
shift
[ "$gate" = /run/opsctl-gate ] || exit 64
case "$1" in
    /bin/bash)
        [ "$#" -eq 5 ] || exit 64
        [ "$2" = --noprofile ] && [ "$3" = --norc ] || exit 64
        [ "$5" = /run/opsctl-keys/inputs.json ] || exit 64
        prefix=/workspace/user/ ;;
    /usr/bin/ansible-playbook)
        [ "$#" -eq 6 ] || exit 64
        [ "$2" = --inventory ] || exit 64
        [ "$3" = /run/opsctl-keys/inventory.json ] || exit 64
        [ "$5" = --extra-vars ] || exit 64
        [ "$6" = @/run/opsctl-keys/inputs.json ] || exit 64
        prefix=/source/ ;;
    *) exit 64 ;;
esac
case "$4" in "$prefix"*) member=${4#"$prefix"} ;; *) exit 64 ;; esac
[ -n "$member" ] && [ "${#member}" -le 256 ] || exit 64
case "$member" in
    /*|*//*|.|..|./*|../*|*/.|*/..|*/./*|*/../*|*\\*|*:*) exit 64 ;;
esac
if printf '%s' "$member" | LC_ALL=C grep -q '[[:cntrl:]]'; then exit 64; fi
[ -d "$gate" ] && [ ! -L "$gate" ] || exit 65
[ "$(stat -c '%u:%a' "$gate")" = 0:755 ] || exit 65

while [ ! -f "$gate/release" ]; do
    [ ! -e "$gate/closed" ] || exit 75
    sleep 1
done
[ ! -e "$gate/closed" ] || exit 75
[ ! -L "$gate/release" ] || exit 65
[ "$(stat -c '%u:%a' "$gate/release")" = 0:444 ] || exit 65
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
exec "$@"
