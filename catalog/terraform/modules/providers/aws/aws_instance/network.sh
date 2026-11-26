#!/bin/sh
# Exact read-only VPC, membership and listener policy collection.
set -eu
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/opsctl-aws-network.XXXXXXXX")
transport_pid=
cleanup() {
    if [ -n "$transport_pid" ]; then
        exec 3>&- 4<&-
        kill "$transport_pid" 2>/dev/null || true
        wait "$transport_pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
trap '' PIPE
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
deadline=$(( $(date +%s) + 24 ))
region=${AWS_DEFAULT_REGION:-}
for file in payload domain instance group interfaces rules selection; do printf '{}\n' > "$work/$file"; done
printf '[]\n' > "$work/missing"
: > "$work/members"
head -c 32769 > "$work/request"

. "$root/aws_transport.sh"

q() {
    mode=$1
    shift
    jq -L "$root" -n "$@" --arg mode "$mode" --arg region "$region" --arg account "${account:-}" \
        --slurpfile request "$work/request" \
        --slurpfile payload "$work/payload" --slurpfile domain "$work/domain" \
        --slurpfile instance "$work/instance" --slurpfile group "$work/group" \
        --slurpfile interfaces "$work/interfaces" --slurpfile rules "$work/rules" \
        --slurpfile selection "$work/selection" --slurpfile members "$work/members" -f "$root/network.jq"
}

finish() {
    jq -n --arg state "$1" --arg reason "$2" --arg start "$started" \
        --arg end "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --slurpfile request "$work/request" \
        --slurpfile domain "$work/domain" --slurpfile members "$work/members" --slurpfile missing "$work/missing" '
        ($request[0] // {}) as $r | {format_version:1, action:$r.action, network_id:$r.network_id,
         collection_started_at:$start, collection_completed_at:$end, status:$state,
         reason:(if $reason == "" then null else $reason end),
         profile:(if $state == "complete" then "aws/existing-vpc" else null end),
         region:(if $state == "complete" then $domain[0].region else null end),
         ipv4_cidr:(if $state == "complete" then $domain[0].ipv4_cidr else null end),
         members:(if $state == "complete" then $members | map({id,host,access_fingerprint}) else [] end),
         missing_listeners:(if $state == "complete" then $missing[0] else [] end)}'
    [ "$1" = complete ] && exit 0
    exit 1
}

read_network() {
    unavailable_reason=$1
    destination=$2
    shift 2
    if printf '%s\n' "$*" >&3 2> "$work/error" && IFS= read -r read_status <&4; then
        if [ "$read_status" = 0 ] && IFS= read -r response <&4 &&
            printf '%s\n' "$response" > "$work/$destination" &&
            [ "$(wc -c < "$work/$destination")" -le 262144 ] && closed_json "$work/$destination"; then
            return 0
        fi
    else
        read_status=1
    fi
    if [ "$read_status" = 124 ] || [ "$(date +%s)" -ge "$deadline" ]; then
        finish unknown collection_timeout
    fi
    finish unknown "$unavailable_reason"
}

if [ "$(wc -c < "$work/request")" -gt 32768 ] || ! closed_json "$work/request"; then
    printf '{}\n' > "$work/request"
    finish rejected request_invalid
fi
q request > /dev/null 2> "$work/error" || finish rejected request_invalid
has_credentials || finish unknown credentials_unavailable
mkfifo "$work/requests" "$work/replies" || finish unknown identity_unavailable
python3 "$root/network_transport.py" "$region" "$deadline" < "$work/requests" > "$work/replies" 2> "$work/error" &
transport_pid=$!
exec 3> "$work/requests" 4< "$work/replies"
read_network identity_unavailable payload identity
account=$(q identity -re 2> "$work/error") || finish unknown identity_unqualified
network=$(jq -r .network_id "$work/request")
read_network domain_unavailable payload vpc "$network"
q domain > "$work/qualified" 2> "$work/error" || finish unknown domain_unqualified
mv "$work/qualified" "$work/domain"

if [ "$(jq -r .action "$work/request")" = domain ]; then
    finish complete ''
fi

# IDs were validated by request/member_selection before forming native filters.
member_ids=$(jq -er '.members[]' "$work/request") || finish unknown member_unqualified
set -- $member_ids
read_network member_unavailable instance instances "$@"
q instances > "$work/members.selected" 2> "$work/error" || finish unknown member_unqualified
mv "$work/members.selected" "$work/selection"
group_ids=$(jq -er '.[].firewall' "$work/selection") || finish unknown member_unqualified
set -- $group_ids
read_network policy_unavailable group groups "$@"
read_network policy_unavailable interfaces interfaces "$@"
read_network policy_unavailable rules rules "$@"
q members -c > "$work/members.qualified" 2> "$work/error" || finish unknown member_unqualified
while IFS= read -r member; do
    printf '%s\n' "$member" > "$work/member"
    jq -cS 'del(.id,.host)' "$work/member" > "$work/preimage" || finish unknown member_unqualified
    digest=$(sha256sum < "$work/preimage") || finish unknown member_unqualified
    jq -c --arg digest "${digest%% *}" '. + {access_fingerprint:$digest}' "$work/member" >> "$work/members"
done < "$work/members.qualified"
q listeners > "$work/missing" 2> "$work/error" || finish unknown listener_unqualified
finish complete ''
