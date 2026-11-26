#!/bin/sh
# Exact read-only VPC, membership and listener policy collection.
set -eu
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/opsctl-aws-network.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 130' HUP INT TERM
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
deadline=$(( $(date +%s) + 24 ))
region=${AWS_DEFAULT_REGION:-}
for file in payload domain instance group interfaces rules; do printf '{}\n' > "$work/$file"; done
printf '[]\n' > "$work/missing"
: > "$work/members"
head -c 32769 > "$work/request"

. "$root/aws_transport.sh"

q() {
    mode=$1
    shift
    jq -L "$root" -n "$@" --arg mode "$mode" --arg region "$region" --arg account "${account:-}" \
        --arg id "${id:-}" --arg firewall "${firewall:-}" --slurpfile request "$work/request" \
        --slurpfile payload "$work/payload" --slurpfile domain "$work/domain" \
        --slurpfile instance "$work/instance" --slurpfile group "$work/group" \
        --slurpfile interfaces "$work/interfaces" --slurpfile rules "$work/rules" \
        --slurpfile members "$work/members" -f "$root/network.jq"
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
    shift
    if read_native "$@"; then
        return 0
    else
        read_status=$?
    fi
    if [ "$read_status" -eq 124 ] || [ "$(date +%s)" -ge "$deadline" ]; then
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
read_network identity_unavailable payload sts get-caller-identity
account=$(q identity -re 2> "$work/error") || finish unknown identity_unqualified
network=$(jq -r .network_id "$work/request")
read_network domain_unavailable payload ec2 describe-vpcs --vpc-ids "$network"
q domain > "$work/qualified" 2> "$work/error" || finish unknown domain_unqualified
mv "$work/qualified" "$work/domain"

jq -r '.members[]' "$work/request" > "$work/ids"
while IFS= read -r id; do
    read_network member_unavailable instance ec2 describe-instances --instance-ids "$id"
    firewall=$(q group -re 2> "$work/error") || finish unknown member_unqualified
    read_network policy_unavailable group ec2 describe-security-groups --group-ids "$firewall"
    read_network policy_unavailable interfaces ec2 describe-network-interfaces --filters "Name=group-id,Values=$firewall"
    read_network policy_unavailable rules ec2 describe-security-group-rules --filters "Name=group-id,Values=$firewall"
    q member > "$work/member" 2> "$work/error" || finish unknown member_unqualified
    jq -cS 'del(.id,.host)' "$work/member" > "$work/preimage" || finish unknown member_unqualified
    digest=$(sha256sum < "$work/preimage") || finish unknown member_unqualified
    jq -c --arg digest "${digest%% *}" '. + {access_fingerprint:$digest}' "$work/member" >> "$work/members"
done < "$work/ids"
q listeners > "$work/missing" 2> "$work/error" || finish unknown listener_unqualified
finish complete ''
