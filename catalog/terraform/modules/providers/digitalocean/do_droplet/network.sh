#!/bin/sh
# Exact read-only VPC/member/listener collection; one overall deadline, no retries.
set -eu
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/opsctl-do-network.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 130' HUP INT TERM
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
deadline=$(( $(date +%s) + 15 ))
printf '{}\n' > "$work/domain"
printf '[]\n' > "$work/missing"
: > "$work/members"
head -c 32769 > "$work/request"
closed_json() {
    # Stream paths retain duplicate members which ordinary jq object parsing loses.
    jq --stream -ne '
        reduce inputs as $event ({seen:{},active:[],roots:0};
          $event[0] as $path
          | if ($path | length) > 32 then error("depth")
            elif ($event | length) == 2 then
              if ($event[1] | type) == "number" and ($event[1] | isinfinite) then error("finite") else . end
              | if $path == [] then .roots += 1 else
                  reduce range($path | length) as $i (.;
                    $path[:$i+1] as $prefix | ($prefix | tojson) as $key
                    | if any(.active[]; . == $prefix) then .
                      elif .seen[$key] then error("duplicate")
                      else .seen[$key] = true
                        | if $i < ($path | length)-1 then .active += [$prefix] else . end end)
                end
            else .active |= map(select(length < ($path | length)-1))
              | if ($path | length) == 1 then .roots += 1 else . end end)
        | .roots == 1' "$1" > /dev/null 2> "$work/error"
}

q() {
    mode=$1
    jq -n --arg mode "$mode" --arg id "${id:-}" --slurpfile request "$work/request" \
        --slurpfile payload "$work/payload" --slurpfile domain "$work/domain" \
        --slurpfile members "$work/members" -f "$root/network.jq"
}
finish() {
    state=$1 reason=$2
    jq -n --arg state "$state" --arg reason "$reason" --arg start "$started" \
        --arg end "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --slurpfile request "$work/request" \
        --slurpfile domain "$work/domain" --slurpfile members "$work/members" --slurpfile missing "$work/missing" '
        ($request[0] // {}) as $r | {format_version:1,action:$r.action,network_id:$r.network_id,
         collection_started_at:$start,collection_completed_at:$end,status:$state,
         reason:(if $reason == "" then null else $reason end),
         profile:(if $state == "complete" then "digitalocean/existing-vpc" else null end),
         region:(if $state == "complete" then $domain[0].region else null end),
         ipv4_cidr:(if $state == "complete" then $domain[0].ipv4_cidr else null end),
         members:(if $state == "complete" then $members | map(del(.policy)) else [] end),
         missing_listeners:(if $state == "complete" then $missing[0] else [] end)}'
    [ "$state" = complete ] && exit 0
    exit 1
}
printf '{}\n' > "$work/payload"
if [ "$(wc -c < "$work/request")" -gt 32768 ] || ! closed_json "$work/request" || ! q request > /dev/null 2> "$work/error"; then
    printf '{}\n' > "$work/request"
    finish rejected request_invalid
fi
if [ -z "${DIGITALOCEAN_TOKEN:-}" ] || ! printf '%s' "$DIGITALOCEAN_TOKEN" | jq -Rse \
    'length > 0 and length <= 4096 and (explode | all(.[]; . >= 33 and . <= 126))' > /dev/null; then
    finish unknown credentials_unavailable
fi
printf 'Authorization: Bearer %s\n' "$DIGITALOCEAN_TOKEN" > "$work/authorization"
unset DIGITALOCEAN_TOKEN
read_exact() {
    remaining=$(( deadline - $(date +%s) ))
    [ "$remaining" -gt 0 ] || return 1
    curl --disable --silent --proto '=https' --max-redirs 0 --retry 0 \
        --connect-timeout 5 --max-time "$remaining" --max-filesize 1048576 \
        --header "@$work/authorization" --header 'Accept: application/json' \
        --output "$work/payload" --write-out '%{http_code}' \
        "https://api.digitalocean.com/v2/$1" > "$work/status" 2> "$work/error" || return 1
    [ "$(cat "$work/status")" = 200 ] && closed_json "$work/payload"
}
network=$(jq -r .network_id "$work/request")
read_exact "vpcs/$network" || finish unknown domain_unavailable
q domain > "$work/qualified" 2> "$work/error" || finish unknown domain_unqualified
mv "$work/qualified" "$work/domain"
action=$(jq -r .action "$work/request")
jq -r '.members[]' "$work/request" > "$work/ids"
while IFS= read -r id; do
    read_exact "droplets/$id" || finish unknown member_unavailable
    q member > "$work/member" 2> "$work/error" || finish unknown member_unqualified
    if [ "$action" = creation ]; then
        policy='[]'
    else
        read_exact "droplets/$id/firewalls?per_page=100" || finish unknown policy_unavailable
        q policy > "$work/canonical" 2> "$work/error" || finish unknown policy_unqualified
        policy=$(jq -r . "$work/canonical")
    fi
    printf '%s' "$policy" > "$work/policy"
    digest=$(printf '%s' "$policy" | sha256sum)
    digest=${digest%% *}
    jq -c --arg digest "$digest" --slurpfile policy "$work/policy" \
        '. + {access_fingerprint:$digest,policy:$policy[0]}' "$work/member" >> "$work/members"
done < "$work/ids"
q listeners > "$work/qualified" 2> "$work/error" || finish unknown listener_unqualified
mv "$work/qualified" "$work/missing"
finish complete ''
