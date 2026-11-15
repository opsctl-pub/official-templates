#!/bin/sh
# One exact firewall procedure. Credentials never appear in argv or public output.
set -eu
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/opsctl-do-ingress.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 130' HUP INT TERM
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
deadline=$(( $(date +%s) + 60 ))
digest= fingerprint= observed=
for name in projection firewall page observation; do printf '{}\n' > "$work/$name"; done
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
    shift
    jq -n --arg mode "$mode" --arg digest "$digest" --arg fingerprint "$fingerprint" \
        --arg observed "$observed" --slurpfile request "$work/request" \
        --slurpfile projection "$work/projection" --slurpfile firewall "$work/firewall" \
        --slurpfile page "$work/page" --slurpfile observation "$work/observation" \
        -f "$root/ingress.jq" "$@"
}
finish() {
    status=$1 reason=$2
    completed=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    jq -n --slurpfile request "$work/request" --slurpfile observation "$work/observation" \
        --arg status "$status" --arg reason "$reason" --arg started "$started" --arg completed "$completed" '
        ($request[0] // {}) as $r |
        {format_version:1, action:$r.action, provider_instance_id:$r.provider_instance_id,
         firewall_id:$r.firewall_id, collection_started_at:$started, collection_completed_at:$completed,
         status:$status, reason:(if $reason == "" then null else $reason end),
         observation:(if $status == "complete" and $r.action != "creation" then $observation[0] else null end)}'
    [ "$status" = complete ] && exit 0
    exit 1
}
if [ "$(wc -c < "$work/request")" -gt 32768 ] || ! closed_json "$work/request" || ! q request -e > /dev/null 2> "$work/error"; then
    jq -c 'def identity: if type == "string" and length <= 255 then . else null end;
        {action:(.action | identity), provider_instance_id:(.provider_instance_id | identity),
         firewall_id:(.firewall_id | identity)}' "$work/request" > "$work/safe-request" 2> "$work/error" \
        || printf '{}\n' > "$work/safe-request"
    mv "$work/safe-request" "$work/request"
    finish rejected request_invalid
fi
instance=$(jq -r .provider_instance_id "$work/request")
firewall=$(jq -r .firewall_id "$work/request")
action=$(jq -r .action "$work/request")
if [ "$action" = creation ]; then deadline=$(( $(date +%s) + 360 )); fi
if [ -z "${DIGITALOCEAN_TOKEN:-}" ] || \
    ! printf '%s' "$DIGITALOCEAN_TOKEN" | jq -Rse 'length > 0 and length <= 4096 and (explode | all(.[]; . >= 33 and . <= 126))' > /dev/null; then
    finish unknown credentials_unavailable
fi
printf 'Authorization: Bearer %s\n' "$DIGITALOCEAN_TOKEN" > "$work/authorization"
unset DIGITALOCEAN_TOKEN

http() {
    method=$1 path=$2 output=$3
    remaining=$(( deadline - $(date +%s) ))
    [ "$remaining" -gt 0 ] || return 1
    [ "$remaining" -le 12 ] || remaining=12
    if [ "$method" = GET ]; then
        curl --disable --silent --proto '=https' --max-redirs 0 --retry 0 \
            --connect-timeout 5 --max-time "$remaining" --max-filesize 262144 \
            --header "@$work/authorization" --header 'Accept: application/json' \
            --output "$output" --write-out '%{http_code}' \
            "https://api.digitalocean.com/v2/$path" > "$work/status" 2> "$work/error"
    else
        curl --disable --silent --proto '=https' --max-redirs 0 --retry 0 \
            --connect-timeout 5 --max-time "$remaining" --max-filesize 262144 \
            --request "$method" --header "@$work/authorization" \
            --header 'Content-Type: application/json' --data-binary "@$work/payload" \
            --output "$output" --write-out '%{http_code}' \
            "https://api.digitalocean.com/v2/$path" > "$work/status" 2> "$work/error"
    fi
}
read_policy() {
    http GET "firewalls/$firewall" "$work/firewall" && [ "$(cat "$work/status")" = 200 ] || return 1
    http GET "droplets/$instance/firewalls?per_page=100" "$work/page" && [ "$(cat "$work/status")" = 200 ] || return 1
    closed_json "$work/firewall" && closed_json "$work/page" || return 1
    q projection -ce > "$work/projected" 2> "$work/error" || return 1
    mv "$work/projected" "$work/projection"
    policy=$(q policy -r 2> "$work/error") || return 1
    [ "$(printf '%s' "$policy" | wc -c)" -le 65536 ] || return 1
    digest=$(printf '%s' "$policy" | sha256sum)
    digest=${digest%% *}
    fingerprint_input=$(q fingerprint -r 2> "$work/error") || return 1
    fingerprint=$(printf '%s' "$fingerprint_input" | sha256sum)
    fingerprint=${fingerprint%% *}
    observed=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    q observation -ce > "$work/observed" 2> "$work/error" || return 1
    mv "$work/observed" "$work/observation"
}
wait_next() {
    [ "$((deadline - $(date +%s)))" -gt 2 ] || return 1
    sleep 2
}
read_policy || finish unknown policy_unavailable
if [ "$action" = observe ]; then finish complete ''; fi
if [ "$action" = creation ]; then
    while ! q creation -e > /dev/null 2> "$work/error"; do
        wait_next || finish unknown ingress_not_ready
        read_policy || finish unknown policy_unavailable
    done
    finish complete ''
fi
state=$(q change_state -r 2> "$work/error") || finish rejected request_invalid
[ "$state" != after ] || finish complete ''
[ "$state" = before ] || finish rejected policy_conflict
q payload -ce > "$work/payload" 2> "$work/error" || finish rejected request_invalid
step=$(jq -r .step.action "$work/request")
if [ "$step" = add ]; then method=POST; else method=DELETE; fi
# Send once. A transport error or ambiguous response can only be resolved by readback.
http "$method" "firewalls/$firewall/rules" "$work/write" || :
case $(cat "$work/status") in
    400|401|403|404|422) finish rejected provider_rejected ;;
esac
while wait_next; do
    read_policy || finish unknown write_outcome_unknown
    state=$(q change_state -r 2> "$work/error") || finish unknown write_outcome_unknown
    [ "$state" != after ] || finish complete ''
    case $state in before|pending) : ;; *) finish unknown write_outcome_unknown ;; esac
done
finish unknown write_outcome_unknown
