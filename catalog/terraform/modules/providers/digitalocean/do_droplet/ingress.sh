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
native_prepare=false
for name in projection firewall page observation; do printf '{}\n' > "$work/$name"; done
head -c 16777217 > "$work/request"

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
    if [ "$native_prepare" = true ]; then printf '{"present":null}\n'; exit 1; fi
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
if [ "$(wc -c < "$work/request")" -le 16777216 ] &&
    jq -e '.action == "validate_native_plan"' "$work/request" > /dev/null 2> "$work/error"; then
    if closed_json "$work/request" && q native_plan -e > /dev/null 2> "$work/error"; then
        printf '{"allowed":true}\n'
        exit 0
    fi
    printf '{"allowed":false}\n'
    exit 1
fi
if jq -e '.action == "prepare_native_plan"' "$work/request" > /dev/null 2> "$work/error"; then
    native_prepare=true
    if [ "$(wc -c < "$work/request")" -gt 16777216 ] || ! closed_json "$work/request" ||
        ! firewall=$(q native_prepare -er 2> "$work/error"); then
        printf '{"present":null}\n'
        exit 1
    fi
    action=prepare_native_plan
elif [ "$(wc -c < "$work/request")" -gt 32768 ] || ! closed_json "$work/request" || ! q request -e > /dev/null 2> "$work/error"; then
    jq -c 'def identity: if type == "string" and length <= 255 then . else null end;
        {action:(.action | identity), provider_instance_id:(.provider_instance_id | identity),
         firewall_id:(.firewall_id | identity)}' "$work/request" > "$work/safe-request" 2> "$work/error" \
        || printf '{}\n' > "$work/safe-request"
    mv "$work/safe-request" "$work/request"
    finish rejected request_invalid
else
    instance=$(jq -r .provider_instance_id "$work/request")
    firewall=$(jq -r .firewall_id "$work/request")
    action=$(jq -r .action "$work/request")
fi
if [ "$action" = change ]; then finish rejected action_unsupported; fi
if [ "$action" = creation ]; then deadline=$(( $(date +%s) + 360 )); fi
if [ -z "${DIGITALOCEAN_TOKEN:-}" ] || \
    ! printf '%s' "$DIGITALOCEAN_TOKEN" | jq -Rse 'length > 0 and length <= 4096 and (explode | all(.[]; . >= 33 and . <= 126))' > /dev/null; then
    finish unknown credentials_unavailable
fi
printf 'Authorization: Bearer %s\n' "$DIGITALOCEAN_TOKEN" > "$work/authorization"
unset DIGITALOCEAN_TOKEN

http() {
    method=$1 path=$2 output=$3
    [ "$method" = GET ] || return 1
    remaining=$(( deadline - $(date +%s) ))
    [ "$remaining" -gt 0 ] || return 1
    [ "$remaining" -le 12 ] || remaining=12
    curl --disable --silent --proto '=https' --max-redirs 0 --retry 0 \
        --connect-timeout 5 --max-time "$remaining" --max-filesize 262144 \
        --header "@$work/authorization" --header 'Accept: application/json' \
        --output "$output" --write-out '%{http_code}' \
        "https://api.digitalocean.com/v2/$path" > "$work/status" 2> "$work/error"
}
if [ "$native_prepare" = true ]; then
    http GET "firewalls/$firewall" "$work/firewall" || finish unknown read_unavailable
    case "$(cat "$work/status")" in
        404) printf '{"present":false}\n'; exit 0 ;;
        200)
            if closed_json "$work/firewall" && jq -e --arg id "$firewall" '.firewall.id == $id' \
                "$work/firewall" > /dev/null 2> "$work/error"; then
                printf '{"present":true}\n'
                exit 0
            fi ;;
    esac
    finish unknown read_unavailable
fi
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
finish rejected request_invalid
