#!/bin/sh
# Creation-only exact ingress read. No AWS mutation is supported here.
set -eu
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/opsctl-aws-ingress.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 130' HUP INT TERM
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
deadline=$(( $(date +%s) + 360 ))
head -c 32769 > "$work/request"
printf '{}\n' > "$work/group"
printf '{}\n' > "$work/instance"
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
    jq -n --arg mode "$mode" --slurpfile request "$work/request" \
        --slurpfile group "$work/group" --slurpfile instance "$work/instance" \
        -f "$root/ingress.jq" "$@"
}
finish() {
    completed=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    jq -n --slurpfile request "$work/request" --arg status "$1" --arg reason "$2" \
        --arg started "$started" --arg completed "$completed" '
        ($request[0] // {}) as $r |
        {format_version:1, action:$r.action, provider_instance_id:$r.provider_instance_id,
         firewall_id:$r.firewall_id, collection_started_at:$started, collection_completed_at:$completed,
         status:$status, reason:(if $reason == "" then null else $reason end), observation:null}'
    [ "$1" = complete ] && exit 0
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
region=$(jq -r .region "$work/request")
# No caller-selected endpoint, implicit page walk, CLI history or write retry.
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true AWS_MAX_ATTEMPTS=1 AWS_PAGER=''
export AWS_EC2_METADATA_DISABLED=true AWS_CLI_AUTO_PROMPT=off
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN
unset AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
[ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ] \
    || finish unknown credentials_unavailable
read_exact() {
    remaining=$((deadline - $(date +%s)))
    [ "$remaining" -gt 0 ] || return 1
    [ "$remaining" -le 12 ] || remaining=12
    # Limit native output while keeping the files private; truncation never qualifies.
    (ulimit -f 512; timeout "$remaining" aws --region "$region" --no-paginate --output json \
        --cli-connect-timeout 5 --cli-read-timeout "$remaining" ec2 "$@")
}
while :; do
    read_exact describe-security-groups --group-ids "$firewall" > "$work/group" 2> "$work/error" \
        || finish unknown provider_unavailable
    read_exact describe-instances --instance-ids "$instance" > "$work/instance" 2> "$work/error" \
        || finish unknown provider_unavailable
    [ "$(wc -c < "$work/group")" -le 262144 ] && [ "$(wc -c < "$work/instance")" -le 262144 ] \
        || finish unknown response_too_large
    closed_json "$work/group" && closed_json "$work/instance" || finish unknown malformed_response
    if q observed -e > /dev/null 2> "$work/error"; then finish complete ''; fi
    [ "$((deadline - $(date +%s)))" -gt 2 ] || finish unknown ingress_not_ready
    sleep 2
done
