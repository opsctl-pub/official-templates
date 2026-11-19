#!/bin/sh
set -eu
umask 077

started=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
request=$(head -c 4097)
id=$(printf '%s' "$request" | jq -er '
    select(type == "object" and keys == ["provider_resource_id"]) |
    .provider_resource_id | select(type == "string" and test("^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"))
' 2>/dev/null) || exit 1
test "${#request}" -le 4096 || exit 1

observation() {
    jq -cn --arg id "$id" --arg presence "$1" --arg reason "$2" --arg started "$started" \
        --arg ended "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" '{
            format_version:1,provider_resource_id:$id,presence:$presence,
            reason:(if $reason=="" then null else $reason end),endpoint:null,region:null,
            backend_port:null,backend_ids:null,ready:null,
            collection_started_at:$started,collection_completed_at:$ended
        }'
}

if [ -z "${DIGITALOCEAN_TOKEN:-}" ]; then
    observation unknown credentials_unavailable
    exit
fi

work=$(mktemp -d)
trap 'test ! -e "$work/headers" || unlink "$work/headers"; test ! -e "$work/body" || unlink "$work/body"; rmdir "$work"' 0
trap 'exit 130' 1 2 15
printf 'Authorization: Bearer %s\n' "$DIGITALOCEAN_TOKEN" >"$work/headers"
if ! status=$(curl --silent --show-error --proto '=https' --max-time 15 --max-filesize 1048576 \
        -H @"$work/headers" --output "$work/body" --write-out '%{http_code}' \
        "https://api.digitalocean.com/v2/load_balancers/$id" 2>/dev/null); then
    observation unknown provider_unavailable
    exit
fi
case "$status" in
    404) observation absent "" ;;
    200)
        if ! jq -ce --arg id "$id" --arg started "$started" --arg ended "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" '
            .load_balancer |
            select(.id==$id and (.region.slug|type=="string") and (.status|type=="string")) |
            select(.ip==null or (.ip|type=="string")) |
            select(.droplet_ids|type=="array" and length<=128 and
                all(.[];type=="number" and .>=1 and .<=999999999999999 and .==floor)) |
            select(.forwarding_rules|type=="array") |
            {
                format_version:1,provider_resource_id:$id,presence:"present",reason:null,
                endpoint:(.ip|select(.!=null and length>0)//null), region:.region.slug,
                backend_port:(
                    .forwarding_rules |
                    if length==1 and .[0].entry_protocol=="tcp" and .[0].target_protocol=="tcp" and
                        (.[0].entry_port|type=="number") and .[0].entry_port==.[0].target_port
                    then .[0].target_port else null end
                ),
                backend_ids:(.droplet_ids|unique|map(tostring)),
                ready:(.status=="active" and (.ip // "" | length>0)),
                collection_started_at:$started,collection_completed_at:$ended
            }
        ' "$work/body" 2>/dev/null; then
            observation unknown provider_response_invalid
        fi ;;
    *) observation unknown provider_unavailable ;;
esac
