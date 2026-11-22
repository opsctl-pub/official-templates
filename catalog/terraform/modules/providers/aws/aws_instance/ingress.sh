#!/bin/sh
# Exact creation and configured ingress, saved-state policy and remaining retirement.
set -eu
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/opsctl-aws-ingress.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 130' HUP INT TERM
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
deadline=$(( $(date +%s) + 360 ))
head -c 16777217 > "$work/request"
printf '{}\n' > "$work/group"
printf '{}\n' > "$work/instance"
printf '{}\n' > "$work/policy"
for entry in interfaces rules current before; do printf '{}\n' > "$work/$entry"; done
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
        --slurpfile policy "$work/policy" \
        --slurpfile interfaces "$work/interfaces" --slurpfile native_rules "$work/rules" \
        --slurpfile projection "$work/current" --slurpfile before "$work/before" \
        --arg digest "${digest:-}" --arg fingerprint "${fingerprint:-}" --arg observed "${observed:-}" \
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
procedure_result() {
    printf '{"%s":%s}\n' "$1" "$2"
    [ "$2" = true ] && exit 0
    exit 1
}

# No caller-selected endpoint, implicit page walk, CLI history or write retry.
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true AWS_MAX_ATTEMPTS=1 AWS_PAGER=''
export AWS_EC2_METADATA_DISABLED=true AWS_CLI_AUTO_PROMPT=off
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN
unset AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
has_credentials() {
    [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ]
}

aws_exact() {
    remaining=$((deadline - $(date +%s)))
    [ "$remaining" -gt 0 ] || return 1
    [ "$remaining" -le 12 ] || remaining=12
    # Limit native output while keeping the files private; truncation never qualifies.
    (ulimit -f 512; timeout "$remaining" aws --region "$region" --no-paginate --output json \
        --cli-connect-timeout 5 --cli-read-timeout "$remaining" "$@")
}

ec2_exact() {
    aws_exact ec2 "$@"
}

group_presence() {
    ec2_exact describe-security-groups --filters "Name=group-id,Values=$firewall" > "$work/group" 2> "$work/error" \
        && [ "$(wc -c < "$work/group")" -le 262144 ] && closed_json "$work/group" \
        && q group_presence -re 2> "$work/error"
}

retire_remaining() {
    [ "$(jq -r .purpose "$work/policy")" = retire_remaining ] && has_credentials || return 1
    firewall=$(jq -r .group "$work/policy")
    region=$(jq -r .region "$work/policy")
    presence=$(group_presence) || return 1
    [ "$presence" = present ] || return 0
    [ "$(jq -r .planned "$work/policy")" = true ] || return 1
    if ! ec2_exact delete-security-group --group-id "$firewall" > "$work/delete" 2> "$work/error"; then
        if grep -Eq '^An error occurred \(DependencyViolation\) when calling the DeleteSecurityGroup operation:' "$work/error"; then
            printf '{"applied":false,"reason":"dependency_conflict"}\n'
            exit 1
        fi
        return 1
    fi
    [ "$(group_presence)" = absent ]
}

configuration_snapshot() {
    native_read group describe-security-groups --group-ids "$firewall" &&
    native_read instance describe-instances --instance-ids "$instance" &&
    native_read interfaces describe-network-interfaces --filters "Name=group-id,Values=$firewall" &&
    native_read rules describe-security-group-rules --filters "Name=group-id,Values=$firewall" &&
    q configuration_projection -Sce > "$work/current" 2> "$work/error" &&
    jq -cS '{name,attachment,protected}' "$work/current" > "$work/preserved" &&
    jq -cS '{name,attachment,rows}' "$work/current" > "$work/full" &&
    digest=$(sha256sum < "$work/preserved") && digest=${digest%% *} &&
    fingerprint=$(sha256sum < "$work/full") && fingerprint=${fingerprint%% *} &&
    observed=$(date -u +%Y-%m-%dT%H:%M:%SZ) &&
    q configuration_observation -Sce > "$work/observation" 2> "$work/error"
}

native_read() {
    destination=$1
    shift
    ec2_exact "$@" > "$work/$destination" 2> "$work/error" &&
    [ "$(wc -c < "$work/$destination")" -le 262144 ] && closed_json "$work/$destination"
}

configuration_result() {
    jq -n --slurpfile request "$work/request" --slurpfile observation "$work/observation" \
        --arg started "$started" --arg completed "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
        $request[0] as $r |
        {format_version:1,action:$r.action,provider_instance_id:$r.provider_instance_id,
         firewall_id:$r.firewall_id,collection_started_at:$started,collection_completed_at:$completed,
         status:"complete",reason:null,observation:$observation[0]}'
    exit 0
}

configuration_state_matches() {
    jq -e --arg phase "$1" --slurpfile request "$work/request" '
        .rules == ($request[0][$phase].managed_rules | map([.protocol,.port]) | sort)
    ' "$work/current" > /dev/null
}

configure_ingress() {
    deadline=$(( $(date +%s) + 65 ))
    configuration_snapshot || finish unknown policy_unavailable
    [ "$action" = change ] || configuration_result
    jq -e --slurpfile request "$work/request" '
        .fingerprint == $request[0].expected_before_fingerprint
        and .preserved_policy == $request[0].preserved_policy
    ' "$work/observation" > /dev/null &&
        configuration_state_matches expected_before || finish rejected policy_conflict
    q configuration_change -cre > "$work/change" 2> "$work/error" ||
        finish rejected policy_conflict
    cp "$work/current" "$work/before"
    if [ "$(jq -r .step.action "$work/request")" = add ]; then
        ec2_exact authorize-security-group-ingress --group-id "$firewall" \
            --ip-permissions "file://$work/change" > "$work/write" 2> "$work/error" || :
    else
        ec2_exact revoke-security-group-ingress --group-id "$firewall" \
            --security-group-rule-ids "$(cat "$work/change")" > "$work/write" 2> "$work/error" || :
    fi
    # Even a lost reply may have committed. Observe once without reissuing.
    configuration_snapshot || finish unknown write_unconfirmed
    jq -e --slurpfile request "$work/request" '
        .preserved_policy == $request[0].preserved_policy
    ' "$work/observation" > /dev/null &&
        configuration_state_matches expected_after &&
        q configuration_after -e > /dev/null 2> "$work/error" ||
        finish unknown write_unconfirmed
    configuration_result
}

action=$(jq -r .action "$work/request" 2> "$work/error") || action=''
case "$action" in
    verify_allocation_scope)
        deadline=$(( $(date +%s) + 12 ))
        [ "$(wc -c < "$work/request")" -le 32768 ] && closed_json "$work/request" \
            && q allocation_scope -e > /dev/null 2> "$work/error" && has_credentials \
            || procedure_result matched false
        region=$(jq -r .scope.region "$work/request")
        aws_exact sts get-caller-identity > "$work/instance" 2> "$work/error" \
            && [ "$(wc -c < "$work/instance")" -le 262144 ] && closed_json "$work/instance" \
            && q allocation_match -e > /dev/null 2> "$work/error" || procedure_result matched false
        procedure_result matched true
        ;;
    validate_native_plan|validate_native_apply|retire_remaining)
        result_key=allowed
        [ "$action" != retire_remaining ] || result_key=applied
        [ "$(wc -c < "$work/request")" -le 16777216 ] && closed_json "$work/request" \
            && q native_policy -ce > "$work/qualified-policy" 2> "$work/error" || procedure_result "$result_key" false
        mv "$work/qualified-policy" "$work/policy"
        if [ "$action" = retire_remaining ]; then
            retire_remaining && procedure_result applied true
            procedure_result applied false
        fi
        [ "$(jq -r .purpose "$work/policy")" = retire_compute ] || procedure_result allowed true
        instance=$(jq -r .instance "$work/policy")
        region=$(jq -r .region "$work/policy")
        has_credentials \
            && ec2_exact describe-instances --instance-ids "$instance" > "$work/instance" 2> "$work/error" \
            && [ "$(wc -c < "$work/instance")" -le 262144 ] && closed_json "$work/instance" \
            && q current_devices -e > /dev/null 2> "$work/error" || procedure_result allowed false
        procedure_result allowed true
        ;;
esac

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
has_credentials || finish unknown credentials_unavailable
[ "$action" = creation ] || configure_ingress
while :; do
    ec2_exact describe-security-groups --group-ids "$firewall" > "$work/group" 2> "$work/error" \
        || finish unknown provider_unavailable
    ec2_exact describe-instances --instance-ids "$instance" > "$work/instance" 2> "$work/error" \
        || finish unknown provider_unavailable
    [ "$(wc -c < "$work/group")" -le 262144 ] && [ "$(wc -c < "$work/instance")" -le 262144 ] \
        || finish unknown response_too_large
    closed_json "$work/group" && closed_json "$work/instance" || finish unknown malformed_response
    if q observed -e > /dev/null 2> "$work/error"; then finish complete ''; fi
    [ "$((deadline - $(date +%s)))" -gt 2 ] || finish unknown ingress_not_ready
    sleep 2
done
