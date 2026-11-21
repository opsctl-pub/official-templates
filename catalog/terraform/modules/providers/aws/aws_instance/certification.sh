#!/bin/sh
# Fixed EC2 commands for one leased certification and its frozen proof scope.
set -eu
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/opsctl-aws-cert.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 130' HUP INT TERM
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
deadline=$(( $(date +%s) + 65 ))
head -c 32769 > "$work/request"
printf '[]\n' > "$work/fallback"
for kind in instance security_group volume; do : > "$work/$kind.references"; done
action=''
result() {
    jq -n --arg action "$action" --arg status "$1" --slurpfile refs "${2:-$work/fallback}" \
        '{action:$action,status:$status,resources:$refs[0]}'
    [ "$1" = complete ] && exit 0
    exit 1
}

q() {
    jq --arg kind "${kind:-}" --arg expected "${expected:-}" \
        --slurpfile request "$work/request" --slurpfile instance "$work/instance.references" \
        --slurpfile group "$work/security_group.references" --slurpfile volume "$work/volume.references" \
        -f "$root/certification.jq" "$@"
}

[ "$(wc -c < "$work/request")" -le 32768 ] \
    && q --arg mode request -ne > /dev/null 2> "$work/error" || result unavailable
action=$(jq -r .action "$work/request")
region=$(jq -r .region "$work/request")
name=$(jq -r .name "$work/request")
if [ "$action" = cleanup ] || [ "$action" = absence ]; then
    jq -c .resources "$work/request" > "$work/fallback"
fi

export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true AWS_MAX_ATTEMPTS=1 AWS_PAGER=''
export AWS_EC2_METADATA_DISABLED=true AWS_CLI_AUTO_PROMPT=off
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN
unset AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
[ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ] || result unavailable

ec2() {
    remaining=$((deadline - $(date +%s)))
    [ "$remaining" -gt 0 ] || return 1
    [ "$remaining" -le 10 ] || remaining=10
    (ulimit -f 512; timeout "$remaining" aws --region "$region" --no-paginate --output json \
        --cli-connect-timeout 4 --cli-read-timeout "$remaining" ec2 "$@")
}

collect() (
    kind=$1
    expected=$2
    destination=$3
    case "$kind" in
        instance) command=describe-instances; filter=instance-id ;;
        security_group) command=describe-security-groups; filter=group-id ;;
        volume) command=describe-volumes; filter=volume-id ;;
        *) exit 1 ;;
    esac
    if [ "$expected" = '' ]; then filter="Name=tag:Name,Values=$name"
    else filter="Name=$filter,Values=$expected"; fi
    set -- --max-results 100 --filters "$filter"
    if [ "$kind" = instance ]; then
        set -- "$@" "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down"
    fi
    : > "$work/tokens"
    : > "$work/rows"
    token=''
    pages=0
    while [ "$pages" -lt 16 ]; do
        if [ -z "$token" ]; then ec2 "$command" "$@" > "$work/page" 2> "$work/error" || exit 1
        else ec2 "$command" "$@" --next-token "$token" > "$work/page" 2> "$work/error" || exit 1; fi
        [ "$(wc -c < "$work/page")" -le 262144 ] || exit 1
        q --arg mode page -ce "$work/page" > "$work/decoded" 2> "$work/error" || exit 1
        jq -c '.rows[]' "$work/decoded" >> "$work/rows"
        [ "$(wc -c < "$work/rows")" -le 262144 ] || exit 1
        token=$(jq -r '.next // empty' "$work/decoded")
        if [ -z "$token" ]; then
            q --arg mode rows -sce "$work/rows" \
                > "$destination" 2> "$work/error"
            exit $?
        fi
        if grep -Fxq -- "$token" "$work/tokens"; then exit 1; fi
        printf '%s\n' "$token" >> "$work/tokens"
        pages=$((pages + 1))
    done
    exit 1
)

references() {
    q --arg mode references -ne > "$1" 2> "$work/error"
}

for kind in instance security_group volume; do
    collect "$kind" '' "$work/$kind.rows" || result unavailable
done
# Preserve each independently attributed ID before any mutation is considered.
for kind in instance security_group volume; do
    jq -c '.[]' "$work/$kind.rows" > "$work/$kind.references"
done
references "$work/discovered" || result unavailable
case "$action" in preflight|discover) result complete "$work/discovered" ;; esac
q --arg mode scope -e "$work/discovered" > /dev/null 2> "$work/error" || result conflict

exact_reads() {
    for kind in instance security_group volume; do
        identity=$(jq -r --arg kind "$kind" '.resources[] | select(.kind == $kind).id' "$work/request")
        if [ -n "$identity" ]; then
            collect "$kind" "$identity" "$work/$kind.rows" || return 1
        else
            printf '[]\n' > "$work/$kind.rows"
        fi
        jq -c '.[]' "$work/$kind.rows" > "$work/$kind.references"
    done
    references "$work/visible"
}

safe_devices() {
    devices=$(q --arg mode safe -nre 2> "$work/error") || result conflict
    [ "$devices" = safe ] || result unavailable
}

exact_reads || result unavailable
[ "$action" != absence ] || result complete "$work/visible"
safe_devices
instance=$(jq -r '.[] | select(.kind == "instance").id' "$work/visible")
if [ -n "$instance" ]; then
    ec2 terminate-instances --instance-ids "$instance" > "$work/write" 2> "$work/error" || result unavailable
    while :; do
        collect instance "$instance" "$work/instance.rows" || result unavailable
        [ "$(jq -r length "$work/instance.rows")" -ne 0 ] || break
        [ "$(date +%s)" -lt "$deadline" ] || result unavailable
        sleep 2
    done
fi
exact_reads && [ "$(jq -r length "$work/instance.rows")" -eq 0 ] || result unavailable
safe_devices
group=$(jq -r '.[] | select(.kind == "security_group").id' "$work/visible")
if [ -n "$group" ]; then
    ec2 delete-security-group --group-id "$group" > "$work/write" 2> "$work/error" || result unavailable
fi
volume=$(jq -r '.[] | select(.kind == "volume").id' "$work/visible")
if [ -n "$volume" ]; then
    exact_reads && [ "$(jq -r length "$work/instance.rows")" -eq 0 ] || result unavailable
    safe_devices
    if [ "$(jq -r length "$work/volume.rows")" -ne 0 ]; then
        ec2 delete-volume --volume-id "$volume" > "$work/write" 2> "$work/error" || result unavailable
    fi
fi
exact_reads && [ "$(jq -r length "$work/visible")" -eq 0 ] || result unavailable
result complete
