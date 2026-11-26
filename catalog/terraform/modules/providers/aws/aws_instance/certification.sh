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
reason=''
result() {
    jq -n --arg action "$action" --arg status "$1" --arg reason "$reason" --slurpfile refs "${2:-$work/fallback}" \
        '{action:$action,status:$status,resources:$refs[0]}
         + if $status != "complete" and $reason != "" then {failure_reason:$reason} else {} end'
    [ "$1" = complete ] && exit 0
    exit 1
}
# $1 fixed reason code, $2 the unchanged non-complete status.
failed() {
    reason=$1
    result "$2"
}
# $1 resource kind, $2 collect status: 2 is an unclassified EC2 read failure, 3-8 a classified one,
# anything else an unqualified response.
read_failure() {
    case "$2" in
        2) reason=${1}_read_failed ;;
        3) reason=read_timed_out ;;
        4) reason=read_endpoint_unreachable ;;
        5) reason=read_throttled ;;
        6) reason=read_access_denied ;;
        7) reason=read_authentication_failed ;;
        8) reason=read_service_unavailable ;;
        *) reason=${1}_response_unqualified ;;
    esac
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
[ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ] || failed credentials_missing unavailable

ec2() {
    remaining=$((deadline - $(date +%s)))
    [ "$remaining" -gt 0 ] || return 1
    [ "$remaining" -le 10 ] || remaining=10
    (ulimit -f 512; timeout "$remaining" aws --region "$region" --no-paginate --output json \
        --cli-connect-timeout 4 --cli-read-timeout "$remaining" ec2 "$@")
}

# Reads only: standard retries within the remaining action deadline, each attempt keeping the socket bounds.
ec2_read() {
    remaining=$((deadline - $(date +%s)))
    [ "$remaining" -gt 0 ] || return 1
    socket=$remaining
    [ "$socket" -le 10 ] || socket=10
    (ulimit -f 512; AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=3 timeout "$remaining" aws --region "$region" \
        --no-paginate --output json --cli-error-format json --cli-connect-timeout 4 --cli-read-timeout "$socket" \
        ec2 "$@")
}

# $1 read wrapper status. Exits collect with the read failure class from the deadline, the fixed client error
# prefix of the CLI's single plain-text line, or the structured error Code; nothing from stderr is emitted.
read_error() {
    [ "$1" -ne 124 ] && [ "$(date +%s)" -lt "$deadline" ] || exit 3
    if [ "$1" -eq 255 ] && [ "$(awk 'END { print NR }' "$work/error")" -eq 2 ] && [ -z "$(head -n 1 "$work/error")" ]; then
        case "$(sed -n 2p "$work/error")" in
            'aws: [ERROR]: Could not connect to the endpoint URL: '*) exit 4 ;;
            'aws: [ERROR]: Connect timeout on endpoint URL: '*) exit 3 ;;
            'aws: [ERROR]: Read timeout on endpoint URL: '*) exit 3 ;;
        esac
    fi
    code=$(jq -r 'if type == "object" and (.Code | type) == "string" then .Code else empty end' \
        "$work/error" 2> /dev/null) || exit 2
    case "$code" in
        RequestLimitExceeded|Throttling) exit 5 ;;
        UnauthorizedOperation|AccessDenied) exit 6 ;;
        AuthFailure|InvalidClientTokenId|ExpiredToken) exit 7 ;;
        ServiceUnavailable|InternalFailure) exit 8 ;;
    esac
    exit 2
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
        if [ -z "$token" ]; then ec2_read "$command" "$@" > "$work/page" 2> "$work/error" || read_error $?
        else ec2_read "$command" "$@" --next-token "$token" > "$work/page" 2> "$work/error" || read_error $?; fi
        [ "$(wc -c < "$work/page")" -le 262144 ] || exit 1
        q --arg mode page -ce "$work/page" > "$work/decoded" 2> "$work/error" || exit 1
        jq -c '.rows[]' "$work/decoded" >> "$work/rows"
        [ "$(wc -c < "$work/rows")" -le 262144 ] || exit 1
        token=$(jq -r '.next // empty' "$work/decoded")
        if [ -z "$token" ]; then
            q --arg mode rows -sce "$work/rows" \
                > "$destination" 2> "$work/error" || exit 1
            exit 0
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
    collect "$kind" '' "$work/$kind.rows" || { read_failure "$kind" $?; result unavailable; }
done
# Preserve each independently attributed ID before any mutation is considered.
for kind in instance security_group volume; do
    jq -c '.[]' "$work/$kind.rows" > "$work/$kind.references"
done
references "$work/discovered" || failed inventory_response_unqualified unavailable
case "$action" in preflight|discover) result complete "$work/discovered" ;; esac
q --arg mode scope -e "$work/discovered" > /dev/null 2> "$work/error" || failed scope_conflict conflict

exact_reads() {
    for kind in instance security_group volume; do
        identity=$(jq -r --arg kind "$kind" '.resources[] | select(.kind == $kind).id' "$work/request")
        if [ -n "$identity" ]; then
            collect "$kind" "$identity" "$work/$kind.rows" || { read_failure "$kind" $?; return 1; }
        else
            printf '[]\n' > "$work/$kind.rows"
        fi
        jq -c '.[]' "$work/$kind.rows" > "$work/$kind.references"
    done
    references "$work/visible" || { reason=inventory_response_unqualified; return 1; }
}

safe_devices() {
    devices=$(q --arg mode safe -nre 2> "$work/error") || failed cleanup_unqualified conflict
    [ "$devices" = safe ] || failed cleanup_unqualified unavailable
}

exact_reads || result unavailable
[ "$action" != absence ] || result complete "$work/visible"
safe_devices
instance=$(jq -r '.[] | select(.kind == "instance").id' "$work/visible")
if [ -n "$instance" ]; then
    ec2 terminate-instances --instance-ids "$instance" > "$work/write" 2> "$work/error" ||
        failed cleanup_unqualified unavailable
    while :; do
        collect instance "$instance" "$work/instance.rows" || { read_failure instance $?; result unavailable; }
        [ "$(jq -r length "$work/instance.rows")" -ne 0 ] || break
        [ "$(date +%s)" -lt "$deadline" ] || failed absence_unconfirmed unavailable
        sleep 2
    done
fi
exact_reads || result unavailable
[ "$(jq -r length "$work/instance.rows")" -eq 0 ] || failed absence_unconfirmed unavailable
safe_devices
group=$(jq -r '.[] | select(.kind == "security_group").id' "$work/visible")
if [ -n "$group" ]; then
    ec2 delete-security-group --group-id "$group" > "$work/write" 2> "$work/error" ||
        failed cleanup_unqualified unavailable
fi
volume=$(jq -r '.[] | select(.kind == "volume").id' "$work/visible")
if [ -n "$volume" ]; then
    exact_reads || result unavailable
    [ "$(jq -r length "$work/instance.rows")" -eq 0 ] || failed absence_unconfirmed unavailable
    safe_devices
    if [ "$(jq -r length "$work/volume.rows")" -ne 0 ]; then
        ec2 delete-volume --volume-id "$volume" > "$work/write" 2> "$work/error" ||
            failed cleanup_unqualified unavailable
    fi
fi
exact_reads || result unavailable
[ "$(jq -r length "$work/visible")" -eq 0 ] || failed absence_unconfirmed unavailable
result complete
