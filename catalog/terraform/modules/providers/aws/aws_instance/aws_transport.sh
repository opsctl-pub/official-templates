# Module-local AWS CLI transport. Source from an entrypoint with private work, region and deadline.
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
read_native() {
    destination=$1
    shift
    aws_exact "$@" > "$work/$destination" 2> "$work/error" &&
    [ "$(wc -c < "$work/$destination")" -le 262144 ] && closed_json "$work/$destination"
}
