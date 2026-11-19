#!/bin/sh
set -eu

if jq -e '
    .scope as $scope |
    .variables.opsctl_load_balancer as $inputs |
    select(.action == "validate_native_plan" and $inputs == $scope.intent.inputs) |
    [ .plan.resource_changes[] | select(.address == "digitalocean_loadbalancer.managed") ] |
    (length == 0 and $scope.purpose == "load_balancer_delete") or
    (length == 1 and (
        .[0].change as $change |
        if $scope.purpose == "load_balancer_delete" then
            $scope.intent.retiring_backend_id as $server |
            $server == null or
                ($change.before.droplet_ids | type == "array" and all(.[]; tostring == $server))
        else
            $change.after as $after |
            $after.name == $inputs.name and $after.region == $inputs.region and
            ($after.droplet_ids | map(tostring) | sort) == ($inputs.backend_ids | sort) and
            ($after.forwarding_rule | length == 1 and all(.[];
                .entry_protocol == "tcp" and .target_protocol == "tcp" and
                .entry_port == $inputs.backend_port and .target_port == $inputs.backend_port))
        end
    ))
' >/dev/null 2>&1; then
    printf '%s\n' '{"allowed":true}'
else
    printf '%s\n' '{"allowed":false}'
    exit 1
fi
