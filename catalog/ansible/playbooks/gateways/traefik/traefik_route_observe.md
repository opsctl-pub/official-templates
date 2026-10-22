# Observe a deployment route

## Inputs

`traefik_route_observe.yml` takes selected Server inventory, `org_id` and canonical
`deployment_id`. `traefik_container_name` defaults to `traefik` and
`traefik_dynamic_dir` to `/etc/traefik/dynamic/opsctl`. Optional `gateway_interface`
and `gateway_service={manager:systemd,name}` must be supplied together; they are
recorded native references, not names inferred from the deployment.

## Behavior

Read the configured native route without mutation. Without gateway references,
an actually uninstalled gateway can be observed absent. With gateway references,
require exactly one loopback backend, the recorded WireGuard public key/address
and loaded active service. Do not install tools, create routes or infer absence
from a failed read.

## Results

`TEMPLATE_OUTPUT_JSON` contains `deployment_route_observation` with normalized
route facts, outcome/time and opaque router reference. Optional
`gateway_bootstrap_observation` contains interface, IPv4, public key, service,
route backend URLs and observation time. Unknown route facts are published before
failure; earlier prerequisite failures may emit nothing. Configuration is not
active serving evidence. The [route field contract](traefik_route_converge.md#route-inputs-and-observations)
and adjacent [sidecar](traefik_route_observe.contract.json) define the complete
field/absence/unknown meanings.

## Progress

This entrypoint emits named results, not an `OPERATION_STEP` sequence.

## Observation declaration and references

The adjacent [route-observe declaration](traefik_route_observe.contract.json)
defines version1 with four closed envelopes: succeeded present/absent, incomplete
unknown, and present with actual `GatewayBootstrapObservation` facts. The optional
paired gateway references require the observed single loopback route/backend and
active WireGuard service; missing/ambiguous evidence refuses before publication.
Ordinary unknown facts are emitted before failure; earlier prerequisites may emit
nothing. Unknown never qualifies success; configured facts do not establish
bootstrap readiness or active serving.

Recorded WireGuard field bounds and cleanup meanings are in
[WireGuard references](../../networking/wireguard_overlay_ensure.md#wireguard-references).
