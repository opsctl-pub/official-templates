# Manage a temporary backend canary

## Inputs

`traefik_backend_canary.yml` takes `action=observe|converge_present|converge_absent`,
canonical `promotion_id`, `deployment_id`, `org_id`, `gateway_id`, `target_node_id`
and `target_revision_id`. Supply one normalized `route_hosts` entry, one
`traefik_backends=[{url}]` endpoint, integer `route_port` and `canary_router` naming
intent. Mutations require the complete `expected_canary` snapshot with `presence`,
`host`, `router_name` and `backends`; observe must not supply it. `simulate`
defaults to false.

## Behavior

Read and validate the existing canary's exact ownership/configuration before any
write. Compare the expected snapshot, then stage/activate or remove only this
promotion's canary and reobserve it. The route restricts requests to loopback.
Failure attempts restoration of prior bytes, metadata or absence; failed
restoration remains a failure. Simulation ends before validation/reads/effects.

## Results

`TEMPLATE_OUTPUT_JSON` contains `promotion_canary_observation` with the snapshot
plus `outcome` and UTC `observed_at`. Absence has null host/router and empty
backends. The observed provider-qualified router reference is opaque.
Configured presence is not successful serving or application readiness. Ownership,
comparison or restoration failure may produce no result, never invented unknown
or restored facts. See the [sidecar](traefik_backend_canary.contract.json) and
[canary contract below](#canary-inputs-and-declaration).

## Progress

Convergence completion emits `traefik-backend-canary:complete` with existing
action/promotion metadata. Observe emits only its named result.

## Canary inputs and declaration

Common port/host/endpoint/middleware bounds and simulation distinctions are in
[route inputs](traefik_route_converge.md#route-inputs-and-observations).

`traefik_backend_canary` adds `action=observe|converge_present|converge_absent`,
`promotion_id`, `gateway_id`, `target_node_id`, `target_revision_id`, one admitted
temporary `route_hosts` entry, `canary_router` naming intent, `route_port` and
one approved `traefik_backends` entry. Mutations require `expected_canary` with
exactly `presence`, `host`, `router_name`, `backends`; observe has no expectation.
Return `promotion_canary_observation` with that snapshot plus outcome/time.
Absent/unknown uses null host/router and empty backends. Keep the temporary
router private-only. Never recompute a backend naming digest in an override.
The full observed provider reference is opaque; neither configured presence nor
successful publication establishes active serving; see the
[verification contract](../../health/health_verify.md#verification).

The adjacent [canary declaration](traefik_backend_canary.contract.json)
defines version1 with only succeeded configured present/absent envelopes, not
unknown, error or restored-state results. Ownership/CAS refusals and failed
convergence/restoration may emit no facts. Canary simulation ends at the
first pretask, before validation, reads or writes, and emits no result/readiness.
Use Automation Overrides to replace the route observation or canary procedure
while preserving its documented inputs and results.
