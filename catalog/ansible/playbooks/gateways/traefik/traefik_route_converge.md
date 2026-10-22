# Configure a deployment route

## Inputs

`traefik_route_converge.yml` takes the selected Server, `org_id`, `deployment_id`,
explicit `route_state=present|absent`, integer `route_port` (1–65535), boolean
`route_https` and `redirect_http_to_https`, `route_hosts`, `traefik_backends=[{url}]`
and the complete `expected_route` snapshot. `route_middlewares` defaults to `[]`.
Present routes need hosts/backends; absent routes need empty lists. At most 100
normalized unique hosts, 64 unique private endpoints and 50 middleware references
are accepted. Redirect requires HTTPS; a route TLS resolver is not supported.
`simulate` defaults to false. Full snapshot fields are defined in the
[route contract below](#route-inputs-and-observations).

## Behavior

Read and compare the actual route, stage/validate a present route or remove this
deployment's route, then observe the desired native configuration. Already absent
routes are idempotent. Failed activation attempts restoration of prior bytes or
absence; restoration can itself fail. No other route, certificate or backend
runtime is removed. Simulation ends before effects and emits no readiness facts.

## Results

Emit `deployment_route_observation` with `presence`, `hosts`, `route_port`, `https`,
`redirect_http_to_https`, `middlewares`, `backends`, `router_name`, `outcome` and
`observed_at`. Configured presence is not proof of serving. Failure may return
restored facts plus `procedure_error={phase:apply,code:route_apply_failed}` or only
`{phase:restore,code:restoration_failed}`. Early refusal may emit no result.
The adjacent [sidecar](traefik_route_converge.contract.json) retains exact examples
and version/consumer bounds; missing/error-bearing facts never qualify success.

## Progress

Existing steps are `traefik-route:start`, `traefik-route:complete` and
`traefik-route:failure`.

## Route inputs and observations

Common inputs identify the Deployment, organization and target Server through
the existing inventory. Ports are strict integers 1..65535; normalized hosts are
sorted/unique (maximum 100), private/loopback endpoints unique (maximum 64).
Middleware references are opaque strings (maximum 255 characters, 50 entries).
Convergence/canary `simulate=true` exits before effects and supplies no facts or
consumed success. Route observation remains read-only; its configured facts alone
are not a simulated readiness result.

`traefik_route_observe` needs only its subject and optional recorded WireGuard
references. `traefik_route_converge` adds explicit `route_state=present|absent`,
`route_hosts`, `route_port`, `route_https`, `redirect_http_to_https`,
`route_middlewares` (default `[]`), `traefik_backends=[{url}]` and `expected_route`.
Present requires hosts/backends; absent requires empty lists; redirect requires
HTTPS. The expected snapshot has exactly `presence`, `hosts`, `route_port`,
`https`, `redirect_http_to_https`, `middlewares`, `backends`, `router_name`.
Absence has empty lists and null scalar fields. Unknown never authorizes a write.

Return `deployment_route_observation` with those fields plus `outcome` and
`observed_at`. Compare the complete snapshot immediately before writing; stage,
validate and atomically activate only this subject, then reobserve. On failure,
restore its prior file where possible and report actual restored/unknown facts.
Paths and native layout belong to the public procedure, not the backend input.
The official defaults are gateway container `traefik` and watched directory
`/etc/traefik/dynamic/opsctl`; overrides may use their own layout.

The adjacent [route-converge declaration](traefik_route_converge.contract.json)
defines version1 with four closed envelopes: succeeded present/absent, restored
route facts plus `apply/route_apply_failed`, and error-only
`restore/restoration_failed`. Configured presence does not establish serving.
Error-bearing results are failures; restoration failure supplies no route facts.
Preconditions may refuse without any output, and simulate supplies no readiness.
Use Automation Overrides to replace this procedure while preserving its inputs
and results.
