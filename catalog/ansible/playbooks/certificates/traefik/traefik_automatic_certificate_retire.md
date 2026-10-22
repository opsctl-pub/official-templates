# Retire automatic certificate enrollment

## Inputs

`traefik_automatic_certificate_retire.yml` takes selected Server inventory,
`org_id`, `certificate_subject`, `route_hosts` and the complete
`expected_certificate` snapshot. Native paths retain their existing defaults.
`simulate` defaults to false. The generic retirement helper is invoked with
`certificate_dashboard_retirement=false`.

## Behavior

Disable only this subject's automatic enrollment and remove its matching
automatic selection through the existing
[retirement procedure](../../../tasks/traefik_server_dashboard_retirement.yml).
Preserve native/custom selection and unused material. There is no account purge,
certificate revocation or cross-subject sweep. An expected absent selection
allows observation of an uninstalled gateway. Simulation has no consumed result.

## Results

The [shared certificate result](observe_traefik_certificate.md#plain-results-and-failures)
contains actual `certificate_observation`, nullable `automatic_retired` and any
`procedure_error`. Retirement is true only after observed selection/enrollment
disposition. Unknown state or failed cleanup cannot be treated as absence or
successful retirement.

## Progress

Named outputs come from the included procedure; this entrypoint adds no separate
`OPERATION_STEP` sequence.
