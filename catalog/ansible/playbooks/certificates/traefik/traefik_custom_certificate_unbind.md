# Unbind a custom certificate

## Inputs

`traefik_custom_certificate_unbind.yml` requires a deployment subject, `org_id`,
sorted unique `route_hosts`, `material_id`, `revision_id`,
`leaf_fingerprint_sha256` and complete `expected_certificate`. It does not read
chain/key inputs. Optional native/trust settings follow the
[shared certificate contract](observe_traefik_certificate.md#public-inputs).
`simulate` defaults to false.

## Behavior

Use the existing selection helper with action `remove` and source `custom`.
Compare the observed snapshot, pause renewal and remove only a matching custom
selection. Retain unused certificate/key material and other subjects. Failed
selection changes attempt restoration without promising atomic rollback.
Simulation emits no consumed success.

## Results

Emit `certificate_observation` and any `procedure_error` before a failed outcome
fails the play. Actual selection absence is distinct from unavailable/unknown
state; unbinding does not claim certificate revocation or deletion of material.
Full field/failure meanings remain in the
[shared result contract](observe_traefik_certificate.md#plain-results-and-failures).

## Progress

There is no entrypoint-specific `OPERATION_STEP` sequence.
