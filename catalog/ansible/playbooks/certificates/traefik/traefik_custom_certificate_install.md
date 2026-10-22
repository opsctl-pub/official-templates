# Install a custom certificate

## Inputs

`traefik_custom_certificate_install.yml` requires a deployment
`certificate_subject`, `org_id`, sorted unique `route_hosts`, `material_id`,
`revision_id`, `leaf_fingerprint_sha256`, `content_digest` and the complete
five-field `expected_certificate`. Protected `tls.crt`/`tls.key` arrive under
`certificate_source_dir` (default `/var/run/opsctl/file-secret`). Optional trust
and native settings follow the [shared contract](observe_traefik_certificate.md#public-inputs).
`simulate` defaults to false.

## Behavior

Validate IDs/fingerprint and the bounded mounted-file content digest before
delivery. The [selection helper](../../../tasks/traefik_certificate_selection.yml)
observes/compares existing material, pauses this subject's renewal, stages
privately, compares again at publication and probes serving. Failed switching
attempts prior selection/enrollment restoration, which can itself fail.
Simulation ends without effects or consumed success. Secrets are not logged.

## Results

Emit actual `certificate_observation` plus any safe `procedure_error` in
`TEMPLATE_OUTPUT_JSON`, then fail if selection or observation failed. Available
selected facts survive failure without implying successful serving or rollback.
The full [result/unknown contract](observe_traefik_certificate.md#plain-results-and-failures)
applies; no private key, chain or raw native stderr is returned.

## Progress

This entrypoint emits named results, not a separate `OPERATION_STEP` sequence.

## Switching and incomplete serving

Custom switching supplies the actually observed automatic leaf in the expected
snapshot plus admitted custom IDs/fingerprint/protected files. Success requires
actual custom selection and all-host matched/trusted facts; automatic retirement
is not inferred. Unreachable hosts report served=unreachable with null trust/leaf
and failed outcome, retaining available selected material.
