# Manage a gateway-local certificate revision

## Inputs

`traefik_native_certificate.yml` takes `native_certificate_action=csr|install|observe|retire`,
`certificate_subject={type:deployment|server,id}`, `org_id`, `revision_id` and
sorted unique `route_hosts` (maximum 100; nonempty for CSR/install). Install also
needs `certificate_chain_pem`, expected selection, fingerprint and selected trust.
Retire requires `previous_revision_id` and current `expected_certificate` after
the backend's unused/revocation authorization. `simulate` defaults to false.

## Behavior

CSR creates/reuses only the revision's local EC P-256 private key, creates its
immutable public CSR and checks key/SAN/signature facts. Install retains the
immutable public chain, then invokes existing selection/serving verification.
Observe reads existing selection without mutation. Retire reobserves current
selection and all bounded TLS references before deleting only the exact unused
revision's approved files and now-empty directory. No unknown/unreadable state
authorizes deletion. Tools must already exist; keys never leave the gateway.

## Results

CSR emits `native_certificate_csr={outcome,observed_at,csr_pem,public_key_sha256,
revision_id}`; public CSR is bounded to 16 KiB. Other actions emit
`certificate_observation`; retirement adds nullable `retired_revision_absent`.
Available facts and safe `procedure_error` precede failure. CSR is not serving
readiness, failed retirement does not imply rollback, and unknown absence stays
unknown. See the [shared fields and limits](observe_traefik_certificate.md#plain-results-and-failures).

## Progress

This entrypoint emits `TEMPLATE_OUTPUT_JSON`, not a separate step sequence.
