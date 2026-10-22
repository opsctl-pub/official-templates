# Issue, retry or renew an automatic certificate

## Inputs

`traefik_automatic_certificate.yml` uses selected Server inventory, `org_id`,
`certificate_subject`, sorted unique `route_hosts`, `expected_certificate`,
`certificate_action=issue|retry|renew`, `acme_email` and an admitted HTTPS
`acme_directory_url`, explicit `challenge=http-01|dns-01` and
`renewal_enabled=true`. HTTP requires null broker inputs. DNS-01 requires approved `broker_url`,
protected `broker_token_source_file` and the existing token revision/content
binding. Native settings and complete bounds are in the
[shared certificate contract](observe_traefik_certificate.md#public-inputs).

## Behavior

The [automatic procedure](../../../tasks/traefik_automatic_certificate.yml) owns native
issuance and renewal enrollment. Manual and scheduled work use the same subject
service. HTTP challenge uses its bounded shared lock/listener; DNS uses protected
broker token delivery. Selection comparison, activation, serving verification and
restoration remain subject-local. The procedure uses the documented ACME challenge
modes, not other issuer APIs.
Simulation ends without effects or a consumed result.

## Results

Emit `certificate_observation` and any safe `procedure_error` under the
[shared result contract](observe_traefik_certificate.md#plain-results-and-failures).
Selected leaf and renewal enabled/active/next-due facts are separate from actual
per-host serving/trust. Failure or uncertain cleanup cannot claim success;
unavailable fields remain null/unknown. No token/private key is returned.

## Progress

The included automatic procedure emits the named result above; this entrypoint
adds no separate `OPERATION_STEP` sequence.

## Native issuance and renewal

Automatic issuance pins goacme/lego@sha256:1944e8c36055beec47c7de6f15202b41128be75eea0ffa257f0c14d93c5155fd.
Per-subject .service/.timer invokes renew.sh, including manual actions through
the same unit. Due uses v5 run --renew-days 30; explicit renew uses run --renew-force.
Schedule is 00/06/12/18 UTC, RandomizedDelaySec=30m, Persistent=true. HTTP uses one
shared flock and exact temporary challenge route to loopback38473. DNS uses
protected httpreq token delivery without HTTP lock/listener. Lock/client each
bound600s, publication/probe30s, cleanup30s, unit1260s. Docker CLI stays only in
the finite local script; Ansible modules observe/reap positively owned clients.
Unknown cleanup retains exact native state. Newly delivered broker tokens are
removed only after complete native container/renewal reference exclusion.

Example first issuance intent (common inventory fields omitted):

~~~yaml
certificate_subject: {type: deployment, id: 11111111-1111-4111-8111-111111111111}
route_hosts: [app.example.test]
expected_certificate:
  presence: absent
  source: null
  material_id: null
  revision_id: null
  leaf_fingerprint_sha256: null
certificate_action: issue
acme_email: operator@example.test
acme_directory_url: https://acme-v02.api.letsencrypt.org/directory
challenge: http-01
broker_url: null
broker_token_source_file: null
renewal_enabled: true
~~~
