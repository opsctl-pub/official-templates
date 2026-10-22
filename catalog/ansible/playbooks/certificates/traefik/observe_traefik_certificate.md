# Observe Traefik certificate selection and serving

## Inputs

Selected Server inventory, `org_id`, `certificate_subject={type:deployment|server,id}`,
sorted unique `route_hosts` (maximum 100), and required boolean
`certificate_probe_hosts`. Optional `trust_bundle_pem` selects supplied trust
instead of system trust. Native defaults and plain facts follow the
[certificate procedure contract below](#certificate-procedure-contract).

## Behavior

The [observation tasks](../../../tasks/traefik_custom_certificate_observation.yml)
read native selection and enrollment without mutation. With probes enabled,
verify the managed gateway and actual SNI serving; genuine selection absence
skips SNI. With probes disabled, return selection without host serving claims
and allow an actually uninstalled gateway. This is not the helper's private
`certificate_selection_only` mode. Missing or unreadable evidence remains
unknown, never invented absence. No files, timers, material or configuration
are changed.

## Results and progress

Emit `TEMPLATE_OUTPUT_JSON` containing `certificate_observation` and
any safe `procedure_error`, then fail unless outcome is `succeeded`. Selected,
served, trust, validity and renewal remain distinct. There is no entrypoint
`OPERATION_STEP` sequence.

## Certificate procedure contract

OpsControl authorizes the issuer, hosts, material and sequence of actions. The
procedure uses the supplied inventory/SSH connection, target and organization.
Native paths and service names follow the procedure settings below.
simulate=true ends without changes or consumed success.

### Public Inputs

All items take certificate_subject={type:deployment|server,id:UUID} and route_hosts
(sorted unique normalized DNS names, maximum100). Mutation requires exactly
expected_certificate={presence,source,material_id,revision_id,leaf_fingerprint_sha256}.
Absent has four nulls; present requires source/fingerprint; custom requires both
IDs, native revision, automatic IDs may be null. UUIDs are canonical lowercase.
Unknown never authorizes mutation. Material/trust keeps the existing256KiB bound.

| Item | Additional inputs and behavior |
|---|---|
| observe_traefik_certificate | Required boolean certificate_probe_hosts: false observes selection with hosts=[] and no serving claim; true probes every requested host when selection is present. Genuine absence skips SNI and returns full succeeded ABSENT facts with hosts=[]. No expected snapshot/material. Optional private trust_bundle_pem=null selects system trust; otherwise supplied trust. |
| traefik_automatic_certificate | certificate_action=issue/retry/renew, expected snapshot, acme_email3..320, admitted HTTPS acme_directory_url, challenge=http-01/dns-01, renewal_enabled=true. HTTP requires null broker_url/broker_token_source_file. DNS requires approved broker_url, runner broker_token_source_file and existing dns_challenge_token_revision_id/dns_challenge_token_content_digest custody binding. |
| traefik_automatic_certificate_retire | Expected snapshot. Disable only subject enrollment and remove matching automatic selection. Preserve custom/native selection and material; no account purge/revocation/sweep. |
| traefik_custom_certificate_install | Deployment subject, material_id/revision_id/leaf_fingerprint_sha256, expected snapshot. certificate_source_dir defaults /var/run/opsctl/file-secret with protected tls.crt/tls.key; existing content_digest checked before delivery. |
| traefik_custom_certificate_unbind | Same identities/expected snapshot, no chain/key input; remove only matching custom selection, retain unused pair. |
| traefik_native_certificate | native_certificate_action=csr/install/observe/retire, subject, hosts, revision_id. CSR creates/reuses local EC P-256 key. Install adds certificate_chain_pem, trust_bundle_pem, leaf_fingerprint_sha256 and expected snapshot. Observe needs no material. Retire requires previous_revision_id and current expected snapshot after backend revocation/unused authorization; actual native references checked before exact unused revision deletion. |

Observe never creates directories, installs tools or mutates configuration.
Missing tooling or unreadable/changed native references is unknown, not absence.
Full observation rereads and compares the exact native selection before returning,
including absence. Absent facts claim no serving, trust, material, validity or
renewal. Backend absence acceptance defaults off; only ordinary HTTPS
certificate_stage=before may consume it as not_configured, never HTTPS completion.

### Native Procedure And Overrides

Overridable defaults: traefik_container_name=traefik;
traefik_dynamic_dir=/etc/traefik/dynamic/opsctl;
traefik_certificate_dir=/etc/traefik/certificates/opsctl;
traefik_acme_state_dir=/var/lib/opsctl/automatic-certificates;
traefik_acme_dir=/var/lib/traefik; certificate_unit_prefix=opsctl-certificate-;
certificate_probe_address=127.0.0.1; certificate_probe_port=443;
certificate_http_port=38473;
certificate_system_trust_file=/etc/ssl/certs/ca-certificates.crt.
These are template settings, never backend-derived filenames/service names.

Selection is a native TLS document named certificate-<type>-<UUID>.yml with a
local source/material comment. Generated pairs have private store directories;
native keys remain in native-<type>-<UUID>/revision-<UUID>. Selection observation
reads actual pair identity/SAN/validity/fingerprint, not metadata alone.

Mutation pauses the subject timer, waits for its active service, stages privately
and compares the complete expected snapshot immediately at atomic publication.
Key/chain match, validity and requested SANs are validated. Every requested SNI
host is probed with selected trust. Failed activation restores its own prior
selection and automatic enrollment; failed restoration is retained liability.
Only this invocation's generated pair is disposed after confirmed restoration;
native source material and other stored pairs remain untouched.

Existing Server tooling: Python cryptography/PyYAML, OpenSSL, systemd, Docker,
Bash, flock, timeout; Python3.11 for native TOML reference observation. Observers
never install tools. Overrides may use another native layout/implementation with
the same public facts/safety; no OpsCtl API imports or private algorithms needed.

### Narrow Template-Local Primitives

certificate_facts.py reads --selection/--root/--subject, optional --hosts/--timer,
loopback --address/--port and --trust-file or --trust-pem. --snapshot emits only
five compare fields; --require-source refuses changed source. --csr/--revision/
--hosts returns bounded public CSR facts. --selection-directory/--unused-directory
reads bounded native TLS references. No issuance, scheduling, Docker or mutation.

traefik_certificate_publish.py takes native --selection/--root/--subject/--source,
optional --material/--revision, --hosts, private --expected-file, chain/key/
fingerprint and optional trust/listener. --remove unselects only matching source.
It validates and atomically publishes one selection, restoring its prior selection
after bounded failed SNI verification. No issuance, lifecycle/backend state,
scheduling or cross-subject cleanup occurs inside the primitive.

### Plain Results And Failures

One TEMPLATE_OUTPUT_JSON object contains certificate_observation: outcome=
succeeded/failed/incomplete, UTC observed_at, five selection fields, nullable UTC
not_before/not_after, selected_hosts, binding_count, hosts=[{hostname,
served:matched/mismatch/unreachable/unknown,trusted:bool|null,
leaf_fingerprint_sha256:string|null}], renewal. Automatic renewal is
{enabled:bool|null,active:bool|null,next_due_at:UTC|null}; other sources use null.
Selection-only hosts=[] never claims serving. Retirement adds automatic_retired
or retired_revision_absent, nullable and true only after actual corresponding
absence/disabled enrollment.
binding_count is nullable for unknown presence, positive for present, and exactly0
for absent; unavailable observation never fabricates zero.

CSR returns native_certificate_csr={outcome,observed_at,csr_pem,
public_key_sha256,revision_id}; public CSR maximum16KiB, private key never exported.
Combined compact output maximum128KiB. Null means unknown, never guessed false,
zero or absence. Failure retains available facts plus sibling procedure_error=
{phase,code}, then fails safely. Shared closed routing codes/fixed safe messages
apply. No native stderr, paths, key/chain, token or arbitrary exception output.
Exit zero alone is not readiness.

Certificate errors use phases validate/observe/stage/apply/probe/renew/remove/
restore and codes routing_input_invalid, native_tool_unavailable,
certificate_state_changed, certificate_material_invalid, certificate_issue_failed,
certificate_serving_unverified, certificate_renewal_unavailable, restoration_failed.
Examples of fixed messages: "Server configuration changed. Refresh its observation
before retrying." and "Previous Server configuration could not be restored.
Resolve retained cleanup liability." Native exceptions are never interpolated.

A complete selection-only absence result (illustrative UTC timestamp):

~~~json
{"certificate_observation":{"outcome":"succeeded","observed_at":"2026-10-07T00:00:00Z","presence":"absent","source":null,"material_id":null,"revision_id":null,"leaf_fingerprint_sha256":null,"not_before":null,"not_after":null,"selected_hosts":[],"binding_count":0,"hosts":[],"renewal":null}}
~~~
