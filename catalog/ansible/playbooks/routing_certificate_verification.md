# Routing, Certificate And Verification Procedures

## Certificates

Trusted privileged templates own native layout and procedures; backend admission
chooses authority, issuer, hosts, material and sequencing. Existing inventory/SSH,
target and organization fields remain. No private receipt, binding program,
API-selected remote layout or compatibility controller is accepted.
simulate=true ends without changes or consumed success.

### Server Dashboard Setup

Dashboard setup admits automatic issue for an exact Server subject without a
backend-invented preimage. Before dashboard, runtime, broker or renewal mutation,
it reads the native five-field snapshot in explicit selection-only mode, with
host probes disabled and no running-gateway or enrollment prerequisite. Absolute
template-owned selection paths and ancestors must be root-owned, unlinked and
of the expected type. Actual missing selection/ancestors may establish absence;
unreadable, foreign, malformed or changed state remains unknown. Only a successful
absent or automatic selection is admitted; custom/native/unknown refuses setup.
The captured snapshot becomes local expected_certificate. After runtime converge,
unchanged generic issuance reobserves/compares it before mutation, preserving final
serving, enrollment and restoration. Existing automatic material may change to
the admitted hostname for that same Server. The helper's explicit --selection-only
returns exactly the five snapshot fields and skips probes/enrollment; its default
observation and --snapshot behavior remain unchanged.

### Public Inputs

All items take certificate_subject={type:deployment|server,id:UUID} and route_hosts
(sorted unique normalized DNS names, maximum100). Mutation requires exactly
expected_certificate={presence,source,material_id,revision_id,leaf_fingerprint_sha256}.
Absent has four nulls; present requires source/fingerprint; custom requires both
IDs, native revision, automatic IDs may be null. UUIDs are canonical lowercase.
Unknown never authorizes mutation. Material/trust keeps the existing256KiB bound.

| Item | Additional inputs and behavior |
|---|---|
| traefik_certificate_selection_observe | No expected snapshot/material. Selection only, hosts=[] in output, no serving claim. |
| traefik_https_observe; traefik_custom_certificate_observe | Probe every requested host. Optional private trust_bundle_pem=null selects system trust; otherwise supplied trust. |
| traefik_automatic_certificate | certificate_action=issue/retry/renew, expected snapshot, acme_email3..320, admitted HTTPS acme_directory_url, challenge=http-01/dns-01, renewal_enabled=true. HTTP requires null broker_url/broker_token_source_file. DNS requires approved broker_url, runner broker_token_source_file and existing dns_challenge_token_revision_id/dns_challenge_token_content_digest custody binding. |
| traefik_automatic_certificate_retire | Expected snapshot. Disable only subject enrollment and remove matching automatic selection. Preserve custom/native selection and material; no account purge/revocation/sweep. |
| traefik_custom_certificate_install | Deployment subject, material_id/revision_id/leaf_fingerprint_sha256, expected snapshot. certificate_source_dir defaults /var/run/opsctl/file-secret with protected tls.crt/tls.key; existing content_digest checked before delivery. |
| traefik_custom_certificate_unbind | Same identities/expected snapshot, no chain/key input; remove only matching custom selection, retain unused pair. |
| traefik_native_certificate | native_certificate_action=csr/install/observe/retire, subject, hosts, revision_id. CSR creates/reuses local EC P-256 key. Install adds certificate_chain_pem, trust_bundle_pem, leaf_fingerprint_sha256 and expected snapshot. Observe needs no material. Retire requires previous_revision_id and current expected snapshot after backend revocation/unused authorization; actual native references checked before exact unused revision deletion. |

Observe never creates directories, installs tools or mutates configuration.
Missing tooling or unreadable/changed native references is unknown, not absence.

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
not_before/not_after, selected_hosts, nullable binding_count, hosts=[{hostname,
served:matched/mismatch/unreachable/unknown,trusted:bool|null,
leaf_fingerprint_sha256:string|null}], renewal. Automatic renewal is
{enabled:bool|null,active:bool|null,next_due_at:UTC|null}; other sources use null.
Selection-only hosts=[] never claims serving. Retirement adds automatic_retired
or retired_revision_absent, nullable and true only after actual corresponding
absence/disabled enrollment.

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

Custom switching supplies the actually observed automatic leaf in the expected
snapshot plus admitted custom IDs/fingerprint/protected files. Success requires
actual custom selection and all-host matched/trusted facts; automatic retirement
is not inferred. Unreachable hosts report served=unreachable with null trust/leaf
and failed outcome, retaining available selected material. Native CSR success
means only public CSR/key identity, never serving readiness.
