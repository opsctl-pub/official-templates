# Routing, Certificate And Verification Procedures

## Verification

`private_http_verify` uses `health_verify.yml`; `private_backend_verify` uses
`container_inspect.yml`. They observe only and never install tooling or change
containers, routes or certificates. Ordinary health HTTP/TCP inputs are unchanged.

| Input | Contract |
|---|---|
| `verification_kind` | `runtime_before`, `gateway`, `public_edge` or `runtime_after`. |
| `verification_target` | Required `container_name`, full `expected_container_id`, digest-pinned `image_ref`, canonical private/loopback `backend_url` and integer `container_port` (1..65535). |
| Gateway fields inside `verification_target` | Observed native `router_name` (1..128 characters), canonical DNS `host`, `gateway_port`, absolute `path`, integer `expected_status` (100..599), required nullable `body_contains`. Path and nonnull body assertion are at most 1024 UTF-8 bytes. |
| Public fields inside `verification_target` | Canonical approved public `destination`, distinct public `origin_address` and nonempty unique `cache_header_names` (maximum 64 names, 128 characters each). TLS uses system trust and `host` as SNI. |
| Common transport | Existing Server inventory and protected input delivery; `simulate=false`. Combined public input is bounded to 256 KiB. No nonce, digest, backend journal or preceding result is supplied. |

Runtime kinds run on the selected backend Server. Docker info must report the
exact full container ID, requested image and running state; report its actual
image config ID and start timestamp. They do not make an HTTP request.

Gateway/public kinds run on the gateway Server, not the backend Server. The
procedure observes its own gateway container; `traefik_container_name` defaults
to `traefik` and may be overridden locally. Gateway HTTP connects directly to
loopback at `gateway_port`; public HTTPS connects to `destination` with the
supplied hostname. Neither uses proxy environment settings nor follows redirects.
The public origin must be the gateway, not an alternate public destination.

The request helper performs at most ten attempts with three-second spacing.
Each request has a six-second total budget and reads at most 64 KiB. Each
attempt creates a local `X-Opsctl-Request-Id`, then reads at most 256 gateway
access-log entries/64 KiB within six seconds. Exactly one matching
`request_X-Opsctl-Request-Id` entry must identify the observed router, upstream,
host, method, path and status. `router_name` is the full provider-qualified native
opaque reference. The official file-provider procedure qualifies its parsed key
locally; the backend never appends or strips provider identity. `canary_router`
is naming intent, not that observed reference. Configured file state is not
serving evidence: verification corroborates the full `RouterName` and upstream
from request-correlated telemetry. Public checks additionally require actual
system-trusted hostname-verified TLS, destination, origin-side TLS and requested
cache response headers. No browser procedure runs.
Missing/duplicate correlation refuses success. Request bodies/assertion text
and correlation markers are never emitted.

### Results And Overrides

Emit one `TEMPLATE_OUTPUT_JSON` object containing `deployment_verification`:

- `outcome`: `succeeded`, `failed` or `incomplete`; `observed_at`: actual UTC RFC3339; `kind`: the primitive; `passed`: strict boolean.
- Request facts: nullable `status`, `body_match`, full `gateway_container_id`, `router_name`, canonical private `upstream`.
- Runtime facts: nullable full `container_id`, `image_id` (`sha256:` plus 64 hex characters), UTC `started_at`.
- Public facts: nullable `tls` (`status=verified|failed|not_checked|unknown` and nullable `leaf_fingerprint_sha256`; verified requires the observed leaf), canonical `destination`, `origin_tls_observed`, `cache_headers` (bounded ASCII values, 128 bytes each).

Include every nullable field explicitly. Unavailable facts are null, never
invented zero/false values. Runtime facts cannot claim request/public results;
request facts cannot claim a backend inspection. `passed=true` requires complete
successful facts for that kind. Never emit response bodies, secrets, local
paths/configuration or a copy of the request. Combined named outputs are bounded
to 128 KiB. Exit zero without complete facts is not success.

On refusal, emit available facts and sibling
`procedure_error={phase,code}` before failing the Job. Verification uses phases
`validate`, `observe`, `probe` and codes `routing_input_invalid`,
`native_tool_unavailable`, `verification_identity_changed`,
`verification_failed`, `verification_upstream_unverified`; no native error text.

An organization override may replace these items with its own Docker-info and
HTTP/telemetry tasks. It must consume the same public variables, observe its own
native layout, retain these bounds and produce the same plain facts; it need not
know any OpsCtl journal, signing scheme or proxy configuration format. Backend
sequencing separately consumes runtime-before, request, runtime-after and
requires the same original container/image/start identity within its deadline.

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

## Routes And Temporary Canaries

Common inputs identify the Deployment, organization and target Server through
the existing inventory. Ports are strict integers 1..65535; normalized hosts are
sorted/unique (maximum 100), private/loopback endpoints unique (maximum 64).
Middleware references are opaque strings (maximum 255 characters, 50 entries).
`simulate=true` changes nothing and supplies no consumed success.

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

`traefik_backend_canary` adds `action=observe|converge_present|converge_absent`,
`promotion_id`, `gateway_id`, `target_node_id`, `target_revision_id`, one admitted
temporary `route_hosts` entry, `canary_router` naming intent, `route_port` and
one approved `traefik_backends` entry. Mutations require `expected_canary` with
exactly `presence`, `host`, `router_name`, `backends`; observe has no expectation.
Return `promotion_canary_observation` with that snapshot plus outcome/time.
Absent/unknown uses null host/router and empty backends. Keep the temporary
router private-only. Never recompute a backend naming digest in an override.
The full observed provider reference is opaque; neither configured presence nor
successful publication establishes active serving (see Verification).

## WireGuard References

Ensure returns actual `wireguard_interface` and `wireguard_service` alongside
the existing IP/key. Route/bootstrap observation returns
`gateway_bootstrap_observation={interface,ipv4,public_key,service,route_backend_urls,observed_at}`;
service is `{manager,name,state:active|inactive|unknown}`. Interface/name/manager
limits are 15/255/32 characters. Subsequent observation/cleanup receives recorded
`gateway_interface`/`gateway_service`; never reconstruct Deployment-prefix names.
Missing references are unknown. Observe address/key/backends and active state;
absence must be consumed before removing the recorded gateway entry.

## Drain And Image Removal

Gateway `lb_backend_drain_detach` takes `phase=gateway`, `retiring_backend`,
nonempty `remaining_backends`, `expected_route` and the route subject. Observe
the already-switched route and exact exclusion; no sleep-as-drained result.
Ordinary detach uses explicit `phase=converge`: complete `RouteConvergeInput`
plus `retiring_backend` and `remaining_backends`. Its frozen pre-withdrawal CAS
must contain the retiring endpoint; desired endpoints equal the remaining set.
The same child withdraws then observes exclusion. Missing phase refuses.

Only after consumed exclusion, the normal `container_remove` child takes optional
`drain_before_remove={container_id,container_port,timeout_s}` with exact full ID,
strict port and timeout default 120s, allowed 1..120. Preserve ordinary image
removal/resource retention inputs documented in `container_remove.md`.
Ansible polls read-only counts, rechecks the incarnation, then performs normal
Docker stop/remove with separate stop_timeout 10s. The count helper only reads;
it never waits, changes namespaces/firewalls, or removes a container.
Unknown identity/count refuses removal. Already observed absent is idempotent
without inventing a count. At grace expiry, a known positive count permits normal
termination and is reported honestly as the last pre-stop observation.

Return `connection_drain` with outcome/time, `phase=gateway|runtime`,
`state=clear|timed_out|unknown|failed`, nullable `remaining_backends`, full
`container_id` and `active_inbound_connections`. Gateway clear has nonempty
remaining backends and null runtime fields; runtime clear has exact ID/count 0;
timed_out has known positive count; unknown count is null. Final removal also
requires complete `image_runtime` absence in the SAME named-output object,
including empty unmanaged resource lists. Counts are last observed, not live or
an exact tally of disconnected clients. No barrier/netns/digest receipt is input
or output. Emit available facts plus closed `procedure_error` on refusal; missing
facts, unknown state and exit zero alone never authorize lifecycle advancement.
