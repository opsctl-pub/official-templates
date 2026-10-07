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
