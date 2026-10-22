# Gateway ensure procedure

`traefik_gateway_ensure.yml` is the replaceable Ansible entrypoint for ensuring
one managed Traefik gateway. The adjacent JSON declaration describes its
version1 completion-only result.

## Inputs and behavior

The backend forwards `server_id`, `target_server`, `target_server_ip`, `org_id`
and `simulate` (default `false`). Target fields identify the authorized execution
placement; `org_id` identifies the managed runtime's organization. The execution
owner supplies SSH transport privately. Scaling's route hosts, port, HTTPS,
middlewares and email arguments are not forwarded as this procedure's inputs.
They do not authorize route or certificate configuration here.

The official procedure installs/starts Docker and ensures its managed Traefik
runtime. It checks organization/management labels, immutable image identity,
runtime command, host networking, mount layout and native ping readiness.
An unmanaged container or unmanaged public listener conflicts rather than being
adopted. Cross-major replacement is guarded. Existing runtime restoration is
attempted if replacement fails; this is not an atomicity guarantee. Failure or
interruption may leave changes requiring the ordinary owning lifecycle to settle.
The procedure and its included tasks define image/version, container naming,
file layout and verification.

## Completion and limits

There is no `TEMPLATE_OUTPUT_JSON` result contract or persisted native identity
consumed from this entrypoint. Normal successful completion means the procedure
verified its gateway runtime during that invocation. The backend retains the
executing child/source/placement and ordinary completion sequencing; scaling then
continues overlay setup. An override may change implementation while preserving
the approved intent and completion semantics.

Progress uses `traefik:start`, `traefik:ready`, `traefik:complete`, and
`traefik:failure`; failure propagates through the ordinary failed execution.
Missing completion, failed or uncertain execution is not readiness. `simulate:true`
ends the play before effects and native checks; its completion is not native
readiness. There is no absent/removal mode, absence result or absence consumer.

Completion reports checks made during the run, not ongoing gateway health.
TLS, routes, backends, public reachability and application health have separate
checks. Never include private transport material or raw private native errors
in declarations or progress metadata.
