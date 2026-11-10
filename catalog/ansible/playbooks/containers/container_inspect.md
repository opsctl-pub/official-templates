# Inspect an image container

`container_inspect.yml` is read-only Ansible item `container_inspect`, logical type
`inspect_deployment`. Use its existing Official Sources registration or Automation
Override and normal inventory/SSH access, not source Secrets/registry credentials.
Compose projects use the separate [compose_inspect](../compose/compose_inspect.md) item.

## Inputs

| Variable | Default | Origin/meaning |
|---|---|---|
| `app_container_name` | `app` | Captured native image target name. |
| `app_previous_container_id` | null | Optional recorded full predecessor ID to observe, never adoption authority. |
| `app_observe_volumes` | `[]` | Up to64 `{name,created_at}` references; recorded timestamps required nonempty strings. |
| `app_observe_networks` | `[]` | Up to64 `{id,name}` full-ID references. |
| `collect_resource_usage` | `false` | Optional usage snapshot for the recorded, observed-running container only. |

Every ordinary image inspection emits image_runtime through the shared info modules,
including workloads without managed references (empty resource lists).
It observes the named target, predecessor by full ID, all stopped/running Volume
users, and Networks by full ID; mismatching/unavailable volume incarnation means
unknown/incomplete. No object is created, started, stopped, deleted or adopted.

Inspection reads only the named target, never a label-selected candidate. No
organization/Project/application label is used to adopt a replacement. The former
singular inspection result and inspect:result metadata are not emitted.

When `verification_kind` is supplied, the separate private verification procedure
uses `verification_target` with exact container/image/backend/port identity and,
for gateway/public_edge, the admitted HTTP assertions within that same target.
Kinds are runtime_before, runtime_after, gateway and public_edge. The full input
and deployment_verification result contract is documented in the shared
[verification procedure](../health/health_verify.md#verification).
It is separate from image storage evidence and ends the play instead of running
ordinary image inspection.

## Plain Results

The adjacent [version1 declaration](container_inspect.contract.json) includes four
`image_runtime` examples: ready present, present but not ready, absent, and
incomplete with null readiness. Predecessor observation is independent and
nullable. The declaration covers image observations, not `verification_kind`,
`deployment_verification` or private HTTP verification.

Every ordinary image inspection emits one `TEMPLATE_OUTPUT_JSON={"image_runtime":...}`:

| Field | Meaning |
|---|---|
| `action` | `inspect`. |
| `observation_complete` | All required observations complete within bounds. |
| `ready` | Current running/health boolean when complete; null for every incomplete observation. |
| `container` | Actual safe instance or null for absent/unavailable target. |
| `previous_container_absent` | Actual full-ID absence boolean or null without successful predecessor lookup. |
| `volumes` | `{name,created_at,presence,users:[{id,state,read_only}]}`; timestamp nullable only in observed results. |
| `networks` | `{id,name,presence,containers:[fullDockerID]}`. |

Presence is `present|absent|unknown`. Instance is
`{id,name,replica:null,image_ref,image_id,image_digest,state,health,exit_code,ports,mounts}`;
digest is unambiguous native repo digest/null, exit_code integer/null. State and
health literals follow [image deployment](container_deploy.md#results). Ports:
`{host_ip,host_port,container_port,protocol:tcp|udp}`; mounts:
`{type:volume|bind|tmpfs|other,source,target,read_only}`. Source is volume name/bind
path/null. No env/options/health command/labels/credential/native error is projected.

### Optional resource usage

Only explicit inspectors use the shared
[`container_resource_usage.yml`](../../tasks/container_resource_usage.yml) task.
With `collect_resource_usage=true`, the running container must match the admitted
full64 `app_previous_container_id`. Compose uses the same task for its admitted
running instances; unexpected, replaced and stopped containers are never sampled.
An empty selection skips Docker entirely. Before launch the task requires1-128
unique full IDs; one literal-argv `docker stats --no-stream --no-trunc` batch must
return exactly those unique IDs, with only the fixed ID/CPU/memory formatter.
It uses the local socket, an isolated environment/temporary CLI config and Linux
`timeout`10s with `--kill-after=2s`; `always` removes its owned config. Collection
and validation tasks use `no_log`.

An instance may include `resource_usage:{observed_at,cpu_percent,memory_usage}`:
UTC sample completion time, finite nonnegative Docker CPU percentage (100 means
one logical core; values can exceed100), and Docker's bounded used/limit memory
string, for example `12.5MiB / 1GiB`. Memory retains reported precision and
cache-adjusted meaning, not inferred exact bytes. Missing, malformed, failed or
over-budget sampling omits this object, never substitutes zero or an old sample.
Usage does not affect readiness, observation completeness, identity or drift.
Deploy/remove and private verification never invoke this task. The existing
Inspect action obtains another snapshot; there is no background collector.

Bounds:64 Volume/Network references,128 users per resource,256 ports/128 mounts per
instance,256KiB output. Unknown cannot release backend references or establish
readiness.

## Example

```yaml
app_container_name: sample
app_org_id: 11111111-1111-1111-1111-111111111111
app_slug: sample
app_previous_container_id: null
app_observe_volumes: [{name: sample-data, created_at: '2026-10-06T00:00:00Z'}]
```

Full complete result for absent workload with retained data:

```json
{"image_runtime":{"action":"inspect","observation_complete":true,"ready":false,"container":null,"previous_container_absent":null,"volumes":[{"name":"sample-data","created_at":"2026-10-06T00:00:00Z","presence":"present","users":[]}],"networks":[]}}
```

Progress emits inspect:start with the target name; the image_runtime envelope
above is the ordinary inspection result. Incomplete observations retain available
facts and ready=null, never inferred identity, absence or readiness.
