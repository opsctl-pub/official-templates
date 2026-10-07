# Ordinary image inspection

`container_inspect.yml` is read-only Ansible item `container_inspect`, logical type
`inspect_deployment`. Register/override through existing Admin accepted-source
flow. Use normal inventory/SSH access, not source Secrets/registry credentials.
Compose projects use the separate [compose_inspect](compose_inspect.md) item.

## Inputs

| Variable | Default | Origin/meaning |
|---|---|---|
| `app_container_name` | `app` | Captured native image target name. |
| `app_org_id` | empty | Expected existing managed organization label. |
| `app_project_id` | empty | Optional expected Project label. |
| `app_slug` | container name | Expected application label. |
| `app_previous_container_id` | null | Optional recorded full predecessor ID to observe, never adoption authority. |
| `app_observe_volumes` | `[]` | Up to64 `{name,created_at}` references; recorded timestamps required nonempty strings. |
| `app_observe_networks` | `[]` | Up to64 `{id,name}` full-ID references. |

The existing singular image inspection/progress output stays unchanged. Every
ordinary image inspection also emits image_runtime through the shared info modules,
including workloads without managed references (empty resource lists).
It observes the named target, predecessor by full ID, all stopped/running Volume
users, and Networks by full ID; mismatching/unavailable volume incarnation means
unknown/incomplete. No object is created, started, stopped, deleted or adopted.

The private HTTP verification include remains a separate E-owned procedure.
Its verification inputs/output are not image storage evidence; combined source
reconciliation preserves that seam rather than adding a second verifier here.

## Plain Results

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

Bounds:64 Volume/Network references,128 users per resource,256 ports/128 mounts per
instance,256KiB output. Unknown cannot release backend references or establish
readiness. This is native observation, not proof hashes or attribution echoes.

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

An override needs only these native references/fields and existing image inspect
contract; it does not import backend APIs or synthesize resource identity receipts.
