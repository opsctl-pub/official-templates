# Native Compose removal

Register `ansible/playbooks/compose_remove.yml` as high-impact Ansible item
`compose_remove`, logical type `remove_container`, through the existing accepted
Admin source/override flow. Normal inventory/SSH access applies. This item needs no
source files, registry Secret, generated Compose model or private protocol.

## Inputs

| Variable | Default | Origin/contract |
|---|---|---|
| `compose_project_name` | required | Recorded native project name. |
| `compose_workspace` | required | Stable absolute backend Server/project workspace; retained, never recursively removed. |
| `compose_services` | required | Up to 32 captured `{name,replicas,condition,allow_completion:false}`; total replicas<=128; same conditions as deploy. |
| `compose_known_containers` | `[]` | Up to 128 recorded full Docker IDs eligible for exact removal. |
| `compose_known_networks` | required list, may be empty | Up to 64 recorded `{id,name,origin:created|reused|external|unknown}`. Unknown ownership refuses mutation. |
| `compose_known_volumes` | `[]` | Up to 64 recorded `{name,created_at,origin}`, nullable timestamp; unknown incarnation remains incomplete, not deletion permission. |

Observe current project members and recorded incarnations/users before effects.
Unknown project IDs or replaced resources refuse before mutation. Remove only
recorded container IDs with `docker_container`, `keep_volumes=true`, normal stop
timeout, no forced kill. Reobserve absence. Only recorded `created` networks with
the same full ID and no users can be removed. Use approved `builtin.command` argv
`[docker,network,rm,--,qualified_full_ID]`: pinned docker_network removal forcibly
disconnects users, whereas this native no-force seam retains daemon in-use refusal.
Pre/post facts remain standard info modules. No shell/detach/helper is used.

Keep reused/external networks, every named/anonymous volume, source workspace,
bind data and images. Foreign users on retained reused/external networks do not
block removal of the recorded containers; deletion-specific user exclusivity
applies only to qualified created networks. Incarnation checks still cover all
recorded networks. There is no down, volume deletion, prune, prefix sweep or
rollback. Already absent identities are idempotent observed absence. Failure after
some effects retains safe partial facts, not an automatic retry or success claim.

## Results

Exactly one final `TEMPLATE_OUTPUT_JSON={"compose":...}` precedes fixed failure.

| Field | Meaning |
|---|---|
| `action`, `project_name`, `project_directory` | `remove`, native name, `.` for identity-only removal. |
| `observed_at` | UTC RFC3339 or null if observation failed. |
| `outcome`, `observation_complete`, `changed` | `succeeded|failed|unknown`, complete facts boolean, actual effects boolean. |
| `ready` | Always null; retained data presence is not failed absence. |
| `phase`, `reason` | Actual prepare/remove/observe/complete phase, null or closed safe reason. |
| `files_written` | Empty. |
| `services` | `{name,desired_replicas,condition,state,instances}`; captured desired services can be missing after successful removal. |
| `unexpected_containers` | Project extras, never implicitly removed. |
| `networks` | `{id,name,origin,presence:present|absent|unknown}`; absence retains recorded ID. |
| `volumes` | `{name,created_at,origin,presence}` including anonymous retained references. |
| `removed_containers` | Full IDs actually reobserved absent, not just successfully stopped. |

Instance fields are `{id,name,replica,image_ref,image_id,image_digest,state,health,
exit_code,ports,mounts}`. Replica/digest/exit_code nullable; state/health and all
service-state literals follow [deployment](compose_deploy.md#results). Ports are
`{host_ip,host_port,container_port,protocol:tcp|udp}`; mounts
`{type:volume|bind|tmpfs|other,source,target,read_only}`. No env/options/labels/health
commands/native errors or backend attribution IDs are exposed.

Closed reasons are listed in [deployment](compose_deploy.md#results); removal uses
prerequisite_unavailable, resource_changed, resource_in_use, remove_failed,
observation_failed/limit with the `compose_` prefix. OPERATION_STEP carries fixed
display text, actual running/completed/failed status and safe reason. Bounds: 256
KiB, 32 services, 128 total instances, 64 networks/volumes, 256 ports and 128 mounts
per instance. Overflow is explicit incomplete/unknown, not truncated success.
Incomplete partial facts do not release backend references. Job failure stays
failure even if earlier facts looked successful.

## Example

```yaml
compose_project_name: metrics
compose_workspace: /var/lib/opsctl/compose/00000000-0000-0000-0000-000000000001/projects/metrics/workspace
compose_services: [{name: prometheus, replicas: 1, condition: running}]
compose_known_containers: [aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]
compose_known_networks: [{id: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc, name: metrics_default, origin: created}]
compose_known_volumes:
  - {name: metrics_data, created_at: '2026-10-06T12:00:00Z', origin: created}
  - {name: shared, created_at: '2026-10-01T12:00:00Z', origin: external}
```

Full result with created network removed and all created/external data retained:

```json
{"compose":{"action":"remove","project_name":"metrics","project_directory":".","observed_at":"2026-10-06T12:10:00Z","outcome":"succeeded","observation_complete":true,"changed":true,"ready":null,"phase":"compose:complete","reason":null,"files_written":[],"services":[{"name":"prometheus","desired_replicas":1,"condition":"running","state":"missing","instances":[]}],"unexpected_containers":[],"networks":[{"id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","name":"metrics_default","origin":"created","presence":"absent"}],"volumes":[{"name":"metrics_data","created_at":"2026-10-06T12:00:00Z","origin":"created","presence":"present"},{"name":"shared","created_at":"2026-10-01T12:00:00Z","origin":"external","presence":"present"}],"removed_containers":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}}
```

An org override can implement this documented native procedure
without OpsCtl API imports, custody hashes or attribution echoes.
