# Native Compose inspection

Register `ansible/playbooks/compose_inspect.yml` as read-only Ansible item
`compose_inspect`; logical type remains `inspect_deployment`. Use the existing
Admin accepted-source/override flow and inventory/SSH connection. No source files,
registry credentials, Compose apply, image pull, login, creation or deletion occur.

## Inputs

| Variable | Default | Origin/contract |
|---|---|---|
| `compose_project_name` | required | Captured native project name. |
| `compose_workspace` | required | Backend stable absolute Server/project workspace; not read or removed. |
| `compose_services` | required | Up to 32 captured `{name,replicas,condition,allow_completion:false}`; replicas0-128/total128; condition `running|healthy|completed|scaled_down`. |
| `compose_known_containers` | `[]` | Up to 128 recorded full Docker IDs; missing IDs are observed, not fabricated instances. |
| `compose_known_networks` | `[]` | Up to 64 `{id,name,origin}`; origin `created|reused|external|unknown`. |
| `compose_known_volumes` | `[]` | Up to 64 `{name,created_at,origin}`; nullable timestamp, same origins. |

Native project listing includes stopped instances. Inspect each current/recorded
ID, resource incarnation and image through info modules. Readiness covers all
replicas and inherited health, strict completed dependency exit-zero and captured
standalone completion alternative. Extras are visible drift, not adopted ownership.
No original file replay is necessary. Unknown/replaced resource incarnations remain
incomplete. Stopped/unhealthy/missing work is a successful complete inspection with
ready=false, not a failed read.

## Results

One final `TEMPLATE_OUTPUT_JSON={"compose":...}` has the following full field set;
the detailed neutral instance vocabulary is in [deployment](compose_deploy.md#results).

| Field | Meaning |
|---|---|
| `action`, `project_name`, `project_directory` | `inspect`, actual name, `.` for identity-only inspection. |
| `observed_at` | UTC RFC3339 or null on failed observation. |
| `outcome`, `observation_complete`, `changed` | `succeeded|failed|unknown`, boolean completeness, always false for changed. |
| `ready` | Complete readiness boolean, otherwise null. |
| `phase`, `reason` | `compose:observe|compose:complete`; null or closed observation failure/limit reason. |
| `files_written`, `removed_containers` | Empty arrays; inspect performs no delivery/removal. |
| `services` | `{name,desired_replicas,condition,state,instances}`; state `running|healthy|starting|completed|scaled_down|stopped|failed|missing|unknown|drifted`. |
| `unexpected_containers` | Instances outside captured/selected project membership. |
| `networks` | `{id,name,origin,presence:present|absent|unknown}`; absent recorded networks retain ID. |
| `volumes` | `{name,created_at,origin,presence}` including mounted anonymous volumes; timestamp nullable. |

All instance fields are `{id,name,replica,image_ref,image_id,image_digest,state,
health,exit_code,ports,mounts}`. Replica/digest/exit_code may be null; ports contain
`{host_ip,host_port,container_port,protocol:tcp|udp}`, mounts
`{type:volume|bind|tmpfs|other,source,target,read_only}`. Digest is the unambiguous
native repo digest; source is volume name/bind path/null. No env, health commands,
labels, credentials, arbitrary errors or private proof fields are returned.

Bounds are 256 KiB, 32 services, 128 total instances, 64 networks/volumes, 256
ports/128 mounts per instance. Overflow explicitly emits incomplete/unknown.
OPERATION_STEP reports prepare/observe/complete with actual status, not health
success inferred from process exit. Available incomplete facts precede a fixed
failure; backend cannot promote or release references from them.

## Example

```yaml
compose_project_name: metrics
compose_workspace: /var/lib/opsctl/compose/00000000-0000-0000-0000-000000000001/projects/metrics/workspace
compose_services: [{name: prometheus, replicas: 1, condition: running}]
compose_known_containers: [aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]
```

Full result for an exited/nonzero desired service; observation succeeds, readiness
does not. Docker read failure instead returns unknown/null/false:

```json
{"compose":{"action":"inspect","project_name":"metrics","project_directory":".","observed_at":"2026-10-06T12:05:00Z","outcome":"succeeded","observation_complete":true,"changed":false,"ready":false,"phase":"compose:complete","reason":null,"files_written":[],"services":[{"name":"prometheus","desired_replicas":1,"condition":"running","state":"failed","instances":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"metrics-prometheus-1","replica":1,"image_ref":"prom/prometheus:v3.5.0","image_id":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","image_digest":null,"state":"exited","health":"none","exit_code":7,"ports":[],"mounts":[]}]}],"unexpected_containers":[],"networks":[],"volumes":[],"removed_containers":[]}}
```

An org override needs only these native inputs/plain facts and normal Ansible
access, not API packages, registry custody or source attribution echoes.
