# Native Compose removal

`compose_remove.yml` is the high-impact `compose_remove` Ansible item, with logical
type `remove_container`. Use its existing catalog registration or Automation
Override and normal inventory/SSH access. It needs no source files, registry
Secret or generated Compose model.

Retained settings staging requires this selected source's explicit
`settings_delivery:{version:1,capability:cleanup}` declaration. Its adjacent
documentation is still validated. An older undeclared source cannot perform file
cleanup; ordinary removal without retained staging keeps its original contract.

## Inputs

| Variable | Default | Origin/contract |
|---|---|---|
| `compose_project_name` | required | Recorded native project name. |
| `compose_project_directory` | `.` | Recorded confined relative project directory beneath the workspace, never a caller-selected replacement. |
| `compose_workspace` | required | Stable absolute backend Server/project workspace; retained, never recursively removed. |
| `compose_services` | required, may be empty | Retained wire field, not a removal service allowlist. Current service labels come from bounded full native inspection. |
| `compose_known_containers` | `[]` | Up to 128 recorded full Docker IDs retained as identity hints and absence checks, not a membership whitelist. |
| `compose_known_networks` | required list, may be empty | Up to 64 recorded `{id,name,origin:created|reused|external|unknown}`. Unresolved observed ownership refuses mutation. |
| `compose_known_volumes` | `[]` | Up to 64 recorded `{name,created_at,birth_marker,origin}`; nullable timestamp/marker means keep-only. |
| `compose_delete_volumes` | `[]` | Up to 64 unique explicit `{name,created_at,birth_marker}` selections; original created identity only. |
| `compose_managed_volumes` | `[]` | Exact existing `{name,created_at,labels}` managed bindings; retain data, verify local identity and no foreign users. Only the managed Volume owner deletes these external backings. |
| `compose_secret_file_cleanup_incarnations` | `[]` | Up to 128 exact retained Operation UUIDs, including admitted failed attempts; after workload absence, remove only their owned files if no native container still mounts the namespace. Requires admitted `app_org_id`, `app_deployment_id` and `server_id`. |

Observe current project members and recorded incarnations/users before effects.
Exact inspected local built-ins `none`/`null` and `host`/`host` are external when
no origin is recorded or a matching full recorded ID has unknown origin. Original
inputs stay unchanged; a recorded created origin is never replaced. Built-ins are
retained, while missing/mismatched or other unresolved unknown networks refuse.
Discover every current project instance using bounded full inspection. Require exact
project and working-directory labels, a nonempty bounded service label and non-oneoff identity;
a project label alone never proves ownership. Snapshot that verified current set before
effects, including owned replacements from failed updates. Unknown/foreign members
or changed resource incarnations refuse. Newly appearing members after the snapshot
refuse without expanding the deletion loop. Remove only those frozen current IDs
with `docker_container`, `keep_volumes=true`, normal stop
timeout, no forced kill. Reobserve absence. Only recorded `created` networks with
the same full ID and no users can be removed. Use `builtin.command` argv
`[docker,network,rm,--,full_ID]`: pinned docker_network removal forcibly
disconnects users, whereas this native no-force seam retains daemon in-use refusal.
Pre/post facts remain standard info modules. No shell/detach/helper is used.

Keep reused/external networks, every unselected volume, source workspace,
bind data and images. Foreign users on retained reused/external networks do not
block removal of the recorded containers; deletion-specific user exclusivity
applies only to networks this deployment created. Incarnation checks still cover all
recorded networks. Selected volumes require original creation ownership, exact
timestamp and opaque 64-lowercase-hex birth marker, Compose ownership labels, ordinary local backing and no foreign
container users (including stopped containers). Reobserve after workload removal,
then use only `docker volume rm -- <selected-name>` without force. External,
reused, unknown-incarnation and nonlocal volumes are never eligible. Already
absent selected incarnations preserve their recorded timestamp for exact replay.
No unselected data is deleted; retaining it does not protect Server-local data
against later Server deletion. Native observe/remove is not atomic against a
privileged concurrent host actor; the daemon still refuses in-use deletion.
The marker is identity metadata, not authority; a privileged actor can deliberately copy it.
Historical or preexisting unmarked volumes remain keep-only, without backfill.
There is no down, blanket volume removal, prune, prefix sweep or
rollback. Already absent identities are idempotent observed absence. Failure after
some effects retains safe partial facts, not an automatic retry or success claim.

## Results

Exactly one final `TEMPLATE_OUTPUT_JSON={"compose":...}` precedes fixed failure.

| Field | Meaning |
|---|---|
| `action`, `project_name`, `project_directory` | `remove`, native name, exact admitted recorded relative project directory. |
| `observed_at` | UTC RFC3339 or null if observation failed. |
| `outcome`, `observation_complete`, `changed` | `succeeded|failed|unknown`, complete facts boolean, actual effects boolean. |
| `ready` | Always null; retained data presence is not failed absence. |
| `phase`, `reason` | Actual prepare/remove/observe/complete phase, null or bounded root diagnostic reason. |
| `files_written` | Empty. |
| `services` | Current discovered names with the Destroy goal `desired_replicas:0,condition:scaled_down`; actual instances remain visible until absent. Final empty groups retain the frozen pre-effect names. No original-install membership is required. |
| `unexpected_containers` | Unqualified or newly appearing project members, never implicitly removed. |
| `networks` | `{id,name,origin,presence:present|absent|unknown}`; absence retains recorded ID. |
| `volumes` | `{name,created_at,birth_marker,origin,presence,delete_eligible,deletion_reason}`; absent entries retain recorded timestamps/markers. Eligibility is an observation, not consent; a fixed reason explains unavailable deletion. |
| `removed_containers` | Full IDs actually reobserved absent, not just successfully stopped. |

Instance fields are `{id,name,replica,image_ref,image_id,image_digest,state,health,
exit_code,ports,mounts}`. Replica/digest/exit_code nullable; state/health and all
service-state literals follow [deployment](compose_deploy.md#results). Ports are
`{host_ip,host_port,container_port,protocol:tcp|udp}`; mounts
`{type:volume|bind|tmpfs|other,source,target,read_only}`. No env/options/labels/health
commands/native errors or backend attribution IDs are exposed.

Current producer reasons are listed in [deployment](compose_deploy.md#results); removal uses
prerequisite_unavailable, resource_changed, resource_in_use, remove_failed,
observation_failed/limit with the `compose_` prefix. OPERATION_STEP carries fixed
display text, actual running/completed/failed status and safe reason. Bounds: 256
KiB, 32 services, 128 total instances, 64 networks/volumes, 256 ports and 128 mounts
per instance. Overflow is explicit incomplete/unknown, not truncated success.
Incomplete partial facts do not release backend references. Job failure stays
failure even if earlier facts looked successful.

The [root-only result evolution rules](compose_deploy.md#public-result-evolution) apply:
unknown root fields are projected away after the raw 256 KiB bound; any root
`procedure_error` key refuses even when null. New diagnostic codes never
mean success, removal or coverage. Nested identities/states remain closed;
exact complete/null-reason and recorded incarnation/absence guards are unchanged.
Projection does not redact raw markers/logs or authorize secret output.

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
