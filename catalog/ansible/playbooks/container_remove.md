# Image container removal

`container_remove.yml` removes one ordinary-image deployment. Register this
Ansible subpath as `container_remove` through the existing Admin catalog flow;
removal remains high-impact. Compose projects use the separate `compose_remove`
item, never this procedure.

## Inputs

The existing inventory/SSH target and privilege escalation apply. Required
variables are `app_managed=true`, `app_container_name`, `app_org_id`,
`app_deployment_id`, and `app_slug`. The organization and deployment are canonical
UUIDs. The container must have the matching existing `com.opsctl.*` labels.
`app_expected_image_ref` defaults to null; a value must equal the observed
container's configured image reference.

Managed native resources use these additional public variables:

| Variable | Default | Meaning |
|---|---|---|
| `app_previous_container_id` | null | Recorded full Docker ID. When supplied, a present named container must match; null authorizes only an absent target, not adoption. |
| `app_observe_volumes` | `[]` | Up to 64 `{name,created_at}` references, including retiring volumes. `created_at` is a required recorded nonempty native timestamp. |
| `app_observe_networks` | `[]` | Up to 64 `{id,name}` references; IDs are full native Docker IDs. |

Omitting the predecessor variable retains the ordinary label-qualified removal
path. New managed attachment callers supply it explicitly. Observations include
stopped users; read-only mounts remain users, not permission to delete data.

The separate existing route-retirement and promotion-drain inputs remain owned
by their routing procedures. Their output keys are preserved separately from
`image_runtime`; image resource observation is not route or connection evidence.

## Procedure And Retention

Inspect the target and check ownership/image/predecessor before effects. Preserve
the existing qualified route-retirement/drain sequence. Remove only the inspected
immutable ID through `community.docker.docker_container`, with a normal ten-second
stop timeout and `keep_volumes=true`. Reinspect that ID and the named target;
observe referenced volumes, all their users, networks and the recorded predecessor.
No network, volume, bind data, image, workspace or unrelated container is deleted.
Confirmed absence is idempotent; Docker connectivity failure is not absence.
An unavailable or mismatching observed volume timestamp is unknown/incomplete,
never permission to adopt a replacement. Null timestamps occur only in results
when observation is unavailable, not in supplied incarnation references.

## Plain Results

One final `TEMPLATE_OUTPUT_JSON` contains `image_runtime`, plus any independently
qualified route/drain results. `image_runtime` has exactly these fields:

| Field | Value |
|---|---|
| `action` | `remove` |
| `observation_complete` | Boolean; false on unknown, changed or unavailable observations. |
| `ready` | null for removal. |
| `container` | null after confirmed named-target absence; otherwise the safe instance below. |
| `previous_container_absent` | Boolean after an actual predecessor lookup; null if no predecessor was supplied or lookup was unavailable. |
| `volumes` | `{name,created_at,presence,users:[{id,state,read_only}]}`; presence is `present`, `absent` or `unknown`. |
| `networks` | `{id,name,presence,containers:[fullDockerID]}` with the same presence values. |

A safe instance is `{id,name,replica,image_ref,image_id,image_digest,state,health,
exit_code,ports,mounts}`. For an image container `replica` is null; unavailable
digest/exit code is null. State is `created|running|restarting|paused|exited|dead|
removing|unknown`; health is `healthy|unhealthy|starting|none|unknown`.
Ports are `{host_ip,host_port,container_port,protocol}` with integer ports and
`tcp|udp`. Mounts are `{type,source,target,read_only}`: type is
`volume|bind|tmpfs|other`; source is the volume name, native bind path or null.
No environment, labels, health command/output or native error text is published.

Each volume/network user inventory is bounded to 128 and the entire emitted
envelope to 256 KiB. Overflow refuses publication as success. Incomplete facts
cannot release backend attachment references. Available incomplete facts are
published before a fixed failure; neither exit zero nor a stop response proves
absence. These are native observations, not backend identity receipts.

Example after a successful removal retaining a volume and network:

```json
{"image_runtime":{"action":"remove","observation_complete":true,"ready":null,"container":null,"previous_container_absent":true,"volumes":[{"name":"example-data","created_at":"2026-10-06T00:00:00Z","presence":"present","users":[]}],"networks":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"example-network","presence":"present","containers":[]}]}}
```

An organization override can implement the same documented native checks and
facts with normal modules. It needs no private API imports, attachment IDs,
protocol versions, proof hashes or internal receipt algorithms.
