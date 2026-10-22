# Image container removal

`container_remove.yml` removes one image deployment through the existing
`container_remove` catalog registration or Automation Override. Removal is
high-impact. Compose projects use the separate `compose_remove` item.

## Inputs

The existing inventory/SSH target and privilege escalation apply. Required
variables are `app_managed=true`, `app_container_name`, `app_org_id`,
`app_deployment_id`, and `app_slug`. The organization and deployment are canonical
UUIDs. The container must have exactly matching ownership values:
`com.opsctl.managed=true`, `com.opsctl.org_id=app_org_id`,
`com.opsctl.deployment_id=app_deployment_id`, and `com.opsctl.app=app_slug`.
Additional labels are not removal authority and need not be absent.
`app_expected_image_ref` defaults to null; a value must equal the observed
container's configured image reference.

Managed native resources use these additional public variables:

| Variable | Default | Meaning |
|---|---|---|
| `app_previous_container_id` | null | Recorded full Docker ID. When supplied, a present named container must match; null authorizes only an absent target, not adoption. |
| `app_observe_volumes` | `[]` | Up to 64 `{name,created_at}` references, including retiring volumes. `created_at` is a required recorded nonempty native timestamp. |
| `app_observe_networks` | `[]` | Up to 64 `{id,name}` references; IDs are full native Docker IDs. |
| `app_secret_file_cleanup_incarnation` | omitted | Previous file-owning Operation UUID; requires the recorded predecessor variable and confirmed container absence. |

Omitting the predecessor variable keeps the ordinary removal path, which selects
the container by its labels. New managed attachment callers supply it explicitly. Observations include
stopped users; read-only mounts remain users, not permission to delete data.

Whole-image retirement supplies `app_route_retirement`, containing only the
public `RouteConvergeInput` documented in [route procedure](../gateways/traefik/traefik_route_converge.md#route-inputs-and-observations),
with `route_state=absent` and the full consumed `expected_route` snapshot.
This same child checks the snapshot, withdraws the route and reobserves absence
before removing the image. Already-observed absence is idempotent; unknown or
changed present routes refuse removal. Caddy retirement is unsupported here.
Sibling `deployment_route_observation` and `image_runtime` report the observed
route and runtime state.

Promotion removal supplies `drain_before_remove={container_id,container_port,
timeout_s}` only after the gateway has stopped sending it traffic. The full ID is required;
timeout defaults to 120 seconds, allowed 1..120. This SAME child polls read-only
counts, rechecks the incarnation, then performs normal ten-second stop/removal.
Unknown counts refuse removal; a positive count at grace expiry is reported as
`timed_out` before normal termination. Already absent has no invented count.
Sibling `connection_drain` records last-observed count/time/outcome, not a live
count or exact disconnected-client tally. Combined route/drain/image output is
bounded to 128 KiB. No gateway receipt, firewall barrier or namespace mutation is input.

## Procedure And Retention

Inspect the target and check ownership/image/predecessor before effects. When requested,
route retirement and then connection draining run before removal. Remove only the inspected
immutable ID through `community.docker.docker_container`, with a normal ten-second
stop timeout and `keep_volumes=true`. Reinspect that ID and the named target;
observe referenced volumes, all their users, networks and the recorded predecessor.
No network, volume, bind data, image, workspace or unrelated container is deleted.
Only this workload's staged secret files are removed, after its exact full
container ID is confirmed absent. The retained manifest and
[shared helper](../../tasks/container_secret_files.yml) identify the files and their
directory. Missing or different ownership, symlinks and uncertain absence refuse
cleanup. Other Operations' files and neighboring files remain. Per-job Secret
cleanup does not remove live workload files; they stay on disk until removal.
The adjacent optional `workload_files={version:1,capability:cleanup}` declares this
support. Without it, ordinary no-file removal remains valid, but staged-file
cleanup requires this capability from the exact source selected at review.
Confirmed absence is idempotent; Docker connectivity failure is not absence.
An unavailable or mismatching observed volume timestamp is unknown/incomplete,
never permission to adopt a replacement. Null timestamps occur only in results
when observation is unavailable, not in supplied incarnation references.

## Plain Results

When removal reaches final observation it emits `TEMPLATE_OUTPUT_JSON` containing
`image_runtime` (empty resource lists when unmanaged), plus any route and drain
results. `image_runtime` has exactly these fields:

| Field | Value |
|---|---|
| `action` | `remove` |
| `observation_complete` | Boolean; false on unknown, changed or unavailable observations. |
| `ready` | null for removal and for every incomplete image observation, including deploy. |
| `container` | null after confirmed named-target absence; otherwise the safe instance below. |
| `previous_container_absent` | Boolean after an actual predecessor lookup; null if no predecessor was supplied or lookup was unavailable. |
| `volumes` | `{name,created_at,presence,users:[{id,state,read_only}]}`; presence is `present`, `absent` or `unknown`. |
| `networks` | `{id,name,presence,containers:[fullDockerID]}` with the same presence values. |

The adjacent [version1 declaration](container_remove.contract.json) includes four
`image_runtime` examples: recorded predecessor absent, target absent without a
predecessor, present/not removed, and incomplete with null readiness. A refusal
does not always emit one of these shapes.

Early identity, inspection or route checks can refuse before final image facts.
Drain failure may emit only `connection_drain` with `procedure_error`, without
`image_runtime`. Missing image facts never establish absence. Optional route/drain
siblings have separate result contracts and combined-envelope limits.
An omitted predecessor input remains distinct from explicit null (absent target
only) and a full recorded ID. A null public predecessor observation does not prove
the predecessor is gone, so callers that need that proof get no confirmation from it.

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
absence.

## Progress

Progress uses `remove:start` and `remove:complete`, including the already-absent
case. Optional route withdrawal retains its separate `traefik-route:*` steps.
Completion markers do not replace the required final absence/resource observations.

Example after a successful removal retaining a volume and network:

```json
{"image_runtime":{"action":"remove","observation_complete":true,"ready":null,"container":null,"previous_container_absent":true,"volumes":[{"name":"example-data","created_at":"2026-10-06T00:00:00Z","presence":"present","users":[]}],"networks":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"example-network","presence":"present","containers":[]}]}}
```

## Runtime drain observations

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
