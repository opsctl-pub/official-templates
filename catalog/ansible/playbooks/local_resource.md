# Native local resource

`local_resource.yml` creates, inspects or removes one backend-named Docker volume
or network through the existing Ansible inventory/SSH connection. Register/override
the existing `local_resource` catalog item through Admin; do not create a second
transport. It uses standard native modules, not a private request program.

## Inputs

| Variable | Default | Contract |
|---|---|---|
| `local_resource_kind` | required | `volume` or `network`. |
| `local_resource_action` | required | `create`, `inspect` or `remove`. |
| `local_resource_name` | required | Existing backend-rendered native name. |
| `local_resource_driver` | `local` for volume; `bridge` for network | Exact native driver to create/compare. |
| `local_resource_labels` | required | Complete native identity label map to create/compare. |
| `local_resource_expected_incarnation` | null | Recorded Docker Volume CreatedAt or full Network ID; required for remove. |
| `simulate` | false | Exit before all observations/mutations; produces no consumed-effect result. |

No organization/resource/backing/generation admission program is passed to this
item. Backend identity, authorization, requested capacity and signed deletion
consent remain backend-owned. Capacity is informational, not enforced here.

Inspect never mutates. Create first inspects, refuses identity/driver/label changes
and only creates an absent object without a recorded previous incarnation. Remove
requires exact recorded identity and no users, including stopped/read-only volume
users. Native absence is idempotent. Volumes retain Docker's in-use refusal; no
container is deleted to make a resource removable. Failed or unavailable native
observations do not become absence or zero usage.
Network creation uses native `docker network create` argv with the admitted driver,
sorted label pairs and name, then requires module post-observation to match the
returned full ID, name, driver and labels. A native failure never adopts an arriving
object or deletes/disconnects/retries it. The pinned network module can replace a
same-name object during creation, so it is used only for observation here.
Network deletion uses only `docker network rm -- <qualified-full-ID>` after native
identity/user checks and then reobserves absence. It deliberately does not use
`docker_network state=absent`: the pinned module forcibly disconnects users.
The native no-force deletion retains the daemon's final in-use race refusal.

## Results

One `TEMPLATE_OUTPUT_JSON={"local_resource":...}` carries these plain facts:

| Field | Meaning |
|---|---|
| `kind`, `action`, `name` | Native operation subject and action. |
| `observed_at` | UTC RFC3339 observation time. |
| `outcome` | `succeeded`, `failed` or `incomplete`. |
| `presence` | `present`, `absent` or `unknown`. |
| `incarnation` | Native Volume CreatedAt or full Network ID; null when absent/unavailable. |
| `driver` | Actual observed driver or null. |
| `changed` | Actual observed procedure effects, not desired intent. |
| `attachment_count` | Native users; null when unavailable. Stopped volume users count. |
| `observed_used_bytes`, `observed_free_bytes` | Nullable capacity observations. |
| `quota_enforced` | Always false. |
| `reason_code` | Null or `local_resource_identity_changed`, `local_resource_in_use`, `local_resource_observation_incomplete`, `local_resource_execution_failed`. |

Failures emit available safe facts before a fixed error. Partial observations are
not permission to release backend resource references. Native errors, options,
labels and arbitrary output are not interpolated into public diagnostics.

Example inspect result:

```json
{"local_resource":{"kind":"volume","action":"inspect","name":"example-data","observed_at":"2026-10-06T00:00:00Z","outcome":"succeeded","presence":"present","incarnation":"2026-10-06T00:00:00Z","driver":"local","changed":false,"attachment_count":1,"observed_used_bytes":4096,"observed_free_bytes":null,"quota_enforced":false,"reason_code":null}}
```

## Accounting And Overrides

`local_volume_usage.py` receives only the module-observed local-driver mountpoint.
It opens directories without following symlinks, deduplicates hardlinks, and counts
allocated regular-file blocks. Its scan is bounded to 100000 entries, 256 open
directories (including the iterator), and two seconds of scan work. Exhaustion or
unavailable filesystem information yields null values, never fabricated zero.
Free space is filesystem availability, not a per-volume reserved quota. Native
resource identity is rechecked after accounting. This helper has no Docker calls,
locks, admission or mutation.

An organization override can implement these public scalar inputs and facts with
its own readable native procedure. It needs no OpsCtl API imports, private protocol,
receipt signature, backing ID or plan context; the executing Operation associates
the result with the already-authorized backend subject.
