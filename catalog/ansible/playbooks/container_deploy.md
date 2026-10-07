# Ordinary image deployment

`container_deploy.yml` is the high-impact `container_deploy` Ansible item, logical
Operation type `deploy_container`. Register/override through existing Admin source
validation/acceptance; no automatic catalog registration occurs. Compose uses
[compose_deploy](compose_deploy.md), never this image procedure or a generated model.
Existing inventory/SSH and privilege escalation apply.

## Inputs

Existing image/exposure variables remain unchanged:

| Variable | Default | Origin/meaning |
|---|---|---|
| `app_managed` | required true | Backend managed image intent. |
| `app_org_id`, `app_deployment_id` | required canonical UUIDs | Existing backend labels; not returned as image proof echoes. |
| `app_project_id`, `app_revision_id` | omitted | Optional existing Project/revision labels. |
| `app_container_name` | `app` | Reviewed target name. |
| `app_slug` | container name | Existing application label. |
| `app_image` | required | Reviewed native image reference. |
| `app_run_command` | omitted | Existing native command. |
| `app_env` | `{}` | Native environment; dollars remain literal, never logged in image results. |
| `app_ports`, `app_container_ports` | `[]` | Existing host/container port selections. |
| `backend_exposure_mode` | `host` | `host|wireguard|loopback|loopback_wireguard`. |
| `wireguard_ip` | empty | Backend private address when required by exposure mode. |
| `route_port`, `container_port` | null | Backend route/container ports required by selected exposure mode. |
| `app_router_name` | container name | Existing Traefik router name. |
| `app_traefik_enabled` | false | Existing routing selection; loopback disables direct Traefik labels. |
| `app_traefik_hosts` | single `app_traefik_host`, otherwise `[]` | Reviewed hostnames. |
| `app_traefik_host` | omitted | Existing single-host input. |
| `app_traefik_https` | true | Existing router TLS selection. |
| `app_traefik_middlewares` | `[]` | Existing middleware selections. |
| `app_health_mode` | `auto` | Existing auto/host/container/traefik strategy. |
| `app_health_path` | `/health` | Existing HTTP path. |
| `app_health_port` | first app port or null | Host HTTP port. |
| `app_health_container_port` | null | Container HTTP port. |
| `app_health_container_path` | health path | Container namespace HTTP path. |
| `replace_conflicts` | false | Existing legacy replacement choice; forbidden for native managed-resource path. |
| `source_replacement` | omitted | Existing separately qualified source restoration input; forbidden for native managed-resource path. |

Existing protected registry Secret and pre-replacement image/platform preparation
remain unchanged. Source replacement/routing contracts are not redefined by these
native resource additions.

| Native variable | Default | Public contract/origin |
|---|---|---|
| `app_mounts` | `[]` | Up to 128 admitted existing `{source,target,read_only}` named Volume mounts; target absolute. |
| `app_networks` | `[]` | Up to 64 admitted existing `{id,name,aliases:[]}` Networks; full IDs, up to128 aliases. |
| `app_previous_container_id` | null | Recorded full predecessor ID; explicit null permits only qualified target absence, not adoption. |
| `app_observe_volumes` | `[]` | Up to64 current/retiring `{name,created_at}` references with required nonempty recorded timestamp. |
| `app_observe_networks` | `[]` | Up to64 current/retiring `{id,name}` references. |
| `app_health_exec` | null | Optional1-128 literal exec argv elements; Docker receives `['CMD', ...argv]`, no shell interpolation. |
| `app_memory_bytes` | null | Optional positive native memory limit. |

Supplying the predecessor variable or any resource references selects the managed
resource path. All backing/network incarnations must already exist and match;
this item creates/adopts no resource by name. It excludes legacy name conflict
cleanup/source replacement. All Volume users, including stopped/read-only, are
observed. A writer conflicts only with another running read-write user, excluding
the exact predecessor that is replaced. No storage lock controller is added.

The existing docker_container start receives native mounts/networks, environment,
literal health argv and memory. With no selected networks it uses Docker's default
bridge; it does not create a Compose network. Existing prepared-image/platform,
authentication, HTTP/Traefik health and source-restoration behavior are retained.
Replaced predecessor absence and current/retiring resource users are reobserved.
No volume/network/bind data or image is deleted for managed-resource deployment.

## Results

Existing progress/health output remains. Every ordinary-image deployment emits
`TEMPLATE_OUTPUT_JSON={"image_runtime":...}` before refusing incomplete/not-ready
observations, including workloads without managed resources (empty resource
lists). Startup/health rescue also observes and publishes available facts after
attempting source restoration, even if restoration or diagnostics fail; the
original deployment failure remains a failure. This same result is consumed by
the executing installation; the separate E handoff supplies start identity. Fields are:

| Field | Meaning |
|---|---|
| `action` | `deploy`. |
| `observation_complete` | Required bounded observations all succeeded; unknown/replaced resources make false. |
| `ready` | Boolean for complete deploy; every incomplete observation requires null. |
| `container` | Actual safe instance or null when absent/unavailable. |
| `previous_container_absent` | Actual full-ID lookup boolean or null when not supplied/unavailable. |
| `volumes` | `{name,created_at,presence,users:[{id,state,read_only}]}`; presence `present|absent|unknown`, observed timestamp nullable. |
| `networks` | `{id,name,presence,containers:[fullDockerID]}`. |

Safe instance fields: `{id,name,replica:null,image_ref,image_id,image_digest,state,
health,exit_code,ports,mounts}`. Digest is the unambiguous native repo digest or null;
exit code integer/null. State `created|running|restarting|paused|exited|dead|removing|unknown`;
health `healthy|unhealthy|starting|none|unknown`. Ports are
`{host_ip,host_port,container_port,protocol:tcp|udp}`; mounts
`{type:volume|bind|tmpfs|other,source,target,read_only}`. Source is volume name, bind
path or null. Env/options/labels/health commands/credentials/native errors stay private.
Bounds:64 references each,128 users per resource,256 ports/128 mounts,256KiB output.
No attachment IDs or writer-excluded receipts. Incomplete facts cannot release
backend attachments; absence/ready are observations, never inferred from exit0.

## Example

Existing reviewed image inputs plus one managed mount:

```yaml
app_managed: true
app_org_id: 11111111-1111-1111-1111-111111111111
app_deployment_id: 22222222-2222-2222-2222-222222222222
app_container_name: sample
app_image: registry.example/sample:release
app_previous_container_id: null
app_mounts: [{source: sample-data, target: /data, read_only: false}]
app_observe_volumes: [{name: sample-data, created_at: '2026-10-06T00:00:00Z'}]
```

Unavailable observation shape (not success):

```json
{"image_runtime":{"action":"deploy","observation_complete":false,"ready":null,"container":null,"previous_container_absent":null,"volumes":[{"name":"sample-data","created_at":null,"presence":"unknown","users":[]}],"networks":[]}}
```

An org override uses these normal native variables/facts and existing image
preparation contracts; it needs no backend package or private execution protocol.
