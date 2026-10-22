# Deploy an image container

`container_deploy.yml` runs one image as a container on a Server. It is the
high-impact `container_deploy` Ansible item, Operation type `deploy_container`.
It runs from its Official Sources registration or an Automation Override; it does
not register sources itself. Compose applications use
[compose_deploy](../compose/compose_deploy.md) instead. The Server's inventory,
SSH access and privilege escalation are used as configured.

## Inputs

| Variable | Default | Meaning |
|---|---|---|
| `app_managed` | required true | Marks the container as managed by OpsControl. |
| `app_org_id`, `app_deployment_id` | required canonical UUIDs | Identify the organization and deployment in container labels; not echoed in `image_runtime` results. |
| `app_project_id`, `app_revision_id` | omitted | Optional Project and revision labels. |
| `app_container_name` | `app` | Container name. |
| `app_slug` | container name | Application label (`com.opsctl.app`). |
| `app_image` | required | Image reference to run. |
| `app_run_command` | omitted | Command to run instead of the image default. |
| `app_env` | `{}` | Environment variables; dollars stay literal and values are never logged in image results. |
| `app_ports`, `app_container_ports` | `[]` | Host and container ports to publish. |
| `backend_exposure_mode` | `host` | How the container is reached: `host|wireguard|loopback|loopback_wireguard`. |
| `wireguard_ip` | empty | Private address, required by the WireGuard modes. |
| `route_port`, `container_port` | null | `route_port` is required for loopback, WireGuard and combined exposure. Explicit `container_port` is required for `loopback` and `loopback_wireguard`; WireGuard-only exposure can derive it from the first `app_container_ports` entry or `route_port`. |
| `app_router_name` | container name | Traefik router name. |
| `app_traefik_enabled` | false | Adds Traefik routing labels; direct labels are disabled specifically for `backend_exposure_mode=loopback`, not the separate `loopback_wireguard` mode. |
| `app_traefik_hosts` | single `app_traefik_host`, otherwise `[]` | Hostnames to route. |
| `app_traefik_host` | omitted | Single hostname, used when `app_traefik_hosts` is not given. |
| `app_traefik_https` | true | Enables TLS on the router. |
| `app_traefik_middlewares` | `[]` | Traefik middlewares to attach. |
| `app_health_mode` | `auto` | Health check method: `auto`, `host`, `container` or `traefik`. |
| `app_health_path` | `/health` | HTTP health path. |
| `app_health_port` | first app port or null | Host HTTP port for health checks. |
| `app_health_container_port` | null | Container HTTP port for health checks. |
| `app_health_container_path` | health path | HTTP path checked inside the container. |
| `replace_conflicts` | false | Removes conflicting OpsControl-managed containers only in the requested organization and, when supplied, Project. Not allowed with managed resources. |
| `source_replacement` | omitted | Replaces one exact source container, for restoring a recorded deployment. Not allowed with managed resources. |

Registry credentials arrive through a protected Secret. Image/platform preparation
runs before replacement; source restoration and routing retain their separate
input requirements.

| Native variable | Default | Public contract/origin |
|---|---|---|
| `app_mounts` | `[]` | Up to 128 admitted existing `{source,target,read_only}` named Volume mounts; target absolute. |
| `app_networks` | `[]` | Up to 64 admitted existing `{id,name,aliases:[]}` Networks; full IDs, up to128 aliases. |
| `app_previous_container_id` | null | Full ID of the container being replaced. Explicit null means no container with the target name may exist; an existing one is never adopted. |
| `app_observe_volumes` | `[]` | Up to64 current/retiring `{name,created_at}` references with required nonempty recorded timestamp. |
| `app_observe_networks` | `[]` | Up to64 current/retiring `{id,name}` references. |
| `app_health_exec` | null | Optional1-128 literal exec argv elements; Docker receives `['CMD', ...argv]`, no shell interpolation. |
| `app_memory_bytes` | null | Optional positive native memory limit. |
| `app_secret_file_incarnation` | omitted | Executing Operation UUID for readonly workload files delivered by the per-job FileSecret. |
| `app_secret_file_cleanup_incarnation` | omitted | Previous file-owning Operation UUID; its container must be confirmed absent before its files are removed. |

Supplying the predecessor variable or any resource references selects the managed
resource path. All backing/network incarnations must already exist and match;
this item creates/adopts no resource by name. It excludes legacy name conflict
cleanup/source replacement. All Volume users, including stopped/read-only, are
observed. A writer conflicts only with another running read-write user, excluding
the exact predecessor that is replaced. No storage lock controller is added.

The container starts with the given mounts, networks, environment, literal health
argv and memory limit. With no selected networks it uses Docker's default bridge;
it does not create a Compose network. Image preparation, registry authentication,
HTTP/Traefik health checks and source restoration work as in ordinary deployment.
Replaced predecessor absence and current/retiring resource users are reobserved.
No volume/network/bind data or image is deleted for managed-resource deployment.
Workload files are the only exception: at most 16 files mounted readonly beneath
`/run/secrets`, each 64 KiB or less, with a 128 KiB total limit. Numeric uid/gid
values are 0..2147483647; mode is the string `0400` or `0440`. The private delivery
manifest lists exact targets and permissions; Vault values never enter variables.
The shared [`container_secret_files.yml`](../../tasks/container_secret_files.yml)
stages files on disk beneath `/var/lib/opsctl/workload-secrets`, separated by
organization, Deployment, Server and executing Operation. Parent directories are
0700. Files are written atomically with the specified owner and mode; target paths
never follow links. Immutable Kubernetes projection links are read only from the
fixed per-job Secret mount.
Files remain after Job/Secret cleanup. Replacement or removal deletes only the
previous Operation's staged files, after confirming its exact container ID is
absent. Uncertain absence or ownership does not permit deletion. This is not
memory-only delivery, automatic rotation or restoration after reboot.
The adjacent sidecar declares optional `workload_files={version:1,
capability:delivery_and_replacement_cleanup}`. Without it, ordinary no-file use
remains valid, but file delivery and replacement of file-owning containers are
unavailable. Review and each new execution check the selected immutable source
and artifact, never a newer default.

## Results

The adjacent [version1 declaration](container_deploy.contract.json) includes
`image_runtime` examples for an observed ready container, a complete but not-ready
observation, and an incomplete observation with null readiness.

Progress and health output are described below. Every ordinary-image deployment emits
`TEMPLATE_OUTPUT_JSON={"image_runtime":...}` before refusing incomplete/not-ready
observations, including workloads without managed resources (empty resource
lists). Startup/health rescue also observes and publishes available facts after
attempting source restoration, even if restoration or diagnostics fail; the
original deployment failure remains a failure. Fields are:

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

## Progress

Step names include `deploy:start`, `docker:install`, `preflight:ports`,
conditional `replace:complete`/`replace:legacy_cleanup`, `container:prepare` and
`health:check`. Their actual running/completed/failed metadata remains separate
from the final `image_runtime` observation. Progress alone does not establish
readiness or predecessor absence.

## Example

Example image inputs with one managed mount:

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
