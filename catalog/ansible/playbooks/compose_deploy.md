# Native Compose deployment

Register `ansible/playbooks/compose_deploy.yml` as the high-impact Ansible item
`compose_deploy` through the existing Admin tracked-source/Validate All/accepted
revision flow. Logical Operation type remains `deploy_container`. Org overrides
use these public variables and facts; no private API, receipt or protocol is needed.
Inventory, SSH access and privilege escalation use the existing Ansible contract.

## Inputs

| Variable | Default/type | Origin and meaning |
|---|---|---|
| `compose_project_name` | required string | Reviewed native name, fixed on update; native Compose naming precedence is resolved before delivery. |
| `compose_workspace` | required absolute directory | Backend-configured stable Server/project workspace, retained across removal/reuse. |
| `compose_project_directory` | `.`; relative directory | Original native project base inside workspace. |
| `compose_files` | required 1-16 ordered strings | Reviewed original Compose selections relative to project base. Parent components may resolve within workspace only. |
| `compose_env_files` | `[]`; up to 16 ordered strings | Explicit ordered env selections replace the automatic default. With none selected, only a supplied authenticated project-base `.env` contributes. |
| `compose_profiles` | `[]`; up to 32 strings | Reviewed native profile selections, unchanged. |
| `compose_source_directory` | required absolute controller path | Existing read-only file Secret mount, normally `/var/run/opsctl/file-secret`. |
| `compose_interpolation_source_file` | null; exact absolute controller path | When supplied, exactly `compose_source_directory + '/compose-interpolation.env'`: the operation-staged protected env file, not a captured original or arbitrary path. |
| `compose_supplied_files` | required 1-32 objects | `{source,path,mode}`: flat Secret key `source-00`, confined workspace-relative original destination, four-character octal mode. |
| `compose_directories` | `[]`; up to 32 relative paths | Explicit empty input directories; missing file parents are also created. |
| `compose_registry_auth_file` | null; absolute controller path | Existing protected registry Secret, normally `/secrets/registry-auth.json`, containing only `{registries:[{host,username,password}]}`. Null selects anonymous access. |
| `compose_services` | required 0-32 objects | Reviewed selected `{name,replicas,condition,allow_completion:false}`. Replicas 0-128, total <=128; condition `running|healthy|completed|scaled_down`. |
| `compose_wait_timeout` | 300; integer 1-1800 seconds | Backend readiness setting; observations separated by up to five seconds. |
| `compose_known_containers` | `[]`; up to 128 full IDs | Recorded installed/partial instances; only these pre-existing project members permit mutation. |
| `compose_known_networks` | `[]`; up to 64 objects | Recorded `{id,name,origin}`; origin `created|reused|external|unknown`. |
| `compose_known_volumes` | `[]`; up to 64 objects | Recorded `{name,created_at,origin}`; timestamp nullable, same origins. Unknown timestamp conveys no deletion authority. |

Files/env selections must resolve to supplied paths. Supplied paths are regular
files, not symlinks/special files. Workspace ancestors and destinations are checked
without following links. Missing directories are created without recursively
changing existing permissions. Every supplied file overwrites on each deploy
(`force=true`, `backup=false`, `diff=false`), including supplied database bytes.
Unsupplied files, retained `.env`, bind data and named/anonymous volumes remain.
An unsupplied retained `.env` does not contribute project interpolation.
This is not directory synchronization; omission is not an absence instruction.

## Procedure

Observe current project membership before effects. Unknown pre-existing IDs refuse
mutation; labels do not authorize adoption. Copy originals, then create a private
operation-local directory outside the captured workspace, at mode `0700`, even for
anonymous access. Only selected credentials are logged in with `docker_login`.
Native config and apply share its private Docker config; the user's config is never
changed. The same owned directory holds the constant environment wrapper and any
protected or empty env file, never captured inventory.

The caller freezes the operation file Secret read-only. The optional protected file
must have the exact bound spelling above and resolve to a regular file inside that
same mount. Confined Kubernetes projection links are allowed; escapes, special
files and sizes above 262144 bytes refuse before delivery. The procedure copies
raw bytes at mode `0600`, without parsing, rendering or reserializing them. Track2
owns serialization and the total Secret/helper budgets. Protected bytes are never
included in `compose_supplied_files`, `files_written` or public results.

Config and apply use one effective env list: explicit base selections in order,
or only the authenticated supplied project-base `.env`, followed by the protected
file last. Explicit selections never augment the automatic default. If neither a
base nor protected file exists, both receive an explicitly selected owned empty
mode-0600 file to suppress native automatic `.env` loading. No captured originals
are rewritten and no interpolation keys are stripped or filtered here. Stack
review owns its modeled/conflicting control policy separately from ordinary Compose.

The public `../scripts/compose_controlled_environment.sh` is copied from this exact
official source at mode `0700`. It is only a constant native `env -i` wrapper, not
an env parser, secret transport or orchestration engine. Its required operational
inputs are `OPSCTL_COMPOSE_OPERATIONAL_PATH`, `OPSCTL_COMPOSE_DOCKER_CONFIG` and
`OPSCTL_COMPOSE_DOCKER_EXECUTABLE`. The procedure resolves and observes the installed
real Docker executable using the operational system PATH, independently of captured
files, then forwards argv unchanged. The resulting Docker process receives only
that PATH and private DOCKER_CONFIG, not ambient application, HOME, COMPOSE_* or
connection variables. File-based application PATH/DOCKER_HOST remain literal values;
they do not select the process executable, PATH or daemon.

Config passes `--host unix:///var/run/docker.sock`; apply selects the wrapper through
`docker_cli` and explicitly supplies the same `docker_host`, omitting `cli_context`,
false `tls`/`validate_certs`, null `tls_hostname`/`ca_path`/`client_cert`/`client_key`,
and `api_version: auto`. These explicit module parameters prevent its environment
fallbacks from selecting another connection before the clean wrapper is invoked.
The context option has no environment fallback; omitting it avoids the module's
mutually-exclusive host/context key check, which also counts a supplied null key.
This is the procedure's authorized local daemon, not a remote-connection input.
Argument-variable expansion is disabled for native argv commands.

Normal terminal paths reobserve the temporary directory's device/inode/owner before
removing only that allocation, then require observed absence. Cleanup failure or
uncertainty cannot publish success; an existing native failure reason is preserved,
otherwise `compose_file_delivery_failed` describes unavailable private-file cleanup.
No raw native error or private path is added to public results. Interrupted or
unreachable execution can prevent cleanup/publication and must remain uncertain.

Privately read `docker compose config --format json` from the original project
base. Compare selected service/count/readiness/completion intent, not full-model
hashes. Changed selected references can cause `compose_configuration_changed`
before apply. Native include/extends/path bases and source platform/image/pull policy
remain authoritative; no generated overrides or OpsCtl revision labels are injected.

Apply with `docker_compose_v2`: exact project_src/name/files/env/profiles,
`state=present`, `pull=policy`, `build=never`, `recreate=auto`,
`renew_anon_volumes=false`, `assume_yes=false`, `wait=false`. Orphans are removed
only after complete known-membership checks. Build-only/required-build services
refuse; image-backed build metadata is retained without executing a build.
File delivery alone does not promise a reload/restart. Platform/native failures can
leave partial effects; there is no automatic rollback or application-data deletion.

Readiness intent collects incoming dependency conditions across selected resolved
services: zero replicas takes precedence as scaled_down, then a completion
dependency selects completed, then a healthy dependency or enabled own healthcheck
selects healthy, otherwise running. `disable:true` or `test: ["NONE"]` disables
only the own check. `allow_completion` requires restart absent/empty/`no` and no
incoming conditions; it is not inferred from a service's outgoing dependencies.

Observe every replica. Running requires actual healthy status when Docker exposes
inherited health; explicit native disablement follows Docker. Completed dependencies
require exited/zero. `allow_completion=true` permits restart-disabled standalone
running/healthy services to finish exited/zero. Restarting/nonzero never succeeds;
zero desired replicas is scaled_down. Native wait alone is not readiness evidence.

## Results

Exactly one final `TEMPLATE_OUTPUT_JSON={"compose":...}` precedes any fixed failure.

| Field | Contract |
|---|---|
| `action`, `project_name`, `project_directory` | `deploy`, native name, original relative project base. |
| `observed_at` | UTC RFC3339 or null when observation failed. |
| `outcome`, `observation_complete`, `changed` | `succeeded|failed|unknown`, complete observation boolean, actual-effect boolean. |
| `ready` | Boolean when complete; null when incomplete. Failure/unknown cannot install a revision. |
| `phase`, `reason` | Actual phase and closed safe reason below; reason null on success. |
| `files_written` | Successfully copied relative paths, including partial delivery; no content/hash. |
| `services` | `{name,desired_replicas,condition,state,instances}` for every selected service. State `running|healthy|starting|completed|scaled_down|stopped|failed|missing|unknown|drifted`. |
| `unexpected_containers` | Actual project instances outside recorded/selected membership. |
| `networks` | `{id,name,origin,presence}`; absence retains recorded ID; presence `present|absent|unknown`. |
| `volumes` | `{name,created_at,origin,presence}`, including anonymous mounts. Timestamp nullable; all are retained. |
| `removed_containers` | Recorded full IDs actually reobserved absent, never inferred from stop success. |

Every instance includes `{id,name,replica,image_ref,image_id,image_digest,state,
health,exit_code,ports,mounts}`. IDs are full native IDs; image_id is sha256; digest
is the unambiguous observed repo digest or null. Replica is positive or null for
unnumbered extras; state is `created|running|restarting|paused|exited|dead|removing|unknown`;
health `healthy|unhealthy|starting|none|unknown`; exit_code integer or null.
Ports include every `{host_ip,host_port,container_port,protocol:tcp|udp}` binding;
mounts are `{type:volume|bind|tmpfs|other,source,target,read_only}`. Source is volume
name, bind path or null. Env, labels, options, credentials, health commands/output
and native stderr remain private.

Phases/progress names: `compose:prepare`, `compose:files`, `compose:apply`,
`compose:observe`, `compose:remove`, `compose:complete`. OPERATION_STEP carries
actual `running|completed|failed`, fixed display name and safe reason only.
Closed reasons: `compose_prerequisite_unavailable`, `compose_project_conflict`,
`compose_configuration_changed`, `compose_file_delivery_failed`,
`compose_registry_auth_failed`, `compose_apply_failed`, `compose_readiness_timeout`,
`compose_observation_failed`, `compose_observation_limit`, `compose_resource_changed`,
`compose_resource_in_use`, `compose_remove_failed`, `compose_build_unavailable`.
Generic module errors do not become invented precise diagnoses.

Bounds: 256 KiB output, 32 services, 128 total instances, 64 networks/volumes,
256 ports and 128 mounts per instance. Overflow emits incomplete/unknown, never
silently truncated success. Safe partial facts can support later exact cleanup
after backend authority/quiescence checks, not success or name-based adoption.
Existing resource incarnations preserve recorded origins; complete absence before
and presence after establishes created; native external declarations stay external;
otherwise references are reused/unknown. Templates return no backend attribution IDs.
After native apply, including partial-apply rescue, an observed replacement network
is present with its new ID. Its origin remains unknown unless independent creation
or external evidence establishes otherwise; the old ID's created authority never
transfers. Pre-apply, inspect and remove still treat recorded-ID replacement as
incomplete observation. Volume incarnation handling is unchanged.

## Example

Illustrative input; each flat source key contains the corresponding original:

```yaml
compose_project_name: metrics
compose_workspace: /var/lib/opsctl/compose/00000000-0000-0000-0000-000000000001/projects/metrics/workspace
compose_project_directory: .
compose_source_directory: /var/run/opsctl/file-secret
compose_files: [compose.yaml, ports.override.yml]
compose_supplied_files:
  - {source: source-00, path: compose.yaml, mode: '0600'}
  - {source: source-01, path: ports.override.yml, mode: '0600'}
  - {source: source-02, path: prometheus/prometheus.yml, mode: '0644'}
compose_services: [{name: prometheus, replicas: 1, condition: running}]
```

Full success shape; actual IDs/images/mounts come from native observations. An
update includes the previous recorded container ID, never guessed label ownership:

```json
{"compose":{"action":"deploy","project_name":"metrics","project_directory":".","observed_at":"2026-10-06T12:00:00Z","outcome":"succeeded","observation_complete":true,"changed":true,"ready":true,"phase":"compose:complete","reason":null,"files_written":["compose.yaml","ports.override.yml","prometheus/prometheus.yml"],"services":[{"name":"prometheus","desired_replicas":1,"condition":"running","state":"running","instances":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"metrics-prometheus-1","replica":1,"image_ref":"prom/prometheus:v3.5.0","image_id":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","image_digest":null,"state":"running","health":"none","exit_code":0,"ports":[],"mounts":[{"type":"bind","source":"/var/lib/opsctl/compose/00000000-0000-0000-0000-000000000001/projects/metrics/workspace/prometheus","target":"/etc/prometheus","read_only":false}]}]}],"unexpected_containers":[],"networks":[],"volumes":[],"removed_containers":[]}}
```

Before accepting same-name reuse, backend review discloses previous removal and
retained workspace/volume facts with their observation time. Historical retention
is not current presence or a promise of an empty install. Org overrides implement
this same native public contract, not a private obedience/custody algorithm.
