# Discover Server Workloads

## Inputs

`discovery_selection` is exactly `{kind: all_running}` or `{kind: containers, container_ids: [...]}` with one to 32 unique full lowercase 64-hex container IDs. `discovery_limits` supplies positive integers `max_containers` (at most 32) and `max_result_bytes` (at most 262144 UTF-8 bytes). The backend supplies its smaller admitted limits. `discovery_result_path` is Runner's private absolute controller destination, never a user-selected output path. The existing authorized management login and enrolled SSH trust are supplied by execution, without privilege escalation.

## Behavior

The named stdlib helper runs on the selected Server and projects facts before they reach the controller. It requires Python 3, Docker CLI and access to the existing local Unix endpoint `/var/run/docker.sock`. Missing dependencies/access or unsupported/rootless endpoints produce incomplete unavailable facts; this procedure never installs tools, changes a login, uses sudo, contacts an ambient remote Docker context or adopts resources.

Reads are native container list/inspect and image inspect, passed as argv without a shell. Each read allows at most 1048576 combined stdout/stderr bytes and ten seconds. All reads share 33554432 bytes and 60 monotonic seconds. The remaining aggregate allowance/deadline bounds each read. Exceeding either terminates/reaps only the owned CLI child, discards raw output and reports a fixed safe problem. Exact selected sets and argv are never truncated. An oversized running list has unknown captured IDs, not a shorter successful set. ID and creation identity are read again after projection; replacements discard the old facts. Missing/failed inspect is unavailable, not proof of absence.

There are no runtime/configuration writes, execs, pulls, restarts, file-content reads or ownership changes. Only ordinary invocation-private Ansible transport scratch is delivered/cleaned by Ansible. The controller writes the projected JSON to its private destination under `no_log`; no result markers or private payloads are logged. Runner owns protected-file validation, key custody, encryption, authenticated bindings and cleanup. This procedure does not implement those algorithms.

## Results

The ordinary closed JSON contains `format_version: 1`, `selection: {kind,container_ids}`, nullable UTC `started_at`/`observed_at`, `complete`, `containers` and `problems`. Unknown captured IDs are null. Completeness is not an atomic host snapshot, storage consistency, application readiness or successful Blueprint generation.

Each container has its exact `id`, `observation` (observed/absent/changed/unavailable), nullable `name`, `created_at`, `state` and `image: {reference,id,repo_digests}`. An image ID is not a guessed pullable pin. `command` and `entrypoint` each contain `state: observed|unknown` and nullable ordered string `argv`; empty arrays/arguments and literal dollars remain unchanged. Null command or entrypoint data means the value is unknown; it does not establish whether the author intended to inherit the image defaults.

`environment_names` contains only validated names in native order, never values or original Env entries. `ports` contains `{container_port,protocol,declared,publications}` with nullable declaration and nullable publication arrays of `{host_ip,host_port}`. Empty publications means observed none, not firewall or reachability evidence. `mounts` contains `{type,source,target,read_only,tmpfs_size_bytes,tmpfs_mode}`; unavailable options remain null with problems. `networks` contains `{id,name,aliases}` with nullable strings/ordered aliases. Unsupported types/options/configuration become explicit problems, never recreated ownership or defaults.

For volume mounts, `source` is the observed nonempty Docker volume `Name`, suitable as the external Compose volume name, never its internal host `Source` directory. For bind mounts it is the observed nonempty `Source` path. Missing/empty required sources remain null with an explicit problem and incomplete observation. Tmpfs and unknown types have null source, not an inferred name or directory.

Global/container problems have exactly `{code,resource_path,fact,message}` with fixed safe messages and bounded field references, never native stderr, inspect objects, label values, health commands or arbitrary options. Any unsupported/unavailable fact makes completeness false. A whole-result overflow falls back to an explicit incomplete observation preserving selected identity. If that minimal result cannot fit, execution fails without delivering a result file; absence is unavailable, never successful empty discovery. Partial observations and safe failures do not establish native readiness or connectivity.

## Progress

Tasks expose only their fixed names through the ordinary execution callback. Private tasks are `no_log`. No `OPERATION_STEP` or `TEMPLATE_OUTPUT_JSON` payload is emitted for these private facts. The private controller file is the sole ordinary-result channel; public operation readers are not authorized to serialize it.
