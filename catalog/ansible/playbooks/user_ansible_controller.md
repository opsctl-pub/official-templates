# User Ansible Controller

Authored native procedure and isolated actual-task/helper behavior are accepted
with labelled external transports substituted. Connected
containment is not qualified. No admitted user-run route or selected-target private-key delivery
is implemented here. The platform
Runner may run only the accepted official control procedure; user Ansible,
controller-side plugins, lookups and local tasks belong inside the container on
the separately authorized user-owned controller Server.
The observe/settle increment is authored; isolated behavior review and connected
result-consumer qualification remain separate acceptance boundaries.

## Inputs And Authority

The closed internal `template_execution` mapping contains exactly `operation_id`,
`controller_server_id`, `source_digest`, `input_digest`, `staging_directory`,
`supplied_files`, `entrypoint`, `image`, `uid`, `gid`, `payload_engine`, `targets`
and `limits`. Required `payload_engine` is exactly `ansible` or `bash`, derived
centrally from the exact published revision, never inferred from targets.
It binds the Operation/controller UUIDs and source/input SHA-256 digests to the
frozen materialization manifest, member entrypoint, immutable image reference
and nonroot numeric UID/GID. The interpreter/argv is fixed, not another input. Source
bounds and literal byte delivery remain owned by `materialize_template_files`.
No user shell expression, address, environment, interpreter or executable may
replace these bindings.

For Ansible, the ordered 1..32 targets require exact Server UUIDs, current backend-resolved
IPv4/SSH port/login, frozen host public keys and authorized private regular-file
bindings with exact credential versions. Each target contains exactly `server_id`,
`address`, `port`, `username`, `host_public_key`, `credential_file`,
`ssh_access_key_id`, `credential_secret_id` and `credential_version`. Require the
managed port22 profile; private filenames and ordinary Vault bytes come from the
central owner, while trusted management-channel observation supplies host keys.
Reject duplicates and controller/self
targets before start. Content visibility, accepted template publication and an
exact digest do not grant target access. Central admission rechecks actor, scope,
controller and every target before delivery/execution.

Bash has exactly `targets: []`; `controller_server_id` identifies its one
backend-authorized execution Server. It delivers no SSH credentials, inventory,
known_hosts or Ansible configuration. The same private keys directory contains
only `inputs.json`; ordered source bytes/modes remain unchanged. Its executable
entrypoint must retain mode `0700` or `0755`.

Private material comes through the same immutable Operation Secret and protected
file custody, never public arguments, plaintext credential variables or inherited
platform environment. Public SSH access records are not a private-key selector;
the organization SSH key is not payload material. The central carrier and this
selected-target private-key route remain prerequisites, not local substitutes.

The generated `template-inputs.json` is required in `staging_directory`. Its
canonical UTF-8 JSON envelope is `{"opsctl_inputs": <validated merged application object>}`.
`input_digest` covers the exact envelope bytes; schemas, defaults and Hook merging
describe the inner object, and templates read `opsctl_inputs.<name>`. The central
serializer adds the envelope once. The procedure checks a
bounded regular file with staged mode `0400` or `0600`, then copies those raw
bytes to fresh `keys/inputs.json` with admitted UID/GID and mode `0600`.
Both generated names are reserved against credential collisions. No parameter
parsing, merging, defaults or plaintext parameter variables occur here.
The frozen payload argv uses `/usr/bin/ansible-playbook`, the fixed inventory,
the source entrypoint and `--extra-vars @/run/opsctl-keys/inputs.json`.
The platform materialization subprocess retains `/usr/local/bin/ansible-playbook`.
Bash instead uses exactly `[/bin/bash, --noprofile, --norc,
/workspace/user/<entrypoint>, /run/opsctl-keys/inputs.json]`. The sole input is
the unchanged envelope file argument, not environment injection or interpolation.
Nesting application connection-like keys does not override inventory bindings;
it does not prevent authored playbooks changing variables or prove containment.

Available source/key/input material must fit the Operation Secret limits:
262144 bytes per file, 786432 bytes total and 40 files. Central admission also
counts its protected-redaction manifest and enforces the admitted SourceBudget;
the local subtotal is not a complete Secret admission proof. Those central
delivery/aggregate bindings remain prerequisites. Input copies live under the
existing owned keys tree and are removed only after observed process closure.

| Admitted limit | Closed range |
| --- | --- |
| Runtime deadline | 1..900 seconds |
| CPU | 100..1000 millicores |
| Memory | 64..512 MiB |
| Aggregate writable tmpfs, including shared memory | 1..64 MiB |
| PIDs | 1..128 |
| Returned logs | 1..65536 UTF-8 bytes |

Reject extra/invalid inputs and unavailable prerequisites rather than silently
falling back. Existing SSH-access/baseline ordering precedes the procedure; do not
reprovision an existing controller or install dependencies from user content.
The closed `limits` keys are `timeout_seconds`, `cpu_millicores`, `memory_mib`,
`tmpfs_mib`, `pids` and `log_bytes`; booleans are not numeric limits.

## Native Profile And Mapping

The first profile requires managed Linux, systemd, rootful Docker using its
iptables backend and functioning cgroup-v2 CPU/memory/swap/PID enforcement. A
responsive daemon or completed Docker baseline alone does not establish this
profile. Verify the required Engine API/options, controller tools and effective
configuration before any payload start. Unsupported profiles refuse.

The explicit Bash profile is `managed-linux-systemd-docker-none-v1`. Common
rootful Docker/systemd/cgroup prerequisites remain; SSH, bridge, firewall and
namespace-policy prerequisites apply only to Ansible. Bash requires effective
`network_mode: none`, no additional attachments or ports, read-only source at
`/workspace/user` and the existing read-only root/private/gate mounts. It
allocates no bridge or policy and keeps `network_cleanup: not_allocated`, never
claims network removal. The same stopped-container readback, independent deadline,
finite lock, effective cgroup observation and root-controlled gate precede exec.
Ansible retains its `/source` binding and destination-only policy unchanged.

The source mapping below is against Ansible 2.19.3/community.docker 5.3.0. It is
installed-source evidence, not a remote behavior or containment qualification.

| Phase | Native owner and explicit binding |
| --- | --- |
| Input/source checks | `ansible.builtin.assert`, no-follow `stat` and the accepted materialization validation; preserve ordered manifest, byte/mode/checksum and entrypoint equality. |
| Fresh delivery | Native `tempfile`, `copy` and `file`; chown only newly allocated owned copies to the qualified numeric UID/GID, without changing modes. Retain workspace/parents `0700` and authenticated regular-source modes exactly `0600`, `0644`, `0700` or `0755`; originals remain unchanged and payload source binds remain read-only. |
| Image inspection | `community.docker.docker_image_info`; require the qualified immutable image already prepared. Refuse nonempty `Config.Volumes`; inspect image environment/interpreter and override entrypoint plus healthcheck. No registry access from the restricted payload. |
| Network creation | `community.docker.docker_network`: `driver: bridge`, `enable_ipv6: false`, explicit operation labels and qualified `driver_options`/IPAM. Record the full network ID and actual bridge interface. `internal` is not a destination allowlist. |
| Container creation | `community.docker.docker_container`: `state: present`, `pull: never`, `detach: true`, `auto_remove: false`, `restart_policy: no`, `output_logs: false`, exact image/labels and numeric `user: UID:GID`. Record full container ID before start. |
| Process binding | Fixed trusted public `user_ansible_controller_start.sh` entrypoint with frozen list argv, `command_handling: correct`, `healthcheck.test: [NONE]` and a root-controlled read-only gate directory. After release, exec only the exact Ansible argv using immutable inventory/known-hosts and exact private files. No inherited platform inventory/plugins, token, service-account, socket or cloud environment. |
| Filesystem | `read_only: true`; each source/key bind uses `mounts` with explicit `type: bind`, `read_only: true`, `propagation: rprivate`. No volumes, devices or caller-selected host mounts. Fresh bind sources must have no nested mounts or unqualified UID remapping. |
| Writable storage | Explicit bounded `tmpfs` entries and `shm_size`; sum every writable tmpfs allocation, including `/dev/shm`, within the admitted budget. Do not inherit Docker's default 64 MiB shm or image volumes. Observe daemon-generated special mounts too; no unaccounted writable disk mount is admitted. |
| Resource/security limits | `cpus = millicores / 1000`; explicit byte strings for `memory` and equal `memory_swap` (no additional swap); positive `pids_limit`; `cap_drop: [ALL]`, no added capabilities, `privileged: false`, `security_opts: [no-new-privileges:true]`. No host PID/IPC/network namespace or published ports. |
| Attachment | Explicit owned network only, `networks_cli_compatible: true`, `comparisons.networks: strict`, no links/extra hosts/unrelated attachment. Revalidate actual endpoints before start. |
| Connection | Explicit controller-local Docker socket, API version and TLS choices through the installed module connection options. Ambient `DOCKER_HOST`/TLS/API variables must not select another daemon. These are official control bindings, never payload environment. |
| Deadline/start/release | Root-controlled identity record and systemd deadline installed/verified before exact-ID trusted-gate start. Revalidate full ID/labels/PID namespace, install/observe namespace policy, then release the owned marker under the same deadline/start lock. Do not reuse `state: started` as redispatch/recreation authority. |
| Observation | `docker_container_info.name` accepts the full recorded ID. Privately inspect identity/labels/configuration and `State`; publish only allowed facts. Raw inspect includes environment and must not become output. |
| Termination/removal | Trusted close helper targets only revalidated full ID/labels, bounded stop then kill/readback. Remove only after stopped/PID-zero or exact absence; never use a name collision to adopt, recreate or delete another invocation. |

The installed module's `state: present`, `started` and `stopped` can create or
recreate containers. Invocation records therefore gate those calls; a missing
recorded container is observation, not permission to launch again. Native argv
tasks carrying saved values require `expand_argument_vars: false`.

Existing delivery owns files as its SSH user. Read-only binds do not make `0600`
files readable by another UID. Qualify effective host/container UID mapping;
rootful Docker alone does not prove user-namespace remapping is disabled. Never
weaken private modes or chown an original/Secret projection. The module supports
`mounts.tmpfs_options` only with API >=1.46; the baseline does not pin that API.
Use only observed-supported options or refuse, not an implicit version fallback.
Private generated inputs and copied credentials remain `0600`; staged credential
checks still require `0400` or `0600`. Regular-source mode preservation does not
relax those private permissions.
The candidate divides the writable budget between `/tmp`, `/dev` and `/dev/shm`,
rounding each allocation down to a 4096-byte boundary. Before marker release,
observe effective cgroup limits rather than infer enforcement from create options.

## Destination-Only Policy

Before trusted-gate start, install and verify operation-owned rules ahead of permissive
forwarding rules: exact selected IPv4/TCP-SSH destinations and their response
flows, then rejection for other traffic on the owned bridge. Do not use a global
established/related allowance to bypass the exact-target boundary. Reject
bridge-to-controller traffic separately in INPUT, including every local controller
address. No public ingress, IPv6 or additional namespace attachment is admitted.
Remove only exact recorded rules/chains after process closure; preserve unrelated
rule order, policies, networks and management SSH access.

[Docker's iptables documentation](https://docs.docker.com/engine/network/firewall-iptables/)
places forwarded policy in DOCKER-USER and notes DNS rules inside the container
network namespace. Neither `docker_network` nor `docker_container` has a
destination ACL or an option disabling the embedded resolver. Empty resolv.conf,
`dns_servers` selection and forwarded UDP/53 denial alone do not prove no DNS.
The decided mechanism starts only the fixed trusted public startup gate after
the independent deadline is armed. The gate waits for one owned release marker;
before release it never imports or reads user source/configuration or reads or
selects credentials. It cannot run the payload to establish a namespace.

Host preparation revalidates the recorded full container ID, operation labels,
current PID and its network namespace before native `nsenter`/iptables policy
installation and observation. Operation-owned namespace OUTPUT rules reject
embedded DNS TCP/UDP and upstream/IPv6 bypass before marker release; forwarded
and controller INPUT rules remain separately required. The admitted host profile
requires these tools and verified enforcement. No network capability is given
to the gate or payload. Failed or changed identity/policy refuses release.

The root-controlled gate directory is mounted read-only in the container; the
release marker is not user writable. Release occurs under the same lock as
deadline/start/cleanup, only after policy verification. The gate then execs only
the frozen Ansible argv. This is neither another consent/dispatch protocol nor
a payload-selected namespace owner. Native modules alone still lack these
controls, but the startup placement decision is resolved; implementation and
live embedded-resolver/IPv6 containment remain unqualified.

## Independent Deadline And Closure

The management SSH user must already be root: native `id -u` runs without
escalation before allocation. Fresh invocation exclusively reserves its `0700`
Operation record and atomically writes a bounded `0600` nonprivate journal before
materialization or local private variables. Delivery uses a fresh child of the
journaled source parent. Existing records refuse before delivery, and a lost
reservation reply never authorizes adoption. The journal retains frozen identity,
full native IDs, filesystem identities, allocation intentions, writer completion,
original outcome and independent liabilities. Lost delivery replies retain the
owned source parent; they establish neither removal nor writer completion.
The journal additionally freezes the explicit engine, source mount and closed
payload argv before delivery. Recovery derives these only from that exact root
record. Missing or contradictory branch facts retain uncertainty; Bash requires
no network ID, bridge or owned chain and `not_allocated` network liability.

Create the container stopped, record full ID/operation labels in a root-controlled
record, then install and verify the operation-owned systemd deadline. It must
survive Runner/SSH loss. API response timeout, Ansible async expiry and
`stop_timeout` do not schedule daemon-owned payload termination.

Start only the trusted gate after deadline verification, not direct Ansible.
Revalidate its exact identity/PID namespace and observe host-installed namespace
policy before release. Deadline or lost preparation leaves user content
unstarted and closes the exact container; no re-entry renews the invocation.

The trusted public close helper supplies identity-checked native stop/kill/readback
only. Gate start/release, normal completion and deadline closure serialize on the same
root-controlled operation lock/record. A deadline that wins before start marks
the invocation closed; start then refuses. A started invocation cannot renew its
deadline, recreate missing payload or dispatch another container on re-entry.
Record the timeout decision separately from exit status; do not infer timeout
from a nonzero exit or loss of SSH alone.
Lock acquisition and the complete pre-release critical section are finite. The
close helper records its actual closure decision under that lock; timer firing
after an observed ordinary exit does not change it into a timeout. Exact absence
requires a successful full-ID daemon listing, never interpretation of an error.

Normal completion may disable the exact owned deadline only after observing
process closure while holding that same serialization boundary. Stop the exact
timer and settle any already-running deadline service after close-helper lock
release. Never wait on a service that needs a held lock. Retain the nonprivate
root-owned closed record after deleting its keys/gate and source workspace;
existing records refuse re-entry, including after successful cleanup.
If process state is unobservable, retain keys/workspace/policy and report unknown
closure; process death is not inferred from expired central timeouts.

After stopped/PID-zero or exact absence: collect bounded terminal observations,
remove the exact owned container and observe absence, then remove fresh private
copies/workspace, the exact network/rules and deadline artifacts. Retain original
failure plus any closure failure independently. Reboot, daemon loss and concurrent
cleanup still need connected proof; systemd installation alone is not that proof.
Log collection failure does not prevent independently safe owned cleanup. Existing
invocations refuse redispatch and retain unknown process/material liability.

## Observe And Settle

Exactly one carrier is allowed: fresh `template_execution` or closed
`template_execution_recovery` containing only `operation_id`,
`controller_server_id`, `source_digest`, `input_digest`, `mode` and `log_bytes`.
Mode is `observe` or `settle`; the strict integer log budget is `0..65536`, no
greater than the original recorded budget. Recovery accepts no source manifest,
target authority, private-key lookup or input reread.

Observe reads only bounded unchanged journal/native full-ID facts; it creates no
lock, renews no deadline, and starts or removes nothing. Successful exact absence
differs from an unavailable daemon. Settle uses existing close/cleanup owners
without redispatch, private copying or gate release. Known original outcome is
independent of current closure; an unfinished writer retains material even after
process closure. Verified removal leaves a nonprivate tombstone. Replay reobserves
rather than recreates resources, and finite locked journal settlement refuses a
changed generation rather than replacing concurrent original observations.

At recovery `log_bytes: 0`, skip payload logs entirely and return `logs: ''`,
`logs_truncated: false`, including unknown/failure. The first central profile uses
zero; positive recovery logs are official-only pending authorized redaction
delivery. Fresh logging is unchanged. Log failure does not block independently
safe owned cleanup. The central admitted consumer owns management-success and
original Job/UID qualification; later settlement never rewrites original failed
Operation/Run history or upgrades liability to successful management execution.

Only signed settle may additionally carry backend-only `terminal_bash_gate_fence`:
exact `controller_source_digest`, `job_name`, `job_uid`, `condition: failed`.
Central authority freezes/rechecks the original official source/engine, exact
original Job/UID terminal and current manager. The application `source_digest`
is not that procedure digest; the host does not authenticate Kubernetes itself.
Normal observe, Ansible and completed-terminal recovery retain the six-field carrier.

The exception requires an authentic Bash `gate_pending` journal with
`writer_closed: false`, fixed argv, exact full-ID labels and network-none. Accepted
preparation persists this phase only after allocations, stopped restrictions and
active deadline; its remaining locked shell cannot allocate another container or
workspace. Qualified settle refreshes the original record's copied close helper
from current trusted source under its no-follow identity/generation lock; observe
never changes it. The helper places permanent root and mounted-gate closed
tombstones under that lock, then stops only the exact ID. Native full-ID removal
and positively observed absence precede deadline/private release. This fences
effects, not preparer descendants: `writer_closed` stays false and original
outcome/history stay unchanged. Delayed start cannot recreate the absent ID;
release cannot recreate deleted directories. Earlier phases, other engines,
ambiguous identity, lock/removal/CAS failure retain unresolved liabilities.

A failed exact deadline stop still requires authoritative readback of both owned
units; only rc3/4 for each establishes removal. Signed exceptional settle may
resume a closed/material-removed partial finalizer after unchanged locked journal,
root tombstone, exact full-ID absence and no-follow absence of every recorded
source/private allocation. It runs only remaining deadline cleanup and journal CAS,
without refreshing helpers or recreating material; writer completion and original
outcome/history remain unchanged. Active or unknown units retain liability.

One `Controller recovery observation: ` message separately reports authenticated
phase/writer completion, root/gate closed and release presence, exact current
running/PID-zero/ExitCode/OOM and timer-active/never-triggered facts. Unknowns are
null, never inferred absence or original payload outcome. Stored ASCII JSON plus
the fixed prefix/newline is bounded to2048 bytes with same-membership unknown
fallback; no paths, logs, raw errors, cgroups or historical attribution are emitted.
This correction requires isolated production behavior review and later coupled
publication/native qualification; terminal management alone is not writer death.

Final management progress and play exit share one internal classification. Fresh
execution retains its payload-success/cleanup requirements. Recovery must finish
the entire qualified read/cleanup include without a later refusal or collection
failure. Qualified observe can retain original outcome and current uncertainty;
settle additionally requires observed process closure and no retained cleanup
state or cleanup/log failure. Original unknown, failed or timed-out execution
does not itself fail management, and remains unchanged in result/journal/history.

## Logs And Plain Results

Keep exit observation independent of output collection. `detach: false` calls
the installed module's log reader with `tail: all` and stores raw `Output` even
when `output_logs: false`. Auto-removal also loses terminal inspection. Both are
excluded from this profile.

Select an explicit qualified `log_driver` plus finite `log_options.max-size` and
`max-file` before start to bound daemon retention separately. Driver rotation is
not an exact aggregate byte quota or the returned-log limit; a hard storage quota
cannot be claimed from these options. An independently bounded native reader
must limit input before Ansible registration, preserve observed stdout/stderr
frame order with TTY disabled, and return valid UTF-8 within the selected budget,
including any truncation marker. Do not read all output and truncate afterward,
perform an unbounded slurp or publish raw module errors/inspect.

The pinned modules expose no byte-capped log read. Collection requires a narrow
native bounded-stream binding within the existing control closure, not another
executor. Missing bounded collection/retention support refuses before start.
User output still follows the existing protected-value redactor; truncation and
redaction do not promise that arbitrary payload output contains no secrets.

`OPERATION_STEP` reports preparation, execution and cleanup progress.
`TEMPLATE_OUTPUT_JSON` carries plain `template_execution_result` fields:
`operation_id`, `controller_server_id`, `outcome`, `reason`, `original_reason`,
`container_id`, `exit_code`, `timed_out`, `process_closed`, `material_cleanup`,
`network_cleanup`, `deadline_cleanup`, `logs` and `logs_truncated`.
Outcomes are `unknown`, `refused`, `succeeded`, `failed` or `timed_out`; reasons are
`invalid_inputs`, `unsupported_profile`, `delivery_failed`, `policy_failed`,
`deadline_failed`, `execution_unknown`, `exited`, `execution_failed`,
`deadline_expired`, `existing_invocation`, `log_collection_failed` or `cleanup_failed`. Cleanup states are `not_allocated`,
`retained` or `removed`. Identity/exit may be null; refusal does not imply an
observed payload exit. `material_cleanup` refers to private keys/gate/workspace,
not removal of the nonprivate closed record.

Refusal before start, observed zero/nonzero exit, deadline termination and unknown
execution are distinct outcomes. Closure states distinguish not allocated,
retained, observed removed and failed/unknown. Cleanup failure never replaces the
original execution reason or makes resource release successful. A retained ID is
evidence to settle, not redispatch or unrelated-destruction authority. Existing
Run/stage owners attach these facts to the actual executing Job; no private
mirrored API proof protocol is required.

## Delivery Boundary

The finite candidate native closure is adjacent `user_ansible_controller.yml`,
`../tasks/user_ansible_controller_prepare.yml`,
`../tasks/user_ansible_controller_cleanup.yml`,
`../tasks/user_ansible_controller_recover.yml`,
`../scripts/user_ansible_controller_close.sh` and
`../scripts/user_ansible_controller_start.sh`. Central
admission/private-key delivery precedes connected executable consumer wiring. Native
pre-release DNS enforcement through the decided trusted gate, serialized host deadline, bounded stream collection,
effective resource/mount enforcement and remote loss/recovery require actual
demonstration, then proportionate tests and separately authorized live acceptance.

Installed evidence: runner image
`sha256:1e42eba472994ebd5df283d3b196ba9beac5324324ace59e889928f24a654adb`;
collection `plugins/modules/docker_container.py`, `docker_container_info.py`,
`docker_image_info.py`, `docker_network.py`; implementation
`plugins/module_utils/_module_container/module.py` and `docker_api.py`.
Detached output behavior is in `module.py` lines1157-1189 and `docker_api.py`
lines369-385; image-volume merging is in `docker_api.py` lines1692-1715.
Read-only, nonroot, network-disabled source inspection used no daemon socket.
The isolated demonstration executes the production tasks and both helpers with
finite SSH/module, root-identity, daemon, firewall, systemd and timed-flock
transport substitutions. File byte/mode checks and owned filesystem removal are
actual; root ownership, daemon restrictions and containment are not. No live SSH,
firewall, systemd or user payload execution was tested.

The target-local Bash isolated behavior is accepted with labelled external
transports substituted; affected regression evidence awaits checkpoint review.
Qualified immutable image startup is not live containment acceptance;
effective special mounts, resources, network isolation and independent deadline
still require separately authorized host proof.
