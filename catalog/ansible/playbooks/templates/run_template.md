# Run Template

## Inputs and behavior

The trusted procedure delivers the frozen source through `materialize_template_files.yml`
and executes it on the one backend-selected Server. Bash runs on its authorized host;
user Ansible runs on its explicitly selected controller with the selected target keys,
inventory and observed known-host keys. The management Runner never executes user code.

`template_execution` contains the original Operation and selected Server identities,
source/input digests, engine, entrypoint, staged source manifest, selected targets and
timeout. Backend private staging supplies files; this is not a public arbitrary-path API.
Inputs are delivered as mode0600 `template-inputs.json` containing `opsctl_inputs`.
Bash receives `OPSCTL_INPUTS_FILE`; Ansible receives that JSON file through `-e @file`.

The host must already provide Bash or Ansible, GNU timeout and declared dependencies.
Execution uses the existing management login without adding a privilege policy or
installer. The requested timeout sends TERM followed by bounded KILL. CPU, memory,
PID, tmpfs and container-log limits retained in authoring are not host containment.
Generated user-content delivery is noninteractive and does not allocate an SSH PTY.

## Results and failure

Nonzero commands fail the Job. Presentation passes through the existing Runner redactor.
Normal success/failure removes only the materializer's exact private workspace.
Lost SSH, timeout or Job cancellation does not prove every remote descendant stopped;
the procedure supplies no remote replay, recovery or containment guarantee.
Generated controller-to-target SSH verifies enrolled keys without key updates,
uses invocation-private control sockets and closes those sockets before normal
workspace cleanup. Privileged overrides are excluded; TOFU/private-only first
enrollment limits remain.

## Progress

The imported [file-delivery contract](../../tasks/materialize_template_files.md) emits
`template:files` progress and `template_file_delivery` in `TEMPLATE_OUTPUT_JSON`.
That delivery result is not execution success. This entrypoint adds no structured
execution result: actual host command output and nonzero exit determine Job
presentation/failure, followed by workspace cleanup.
