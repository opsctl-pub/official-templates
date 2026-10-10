# Run Template

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

Nonzero commands fail the Job. Presentation passes through the existing Runner redactor.
Normal success/failure removes only the materializer's exact private workspace.
Lost SSH, timeout or Job cancellation does not prove every remote descendant stopped;
the procedure supplies no remote replay, recovery or containment guarantee. Platform
management SSH host verification retains its existing documented limitation.
