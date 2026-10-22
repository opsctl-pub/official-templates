# OpsControl Official Templates

Procedures for configuring and observing Servers with OpsControl. Start with the
[catalog](catalog/README.md) to find a procedure's inputs, behavior, results and
failure handling. Organization overrides can replace a procedure while preserving
its documented inputs and results; OpsControl still authorizes and sequences runs.

## Structure

- `catalog/ansible/playbooks/`: Procedures grouped by task, with adjacent documentation and declarations.
- `catalog/ansible/tasks/`: Shared procedure tasks.
- `catalog/ansible/scripts/`: Native helpers.
- `catalog/ansible/roles/` and `catalog/ansible/templates/`: Baseline tasks and rendered configuration.
- `catalog/ansible/inventory/`: Runner inventory.
- `catalog/terraform/modules/`: Provider HCL consumed by OpenTofu.

Each registered entrypoint has a matching `.contract.json` declaration describing
its result/completion format or associating the item and engine with its adjacent
documentation. HCL modules also have a separate optional Server-create family
declaration. Shared tasks and helpers support the entrypoints; they are not
separate catalog items.

## Selecting a source

Admin Official Sources selects an accepted immutable repository revision.
Automation Overrides selects an organization's accepted replacement source.
Tracking a branch does not automatically use later commits. Accepting a revision
checks its paths and declarations; it does not run the procedures.

Keep credentials and private files in protected delivery, never logs, example
variables or results. Missing or incomplete observations remain unknown; a
completed progress step alone does not establish the procedure's final result.
