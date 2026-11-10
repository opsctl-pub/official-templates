# OpsControl Official Templates

Procedures for configuring and observing Servers with OpsControl. Organization
overrides can replace a procedure while keeping its inputs and results; OpsControl
still authorizes and sequences runs.

## Structure

- `catalog/ansible/playbooks/`: Procedures grouped by task, with their declarations.
- `catalog/ansible/tasks/`: Shared procedure tasks.
- `catalog/ansible/scripts/`: Native helpers.
- `catalog/ansible/roles/` and `catalog/ansible/templates/`: Baseline tasks and rendered configuration.
- `catalog/ansible/inventory/`: Runner inventory.
- `catalog/terraform/modules/`: Provider HCL consumed by OpenTofu.

Each registered entrypoint has a matching `.contract.json` declaration describing
its result format or naming its item and engine. HCL modules can also have an
optional Server-create declaration. Shared tasks and helpers support the entrypoints; they are not
separate catalog items.

## Selecting a source

Admin Official Sources selects an accepted immutable repository revision.
Automation Overrides selects an organization's accepted replacement source.
Tracking a branch does not automatically use later commits. Accepting a revision
checks its paths and declarations; it does not run the procedures.

Keep credentials and private files in protected delivery, never logs, example
variables or results. Missing or incomplete observations remain unknown; a
completed progress step alone does not establish the procedure's final result.
