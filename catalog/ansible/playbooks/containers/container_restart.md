# Restart installed Deployment containers

`container_restart` restarts the exact installed image container or recorded Compose
service/replica group on one Server. It interrupts application work and loses
in-memory state. Persistent storage stays attached; application-consistent writes
and HTTP/TLS/DNS health are not promised.

The reviewed backend supplies `restart_profile` (`image` or `compose`),
`restart_containers` (1–128 unique full Docker IDs with exact names), and for
Compose `restart_compose_project` plus each member's `service` and `replica`.
All members are inspected by full ID and checked before any effect. A missing or
replacement container refuses the group; names and labels never adopt a target.

The pinned Docker modules use `state=started`, `restart=true`, `recreate=false`,
`pull=never` and ignored configuration comparisons, with no image/configuration
arguments. Existing stopped containers can start. There is no build, recreation,
secret delivery, Hook replay, revision change or volume/network mutation.
Execution uses normal Runner/module bounds and the existing admitted budget.

The first actual module failure stops further restarts. `TEMPLATE_OUTPUT_JSON`
publishes only `restarted_container_ids` acknowledged by successful native module
results. Partial acknowledgements never certify whole-group success; the normal
Job/Run carries failure. A lost result stays unconfirmed and is not permission to
repeat an effect. Normal original-Job recovery remains the execution owner's duty.
Raw Docker facts are `no_log`; normal progress uses `OPERATION_STEP`.

The result is not an installation receipt or health observation. Existing
inspection history remains intact; use the existing Inspect action for a new
snapshot. Organization Automation Overrides retain their normal source selection.
