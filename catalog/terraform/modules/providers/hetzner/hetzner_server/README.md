# Manage a Hetzner Cloud Server

## Inputs

This HCL source uses OpenTofu with privately supplied hcloud provider credentials.
`destroy` defaults to false. Creation requires `name`, `location`, `server_type`
and a positive decimal `image_id`. Optional `ssh_key_id` selects an existing key;
`labels` defaults to `{}` and `user_data` to empty. Destroy requires recorded
positive decimal `server_id`; `destroy_primary_ipv4` defaults to false and requires
`primary_ipv4_id` when enabled. See [variable declarations](variables.tf).

## Behavior

Create a Primary IPv4 with automatic deletion disabled, then a Server using that
address, the selected system image, key and optional user data. IPv6 is disabled.
The caller imports recorded state for the existing destroy path. The module does
not create a key, install a baseline, configure a nondefault SSH port or prove
provider/lifecycle support beyond the actual admitted caller. A retained `simulate`
variable does not itself run a plan or suppress resource changes; the caller owns
plan versus apply selection.

## Results

[Outputs](outputs.tf) report `server_id`, `name`, `ipv4_address`, `server_status`,
`location`, `server_type`, `labels` and `primary_ipv4_id`. Destroy mode uses empty
values/maps. Empty fallbacks do not establish observed absence; provider failure
can leave a retained IP or other partial resources for normal cleanup.

## Progress

This module uses native OpenTofu progress/output, not `OPERATION_STEP` or
`TEMPLATE_OUTPUT_JSON`.
