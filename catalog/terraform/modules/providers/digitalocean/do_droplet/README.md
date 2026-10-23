# Manage a DigitalOcean Droplet

## Inputs

This HCL module uses OpenTofu and private `DIGITALOCEAN_TOKEN` provider delivery.
`destroy` defaults to false; creation requires `name`, `region`, `size` and `image`.
`ssh_key_id` takes precedence over optional `ssh_key_name`. Monitoring, backups
and IPv6 default to false; `vpc_uuid` and `user_data` default to empty.
`ingress_rules` defaults to `[]` with explicit TCP/UDP ports; tags default to
`terraform` and `opsctl`. An optional nonempty `project_name` creates a provider
project and assigns the Droplet; this is not an OpsCtl Project.

`private_ingress_rules` defaults to `[]`. Each row has `protocol: "tcp"`, an
integer `port` (1–65535), and `source_addresses` containing one qualified IPv4
host `/32`. These are separate from public `ingress_rules`; the module never
discovers peers, changes VPC ownership or implies workload connectivity.

`ssh_port` defaults to 22. A different integer port (1–65535) requires a declared
Ubuntu 22.04/24.04 bootstrap profile and empty custom user data. Destroy mode
requires the recorded `droplet_id`; optional `destroy_firewall` defaults to false
and requires `firewall_id` when enabled. See [variable declarations](variables.tf).

## Behavior

Create the requested Droplet, attach selected keys and declared firewall ingress,
and optionally create the provider project. Outbound TCP/UDP/ICMP is allowed.
Nondefault SSH uses the existing shared first-boot template. The caller imports
recorded resources for the existing destroy path; this module does not search
for deletion targets. It does not install Docker or establish SSH trust/readiness.

## Results

[Outputs](outputs.tf) include Droplet/firewall IDs, name, region, size, IPv4,
URN, private IPv4, optional IPv6, status, creation time, tags and the full provider
resource. Existing `droplet_*` aliases remain unchanged. Destroy mode emits the
declared empty/null outputs, not an independent absence observation. Provider
failure can leave partial resources; no automatic rollback is promised.

## Progress

Use native OpenTofu progress/results. No module-owned `OPERATION_STEP` or
`TEMPLATE_OUTPUT_JSON` is emitted.
