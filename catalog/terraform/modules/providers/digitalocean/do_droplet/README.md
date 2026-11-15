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
selects one recorded target through `destroy_target_names` and uses its
`droplet_id` or provision-owned `firewall_id`. See [variable declarations](variables.tf).

## Behavior

Create the requested Droplet, attach selected keys and declared firewall ingress,
and optionally create the provider project. Outbound TCP/UDP/ICMP is allowed.
Nondefault SSH uses the existing shared first-boot template. The caller imports
recorded resources for the existing destroy path; this module does not search
for deletion targets. It does not install Docker or establish SSH trust/readiness.

## Results

[Outputs](outputs.tf) include Droplet/firewall IDs, name, region, size, IPv4,
URN, private IPv4, optional IPv6, status, creation time, tags and the full provider
resource. Observation is isolated in the data-only root below.

## Progress

Use native OpenTofu progress/results. No module-owned `OPERATION_STEP` or
`TEMPLATE_OUTPUT_JSON` is emitted.

## Read-only observation

The independent [observe/](observe/main.tf) root accepts only `targets`, an ordered
list of `{name, id}` objects (`droplet`, `firewall`) with exact string IDs.
The v2 item contract declares no additional observation inputs. Credentials use
native `DIGITALOCEAN_TOKEN` delivery. This root
pins OpenTofu >= 1.13.2 and digitalocean/digitalocean = 2.107.0. It contains no
managed resources, imports or application/destroy controls.

Pairs must be unique; the same name with different IDs supports batched Servers.
`opsctl_provider_observations` contains exactly the string request ordinals
`"0"` through `"N-1"`. The Runner joins each ordinal to the requested ID and
returns the original ordered `{name, id, observation}` list. Values retain the
requested `id`, `presence`, `reason`, independently qualified `lifecycle`, `size`,
`public_ips`, `private_ips`, and nullable `provider_observed_at`. Attribute
objects contain `coverage`, `value`, and `reason`; empty complete IP lists mean
observed empty inventory. Native statuses new/active/off map to
provisioning/active/stopped; other statuses remain unknown. Creation time is not
an observation clock. The Runner adds UTC collection clocks and publishes the
versioned `provider_observations` result; these are reads, not health guarantees.

One plural Droplet query uses the exact ID filter, never name or tags. A
successful empty filtered result means absent; one exact match supplies public
and private IPv4/IPv6, size and status. Each Firewall uses the singular exact-ID
lookup: its successful known-null ID means absent, while a matching nonnull ID
means present. Firewall Server attributes are unsupported. Errors, incomplete
plans and mismatched identities never prove absence; no REST fallback exists.
The shared Destroy executor uses this root before import and after apply.

The [shared formatter](../../../opsctl/observation/main.tf) alone turns raw
native facts into coverage envelopes. The complete captured source package keeps
that local dependency at the same revision and relative path in each private
state. The Runner requires exact captured `input_names`/`inputs` (finite JSON,
32 KiB total), independently of provider variable types. Destroy captures these
under `observation`; no old observation-input fallback is supported. One
execution-private `TF_PLUGIN_CACHE_DIR` is reused by reads and import/delete
plans and removed at closure. Its first cold fetch remains a cost; no persistent
cache or zero-network initialization is promised.
