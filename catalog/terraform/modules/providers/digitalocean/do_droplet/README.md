# Manage a DigitalOcean Droplet

## Inputs

Creation accepts one `opsctl_server` object: `name`, `region`, `size`, `image`,
`image_metadata`, `tags`, `user_data`, `provider_config`, `ssh_port`,
`ssh_bootstrap_profile`, `public_ingress_rules`, `networks`,
`private_ingress_bindings`, `ssh_key` and `simulate`. Strings and collections are
bounded by the public API contract; credentials stay in `DIGITALOCEAN_TOKEN`.
The object contains no private management key. Runner simulation remains a
separate execution control and the object also identifies a simulation plan.

`ssh_key` carries `public_key`, `fingerprint`, `registered_id` and
`registered_name`. Ordinary creation uses the registered id. Saved planning
uses native `digitalocean_ssh_keys` filtered by fingerprint and requires exactly
one match with identical first two OpenSSH fields; it never creates a key.
Simulation skips registration and key lookup.

`provider_config.do` owns optional monitoring, backups and IPv6 (default false).
The single authorized `networks` domain supplies its VPC. Private bindings supply
only their exact peer host/32
and requested TCP port; they cannot discover peers or change network ownership.
Public rules use explicit TCP/UDP ports. `ssh_port` is an integer 1–65535; a
nondefault port requires the declared Ubuntu profile and empty user data.

Recorded Destroy keeps `destroy`, `destroy_target_names`, `droplet_id` and
`firewall_id`; there are no flat creation-input aliases.

## Behavior

Create the requested Droplet, attach selected keys and declared firewall ingress.
Outbound TCP/UDP/ICMP is allowed.
Nondefault SSH uses the existing shared first-boot template. The caller imports
recorded resources for the existing destroy path; this module does not search
for deletion targets. It does not install Docker or establish management SSH trust/reachability.

## Results

[Outputs](outputs.tf) include Droplet/firewall IDs, name, region, size, IPv4,
URN, private IPv4, optional IPv6, status, creation time, tags and the full provider
resource. `opsctl_server` is the plain version-1 allocation result: native identity,
hostname, region, size, canonical status, nullable IPv4 addresses, tags, `ready`
and nullable `reason`. Native active status plus usable public IPv4 is ready;
other statuses remain factual and report not ready. Readiness is independent of
managed ingress and SSH setup. The platform retains an unready allocation as a
failed, charged Server without rewriting this result. Saved apply selects the
seven original registration outputs plus this result. Observation stays isolated
in the data-only root below.

## Progress

Use native OpenTofu progress/results. No module-owned `OPERATION_STEP` or
`TEMPLATE_OUTPUT_JSON` is emitted.

## Read-only observation

The independent [observe/](observe/main.tf) root accepts only `targets`, an ordered
list of `{name, id}` objects (`droplet`, `firewall`) with exact string IDs.
The v3 item contract declares no additional observation inputs. Credentials use
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
