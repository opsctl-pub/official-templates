# Manage an AWS instance

The creation root uses the recorded region and native AWS credentials. It
creates the requested instance, declared security-group ingress and optional
key pair, preserving the existing SSM image selection and SSH bootstrap.
`destroy_target_names` selects one recorded `instance` or `security_group` for
import and saved deletion; neither target is discovered by name.

## Read-only observation

The independent [observe/](observe/main.tf) root requires an ordered `targets`
list of `{name, id}` objects (`instance`, `security_group`) and a nonempty
`region`. It uses hashicorp/aws ~> 5.0, OpenTofu >= 1.13.2 and native AWS credential
delivery. No secret is a module input; no managed resource/import/apply belongs
to this root.

Instance inventory retains the exact instance-ID filter and the
pending/running/stopping/stopped/shutting-down state selection. Security groups
use the exact group-ID filter. Successful empty results mean absence; only a
unique matching instance receives a singular detail read. A matching detail ID
supplies type, lifecycle and native addresses. Pending/running/stopped/
shutting-down/terminated map to provisioning/active/stopped/destroying/terminated;
other statuses remain unqualified. Terminated instances excluded by the inventory
filter are absent from that live selection. Security-group Server attributes
are unsupported; errors or identity conflicts never imply absence.

Pairs must be unique; repeated names with different IDs support batched Servers.
`opsctl_provider_observations` is keyed by exactly the string request ordinals
`"0"` through `"N-1"`. The Runner joins by ordinal and ID, preserving the original
ordered `{name, id, observation}` list. Each value has
the requested `id`, `presence`, `reason`, nullable `provider_observed_at`, and
`lifecycle`, `size`, `public_ips`, `private_ips` objects with
`coverage`/`value`/`reason`. Empty complete IP lists mean observed empty inventory.
No creation timestamp is presented as an observation clock. The Runner adds UTC
collection clocks and emits the versioned `provider_observations` result. Reads
are dated facts, not current health or universal provider-parity claims. Destroy
uses this same read before import and after apply; failed reads never grant it
a deletion/absence result. Native AWS behavior remains unqualified until tested.

The v2 item contract declares `region` from the recorded Server metadata/region
selectors; it retains the existing Destroy inputs and import declarations.
The [shared formatter](../../../opsctl/observation/main.tf) alone constructs
coverage envelopes from raw native facts. Exact full-package materialization
preserves this local dependency's revision and relative path. The Runner
requires exactly the captured `input_names`/`inputs`, with finite JSON bounded
to 32 KiB; HCL owns provider input types. Destroy captures the same declaration
under `observation`, without a region-specific Python path or compatibility
fallback. One execution-private `TF_PLUGIN_CACHE_DIR` serves observation and
import/delete states and is removed at closure. Cold fetches remain a cost;
there is no persistent/shared cache or zero-network initialization claim.
