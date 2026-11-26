# Manage an AWS instance

The managed root uses the recorded region and native AWS credentials. Saved
creation creates the instance and its security group using the registered
organization key. Saved retirement removes compute before the security group.
Both phases use the original state and recorded identities.

## Creation input and result

Creation accepts one `opsctl_server` object: `name`, `region`, `size`, `image`,
`image_metadata`, `tags`, `user_data`, `provider_config`, `ssh_port`,
`ssh_bootstrap_profile`, `public_ingress_rules`, `networks`,
`private_ingress_bindings`, `ssh_key` and `simulate`. The fixed public object
contains no credentials or private key. Native AWS credentials stay in their
execution environment.

The module maps size to instance type and requires a nonblank
`image_metadata.ssm_parameter_by_region[opsctl_server.region]` entry for the
sealed region. It reads that reference through native SSM and converts platform
tags to native tag keys with `Name` set to the actual requested name. The instance,
security group and root volume receive those same tags at launch. A bounded
exact AMI read qualifies an EBS root with no additional EBS mapping. Ordinary
creation uses `ssh_key.registered_name`; the public key and fingerprint do not
grant registration authority. Simulation skips key registration. Initial SSH
uses the declared port/Ubuntu profile and existing shared cloud-init template.

The plain `opsctl_server` version-1 result contains the allocated identity,
hostname, region, size, canonical status, nullable public/private IPv4, tags,
`ready` and nullable `reason`. Only running plus usable public IPv4 is ready;
other native states map honestly, including explicit unknown. An unready
allocation remains a failed, charged Server without changing this raw result.
Raw instance/security-group/AMI outputs remain available to existing callers.
`root_volume_id` comes from the actual native instance root block. Retirement
uses that exact ID independently of launch tags.
Native readiness does not attest managed ingress or SSH setup.

## Saved retirement

The compute plan may delete only the recorded instance. Its security group and
rules stay in place until exact instance absence is confirmed. The plan must
show the recorded root volume with deletion on termination and no additional
EBS volume set to delete on termination. The module corroborates those facts
with one exact `DescribeInstances` read during plan and another immediately
before saved apply. Unknown, incomplete or conflicting attachments refuse.
AWS termination has no attachment revision precondition, so the fresh read
narrows the interval in which an external change could invalidate the check.

The remaining plan may delete only the recorded security group. The saved apply
uses the declared procedure for one exact group deletion and confirms absence
before settling native state with a saved refresh-only plan. The procedure
leaves dependencies in place. An explicit AWS dependency refusal leaves the
group for fresh review. An uncertain delete keeps the original retirement held.
Final settlement requires independent absence of the instance, security group
and root volume. The volume never receives its own mutation permission. A
present or unqualified volume holds retirement open.

## Leased certification

The private certification procedure qualifies the sealed proof Name and birth
tags across complete instance, security-group and volume inventories. It can
report an owned root volume after the instance disappears. The backend records
the exact IDs before admitting fallback. Cleanup can terminate only their
exact instance, delete only their exact security group, and delete the recorded
root volume only when AWS reports it available and unattached. The procedure
does not detach, revoke, or retry an uncertain delete. A separate exact read
confirms absence before the certification records cleanup.

The original failed-create observer uses the sealed Name and tags for all three
inventories. Any surviving matching group or volume prevents release of the
failed apply's retained material and capacity through that observer.

## Read-only observation

The independent [observe/](observe/main.tf) root requires an ordered `targets`
list of `{name, id}` objects (`instance`, `security_group`, `volume`) and a nonempty
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

EBS volumes use one exact `volume-id` filter per recorded `vol-…` ID through
`aws_ebs_volumes`. One matching result establishes presence. A successful
empty result establishes absence. A different or extra ID yields unknown
with `identity_conflict`. Lifecycle, size and addresses are unsupported
for present volumes. Volume observation cannot grant deletion authority.

Pairs must be unique; repeated names with different IDs support batched Servers.
`opsctl_provider_observations` is keyed by exactly the string request ordinals
`"0"` through `"N-1"`. The Runner joins by ordinal and ID, preserving the original
ordered `{name, id, observation}` list. Each value has
the requested `id`, `presence`, `reason`, nullable `provider_observed_at`, and
`lifecycle`, `size`, `public_ips`, `private_ips` objects with
`coverage`/`value`/`reason`. Empty complete IP lists mean observed empty inventory.
No creation timestamp is presented as an observation clock. The Runner adds UTC
collection clocks and emits the versioned `provider_observations` result. Reads
are dated facts, not current health or universal provider-parity claims.
Retirement uses this read for its ordered absence gates. Failed reads never
establish absence.

The v3 item contract declares `region` from the recorded Server metadata/region
selectors and declares the exact retirement targets.
The [shared formatter](../../../opsctl/observation/main.tf) alone constructs
coverage envelopes from raw native facts. Exact full-package materialization
preserves this local dependency's revision and relative path. The Runner
requires exactly the captured `input_names`/`inputs`, with finite JSON bounded
to 32 KiB; HCL owns provider input types. Destroy captures the same declaration
under `observation`, without a region-specific Python path or compatibility
fallback. One execution-private `TF_PLUGIN_CACHE_DIR` serves observation and
the native state steps and is removed at closure. Cold fetches remain a cost;
there is no persistent/shared cache or zero-network initialization claim.

## Declared ingress procedure

The optional v3 `ingress` capability selects [ingress.sh](ingress.sh), with
[ingress.jq](ingress.jq) owning its exact request/read projection. The creation action remains an exact readiness read. The observe and change
actions qualify public IPv4 TCP and UDP and reviewed private IPv4 TCP ingress
on the exact module-owned Server and security group.

Stdin is one finite JSON object, at most32 KiB, with exactly `format_version:1`,
`action:"creation"`, recorded `provider_instance_id` (`i-...`), `firewall_id`
(`sg-...`), `region`, `ssh_port`, `managed_rules`, `managed_private_rules`.
Public rules are exact `{protocol:"tcp"|"udp",port:<integer 1–65535>}`, unique,
at most35, including the recorded TCP SSH port. Private rules must be empty.
No URL or credential is accepted. Existing native AWS environment credentials
and AWS CLI are used with the explicit recorded region, no implicit endpoint
selection, metadata credentials, CLI pagination or write retry. No resource is
searched by name and no allocation/mutation is performed.

Only exact `describe-security-groups --group-ids` and `describe-instances
--instance-ids` reads are made within a 360-second total wait, with a 375-second
Runner invocation ceiling. Exactly one matching
group, one matching instance and its sole matching security-group attachment
are required. At most100 native ingress rules are considered; each must be a
TCP/UDP single port with exactly `0.0.0.0/0`. IPv6, group/prefix-list peers,
ranges, duplicates and unsupported protocol forms do not qualify. Complete
requires the exact expected rule set. Errors, malformed/truncated responses,
authentication and timeout never prove a match or absence.

Stdout is one version1 object with `format_version`, original `action`,
`provider_instance_id`, `firewall_id`, real UTC `collection_started_at` and
`collection_completed_at`, `status` (`complete`, `unknown`, `unsupported`,
`rejected`), nullable bounded `reason`, and `observation:null`. Complete exits0;
all other statuses exit1. The Runner bounds results to256 KiB and owns Operation
markers; the script emits only this JSON and no raw native diagnostic/secret.
Temporary files are private and removed on exit or interruption.

### Creation caller contract

The ingress declaration's optional `firewall_output` is required when `creation`
is declared. Here it names `security_group_id` exactly, without provider-name or
output-alias inference. Runner passes only `procedure`/`actions` to its confined
invoker. One shared request builder uses the original neutral `opsctl_server`
input's SSH/public rules and authorized private binding hosts as /32; allocated
identity/region come from the plain `opsctl_server` result and the firewall ID
comes from the explicitly declared original output.

`provider_ingress` is reserved for auxiliary evidence, not a declared firewall
or saved native output name. The declared firewall output must differ from the
provision result and be included when saved native outputs are selected. An
ordinary native output already named `provider_ingress` is preserved unchanged;
Runner does not overwrite it, and the typed creation gate refuses unavailable
evidence.

Ordinary creation appends `provider_ingress` alongside all native outputs after
successful apply/output selection. Saved create appends it beside
`opentofu_applied`/the unchanged `provider_outputs`, after actual saved apply
returns. The same original Job performs the read; no extra Job or apply exists.
Plans, simulation, updates and Destroy do not run this creation read. Missing
historical capability invents no result. Unavailable ingress retains native
allocation/apply success and exact artifact consumption; the API completion gate
fails creation while existing registration/capacity owners retain responsibility.
It qualifies original source/terminal custody and immutable reviewed intent;
saved evidence stays on the original closed apply child, not a synthetic root
receipt. Creation complete requires reason=null and observation=null. A source
without captured creation ingress requires fresh review before new work. Verify captures ingress in its existing native read Job.

### Verify reuse

Verify captures an optional ordered ingress read beside each existing primary
target in the same account/module group and Job. Only provision-owned Servers
with recorded firewall output, exposure, SSH port and qualified private bindings
supply a scope. Imported/registered inventory and unavailable scope use null;
there is no guessed firewall ID or peer/network/source lookup during ingestion.
Verify selects the declared `observe` action when available. `change`
is never a Verify action.
The observe-only `network_id` is the qualified VPC ID for that exact attachment and is omitted when evidence is unavailable.

The backend's closed read capture includes `exposure` and `private_bindings` for
current-scope requalification. Runner delivers only the eight plain procedure
request fields above, with the captured module's `procedure`/`actions`. Reads
run only for primary targets observed present. The original primary result is
retained; `provider_ingress_observations` adds `{version:1,targets:[{name,id,result}]}`
in that same order. Null means no usable ingress result. Failed ingress reads
retain failed native status, while Verify owns aggregate warnings. Each ingress
result is validated independently after ordered attribution; malformed ingress
cannot erase valid primary facts or a sibling's valid ingress.

Request/result evidence lives in the latest recorded provider verification.
Pending/unknown refresh supersedes prior ingress success. Before projection,
current Server/account custody, captured scope and the existing observation
freshness rule are requalified without another provider request. Scope drift
discards ingress only. Unavailable requested ingress warns while independently
usable lifecycle/size/address facts remain usable. Only complete, settled exact
desired public/private rules with no foreign inbound policy may repair an
unverified creation gate; AWS creation-complete supplies that exact match.
Desired exposure and peer bindings are never changed by Verify.

### Reviewed configuration

Observation cross-checks the exact instance, group and VPC, the sole attached
interface, and the bounded native rule inventory with its stable rule IDs.
An exact reviewed public IPv4 TCP or UDP single-port tuple or private IPv4
TCP /32 tuple qualifies as managed with its distinct module-owned description.
SSH, other ingress and egress are
preserved. All-protocol rules with absent ports or the exact AWS `-1/-1`
pair project as `all` with null ports. Unsupported
protocols, non-CIDR peers and incomplete pages refuse. Private changes also
refuse foreign tuples and broader overlapping inbound policy before writing.

One change requires the reviewed full fingerprint, the expected logical before
state and the preserved policy. Both states must fit the reviewed Plan's
rule union and differ by exactly the requested step. The full fingerprint includes native rule IDs,
so a replacement with the same tuple invalidates the review. The preserved
fingerprint covers the attachment, SSH and all foreign and outbound rules.
Add authorizes one allowance with the module description. Remove revokes only
the exact recorded rule ID. After a write attempt, one bounded read can settle
the expected after state with unchanged non-step rows. An unavailable or
conflicting read leaves the write unconfirmed. The procedure never retries it.

EC2 provides no atomic compare-and-write for this policy and attachment.
Fresh reads constrain the change and detect drift but cannot prevent an
external change in the gap before the write. Configuration has a 65-second
deadline inside the Runner's 75-second invocation ceiling.

### Existing provider network

The [network procedure](network.sh) reads an owned VPC in the credential's
configured AWS region. It requires one canonical private IPv4 CIDR and can
qualify one or two existing running instances in the requested order. STS,
the VPC, reservations, primary interfaces and exclusive groups must agree.
The attachment and complete native policy are fingerprinted for requalification.
The listener result requires exact approved peer hosts and source egress.
A missing rule is reported after complete observations. Broad or incomplete
policy leaves the result unavailable. These facts do not attest application
reachability. The declaration provides no creation action or VPC placement.
