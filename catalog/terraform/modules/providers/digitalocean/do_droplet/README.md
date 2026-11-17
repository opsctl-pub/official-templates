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

Retirement reuses this module's existing state and `compute_present`; there are
no disposable import/delete resources or flat creation-input aliases.

## Behavior

### Persistent Server state (implementation in progress)

`managed_state` declares the two addresses in this one module and `compute_present`
(default true). Retirement first plans with compute absent while retaining the
firewall. OpenTofu leaves its live name, rules and Droplet attachments unchanged
after creation. After independent
host absence and current ownership checks, a normal destroy removes the remaining
firewall. This proposed ordering still requires pinned-provider and live proof;
setting the input alone is not deletion authority. No resource targeting is used.

For retirement and adoption, the same procedure accepts `action:"prepare_native_plan"`,
`scope` and original `variables`. It reads only the exact owned firewall and returns
`{"present":true|false}` (null/exit1 when unavailable). Runner derives the declared
`protection_present` input inside that planning Job, so missing protection is not
recreated. The saved plan binds this value; approved caller inputs stay unchanged.

`opsctl_adoption` selects exact existing `compute_id` and nullable owned
`protection_id` for import-only native planning. It reads their current values and
imports them at the same declared addresses; any planned provider mutation refuses.
An absent host uses `compute_present=false`; unowned/shared protection is never
selected. Adoption does not need creation inputs or management-key registration.
Later rule updates use the declared ingress procedure.

The declared policy procedure accepts `action:"validate_native_plan"`, `scope`,
`variables` and the native JSON `plan` on stdin (16 MiB maximum). It uses no HTTP
or credentials and returns only `{"allowed":true}` or a refusal. Runner separately
bounds exact addresses, actions, identities and replacements. Creation checks the
approved neutral input. Compute removal cannot change the firewall. Remaining-state destruction
requires no retained compute or foreign attachment. Overrides implement the same
plain policy contract rather than a private attestation protocol.

Create the requested Droplet, attach selected keys and declared firewall ingress.
Outbound TCP/UDP/ICMP is allowed.
Nondefault SSH uses the existing shared first-boot template. An unbound selected
resource is imported once before mutation; subsequent work uses the same state.
The module does not search for deletion targets, install Docker or establish
management SSH trust/reachability.

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

## Declared ingress procedure (source only)

The optional v3 `ingress` capability selects [ingress.sh](ingress.sh) and its
provider-owned [policy projection](ingress.jq). This source is **unexecuted**;
serving callers remain unchanged. This private source wires creation reads into
the original apply Job; it is not execution or serving acceptance. The procedure requires the Runner's
existing POSIX shell, curl, jq and sha256sum; no Python/provider SDK is used.

Supply one finite JSON object on stdin (32 KiB maximum). The exact common fields
are `format_version:1`, `action` (`creation`, `observe`),
`provider_instance_id` (decimal Droplet ID), `firewall_id` (recorded UUID),
`region` (recorded slug), `ssh_port` (integer 1–65535), `managed_rules` and
`managed_private_rules`. Region is sealed context, not a discovery selector.
Public rules are exact `{protocol:"tcp"|"udp",port:<integer>}`. Private rules
are exact `{protocol:"tcp",port:<integer>,source_addresses:["<IPv4>/32"]}`;
the backend must have authorized each exact peer. No credential or URL is input.
Rules are unique. Creation and each expected before/after state have at most35
public entries; configuration observation accepts their union of at most67.
Private unions contain at most64 entries. The SSH
TCP rule is required; public/private scope for the same protocol/port conflicts.
Private SSH/80/443 bindings are refused. Unknown fields/contradictory requests
are refused before HTTP. Credentials use only `DIGITALOCEAN_TOKEN`; the token is
read through a private header file, never a command-line argument.

`creation` supplies the complete expected ingress. Only the exact firewall and
that Droplet's firewall attachments are read, with a 360-second total wait.
Runner bounds creation invocation to 375 seconds; observation retains a
60-second module budget and 75-second invocation ceiling.
Complete requires the exact attachment, no tags, settled policy and the expected
managed rules. Additional rules are preserved. Broader access on a private listener
prevents a private-access match.
`observe` supplies the union of current/requested managed rules. It reads once,
returns the managed subset actually present and separately preserves all foreign
policy. Waiting/failed attachment state is explicit in `settled`, not readiness.
No name search or account-wide inventory is performed.

The signed `change` request adds `step`, `expected_before`, `expected_after`
and `preserved_policy`. `step` is `{action:"add"|"remove",rule:<one public or
private rule>}`. Each expected state is an exact object with `managed_rules`
and `managed_private_rules` arrays, drawn only from the supplied union. Their
only difference must be that single step. Both retain management SSH. Public
TCP SSH changes, removal of TCP80/443, and private SSH/80/443 changes are refused.
`preserved_policy` is the full object returned by observe, not a provider payload.
The procedure qualifies the exact attachment and managed state, sends one targeted
rule request when needed, and reads back the result. Unrelated live policy can
change without blocking the command. Readback settles an uncertain response
without resending the writer.

Stdout is one object (256 KiB maximum): `format_version:1`, original `action`,
`provider_instance_id`, `firewall_id`, UTC `collection_started_at` and
`collection_completed_at`, `status` (`complete`, `unknown`, `unsupported`,
`rejected`), nullable safe `reason` and nullable `observation`. Complete exits0;
other results exit1 and carry no observation. Creation's complete observation
is null. Scripts emit no Operation markers; Runner publishes the public object.
Native authentication, throttling, malformed/truncated data and timeout are
unknown, never absence or a successful match. Private temporary files are
removed on normal exit/interruption; no raw provider error is returned.

Observe/change complete returns the plain policy-observation fields:
`provider_instance_id`, `firewall_id`, sorted `rules` pairs and `private_rules`
triples, `attached_firewall_ids`, `attached_instance_ids`, `settled`,
`policy_fingerprint`, `fingerprint`, `preserved_policy`, UTC `observed_at` and
`observation_complete:true`. There is exactly one owned Droplet/firewall pair.
Native ingress/egress each have at most100 rules. Each allow rule preserves its
protocol and single/ranged ports (ICMP uses null endpoints); peers retain sorted
`kind`/`identity` for canonical strict IPv4/IPv6 networks, Droplets, tags, load
balancers and Kubernetes IDs. Unrepresentable peers, duplicate/overlapping
managed rules, pagination and attachment drift refuse qualification.

Fingerprint meaning is unchanged: compact sorted-key ASCII JSON, SHA256 over
`{id,instance,name,unrelated_ingress,outbound,tags:[],attachments,
raw_unrelated_ingress,raw_outbound}`. Normalized foreign inbound/outbound and
raw policy arrays sort by their canonical JSON. Policy JSON is bounded to64 KiB.
`preserved_policy` contains `name`, normalized `unrelated_ingress`/`outbound`,
exact attachment arrays and that `fingerprint`. The overall fingerprint hashes
compact JSON `[policy_digest,sorted_public,sorted_private,settled]`, omitting
`sorted_private` only when no private union was supplied. Native unrelated rules,
outbound rules, name and attachments are never replaced by a managed change.

### Creation caller contract (unexecuted source)

The ingress declaration's optional `firewall_output` is required when `creation`
is declared. Here it names `firewall_id` exactly, without provider-name or
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
without captured creation ingress requires fresh review before new work. Verify
captures ingress in its existing native read Job; comparison consumes that record,
and configuration captures this procedure for its approved native children. No behavior here
has been demonstrated or accepted by this source handback.

### Verify reuse (unexecuted source)

Verify captures an optional ordered ingress read beside each existing primary
target in the same account/module group and Job. Only provision-owned Servers
with recorded firewall output, exposure, SSH port and qualified private bindings
supply a scope. Imported/registered inventory and unavailable scope use null;
there is no guessed firewall ID or peer/network/source lookup during ingestion.
DO selects declared `observe`; AWS selects its declared creation-only exact
match. `change` is never a Verify action.

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

The API creation-ingress recovery poll and DO/AWS creation reader are removed
in this private source. Configuration uses the same declared procedure through
the original Run's native children. Preview consumes qualified recorded Verify
facts from the same captured source and checks for conflicting private access.
Each approved remove-before-add step has one durable claim/native child;
no-op uses one observe child. Unknown keeps the original claim pending. Only
explicit replay can request read-only reconciliation after terminal/material
closure; before/unsettled/unknown never authorizes a repeated write. Settlement
requires the fresh managed after-state and current authority and peers.
The old Python firewall readers/writers are removed. This source has not run:
the earlier credential-free diagnostic does not qualify Verify, provider
behavior, AWS parity or serving acceptance.

## Existing private network procedure

`network` declares `network.sh` with read-only `domain`, `targets` and `creation`
actions. No network resource is created, adopted or modified. AWS has no such
capability. The request is one closed JSON object (32 KiB maximum):
`format_version:1`, `action`, exact `network_id`, nullable `region`/`ipv4_cidr`,
ordered `members` (native Droplet IDs, at most32) and `listeners` (at most128).
A listener is `{from_id,to_id,protocol:"tcp",port}` with distinct selected
members. Domain requests have null region/CIDR and empty members/listeners;
targets require the approved region/CIDR. Creation selects exactly one allocated
member and no listener. Credentials remain solely in `DIGITALOCEAN_TOKEN`.

One15-second overall budget covers exact VPC, Droplet and attached-firewall GETs,
with no retries or inventory fallback. Complete membership requires the same VPC,
region and private IPv4 CIDR and one unique usable private host per member. The
complete bounded firewall page must have matching total, no next page, unique
firewalls, settled direct membership and no tag attachment. At most100 firewalls,
100 inbound/outbound rules per firewall and100 peers per rule are admitted.
Native allow rules normalize protocol/port ranges and canonical address/instance/
tag/load-balancer/Kubernetes peers. Policies sort by canonical compact ASCII JSON;
SHA256 of that exact policy JSON is the source-owned access fingerprint.

Listener qualification requires permitted consumer egress and a directly attached
producer firewall. Matching producer ingress may cover only the selected consumer
instances or exact host/32 addresses of the approved consumers; public, broadened or foreign
or unrepresentable access refuses. A safe policy lacking the consumer allowance
returns that listener in `missing_listeners`, allowing normal imported-peer
instructions. Missing egress, unsettled/incomplete/malformed/unauthorized reads
are unknown, never missing-listener permission or observed workload reachability.

Stdout is one bounded JSON result: `format_version`, original `action`/`network_id`,
ordered UTC `collection_started_at`/`collection_completed_at`, `status`, nullable
`reason`, explicit `profile` (`digitalocean/existing-vpc`), `region`, `ipv4_cidr`, ordered `members` (`id`, `host`,
`access_fingerprint`) and `missing_listeners`. Complete exits0; unknown,
unsupported and rejected exit1 with null domain and empty fact arrays. Raw
responses/credentials never appear in the result. Creation reports membership
only, without asserting listener access. Runner appends it as reserved auxiliary
`provider_network` after successful ordinary/saved apply; original outputs,
artifact and native success remain unchanged when membership is unavailable.
Selected VPC data/preconditions qualify exact ID/region/CIDR before allocation;
Destroy and simulation skip that data read. No VPC lifecycle ownership is implied.
