# Prometheus Blackbox Observation

Read-only journey observation on exactly one selected inventory host B. The
accepted adjacent helper requires Python3 and PyYAML at that execution location;
missing support returns unknown without installing packages. Native configuration
normalization is pinned to blackbox0.27.0 and Prometheus3.9.1, not arbitrary versions.
This procedure neither probes A itself nor reloads configuration.

## Inputs

The application envelope contains the closed `opsctl_inputs.monitoring_observation`
object: `bindings`, `prometheus_base_url`, `exporter_base_url`, `target_url`, `module`,
`job`, `instance`, `declared_module`, `declared_job`, `max_age_seconds`.
Origins are the admitted B-loopback pair `http://127.0.0.1:18175` and
`http://127.0.0.1:18178`; no redirects, proxies, authentication or alternate origins.
The frozen HTTPS installer target is also `instance`; module/job are
`wordpress_https`, with strict integer age1..60 seconds. Declared projections
match the explicit module/job profile in the accepted journey input, not hashes
of marshaled loaded YAML. No caller query, credentials or expected success.

`bindings` contains UUIDs `server_a_id`, `deployment_a_id`, `server_b_id`,
`deployment_b_id`, `node_b_id`, `install_operation_b_id`, `project_id`,
`source_revision_id`; full `prometheus_container_id`/`exporter_container_id`;
digest-qualified `prometheus_image`/`exporter_image`; SHA-256 `inventory_digest`,
`effective_checksum`, `prometheus_config_sha256`, `exporter_config_sha256`; and
confined relative `prometheus_config_path`/`exporter_config_path`.
These are safe declared associations, not observations of Docker/resource identity.
Current authorization and PM2's exact pre/post workload inspection bind the actual
Run/input/source/placement. No B identity is supplied by the procedure.
Ordinary controller-A/target-B admission selects the authorized user SSH key,
applied ServerSshAccess/fingerprint and exact Vault version; system/platform key
payloads are refused. This source pairing does not qualify live admission,
rootful Docker/systemd/cgroup/firewall/deadline containment or the preexisting
pinned controller image. Actual B/key/invocation identities remain unset.

## Observation And Limits

Exactly five fixed no-retry HTTP reads: active targets, loaded Prometheus config,
loaded blackbox config, exact equality-label `probe_success`, and its timestamp
at the same captured evaluation time. Require one exact business-label target and
one exact series per query; metric name is separately checked and timestamp's
dropped metric name is not fabricated. Scrape/sample ages use the underlying
sample value, never the instant query response timestamp. Qualified down/zero is
failure; stale, ambiguous or unavailable observations remain unknown.

Each HTTP worker is killed/waited by its parent at10 seconds, including slow
headers/body; total collection60 seconds. Response cap262144 bytes,
aggregate1048576, decoded config65536 bytes,4096 lexical/composed nodes/depth16,
256 targets/modules/jobs. Reject compressed responses, duplicate JSON/YAML keys,
nonstring YAML keys, unsafe tags/aliases/anchors/merges, nonfinite clocks/values
and unqualified additions. Output is one complete JSON line at most16384 bytes;
overflow returns a safe unknown, never clipped JSON. Raw bodies/config/errors
remain private under native task `no_log` and are never helper stdout.
The helper owns report construction and semantic qualification. The playbook
checks transport framing, closed public fields and the exact ASCII serialization
including newline; PM2 qualifies journey reports and immutable pre/post association.

## Public Report

Closed scalars/booleans/nulls: `outcome`, `reason`, `collection_origin:host-on-b`,
`probe_origin:workload-on-b`, `loaded_job_matches`, `loaded_module_matches`,
`target_healthy`, `last_error_empty`, `probe_success`, `native_start`, `native_end`,
`evaluation_time`, `last_scrape`, `sample_time`, `max_age_seconds`.
Unavailable facts are null. Outcomes are succeeded/failed/unknown; reasons are
observed, probe_down, probe_failed, invalid_inputs, unsupported_prerequisite,
association_mismatch, ambiguous_target, ambiguous_series, config_mismatch,
stale_observation, clock_invalid, response_unavailable, response_invalid,
response_limit_exceeded, collection_deadline, report_limit_exceeded.

Reports do not echo declared identities or selectors. Correlation uses the frozen
invocation/input/source, exact native management and current pre/post A/B receipts.
Protected-output redaction remains enforced; a malformed or redacted report is
uncertain, not evidence of successful observation.

Host-on-B API collection is not itself a workload-origin probe or B identity
proof. Exact loaded-config/target/series association and separately qualified
placement are necessary; self-scrape, HTML/TCP success and stale history do not
qualify connectivity. The authored slice is behavior-accepted and covered by
focused isolated regression, not published or live-ready. Native containment,
real B probe and connected invocation remain held.
