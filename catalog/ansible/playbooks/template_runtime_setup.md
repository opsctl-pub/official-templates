# Template Runtime Setup

Registered management item `template_runtime_setup` prepares or verifies one
authorized existing Server. It runs no user source, target keys, interpreter or
probe container. Current authority and actual Server identity remain central.

The closed `template_runtime_setup` input contains canonical UUID `operation_id`
and `server_id`, `action: prepare|verify`, fixed profile
`managed-linux-systemd-docker-iptables-v1` and exact image
`alpine/ansible@sha256:8942d1bbd23d13ad2af40ae84241f52a796c7c6e24177587bcdcc26e1e07f91e`.
Require one inventory host and existing management root without become. Invalid
carriers echo no unqualified values and observe no setup facts.

## Observations And Effects

Fixed private native checks use GNU `/usr/bin/timeout --signal=KILL 10` with
no foreground mode, empty stdin, fixed operational PATH and no argument expansion.
Ansible async30/poll1 is an outer management guard. Initial timeout qualification
necessarily trusts the preexisting root-controlled executable before its help is
observed; unsupported/missing support refuses eligibility, not a containment claim.
Linux, systemd PID1/active Docker service, required tool options and cgroup-v2
CPU/memory/PID availability are prerequisite observations only. No packages,
service/firewall/config changes or resource allocations occur.

Docker modules bind only `unix:///var/run/docker.sock`, auto API, TLS/certificate
validation false and timeout10. Object enumeration stays disabled. Effective
backend evidence comes only from the same daemon's direct `FirewallBackend.Driver`
with a nonempty string daemon ID and exact string driver `iptables` or `nftables`;
no daemon-version whitelist applies. Missing/malformed/other/suffixed drivers remain
null/unsupported; `nftables` refuses. Disk config and retained DOCKER-USER never
prove backend. `iptables` also requires the existing chain read to succeed.
Rootless/userns remapping refuses.
Local daemon identity/version/backend/security/cgroup facts are rechecked afterward.

Versioned [Moby29.8.0 info](https://github.com/moby/moby/blob/docker-v29.8.0/daemon/info.go)
and [29.0.0 info](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/info.go)
obtain the backend from the live network controller, not a config file.
[Docker's nftables migration contract](https://docs.docker.com/engine/network/firewall-nftables/)
explains why DOCKER-USER may remain after migration. No legacy/default fallback.
The [Engine info transport](https://github.com/moby/moby/blob/v28.5.1/api/server/router/system/system_routes.go)
omits the direct field for API versions below1.49; absence is not backend proof.

Before host eligibility refusal, one ordinary `Runtime backend observation: `
progress message reports only `server_version`, `firewall_backend_present`,
`driver_string_present`, `driver` and `docker_user_read_succeeded`. Version is null
unless an ASCII version string of at most64 characters matches the closed numeric
triplet/optional suffix grammar. Presence distinguishes absent from malformed;
driver is exactly `iptables`, `nftables` or null, never a raw unsupported value.
The stored ASCII JSON plus prefix/newline is bounded to1024 bytes with a same-key
null/false fallback. This diagnostic grants no eligibility and changes no typed
result fields; raw native/module/security/config failures remain private.

Prepare's only setup mutation is `docker_image_pull` for that digest,
`platform: linux/amd64`, `pull: not_present`, followed by exact local reinspection.
Verify never pulls. Compatibility requires exactly one qualified SHA256 image ID,
exact RepoDigest, Linux/amd64 and no declared image volumes. It does not establish
interpreter usability or effective resource/mount/firewall/deadline enforcement.
The earlier immutable-image interpreter proof remains separate, not repeated here.

## Plain Result

One bounded `TEMPLATE_OUTPUT_JSON` envelope contains `template_runtime_setup_result`:
`operation_id`, `server_id`, `action`, `profile`, `image`, `outcome`, `reason`,
UTC RFC3339 `observed_at` and `checks`. Outcomes are eligible/unsupported/failed;
reasons ready/invalid_inputs/management_unavailable/unsupported_profile/
image_unavailable/image_incompatible/setup_failed. The nine strict boolean/null
checks are management_root/linux/systemd/rootful_docker/iptables_backend/cgroup_v2/
required_tools/image_present/image_compatible. Unknown facts stay null; eligible
requires all true. No daemon/config/error/environment/object lists are public.
The exact ASCII envelope and prefix/newline are bounded to16384 bytes.
`observed_at` is trusted management-side UTC emission time, not target-clock
qualification. Private module failures are retained as observations before fixed
safe refusal guards; this is not blanket Ansible action-plugin error suppression.

Isolated behavior is accepted with four focused regression methods and syntax
qualified; root/systemd/daemon transports and loop polling were substituted,
while the native GNU deadline and owned sleeper closure were exercised directly.
Publication, live management and
ordinary invocation containment remain separately held; no disposable diagnostic
or payload container is allocated by either action.
