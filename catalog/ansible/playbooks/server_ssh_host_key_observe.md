# Observe Server SSH Host Key

`server_ssh_host_key_observe.yml` reads locally configured OpenSSH host identity
through the existing management inventory. It does not scan peers or mutate keys,
permissions, configuration or services. No procedure workspace is allocated;
ordinary Ansible module/async temporary mechanics still apply.

## Input

The sole public input `ssh_host_key_request` has exactly canonical lowercase UUID
strings `operation_id` and `server_id`. Exactly one inventory Server must match
`server_id` before native access. Addresses, credentials, paths, executables and
environment are not request inputs; current authority/physical binding is central.

## Observation

Managed Linux tooling uses `/usr/sbin/sshd -T` with its default configuration.
At most eight configured HostKey declarations are considered, without truncation.
`/usr/bin/ssh-keygen -y -P '' -f` extracts each actual public key, not a `.pub`
sidecar; native `ssh-keygen -l -f /dev/stdin` validates the public wire identity.
Executable GNU-compatible `/usr/bin/timeout` is required and qualified before
key access; absent/unsupported deadline tooling refuses safely. Each discovery,
extraction and validation argv starts with `timeout --signal=KILL 10`, without
`--foreground`, so native command descendants share the deadline. Literal argv,
empty interactive input and no argument expansion remain. Ansible async30/poll1
is only the outer management guard, not a wider native command duration.
Private/config/path output, including loop failures, is censored.

Select first usable ed25519, then ECDSA nistp256/384/521, then RSA, preserving
declaration order within a family. Missing, unreadable, encrypted, malformed,
unsupported or oversized candidates cannot become identity. Other independently
validated configured candidates remain eligible. The canonical public line is
algorithm plus base64, without comments, at most4096 characters.

## Result

Exactly one `TEMPLATE_OUTPUT_JSON` contains only `ssh_host_key_observation`:
`operation_id`, `server_id`, `outcome`, `host_public_key`, `reason`.
Observed uses outcome/reason `observed` and the validated public line.
Unavailable has null key and one safe reason: `openssh_unavailable`,
`configuration_unavailable`, `candidate_limit`, `no_supported_host_key` or
`observation_failed`; it emits its result then fails. `openssh_unavailable`
includes unavailable/unsupported required deadline tooling. Invalid carrier/inventory
fails before observation and emits no fabricated result. Existing OPERATION_STEP
markers report observation start and terminal disposition.

This is local configured-key observation, not an authenticated remote handshake
or independently verified provider identity. Existing management disables host-key
checking; preserve that bootstrap trust limitation. Central current-target binding,
freshness and accepted-source/result consumption remain prerequisites. The payload
later pins the captured key in known_hosts; public-key visibility grants no access.
Local/substituted evidence does not qualify live SSH or connected containment.
