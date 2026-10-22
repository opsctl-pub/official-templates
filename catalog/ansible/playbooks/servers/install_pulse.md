# Install Pulse

## Inputs

`install_pulse.yml` uses selected Server inventory and privilege escalation.
`pulse_download_url` and `pulse_download_sha256` select the binary and expected
SHA-256. `pulse_api_url`, private `pulse_token`, `pulse_interval_seconds` and
`pulse_enable_docker` supply the existing [environment template](../../templates/pulse.conf.j2).
`ssh_wait_timeout` defaults to 60 seconds and
`simulate` to false. Private configuration must arrive through protected inputs.

## Behavior

Wait for SSH, create `/etc/opsctl`, download the checksum-verified executable,
render root-owned configuration (0600) and the systemd unit, then enable/start
Pulse and require `systemctl is-active` to return `active`. Simulation ends before
installation. Failure can leave downloaded/configured files or a running service;
there is no automatic uninstall or rollback.

## Results

No `TEMPLATE_OUTPUT_JSON` is emitted. Service verification reports actual active
state at execution, not future telemetry delivery. Missing/failed checks do not
establish installation success. Configuration rendering is protected by `no_log`.

## Progress

Existing steps are `pulse:download`, `pulse:configure`, `pulse:enable`,
`pulse:verify` and `pulse:complete`, including verification/certification metadata.
