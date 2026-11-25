# Observe a Traefik certificate

This read-only procedure reports the subject's recorded selection. Set
`certificate_probe_hosts` explicitly to request or skip live SNI verification.

For an installed managed file-provider gateway, set
`certificate_observe_subject_units: true` with a deployment subject and
`certificate_probe_hosts: false`. The procedure also reports
`certificate_subject_units`: version `1` and exactly one `timer` and `service`,
each with `load_state`, `active_state` and `unit_file_state`. The procedure
observes the deployment's own units before and after reading the selection.

A unit is known absent only when systemd explicitly reports `not-found`,
`inactive` and no unit-file state (returned as `null`). Missing, unrecognized
or changed facts are not absence; the opt-in observation refuses them. Units
are independent of the selection and its ordinary `renewal` facts. This mode
does not establish serving or restore anything. Omission or `false` keeps the
ordinary output unchanged.
