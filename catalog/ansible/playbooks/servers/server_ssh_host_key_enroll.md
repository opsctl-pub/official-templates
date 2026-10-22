# SSH Host Key Enrollment

## Inputs

The local procedure observes first-use keys after genuine Server registration and
TCP readiness, before SSH followups. `ssh_host_key_request` contains only the
original Operation UUID, Server UUID, registered IP address and required integer
`port` (1 through 65535). No target login or private host key is used.

## Behavior

The scan uses the supplied port with a 10-second socket timeout and 30-second
outer deadline; at most eight candidates and 4096 characters per supported public
wire key. No port is guessed or changed. Selection prefers Ed25519, then ECDSA,
then RSA deterministically. Unknown/unavailable observations cannot install a pin.

This is unauthenticated trust on first use, not independent identity proof. An
attacker present at enrollment can supply the first key. Later generated
connections require the retained pin; privileged content can override generated
SSH settings. This procedure covers first-use enrollment only, not re-enrollment,
imported Servers or controller-to-target trust.

## Results

`TEMPLATE_OUTPUT_JSON` contains `ssh_host_key_observation` with `operation_id`,
`server_id`, `outcome`, nullable `host_public_key` and `reason`. Only `observed`
returns a supported public key. `unavailable` retains null key and a reason such
as `observation_failed`, `candidate_limit`, `no_supported_host_key` or
`openssh_unavailable`.

## Progress

This procedure emits its named result only, not an `OPERATION_STEP` sequence.
