# SSH Host Key Enrollment

Backend-owned local first-use observation after genuine Server registration and TCP readiness, before SSH followups. Input `ssh_host_key_request` contains only the original Operation UUID, Server UUID and registered IP address. No target login or private host key is used.

Port22, socket timeout10s, outer deadline30s; at most8 candidates and4096 characters per supported public wire key. Selection prefers Ed25519, then ECDSA, then RSA deterministically. Unknown/unavailable observations cannot install a pin. The result is the existing closed `ssh_host_key_observation` carrier.

This is unauthenticated trust on first use, not independent identity proof. An attacker present at enrollment can supply the first key. Later generated connections require the retained pin; privileged content can override generated SSH settings. Re-enrollment, imports and controller-to-target trust are outside this slice.
