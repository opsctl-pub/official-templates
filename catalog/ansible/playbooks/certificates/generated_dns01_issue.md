# Issue a generated hostname certificate

## Inputs

- The platform owner admits a local Runner operation with only an issuer_request
  object: acme_directory_url, broker_url, account_id, and route_hosts. The broker
  URL ends at /api/v1/dns-challenge; the hosts are sorted, distinct exact names.
- The Runner owns OPSCTL_GENERATED_DNS01_ATTEMPT_DIR: a fresh, empty, mode-0700
  directory in private memory-backed /tmp. It qualifies the exact operation-file
  bundle and owns its cleanup.
- The read-only /var/run/opsctl/file-secret projection supplies acme-account.json,
  acme-account.key and broker-password. The procedure does not access result-key.

## Behavior

Refuse any inventory other than the local Runner. Validate the request and the
native, already-registered lego account before starting the client. Copy only
the supplied account bytes into the pinned private layout under attempt/lego. Use
lego 5.5.2 once with its httpreq provider, normal TLS trust, DNS propagation
checks and certificate bundling. This is not account enrollment, recovery,
repair or write-back. The platform and broker own authorization and challenge
custody; the play does not take cloud credentials or connect to a Server.
Only the pinned client's stdout is drained into a private in-memory tail of
at most 16 KiB. Stderr is discarded. The local 600-second deadline kills and
reaps the original client on timeout, within the Runner Job's own deadline.
The play never retries the client.

## Results

After joining the client, even on native failure, verify the exact private
account tree: one CA namespace, one account ID, and only its metadata and key
with bytes unchanged from the admitted snapshot. A changed or unverifiable
tree fails before accepting the native result. An intact tree preserves the
native failure code.

After native success and account verification, read the two stable, bounded
native files without following links. Export only generated-hostname.crt and
generated-hostname.key to a fresh private attempt/certificates directory. The
native sidecars remain under attempt/lego until whole-attempt cleanup.
A failed or interrupted play can
leave private partial artifacts for the Runner to remove, and does not prove
that the CA or broker performed no effects. Successful exit is not a sealed
receipt, delivery confirmation or trusted serving evidence.

The public failure codes are closed and advisory, not evidence of cleanup or
permission to retry:

| Exit | Code | Meaning |
|---|---|---|
| 20 | rate_limited | Recognized ACME rate-limit problem. |
| 21 | dns_challenge_failed | Recognized DNS problem, challenge refusal or propagation failure. |
| 22 | account_unauthorized | Recognized missing ACME account problem, not generic challenge unauthorized. |
| 23 | timeout | The local client deadline expired. |
| 24 | other | Local qualification failed, or the native result was missing, ambiguous or unrecognized. |
| 25 | account_registered_unexpectedly | Local account state changed or could not be verified. This is not proof of external registration. |

After native entry, a recognized failure writes only its numeric code to the
private, exclusive mode-0600 diagnostic.status file. No status file accompanies
success; an unavailable status on failure is classified as other by the Runner.

## Progress

The play itself emits no OPERATION_STEP or TEMPLATE_OUTPUT_JSON frame. The
bound Runner suppresses all play output and owns failure or sealed-result delivery.
