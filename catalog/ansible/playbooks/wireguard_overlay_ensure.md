# WireGuard overlay procedure

`wireguard_overlay_ensure.yml` is the replaceable Ansible entrypoint for one
deployment overlay. Its adjacent JSON declaration defines public result version1.
Validation checks that declaration and safe examples against the same fact decoder
used by API consumers; it does not execute the procedure or prove native readiness.

## Inputs and behavior

The backend supplies the authorized target, `deployment_id`, `overlay_cidr`,
`wireguard_ip` and `wireguard_state` (`present` by default, or `absent`).
`wireguard_peers` defaults to an empty list; each peer supplies `public_key` and
`allowed_ips`, optionally `endpoint` and `persistent_keepalive`.
`wireguard_listen_port` defaults to 51820. The procedure installs WireGuard,
maintains its private files, configures the interface/peers and starts its service.
The default interface uses the deployment's short ID; `gateway_interface` and
`gateway_service` carry recorded native references instead of requiring that naming
algorithm from an override. The official implementation uses `/etc/wireguard` and
systemd. These implementation paths are not API-owned identity.

`require_absent:true` permits fresh installation only after interface, files and
service prechecks. Removal requires explicit recorded interface/service references;
`expected_public_key` and `expected_wireguard_ip` are paired cleanup guards against
another owner. Guarded removal checks the exact key/address before mutation and
interface absence plus inactive service afterward. No unobserved absence qualifies.
`simulate:true` ends the play without mutation or readiness facts.

The procedure attempts restoration of prior files/service on installation failure;
restoration is not an atomicity or rollback guarantee. Failed or interrupted work
may leave changes. Backend execution/cleanup ownership remains until qualified
current evidence settles it. An override may change the implementation, not the
approved intent, cleanup ownership or required truthful observations.

## Public results

`TEMPLATE_OUTPUT_JSON` contains these plain fields:

| Field | Meaning |
|---|---|
| `wireguard_ip` | Canonical observed IPv4 address, matching the requested/recorded address. |
| `wireguard_public_key` | Public WireGuard key (44-character base64 shape); never a private key. |
| `wireguard_interface` | Observed native interface reference, 1–15 ASCII name characters. |
| `wireguard_service` | Opaque `manager`, `name`, and observed `state` (`active`, `inactive`, `unknown`). |
| `wireguard_absent` | Exactly `true` only for qualified guarded cleanup; omitted/false for active facts. |

Active consumption requires active service and no absence assertion. Guarded cleanup
requires inactive service and explicit absence, plus the backend's exact recorded
identity. These are observations of that invocation, not ongoing liveness. Backend
consumers retain executing Operation/Run/source, requested identity and current-state
joins; public examples do not authorize a resource or establish those joins.

Missing, malformed, oversized or unknown facts do not qualify either disposition.
Any `procedure_error` field refuses consumption, regardless of diagnostic code;
failed/incomplete `outcome`, if supplied, also refuses. The official procedure can
fail without emitting a final result; no missing output implies success or absence.
It does not currently emit a structured unknown result; that safe example documents
the consumer's refusal boundary, not a native result this procedure has demonstrated.

Result objects are bounded to 128KiB before decoding. Additive public fields (also
inside `wireguard_service`) are ignored, not granted meaning or preserved as new
coverage. Existing required fields cannot change type/meaning within version1.
Private admission/custody records remain closed. Never include credentials, private
keys or raw private native errors in output or examples.

Progress uses existing `OPERATION_STEP` names `wireguard:start`, `wireguard:ready`
and `wireguard:complete`, or `wireguard:failure` on failure. This item contract does not validate other catalog items,
including the separate `lb_backend_attach` procedure.
