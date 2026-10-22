# WireGuard overlay procedure

`wireguard_overlay_ensure.yml` is the replaceable Ansible entrypoint for one
deployment overlay. Its adjacent JSON declaration defines public result version1.

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
interface absence plus inactive service afterward. Removal succeeds only when absence is observed.
`simulate:true` ends the play without mutation or readiness facts.

The procedure attempts restoration of prior files/service on installation failure;
restoration is not an atomicity or rollback guarantee. Failed or interrupted work
may leave changes. OpsControl retains cleanup responsibility until current
observations resolve the recorded state; restoration cannot be assumed to have
succeeded. Overrides must preserve the authorized intent, cleanup guards and
result meanings.

## Public results

`TEMPLATE_OUTPUT_JSON` contains these plain fields:

| Field | Meaning |
|---|---|
| `wireguard_ip` | Canonical observed IPv4 address, matching the requested/recorded address. |
| `wireguard_public_key` | Public WireGuard key (44-character base64 shape); never a private key. |
| `wireguard_interface` | Observed native interface reference, 1-15 ASCII name characters. |
| `wireguard_service` | Opaque `manager`, `name`, and observed `state` (`active`, `inactive`, `unknown`). |
| `wireguard_absent` | Exactly `true` only after guarded cleanup observed the interface gone; omitted or false for active facts. |

Active consumption requires active service and no absence assertion. Guarded cleanup
requires inactive service and explicit absence, plus the backend's exact recorded
identity. These are observations of that invocation, not ongoing liveness.

Missing, malformed, oversized or unknown facts count as neither active nor removed.
Any `procedure_error` field refuses consumption, regardless of diagnostic code;
failed/incomplete `outcome`, if supplied, also refuses. The official procedure can
fail without emitting a final result; no missing output implies success or absence.
The procedure does not emit a structured unknown result.

Result objects are bounded to 128KiB before decoding. Additive public fields (also
inside `wireguard_service`) are ignored. Required fields cannot change type or
meaning within version1. Never include credentials, private keys or raw private
native errors in output or examples.

Progress uses existing `OPERATION_STEP` names `wireguard:start`, `wireguard:ready`
and `wireguard:complete`, or `wireguard:failure` on failure. Backend attachment
uses the separate [attach_gateway_backends](../gateways/traefik/attach_gateway_backends.md)
procedure.

## WireGuard References

Ensure returns actual `wireguard_interface` and `wireguard_service` alongside
the existing IP/key. Route/bootstrap observation returns
`gateway_bootstrap_observation={interface,ipv4,public_key,service,route_backend_urls,observed_at}`;
service is `{manager,name,state:active|inactive|unknown}`. Interface/name/manager
limits are 15/255/32 characters. Subsequent observation/cleanup receives recorded
`gateway_interface`/`gateway_service`; never reconstruct Deployment-prefix names.
Missing references are unknown. Observe address/key/backends and active state;
absence must be consumed before removing the recorded gateway entry.
