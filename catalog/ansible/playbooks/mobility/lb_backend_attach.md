# Attach Deployment Backends

`lb_backend_attach.yml` updates an existing recorded gateway's WireGuard peers,
then imports the normal `traefik_route_converge.yml` procedure. It does not create
an overlay, generate keys, derive native identities or render a second route.
Use the existing accepted-source catalog and normal inventory/SSH execution.

## Inputs

Pass the complete public RouteConvergeInput: `deployment_id`, authenticated
`org_id`, `server_id`, `target_server`, `target_server_ip`, `simulate`,
`route_state`, `route_hosts`, `route_port`, `route_https`,
`redirect_http_to_https`, `route_middlewares`, `traefik_backends`, `expected_route`.
Attach requires route_state=present. No route_host alias or endpoint fallback.
Hosts are normalized sorted unique DNS names (maximum100); port is1..65535,
middlewares maximum50, backends maximum64 unique `{url}` private endpoints.
HTTPS/redirect are explicit booleans; redirect requires HTTPS.

`expected_route` is the consumed native snapshot with exactly presence, hosts,
route_port, https, redirect_http_to_https, middlewares, backends, router_name.
Presence must be present or absent, never unknown. Preserve the observed opaque
router reference, not a guessed name. Normal route convergence owns validation,
comparison, activation, final observation and restoration.

Additional existing overlay inputs:

| Input | Contract |
|---|---|
| `overlay_cidr` | Admitted overlay CIDR; its prefix is checked against the actual interface address. |
| `gateway_wireguard_ip` | Recorded canonical native IP without prefix. |
| `gateway_wireguard_public_key` | Recorded base64 WireGuard public key. |
| `gateway_interface` | Recorded native interface,1..15 safe filename characters; no deployment-derived fallback. |
| `gateway_service` | Recorded `{manager:systemd,name,state:active}`; exact native unit name, maximum255 characters, not reconstructed from interface. |
| `wireguard_peers` | Existing `{public_key,allowed_ips,endpoint,persistent_keepalive}` objects under the Registry's complete input-byte bound; base64 key, canonical single CIDR, native IP:port endpoint and keepalive integer0..65535. |

The template-owned `wireguard_base_dir` defaults `/etc/wireguard`. Its existing
directory and interface `.key`/`.conf` must be root-owned, unlinked and regular
where appropriate; files are private0600. No backend path is accepted.
Existing listener51820/firewall behavior is retained. Shared issuer/broker and
certificate delivery are unrelated and untouched. simulate=true performs no work.

## Procedure And Results

Before mutation, native `wg show`, JSON `ip address` and systemd observation must
match the recorded key, interface IP/prefix and active unit. The retained private
key is read privately and its derived public key must match; no key is generated
or replaced. Readable Ansible writes peers and restarts only the recorded service
if configuration changed, then independently repeats the native identity checks.

Publish actual `wireguard_ip`, `wireguard_public_key`, `wireguard_interface` and
`wireguard_service={manager,name,state}` before route attachment. Import the normal
route procedure with the full original intent/snapshot. The final named-output
object includes those WireGuard fields plus `deployment_route_observation`:
outcome, observed_at, presence, hosts, route_port, https, redirect_http_to_https,
middlewares, backends and opaque router_name. Complete succeeded route facts and
active matching WireGuard facts are both required by the executing-child consumer;
file existence or a successful peer update alone is not attachment success.

Native errors/keys/configuration stay private. Refusal emits fixed
`procedure_error={phase,code}` before failure; route failures retain the canonical
procedure's available facts and restoration liability. A peer update may already
have happened when later activation/route checks fail; no peer rollback or global
transaction is claimed. Route restoration does not imply peer rollback. Unknown
facts cannot settle installation or trigger direct health. Org overrides use these
public variables/facts, not private receipts, backend algorithms or helper imports.
