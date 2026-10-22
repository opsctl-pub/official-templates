# Official Catalog

Browse procedures by task. Use Admin Official Sources to view their configured
sources and Automation Overrides to select supported organization replacements.
See the [repository guide](../README.md) for source selection.

## Containers and Compose

- [Deploy an image](ansible/playbooks/containers/container_deploy.md).
- [Inspect an image workload](ansible/playbooks/containers/container_inspect.md).
- [Remove an image workload](ansible/playbooks/containers/container_remove.md).
- [Deploy original Compose files](ansible/playbooks/compose/compose_deploy.md).
- [Inspect a Compose project](ansible/playbooks/compose/compose_inspect.md).
- [Remove a Compose project](ansible/playbooks/compose/compose_remove.md).

Compose uses original files and native configuration, not generated image
wrappers. Removal retains data according to the selected procedure's documented
resource rules.

## Resources, backup and Templates

- [Manage Docker volumes and networks](ansible/playbooks/resources/manage_docker_resource.md).
- [Back up a volume or restore into a fresh volume](ansible/playbooks/backups/manage_volume_backup.md).
- [Run selected Template content on its host/controller](ansible/playbooks/templates/run_template.md).

## Servers and health

- [Discover existing Server workloads without adoption](ansible/playbooks/servers/server_workload_discover.md).
- [Prepare Docker](ansible/playbooks/servers/baseline_docker.md).
- [Install Pulse](ansible/playbooks/servers/install_pulse.md).
- [Enroll SSH host keys](ansible/playbooks/servers/server_ssh_host_key_enroll.md).
- [Synchronize managed SSH access](ansible/playbooks/servers/ssh_access_sync.md).
- [Check HTTP health, TCP connectivity or routed verification](ansible/playbooks/health/health_verify.md).
- [Check Runner Ansible execution](ansible/playbooks/health/ansible_health.md) (not Server readiness).
- [Manage an AWS instance](terraform/modules/providers/aws/aws_instance/README.md).
- [Manage a DigitalOcean Droplet](terraform/modules/providers/digitalocean/do_droplet/README.md).
- [Hetzner module](terraform/modules/providers/hetzner/hetzner_server/README.md) (available actions depend on configured provider support).

## Networking and gateway routes

- [Synchronize Cloudflare A records](ansible/playbooks/networking/dns_records_sync.md).
- [Ensure a WireGuard overlay](ansible/playbooks/networking/wireguard_overlay_ensure.md).
- [Ensure a Traefik gateway](ansible/playbooks/gateways/traefik/traefik_gateway_ensure.md).
- [Configure a Server's Traefik proxy/dashboard](ansible/playbooks/gateways/traefik/traefik_proxy.md).
- [Attach recorded gateway backends](ansible/playbooks/gateways/traefik/attach_gateway_backends.md).
- [Exclude a gateway backend](ansible/playbooks/gateways/traefik/exclude_gateway_backend.md).
- [Converge a route](ansible/playbooks/gateways/traefik/traefik_route_converge.md).
- [Observe a route](ansible/playbooks/gateways/traefik/traefik_route_observe.md).
- [Manage a private temporary canary](ansible/playbooks/gateways/traefik/traefik_backend_canary.md).

## Certificates

- [Observe selected certificates and optionally probe serving](ansible/playbooks/certificates/traefik/observe_traefik_certificate.md).
- [Issue, retry or renew automatically](ansible/playbooks/certificates/traefik/traefik_automatic_certificate.md).
- [Retire automatic enrollment](ansible/playbooks/certificates/traefik/traefik_automatic_certificate_retire.md).
- [Install custom material](ansible/playbooks/certificates/traefik/traefik_custom_certificate_install.md).
- [Unbind custom selection](ansible/playbooks/certificates/traefik/traefik_custom_certificate_unbind.md).
- [Manage gateway-local native revisions](ansible/playbooks/certificates/traefik/traefik_native_certificate.md).

Selected material, active serving, renewal enrollment, configured routes and
application health are reported separately. Missing or unknown results remain
unknown; progress markers alone do not establish success.
