# Managed DigitalOcean load balancer

The module owns one regional TCP load balancer. Its input supplies the approved name, region, port and complete set of Droplet IDs. The same port is used for entry, forwarding and health checks. The configured size is one unit. Membership changes update the same resource in its persistent state.

`observe.sh` accepts one JSON object on stdin containing `provider_resource_id`. It returns the endpoint, backend membership, forwarding port and readiness of the exact load balancer. Readiness requires an active provider status and a public endpoint. A provider 404 establishes absence. Other failed or invalid reads return unknown. The procedure makes no changes.

The platform approves membership and owns sequencing. Run create, update and destroy using the exact saved OpenTofu plan and the existing state. Observe independently before releasing the load balancer's tracking record.

`plan-policy.sh` checks the proposed TCP rule and backend identities against the approved input. A Server retirement may remove a load balancer only when its native plan shows no other Server attached.
