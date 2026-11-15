# Standard outputs expected by monitor_provision_job
output "droplet_id" {
  description = "ID of the created droplet"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].id : "")
}

output "firewall_id" {
  description = "ID of the provision-owned cloud firewall"
  value       = var.destroy ? "" : try(digitalocean_firewall.server[0].id, "")
}

output "name" {
  description = "Name of the created droplet"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].name : "")
}

output "region" {
  description = "Region of the droplet"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].region : "")
}

output "size" {
  description = "Size of the droplet"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].size : "")
}

output "ipv4_address" {
  description = "Public IPv4 address of the droplet"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].ipv4_address : "")
}

# Additional detailed outputs
output "droplet_urn" {
  description = "URN of the created droplet"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].urn : "")
}

output "droplet_name" {
  description = "Name of the created droplet (alias)"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].name : "")
}

output "droplet_region" {
  description = "Region of the droplet (alias)"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].region : "")
}

output "droplet_size" {
  description = "Size of the droplet (alias)"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].size : "")
}

output "droplet_ipv4_address" {
  description = "Public IPv4 address of the droplet (alias)"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].ipv4_address : "")
}

output "droplet_ipv4_address_private" {
  description = "Private IPv4 address of the droplet"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].ipv4_address_private : "")
}

output "droplet_ipv6_address" {
  description = "IPv6 address of the droplet"
  value       = var.destroy ? "" : (try(local.options.enable_ipv6, false) && length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].ipv6_address : "")
}

output "droplet_status" {
  description = "Status of the droplet"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].status : "")
}

output "droplet_created_at" {
  description = "Creation timestamp of the droplet"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].created_at : "")
}

output "droplet_tags" {
  description = "Tags applied to the droplet"
  value       = var.destroy ? [] : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].tags : [])
}

# Output the full droplet resource for detailed access
output "droplet" {
  description = "Complete droplet resource"
  value       = var.destroy ? null : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0] : null)
  sensitive   = false
}


locals {
  allocated_ipv4 = try(digitalocean_droplet.server[0].ipv4_address, "")
  usable_public_ipv4 = can(cidrnetmask("${local.allocated_ipv4}/32")) && !anytrue([
    for cidr in ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"] :
    try(cidrcontains(cidr, local.allocated_ipv4), true)
  ])
  allocated_status = lookup({ new = "provisioning", active = "active", off = "stopped", error = "error" }, try(digitalocean_droplet.server[0].status, ""), "unknown")
  provider_ready   = local.allocated_status == "active" && local.usable_public_ipv4
}

output "opsctl_server" {
  description = "Allocated Server identity and native readiness, independently of management setup"
  value = var.destroy ? null : {
    format_version       = 1
    provider_instance_id = tostring(digitalocean_droplet.server[0].id)
    hostname             = digitalocean_droplet.server[0].name
    region               = digitalocean_droplet.server[0].region
    size                 = digitalocean_droplet.server[0].size
    status               = local.allocated_status
    ip_address           = local.allocated_ipv4 != "" ? local.allocated_ipv4 : null
    private_ip           = digitalocean_droplet.server[0].ipv4_address_private != "" ? digitalocean_droplet.server[0].ipv4_address_private : null
    tags                 = sort(tolist(digitalocean_droplet.server[0].tags))
    ready                = local.provider_ready
    reason               = local.provider_ready ? null : (local.allocated_status == "active" ? "public_ip_unavailable" : "provider_not_ready")
  }
}
