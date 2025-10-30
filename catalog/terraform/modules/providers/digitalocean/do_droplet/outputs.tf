# Standard outputs expected by monitor_provision_job
output "droplet_id" {
  description = "ID of the created droplet"
  value       = var.destroy ? "" : (length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].id : "")
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
  value       = var.destroy ? "" : (var.enable_ipv6 && length(digitalocean_droplet.server) > 0 ? digitalocean_droplet.server[0].ipv6_address : "")
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