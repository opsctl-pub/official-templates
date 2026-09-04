output "server_id" {
  description = "ID of the created server"
  value       = var.destroy ? "" : try(tostring(hcloud_server.server[0].id), "")
}

output "name" {
  description = "Name of the created server"
  value       = var.destroy ? "" : try(hcloud_server.server[0].name, "")
}

output "ipv4_address" {
  description = "Public IPv4 address of the server"
  value       = var.destroy ? "" : try(hcloud_primary_ip.server[0].ip_address, "")
}

output "server_status" {
  description = "Provider status of the server"
  value       = var.destroy ? "" : try(hcloud_server.server[0].status, "")
}

output "location" {
  description = "Location of the server"
  value       = var.destroy ? "" : try(hcloud_server.server[0].location, "")
}

output "server_type" {
  description = "Server type of the server"
  value       = var.destroy ? "" : try(hcloud_server.server[0].server_type, "")
}

output "labels" {
  description = "Labels applied to the server"
  value       = var.destroy ? {} : try(hcloud_server.server[0].labels, {})
}

output "primary_ipv4_id" {
  description = "ID of the provision-owned Primary IPv4"
  value       = var.destroy ? "" : try(tostring(hcloud_primary_ip.server[0].id), "")
}
