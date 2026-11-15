output "instance_id" {
  description = "ID of the created EC2 instance"
  value       = var.destroy ? "" : try(aws_instance.server[0].id, "")
}

output "instance_name" {
  description = "Name of the created EC2 instance"
  value       = var.destroy ? "" : local.resource_name
}

output "public_ip" {
  description = "Public IPv4 address of the instance"
  value       = var.destroy ? "" : try(aws_instance.server[0].public_ip, "")
}

output "ipv4_address" {
  description = "Public IPv4 address of the instance (alias)"
  value       = var.destroy ? "" : try(aws_instance.server[0].public_ip, "")
}

output "private_ip" {
  description = "Private IPv4 address of the instance"
  value       = var.destroy ? "" : try(aws_instance.server[0].private_ip, "")
}

output "instance_state" {
  description = "State of the instance"
  value       = var.destroy ? "" : try(aws_instance.server[0].instance_state, "")
}

output "ami_id" {
  description = "AMI ID used by the instance"
  value       = var.destroy ? "" : try(nonsensitive(aws_instance.server[0].ami), "")
}

output "availability_zone" {
  description = "Availability zone of the instance"
  value       = var.destroy ? "" : try(aws_instance.server[0].availability_zone, "")
}

output "region" {
  description = "AWS region"
  value       = var.destroy ? var.region : local.creation.region
}

output "instance_type" {
  description = "EC2 instance type"
  value       = var.destroy ? "" : try(aws_instance.server[0].instance_type, "")
}

output "tags" {
  description = "OpsControl tags applied to the instance"
  value       = var.destroy ? [] : local.creation.tags
}

output "security_group_id" {
  description = "ID of the created security group"
  value       = var.destroy ? "" : try(aws_security_group.this[0].id, "")
}

output "key_pair_name" {
  description = "EC2 key pair name used by the instance, if any"
  value       = var.destroy ? "" : (local.instance_key_name != null ? local.instance_key_name : "")
}


locals {
  allocated_ipv4 = try(aws_instance.server[0].public_ip, "")
  usable_public_ipv4 = can(cidrnetmask("${local.allocated_ipv4}/32")) && !anytrue([
    for cidr in ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"] :
    try(cidrcontains(cidr, local.allocated_ipv4), true)
  ])
  allocated_status = lookup({ pending = "provisioning", running = "active", stopping = "stopped", stopped = "stopped", shutting-down = "destroying", terminated = "destroyed" }, try(aws_instance.server[0].instance_state, ""), "unknown")
  provider_ready   = local.allocated_status == "active" && local.usable_public_ipv4
}

output "opsctl_server" {
  description = "Allocated Server identity and native readiness, independently of management setup"
  value = var.destroy ? null : {
    format_version       = 1
    provider_instance_id = aws_instance.server[0].id
    hostname             = local.resource_name
    region               = local.creation.region
    size                 = aws_instance.server[0].instance_type
    status               = local.allocated_status
    ip_address           = local.allocated_ipv4 != "" ? local.allocated_ipv4 : null
    private_ip           = aws_instance.server[0].private_ip != "" ? aws_instance.server[0].private_ip : null
    tags                 = local.creation.tags
    ready                = local.provider_ready
    reason               = local.provider_ready ? null : (local.allocated_status == "active" ? "public_ip_unavailable" : "provider_not_ready")
  }
}
