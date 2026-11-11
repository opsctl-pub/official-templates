output "instance_id" {
  description = "ID of the created EC2 instance"
  value       = var.destroy_observe_only ? null : (var.destroy ? "" : try(aws_instance.server[0].id, ""))
}

output "instance_name" {
  description = "Name of the created EC2 instance"
  value       = var.destroy_observe_only ? null : (var.destroy ? "" : local.resource_name)
}

output "public_ip" {
  description = "Public IPv4 address of the instance"
  value       = var.destroy_observe_only ? null : (var.destroy ? "" : try(aws_instance.server[0].public_ip, ""))
}

output "ipv4_address" {
  description = "Public IPv4 address of the instance (alias)"
  value       = var.destroy_observe_only ? null : (var.destroy ? "" : try(aws_instance.server[0].public_ip, ""))
}

output "private_ip" {
  description = "Private IPv4 address of the instance"
  value       = var.destroy_observe_only ? null : (var.destroy ? "" : try(aws_instance.server[0].private_ip, ""))
}

output "instance_state" {
  description = "State of the instance"
  value       = var.destroy_observe_only ? null : (var.destroy ? "" : try(aws_instance.server[0].instance_state, ""))
}

output "ami_id" {
  description = "AMI ID used by the instance"
  value       = var.destroy_observe_only ? null : (var.destroy ? "" : try(nonsensitive(aws_instance.server[0].ami), ""))
}

output "availability_zone" {
  description = "Availability zone of the instance"
  value       = var.destroy_observe_only ? null : (var.destroy ? "" : try(aws_instance.server[0].availability_zone, ""))
}

output "region" {
  description = "AWS region"
  value       = var.destroy_observe_only ? null : (var.region)
}

output "instance_type" {
  description = "EC2 instance type"
  value       = var.destroy_observe_only ? null : (var.destroy ? "" : try(aws_instance.server[0].instance_type, ""))
}

output "tags" {
  description = "OpsControl tags applied to the instance"
  value       = var.destroy_observe_only ? null : (var.destroy ? [] : var.tags)
}

output "security_group_id" {
  description = "ID of the created security group"
  value       = var.destroy_observe_only ? null : (var.destroy ? "" : try(aws_security_group.this[0].id, ""))
}

output "key_pair_name" {
  description = "EC2 key pair name used by the instance, if any"
  value       = var.destroy_observe_only ? null : (var.destroy ? "" : (local.instance_key_name != null ? local.instance_key_name : ""))
}

output "opsctl_destroy_target" {
  description = "Successful exact-ID filtered provider inventory, including stopped instances"
  value = var.destroy && var.destroy_observe_only ? {
    name  = local.destroy_target
    id    = local.destroy_id
    state = (length(local.observed_destroy_ids) == 0 ? "absent" :
      length(local.observed_destroy_ids) == 1 && contains(local.observed_destroy_ids, local.destroy_id)
      ? "present" : "unknown")
  } : null
}
