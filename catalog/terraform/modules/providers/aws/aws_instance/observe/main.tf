terraform {
  required_version = ">= 1.13.2"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.creation_recovery && length(var.targets) == 0 ? var.creation_region : var.region
}

locals {
  instance_targets = { for index, target in var.targets : tostring(index) => target.id if target.name == "instance" }
  group_targets    = { for index, target in var.targets : tostring(index) => target.id if target.name == "security_group" }
}

data "aws_instances" "selected" {
  for_each = local.instance_targets
  instance_state_names = ["pending", "running", "stopping", "stopped", "shutting-down"]
  filter {
    name   = "instance-id"
    values = [each.value]
  }
}

data "aws_security_groups" "selected" {
  for_each = local.group_targets
  filter {
    name   = "group-id"
    values = [each.value]
  }
}

data "aws_instance" "selected" {
  for_each = { for ordinal, id in local.instance_targets : ordinal => id
    if length(data.aws_instances.selected[ordinal].ids) == 1 && contains(data.aws_instances.selected[ordinal].ids, id)
  }
  instance_id = each.value
}

locals {
  status = {
    pending = "provisioning", running = "active", stopped = "stopped"
    shutting-down = "destroying", terminated = "terminated"
  }
  instance_presence = { for ordinal, id in local.instance_targets : ordinal => (
    length(data.aws_instances.selected[ordinal].ids) == 0 ? "absent" :
    length(data.aws_instances.selected[ordinal].ids) == 1 && contains(data.aws_instances.selected[ordinal].ids, id) ? (
      data.aws_instance.selected[ordinal].id == id ? "present" : "unknown"
    ) : "unknown"
  ) }
  group_presence = { for ordinal, id in local.group_targets : ordinal => (
    length(data.aws_security_groups.selected[ordinal].ids) == 0 ? "absent" :
    length(data.aws_security_groups.selected[ordinal].ids) == 1 && contains(data.aws_security_groups.selected[ordinal].ids, id)
    ? "present" : "unknown"
  ) }
  instance_facts = { for ordinal, instance in data.aws_instance.selected : ordinal => {
    lifecycle   = lookup(local.status, instance.instance_state, null)
    size        = instance.instance_type != "" ? instance.instance_type : null
    public_ips  = distinct(compact(concat([instance.public_ip], tolist(instance.ipv6_addresses))))
    private_ips = compact([instance.private_ip])
  } }
  instance_observations = { for ordinal, id in local.instance_targets : ordinal => merge({
    id       = id
    presence = local.instance_presence[ordinal]
    reason   = local.instance_presence[ordinal] == "unknown" ? "identity_conflict" : null
  }, try(local.instance_facts[ordinal], {})) }
  group_observations = { for ordinal, id in local.group_targets : ordinal => {
    id       = id
    presence = local.group_presence[ordinal]
    reason   = local.group_presence[ordinal] == "unknown" ? "identity_conflict" : null
    unsupported = ["lifecycle", "size", "public_ips", "private_ips"]
  } }
}

module "observation" {
  source       = "../../../../opsctl/observation"
  observations = merge(local.instance_observations, local.group_observations)
  creation_observation = local.creation_enabled ? {
    presence      = local.creation_complete ? (length(local.creation_rows) == 0 ? "absent" : "present") : "unknown"
    basis         = "name"
    provider_name = var.creation_name
    region        = var.creation_region
    reason        = "malformed_response"
  } : null
}

data "aws_instances" "creation" {
  count                = local.creation_enabled ? 1 : 0
  instance_state_names = ["pending", "running", "stopping", "stopped", "shutting-down"]
  dynamic "filter" {
    for_each = local.creation_tags
    content {
      name   = "tag:${filter.key}"
      values = [filter.value]
    }
  }
}

locals {
  creation_enabled = var.creation_recovery && length(var.targets) == 0
  creation_tags = local.creation_enabled ? merge(
    { for tag in var.creation_tags : tag => "true" }, { Name = var.creation_name }
  ) : {}
  creation_rows     = local.creation_enabled ? data.aws_instances.creation[0].ids : []
  creation_complete = alltrue([for id in local.creation_rows : can(regex("^i-[0-9a-f]+$", id))])
}
