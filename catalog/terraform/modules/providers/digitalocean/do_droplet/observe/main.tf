terraform {
  required_version = ">= 1.13.2"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "= 2.107.0"
    }
  }
}

provider "digitalocean" {}

locals {
  droplet_targets  = { for index, target in var.targets : tostring(index) => target.id if target.name == "droplet" }
  firewall_targets = { for index, target in var.targets : tostring(index) => target.id if target.name == "firewall" }
}

data "digitalocean_droplets" "selected" {
  count = length(local.droplet_targets) > 0 ? 1 : 0
  filter {
    key      = "id"
    values   = values(local.droplet_targets)
    match_by = "exact"
    all      = false
  }
}

data "digitalocean_firewall" "selected" {
  for_each    = local.firewall_targets
  firewall_id = each.value
}

locals {
  droplets = length(local.droplet_targets) > 0 ? data.digitalocean_droplets.selected[0].droplets : []
  inventory_exact = alltrue([
    for droplet in local.droplets : contains(values(local.droplet_targets), tostring(droplet.id))
  ])
  matches = { for ordinal, id in local.droplet_targets : ordinal => [
    for droplet in local.droplets : droplet if tostring(droplet.id) == id
  ] }
  status = { new = "provisioning", active = "active", off = "stopped" }
  droplet_observations = { for ordinal, rows in local.matches : ordinal => {
    id       = local.droplet_targets[ordinal]
    presence = !local.inventory_exact || length(rows) > 1 ? "unknown" : length(rows) == 0 ? "absent" : "present"
    reason   = !local.inventory_exact || length(rows) > 1 ? "identity_conflict" : null
    lifecycle = length(rows) == 1 ? lookup(local.status, rows[0].status, null) : null
    size      = length(rows) == 1 ? (rows[0].size != "" ? rows[0].size : null) : null
    public_ips = length(rows) == 1 ? compact([rows[0].ipv4_address, rows[0].ipv6_address]) : null
    private_ips = length(rows) == 1 ? compact([rows[0].ipv4_address_private, rows[0].ipv6_address_private]) : null
  } }
  firewall_observations = { for ordinal, id in local.firewall_targets : ordinal => {
    id       = id
    presence = data.digitalocean_firewall.selected[ordinal].id == null ? "absent" : data.digitalocean_firewall.selected[ordinal].id == id ? "present" : "unknown"
    reason   = data.digitalocean_firewall.selected[ordinal].id == null || data.digitalocean_firewall.selected[ordinal].id == id ? null : "identity_conflict"
    unsupported = ["lifecycle", "size", "public_ips", "private_ips"]
  } }
}

module "observation" {
  source       = "../../../../opsctl/observation"
  observations = merge(local.droplet_observations, local.firewall_observations)
  creation_observation = local.creation_enabled ? {
    presence      = local.creation_complete ? (length(local.creation_rows) == 0 ? "absent" : "present") : "unknown"
    basis         = "name"
    provider_name = var.creation_name
    region        = var.creation_region
    reason        = "malformed_response"
  } : null
}

data "digitalocean_droplets" "creation" {
  count = local.creation_enabled ? 1 : 0
  filter {
    key      = "name"
    values   = [var.creation_name]
    match_by = "exact"
    all      = true
  }
  filter {
    key      = "region"
    values   = [var.creation_region]
    match_by = "exact"
    all      = true
  }
  dynamic "filter" {
    for_each = var.creation_tags == null ? [] : length(var.creation_tags) > 0 ? [var.creation_tags] : []
    content {
      key      = "tags"
      values   = filter.value
      match_by = "exact"
      all      = true
    }
  }
}

locals {
  creation_enabled = var.creation_recovery && length(var.targets) == 0
  creation_rows    = local.creation_enabled ? data.digitalocean_droplets.creation[0].droplets : []
  creation_complete = alltrue([for row in local.creation_rows :
    can(regex("^[1-9][0-9]*$", tostring(row.id))) && row.name == var.creation_name &&
    row.region == var.creation_region && length(setsubtract(toset(var.creation_tags), toset(row.tags))) == 0
  ])
}
