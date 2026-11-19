terraform {
  required_version = ">= 1.13.2"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

# Provider configuration - token comes from DIGITALOCEAN_TOKEN environment variable
provider "digitalocean" {
  # Token is automatically read from DIGITALOCEAN_TOKEN env var
}

locals {
  creation   = var.opsctl_server
  options    = try(local.creation.provider_config.do, {})
  lookup_key = var.compute_present && !local.creation.simulate && local.creation.ssh_key.registered_id == ""
  networks   = try(values(local.creation.networks), [])
  vpc_uuid   = length(local.networks) == 0 ? null : local.networks[0].network_id
}

data "digitalocean_ssh_keys" "existing" {
  count = local.lookup_key ? 1 : 0
  filter {
    key    = "fingerprint"
    values = [local.creation.ssh_key.fingerprint]
  }
}

data "digitalocean_vpc" "selected" {
  count = var.compute_present && !local.creation.simulate && local.vpc_uuid != null ? 1 : 0
  id    = local.vpc_uuid
}

resource "digitalocean_droplet" "server" {
  count = var.compute_present ? 1 : 0

  name   = local.creation.name
  region = local.creation.region
  size   = local.creation.size
  image  = local.creation.image

  # Enable monitoring and backups based on variables
  monitoring = try(local.options.enable_monitoring, false)
  backups    = try(local.options.enable_backups, false)
  ipv6       = try(local.options.enable_ipv6, false)
  vpc_uuid   = local.vpc_uuid

  # Add SSH keys if provided
  ssh_keys = local.creation.simulate ? [] : (local.lookup_key ? [one(data.digitalocean_ssh_keys.existing[0].ssh_keys).id] : [local.creation.ssh_key.registered_id])

  # User data for cloud-init (optional)
  user_data = local.creation.ssh_port == 22 ? (local.creation.user_data != "" ? local.creation.user_data : null) : templatefile(
    "${path.module}/../../../ssh/cloud-init.yaml.tftpl", { ssh_port = local.creation.ssh_port }
  )

  # Tags
  tags = local.creation.tags

  lifecycle {
    precondition {
      condition = local.creation.simulate || local.vpc_uuid == null ? true : try(
        data.digitalocean_vpc.selected[0].id == local.vpc_uuid &&
        data.digitalocean_vpc.selected[0].region == local.creation.region &&
        alltrue([for network in local.networks :
          network.ipv4_cidr == data.digitalocean_vpc.selected[0].ip_range
        ]), false
      )
      error_message = "The selected existing VPC must retain its exact region and private CIDR."
    }
    precondition {
      condition = !local.lookup_key ? true : try(
        length(data.digitalocean_ssh_keys.existing[0].ssh_keys) == 1 &&
        one(data.digitalocean_ssh_keys.existing[0].ssh_keys).fingerprint == local.creation.ssh_key.fingerprint &&
        slice(regexall("\\S+", one(data.digitalocean_ssh_keys.existing[0].ssh_keys).public_key), 0, 2) ==
        slice(regexall("\\S+", local.creation.ssh_key.public_key), 0, 2), false
      )
      error_message = "The exact management public key must already be registered once."
    }

    precondition {
      condition = alltrue([for network in local.networks :
        network.provider == "digitalocean" && network.region == local.creation.region &&
        network.network_id == local.vpc_uuid
      ])
      error_message = "All creation network bindings must name the same Droplet region and VPC."
    }

    precondition {
      condition = local.creation.ssh_port == 22 || (
        local.creation.user_data == "" && contains(["ubuntu-22.04", "ubuntu-24.04"], local.creation.ssh_bootstrap_profile)
      )
      error_message = "Nondefault SSH requires a qualified image and no custom user_data."
    }

    precondition {
      condition     = local.creation.name != "" && local.creation.region != "" && local.creation.size != "" && local.creation.image != ""
      error_message = "Creation requires name, region, size, and image."
    }
  }
}

locals {
  ingress = {
    managed_rules = try(local.creation.public_ingress_rules, [])
    managed_private_rules = [for binding in try(local.creation.private_ingress_bindings, []) : {
      protocol         = binding.requested.protocol, port = binding.requested.port,
      source_addresses = ["${binding.endpoint.host}/32"]
    }]
  }
  inbound = [for rule in concat(
    [for rule in local.ingress.managed_rules : merge(rule, { source_addresses = ["0.0.0.0/0"] })],
    local.ingress.managed_private_rules) : {
    protocol                  = rule.protocol, port_range = tostring(rule.port), action = "allow",
    source_addresses          = rule.source_addresses, source_droplet_ids = [], source_tags = [],
    source_load_balancer_uids = [], source_kubernetes_ids = []
  }]
  outbound = [for protocol in ["tcp", "udp", "icmp"] : {
    protocol                       = protocol, port_range = protocol == "icmp" ? "0" : "1-65535", action = "allow",
    destination_addresses          = ["0.0.0.0/0", "::/0"], destination_droplet_ids = [], destination_tags = [],
    destination_load_balancer_uids = [], destination_kubernetes_ids = []
  }]
}

resource "digitalocean_firewall" "server" {
  count = var.protection_present ? 1 : 0

  name        = "${local.creation.name}-fw"
  droplet_ids = digitalocean_droplet.server[*].id
  tags        = []

  lifecycle {
    ignore_changes = [droplet_ids, inbound_rule, outbound_rule, name]
  }

  dynamic "inbound_rule" {
    for_each = local.inbound
    content {
      protocol                  = inbound_rule.value.protocol
      port_range                = inbound_rule.value.port_range
      action                    = inbound_rule.value.action
      source_addresses          = inbound_rule.value.source_addresses
      source_droplet_ids        = inbound_rule.value.source_droplet_ids
      source_tags               = inbound_rule.value.source_tags
      source_load_balancer_uids = inbound_rule.value.source_load_balancer_uids
      source_kubernetes_ids     = inbound_rule.value.source_kubernetes_ids
    }
  }

  dynamic "outbound_rule" {
    for_each = local.outbound
    content {
      protocol                       = outbound_rule.value.protocol
      port_range                     = outbound_rule.value.port_range
      action                         = outbound_rule.value.action
      destination_addresses          = outbound_rule.value.destination_addresses
      destination_droplet_ids        = outbound_rule.value.destination_droplet_ids
      destination_tags               = outbound_rule.value.destination_tags
      destination_load_balancer_uids = outbound_rule.value.destination_load_balancer_uids
      destination_kubernetes_ids     = outbound_rule.value.destination_kubernetes_ids
    }
  }
}

