terraform {
  required_version = ">= 1.0"

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
  creation = var.opsctl_server
  options  = try(local.creation.provider_config.do, {})
  lookup_key = var.destroy ? false : (!local.creation.simulate && local.creation.ssh_key.registered_id == "")
  networks = try(values(local.creation.networks), [])
  vpc_uuid = length(local.networks) == 0 ? null : local.networks[0].network_id
}

data "digitalocean_ssh_keys" "existing" {
  count = local.lookup_key ? 1 : 0
  filter {
    key    = "fingerprint"
    values = [local.creation.ssh_key.fingerprint]
  }
}

# Create the droplet (only when not destroying)
resource "digitalocean_droplet" "server" {
  count = var.destroy ? 0 : 1

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
      error_message = "name, region, size, and image are required when destroy=false"
    }
  }
}

resource "digitalocean_firewall" "server" {
  count = var.destroy ? 0 : 1

  name        = "${local.creation.name}-fw"
  droplet_ids = [digitalocean_droplet.server[0].id]

  dynamic "inbound_rule" {
    for_each = local.creation.public_ingress_rules
    content {
      protocol         = inbound_rule.value.protocol
      port_range       = tostring(inbound_rule.value.port)
      source_addresses = ["0.0.0.0/0"]
    }
  }

  dynamic "inbound_rule" {
    for_each = local.creation.private_ingress_bindings
    content {
      protocol         = inbound_rule.value.requested.protocol
      port_range       = tostring(inbound_rule.value.requested.port)
      source_addresses = ["${inbound_rule.value.endpoint.host}/32"]
    }
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# For destroy operations, import the existing droplet
resource "digitalocean_droplet" "this" {
  count = var.destroy && contains(var.destroy_target_names, "droplet") ? 1 : 0

  # Minimal required fields for import
  # These values don't matter as we're destroying
  name   = "destroying"
  region = "nyc3"
  size   = "s-1vcpu-1gb"
  image  = "ubuntu-24-04-x64"

  lifecycle {
    precondition {
      condition     = var.droplet_id != ""
      error_message = "droplet_id is required when destroy=true"
    }
  }
}

resource "digitalocean_firewall" "destroy" {
  count = var.destroy && contains(var.destroy_target_names, "firewall") ? 1 : 0

  name       = "opsctl-destroy-firewall"

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0"]
  }

  lifecycle {
    precondition {
      condition     = var.firewall_id != ""
      error_message = "The selected firewall target requires firewall_id."
    }
  }
}

