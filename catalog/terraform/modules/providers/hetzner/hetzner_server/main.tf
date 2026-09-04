locals {
  resource_name = trimspace(var.name) != "" ? trimspace(var.name) : "opsctl-server"
}

resource "hcloud_primary_ip" "server" {
  count = var.destroy ? 0 : 1

  name        = "${local.resource_name}-ipv4"
  location    = var.location
  type        = "ipv4"
  auto_delete = false
  labels      = var.labels

  lifecycle {
    precondition {
      condition     = trimspace(var.location) != ""
      error_message = "location is required when destroy=false."
    }
  }
}

resource "hcloud_server" "server" {
  count = var.destroy ? 0 : 1

  name        = local.resource_name
  location    = var.location
  server_type = var.server_type
  image       = var.image_id
  ssh_keys    = trimspace(var.ssh_key_id) != "" ? [var.ssh_key_id] : []
  labels      = var.labels
  user_data   = trimspace(var.user_data) != "" ? var.user_data : null

  public_net {
    ipv4_enabled = true
    ipv4         = hcloud_primary_ip.server[0].id
    ipv6_enabled = false
  }

  lifecycle {
    precondition {
      condition = (
        trimspace(var.name) != "" &&
        trimspace(var.location) != "" &&
        trimspace(var.server_type) != "" &&
        can(regex("^[1-9][0-9]*$", var.image_id))
      )
      error_message = "name, location, server_type, and a positive image_id are required when destroy=false."
    }
  }
}

resource "hcloud_primary_ip" "this" {
  count = var.destroy && var.destroy_primary_ipv4 ? 1 : 0

  name        = "opsctl-destroy-primary-ipv4"
  location    = var.location
  type        = "ipv4"
  auto_delete = false

  lifecycle {
    precondition {
      condition     = can(regex("^[1-9][0-9]*$", var.primary_ipv4_id))
      error_message = "primary_ipv4_id is required when destroy_primary_ipv4=true."
    }
  }
}

resource "hcloud_server" "this" {
  count = var.destroy ? 1 : 0

  name        = "opsctl-destroy-server"
  server_type = "cx23"

  public_net {
    ipv4_enabled = true
    ipv4 = var.destroy_primary_ipv4 ? (
      hcloud_primary_ip.this[0].id
    ) : null
    ipv6_enabled = false
  }

  lifecycle {
    precondition {
      condition     = can(regex("^[1-9][0-9]*$", var.server_id))
      error_message = "server_id is required when destroy=true."
    }
  }
}
