terraform {
  required_version = ">= 1.13.2"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

provider "digitalocean" {}

variable "opsctl_load_balancer" {
  description = "The approved regional TCP load balancer and exact backend membership."
  type = object({
    name         = string
    region       = string
    backend_port = number
    backend_ids  = set(string)
  })
  nullable = false

  validation {
    condition = (
      can(regex("^[a-z0-9][a-z0-9-]{0,62}$", var.opsctl_load_balancer.name)) &&
      can(regex("^[a-z0-9-]{1,32}$", var.opsctl_load_balancer.region)) &&
      var.opsctl_load_balancer.backend_port == floor(var.opsctl_load_balancer.backend_port) &&
      var.opsctl_load_balancer.backend_port >= 1 &&
      var.opsctl_load_balancer.backend_port <= 65535 &&
      length(var.opsctl_load_balancer.backend_ids) > 0 &&
      length(var.opsctl_load_balancer.backend_ids) <= 128 &&
      alltrue([for id in var.opsctl_load_balancer.backend_ids : can(regex("^[1-9][0-9]{0,14}$", id))])
    )
    error_message = "The load balancer requires a name, region, TCP port and exact Droplet IDs."
  }
}

locals {
  load_balancer = var.opsctl_load_balancer
}

resource "digitalocean_loadbalancer" "managed" {
  name        = local.load_balancer.name
  region      = local.load_balancer.region
  size_unit   = 1
  droplet_ids = [for id in local.load_balancer.backend_ids : tonumber(id)]

  forwarding_rule {
    entry_protocol  = "tcp"
    entry_port      = local.load_balancer.backend_port
    target_protocol = "tcp"
    target_port     = local.load_balancer.backend_port
  }

  healthcheck {
    protocol = "tcp"
    port     = local.load_balancer.backend_port
  }
}

output "load_balancer_id" {
  description = "Identity of the resource that owns this state."
  value       = digitalocean_loadbalancer.managed.id
}

output "load_balancer_ip" {
  description = "Address reported by the provider after apply."
  value       = digitalocean_loadbalancer.managed.ip
}
