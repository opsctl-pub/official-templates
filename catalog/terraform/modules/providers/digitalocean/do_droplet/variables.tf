variable "opsctl_server" {
  description = "Sealed neutral Server creation input; null only for recorded Destroy"
  type = object({
    name                     = string
    region                   = string
    size                     = string
    image                    = string
    image_metadata           = any
    tags                     = list(string)
    user_data                = string
    provider_config          = any
    ssh_port                 = number
    ssh_bootstrap_profile    = string
    public_ingress_rules     = list(object({ protocol = string, port = number }))
    networks                 = any
    private_ingress_bindings = any
    ssh_key = object({
      public_key      = string
      fingerprint     = string
      registered_id   = string
      registered_name = string
    })
    simulate = bool
  })
  default = null

  validation {
    condition = var.opsctl_server == null ? true : (
      var.opsctl_server.ssh_port >= 1 && var.opsctl_server.ssh_port <= 65535 &&
      floor(var.opsctl_server.ssh_port) == var.opsctl_server.ssh_port &&
      length(var.opsctl_server.tags) <= 128 &&
      length(var.opsctl_server.public_ingress_rules) <= 35 &&
      length(var.opsctl_server.private_ingress_bindings) <= 32 &&
      alltrue([for binding in var.opsctl_server.private_ingress_bindings :
        binding.requested.protocol == "tcp" && binding.requested.port >= 1 &&
        binding.requested.port <= 65535 && floor(binding.requested.port) == binding.requested.port &&
        can(cidrnetmask("${binding.endpoint.host}/32"))
      ]) &&
      alltrue([for rule in var.opsctl_server.public_ingress_rules :
        contains(["tcp", "udp"], rule.protocol) && rule.port >= 1 && rule.port <= 65535 && floor(rule.port) == rule.port
      ])
    )
    error_message = "Server creation requires bounded ports, tags and private peers."
  }
}

variable "destroy" {
  description = "Whether this is a recorded Destroy operation"
  type        = bool
  default     = false
}

variable "droplet_id" {
  description = "Exact recorded Droplet target"
  type        = string
  default     = ""
}

variable "firewall_id" {
  description = "Exact provision-owned firewall target"
  type        = string
  default     = ""
}

variable "destroy_target_names" {
  description = "The single recorded target selected by the shared retirement executor"
  type        = set(string)
  default     = []
  validation {
    condition = !var.destroy || (length(var.destroy_target_names) == 1 && alltrue([
      for name in var.destroy_target_names : contains(["droplet", "firewall"], name)
    ]))
    error_message = "Destroy requires exactly one declared target."
  }
}
