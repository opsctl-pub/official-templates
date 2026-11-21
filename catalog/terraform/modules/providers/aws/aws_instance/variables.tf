variable "opsctl_server" {
  description = "Sealed neutral Server creation input retained for the resource lifetime"
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
  nullable = false

  validation {
    condition = (
      var.opsctl_server.ssh_port >= 1 && var.opsctl_server.ssh_port <= 65535 &&
      floor(var.opsctl_server.ssh_port) == var.opsctl_server.ssh_port &&
      length(var.opsctl_server.tags) <= 128 &&
      length(var.opsctl_server.networks) == 0 && length(var.opsctl_server.private_ingress_bindings) == 0 &&
      length(var.opsctl_server.public_ingress_rules) <= 35 &&
      alltrue([for rule in var.opsctl_server.public_ingress_rules :
        contains(["tcp", "udp"], rule.protocol) && rule.port >= 1 && rule.port <= 65535 && floor(rule.port) == rule.port
      ])
    )
    error_message = "Server creation requires bounded ports and tags and no private network bindings."
  }
}

variable "compute_present" {
  description = "Retain the security group when removing the instance"
  type        = bool
  default     = true
}
