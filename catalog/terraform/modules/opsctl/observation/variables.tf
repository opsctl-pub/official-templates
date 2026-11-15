variable "observations" {
  description = "Native facts keyed by request ordinal, before public coverage formatting"
  type = map(object({
    id                   = string
    presence             = string
    reason               = optional(string)
    provider_observed_at = optional(string)
    lifecycle            = optional(string)
    size                 = optional(string)
    public_ips           = optional(list(string))
    private_ips          = optional(list(string))
    unsupported          = optional(set(string), [])
  }))
  validation {
    condition = alltrue([for ordinal, observation in var.observations :
      can(regex("^(0|[1-9][0-9]*)$", ordinal)) && observation.id != "" &&
      contains(["present", "absent", "unknown"], observation.presence) &&
      length(setsubtract(observation.unsupported, toset(["lifecycle", "size", "public_ips", "private_ips"]))) == 0 && (
        observation.reason == null ? true : contains([
          "missing_lookup_identity", "unsupported_provider", "provider_unauthorized",
          "provider_rate_limited", "provider_timeout", "provider_unavailable",
          "response_too_large", "malformed_response", "identity_conflict", "binding_changed", "resource_absent"
        ], observation.reason)
      )
    ])
    error_message = "Observation facts require ordinal keys, exact IDs and documented presence/reasons."
  }
}

variable "creation_observation" {
  description = "Optional native allocation query facts, without inventory"
  type = object({
    presence      = string
    basis         = optional(string)
    provider_name = optional(string)
    region        = optional(string)
    reason        = optional(string)
  })
  default = null
  validation {
    condition = var.creation_observation == null ? true : (
      contains(["present", "absent", "unknown"], var.creation_observation.presence) &&
      var.creation_observation.basis == "name" &&
      var.creation_observation.provider_name != null &&
      var.creation_observation.region != null
    )
    error_message = "Creation facts require a native name/region scope."
  }
}
