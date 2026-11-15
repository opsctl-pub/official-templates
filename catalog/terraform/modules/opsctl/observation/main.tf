locals {
  fields = { for ordinal, observation in var.observations : ordinal => {
    for field in ["lifecycle", "size", "public_ips", "private_ips"] : field => {
      coverage = observation.presence != "present" ? "unknown" : (
        contains(observation.unsupported, field) ? "unsupported" :
        observation[field] != null ? "complete" : "unknown"
      )
      value = observation.presence == "present" && !contains(observation.unsupported, field) ? observation[field] : null
      reason = observation.presence == "absent" ? "resource_absent" : (
        observation.presence == "unknown" ? "not_observed" :
        contains(observation.unsupported, field) ? "field_unsupported" :
        observation[field] == null ? "not_observed" : null
      )
    }
  } }
  observations = { for ordinal, observation in var.observations : ordinal => merge({
    id                   = observation.id
    presence             = observation.presence
    reason               = observation.presence == "present" ? null : observation.presence == "absent" ? "resource_absent" : coalesce(observation.reason, "provider_unavailable")
    provider_observed_at = observation.presence == "present" ? observation.provider_observed_at : null
  }, local.fields[ordinal]) }
}

locals {
  creation_observation = var.creation_observation == null ? null : {
    presence      = var.creation_observation.presence
    basis         = var.creation_observation.presence == "unknown" ? null : var.creation_observation.basis
    provider_name = var.creation_observation.presence == "unknown" ? null : var.creation_observation.provider_name
    region        = var.creation_observation.presence == "unknown" ? null : var.creation_observation.region
    reason = var.creation_observation.presence == "present" ? null : (
      var.creation_observation.presence == "absent" ? "provider_name_absent" : coalesce(var.creation_observation.reason, "provider_unavailable")
    )
  }
}
