output "opsctl_provider_observations" {
  description = "Request ordinals with exact identities; provider failures never become absence"
  value       = module.observation.opsctl_provider_observations
}

output "opsctl_creation_observation" {
  description = "Scoped creation allocation facts without account inventory"
  value       = module.observation.opsctl_creation_observation
}
