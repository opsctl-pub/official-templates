output "opsctl_provider_observations" {
  description = "Public observation fields; Runner adds actual collection clocks"
  value       = local.observations
}

output "opsctl_creation_observation" {
  description = "Public allocation-query facts; Runner adds actual collection clocks"
  value       = local.creation_observation
}
