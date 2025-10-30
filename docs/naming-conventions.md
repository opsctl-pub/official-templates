# Naming Conventions

- Templates: `action_object` snake_case (container_deploy, health_verify).
- Files mirror template names (container_deploy.yml).
- Terraform modules: snake_case directories; provider modules under `providers/<provider>/`.
- Keep names stable; avoid abbreviations that hide intent.
