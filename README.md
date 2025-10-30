# OpsControl Official Templates

Automation assets for the OpsControl platform:
- Ansible playbooks (deploy, health checks, mobility)
- Terraform modules (infrastructure baselines)
- Dynamic inventory
- Template/Blueprint packages

## Structure

- `catalog/ansible/playbooks/` — Deployment and operational playbooks
- `catalog/ansible/inventory/` — Dynamic inventory script
- `catalog/terraform/modules/` — Infrastructure modules
- `catalog/packages/` — Template and blueprint manifests

## Usage

Templates are consumed through OpsControl. Production jobs use baked assets; development can fetch specific refs.

No secrets in templates — use vault/secret references only.
