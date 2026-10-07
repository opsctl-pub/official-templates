# Official Catalog

All Admin/Org "Official Sources" subpaths point under this catalog directory.
See top-level README for usage and acceptance.

## Container And Local Resources

Register these Ansible subpaths through the existing Admin official-source and
org-override flow; validation/acceptance remains an explicit Admin action.

| Item | Subpath under catalog | Classification | Public contract |
|---|---|---|---|
| `compose_deploy` | `ansible/playbooks/compose_deploy.yml` | high-impact; `deploy_container` | [Deploy](ansible/playbooks/compose_deploy.md) |
| `compose_inspect` | `ansible/playbooks/compose_inspect.yml` | read-only; `inspect_deployment` | [Inspect](ansible/playbooks/compose_inspect.md) |
| `compose_remove` | `ansible/playbooks/compose_remove.yml` | high-impact; `remove_container` | [Remove](ansible/playbooks/compose_remove.md) |
| `container_deploy` | `ansible/playbooks/container_deploy.yml` | high-impact; image only | [Deploy](ansible/playbooks/container_deploy.md) |
| `container_inspect` | `ansible/playbooks/container_inspect.yml` | read-only; image only | [Inspect](ansible/playbooks/container_inspect.md) |
| `container_remove` | `ansible/playbooks/container_remove.yml` | high-impact; image only | [Remove](ansible/playbooks/container_remove.md) |
| `local_resource` | `ansible/playbooks/local_resource.yml` | existing create/inspect/remove classifications | [Native resource](ansible/playbooks/local_resource.md) |

Compose uses original files/native configuration, not generated image wrappers.
Removal retains volumes/bind data/workspaces and reused/external networks. These
source items do not seed catalog rows or publish/accept a revision automatically.
