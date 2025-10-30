# Acceptance Checklists

Container Deploy (Ansible)
- Inputs mapped: image, environment, ports[], health_path, env, name, target_server
- Markers: Ansible playbook running → completed|failed
- Outcome: container present/running; hint log emitted

Health Verify (Ansible)
- Input: health_url (or path/port)
- Retries and timeout handled; non‑200 fails

Runner Selftest (Ansible)
- Emits running/completed markers without external infra

Server Baseline Docker (Terraform)
- Emits baseline:start → baseline:done markers
- No destructive resources in baseline path

Mobility (Ansible)
- LB attach/detach and DNS sync playbooks log expected messages/markers
