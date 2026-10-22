# Prepare the Docker baseline

## Inputs

`baseline_docker.yml` uses the selected Server inventory and privilege escalation.
`baseline_profile` defaults to `declared_image`; that mode requires
`image_distribution`, `image_version` and `image_architecture`. `imported` instead
observes the host distribution/version and requires x86_64. Both select an existing
[managed variable file](../../roles/baseline_docker/vars/managed).
`ssh_wait_timeout` defaults to 60 seconds; `simulate` defaults to false.

## Behavior

The [role](../../roles/baseline_docker/tasks/main.yml) waits for SSH and cloud-init,
installs declared Docker packages with apt or dnf, enables Docker and checks its
daemon. It installs the checksum-pinned Compose CLI plugin and checks its exact
version. Unsupported profiles, versions or architectures fail rather than guess.
Simulation ends before these effects. A later failure does not undo installation.

## Results

There is no `TEMPLATE_OUTPUT_JSON` result. Completion records checks made during
this invocation, not ongoing daemon or application health. Missing completion or
failed SSH, cloud-init, package, daemon or version checks do not establish readiness.

## Progress

Existing steps are `baseline:wait-ssh`, `baseline:cloud-init`, `docker:install`
and `baseline:complete`. Installation completion includes its certification
metadata.
