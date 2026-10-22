# Manage an AWS instance

## Inputs

This HCL module is executed by OpenTofu with AWS credentials supplied privately
through the provider environment. `destroy` defaults to false. Creation requires
`name`, `region`, `instance_type` and `image_ssm_parameter`; the region must have
a default VPC/subnet. Optional `public_key` creates a key pair; otherwise
`key_name` can select an existing pair. `ingress_rules` defaults to `[]` and
contains explicit TCP/UDP ports. `tags` defaults to `terraform` and `opsctl`.
`user_data` defaults to empty. `ssh_port` defaults to 22; a different integer port
(1–65535) requires an admitted Ubuntu 22.04/24.04 bootstrap profile and no custom
user data. See [all variable declarations](variables.tf).

Destroy mode requires `instance_id`, `region` and imported-state `destroy_ami_id`.
`destroy_security_group` defaults to true and requires `security_group_id` when
enabled. The existing caller supplies/imports the recorded resource state; this
module does not discover an arbitrary instance to remove.

## Behavior

Resolve the AMI through SSM, select the sorted first default subnet, create the
instance/key pair/security group and attach public IPv4. Ingress is the declared
port set; egress permits all outbound traffic. Nondefault SSH renders the
existing shared first-boot template. Destroy resource declarations support the
existing imported-state destroy path; they are not standalone deletion commands.
The module does not install Docker, enroll SSH trust or prove readiness.

## Results

[Outputs](outputs.tf) report `instance_id`, `instance_name`, `public_ip`, alias
`ipv4_address`, `private_ip`, `instance_state`, `ami_id`, `availability_zone`,
`region`, `instance_type`, `tags`, `security_group_id` and `key_pair_name`.
Destroy mode yields empty values except region; unavailable reads use the declared
empty fallbacks. Those fallbacks are not proof of resource absence. Provider or
precondition failure may leave partial infrastructure requiring normal recovery.

## Progress

The module emits native OpenTofu output, not `OPERATION_STEP` or
`TEMPLATE_OUTPUT_JSON`.
