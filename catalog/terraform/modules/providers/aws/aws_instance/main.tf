provider "aws" {
  region = var.region
}

locals {
  resource_name       = trimspace(var.name) != "" ? trimspace(var.name) : "opsctl-instance"
  image_ssm_parameter = trimspace(var.image_ssm_parameter)
  default_subnet_id   = try(sort(data.aws_subnets.default[0].ids)[0], "")
  create_key_pair     = !var.destroy && trimspace(var.public_key) != ""
  created_key_name    = trimspace(var.key_name) != "" ? trimspace(var.key_name) : "${local.resource_name}-key"
  instance_key_name   = local.create_key_pair ? aws_key_pair.this[0].key_name : (trimspace(var.key_name) != "" ? trimspace(var.key_name) : null)
  aws_tags = merge(
    { for tag in var.tags : tag => "true" },
    { Name = local.resource_name }
  )
}

data "aws_vpc" "default" {
  count   = var.destroy ? 0 : 1
  default = true
}

data "aws_subnets" "default" {
  count = var.destroy ? 0 : 1

  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default[0].id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

data "aws_ssm_parameter" "selected_image" {
  count = !var.destroy && local.image_ssm_parameter != "" ? 1 : 0
  name  = local.image_ssm_parameter
}

resource "aws_key_pair" "this" {
  count = local.create_key_pair ? 1 : 0

  key_name   = local.created_key_name
  public_key = var.public_key
  tags       = local.aws_tags
}

resource "aws_security_group" "this" {
  count = var.destroy ? 0 : 1

  name        = "${local.resource_name}-sg"
  description = "OpsControl managed instance access"
  vpc_id      = data.aws_vpc.default[0].id
  tags        = local.aws_tags

  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      description = "OpsControl declared ingress"
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = ingress.value.protocol
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "server" {
  count = var.destroy ? 0 : 1

  ami                         = try(nonsensitive(data.aws_ssm_parameter.selected_image[0].value), "")
  instance_type               = var.instance_type
  subnet_id                   = local.default_subnet_id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.this[0].id]
  key_name                    = local.instance_key_name
  user_data = var.ssh_port == 22 ? (trimspace(var.user_data) != "" ? var.user_data : null) : templatefile(
    "${path.module}/../../../ssh/cloud-init.yaml.tftpl", { ssh_port = var.ssh_port }
  )
  tags = local.aws_tags

  root_block_device {
    volume_type           = "gp3"
    delete_on_termination = true
  }

  lifecycle {
    precondition {
      condition = var.ssh_port == 22 || (
        var.user_data == "" && contains(["ubuntu-22.04", "ubuntu-24.04"], var.ssh_bootstrap_profile)
      )
      error_message = "Nondefault SSH requires a qualified image and no custom user_data."
    }

    precondition {
      condition = (
        trimspace(var.name) != ""
        && trimspace(var.region) != ""
        && trimspace(var.instance_type) != ""
        && local.image_ssm_parameter != ""
      )
      error_message = "name, region, instance_type, and image_ssm_parameter are required when destroy=false."
    }

    precondition {
      condition     = local.default_subnet_id != ""
      error_message = "selected region must have a default subnet in the default VPC."
    }
  }
}

resource "aws_instance" "this" {
  count = var.destroy && !var.destroy_observe_only && contains(var.destroy_target_names, "instance") ? 1 : 0

  ami           = var.destroy_ami_id
  instance_type = "t3.micro"
  tags          = local.aws_tags

  lifecycle {
    precondition {
      condition     = trimspace(var.instance_id) != ""
      error_message = "instance_id is required when destroy=true."
    }

    precondition {
      condition     = trimspace(var.region) != ""
      error_message = "region is required when destroy=true."
    }

    precondition {
      condition     = trimspace(var.destroy_ami_id) != ""
      error_message = "destroy_ami_id is required when destroy=true."
    }
  }
}

resource "aws_security_group" "destroy" {
  count = var.destroy && !var.destroy_observe_only && contains(var.destroy_target_names, "security_group") ? 1 : 0

  name        = "opsctl-destroy-placeholder"
  description = "OpsControl destroy import placeholder"

  lifecycle {
    precondition {
      condition     = trimspace(var.security_group_id) != ""
      error_message = "The selected security group target requires security_group_id."
    }
  }
}

locals {
  destroy_target = var.destroy && var.destroy_observe_only ? one(var.destroy_target_names) : ""
  destroy_ids    = { instance = var.instance_id, security_group = var.security_group_id }
  destroy_id     = lookup(local.destroy_ids, local.destroy_target, "")
}

data "aws_instances" "destroy_target" {
  count = var.destroy && var.destroy_observe_only && local.destroy_target == "instance" ? 1 : 0
  instance_state_names = ["pending", "running", "stopping", "stopped", "shutting-down"]
  filter {
    name   = "instance-id"
    values = [local.destroy_id]
  }
  lifecycle {
    precondition {
      condition     = can(regex("^i-[0-9a-f]+$", local.destroy_id))
      error_message = "The selected instance requires an exact EC2 instance ID."
    }
  }
}

data "aws_security_groups" "destroy_target" {
  count = var.destroy && var.destroy_observe_only && local.destroy_target == "security_group" ? 1 : 0
  filter {
    name   = "group-id"
    values = [local.destroy_id]
  }
  lifecycle {
    precondition {
      condition     = can(regex("^sg-[0-9a-f]+$", local.destroy_id))
      error_message = "The selected security group requires an exact security group ID."
    }
  }
}

locals {
  observed_destroy_ids = (var.destroy && var.destroy_observe_only ?
    (local.destroy_target == "instance" ? data.aws_instances.destroy_target[0].ids : data.aws_security_groups.destroy_target[0].ids) : [])
}
