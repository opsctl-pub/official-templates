provider "aws" {
  region = var.opsctl_server.region
}

data "aws_caller_identity" "allocation" {
  count = var.compute_present ? 1 : 0
}

locals {
  creation            = var.opsctl_server
  resource_name       = local.creation.name
  image_ssm_parameter = try(trimspace(local.creation.image_metadata.ssm_parameter_by_region[local.creation.region]), "")
  image_id            = try(nonsensitive(data.aws_ssm_parameter.selected_image[0].value), "")
  default_subnet_id   = try(sort(data.aws_subnets.default[0].ids)[0], "")
  instance_key_name   = local.creation.simulate ? null : local.creation.ssh_key.registered_name
  aws_tags = merge(
    { for tag in local.creation.tags : tag => "true" },
    { Name = local.resource_name }
  )
}

data "aws_vpc" "default" {
  count   = var.compute_present ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.compute_present ? 1 : 0

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
  count = var.compute_present && local.image_ssm_parameter != "" ? 1 : 0
  name  = local.image_ssm_parameter
}

data "aws_ami" "selected" {
  count = var.compute_present && can(regex("^ami-([0-9a-f]{8}|[0-9a-f]{17})$", local.image_id)) ? 1 : 0

  filter {
    name   = "image-id"
    values = [local.image_id]
  }

  timeouts {
    read = "30s"
  }
}

locals {
  image = try(data.aws_ami.selected[0], null)
  image_ebs_devices = try([
    for mapping in local.image.block_device_mappings : mapping.device_name if try(length(mapping.ebs), 0) != 0
  ], [])
}

resource "aws_security_group" "this" {
  count = 1

  name        = "${local.resource_name}-sg"
  description = "OpsControl managed instance access"
  vpc_id      = try(data.aws_vpc.default[0].id, null)
  tags        = local.aws_tags

  lifecycle {
    ignore_changes = all
  }

  dynamic "ingress" {
    for_each = local.creation.public_ingress_rules
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
  count = var.compute_present ? 1 : 0

  ami                         = local.image_id
  instance_type               = local.creation.size
  subnet_id                   = local.default_subnet_id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.this[0].id]
  key_name                    = local.instance_key_name
  user_data = local.creation.ssh_port == 22 ? (trimspace(local.creation.user_data) != "" ? local.creation.user_data : null) : templatefile(
    "${path.module}/../../../ssh/cloud-init.yaml.tftpl", { ssh_port = local.creation.ssh_port }
  )
  tags        = local.aws_tags
  volume_tags = local.aws_tags

  root_block_device {
    volume_type           = "gp3"
    delete_on_termination = true
  }

  lifecycle {
    precondition {
      condition = local.creation.ssh_port == 22 || (
        local.creation.user_data == "" && contains(["ubuntu-22.04", "ubuntu-24.04"], local.creation.ssh_bootstrap_profile)
      )
      error_message = "Nondefault SSH requires a qualified image and no custom user_data."
    }

    precondition {
      condition = (
        trimspace(local.creation.name) != ""
        && trimspace(local.creation.region) != ""
        && trimspace(local.creation.size) != ""
        && local.image_ssm_parameter != ""
      )
      error_message = "Creation requires name, region, instance_type, and a nonblank image_metadata.ssm_parameter_by_region entry for the selected region."
    }

    precondition {
      condition = try(
        local.image.id == local.image_id
        && local.image.root_device_type == "ebs"
        && local.image.root_device_name != ""
        && local.image_ebs_devices == [local.image.root_device_name],
        false
      )
      error_message = "The exact SSM-selected AMI must declare one EBS mapping for its root device."
    }

    precondition {
      condition     = local.creation.simulate || local.instance_key_name != ""
      error_message = "Creation requires the organization SSH key registered in this region."
    }

    precondition {
      condition     = local.default_subnet_id != ""
      error_message = "selected region must have a default subnet in the default VPC."
    }
  }
}
