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

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
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
  user_data                   = trimspace(var.user_data) != "" ? var.user_data : null
  tags                        = local.aws_tags

  root_block_device {
    volume_type           = "gp3"
    delete_on_termination = true
  }

  lifecycle {
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
  count = var.destroy ? 1 : 0

  ami           = var.destroy_ami_id
  instance_type = "t3.micro"
  tags          = local.aws_tags
  depends_on    = [aws_security_group.destroy]

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
  count = var.destroy && var.destroy_security_group ? 1 : 0

  name        = "opsctl-destroy-placeholder"
  description = "OpsControl destroy import placeholder"

  lifecycle {
    precondition {
      condition     = trimspace(var.security_group_id) != ""
      error_message = "security_group_id is required when destroy_security_group=true."
    }
  }
}
