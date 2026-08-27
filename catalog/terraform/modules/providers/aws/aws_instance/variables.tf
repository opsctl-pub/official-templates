variable "destroy" {
  description = "Whether this is a destroy operation"
  type        = bool
  default     = false
}

variable "instance_id" {
  description = "ID of the existing EC2 instance to destroy (required when destroy=true)"
  type        = string
  default     = ""
}

variable "security_group_id" {
  description = "ID of the provision-owned security group to destroy (required when destroy=true)"
  type        = string
  default     = ""
}

variable "destroy_security_group" {
  description = "Whether to destroy the exact provision-owned security group"
  type        = bool
  default     = true
}

variable "destroy_ami_id" {
  description = "AMI ID from the imported EC2 instance state (required when destroy=true)"
  type        = string
  default     = ""
}

variable "name" {
  description = "Name of the EC2 instance (required when destroy=false)"
  type        = string
  default     = ""
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = ""
}

variable "instance_type" {
  description = "EC2 instance type (required when destroy=false)"
  type        = string
  default     = ""
}

variable "image_ssm_parameter" {
  description = "AWS SSM parameter path that resolves to the AMI ID (required when destroy=false)"
  type        = string
  default     = ""
}

variable "public_key" {
  description = "Optional SSH public key material used to create an EC2 key pair"
  type        = string
  default     = ""
}

variable "key_name" {
  description = "Optional existing EC2 key pair name, or name to use when public_key is provided"
  type        = string
  default     = ""
}

variable "user_data" {
  description = "Optional cloud-init user data"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to the instance and supporting resources"
  type        = list(string)
  default     = ["terraform", "opsctl"]
}
