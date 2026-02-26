# Destroy operation flag
variable "destroy" {
  description = "Whether this is a destroy operation"
  type        = bool
  default     = false
}

# Droplet ID for destroy operations
variable "droplet_id" {
  description = "ID of existing droplet to destroy (required when destroy=true)"
  type        = string
  default     = ""
}

# Variables required only for provisioning (when destroy=false)
variable "name" {
  description = "Name of the droplet (required when destroy=false)"
  type        = string
  default     = ""
}

variable "region" {
  description = "DigitalOcean region (required when destroy=false)"
  type        = string
  default     = ""
}

variable "size" {
  description = "Droplet size (required when destroy=false)"
  type        = string
  default     = ""
}

variable "image" {
  description = "Operating system image (required when destroy=false)"
  type        = string
  default     = ""
}

variable "ssh_key_name" {
  description = "Name of the SSH key registered in DigitalOcean account"
  type        = string
  default     = ""
}

variable "ssh_key_id" {
  description = "ID of the SSH key in DigitalOcean account (alternative to name)"
  type        = string
  default     = ""
}

variable "enable_monitoring" {
  description = "Enable DigitalOcean monitoring"
  type        = bool
  default     = false
}

variable "enable_backups" {
  description = "Enable automatic backups"
  type        = bool
  default     = false
}

variable "enable_ipv6" {
  description = "Enable IPv6"
  type        = bool
  default     = false
}

variable "vpc_uuid" {
  description = "VPC UUID to place the droplet in (optional)"
  type        = string
  default     = ""
}

variable "user_data" {
  description = "Cloud-init user data script (optional)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to the droplet"
  type        = list(string)
  default     = ["terraform", "opsctl"]
}

# Project-related variables (optional)
variable "project_name" {
  description = "DigitalOcean project name (optional)"
  type        = string
  default     = ""
}

variable "project_description" {
  description = "Project description"
  type        = string
  default     = "Resources managed by OpsControl"
}

variable "project_purpose" {
  description = "Project purpose"
  type        = string
  default     = "Web Application"
}

variable "project_environment" {
  description = "Project environment (Development, Staging, Production)"
  type        = string
  default     = "Development"
}
