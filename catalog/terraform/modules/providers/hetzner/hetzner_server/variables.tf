variable "destroy" {
  description = "Whether this is a destroy operation"
  type        = bool
  default     = false
}

variable "destroy_primary_ipv4" {
  description = "Whether the exact provision-owned Primary IPv4 is destroyed"
  type        = bool
  default     = false
}

variable "server_id" {
  description = "Positive decimal ID of the server to destroy"
  type        = string
  default     = ""
}

variable "primary_ipv4_id" {
  description = "Positive decimal ID of the provision-owned Primary IPv4"
  type        = string
  default     = ""
}

variable "name" {
  description = "Server name"
  type        = string
  default     = ""
}

variable "location" {
  description = "Hetzner Cloud location name"
  type        = string
  default     = ""
}

variable "server_type" {
  description = "Hetzner Cloud server type name"
  type        = string
  default     = ""
}

variable "image_id" {
  description = "Positive decimal system image ID"
  type        = string
  default     = ""
}

variable "ssh_key_id" {
  description = "ID of the reusable organization SSH key"
  type        = string
  default     = ""
}

variable "labels" {
  description = "Labels applied to the server and Primary IPv4"
  type        = map(string)
  default     = {}
}

variable "user_data" {
  description = "Optional cloud-init user data"
  type        = string
  default     = ""
}

variable "simulate" {
  description = "Whether the caller is generating a plan only"
  type        = bool
  default     = false
}
