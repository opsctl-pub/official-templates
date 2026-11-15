variable "targets" {
  description = "Ordered recorded target names and exact provider IDs"
  type        = list(object({ name = string, id = string }))
  default     = []
  validation {
    condition = (length(var.targets) >= 1 || var.creation_recovery) && length(var.targets) <= 16 && (
      length(distinct([for target in var.targets : jsonencode([target.name, target.id])])) == length(var.targets)
    ) && alltrue([
      for target in var.targets : contains(["instance", "security_group"], target.name) && (
        target.name == "instance" ? can(regex("^i-[0-9a-f]+$", target.id)) : can(regex("^sg-[0-9a-f]+$", target.id))
      )
    ])
    error_message = "Observation requires declared targets and exact IDs."
  }
}

variable "region" {
  description = "Recorded AWS region required for native provider lookup"
  type        = string
  default     = ""
  validation {
    condition     = var.creation_recovery && length(var.targets) == 0 ? true : trimspace(var.region) != ""
    error_message = "AWS observation requires the recorded region."
  }
}
variable "creation_recovery" {
  description = "Explicit allocation-query mode; ordinary reads require exact targets"
  type        = bool
  default     = false
}

variable "creation_region" {
  description = "Region from the original sealed creation request"
  type        = string
  default     = null
  validation {
    condition     = var.creation_region == null ? !(var.creation_recovery && length(var.targets) == 0) : can(regex("^[a-z0-9][a-z0-9-]*$", var.creation_region))
    error_message = "Allocation queries require their captured region."
  }
}

variable "creation_name" {
  description = "Actual name supplied by the original provisioning spec"
  type        = string
  default     = null
  validation {
    condition     = var.creation_name == null ? !(var.creation_recovery && length(var.targets) == 0) : length(var.creation_name) > 0 && length(var.creation_name) <= 255
    error_message = "Allocation queries require the actual captured name."
  }
}

variable "creation_tags" {
  description = "Complete tags supplied by the original provisioning spec"
  type        = list(string)
  default     = null
  validation {
    condition     = var.creation_tags == null ? !(var.creation_recovery && length(var.targets) == 0) : length(var.creation_tags) <= 128 && alltrue([for tag in var.creation_tags : length(tag) > 0 && length(tag) <= 255])
    error_message = "Allocation queries require the actual bounded tag list."
  }
}
