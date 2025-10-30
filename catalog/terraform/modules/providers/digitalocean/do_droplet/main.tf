terraform {
  required_version = ">= 1.0"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

# Provider configuration - token comes from DIGITALOCEAN_TOKEN environment variable
provider "digitalocean" {
  # Token is automatically read from DIGITALOCEAN_TOKEN env var
}

# Look up existing SSH key by name (only for provisioning)
data "digitalocean_ssh_key" "existing" {
  count = !var.destroy && var.ssh_key_name != "" ? 1 : 0
  name  = var.ssh_key_name
}

# Create the droplet (only when not destroying)
resource "digitalocean_droplet" "server" {
  count = var.destroy ? 0 : 1

  name     = var.name
  region   = var.region
  size     = var.size
  image    = var.image

  # Enable monitoring and backups based on variables
  monitoring         = var.enable_monitoring
  backups           = var.enable_backups
  ipv6              = var.enable_ipv6
  vpc_uuid          = var.vpc_uuid != "" ? var.vpc_uuid : null

  # Add SSH keys if provided
  ssh_keys = var.ssh_key_name != "" ? [data.digitalocean_ssh_key.existing[0].id] : []

  # User data for cloud-init (optional)
  user_data = var.user_data != "" ? var.user_data : null

  # Tags
  tags = var.tags
}

# For destroy operations, import the existing droplet
resource "digitalocean_droplet" "this" {
  count = var.destroy ? 1 : 0

  # Minimal required fields for import
  # These values don't matter as we're destroying
  name     = "destroying"
  region   = "nyc3"
  size     = "s-1vcpu-1gb"
  image    = "ubuntu-24-04-x64"
}

# Create a project and assign the droplet (optional, only for provisioning)
resource "digitalocean_project" "default" {
  count       = !var.destroy && var.project_name != "" ? 1 : 0
  name        = var.project_name
  description = var.project_description
  purpose     = var.project_purpose
  environment = var.project_environment
  resources   = [digitalocean_droplet.server[0].urn]
}