variable "aws_region" {
  description = "La région AWS où déployer les ressources"
  type        = string
  default     = "eu-west-3"  # Paris
}

variable "project_name" {
  description = "Nom du projet"
  type        = string
  default     = "aws-security-baseline"
}

variable "environment" {
  description = "Environnement (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "admin_ssh_cidr" {
  description = "Adresse IP autorisée en SSH, au format CIDR /32 (ex. 203.0.113.10/32)"
  type        = string

  validation {
    condition     = can(cidrhost(var.admin_ssh_cidr, 0)) && endswith(var.admin_ssh_cidr, "/32")
    error_message = "admin_ssh_cidr doit être une seule adresse IP au format /32 : SSH n'est jamais ouvert à un réseau entier."
  }
}
