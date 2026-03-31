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