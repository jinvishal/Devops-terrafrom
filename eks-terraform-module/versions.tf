terraform {
  required_version = ">= 1.0" # Added a minimum Terraform version

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.9" # Consider updating to latest stable, e.g., 2.12+
    }
  }
}
