# Example usage of the EKS Terraform Module

# Configure the AWS Provider
provider "aws" {
  region = "us-west-2" # Choose your desired region
}

# Configure Kubernetes and Helm providers (for outputs that might need them, though module handles internal setup)
# These provider blocks are illustrative for a root module; the EKS module itself configures its own.
# If these are uncommented, ensure the module outputs `cluster_token` or manage auth another way.
/*
provider "kubernetes" {
  host                   = module.eks_cluster.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_cluster.cluster_ca_certificate)
  token                  = module.eks_cluster.cluster_token
}

provider "helm" {
  kubernetes {
    host                   = module.eks_cluster.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_cluster.cluster_ca_certificate)
    token                  = module.eks_cluster.cluster_token
  }
}
*/

# Instantiate the EKS Module
module "eks_cluster" {
  source = "../" # Assumes this examples/main.tf is in a subdirectory of the module root

  cluster_name = "my-test-eks"
  vpc_azs      = ["us-west-2a", "us-west-2b", "us-west-2c"] # Specify 3 AZs

  # Example: Using default VPC CIDRs and subnet layouts
  # vpc_private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"] # If not using defaults from variables.tf
  # vpc_public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"] # If not using defaults

  # Example: Enable specific components (defaults are mostly true)
  install_metrics_server = true
  install_loki           = true
  install_grafana        = true

  # IMPORTANT: Override the default Grafana admin password for any real deployment
  grafana_admin_password = "ChangeM3Pa$$w0rd!"

  # Example: Specify an SSH key for node access (optional, ensure it exists in your AWS account)
  # node_group_remote_access_ssh_key = "my-ec2-ssh-key-name"

  tags = {
    Environment = "test"
    Project     = "eks-module-testing"
  }
}

# Outputs from the EKS module
output "cluster_name" {
  description = "EKS cluster name."
  value       = module.eks_cluster.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint."
  value       = module.eks_cluster.cluster_endpoint
}

output "cluster_ca_certificate" {
  description = "Base64 encoded CA certificate for the EKS cluster."
  value       = module.eks_cluster.cluster_ca_certificate
}

output "cluster_oidc_issuer_url" {
  description = "OIDC issuer URL for the EKS cluster."
  value       = module.eks_cluster.cluster_oidc_issuer_url # Assuming this output exists
}

output "region" {
  description = "AWS region where the cluster is deployed."
  value       = module.eks_cluster.region # Assuming this output exists
}

output "vpc_id" {
  description = "ID of the VPC created for the EKS cluster."
  value       = module.eks_cluster.vpc_id
}

output "s3_bucket_id" {
  description = "ID of the S3 bucket created for general storage."
  value       = module.eks_cluster.s3_bucket_id
}

output "ecr_repository_url" {
  description = "URL of the ECR repository."
  value       = module.eks_cluster.ecr_repository_url
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL."
  value       = module.eks_cluster.waf_web_acl_arn
}

# Simplified Kubeconfig Output (for testing convenience)
# For production, manage kubeconfig distribution securely.
output "kubeconfig_test" {
  description = "A simplified Kubeconfig for testing. Requires AWS CLI configured."
  value = yamlencode({
    apiVersion      = "v1"
    kind            = "Config"
    current-context = module.eks_cluster.cluster_name
    clusters = [{
      name    = module.eks_cluster.cluster_name
      cluster = {
        server                   = module.eks_cluster.cluster_endpoint
        certificate-authority-data = module.eks_cluster.cluster_ca_certificate
      }
    }]
    contexts = [{
      name    = module.eks_cluster.cluster_name
      context = {
        cluster = module.eks_cluster.cluster_name
        user    = module.eks_cluster.cluster_name
      }
    }]
    users = [{
      name = module.eks_cluster.cluster_name
      user = {
        exec = {
          apiVersion = "client.authentication.k8s.io/v1beta1"
          command    = "aws"
          args = [
            "eks",
            "get-token",
            "--cluster-name", module.eks_cluster.cluster_name
            # Optional: "--region", module.eks_cluster.region # if not default
            # Optional: "--profile", "<your-aws-profile>" # if not default
          ]
        }
      }
    }]
  })
  sensitive = true # Kubeconfig can contain sensitive info
}

# Note: The module itself should output `cluster_token` if the root module's k8s/helm providers need it.
# It's better if the EKS module itself handles its k8s/helm provider config internally using data sources,
# which it already does. The provider blocks at the top of this example are more for general illustration.
# The EKS module should also output `cluster_oidc_issuer_url` and `region`.
# Add these to the module's `outputs.tf` if they are not already present.
