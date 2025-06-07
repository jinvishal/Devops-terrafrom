output "cluster_name" {
  description = "The name of the EKS cluster."
  value       = aws_eks_cluster.main.name
}

output "cluster_endpoint" {
  description = "The endpoint for your EKS Kubernetes API server."
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_ca_certificate" {
  description = "Base64 encoded certificate data required to communicate with your cluster."
  value       = aws_eks_cluster.main.certificate_authority[0].data
}

output "node_group_role_arn" {
  description = "The ARN of the IAM role used by the EKS node group."
  value       = module.eks_node_group_role.iam_role_arn # Updated to use module output
}

output "vpc_id" {
  description = "The ID of the VPC created for the EKS cluster."
  value       = module.vpc.vpc_id
}

output "vpc_private_subnet_ids" {
  description = "List of private subnet IDs in the VPC."
  value       = module.vpc.private_subnets
}

output "vpc_public_subnet_ids" {
  description = "List of public subnet IDs in the VPC."
  value       = module.vpc.public_subnets
}

# ECR Outputs
output "ecr_repository_url" {
  description = "The URL of the ECR repository."
  value       = aws_ecr_repository.app_ecr_repo.repository_url
}

# S3 Bucket Outputs
output "s3_bucket_id" {
  description = "The ID (name) of the general purpose S3 bucket."
  value       = aws_s3_bucket.general_s3_bucket.id
}

output "s3_bucket_arn" {
  description = "The ARN of the general purpose S3 bucket."
  value       = aws_s3_bucket.general_s3_bucket.arn
}

# WAFv2 Web ACL Outputs
output "waf_web_acl_arn" {
  description = "The ARN of the WAFv2 Web ACL."
  value       = aws_wafv2_web_acl.default_web_acl.arn
}

output "cluster_token" {
  description = "Bearer token for authenticating to the EKS cluster. Note: This is the token of the Terraform AWS provider's identity."
  value       = data.aws_eks_cluster_auth.main.token
  sensitive   = true
}

output "cluster_oidc_issuer_url" {
  description = "The OIDC issuer URL for the EKS cluster. Useful for configuring IAM roles for service accounts (IRSA)."
  value       = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

output "region" {
  description = "AWS region where the EKS cluster and resources are deployed."
  value       = data.aws_region.current.name
}
