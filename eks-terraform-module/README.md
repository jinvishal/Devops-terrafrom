# AWS EKS Terraform Module for HIPAA-Compliant Clusters

## 1. Module Overview

This Terraform module provisions a robust and security-conscious Amazon EKS (Elastic Kubernetes Service) cluster on AWS. It is designed with HIPAA compliance considerations in mind, integrating essential logging, monitoring, and security components out-of-the-box.

**Key Features:**

*   **Amazon EKS Cluster:** Managed Kubernetes service.
*   **VPC:** Creates a new VPC or uses an existing one, configured with public and private subnets across multiple Availability Zones.
*   **IAM Roles:** Fine-grained IAM roles for the EKS cluster, worker nodes, and other services, leveraging AWS managed policies where appropriate.
*   **EBS Encryption:** Worker node root volumes are encrypted.
*   **AWS ECR Repository:** A private container registry for your application images.
*   **AWS S3 Bucket:** A secure S3 bucket for general storage, optionally used by Loki for log retention.
*   **AWS WAFv2:** Web Application Firewall with pre-configured AWS Managed Rules to protect your applications.
*   **EKS Control Plane Logging:** Comprehensive logging of EKS control plane activities to CloudWatch.
*   **VPC Flow Logs:** Network traffic logging for the VPC.
*   **Metrics Server:** Deploys Kubernetes Metrics Server for pod resource metrics (HPA/VPA).
*   **Loki:** Deploys Loki for log aggregation, with an option for S3 backend.
*   **Grafana:** Deploys Grafana for metrics and log visualization, pre-configured with Loki as a datasource.
*   **HIPAA Considerations:** Incorporates several infrastructure configurations to help meet HIPAA technical safeguards.

## 2. Prerequisites

*   **Terraform:** Version >= 1.0 (Check `versions.tf` for specific provider versions).
*   **AWS Provider:** Configured AWS credentials with permissions to create the necessary resources.
*   **`kubectl`:** For interacting with the Kubernetes cluster post-provisioning.
*   **`helm` CLI:** (Optional) While this module deploys Helm charts via Terraform, the Helm CLI can be useful for inspecting releases or managing charts manually if needed.

## 3. Usage Example

Here's a simple example of how to use this module:

```terraform
module "eks_cluster" {
  source = "./eks-terraform-module" # Or a Git source like "github.com/your-org/eks-terraform-module?ref=v1.0.0"

  cluster_name = "my-hipaa-eks"
  vpc_azs      = ["us-west-2a", "us-west-2b", "us-west-2c"] # Specify 3 AZs for production
  vpc_private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  vpc_public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  # Example: Override instance type and node count
  instance_type    = "m5.large"
  desired_capacity = 3
  min_size         = 2
  max_size         = 5

  # IMPORTANT: Change Grafana admin password in a production environment!
  grafana_admin_password = "MySecurePassword123!"

  # Enable specific features if not already default
  install_loki    = true
  install_grafana = true

  # For HIPAA, consider using a custom KMS key for EBS encryption
  # ebs_kms_key_arn = "arn:aws:kms:us-west-2:123456789012:key/your-kms-key-id"
}

output "eks_cluster_name" {
  description = "EKS cluster name."
  value       = module.eks_cluster.cluster_name
}

output "eks_cluster_endpoint" {
  description = "EKS cluster endpoint."
  value       = module.eks_cluster.cluster_endpoint
}

output "ecr_repository_url" {
  description = "URL of the provisioned ECR repository."
  value       = module.eks_cluster.ecr_repository_url
}

output "s3_bucket_for_loki" {
  description = "S3 bucket ID used for Loki storage (if S3 backend is enabled and no specific bucket name provided for Loki)."
  value       = module.eks_cluster.s3_bucket_id # This output shows the general S3 bucket
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF WebACL."
  value       = module.eks_cluster.waf_web_acl_arn
}

# Example Kubeconfig Output (for direct interaction)
# Note: For production, consider a more secure way to generate and distribute kubeconfig files,
# such as integrating with a secrets manager or using IAM users/roles for cluster access.
output "kubeconfig" {
  description = "Kubeconfig to connect to the cluster using AWS IAM Authenticator."
  value = <<KUBECONFIG
apiVersion: v1
clusters:
- cluster:
    server: ${module.eks_cluster.cluster_endpoint}
    certificate-authority-data: ${module.eks_cluster.cluster_ca_certificate}
  name: ${module.eks_cluster.cluster_name}
contexts:
- context:
    cluster: ${module.eks_cluster.cluster_name}
    user: ${module.eks_cluster.cluster_name}
  name: ${module.eks_cluster.cluster_name}
current-context: ${module.eks_cluster.cluster_name}
kind: Config
preferences: {}
users:
- name: ${module.eks_cluster.cluster_name}
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args:
        - "eks"
        - "get-token"
        - "--cluster-name"
        - "${module.eks_cluster.cluster_name}"
      # Optionally specify AWS profile if not using default credentials
      # env:
      # - name: AWS_PROFILE
      #   value: "<your-aws-profile>"
KUBECONFIG
}

```

## 4. HIPAA Compliance Features

This module implements several infrastructure configurations that help support a HIPAA-compliant environment. However, ultimate HIPAA compliance is a shared responsibility and also depends on how applications are developed, how data is handled within those applications, and ongoing operational practices.

*   **EBS Volume Encryption:** Worker node root volumes (EBS) are encrypted by default using AWS managed keys (AES-256). You can specify a customer-managed KMS key via the `ebs_kms_key_arn` variable for more control.
*   **EKS Control Plane Logging:** All critical EKS control plane log types (`api`, `audit`, `authenticator`, `controllerManager`, `scheduler`) are enabled and sent to AWS CloudWatch Logs for audit and monitoring.
*   **S3 Bucket Security (Encryption, Versioning, Access Logging, Public Access Block)**: The general S3 bucket (e.g., for Loki storage) is configured with AES-256 server-side encryption, versioning for data durability and rollback, and blocks all public access. Server access logging is enabled by default (`enable_s3_server_access_logging = true`), delivering detailed request logs to a separate, dedicated S3 bucket (which is also securely configured with encryption, versioning, and a log retention policy via `s3_access_logs_retention_days`). This aids in security audits and monitoring. Additionally, for Loki data stored in S3 (under the 'loki/' prefix), a configurable lifecycle policy manages log retention (default 30 days via `s3_loki_log_retention_days`).
*   **ECR Repository Security**: Images stored in ECR are encrypted (AES-256), image scanning on push is enabled to detect vulnerabilities, and image tags are set to immutable by default (`ecr_image_tag_mutability = "IMMUTABLE"`) to maintain version integrity. This setting is configurable.
*   **VPC Flow Logs:** Network traffic within the VPC is logged via VPC Flow Logs and sent to AWS CloudWatch Logs, providing an audit trail of network communications.
*   **WAF Integration:** An AWS WAFv2 Web ACL is provisioned and associated with common AWS Managed Rule Groups (CommonRuleSet, AmazonIpReputationList, KnownBadInputsRuleSet, SQLiRuleSet) to protect web applications from common exploits.
*   **IMDSv2 Enforcement:** Worker nodes (EC2 instances) are configured via their launch template to require IMDSv2, enhancing protection against SSRF vulnerabilities that might attempt to access instance metadata.
*   **IAM Roles & Least Privilege:** The module utilizes specific IAM roles for different components (EKS cluster, node groups, VPC Flow Logs) and relies on AWS managed policies, which are regularly updated by AWS. Further refinement of these roles can be done if more restrictive policies are needed based on specific application requirements.
*   **IAM Roles for Service Accounts (IRSA) for Loki**: To enhance security and enforce least privilege for accessing S3, Loki is configured by default to use a dedicated IAM role associated with its Kubernetes service account (`loki_enable_irsa = true`). This avoids granting broader S3 permissions to the worker node IAM roles for Loki's needs.
*   **Secure Ingress with AWS Load Balancer Controller (IRSA)**: The AWS Load Balancer Controller is installed by default and configured with a dedicated IAM Role for Service Accounts (IRSA). This ensures that the controller has only the necessary permissions to manage AWS load balancing resources, following the principle of least privilege. It can be integrated with the provisioned AWS WAF for enhanced security at the edge.

**Disclaimer:** This Terraform module provides infrastructure components and configurations that can help organizations meet HIPAA requirements. It does not guarantee HIPAA compliance. Organizations must conduct their own risk assessments, implement appropriate administrative and technical safeguards, and ensure their applications and operational procedures comply with all applicable HIPAA regulations.

## 5. Included Components

*   **AWS ECR (Elastic Container Registry):** Creates a private ECR repository for storing your container images. Image scanning on push is enabled, images are encrypted with AES256, and image tags are **immutable by default** (`ecr_image_tag_mutability = "IMMUTABLE"`) to ensure tag stability and prevent accidental overwrites. This setting is configurable.
*   **AWS S3 (Simple Storage Service):** Secure, durable, and scalable object storage. This module provisions one S3 bucket with encryption and versioning, which can be used by Loki for log storage or for other general storage needs.
*   **AWS WAF (Web Application Firewall):** Helps protect your web applications or APIs against common web exploits that may affect availability, compromise security, or consume excessive resources.
*   **Metrics Server:** A cluster-wide aggregator of resource usage data. It collects metrics like CPU and memory usage for pods and nodes, making them available for use by Horizontal Pod Autoscaler (HPA) and Vertical Pod Autoscaler (VPA).
*   **Loki:** A horizontally scalable, highly available, multi-tenant log aggregation system inspired by Prometheus. It is designed to be very cost-effective and easy to operate. Logs are indexed by labels, not by content. This module can configure Loki to use the provisioned S3 bucket as a storage backend.
    *   **Loki Log Retention:** If Loki is configured to use the S3 backend, a lifecycle policy is applied to the 'loki/' prefix in the S3 bucket to automatically expire log data after a configurable period (default 30 days, see `s3_loki_log_retention_days`). This helps manage storage costs and adhere to data retention policies.
    *   **Secure S3 Access with IRSA**: When enabled (`loki_enable_irsa` is true, which is the default), Loki is configured to use an IAM Role for Service Accounts (IRSA). This grants its Kubernetes service account fine-grained permissions to access its S3 bucket path directly, enhancing security by adhering to the principle of least privilege without needing to share node IAM role permissions or use IAM user keys.
*   **Grafana:** An open-source platform for monitoring and observability. It allows you to query, visualize, alert on, and explore your metrics, logs, and traces wherever they are stored. This module installs Grafana and pre-configures Loki as a datasource. Persistence for Grafana data is enabled by default.
*   **AWS Load Balancer Controller:** Manages AWS Application Load Balancers (ALBs) and Network Load Balancers (NLBs) to expose Kubernetes services. It's installed via Helm and configured to use IAM Roles for Service Accounts (IRSA) for secure AWS API access. This controller is essential for routing external traffic to applications running in the EKS cluster.

## 6. Inputs

| Variable Name                      | Description                                                                                                                                                  | Type           | Default Value                                                                                                                                                             |
| :--------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `cluster_name`                     | The name of the EKS cluster.                                                                                                                                 | `string`       | `"my-eks-cluster"`                                                                                                                                                        |
| `cluster_version`                  | The Kubernetes version for the EKS cluster.                                                                                                                    | `string`       | `"1.27"`                                                                                                                                                          |
| `instance_type`                    | The EC2 instance type for the worker nodes.                                                                                                                    | `string`       | `"t3.medium"`                                                                                                                                                         |
| `desired_capacity`                 | The desired number of worker nodes.                                                                                                                            | `number`       | `2`                                                                                                                                                                       |
| `min_size`                         | The minimum number of worker nodes.                                                                                                                            | `number`       | `1`                                                                                                                                                                       |
| `max_size`                         | The maximum number of worker nodes.                                                                                                                            | `number`       | `3`                                                                                                                                                                       |
| `node_group_remote_access_ssh_key` | Optional: SSH key name for remote access to worker nodes. For HIPAA, direct SSH access should be minimized and strictly controlled via bastion hosts or Systems Manager Session Manager. | `string`       | `""`                                                                                                                                                              |
| `ebs_kms_key_arn`                  | Optional: KMS key ARN for EBS volume encryption on worker nodes. If null, uses AWS managed key for EBS.                                                        | `string`       | `null`                                                                                                                                                            |
| `ecr_repository_name`              | The name for the ECR repository. If empty, it defaults to `'${var.cluster_name}-app-repo'`.                                                                    | `string`       | `""`                                                                                                                                                              |
| `s3_bucket_name`                   | The name for the general purpose S3 bucket. Must be globally unique. If empty, it defaults to `'${var.cluster_name}-general-storage'`. Consider adding a random suffix or account ID in production for uniqueness. | `string`       | `""`                                                                                                                                                              |
| `waf_web_acl_name`                 | The name for the WAFv2 Web ACL. If empty, it defaults to `'${var.cluster_name}-web-acl'`.                                                                      | `string`       | `""`                                                                                                                                                              |
| `waf_managed_rules`                | A map of AWS Managed Rules to apply to WAF. Key is rule name, value contains priority and override_action ('none' or 'count').                                 | `map(object({ priority = number, override_action = string }))` | `{ "AWSManagedRulesAmazonIpReputationList" = { override_action = "none", priority = 20 }, "AWSManagedRulesCommonRuleSet" = { override_action = "none", priority = 10 }, "AWSManagedRulesKnownBadInputsRuleSet" = { override_action = "none", priority = 30 }, "AWSManagedRulesSQLiRuleSet" = { override_action = "none", priority = 40 } }` |
| `vpc_enable_flow_log`              | Enable VPC flow logs to CloudWatch Logs.                                                                                                                     | `bool`         | `true`                                                                                                                                                            |
| `vpc_cidr`                         | The CIDR block for the VPC.                                                                                                                                  | `string`       | `"10.0.0.0/16"`                                                                                                                                                       |
| `vpc_azs`                          | A list of Availability Zones for the VPC.                                                                                                                      | `list(string)` | `["us-west-2a", "us-west-2b"]`                                                                                                                                            |
| `vpc_private_subnets`              | A list of CIDR blocks for private subnets in the VPC.                                                                                                          | `list(string)` | `["10.0.1.0/24", "10.0.2.0/24"]`                                                                                                                                      |
| `vpc_public_subnets`               | A list of CIDR blocks for public subnets in the VPC.                                                                                                           | `list(string)` | `["10.0.101.0/24", "10.0.102.0/24"]`                                                                                                                                  |
| `vpc_enable_nat_gateway`           | Enable NAT gateway for private subnets.                                                                                                                      | `bool`         | `true`                                                                                                                                                            |
| `vpc_single_nat_gateway`           | Use a single NAT gateway. Requires vpc_enable_nat_gateway to be true.                                                                                        | `bool`         | `true`                                                                                                                                                            |
| `install_metrics_server`           | Enable Metrics Server installation.                                                                                                                          | `bool`         | `true`                                                                                                                                                            |
| `metrics_server_chart_version`     | Metrics Server Helm chart version.                                                                                                                             | `string`       | `"3.11.0"`                                                                                                                                                        |
| `metrics_server_namespace`         | Namespace for Metrics Server.                                                                                                                                | `string`       | `"kube-system"`                                                                                                                                                   |
| `install_loki`                     | Enable Loki installation.                                                                                                                                    | `bool`         | `true`                                                                                                                                                            |
| `loki_chart_version`               | Loki Helm chart version.                                                                                                                                     | `string`       | `"5.10.1"`                                                                                                                                                        |
| `loki_namespace`                   | Namespace for Loki.                                                                                                                                          | `string`       | `"loki"`                                                                                                                                                          |
| `loki_s3_bucket_name`              | S3 bucket name for Loki storage. If empty and install_loki_s3_backend is true, uses the general S3 bucket created by the module. If install_loki_s3_backend is false, this is ignored. | `string`       | `""`                                                                                                                                                              |
| `install_loki_s3_backend`          | Configure Loki to use S3 backend for storage.                                                                                                                | `bool`         | `true`                                                                                                                                                            |
| `install_grafana`                  | Enable Grafana installation.                                                                                                                                 | `bool`         | `true`                                                                                                                                                            |
| `grafana_chart_version`            | Grafana Helm chart version.                                                                                                                                  | `string`       | `"7.0.19"`                                                                                                                                                        |
| `grafana_namespace`                | Namespace for Grafana.                                                                                                                                       | `string`       | `"grafana"`                                                                                                                                                       |
| `grafana_admin_password`           | Grafana admin password. IMPORTANT: Change this in production. Consider using a secrets manager.                                                              | `string`       | `"prom-operator"` (sensitive)                                                                                                                                               |
| `s3_loki_log_retention_days`       | Number of days to retain Loki logs in the S3 bucket. After this period, logs will be expired. This applies to objects prefixed with 'loki/' if Loki is configured to use that prefix. | `number`       | `30`                                                                                                                                                              |
| `loki_enable_irsa`                 | Enable IAM Roles for Service Accounts (IRSA) for Loki to access S3.                                                                                          | `bool`         | `true`                                                                                                                                                            |
| `install_aws_load_balancer_controller` | Enable installation of the AWS Load Balancer Controller.                                                                                                     | `bool`         | `true`                                                                                                                                                            |
| `aws_load_balancer_controller_chart_version` | Helm chart version for the AWS Load Balancer Controller.                                                                                                     | `string`       | `"1.7.1"`                                                                                                                                                         |
| `aws_load_balancer_controller_service_account_name` | Kubernetes service account name for the AWS Load Balancer Controller.                                                                                | `string`       | `"aws-load-balancer-controller"`                                                                                                                                  |
| `enable_s3_server_access_logging`    | Enable server access logging for the general S3 bucket. Creates a new bucket for these logs unless `s3_access_logs_bucket_name_override` is set.                 | `bool`         | `true`                                                                                                                                                            |
| `s3_access_logs_bucket_name_override` | Optional. Name of an existing S3 bucket to store server access logs. If empty and logging is enabled, a new bucket is created.                                  | `string`       | `""`                                                                                                                                                              |
| `s3_access_logs_retention_days`      | Number of days to retain S3 server access logs in their dedicated bucket.                                                                                          | `number`       | `90`                                                                                                                                                              |
| `ecr_image_tag_mutability`         | Sets the tag mutability setting for the ECR repository. Recommended to be 'IMMUTABLE'. Valid values are 'MUTABLE' or 'IMMUTABLE'.                                | `string`       | `"IMMUTABLE"`                                                                                                                                                     |

## 7. Outputs

| Output Name                | Description                                                                      |
| :------------------------- | :------------------------------------------------------------------------------- |
| `cluster_name`             | The name of the EKS cluster.                                                     |
| `cluster_endpoint`         | The endpoint for your EKS Kubernetes API server.                                 |
| `cluster_ca_certificate`   | Base64 encoded certificate data required to communicate with your cluster.         |
| `node_group_role_arn`      | The ARN of the IAM role used by the EKS node group.                              |
| `vpc_id`                   | The ID of the VPC created for the EKS cluster.                                   |
| `vpc_private_subnet_ids`   | List of private subnet IDs in the VPC.                                           |
| `vpc_public_subnet_ids`    | List of public subnet IDs in the VPC.                                            |
| `ecr_repository_url`       | The URL of the ECR repository.                                                   |
| `s3_bucket_id`             | The ID (name) of the general purpose S3 bucket.                                  |
| `s3_bucket_arn`            | The ARN of the general purpose S3 bucket.                                        |
| `waf_web_acl_arn`          | The ARN of the WAFv2 Web ACL.                                                    |

---

This README provides a comprehensive guide to using and understanding the EKS Terraform module. Remember to replace placeholder values and consider security best practices for production deployments.
