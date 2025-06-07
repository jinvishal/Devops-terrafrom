variable "cluster_name" {
  description = "The name of the EKS cluster."
  type        = string
  default     = "my-eks-cluster"
}

variable "cluster_version" {
  description = "The Kubernetes version for the EKS cluster."
  type        = string
  default     = "1.27"
}

variable "eks_endpoint_public_access" {
  description = "Controls whether the EKS cluster endpoint is publicly accessible."
  type        = bool
  default     = true
}

variable "eks_endpoint_private_access" {
  description = "Controls whether the EKS cluster endpoint is accessible from within the VPC. If public access is disabled, private access must be enabled for kubectl and other API interactions from within the VPC."
  type        = bool
  default     = false # Defaulting to false to maintain current behavior unless explicitly changed.
}

variable "eks_public_access_cidrs" {
  description = "List of CIDR blocks that are allowed to access the EKS public endpoint. Only applies if eks_endpoint_public_access is true. Default allows all IPs."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "eks_secrets_encryption_kms_key_arn" {
  description = "Optional. ARN of the AWS KMS Customer Managed Key (CMK) to use for encrypting Kubernetes secrets in EKS. If not provided, EKS uses an AWS-managed KMS key. Ensure the EKS cluster IAM role has encrypt/decrypt permissions on this key."
  type        = string
  default     = "" # Defaulting to empty string, meaning CMK encryption is off by default.
}

variable "instance_type" {
  description = "The EC2 instance type for the worker nodes."
  type        = string
  default     = "t3.medium"
}

variable "desired_capacity" {
  description = "The desired number of worker nodes."
  type        = number
  default     = 2
}

variable "min_size" {
  description = "The minimum number of worker nodes."
  type        = number
  default     = 1
}

variable "max_size" {
  description = "The maximum number of worker nodes."
  type        = number
  default     = 3
}

# EKS Node Group Variables
variable "node_group_remote_access_ssh_key" {
  description = "Optional: SSH key name for remote access to worker nodes. For HIPAA, direct SSH access should be minimized and strictly controlled via bastion hosts or Systems Manager Session Manager."
  type        = string
  default     = ""
}

variable "ebs_kms_key_arn" {
  description = "Optional: KMS key ARN for EBS volume encryption on worker nodes. If null, uses AWS managed key for EBS."
  type        = string
  default     = null
}

# ECR Repository Name
variable "ecr_repository_name" {
  description = "The name for the ECR repository. If empty, it defaults to '${var.cluster_name}-app-repo'."
  type        = string
  default     = ""
}

variable "ecr_image_tag_mutability" {
  description = "Sets the tag mutability setting for the ECR repository. Recommended to be 'IMMUTABLE'. Valid values are 'MUTABLE' or 'IMMUTABLE'."
  type        = string
  default     = "IMMUTABLE"

  validation {
    condition     = contains(["MUTABLE", "IMMUTABLE"], var.ecr_image_tag_mutability)
    error_message = "The ECR image tag mutability must be either 'MUTABLE' or 'IMMUTABLE'."
  }
}

# S3 Bucket Name
variable "s3_bucket_name" {
  description = "The name for the general purpose S3 bucket. Must be globally unique. If empty, it defaults to '${var.cluster_name}-general-storage'. Consider adding a random suffix or account ID in production for uniqueness."
  type        = string
  default     = ""
}

# WAFv2 Web ACL Name
variable "waf_web_acl_name" {
  description = "The name for the WAFv2 Web ACL. If empty, it defaults to '${var.cluster_name}-web-acl'."
  type        = string
  default     = ""
}

variable "waf_managed_rules" {
  description = "A map of AWS Managed Rules to apply to WAF. Key is rule name, value contains priority and override_action ('none' or 'count')."
  type        = map(object({
    priority        = number
    override_action = string # "none" or "count"
  }))
  default = {
    "AWSManagedRulesCommonRuleSet" = {
      priority        = 10 # Adjusted priority
      override_action = "none"
    },
    "AWSManagedRulesAmazonIpReputationList" = {
      priority        = 20
      override_action = "none" # Consider "count" for monitoring before blocking
    },
    "AWSManagedRulesKnownBadInputsRuleSet" = {
      priority        = 30
      override_action = "none"
    },
    "AWSManagedRulesSQLiRuleSet" = { # Specific to SQLi, might be AWSManagedRulesKnownBadInputsRuleSet or a more specific one. Using this as an example.
      priority        = 40
      override_action = "none"
    }
    # AWSManagedRulesAnonymousIpList could be added here.
    # AWSManagedRulesLinuxRuleSet might be relevant if Linux-specific attacks are a concern.
  }
}

# VPC Configuration Variables
variable "vpc_enable_flow_log" {
  description = "Enable VPC flow logs to CloudWatch Logs."
  type        = bool
  default     = true
}

# Helm Chart Installations

variable "install_metrics_server" {
  description = "Enable Metrics Server installation."
  type        = bool
  default     = true
}

variable "install_aws_load_balancer_controller" {
  description = "Enable installation of the AWS Load Balancer Controller."
  type        = bool
  default     = true
}

variable "aws_load_balancer_controller_chart_version" {
  description = "Helm chart version for the AWS Load Balancer Controller."
  type        = string
  default     = "1.7.1" # Specify a recent, known good version. Verify latest if possible.
}

variable "aws_load_balancer_controller_service_account_name" {
  description = "Kubernetes service account name for the AWS Load Balancer Controller."
  type        = string
  default     = "aws-load-balancer-controller" # This must match the trusted SA in the IRSA role
}

variable "enable_s3_server_access_logging" {
  description = "Enable server access logging for the general S3 bucket. This will create a new S3 bucket to store these logs unless an override name is provided."
  type        = bool
  default     = true
}

variable "s3_access_logs_bucket_name_override" {
  description = "Optional: Specify an existing S3 bucket name to store server access logs. If empty, a new bucket will be created. Ensure this bucket has appropriate permissions for s3-log-delivery-group."
  type        = string
  default     = ""
}

variable "s3_access_logs_retention_days" {
  description = "Number of days to retain S3 server access logs in their dedicated bucket."
  type        = number
  default     = 90
}

variable "metrics_server_chart_version" {
  description = "Metrics Server Helm chart version."
  type        = string
  default     = "3.11.0"
}

variable "metrics_server_namespace" {
  description = "Namespace for Metrics Server."
  type        = string
  default     = "kube-system"
}

variable "install_loki" {
  description = "Enable Loki installation."
  type        = bool
  default     = true
}

variable "loki_chart_version" {
  description = "Loki Helm chart version."
  type        = string
  default     = "5.10.1" # Check for latest compatible, e.g., 5.42.0 for chart, app 2.9.x
}

variable "loki_namespace" {
  description = "Namespace for Loki."
  type        = string
  default     = "loki"
}

variable "loki_s3_bucket_name" {
  description = "S3 bucket name for Loki storage. If empty and install_loki_s3_backend is true, uses the general S3 bucket created by the module. If install_loki_s3_backend is false, this is ignored."
  type        = string
  default     = ""
}

variable "install_loki_s3_backend" {
  description = "Configure Loki to use S3 backend for storage."
  type        = bool
  default     = true
}

variable "install_grafana" {
  description = "Enable Grafana installation."
  type        = bool
  default     = true
}

variable "grafana_chart_version" {
  description = "Grafana Helm chart version."
  type        = string
  default     = "7.0.19" # Check for latest compatible, e.g., 7.3.x for app 10.x.x
}

variable "grafana_namespace" {
  description = "Namespace for Grafana."
  type        = string
  default     = "grafana"
}

variable "grafana_admin_password" {
  description = "Grafana admin password. Used only if 'grafana_admin_password_secrets_manager_arn' is not provided. IMPORTANT: Change this in production if not using Secrets Manager."
  type        = string
  default     = "prom-operator" # Example, ensure this is changed
  sensitive   = true
}

variable "grafana_admin_password_secrets_manager_arn" {
  description = "ARN of the AWS Secrets Manager secret containing the Grafana admin password. If provided, this takes precedence over 'grafana_admin_password'."
  type        = string
  default     = ""
}

variable "grafana_admin_password_secrets_manager_version_id" {
  description = "Version ID of the secret in AWS Secrets Manager for the Grafana admin password. Defaults to the latest version if not specified."
  type        = string
  default     = null # Using null for optional arguments in data source
}

variable "grafana_admin_password_secrets_manager_version_stage" {
  description = "Version stage of the secret in AWS Secrets Manager for the Grafana admin password. Defaults to 'AWSCURRENT' if not specified and version_id is also not set."
  type        = string
  default     = null # Using null for optional arguments in data source, data source defaults to AWSCURRENT if both are null
}

variable "s3_loki_log_retention_days" {
  description = "Number of days to retain Loki logs in the S3 bucket. After this period, logs will be expired. This applies to objects prefixed with 'loki/' if Loki is configured to use that prefix."
  type        = number
  default     = 30
}

# VPC Configuration Variables
variable "vpc_cidr" {
  description = "The CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "vpc_azs" {
  description = "A list of Availability Zones for the VPC."
  type        = list(string)
  default     = ["us-west-2a", "us-west-2b"]
}

variable "vpc_private_subnets" {
  description = "A list of CIDR blocks for private subnets in the VPC."
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "vpc_public_subnets" {
  description = "A list of CIDR blocks for public subnets in the VPC."
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24"]
}

variable "vpc_enable_nat_gateway" {
  description = "Enable NAT gateway for private subnets."
  type        = bool
  default     = true
}

variable "loki_enable_irsa" {
  description = "Enable IAM Roles for Service Accounts (IRSA) for Loki to access S3."
  type        = bool
  default     = true # Default to true as it's a security best practice
}

variable "s3_loki_log_retention_days" {
  description = "Number of days to retain Loki logs in the S3 bucket. After this period, logs will be expired. This applies to objects prefixed with 'loki/' if Loki is configured to use that prefix."
  type        = number
  default     = 30
}

# VPC Configuration Variables
variable "vpc_cidr" {
  description = "The CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "vpc_azs" {
  description = "A list of Availability Zones for the VPC."
  type        = list(string)
  default     = ["us-west-2a", "us-west-2b"]
}

variable "vpc_private_subnets" {
  description = "A list of CIDR blocks for private subnets in the VPC."
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "vpc_public_subnets" {
  description = "A list of CIDR blocks for public subnets in the VPC."
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24"]
}

variable "vpc_enable_nat_gateway" {
  description = "Enable NAT gateway for private subnets."
  type        = bool
  default     = true
}

variable "vpc_enable_s3_gateway_endpoint" {
  description = "Enable the S3 Gateway VPC Endpoint. Recommended to keep traffic to S3 within the AWS network."
  type        = bool
  default     = true
}

variable "vpc_enable_ecr_api_interface_endpoint" {
  description = "Enable the ECR API Interface VPC Endpoint (com.amazonaws.<region>.ecr.api). Recommended for private ECR access."
  type        = bool
  default     = true
}

variable "vpc_enable_ecr_dkr_interface_endpoint" {
  description = "Enable the ECR DKR Interface VPC Endpoint (com.amazonaws.<region>.ecr.dkr). Recommended for private ECR image pulls/pushes."
  type        = bool
  default     = true
}

variable "vpc_enable_kms_interface_endpoint" {
  description = "Enable the KMS Interface VPC Endpoint (com.amazonaws.<region>.kms). Important if using KMS CMKs for EKS secrets or other resources."
  type        = bool
  default     = true
}

variable "vpc_enable_sts_interface_endpoint" {
  description = "Enable the STS Interface VPC Endpoint (com.amazonaws.<region>.sts). Important for IAM Roles for Service Accounts (IRSA) to function optimally without NAT Gateway traversal for token exchange."
  type        = bool
  default     = true
}

variable "vpc_enable_cloudwatch_logs_interface_endpoint" {
  description = "Enable the CloudWatch Logs Interface VPC Endpoint (com.amazonaws.<region>.logs). Useful if applications/pods log heavily to CloudWatch Logs directly. Disabled by default due to potential data transfer costs if not carefully managed."
  type        = bool
  default     = false
}

variable "vpc_single_nat_gateway" {
  description = "Use a single NAT gateway. Requires vpc_enable_nat_gateway to be true."
  type        = bool
  default     = true
}
