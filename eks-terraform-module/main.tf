locals {
  tags = {
    Terraform   = "true"
    Environment = "dev" # Example environment, can be customized
  }

  # Default names for resources if not provided by variables
  ecr_repo_name_default    = var.ecr_repository_name == "" ? "${var.cluster_name}-app-repo" : var.ecr_repository_name
  s3_bucket_name_default   = var.s3_bucket_name == "" ? "${var.cluster_name}-general-storage" : var.s3_bucket_name
  waf_web_acl_name_default = var.waf_web_acl_name == "" ? "${var.cluster_name}-web-acl" : var.waf_web_acl_name

  # Determine if a custom KMS key is provided for EBS encryption
  ebs_encryption_kms_key_id = var.ebs_kms_key_arn == null ? null : var.ebs_kms_key_arn

  # Loki S3 bucket: use specific var if provided, else use the general bucket name
  loki_s3_actual_bucket_name = var.install_loki_s3_backend && var.loki_s3_bucket_name == "" ? local.s3_bucket_name_default : var.loki_s3_bucket_name

  # S3 Server Access Logs Bucket Configuration
  s3_access_logs_bucket_actual_name = var.s3_access_logs_bucket_name_override != "" ? var.s3_access_logs_bucket_name_override : (var.enable_s3_server_access_logging ? "${var.cluster_name}-s3-access-logs-${data.aws_caller_identity.current.account_id}" : null)
  create_s3_access_logs_bucket      = var.enable_s3_server_access_logging && var.s3_access_logs_bucket_name_override == ""
}

# Data sources
data "aws_region" "current" {}

data "aws_caller_identity" "current" {} # Ensure this is present

data "aws_eks_cluster_auth" "main" {
  name = aws_eks_cluster.main.name
}

# Provider configurations
provider "kubernetes" {
  host                   = aws_eks_cluster.main.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.main.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.main.token
}

provider "helm" {
  kubernetes {
    host                   = aws_eks_cluster.main.endpoint
    cluster_ca_certificate = base64decode(aws_eks_cluster.main.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.main.token
  }
}

# IAM Role and Policy for VPC Flow Logs
resource "aws_iam_role" "vpc_flow_logs_role" {
  count = var.vpc_enable_flow_log ? 1 : 0

  name_prefix        = "${var.cluster_name}-vpc-flow-logs-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        },
        Action    = "sts:AssumeRole"
      }
    ]
  })
  tags = local.tags
}

resource "aws_iam_policy" "vpc_flow_logs_policy" {
  count = var.vpc_enable_flow_log ? 1 : 0

  name_prefix = "${var.cluster_name}-vpc-flow-logs-policy-"
  description = "Allows VPC Flow Logs to publish to CloudWatch Logs."
  policy      = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ],
        Effect   = "Allow",
        Resource = "*"
      }
    ]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "vpc_flow_logs_attachment" {
  count = var.vpc_enable_flow_log ? 1 : 0

  role       = aws_iam_role.vpc_flow_logs_role[0].name
  policy_arn = aws_iam_policy.vpc_flow_logs_policy[0].arn
}

# VPC Module
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0" # Ensure this is compatible with attributes used

  name = "${var.cluster_name}-vpc"
  cidr = var.vpc_cidr
  azs  = var.vpc_azs

  private_subnets = var.vpc_private_subnets
  public_subnets  = var.vpc_public_subnets

  enable_nat_gateway   = var.vpc_enable_nat_gateway
  single_nat_gateway   = var.vpc_single_nat_gateway
  enable_dns_hostnames = true

  enable_flow_log                 = var.vpc_enable_flow_log
  flow_log_destination_type       = var.vpc_enable_flow_log ? "cloud-watch-logs" : null
  flow_log_cloudwatch_log_group_name = var.vpc_enable_flow_log ? "/aws/vpc-flow-logs/${var.cluster_name}" : null
  flow_log_cloudwatch_iam_role_arn = var.vpc_enable_flow_log ? aws_iam_role.vpc_flow_logs_role[0].arn : null

  public_subnet_tags = merge(
    local.tags,
    {
      "kubernetes.io/cluster/${var.cluster_name}" = "shared"
      "kubernetes.io/role/elb"                   = "1"
    }
  )

  private_subnet_tags = merge(
    local.tags,
    {
      "kubernetes.io/cluster/${var.cluster_name}" = "shared"
      "kubernetes.io/role/internal-elb"          = "1"
    }
  )

  tags = local.tags
}

# IAM Module for EKS Cluster Role
module "eks_cluster_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "~> 5.30"

  create_role             = true
  role_name               = "${var.cluster_name}-cluster-role"
  trusted_role_services   = ["eks.amazonaws.com"]
  custom_role_policy_arns = ["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]
  tags                    = local.tags
}

# IAM Module for EKS Node Group Role
module "eks_node_group_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "~> 5.30"

  create_role = true
  role_name   = "${var.cluster_name}-node-group-role"
  trusted_role_services = ["ec2.amazonaws.com"]
  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  ]
  tags = local.tags
}

resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  version  = var.cluster_version
  role_arn = module.eks_cluster_role.iam_role_arn

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  vpc_config {
    subnet_ids              = module.vpc.private_subnet_ids
    endpoint_public_access  = var.eks_endpoint_public_access
    endpoint_private_access = var.eks_endpoint_private_access
    public_access_cidrs     = var.eks_endpoint_public_access ? var.eks_public_access_cidrs : null # Only apply if public access is true
    # Ensure that if public access is false, public_access_cidrs is not set or is null/empty,
    # as AWS API might reject ["0.0.0.0/0"] if endpoint_public_access is false.
    # Setting to null if public access is disabled is safer.
  }

  dynamic "encryption_config" {
    for_each = var.eks_secrets_encryption_kms_key_arn != "" ? [1] : [] # Create block only if KMS key ARN is provided
    content {
      resources = ["secrets"] # Specifies that Kubernetes secrets should be encrypted
      provider {
        key_arn = var.eks_secrets_encryption_kms_key_arn
      }
    }
  }

  tags = local.tags
}

resource "aws_launch_template" "eks_nodes_lt" {
  name_prefix   = "${var.cluster_name}-lt-"
  description   = "Launch template for EKS worker nodes with EBS encryption"
  instance_type = var.instance_type

  block_device_mappings {
    device_name = "/dev/xvda" # Standard for Amazon Linux 2
    ebs {
      encrypted   = true
      kms_key_id  = local.ebs_encryption_kms_key_id
      volume_type = "gp3"
      # volume_size - Handled by EKS based on AMI unless specified
      delete_on_termination = true
    }
  }

  metadata_options { # IMDSv2 recommended
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, { Name = "${var.cluster_name}-worker-instance" })
  }
  tag_specifications {
    resource_type = "volume"
    tags          = merge(local.tags, { Name = "${var.cluster_name}-worker-volume" })
  }

  tags = local.tags
}

resource "aws_eks_node_group" "final_main_node_group" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.cluster_name}-node-group"
  node_role_arn   = module.eks_node_group_role.iam_role_arn
  subnet_ids      = module.vpc.private_subnet_ids

  dynamic "remote_access" {
    for_each = var.node_group_remote_access_ssh_key != "" ? [1] : []
    content {
      ec2_ssh_key = var.node_group_remote_access_ssh_key
    }
  }

  scaling_config {
    desired_size = var.desired_capacity
    min_size     = var.min_size
    max_size     = var.max_size
  }

  launch_template {
    id      = aws_launch_template.eks_nodes_lt.id
    version = aws_launch_template.eks_nodes_lt.latest_version
  }

  depends_on = [
    module.vpc,
    aws_launch_template.eks_nodes_lt
  ]
  tags = merge(
    local.tags,
    {
      Name = "${var.cluster_name}-worker-node"
    }
  )
}

# ECR Repository
resource "aws_ecr_repository" "app_ecr_repo" {
  name                 = local.ecr_repo_name_default
  image_tag_mutability = var.ecr_image_tag_mutability
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "AES256" }
  tags = local.tags
}

# General S3 Bucket (for Loki, general storage)
resource "aws_s3_bucket" "general_s3_bucket" {
  bucket = local.s3_bucket_name_default
  tags   = local.tags
}

resource "aws_s3_bucket_versioning" "general_s3_bucket_versioning" {
  bucket = aws_s3_bucket.general_s3_bucket.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "general_s3_bucket_encryption" {
  bucket = aws_s3_bucket.general_s3_bucket.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}

resource "aws_s3_bucket_public_access_block" "general_s3_bucket_public_access" {
  bucket = aws_s3_bucket.general_s3_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "general_s3_bucket_lifecycle" {
  bucket = aws_s3_bucket.general_s3_bucket.id
  rule {
    id     = "lokiLogRetention"
    status = "Enabled"
    filter { prefix = "loki/" }
    expiration { days = var.s3_loki_log_retention_days }
    noncurrent_version_expiration { noncurrent_days = var.s3_loki_log_retention_days + 7 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
  depends_on = [aws_s3_bucket_versioning.general_s3_bucket_versioning]
}

# S3 Bucket for Server Access Logs
resource "aws_s3_bucket" "access_logs_s3_bucket" {
  count  = local.create_s3_access_logs_bucket ? 1 : 0
  bucket = local.s3_access_logs_bucket_actual_name
  tags   = merge(local.tags, { Name = "${local.s3_access_logs_bucket_actual_name}-access-logs" })
}

resource "aws_s3_bucket_versioning" "access_logs_s3_bucket_versioning" {
  count  = local.create_s3_access_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.access_logs_s3_bucket[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs_s3_bucket_encryption" {
  count  = local.create_s3_access_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.access_logs_s3_bucket[0].id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}

resource "aws_s3_bucket_public_access_block" "access_logs_s3_bucket_public_access" {
  count  = local.create_s3_access_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.access_logs_s3_bucket[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs_s3_bucket_lifecycle" {
  count  = local.create_s3_access_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.access_logs_s3_bucket[0].id
  rule {
    id     = "logRetention"
    status = "Enabled"
    expiration { days = var.s3_access_logs_retention_days }
    noncurrent_version_expiration { noncurrent_days = var.s3_access_logs_retention_days + 7 } # Or a different value for noncurrent log versions
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
  depends_on = [aws_s3_bucket_versioning.access_logs_s3_bucket_versioning[0]]
}

data "aws_iam_policy_document" "access_logs_s3_bucket_policy_doc" {
  count = local.create_s3_access_logs_bucket ? 1 : 0
  statement {
    sid    = "S3LogDeliveryWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.access_logs_s3_bucket[0].arn}/*"] # Or specific prefix like "logs/"
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.general_s3_bucket.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "access_logs_s3_bucket_policy" {
  count  = local.create_s3_access_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.access_logs_s3_bucket[0].id
  policy = data.aws_iam_policy_document.access_logs_s3_bucket_policy_doc[0].json
}

resource "aws_s3_bucket_logging" "general_s3_bucket_access_logging" {
  count = var.enable_s3_server_access_logging ? 1 : 0

  bucket = aws_s3_bucket.general_s3_bucket.id

  target_bucket = local.s3_access_logs_bucket_actual_name
  target_prefix = "${aws_s3_bucket.general_s3_bucket.id}-access-logs/" # Using source bucket ID as part of prefix

  depends_on = [
    # If the access logs bucket is created by this module, depend on its creation and policy.
    # If an override bucket is used, these dependencies might not be strictly necessary here,
    # but it's safer to include them if the resources are potentially managed by this module.
    # The conditional creation of these resources means they might not exist in `terraform plan` if disabled.
    # However, if var.enable_s3_server_access_logging is true, then s3_access_logs_bucket_actual_name is definitely set.
    # If create_s3_access_logs_bucket is true, then these resources exist.
    # If create_s3_access_logs_bucket is false (meaning override is used), these specific resources don't exist here.
    # This dependency should ideally only be on resources that are definitely created when this resource is created.
    # local.create_s3_access_logs_bucket can gate this.
    # No, this is simpler: if logging is enabled, target_bucket is valid. If that target is created by us, it needs to be ready.
    aws_s3_bucket.access_logs_s3_bucket,
    aws_s3_bucket_policy.access_logs_s3_bucket_policy,
  ]
}

# IAM Policy for Loki S3 Access
resource "aws_iam_policy" "loki_s3_access_policy" {
  name_prefix = var.cluster_name
  name        = "${var.cluster_name}-loki-s3-access-policy"
  description = "IAM policy granting Loki access to its S3 bucket prefix."

  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Sid    = "LokiListBucket",
        Effect = "Allow",
        Action = "s3:ListBucket",
        Resource = aws_s3_bucket.general_s3_bucket.arn,
        Condition = {
          "StringLike" = {
            "s3:prefix" = ["loki/*"]
          }
        }
      },
      {
        Sid    = "LokiReadWriteDeleteObjects",
        Effect = "Allow",
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ],
        Resource = "${aws_s3_bucket.general_s3_bucket.arn}/loki/*"
      }
    ]
  })

  tags = local.tags
}

# IAM Role for Loki Service Account (IRSA)
data "aws_iam_policy_document" "loki_irsa_assume_role_policy" {
  count = var.loki_enable_irsa ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_eks_cluster.main.identity[0].oidc[0].provider]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_eks_cluster.main.identity[0].oidc[0].issuer, "https://", "")}:sub"
      values   = ["system:serviceaccount:${var.loki_namespace}:loki-sa"]
    }
  }
}

resource "aws_iam_role" "loki_irsa_role" {
  name_prefix        = "${var.cluster_name}-loki-irsa-"
  assume_role_policy = var.loki_enable_irsa ? data.aws_iam_policy_document.loki_irsa_assume_role_policy[0].json : null
  tags               = local.tags
  count              = var.loki_enable_irsa ? 1 : 0
}

resource "aws_iam_role_policy_attachment" "loki_irsa_role_s3_policy_attachment" {
  count      = var.loki_enable_irsa ? 1 : 0
  role       = aws_iam_role.loki_irsa_role[0].name
  policy_arn = aws_iam_policy.loki_s3_access_policy.arn
}

# WAF and other resources continue below...
resource "aws_wafv2_web_acl" "default_web_acl" {
  name  = local.waf_web_acl_name_default
  scope = "REGIONAL"
  default_action { allow {} }
  dynamic "rule" {
    for_each = var.waf_managed_rules
    content {
      name     = rule.key
      priority = rule.value.priority
      statement { managed_rule_group_statement { vendor_name = "AWS"; name = rule.key } }
      override_action {
        dynamic "none" { for_each = rule.value.override_action == "none" ? [1] : []; content {} }
        dynamic "count" { for_each = rule.value.override_action == "count" ? [1] : []; content {} }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = substr("WAFRule-${replace(rule.key, "_", "-")}", 0, 255)
        sampled_requests_enabled   = true
      }
    }
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = substr("${local.waf_web_acl_name_default}-metrics", 0, 255)
    sampled_requests_enabled   = true
  }
  tags = local.tags
}

# Helm Releases

# Metrics Server
resource "helm_release" "metrics_server" {
  count = var.install_metrics_server ? 1 : 0

  name       = "metrics-server"
  repository = "https://kubernetes-sigs.github.io/metrics-server/"
  chart      = "metrics-server"
  version    = var.metrics_server_chart_version
  namespace  = var.metrics_server_namespace
  create_namespace = true

  values = [yamlencode({
    args = [
      "--kubelet-insecure-tls",
      "--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname",
      "--kubelet-use-node-status-port"
    ]
  })]

  depends_on = [aws_eks_node_group.final_main_node_group]
}

# Loki Logging Stack
resource "kubernetes_namespace" "loki_ns" {
  count = var.install_loki ? 1 : 0
  metadata {
    name = var.loki_namespace
    labels = {
      "app.kubernetes.io/managed-by" = "Terraform"
      "name" = var.loki_namespace
    }
  }
  lifecycle {
    prevent_destroy = false
  }
}

resource "helm_release" "loki" {
  count = var.install_loki ? 1 : 0

  name       = "loki"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "loki"
  version    = var.loki_chart_version
  namespace  = var.loki_namespace
  create_namespace = false

  values = [templatefile("${path.module}/loki_values.yaml.tpl", {
    s3_bucket_name       = local.loki_s3_actual_bucket_name
    s3_region            = data.aws_region.current.name
    s3_enabled           = var.install_loki_s3_backend
    loki_irsa_role_arn   = var.loki_enable_irsa && length(aws_iam_role.loki_irsa_role) > 0 ? aws_iam_role.loki_irsa_role[0].arn : null
  })]

  depends_on = [
    aws_eks_node_group.final_main_node_group,
    kubernetes_namespace.loki_ns[0],
    aws_s3_bucket.general_s3_bucket,
    aws_iam_role.loki_irsa_role,
  ]
}

# IAM Policy for AWS Load Balancer Controller
resource "aws_iam_policy" "aws_load_balancer_controller_iam_policy" {
  count = var.install_aws_load_balancer_controller ? 1 : 0

  name_prefix = "${var.cluster_name}-ALBCtrl-"
  name        = "${var.cluster_name}-AWSLoadBalancerControllerIAMPolicy"
  description = "IAM Policy for AWS Load Balancer Controller"

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateServiceLinkedRole"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:AWSServiceName": "elasticloadbalancing.amazonaws.com"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeAccountAttributes",
                "ec2:DescribeAddresses",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeVpcs",
                "ec2:DescribeVpcPeeringConnections",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeTags",
                "ec2:GetCoipPoolUsage",
                "ec2:DescribeCoipPools",
                "ec2:GetSecurityGroupsForVpc",
                "ec2:DescribeIpamPools",
                "ec2:DescribeRouteTables",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeListeners",
                "elasticloadbalancing:DescribeListenerCertificates",
                "elasticloadbalancing:DescribeSSLPolicies",
                "elasticloadbalancing:DescribeRules",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetGroupAttributes",
                "elasticloadbalancing:DescribeTargetHealth",
                "elasticloadbalancing:DescribeTags",
                "elasticloadbalancing:DescribeTrustStores",
                "elasticloadbalancing:DescribeListenerAttributes",
                "elasticloadbalancing:DescribeCapacityReservation"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "cognito-idp:DescribeUserPoolClient",
                "acm:ListCertificates",
                "acm:DescribeCertificate",
                "iam:ListServerCertificates",
                "iam:GetServerCertificate",
                "waf-regional:GetWebACL",
                "waf-regional:GetWebACLForResource",
                "waf-regional:AssociateWebACL",
                "waf-regional:DisassociateWebACL",
                "wafv2:GetWebACL",
                "wafv2:GetWebACLForResource",
                "wafv2:AssociateWebACL",
                "wafv2:DisassociateWebACL",
                "shield:GetSubscriptionState",
                "shield:DescribeProtection",
                "shield:CreateProtection",
                "shield:DeleteProtection"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateSecurityGroup"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags"
            ],
            "Resource": "arn:aws:ec2:*:*:security-group/*",
            "Condition": {
                "StringEquals": {
                    "ec2:CreateAction": "CreateSecurityGroup"
                },
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags",
                "ec2:DeleteTags"
            ],
            "Resource": "arn:aws:ec2:*:*:security-group/*",
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:DeleteSecurityGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:CreateLoadBalancer",
                "elasticloadbalancing:CreateTargetGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:CreateListener",
                "elasticloadbalancing:DeleteListener",
                "elasticloadbalancing:CreateRule",
                "elasticloadbalancing:DeleteRule"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:AddTags",
                "elasticloadbalancing:RemoveTags"
            ],
            "Resource": [
                "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
            ],
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:AddTags",
                "elasticloadbalancing:RemoveTags"
            ],
            "Resource": [
                "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
                "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
                "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
                "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:ModifyLoadBalancerAttributes",
                "elasticloadbalancing:SetIpAddressType",
                "elasticloadbalancing:SetSecurityGroups",
                "elasticloadbalancing:SetSubnets",
                "elasticloadbalancing:DeleteLoadBalancer",
                "elasticloadbalancing:ModifyTargetGroup",
                "elasticloadbalancing:ModifyTargetGroupAttributes",
                "elasticloadbalancing:DeleteTargetGroup",
                "elasticloadbalancing:ModifyListenerAttributes",
                "elasticloadbalancing:ModifyCapacityReservation",
                "elasticloadbalancing:ModifyIpPools"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:AddTags"
            ],
            "Resource": [
                "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
            ],
            "Condition": {
                "StringEquals": {
                    "elasticloadbalancing:CreateAction": [
                        "CreateTargetGroup",
                        "CreateLoadBalancer"
                    ]
                },
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:RegisterTargets",
                "elasticloadbalancing:DeregisterTargets"
            ],
            "Resource": "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:SetWebAcl",
                "elasticloadbalancing:ModifyListener",
                "elasticloadbalancing:AddListenerCertificates",
                "elasticloadbalancing:RemoveListenerCertificates",
                "elasticloadbalancing:ModifyRule",
                "elasticloadbalancing:SetRulePriorities"
            ],
            "Resource": "*"
        }
    ]
  })

  tags = local.tags
}

# IAM Role for AWS Load Balancer Controller Service Account (IRSA)
data "aws_iam_policy_document" "aws_load_balancer_controller_irsa_assume_role_policy" {
  count = var.install_aws_load_balancer_controller ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_eks_cluster.main.identity[0].oidc[0].provider]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_eks_cluster.main.identity[0].oidc[0].issuer, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:${var.aws_load_balancer_controller_service_account_name}"]
    }
  }
}

resource "aws_iam_role" "aws_load_balancer_controller_irsa_role" {
  count = var.install_aws_load_balancer_controller ? 1 : 0

  name_prefix        = "${var.cluster_name}-ALBCtrlIRSA-"
  assume_role_policy = data.aws_iam_policy_document.aws_load_balancer_controller_irsa_assume_role_policy[0].json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "aws_load_balancer_controller_irsa_policy_attachment" {
  count = var.install_aws_load_balancer_controller ? 1 : 0

  role       = aws_iam_role.aws_load_balancer_controller_irsa_role[0].name
  policy_arn = aws_iam_policy.aws_load_balancer_controller_iam_policy[0].arn
}

# Grafana Monitoring Stack
resource "kubernetes_namespace" "grafana_ns" {
  count = var.install_grafana ? 1 : 0
  metadata {
    name = var.grafana_namespace
     labels = {
      "app.kubernetes.io/managed-by" = "Terraform"
      "name" = var.grafana_namespace
    }
  }
   lifecycle {
    prevent_destroy = false
  }
}

resource "helm_release" "grafana" {
  count = var.install_grafana ? 1 : 0

  name       = "grafana"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "grafana"
  version    = var.grafana_chart_version
  namespace  = var.grafana_namespace
  create_namespace = false

  set_sensitive {
    name  = "adminPassword"
    value = var.grafana_admin_password
  }

  values = [yamlencode({
    persistence = {
      enabled = true
      storageClassName = "gp2"
      size = "10Gi"
    }
    datasources = {
      "datasources.yaml" = {
        apiVersion = 1
        datasources = [
          {
            name = "Loki"
            type = "loki"
            url = "http://loki.${var.loki_namespace}.svc.cluster.local:3100"
            access = "proxy"
            isDefault = true
            jsonData = {}
          },
        ]
      }
    }
    testFramework = {
        enabled = false
    }
  })]

  depends_on = [
    aws_eks_node_group.final_main_node_group,
    helm_release.loki,
    kubernetes_namespace.grafana_ns[0],
  ]
}

# AWS Load Balancer Controller Helm Release
resource "helm_release" "aws_load_balancer_controller_helm_release" {
  count = var.install_aws_load_balancer_controller ? 1 : 0

  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = var.aws_load_balancer_controller_chart_version
  namespace  = "kube-system"

  values = [yamlencode({
    clusterName = var.cluster_name
    region      = data.aws_region.current.name
    vpcId       = module.vpc.vpc_id
    image = {}
    serviceAccount = {
      create = true
      name   = var.aws_load_balancer_controller_service_account_name
      annotations = {
        "eks.amazonaws.com/role-arn" = aws_iam_role.aws_load_balancer_controller_irsa_role[0].arn
      }
    }
  })]

  depends_on = [
    aws_eks_node_group.final_main_node_group,
    aws_iam_role.aws_load_balancer_controller_irsa_role[0],
    aws_eks_cluster.main,
  ]
}
