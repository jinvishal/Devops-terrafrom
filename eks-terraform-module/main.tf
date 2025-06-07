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
}

# Data sources
data "aws_region" "current" {}

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
    subnet_ids = module.vpc.private_subnet_ids
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

# ECR Repository, S3 Bucket, WAF - unchanged from previous steps, ensure they are here

resource "aws_ecr_repository" "app_ecr_repo" {
  name                 = local.ecr_repo_name_default
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "AES256" }
  tags = local.tags
}

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
  create_namespace = true # kube-system should exist, but this is safe

  values = [yamlencode({
    args = [
      "--kubelet-insecure-tls",
      "--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname",
      "--kubelet-use-node-status-port" # Added for some environments
    ]
    # replicas = 2 # Consider for HA
  })]

  depends_on = [aws_eks_node_group.final_main_node_group] # Ensure nodes are ready
}

# Loki Logging Stack
resource "kubernetes_namespace" "loki_ns" {
  count = var.install_loki ? 1 : 0
  metadata {
    name = var.loki_namespace
    labels = {
      "app.kubernetes.io/managed-by" = "Terraform"
      "name" = var.loki_namespace # Label for easier identification
    }
  }
  lifecycle { # Prevent accidental deletion if something else adopts it
    prevent_destroy = false
  }
}

resource "helm_release" "loki" {
  count = var.install_loki ? 1 : 0

  name       = "loki"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "loki" # This is the simple scalable chart, formerly loki-simple-scalable
  version    = var.loki_chart_version
  namespace  = var.loki_namespace
  create_namespace = false # Using explicit kubernetes_namespace resource

  values = [templatefile("${path.module}/loki_values.yaml.tpl", {
    s3_bucket_name = local.loki_s3_actual_bucket_name
    s3_region      = data.aws_region.current.name
    s3_enabled     = var.install_loki_s3_backend
  })]

  depends_on = [
    aws_eks_node_group.final_main_node_group,
    kubernetes_namespace.loki_ns[0], # Ensure namespace exists
    aws_s3_bucket.general_s3_bucket, # Ensure bucket exists if used for Loki
  ]
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
  create_namespace = false # Using explicit kubernetes_namespace resource

  # Values for Grafana
  # Note: For complex structures like datasources, it's often better to use a values file
  # or multiple `set` blocks with careful quoting if needed.
  # The `set` block doesn't merge deeply, subsequent sets for the same top key overwrite.
  # Using `set_sensitive` for adminPassword.

  set_sensitive {
    name  = "adminPassword"
    value = var.grafana_admin_password
  }

  # Configure Loki Datasource
  # The structure for datasources in Grafana chart can be tricky.
  # It usually expects a YAML string under `datasources."datasources.yaml".datasources`
  # or structured input. The `set` commands below attempt structured input.
  # Refer to the Grafana chart's values.yaml for the exact structure.
  # Example assumes a `datasources.yaml` key under `datasources`:
  values = [yamlencode({
    persistence = {
      enabled = true
      storageClassName = "gp2" # Standard EBS, consider making this configurable (e.g. var.grafana_storage_class)
      size = "10Gi"
    }
    # ingress = {
    #   enabled = true
    #   # hosts = ["grafana.example.com"] # Configure with your domain
    # }
    # serviceMonitor = { # If using Prometheus Operator
    #   enabled = true
    # }
    datasources = {
      "datasources.yaml" = { # This key structure is common
        apiVersion = 1
        datasources = [
          {
            name = "Loki"
            type = "loki"
            url = "http://loki.${var.loki_namespace}.svc.cluster.local:3100" # Assumes Loki service name & port
            access = "proxy" # Server-side access
            isDefault = true
            jsonData = { # Chart version 6.x+ might use this for some settings
              # tlsSkipVerify = true # if using self-signed certs internally
            }
          },
          # Example for Prometheus (if you install it later)
          # {
          #   name = "Prometheus"
          #   type = "prometheus"
          #   url = "http://prometheus-server.prometheus.svc.cluster.local" # Adjust to your Prometheus service
          #   access = "proxy"
          # }
        ]
      }
    }
    # Grafana image tag can be set if needed: grafana.image.tag
    # Sidecar for dashboards/datasources: grafana.sidecar.*
    # Test framework: grafana.testFramework.enabled = false (to speed up deployment)
    testFramework = { # For chart versions around 7.x for Grafana
        enabled = false
    }
  })]

  depends_on = [
    aws_eks_node_group.final_main_node_group,
    helm_release.loki, # Grafana depends on Loki for its datasource
    kubernetes_namespace.grafana_ns[0],
  ]
}
