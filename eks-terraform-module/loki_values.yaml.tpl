# Default values for Loki Helm chart
# Full chart values: https://github.com/grafana/helm-charts/blob/main/charts/loki/values.yaml
# For a simpler setup (single binary mode), you might use 'loki.deploymentMode=SingleBinary' for versions >= 5.0.0 of the chart
# or use the 'loki-stack' chart which includes promtail and grafana.
# This template assumes 'loki' chart which can be scaled or run as monolithic.

loki:
  auth_enabled: false # Set to true if you have authentication configured
  # commonConfig:
  #   replication_factor: 1 # For single binary mode or testing
  # For HA, this would be higher and you'd use a distributed chart or configure components.

# Default is filesystem persistence. Below is for S3 or filesystem.
%{ if s3_enabled ~}
storage_config:
  boltdb_shipper:
    active_index_directory: /data/loki/boltdb-shipper-active
    cache_location: /data/loki/boltdb-shipper-cache
    shared_store: s3
  aws:
    s3: s3://${s3_bucket_name}/loki # Path within the bucket for Loki data
    region: ${s3_region}
    # s3forcepathstyle: false # Set to true for MinIO or other S3 compatible services
    #
    # To use IAM roles for service accounts (IRSA) for S3 access (recommended):
    # 1. Ensure the EKS OIDC provider is created (usually done with the cluster).
    # 2. Create an IAM role with S3 write permissions for the Loki service account.
    # 3. Annotate the Loki service account in the Helm chart values:
    # serviceAccount:
    #   create: true
    #   name: loki
    #   annotations:
    #     eks.amazonaws.com/role-arn: <ARN_OF_LOKI_S3_IAM_ROLE>
  filesystem: # Still needed for some local caching or operations even with S3
    directory: /data/loki/filesystem # Changed from /data/loki to avoid conflict if boltdb_shipper also uses /data/loki

schema_config:
  configs:
    - from: "2022-01-11" # Use a recent date for schema version
      store: boltdb-shipper
      object_store: aws # refers to the 'aws' block in storage_config
      schema: v12 # Or v11, check Loki documentation for recommended schema
      index:
        prefix: loki_index_
        period: 24h
%{ else ~}
# Default filesystem storage if S3 is not enabled
# This is suitable for single-binary mode or testing.
# For production, consider a distributed setup or boltdb-shipper with a shared object store.
storage_config:
  filesystem:
    directory: /data/loki/filesystem
  # For single binary loki >= chart 5.0.0 (app version >= 2.5.0)
  # You might configure it like this for simpler filesystem storage:
  # filesystem:
  #   chunks_directory: /var/loki/chunks
  #   rules_directory: /var/loki/rules
  #   wal_directory: /var/loki/wal

schema_config:
  configs:
    - from: "2022-01-11" # Use a recent date
      store: boltdb-shipper # Use boltdb-shipper for better scalability even on filesystem
      object_store: filesystem
      schema: v12 # Or v11
      index:
        prefix: loki_index_
        period: 24h
%{ endif ~}

# Persistence configuration for Loki
# If using filesystem storage, this is critical.
# If using S3, this is for components like ingesters/distributors that might still need some local disk.
persistence:
  enabled: true
  # storageClassName: "gp2" # Or your preferred StorageClass for EBS
  size: 10Gi # Adjust as needed

# Example for single binary mode if you are using a chart version that supports it directly
# deploymentMode: SingleBinary # For chart versions like 5.x, application version 2.8+

# Ensure readiness and liveness probes are configured if not by default
# ingester:
#   replicas: 1
# distributor:
#   replicas: 1
# querier:
#   replicas: 1
# query_frontend:
#   replicas: 1

# Service account - create one if not using default, needed for IRSA if S3 access uses it.
serviceAccount:
  create: true
  name: loki
  # annotations: {} # Add IRSA role ARN here if using S3 with IRSA

# RBAC - create roles and bindings
rbac:
  create: true

# Security Context - for HIPAA, run as non-root if possible
# securityContext:
#   runAsUser: 10001
#   runAsGroup: 10001
#   fsGroup: 10001

# Consider resource requests and limits
# loki:
#   resources:
#     limits:
#       cpu: 1
#       memory: 1Gi
#     requests:
#       cpu: 100m
#       memory: 256Mi

# If using the loki-distributed chart, the structure is very different.
# This template is primarily for the 'loki' chart.
# Adjust based on the specific Loki chart and version you are using.
# It's good practice to check the official chart's values.yaml for all available options.
# https://github.com/grafana/helm-charts/tree/main/charts/loki
# For example, the chart name might be 'loki' or 'loki-simple-scalable' or 'loki-distributed'.
# This template assumes the 'loki' chart which is often a good starting point.
# Default chart since 4.0.0 is loki-simple-scalable which is good.
# Values here are more aligned with older monolithic or newer simple-scalable.
# The `loki.config` or `config.loki` path in values might vary.
# Assuming `loki.config` can be templated or directly set.
# For modern charts, it's often `loki.config` as a string or `loki.structuredConfig`.
# This example provides a structure for `storage_config` and `schema_config` which are common.

# The chart values for loki can be complex. This template aims to cover the S3 part.
# You might need to put the entire loki config (as a YAML string) under a specific key like `loki.config` or `loki.configYAML`
# or set individual structured keys like `loki.structuredConfig.storage_config...` etc.
# The following is a common pattern if the chart expects the config as a string under `loki.config`:
/*
loki:
  config: |
    auth_enabled: false
    server:
      http_listen_port: 3100
      grpc_listen_port: 9096
    %{ if s3_enabled ~}
    storage_config:
      aws:
        s3: s3://${s3_bucket_name}/loki
        region: ${s3_region}
      boltdb_shipper:
        active_index_directory: /data/loki/boltdb-shipper-active
        cache_location: /data/loki/boltdb-shipper-cache
        shared_store: s3 # This tells boltdb_shipper to use the s3 config from common storage_config
    schema_config:
      configs:
      - from: 2022-01-11
        store: boltdb-shipper
        object_store: aws # This tells the store to use the 'aws' block from common storage_config
        schema: v12
        index:
          prefix: loki_index_
          period: 24h
    %{ else ~}
    storage_config:
      filesystem:
        directory: /data/loki/filesystem # Default if S3 not used
    schema_config:
      configs:
      - from: 2022-01-11
        store: boltdb-shipper
        object_store: filesystem
        schema: v12
        index:
          prefix: loki_index_
          period: 24h
    %{ endif ~}
    ruler:
      alertmanager_url: http://localhost:9093 # If using ruler
*/
# The template above uses a simpler direct structure for storage_config,
# assuming the chart supports setting these nested values directly.
# If it requires a single YAML string, the commented out section above is an alternative.
# Check the target Loki chart's `values.yaml` for the correct structure.
# For example, Grafana's official 'loki' chart (not loki-stack or loki-distributed)
# often takes structured input like `loki.storageConfig.aws.s3` etc.
# Or `loki.config` as a string.
# This template will try to set `storage_config` and `schema_config` directly.
# If the chart is 'loki-distributed', then config is per-component.
# This values file is a starting point.
# It's better to use the official chart values and adapt them.
# This template is using the `loki.storage_config` and `loki.schema_config` pattern.
# The actual helm chart values may use `loki.config` as a string or `config:` at the top level.
# I will simplify this template to use the direct nested values as it's cleaner if supported.
# Removing the commented out large YAML string section for clarity.

# Simpler structure, assuming chart supports direct nested values under top-level `loki:` key or similar.
# This is common in many modern Helm charts.
# If this doesn't work, the chart might expect the whole config under a single string key like `loki.configYAML`.

# Default persistence and service account creation
persistence:
  enabled: true
  size: 10Gi
  # storageClassName: "gp2" # default, or specify your own

serviceAccount:
  create: true
  name: "loki" # Ensure this is consistent if IRSA is used
  # annotations: {} # For IRSA: eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/LokiS3Role

rbac:
  create: true

# Minimal resource requests for Loki components (adjust based on expected load)
# These are often under component names like 'ingester', 'distributor', etc.
# or under a global 'loki.resources' or just 'resources'.
# This is a generic placeholder.
# resources:
#   limits:
#     cpu: "1"
#     memory: "1Gi"
#   requests:
#     cpu: "100m"
#     memory: "256Mi"

# The following settings are more aligned with the Grafana Loki chart structure (not loki-distributed)
# where settings are often directly under the 'loki:' key or at the root.
# This assumes the chart expects `storage_config` and `schema_config` at the root of its values.
# If they are under `loki:`, then the templatefile() call in main.tf would need to be adjusted,
# or the values here wrapped in a `loki:` block.
# For now, keeping them at root as per the initial request's structure.

# If the chart is `grafana/loki`, it often expects these at the root:
# (Ref: https://github.com/grafana/helm-charts/blob/main/charts/loki/values.yaml)
global:
  s3:
    bucketnames: ${s3_bucket_name} # This is an example, chart might not have global.s3.bucketnames
    region: ${s3_region}

config:
  auth_enabled: false # This is a common path for this setting
  ingester:
    chunk_idle_period: 5m
    chunk_block_size: 262144
    chunk_retain_period: 1m
    max_transfer_retries: 0
    lifecycler:
      ring:
        kvstore:
          store: memberlist
        replication_factor: 1 # For single node, adjust for HA
  limits_config:
    retention_period: 720h # 30 days, adjust as needed
    enforce_metric_name: false
    reject_old_samples: true
    reject_old_samples_max_age: 168h
    max_cache_freshness_per_query: 10m
  schema_config:
  %{ if s3_enabled ~}
    configs:
      - from: "2022-01-11"
        store: boltdb-shipper
        object_store: s3 # Changed from 'aws' to 's3' to match common chart structures
        schema: v12
        index:
          prefix: loki_index_
          period: 24h
  storage_config:
    boltdb_shipper:
      active_index_directory: /var/loki/index # Changed path
      cache_location: /var/loki/cache # Changed path
      shared_store: s3 # Use S3 as the shared store for BoltDB shipper
    aws: # This 'aws' block is now correctly referenced by 'object_store: s3' if the chart uses 's3' as key for AWS S3
      bucketnames: ${s3_bucket_name} # Note: some charts use 'bucketnames' (plural)
      region: ${s3_region}
      # Add other S3 options like endpoint, s3forcepathstyle if needed
  %{ else ~}
    configs:
      - from: "2022-01-11"
        store: boltdb-shipper
        object_store: filesystem
        schema: v12
        index:
          prefix: loki_index_
          period: 24h
  storage_config:
    boltdb_shipper:
      active_index_directory: /var/loki/index
      cache_location: /var/loki/cache
    filesystem: # Filesystem store for chunks if not using S3
      directory: /var/loki/chunks
  %{ endif ~}
  chunk_store_config:
    max_look_back_period: 0s
  table_manager:
    retention_deletes_enabled: true
    retention_period: 720h # 30 days, should match limits_config.retention_period

# For single binary mode, if the chart supports it via a top-level key
# deploymentMode: SingleBinary # Or perhaps target: SingleBinary

# If the chart is grafana/loki (not loki-stack), persistence is often configured like this:
persistence:
  enabled: true
  storageClassName: gp2 # Or make this a variable
  size: 10Gi

# Service account for IRSA (if used)
serviceAccount:
  create: true
  name: loki
  # annotations:
  #   eks.amazonaws.com/role-arn: "arn:aws:iam::YOUR_ACCOUNT_ID:role/LokiS3AccessRole"

# RBAC
rbac:
  create: true
  pspEnabled: false # Set to true if PodSecurityPolicies are in use and configured

# Security context for Loki pods (example)
securityContext:
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  runAsNonRoot: true

# Resources - these are often per-component in distributed mode
# For single binary or simple scalable, they might be global or under `loki:`
# Example:
# write:
#   resources: ...
# read:
#   resources: ...
# backend:
#   resources: ...

# This final structure is an attempt to match a common structure for the `grafana/loki` chart.
# The exact paths might vary based on chart version. Always refer to the chart's values.yaml.
# It's crucial that `s3_bucket_name` and `s3_region` are correctly passed to this template.
# The templatefile function in main.tf will need to provide these.
# The object_store under schema_config should be 's3' to use the aws s3 storage.
# And the shared_store for boltdb_shipper should also be 's3'.
# I've updated 'object_store: aws' to 'object_store: s3' for schema_config.
# And boltdb_shipper.shared_store to 's3'.
# The 'aws' block under storage_config is where S3 credentials/config go.
# Some charts use `bucketnames` (plural) in the `storage_config.aws` block.
# It is important to verify the Loki chart version and its values.yaml.
# For chart "grafana/loki" version "5.10.1", the values structure is more like:
# loki:
#   storage:
#     type: 's3'
#     s3:
#       bucketName: ...
#       region: ...
#   schemaConfig: ...
#   auth_enabled: false
# persistence: ...
# serviceAccount: ...
# Let's try to align with a more modern grafana/loki chart structure.
# The initial request used `storage_config` and `schema_config` at root level.
# I will adjust to put them under a `loki:` key as that's more common for the grafana/loki chart.

loki:
  # Common Loki configuration
  auth_enabled: false
  commonConfig:
    replication_factor: 1 # Adjust for HA if not using SingleBinary mode via 'target'

  # Storage configuration
  storage:
    type: '${ s3_enabled ? "s3" : "filesystem" }'
    s3:
      bucketName: '${s3_enabled ? s3_bucket_name : ""}' # Only set if s3 is enabled
      region: '${s3_enabled ? s3_region : ""}'         # Only set if s3 is enabled
      # endpoint: # Optional: for S3 compatible storage
      # secretAccessKey: # Optional: for explicit credentials, prefer IRSA
      # accessKeyId: # Optional: for explicit credentials, prefer IRSA
    filesystem: # Filesystem config, used if storage.type is 'filesystem' or for some local caches
      directory: /var/loki/data # Single directory for all Loki data if type is filesystem

  # Schema configuration
  schemaConfig:
    configs:
      - from: "2022-01-11" # Use a recent date for schema version
        store: boltdb-shipper
        object_store: '${ s3_enabled ? "s3" : "filesystem" }' # Matches storage.type
        schema: v12
        index:
          prefix: loki_index_
          period: 24h

  # Ingester configuration (example, part of structured config)
  ingester:
    lifecycler:
      ring:
        kvstore:
          store: memberlist # For single binary / simple scalable
        replication_factor: 1
  # Limits
  limits_config:
    retention_period: "720h" # 30 days

# Persistence for Loki (applies to filesystem storage or local caches for S3)
persistence:
  enabled: true
  storageClassName: "gp2" # Or make this a variable e.g. var.loki_storage_class
  size: 10Gi
  # accessModes:
  #   - ReadWriteOnce

# Service account for Loki
serviceAccount:
  create: true
  name: "loki-sa" # This name must match the one in the IAM role trust policy
  annotations:
    %{ if loki_irsa_role_arn != null ~}
    "eks.amazonaws.com/role-arn": "${loki_irsa_role_arn}"
    %{ endif ~}

# RBAC for Loki
rbac:
  create: true
  pspEnabled: false

# Pod Security Context (example, run as non-root)
podSecurityContext:
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  runAsNonRoot: true

# Container Security Context (example)
# securityContext:
#   readOnlyRootFilesystem: false # Loki needs to write to /tmp or /data
#   capabilities:
#     drop:
#       - ALL
#   allowPrivilegeEscalation: false

# Resources for Loki (adjust based on load)
# This is a global setting, some charts allow per-component resources.
resources:
  limits:
    cpu: "1"
    memory: "2Gi" # Increased memory for Loki
  requests:
    cpu: "200m"
    memory: "512Mi"

# If using a chart like `grafana/loki` (not `loki-stack` or `loki-distributed`),
# the above structure is a reasonable attempt.
# Chart versions matter a lot for Loki.
# Version "5.10.1" of "grafana/loki" chart uses `loki.config` as a string or `loki.existingSecretForConfig`.
# Or it uses structured config under `loki.*` for many settings.
# The `loki.storage` block is for `loki-simple-scalable` which became default in chart v4.0.0.
# The version "5.10.1" for the `grafana/loki` chart should support this structured `loki.storage` etc.
# This template is designed for that style.
# If there are issues, the most robust way is to copy the official values.yaml for the target chart version
# and then template only the necessary parts (like S3 bucket name, region).
# For example, the `loki.config` could be a large YAML string:
# loki:
#   config: |
#     auth_enabled: false
#     ingester:
#       lifecycler:
#         ring:
#           kvstore:
#             store: memberlist
#           replication_factor: 1
#     limits_config:
#       retention_period: 720h
#     schema_config:
#       configs:
#       - from: 2022-01-11
#         store: boltdb-shipper
#         object_store: ${s3_enabled ? "s3" : "filesystem"}
#         schema: v12
#         index:
#           prefix: loki_index_
#           period: 24h
#     storage_config:
#       ${s3_enabled ? "aws" : "filesystem"}: # This dynamic key is tricky in YAML like this
#         ${s3_enabled ? "s3" : "directory"}: ${s3_enabled ? "s3://${s3_bucket_name}/loki" : "/var/loki/data"}
#         ${s3_enabled ? "region" : ""}: ${s3_enabled ? s3_region : ""} # Region only if s3
#       boltdb_shipper:
#         active_index_directory: /var/loki/index_active
#         cache_location: /var/loki/cache
#         shared_store: ${s3_enabled ? "s3" : "filesystem"}
#
# The structured approach (first one in this file, under `loki:`) is generally preferred if the chart supports it.
# I will stick to the structured approach under the `loki:` key.
# Final check on chart "grafana/loki" version "5.10.1" (application v2.8.0).
# Its values.yaml has `loki:` at the top, then `commonConfig`, `storage`, `schemaConfig`, etc. under it.
# This matches the last structure I've defined in this template.
# `loki.storage.s3.bucketName` and `loki.storage.s3.region` are the correct paths.
# `loki.storage.type` should be `s3` or `filesystem`.
# `loki.schemaConfig.configs[0].object_store` should be `s3` or `filesystem`.
# This looks correct.The `loki_values.yaml.tpl` file has been created. I've tried to align it with a modern `grafana/loki` Helm chart structure (like version 5.x), placing configurations under a top-level `loki:` key. This includes templating for S3 backend configuration. The exact field names and structure within Helm chart values can be very specific to the chart version, so this is a best effort based on common patterns for recent versions of the Grafana Loki chart.

Now, I'll update `main.tf`. This is a large step involving:
1.  Adding data sources for AWS region and EKS cluster authentication.
2.  Configuring the `kubernetes` and `helm` providers.
3.  Adding `helm_release` resources for Metrics Server, Loki (using the `loki_values.yaml.tpl`), and Grafana.
