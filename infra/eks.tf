# Deliberately-vulnerable EKS cluster. Every weakness below is intentional and
# has a one-line hardened counterpart in aws-landing-zone/workload/eks.tf. The
# README carries the full before/after table. Control-plane audit logging stays
# ON on purpose: the blue-team half of the lab reads the attack back out of it.
#
#   WEAKNESS                         HARDENED COUNTERPART (paved road)
#   public endpoint (scoped to /32)  private endpoint over SSM port-forward
#   IMDSv1 reachable, hop limit 2    IMDSv2 required, hop limit 1
#   broad node IAM role              minimal node role + IRSA per workload
#   no etcd KMS encryption           encryption_config over the secrets resource
#   (no admission control)           PodSecurity restricted + Kyverno enforce

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.31"

  cluster_name    = local.name
  cluster_version = var.cluster_version

  # WEAKNESS 1: public control plane. Scoped to a single /32 by variable (the
  # module default of 0.0.0.0/0 is refused in variables.tf) because the cluster
  # holds live stealable credentials. Still a public endpoint, which is the
  # finding; the paved road is private-only.
  cluster_endpoint_public_access       = true
  cluster_endpoint_public_access_cidrs = var.cluster_public_access_cidrs

  # Caller gets cluster-admin so bootstrap works without aws-auth juggling.
  authentication_mode                      = "API_AND_CONFIG_MAP"
  enable_cluster_creator_admin_permissions = true

  # Blue-team evidence source. Keep this on, it is how the attack is detected.
  cluster_enabled_log_types = ["api", "audit", "authenticator"]

  # WEAKNESS 4 (by omission): no encryption_config block, so Kubernetes Secrets
  # sit unencrypted in etcd. The trophy key is one `kubectl get secret -o yaml`
  # away. The paved road envelope-encrypts the secrets resource with a CMK.

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_groups = {
    default = {
      instance_types = [var.node_instance_type]
      min_size       = 1
      max_size       = var.node_desired_size + 1
      desired_size   = var.node_desired_size
      capacity_type  = "ON_DEMAND"

      # WEAKNESS 2: IMDSv1 is reachable (http_tokens optional) and the hop limit
      # of 2 lets a pod one hop away from the node reach 169.254.169.254 and read
      # the node role credentials. This is the SSRF-to-IMDS pivot. The paved road
      # sets http_tokens = "required" and http_put_response_hop_limit = 1.
      metadata_options = {
        http_endpoint               = "enabled"
        http_tokens                 = "optional"
        http_put_response_hop_limit = 2
      }

      # WEAKNESS 3: the node role carries a broad pivot policy on top of the
      # baseline worker policies. Credentials stolen via IMDS can then read every
      # Secrets Manager secret and SSM parameter in the account. The paved road
      # keeps the node role minimal and hands workloads scoped IRSA roles.
      iam_role_additional_policies = {
        lab_pivot = aws_iam_policy.node_pivot.arn
      }
    }
  }

  tags = local.tags
}
