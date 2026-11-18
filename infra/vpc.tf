# Pinned by name (checkov CKV_AWS_394) so the set cannot grow when AWS adds a
# zone. These are the same two zones the slice below always picked: the first
# two names in sorted order. If a lab account's mapping makes one of them a
# zone EKS does not support, change the list here, not the slice.
data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "zone-name"
    values = ["${var.region}a", "${var.region}b"]
  }
}

locals {
  name = var.cluster_name
  azs  = slice(data.aws_availability_zones.available.names, 0, 2)

  # Must match the provider default_tags casing exactly, or module-created
  # resources get both "Project" and "project".
  tags = {
    Project     = "eks-attack-range"
    Environment = var.environment
    Owner       = "jordann6"
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${local.name}-vpc"
  cidr = var.vpc_cidr
  azs  = local.azs

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]

  # Single NAT keeps the hourly footprint small for a throwaway lab.
  enable_nat_gateway = true
  single_nat_gateway = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = local.tags
}
