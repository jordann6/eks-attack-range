terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Local state on purpose. This lab is a throwaway deploy/demo/destroy exercise
  # that runs in an isolated workload account with no shared state bucket, and is
  # fully torn down at the end. The state holds only lab resources and a fake
  # decoy secret value, never a real credential (the trophy key is injected with
  # kubectl, not Terraform), so there is nothing to protect in a remote backend.
  # A longer-lived deployment would use an S3 backend in its own account.
  backend "local" {}
}

provider "aws" {
  region = var.region

  # Keys are PascalCase deliberately, identical to local.tags, so a module call
  # cannot split a cost report into "Owner"/"owner". CostCenter in default_tags
  # is what satisfies the shared FinOps allocation gate for module-created
  # resources that static analysis cannot see.
  default_tags {
    tags = {
      Project     = "eks-attack-range"
      Environment = var.environment
      Owner       = "jordann6"
      ManagedBy   = "terraform"
      CostCenter  = var.cost_center
    }
  }
}
