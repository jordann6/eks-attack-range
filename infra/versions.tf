terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Reuses the shared state bucket. A dedicated key keeps this lab's state
  # isolated from the fleet. The bucket is the same one every portfolio root
  # uses; swap it if you run this in a different account.
  backend "s3" {
    bucket       = "tf-state-jordprojs"
    key          = "eks-attack-range/lab.terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true
    encrypt      = true
  }
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
