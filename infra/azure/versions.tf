terraform {
  required_version = ">= 1.10.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.12"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
  }

  # Local state on purpose, as the EKS root and the netseg lab's AKS port: one
  # deploy/demo/destroy session, torn down in the same sitting.
  backend "local" {}
}
