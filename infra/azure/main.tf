# AKS attack range (ADR-0004, design level). Weakness/fix table mirrors the EKS
# README (docs/adr/0004-aks-port.md decision 1):
#
#   WEAKNESS                           HARDENED COUNTERPART
#   public endpoint (scoped to /32)    private endpoint
#   managed-identity reachable from    pod egress policy denying IMDS
#     pods (no AWS-style hop limit)
#   broad kubelet-identity role        no kubelet role on Key Vault; workload
#     over a lab Key Vault               identity federated to one SA
#   cluster-admin SA + token automount least-privilege RBAC, automount off
#   plaintext key Secret               workload identity, no key in the pod
#
# Bring your own egress policy engine: managed Cilium dataplane (no ACNS add-on
# needed for an L3/L4-only deny), unlike the netseg lab's BYO Cilium (ADR-0006
# needs L7/DNS parity with kind and EKS; this lab only needs the metadata deny).

provider "azurerm" {
  subscription_id = var.subscription_id

  resource_provider_registrations = "none"

  features {
    key_vault {
      # Soft-deleted vault names cannot be reused for the retention period. The
      # lab vault has no purge protection, so the destroy purges it and the
      # next session can recreate it under the same name pattern.
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = false
    }
    resource_group {
      # Fail closed: a destroy that finds something Terraform did not create in
      # the lab group stops instead of deleting it.
      prevent_deletion_if_contains_resources = true
    }
  }
}

data "azurerm_client_config" "current" {}

locals {
  name = var.cluster_name

  tags = {
    Project     = "eks-attack-range"
    Environment = var.environment
    Owner       = "jordann6"
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
  }

  node_resource_group = "rg-${local.name}-nodes"
  name_nodash         = replace(local.name, "-", "")

  vnet_cidr  = "10.60.0.0/16"
  nodes_cidr = "10.60.0.0/22"
}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_virtual_network" "lab" {
  name                = "vnet-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  address_space       = [local.vnet_cidr]
  tags                = local.tags
}

resource "azurerm_subnet" "nodes" {
  name                 = "snet-${local.name}-nodes"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = [local.nodes_cidr]

  service_endpoint {
    service = "Microsoft.KeyVault"
  }
}

resource "azurerm_network_security_group" "nodes" {
  name                = "nsg-${local.name}-nodes"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags
}

resource "azurerm_network_security_rule" "deny_remote_admin" {
  name                        = "deny-ssh-rdp-all"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["22", "3389"]
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.nodes.name
}

resource "azurerm_subnet_network_security_group_association" "nodes" {
  subnet_id                 = azurerm_subnet.nodes.id
  network_security_group_id = azurerm_network_security_group.nodes.id
}
