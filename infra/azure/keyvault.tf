# AKS analogue of EKS weakness 3 (broad node IAM role) and the Secrets Manager
# loot (node-iam.tf's prod/db-backup decoy). The lab Key Vault holds one
# obviously-fake decoy secret. In the BASELINE the kubelet identity (the
# AKS equivalent of the node's instance-profile role) is given an
# intentionally broad read role over this vault, standing in for "broad node
# role reads account-wide secrets" the way EKS's node_pivot policy does. In
# HARDENED, that role is removed; only the summarizer's own workload identity
# (identity.tf) can read the vault, scoped to Key Vault Secrets User.
#
# Purge protection is off on purpose (as the self-healing lab's own Key Vault):
# the lab is destroyed every session and the next one needs the name back.
resource "azurerm_key_vault" "lab" {
  #checkov:skip=CKV_AZURE_42:Purge protection off; this lab is destroyed every session.
  #checkov:skip=CKV_AZURE_109:Firewall default action is handled by network_acls below (service endpoint from the node subnet only).
  #checkov:skip=CKV2_AZURE_32:Private endpoints need Premium; this is a lab vault reached through the node subnet's service endpoint.
  #checkov:skip=CKV_AZURE_110:Purge protection off; this lab is destroyed every session (same choice as the self-healing lab's own Key Vault).
  name                       = "kv-${local.name}-${random_string.suffix.result}"
  location                   = azurerm_resource_group.lab.location
  resource_group_name        = azurerm_resource_group.lab.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
  tags                       = local.tags

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    virtual_network_subnet_ids = [azurerm_subnet.nodes.id]
  }
}

resource "azurerm_key_vault_secret" "loot" {
  #checkov:skip=CKV_AZURE_41:No expiration; this decoy is destroyed with the lab every session, not rotated.
  #checkov:skip=CKV_AZURE_114:Content type adds nothing for a single hardcoded JSON decoy; the value itself says what it is.
  name = "prod-db-backup"
  value = jsonencode({
    note     = "FAKE lab decoy, not a real credential"
    username = "svc_backup"
    password = "not-a-real-password-REPLACE-rotated-in-blue-team-step"
    host     = "db-backup.internal.lab.invalid"
  })
  key_vault_id = azurerm_key_vault.lab.id

  depends_on = [azurerm_role_assignment.operator_keyvault_admin]
}

# The operator needs write access to seed the decoy secret; the kubelet
# identity (baseline) and the summarizer identity (hardened) get read-only
# roles scoped below, never this one.
resource "azurerm_role_assignment" "operator_keyvault_admin" {
  scope                = azurerm_key_vault.lab.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
}

# BASELINE ONLY (ADR-0004 decision 3/4): the broad node-identity role. Applied
# by `make harden`'s Terraform step removing this, not by a variable, so the
# baseline/hardened split in this file matches the EKS lab's pattern of code-
# level before/after rather than a toggle var (ADR-0003 on the EKS side).
# NOTE left for the live session / code-level port: express this as an
# azurerm_role_assignment on azurerm_kubernetes_cluster.lab.kubelet_identity[0]
# scoped to azurerm_key_vault.lab, role "Key Vault Secrets User" (broad only in
# the sense that it is a node-wide identity, not scoped to one workload) --
# intentionally not wired in yet. See docs/adr/0004-aks-port.md decision 3/4
# and the TODO in app/hardened-azure/ (not yet created) for where the removal
# step belongs once the stage code lands.
