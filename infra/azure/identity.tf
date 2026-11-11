# Workload identity for the summarizer's hardened path (ADR-0004 decision 3).
# Federated to exactly one Kubernetes ServiceAccount, direct role assignment,
# never through a group (self-healing lab's own lesson: group membership of
# managed identities can take hours to apply).
resource "azurerm_user_assigned_identity" "summarizer" {
  name                = "id-${local.name}-summarizer"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "summarizer" {
  name                      = "fic-summarizer"
  user_assigned_identity_id = azurerm_user_assigned_identity.summarizer.id
  issuer                    = azurerm_kubernetes_cluster.lab.oidc_issuer_url
  subject                   = "system:serviceaccount:summarizer:summarizer"
  audience                  = ["api://AzureADTokenExchange"]
}

# Hardened only: read the one lab secret, nothing else.
resource "azurerm_role_assignment" "summarizer_keyvault_hardened" {
  scope                = azurerm_key_vault.lab.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.summarizer.principal_id
  principal_type       = "ServicePrincipal"
}
