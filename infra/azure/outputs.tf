output "cluster_name" {
  value = azurerm_kubernetes_cluster.lab.name
}

output "resource_group" {
  value = azurerm_resource_group.lab.name
}

output "node_resource_group" {
  value = local.node_resource_group
}

output "configure_kubectl" {
  value = "az aks get-credentials --resource-group ${azurerm_resource_group.lab.name} --name ${azurerm_kubernetes_cluster.lab.name} --context attack-range-aks --overwrite-existing && kubelogin convert-kubeconfig -l azurecli"
}

output "acr_name" {
  value = azurerm_container_registry.lab.name
}

output "acr_login_server" {
  value = azurerm_container_registry.lab.login_server
}

output "key_vault_name" {
  value = azurerm_key_vault.lab.name
}

output "summarizer_identity_client_id" {
  description = "For the hardened ServiceAccount's azure.workload.identity/client-id annotation."
  value       = azurerm_user_assigned_identity.summarizer.client_id
}
