# network_policy is unset because the CNI is brought by the lab: the pinned
# Cilium enforces the metadata-deny control (ADR-0004 decision 2).
#trivy:ignore:AVD-AZU-0043
resource "azurerm_kubernetes_cluster" "lab" {
  #checkov:skip=CKV_AZURE_170:Free tier for a bounded lab session; no SLA needed.
  #checkov:skip=CKV_AZURE_172:The Secrets Store CSI driver is not used; ESO-style sync is out of scope for this lab.
  #checkov:skip=CKV_AZURE_115:Public API server limited to the operator's /32 by authorized IP ranges, as on EKS.
  #checkov:skip=CKV_AZURE_6:Authorized ranges come from var.api_authorized_cidrs, which has no default, so a directory scan sees no ranges.
  #checkov:skip=CKV_AZURE_7:Bring your own CNI; the pinned Cilium enforces the metadata deny (ADR-0004).
  #checkov:skip=CKV2_AZURE_29:Bring your own CNI on purpose, the same Cilium as the netseg AKS port.
  #checkov:skip=CKV_AZURE_117:Encryption at host with platform-managed keys; no customer-managed key in this lab.
  #checkov:skip=CKV_AZURE_116:Azure Policy for Kubernetes is not part of the experiment.
  #checkov:skip=CKV_AZURE_171:No upgrade channel, so the control plane and nodes cannot change mid-run.
  #checkov:skip=CKV_AZURE_4:Container Insights is not used; Falco is the runtime detector under test (ADR-0004 decision 5).
  #checkov:skip=CKV_AZURE_226:Managed OS disks.
  #checkov:skip=CKV_AZURE_232:One pool by design (EKS has a single node group too); Falco and the app share it on purpose so Falco sees the attacked pod's node.
  name                = local.name
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  node_resource_group = local.node_resource_group
  dns_prefix          = local.name
  kubernetes_version  = var.kubernetes_version
  sku_tier            = "Free"
  tags                = local.tags

  # Workload identity (ADR-0004 decision 3): federated to one SA for the
  # hardened path. The baseline leaves the summarizer unfederated so it falls
  # back to the kubelet identity's broad Key Vault role (the AKS analogue of
  # EKS weakness 3, the broad node IAM role).
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  local_account_disabled            = true
  role_based_access_control_enabled = true
  azure_active_directory_role_based_access_control {
    azure_rbac_enabled = true
    tenant_id          = data.azurerm_client_config.current.tenant_id
  }

  node_os_upgrade_channel = "None"
  run_command_enabled     = true
  azure_policy_enabled    = false

  node_provisioning_profile {
    mode = "Manual"
  }

  api_server_access_profile {
    authorized_ip_ranges = var.api_authorized_cidrs
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.control_plane.id]
  }

  network_profile {
    network_plugin    = "none"
    load_balancer_sku = "standard"
    outbound_type     = "loadBalancer"
    load_balancer_profile {
      managed_outbound_ip_count = 1
    }
  }

  default_node_pool {
    name                        = "default"
    vm_size                     = var.node_vm_size
    node_count                  = var.node_count
    vnet_subnet_id              = azurerm_subnet.nodes.id
    max_pods                    = 60
    os_disk_type                = "Managed"
    os_disk_size_gb             = 64
    host_encryption_enabled     = true
    node_public_ip_enabled      = false
    temporary_name_for_rotation = "dtmp"
    upgrade_settings {
      max_surge = "1"
      # A stranded pod must not hang the destroy forever (the self-healing lab
      # lost about 45 minutes to this, and the netseg AKS port hit the same
      # trap on 2026-11-11: Cilium must stay installed until the cluster goes,
      # see docs/adr note once this port's own live session confirms it).
      drain_timeout_in_minutes = 10
    }
    tags = local.tags
  }

  depends_on = [
    azurerm_role_assignment.control_plane_subnet,
    azurerm_subnet_network_security_group_association.nodes,
  ]
}

resource "azurerm_user_assigned_identity" "control_plane" {
  name                = "id-${local.name}-aks"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags
}

resource "azurerm_role_assignment" "control_plane_subnet" {
  scope                = azurerm_subnet.nodes.id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_user_assigned_identity.control_plane.principal_id
  principal_type       = "ServicePrincipal"
}

# --- image --------------------------------------------------------------- #

resource "azurerm_container_registry" "lab" {
  #checkov:skip=CKV_AZURE_237:Dedicated data endpoints need Premium; Basic for a lab registry.
  #checkov:skip=CKV_AZURE_233:Zone redundancy needs Premium; Basic for a lab registry.
  #checkov:skip=CKV_AZURE_167:Retention policies need Premium; the registry is destroyed with the lab.
  #checkov:skip=CKV_AZURE_164:Content trust needs Premium; images are built from this repo at a pinned git SHA.
  #checkov:skip=CKV_AZURE_165:One region, one session; no geo-replication.
  #checkov:skip=CKV_AZURE_166:Image quarantine needs Premium; images are built from this repo at a pinned git SHA.
  #checkov:skip=CKV_AZURE_163:Registry scanning is not part of the experiment.
  #checkov:skip=CKV_AZURE_139:Private endpoints need Premium; pulls authenticate with the kubelet identity, admin user off.
  name                          = "acr${local.name_nodash}${random_string.suffix.result}"
  location                      = azurerm_resource_group.lab.location
  resource_group_name           = azurerm_resource_group.lab.name
  sku                           = "Basic"
  admin_enabled                 = false
  anonymous_pull_enabled        = false
  public_network_access_enabled = true
  tags                          = local.tags
}

resource "azurerm_role_assignment" "kubelet_acr_pull" {
  scope                = azurerm_container_registry.lab.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_kubernetes_cluster.lab.kubelet_identity[0].object_id
  principal_type       = "ServicePrincipal"
}

# --- the operator (whoever runs terraform with az login) ----------------- #

resource "azurerm_role_assignment" "operator_cluster_user" {
  scope                = azurerm_kubernetes_cluster.lab.id
  role_definition_name = "Azure Kubernetes Service Cluster User Role"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "operator_cluster_admin" {
  scope                = azurerm_kubernetes_cluster.lab.id
  role_definition_name = "Azure Kubernetes Service RBAC Cluster Admin"
  principal_id         = data.azurerm_client_config.current.object_id
}
