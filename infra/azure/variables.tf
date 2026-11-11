variable "subscription_id" {
  description = "Azure subscription for the lab. Lives in the gitignored lab.auto.tfvars; the provider refuses to run without it, the Azure equivalent of allowed_account_ids."
  type        = string
}

variable "location" {
  description = "Region. East US 2, where the self-healing lab and the netseg AKS port already proved AKS 1.36 in this subscription."
  type        = string
  default     = "eastus2"
}

variable "cluster_name" {
  description = "AKS cluster name and the prefix of every lab resource."
  type        = string
  default     = "attack-range"
}

variable "environment" {
  type    = string
  default = "lab"
}

variable "cost_center" {
  description = "Chargeback code, house format cc-NNNN."
  type        = string
  default     = "cc-1009"

  validation {
    condition     = can(regex("^cc-[0-9]{4}$", var.cost_center))
    error_message = "cost_center must match the house format cc-NNNN (e.g. cc-1009)."
  }
}

variable "kubernetes_version" {
  description = "AKS Kubernetes version. Confirm with kubectl version against the server before any stage runs."
  type        = string
  default     = "1.36"
}

variable "node_vm_size" {
  description = "D2s_v6 (2 vCPU, 8 GiB) on the Dsv6 quota; DSv3 is deprecated and cannot be raised. The plan-time quota check, not this default, decides whether it fits."
  type        = string
  default     = "Standard_D2s_v6"
}

variable "node_count" {
  description = "One pool, like EKS's single node group. Two nodes so Falco/platform pods and the lab app are not forced onto the same node."
  type        = number
  default     = 2
}

variable "api_authorized_cidrs" {
  description = <<-EOT
    Who may reach the public API server.

    This is a deliberately-vulnerable lab with exploitable Azure managed-identity
    credentials inside the cluster, so the control plane must not face the whole
    internet. No default, so a bare apply fails loudly; `make aks-plan` passes
    your own IPv4 /32.
  EOT
  type        = list(string)
  sensitive   = true

  validation {
    condition     = length(var.api_authorized_cidrs) > 0 && alltrue([for c in var.api_authorized_cidrs : can(cidrhost(c, 0))])
    error_message = "Give at least one valid CIDR, normally your own IPv4 /32."
  }

  validation {
    condition     = !contains(var.api_authorized_cidrs, "0.0.0.0/0")
    error_message = "Refusing 0.0.0.0/0: this lab has live stealable credentials. Scope the endpoint to your own /32."
  }
}
