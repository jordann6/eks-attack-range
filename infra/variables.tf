variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment, tagged onto every resource for cost allocation."
  type        = string
  default     = "lab"
}

variable "cluster_name" {
  description = "EKS cluster name."
  type        = string
  default     = "attack-range"
}

variable "cost_center" {
  description = "Chargeback code, house format cc-NNNN, stamped on every resource via default_tags so the shared FinOps gate can allocate the spend."
  type        = string
  default     = "cc-1009"

  validation {
    condition     = can(regex("^cc-[0-9]{4}$", var.cost_center))
    error_message = "cost_center must match the house format cc-NNNN (e.g. cc-1009)."
  }
}

variable "cluster_public_access_cidrs" {
  description = <<-EOT
    CIDRs allowed to reach the public EKS API endpoint.

    This is a deliberately-vulnerable lab with exploitable IAM credentials inside
    the cluster, so the control plane must NOT face the whole internet. The
    default here is intentionally a non-routable placeholder so a bare apply
    fails loudly rather than exposing the lab. `make deploy` passes your own /32
    automatically:

      terraform apply -var='cluster_public_access_cidrs=["'"$(curl -4 -s ifconfig.me)"'/32"]'
  EOT
  type        = list(string)
  default     = ["192.0.2.1/32"] # TEST-NET-1, non-routable: forces an explicit value

  validation {
    condition     = !contains(var.cluster_public_access_cidrs, "0.0.0.0/0")
    error_message = "Refusing 0.0.0.0/0: this lab has live stealable credentials. Scope the endpoint to your own /32."
  }
}

variable "cluster_version" {
  description = "EKS Kubernetes version."
  type        = string
  default     = "1.36"
}

variable "node_instance_type" {
  description = "Instance type for the managed node group (EC2 workers)."
  type        = string
  default     = "t3.medium"
}

variable "node_desired_size" {
  description = "Desired number of EC2 worker nodes. Two t3.medium is enough for the app plus Falco; drop to one to shave cost."
  type        = number
  default     = 2
}

variable "vpc_cidr" {
  description = "CIDR block for the lab VPC."
  type        = string
  default     = "10.0.0.0/16"
}
