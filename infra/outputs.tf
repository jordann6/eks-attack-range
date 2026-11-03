output "cluster_name" {
  description = "EKS cluster name."
  value       = module.eks.cluster_name
}

output "region" {
  description = "AWS region."
  value       = var.region
}

output "configure_kubectl" {
  description = "Command to point local kubeconfig at this cluster."
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

output "ecr_repository_url" {
  description = "Push the summarizer image here."
  value       = aws_ecr_repository.app.repository_url
}

output "node_role_name" {
  description = "EC2 node role name. Blue team watches CloudTrail for this principal using stolen IMDS creds."
  value       = module.eks.eks_managed_node_groups["default"].iam_role_name
}

output "loot_secret_arn" {
  description = "Secrets Manager decoy reachable via the stolen node role (lateral-movement target)."
  value       = aws_secretsmanager_secret.loot.arn
}

output "oidc_provider_arn" {
  description = "Cluster OIDC provider ARN. The blue-team fix wires workloads to IRSA through this instead of the node role."
  value       = module.eks.oidc_provider_arn
}
