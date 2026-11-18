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

output "ir_events_bucket" {
  description = "Alert and quarantine records (alerts/<decoy>/<day>.json, quarantine/<decoy>/<day>.json)."
  value       = aws_s3_bucket.ir_events.bucket
}

output "decoy_user_name" {
  description = "IAM user behind the planted D1 key. `make decoys` mints its one key."
  value       = aws_iam_user.decoy.name
}

output "credential_map_prefix" {
  description = "SSM prefix mapping a planted key id to the namespace/Secret it was mounted from."
  value       = local.credential_map_prefix
}

output "responder_role_arn" {
  description = "IRSA role for the in-cluster incident responder."
  value       = aws_iam_role.responder.arn
}

output "credential_rule_name" {
  description = "EventBridge rule that catches D1 use."
  value       = aws_cloudwatch_event_rule.decoy_key_used.name
}

output "cluster_log_group" {
  description = "EKS control-plane log group the audit subscription filter reads."
  value       = module.eks.cloudwatch_log_group_name
}
