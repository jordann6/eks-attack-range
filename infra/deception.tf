# Deception layer (ADR-0005). Three planted credentials, caught from two
# telemetry sources, alerted by one Lambda, contained by an in-cluster responder.
#
#   D1  AWS access key on a zero-policy IAM user, mounted into the summarizer pod.
#       CloudTrail -> EventBridge (ALL management events) -> alert Lambda.
#   D3  Secret prod-db-backup-creds, read by name with a ServiceAccount token.
#   D4  ServiceAccount backup-operator, any request with its token.
#       EKS audit log -> CloudWatch Logs subscription filter -> alert Lambda.
#
# The alert Lambda writes alerts/<decoy>/<day>.json (create-only, the dedupe)
# and publishes to SNS. The responder in the cluster reads that record, labels
# the attributed pod, and the quarantine NetworkPolicy cuts it off.
#
# The D1 key itself is NOT declared here. platform-guardrails denies
# aws_iam_access_key (a long-lived key in state), so `make decoys` mints it with
# `aws iam create-access-key` and `make destroy-plan` deletes it. The same
# pattern as the canary trophy (ADR-0002, ADR-0003), and the secret never lands
# in state.
#
# Nothing an attacker can see is named decoy or honey. AccessDenied messages and
# sts:GetCallerIdentity both echo the user ARN to the caller.

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  # Outside the node pivot policy's ssm:/attack-range/* scope on purpose: an
  # attacker holding the stolen node role must not be able to read the map and
  # learn which key is the trap.
  credential_map_prefix = "/ir/credential-map"

  decoy_secret_name = "prod-db-backup-creds"
  decoy_sa_username = "system:serviceaccount:summarizer:backup-operator"
  responder_sa      = "system:serviceaccount:security-tools:incident-responder"
}

# --- D1: the IAM user behind the planted key --------------------------------

resource "aws_iam_user" "decoy" {
  #checkov:skip=CKV_AWS_273:The planted credential must be a long-lived IAM user key, the thing an intruder expects in .aws/credentials. The user holds zero permissions.
  name          = var.decoy_user_name
  force_destroy = true # also removes the make-minted key if destroy-plan's delete was skipped
}

# No policy attachments, inline policies or group memberships, on purpose.
# Every call except sts:GetCallerIdentity is AccessDenied, and every call is in
# CloudTrail. `make verify-decoys` checks the user stays at zero.

# A rule in plain ENABLED never matches read-only calls such as
# GetCallerIdentity, the first thing anyone does with a found key. This state
# also needs a trail logging management events (`make verify-decoys` checks).
resource "aws_cloudwatch_event_rule" "decoy_key_used" {
  name        = "${local.name}-credential-used"
  description = "Any API call signed by a key of the planted backup user"
  state       = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"

  # User name, not access key id: the key is minted after apply, so its id is
  # unknown at plan time. The user has exactly one key, so the match is exact.
  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        userName = [aws_iam_user.decoy.name]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "decoy_key_used" {
  rule = aws_cloudwatch_event_rule.decoy_key_used.name
  arn  = aws_lambda_function.credential_alert.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.credential_alert.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.decoy_key_used.arn
}

# --- D3 and D4: the EKS audit log ------------------------------------------

# Broad on purpose: either term sends the event to the Lambda, which applies the
# exact, unit-tested rules (a ServiceAccount caller for D3, never the operator's
# own kubectl apply, never kube-system). Payload is base64 gzip JSON;
# CONTROL_MESSAGE records are reachability checks and never detections.
resource "aws_cloudwatch_log_subscription_filter" "audit_decoys" {
  name            = "${local.name}-credential-audit"
  log_group_name  = module.eks.cloudwatch_log_group_name
  filter_pattern  = "{ ($.user.username = \"${local.decoy_sa_username}\") || ($.objectRef.name = \"${local.decoy_secret_name}\") }"
  destination_arn = aws_lambda_function.credential_alert.arn

  depends_on = [aws_lambda_permission.cloudwatch_logs]
}

resource "aws_lambda_permission" "cloudwatch_logs" {
  statement_id   = "AllowCloudWatchLogs"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.credential_alert.function_name
  principal      = "logs.amazonaws.com"
  source_arn     = "${module.eks.cloudwatch_log_group_arn}:*"
  source_account = local.account_id
}

# --- alert Lambda -----------------------------------------------------------

data "archive_file" "credential_alert" {
  type        = "zip"
  output_path = "${path.module}/../build/credential_alert.zip"

  source {
    content  = file("${path.module}/../deception/alert/credential_alert.py")
    filename = "credential_alert.py"
  }
}

resource "aws_lambda_function" "credential_alert" {
  #checkov:skip=CKV_AWS_116:No DLQ. Both sources retry on their own (EventBridge async retries, CloudWatch Logs redelivery), and a lost alert shows up as "missed" in stage 6.
  #checkov:skip=CKV_AWS_117:Not in the VPC on purpose. It needs only S3, SNS and SSM, and keeping it out of the VPC is what avoids the private endpoint work (ADR-0005).
  #checkov:skip=CKV_AWS_173:The environment holds names and ARNs only, no secret.
  #checkov:skip=CKV_AWS_272:Lab function deployed from this repo by Terraform; code signing is out of scope for a one-session lab.
  #checkov:skip=CKV_AWS_115:A burst of attacker calls is deduped by the create-only S3 put; capping concurrency would only delay the first alert.
  function_name    = "${local.name}-credential-alert"
  description      = "Alert on use of a planted credential and record it for the in-cluster responder"
  role             = aws_iam_role.credential_alert.arn
  runtime          = "python3.12"
  handler          = "credential_alert.handler"
  filename         = data.archive_file.credential_alert.output_path
  source_code_hash = data.archive_file.credential_alert.output_base64sha256
  timeout          = 30
  memory_size      = 128

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      BUCKET          = aws_s3_bucket.ir_events.bucket
      TOPIC_ARN       = aws_sns_topic.ir_alerts.arn
      MAP_PREFIX      = local.credential_map_prefix
      DECOY_USER      = aws_iam_user.decoy.name
      DECOY_SECRET    = local.decoy_secret_name
      DECOY_SA        = local.decoy_sa_username
      DECOY_NAMESPACE = "summarizer"
    }
  }

  depends_on = [aws_cloudwatch_log_group.credential_alert]
}

resource "aws_cloudwatch_log_group" "credential_alert" {
  #checkov:skip=CKV_AWS_158:Lambda log lines hold event ids and names, no secret; the AWS-managed key is enough for a lab.
  #checkov:skip=CKV_AWS_338:Kept 14 days, the length of the evidence window; a year of retention would only add cost.
  name              = "/aws/lambda/${local.name}-credential-alert"
  retention_in_days = 14
}

resource "aws_iam_role" "credential_alert" {
  name = "${local.name}-credential-alert"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "credential_alert_logs" {
  role       = aws_iam_role.credential_alert.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "credential_alert_xray" {
  role       = aws_iam_role.credential_alert.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy" "credential_alert" {
  name = "credential-alert"
  role = aws_iam_role.credential_alert.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.ir_events.arn}/alerts/*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.ir_alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.ir.arn
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = "arn:aws:ssm:${var.region}:${local.account_id}:parameter${local.credential_map_prefix}/*"
      },
    ]
  })
}

# --- alert records and notification ----------------------------------------

# One customer managed key for the alert bucket and topic. Pennies for a
# one-session lab, and destroy leaves it in the 7-day deletion window.
resource "aws_kms_key" "ir" {
  description             = "${local.name} credential alert records and topic"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountAdmin"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

resource "aws_kms_alias" "ir" {
  name          = "alias/${local.name}-ir"
  target_key_id = aws_kms_key.ir.key_id
}

resource "aws_s3_bucket" "ir_events" {
  #checkov:skip=CKV_AWS_18:Holds a handful of small alert records for one session; access logging would cost more than the data.
  #checkov:skip=CKV_AWS_144:Single-region lab, destroyed after the session.
  #checkov:skip=CKV_AWS_21:Versioning off on purpose: `make decoys-rearm` deletes the day's records so the second attacker order is a fresh detection, and the create-only put is the dedupe.
  #checkov:skip=CKV2_AWS_62:The responder polls; event notifications are not needed.
  bucket        = "${local.name}-ir-events-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "ir_events" {
  bucket                  = aws_s3_bucket.ir_events.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "ir_events" {
  bucket = aws_s3_bucket.ir_events.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ir_events" {
  bucket = aws_s3_bucket.ir_events.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.ir.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "ir_events" {
  bucket = aws_s3_bucket.ir_events.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "ir_events" {
  bucket = aws_s3_bucket.ir_events.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "TLSOnly"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.ir_events.arn, "${aws_s3_bucket.ir_events.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_sns_topic" "ir_alerts" {
  name              = "${local.name}-ir-alerts"
  kms_master_key_id = aws_kms_key.ir.arn
}

resource "aws_sns_topic_subscription" "ir_alerts_email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.ir_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- the in-cluster responder's AWS identity (IRSA) -------------------------

resource "aws_iam_role" "responder" {
  name = "${local.name}-incident-responder"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = module.eks.oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${module.eks.oidc_provider}:sub" = local.responder_sa
          "${module.eks.oidc_provider}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "responder" {
  name = "incident-responder"
  role = aws_iam_role.responder.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = ["s3:ListBucket"]
        Resource  = aws_s3_bucket.ir_events.arn
        Condition = { StringLike = { "s3:prefix" = ["alerts/*", "quarantine/*"] } }
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.ir_events.arn}/alerts/*", "${aws_s3_bucket.ir_events.arn}/quarantine/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.ir_events.arn}/quarantine/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.ir.arn
      },
    ]
  })
}
