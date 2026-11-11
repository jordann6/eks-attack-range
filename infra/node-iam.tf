# The broad pivot policy attached to the EC2 node role. This is WEAKNESS 3: once
# the SSRF step steals the node's instance-profile credentials from IMDS, these
# permissions are what turn a single compromised pod into account-wide secret
# theft. Read-only on purpose, so the lab demonstrates exfiltration (the realistic
# blast radius) without handing the attacker a way to alter or destroy the account.

resource "aws_iam_policy" "node_pivot" {
  name        = "${local.name}-node-pivot"
  description = "INTENTIONALLY BROAD. Lab-only lateral-movement policy on the EKS node role."

  # Scoped to this lab's own secret and parameter namespace on purpose. The
  # "broad node role" lesson still lands: a web app's node has no business
  # reading the prod/db-backup credential at all. Scoping to attack-range/* means
  # the lab is safe to run in a shared account, because the stolen creds cannot
  # reach any secret this lab did not create. A truly isolated, empty account
  # could widen Resource to "*" to demonstrate full account-wide secret theft.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadLabSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
        ]
        Resource = "arn:aws:secretsmanager:*:*:secret:${local.name}/*"
      },
      {
        Sid    = "ReadLabParameters"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath",
        ]
        Resource = "arn:aws:ssm:*:*:parameter/${local.name}/*"
      },
      {
        Sid    = "EnumerateCompute"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "sts:GetCallerIdentity",
        ]
        Resource = "*"
      },
    ]
  })

  tags = local.tags
}

# The Secrets Manager "loot" the pivot reaches: a fake production database
# credential. Reading this with the stolen node role is the lateral-movement beat
# of the kill chain (the attacker never touches the real app's key to get it).
# The value is obviously fake so nothing sensitive is ever committed or stored.
resource "aws_secretsmanager_secret" "loot" {
  name        = "${local.name}/prod/db-backup"
  description = "LAB DECOY. Fake credential used to demonstrate post-IMDS lateral movement."
  tags        = local.tags

  # No recovery window so `make destroy-plan` leaves nothing billable or lingering.
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "loot" {
  secret_id = aws_secretsmanager_secret.loot.id
  secret_string = jsonencode({
    note     = "FAKE lab decoy, not a real credential"
    username = "svc_backup"
    password = "not-a-real-password-REPLACE-rotated-in-blue-team-step"
    host     = "db-backup.internal.lab.invalid"
  })
}
