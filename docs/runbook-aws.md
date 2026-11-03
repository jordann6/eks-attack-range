# Runbook: deploy, prove, demo, destroy

Authorized lab, run end to end in one sitting. Nothing hourly is left running.

## Preconditions

- AWS credentials for the sandbox account. Local operator auth is a named
  profile, same pattern as release-guard:
  `export AWS_PROFILE=<sandbox-profile>`.
- Tools: `terraform`, `aws`, `kubectl`, `docker`, `jq`, and for the kill chain
  `curl`.
- A **throwaway** Anthropic API key, created just for this run:
  `export ANTHROPIC_API_KEY=sk-ant-...`. It is the trophy and gets revoked at the
  end. Never use a key that matters.

## 1. Deploy

```bash
make deploy
```

This runs `terraform apply` scoped to your current public IP (`curl ifconfig.me`
/32, never 0.0.0.0/0), points kubectl at the cluster, builds and pushes the
summarizer image to ECR, deploys the manifests, and creates the trophy Secret
from your throwaway key. Wait for the LoadBalancer:

```bash
make url
```

## 2. Prove it is reachable

```bash
curl -s "$(make -s url)/healthz" | jq .
# {"status":"ok","key_loaded":true}
```

## 3. Demo (red team)

```bash
make demo
```

Runs `attack/killchain.sh`: recon, RCE foothold, SSRF to IMDS node creds,
lateral move into Secrets Manager, SA-token privilege escalation to cluster-admin,
and the trophy key exfil. Capture the terminal output for the write-up.

## 4. Detect (blue team)

- EKS audit log: run the CloudWatch Logs Insights queries in
  `defend/detections/eks-audit-insights.md` against
  `/aws/eks/attack-range/cluster`.
- GuardDuty: expect `InstanceCredentialExfiltration.OutsideAWS` from the stolen
  node creds, plus EKS Protection findings for the anonymous/SA activity.
- Falco (optional): install with `defend/detections/falco-rules.yaml` to see the
  runtime signals (shell in pod, IMDS contact, token read).

## 5. Remediate and re-prove

```bash
make harden   # applies defend/hardened, deletes the trophy Secret
make test     # asserts the cluster-admin binding is gone and automount is off
```

Then revoke the throwaway key in the Anthropic console and confirm:

```bash
curl -s "$(make -s url)/healthz" | jq .   # key_loaded now false
```

Re-run `make demo`: stage 4/5 return `Forbidden`, stage 2 cannot reach IMDS.

## 6. Destroy

```bash
make destroy
```

Removes the app (so the NLB is deleted before the VPC) and runs
`terraform destroy`. Confirm nothing hourly survived:

```bash
~/platform-guardrails/scripts/hourly-guard.sh   # or the tf-destroy CI check
```

EKS control plane, EC2 nodes, NAT gateway and the NLB are all hourly. If any
remain, destroy did not finish.
