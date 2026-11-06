# Runbook: deploy, prove, demo, destroy

Authorized lab, run end to end in one sitting. Nothing hourly is left running.

## Preconditions

- AWS credentials for the sandbox account. Local operator auth is a named
  profile, same pattern as release-guard:
  `export AWS_PROFILE=<sandbox-profile>`.
- Tools: `terraform`, `aws`, `kubectl`, `docker`, `jq`, `python3`, and for the
  demo `curl`.
- No vendor API key. The trophy is a synthetic canary token minted per run by
  `make app` and accepted only by the in-cluster lab receiver, so there is
  nothing real to revoke.

## 1. Deploy

```bash
make deploy
```

This runs `terraform apply` scoped to your current public IP (`curl -4 ifconfig.me`
/32, never 0.0.0.0/0), points kubectl at the cluster, builds and pushes the
summarizer, receiver and hardened images to ECR, deploys the manifests, and
mints the synthetic canary trophy Secret. Wait for the LoadBalancer:

```bash
make url
```

## 2. Prove it is reachable

```bash
curl -s "$(make -s url)/healthz" | jq .
# {"status":"ok","token_loaded":true}
```

## 3. Demo (red team)

```bash
make demo
```

Runs `attack/demo.py`: recon, RCE foothold, SSRF to IMDS node creds, lateral
move into Secrets Manager, SA-token privilege escalation to cluster-admin, and
the canary trophy. Each stage is judged on its own and prints a status
(exploited / blocked / error), so a blocked stage never hides the ones after it.
Save the baseline table with `make demo` piped to a file, or
`APP_URL=$(make -s url) python3 attack/demo.py --out baseline.json`.

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
make harden            # hardened image + overlay, delete the Secret, then verify
make verify-hardened   # all five controls: binding gone, automount off, hardened
                       # image in use, diagnose rejects metachars, summarize cannot
                       # reach IMDS, trophy Secret deleted
```

`make harden` deletes the trophy Secret, so there is nothing to exfiltrate and
nothing to revoke. Re-run the demo to get the hardened column:

```bash
APP_URL=$(make -s url) python3 attack/demo.py --out hardened.json
python3 attack/demo.py --compare baseline.json hardened.json
```

Every stage should flip from `exploited` to `blocked`. Stage 3 reports `error`
when stage 2 is blocked upstream (no node creds to exercise the IAM-scope
control), which is deliberately not shown as `blocked`.

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
