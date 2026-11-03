# Blue team: detect, then remediate

Two parts. First prove every stage of the kill chain is **visible** with the
logging the lab already ships (control-plane audit logs are on). Then apply the
remediations and re-run the chain to prove each stage now **fails**.

## Detect

| Kill-chain stage | Where it shows up | Signal |
|------------------|-------------------|--------|
| 1 Foothold (RCE) | Falco (`detections/falco-rules.yaml`) | shell spawned in the summarizer container |
| 2 IMDS creds | Falco | pod process opens a connection to 169.254.169.254 |
| 2/3 Stolen creds used | CloudTrail / GuardDuty | expected `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` |
| 4 Privesc | EKS audit log (`detections/eks-audit-insights.md`) | SA `summarizer` doing `list secrets` cluster-wide |
| 5 Trophy | EKS audit log | `get secret summarizer-key` by the pod identity |

Note: traffic to the IMDS endpoint (169.254.169.254) is link-local and does not
appear in VPC Flow Logs, so stage 2 is caught at the host with Falco (the pod
process reaching IMDS), not in flow logs. The stage 4 and 5 rows are confirmed
from the live run; the GuardDuty row is the finding to expect, and should be
treated as unverified until actually observed (findings lag by minutes to an
hour). GuardDuty EKS Protection and Runtime Monitoring are positioned to catch
stages 1, 2 and 4 without the custom Falco rules; Falco shows the runtime signal
directly and feeds the existing `aws-incident-responder` Claude-summary hook.

## Remediate

`hardened/` is a kustomize overlay over `../app/k8s` that removes the five
cluster-side weaknesses. The infrastructure fixes (private endpoint, IMDSv2,
minimal node role, etcd KMS encryption) are the diff back to
`aws-landing-zone/workload/eks.tf`, which is the paved-road cluster this lab was
built by inverting. The mapping:

| Weakness | Fix in this repo |
|----------|------------------|
| cluster-admin SA binding | `hardened/` deletes the ClusterRoleBinding |
| SA token auto-mounted | `hardened/` sets `automountServiceAccountToken: false` |
| runs as root, no limits | `hardened/` adds a `restricted` securityContext |
| namespace privileged | `hardened/` sets `pod-security.kubernetes.io/enforce: restricted` |
| key in a plaintext env Secret | move to External Secrets + Secrets Manager, or keyless Bedrock (`aws-golden-path-copilot/copilot/bedrock_client.py`) |
| IMDS hop limit 2, broad node role, public endpoint, no etcd encryption | revert to `aws-landing-zone/workload/eks.tf` settings (hop limit 1, minimal node role, private endpoint, KMS etcd) |

Apply the overlay:

```bash
kubectl apply -k hardened/
```

Then revoke the throwaway key in the Anthropic console and confirm the app 401s.
Re-run `../attack/killchain.sh`: stage 1 can no longer spawn a shell under the
restricted context, stage 2 cannot reach IMDS, and stages 4 and 5 get `Forbidden`
because the token is gone and the binding is removed.

## Why the trophy hurt: the key never expired

The stolen key in this lab was a static, long-lived credential with no rotation
and no expiry, which is the common case. That is what makes a leak expensive: the
blast radius is not "until the next rotation," it is "forever, until a human
notices." The structural fix is to stop having a long-lived key to steal at all.

| Posture | What an attacker gets from the pod |
|---------|-------------------------------------|
| Static key in a Secret (this lab) | A credential valid indefinitely |
| External Secrets from a secrets manager with rotation | A credential valid until the next rotation window |
| Keyless Bedrock via IRSA (`aws-golden-path-copilot`) | A short-lived STS token scoped to one role, minted per pod |

The last row is the paved road: the pod never holds a key, so there is nothing to
exfiltrate in stage 5, and the SSRF in stage 2 only yields a role it cannot use
off the node once IMDSv2 and the hop limit are fixed. Rotation shrinks the window;
workload identity closes it.
