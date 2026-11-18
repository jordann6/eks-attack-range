# Detection and containment, run 2 (EKS 1.36, 2026-11-18)

The deception layer (ADR-0005) added to the attack range. One live session in an
isolated member account, `us-east-1`. Account IDs and the operator IP are not
shown. Pod IPs are ephemeral in-cluster `10.0.0.0/16` addresses.

This run answers the first run's two honest misses (`../aws-run1/detection.md`):
GuardDuty silent, audit queries matching nothing because stages 4/5 used
`kubectl auth can-i` rather than a real call. Here stages 4/5 make real API
calls and the decoys turn the chain into measured catches.

## First live check: audit sourceIPs is the pod IP

D3/D4 attribution assumes the EKS audit log records the pod's own IP (no SNAT
for in-VPC traffic to the API server). Confirmed before any run. One
ServiceAccount-authenticated `list secrets` from inside the summarizer pod:

- `sourceIPs = ["10.0.2.151"]`, equal to the pod IP.
- `user.extra["authentication.kubernetes.io/pod-name"] = ["summarizer-…"]` also
  present, so the bound-token pod name is available as a cross-check.

Both attribution paths hold.

## Baseline, imds-first (the realistic order)

The existing chain runs first, then the decoys. Stages 1-5 all exploited with
real calls, so the documented audit queries now match them.

| Decoy | Reach | Detected | Alert s | Attributed | Contained | Quarantine s | Held before alert |
|---|---|---|---|---|---|---|---|
| D1 AWS key in `/root/.aws/credentials` | exploited | detected | 2.1 | yes | contained | 3.9 | node role creds, cluster-admin SA token, trophy |
| D3 Secret `prod-db-backup-creds` | exploited | detected | 2.2 | yes | contained | 3.9 | same |
| D4 ServiceAccount `backup-operator` token | exploited | detected | 2.4 | yes | contained | 3.9 | same |

Every decoy detected, attributed to the summarizer pod, and quarantined in about
two seconds to alert and four to contained. The "held before alert" column is
the point: by the time any alarm fires, the attacker already holds the node
role, the SA token and the trophy.

## Baseline, decoy-first (the tip's premise)

The attacker reads and tests the planted key before pivoting.

| Decoy | Reach | Detected | Alert s | Attributed | Contained | Quarantine s | Held before alert |
|---|---|---|---|---|---|---|---|
| D1 AWS key | exploited | detected | 2.2 | yes | contained | 3.4 | none |

Post-label chain (the pivot the attacker would make next):

| Stage | Status | Note |
|---|---|---|
| 2 SSRF to IMDS | exploited | after the quarantine label (3.4s): still reached IMDS |
| 3 Lateral move | error | SSRF won but the IMDSv2 steal failed mid-way: isolation engaged here |
| 4, 5 | error | pod isolated |

The finding: the quarantine **label** lands in 3.4s, but the VPC CNI dataplane
enforcement lags the label by a few seconds. In that window a fast attacker
still completes the SSRF (stage 2); the deeper pivot (stage 3) is cut off as
enforcement engages. So even in the best order the decoy is a tripwire that
contains within seconds, not a shield that pre-empts the first pivot. (Across
two decoy-first runs enforcement engaged at stage 3 once and after stage 3
once, confirming a small variable lag.)

## Hardened, imds-first

`make harden` (hardened image + overlay), then the chain with `--assume-breach`
so RBAC gets a direct verdict.

| Stage | Status |
|---|---|
| 1 Foothold (RCE) | blocked (400) |
| 2 SSRF | blocked (fixed upstream, no IMDS) |
| 3 Lateral move | error (not exercised, SSRF held) |
| 4, 5 (can-i) | blocked (binding removed, automount off) |
| 6 Decoys D1/D3/D4 | error (unreachable, no foothold) |

The decoys are unreachable because the chain stops at stage 1, recorded honestly
as error (not exercised), never as a detection.

## Deviations forced by the environment

1. **S3 SCP.** The account's SCP (`…/p-zepreoac`) denies `s3:PutObject` without
   an explicit SSE-KMS header, even with bucket default encryption. The alert
   Lambda and the responder were changed to pass `ServerSideEncryption=aws:kms`
   and the CMK id on every put. Found live: the first run detected D1 but the
   Lambda's record write was denied.
2. **CNI enforcement lag.** See decoy-first above. The quarantine_s figure is
   time-to-label; dataplane enforcement trails it by a few seconds.
3. **verify-decoys container name.** The VPC CNI v1.23.3 network policy agent
   container is `aws-eks-nodeagent`, not `aws-network-policy-agent`; the check
   was corrected to match either.

## Conclusion

The decoys turn the chain's detection story from two misses into three measured
catches, each attributed to the right pod and contained in seconds. Honestly
stated, the decoy is a tripwire, not a shield: in the realistic order the real
credentials are already gone when it fires, and even tested first the CNI
enforcement lag lets the first pivot through. Revoking the already-stolen node
session is the node-level response left to `aws-incident-forensics` (ADR-0005).
