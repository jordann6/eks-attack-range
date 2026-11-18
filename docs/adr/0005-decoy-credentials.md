# ADR-0005: Decoy credentials, real-call detection, pod-first containment

- **Status:** accepted
- **Date:** 2026-11-18
- **Relates to:** [ADR-0002](0002-throwaway-key-as-trophy.md), [ADR-0003](0003-synthetic-canary-trophy-and-code-level-hardening.md), [ADR-0004](0004-aks-port.md)

## Context

The lab proved a kill chain but not its detection. The first live run
(`evidence/aws-run1/detection.md`) recorded two honest misses: GuardDuty raised
no finding in the window, and the documented EKS audit queries matched nothing.
The audit miss had a root cause worth fixing on its own. Stages 4 and 5 were
evaluated with `kubectl auth can-i --as=<SA>`, a SubjectAccessReview run under
the operator's own identity. EKS's default audit policy does not log
SubjectAccessReview, and more to the point a `can-i` check is not the SA making
a call, so no `get`/`list secrets` event by the SA ever existed to detect.

Separately, a widely shared tip claims a decoy `.aws/credentials` file "catches
the attacker before they reach your real cloud data" and "locks down the
account." A reply to it made the sharper point: a decoy only helps when there
are no real credentials beside it, and on a compromised box there usually are.
This lab is exactly that box. A pod with RCE can reach the node role through
IMDS, a cluster-admin ServiceAccount token, and the trophy, all before any
decoy is touched. The honest question is not "does the decoy fire" but "how much
did the attacker already hold when it fired."

## Decision

1. **Stages 4 and 5 make real API calls.** Through the stage 1 RCE, a probe
   reads the pod's own mounted ServiceAccount token and makes one HTTPS call to
   the API server, judged on the HTTP status (200 exploited, 401/403 blocked,
   no token mounted blocked, no foothold error). This is the SA acting, so the
   call appears in the audit log and the documented queries now match it. A
   `--assume-breach` flag keeps the old `can-i` path so the hardened cluster's
   RBAC still gets a direct verdict when stage 1 is blocked. When stage 1 is
   blocked, stages 4 and 5 read `error` (not exercised), never `blocked`: a
   control that was never reached was not demonstrated.

2. **Three decoys, two telemetry sources.**
   - **D1**, an AWS access key on a zero-policy IAM user, mounted into the
     summarizer pod at `/root/.aws/credentials`. Any API call signed with it is
     caught from CloudTrail through an EventBridge rule. The rule is in the
     `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` state, because a rule in the
     default `ENABLED` state never matches read-only calls such as
     `sts:GetCallerIdentity`, the first thing anyone does with a found key. This
     state also requires a trail logging management events, which `make
     verify-decoys` checks.
   - **D3**, a Kubernetes Secret `prod-db-backup-creds`, caught from the EKS
     audit log when a ServiceAccount reads it by name.
   - **D4**, a ServiceAccount `backup-operator` with no RBAC bindings and a
     long-lived token Secret. Any request authenticated as it is a 403, and the
     403 is logged under its username, so it fires even though it can do nothing.

3. **The imperative key, versus the guardrails deny.** platform-guardrails
   denies `aws_iam_access_key` (a long-lived key in state). So the IAM user is
   declared in Terraform with zero permissions, and `make decoys` mints its one
   key with `aws iam create-access-key`, plants it, and records a key-id to
   Secret map in SSM; `make destroy-plan` deletes the key. The secret value
   never enters Terraform state or git. Same pattern as the canary trophy
   (ADR-0002, ADR-0003).

4. **Attribution without guessing.**
   - D1 is attributed through the SSM map: CloudTrail sees the caller's IP, never
     the pod, so the map names the Secret the key was planted in and the
     responder finds the pods that mount it.
   - D3 and D4 are attributed by the audit event's `sourceIPs`. With the VPC
     CNI, in-VPC traffic to the API server is not source-NATed, so a call from
     inside a pod shows the pod's own IP. A bound token also carries the pod name
     in `user.extra`, used as a cross-check. A record that cannot be resolved to
     a running pod is written with the reason and reported as detected, not
     contained, never silently dropped.

5. **Pod-first containment through an in-cluster responder.** The alert Lambda
   only writes a record and notifies; it never touches Kubernetes. A small
   responder Deployment in the cluster (its own ServiceAccount, a Role that can
   only get/list/patch pods in `summarizer`, an IRSA role that can only read
   `alerts/*` and write `quarantine/*`) polls the records and labels the
   attributed pod. A deny-all NetworkPolicy selecting that label, enforced by the
   VPC CNI's network policy agent, cuts the pod off. Keeping the response in the
   cluster avoids a VPC Lambda, the private endpoint and access-entry work
   entirely. The label is not in the Deployment selector, so the pod is isolated
   in place for forensics rather than replaced.

6. **The decoy is a tripwire, not a shield, and the demo measures that.** Stage
   6 runs two attacker orders. In `imds-first` (the existing chain) the real
   node role, SA token and trophy are already taken when the alarm fires; a
   "held before alert" column records exactly which. In `decoy-first` the planted
   key is tested first, the move the tip assumes, and if quarantine lands in time
   the rest of the chain runs against a contained pod. This answers the reply to
   the original tip with data instead of repeating its overclaim.

## Out of scope (named, not done)

The node-level response is deliberately excluded and left to
`aws-incident-forensics`, which already proves it: D2 (a decoy key inside the
Secrets Manager loot), node EBS snapshots, node role session revocation, and a
VPC Lambda with API access. Pod quarantine denies the quarantined pod's egress
to IMDS, but node-role credentials stolen *before* quarantine stay valid until
they expire; revoking them is the forensics repo's job. These are the next step,
not a gap this ADR claims to have closed.

## Alternatives rejected

| Option | Why not |
| ------ | ------- |
| Keep `can-i` for stages 4/5 | It is a SubjectAccessReview under the operator, not the SA acting, so nothing the detection queries target ever exists |
| Shape the stage 6 attacker so D4 reads the decoy Secret by name | Tuning the test until it passes; a real attacker with a full secrets dump has no reason to, so D4 is attributed by source IP instead |
| Count a secrets *list* as a D3 detection | A list audit event names no Secret, so D3 cannot see it; documented as the blind spot (D1 and D4 still fire once the taken creds are used) |
| Declare the key in Terraform with a guardrails exception | Puts a long-lived secret in state and weakens the shared policy for one lab; minting out of band keeps both clean |
| Quarantine from a VPC Lambda with API access | Needs the private endpoint, an access entry and a VPC-attached function, the pieces most likely to fail live; an in-cluster responder needs none of them |
| Synthesize an alert when a decoy is used | A fabricated event is not a detection; a record exists only because CloudTrail or the audit log delivered a real one |

## Consequences

The lab now mints and deletes a real (zero-permission) AWS key around the live
session, so `make verify-gone` gains a check that the key and its SSM map are
gone, and teardown deletes the key before `terraform destroy`. The source-IP
attribution for D3 and D4 rests on the VPC CNI not SNAT-ing in-VPC traffic to
the API server; this is verified as the first live check, and if it reads a node
IP instead, D4 is reported detected-but-unattributed rather than forced. The
responder is a second small image to keep current. Detection and quarantine
timings depend on CloudTrail and audit-log delivery, which is seconds in
practice but not contractual, so a slow delivery shows as a larger
seconds-to-alert, never as a miss moved to a pass.
