# ADR-0001: Build the lab by inverting an existing hardened cluster

- **Status:** accepted
- **Date:** 2026-11-03

## Context

The lab needs a deliberately-vulnerable EKS cluster that teaches real
misconfigurations, not toy ones. I already run a hardened, paved-road cluster
(`aws-landing-zone/workload/eks.tf`): private endpoint, IMDSv2, IRSA, etcd KMS
encryption, restricted PodSecurity. The teaching value is highest when the
vulnerable cluster is the exact negative of a cluster a reader can also see
hardened, so the fix for every weakness is a concrete one-line diff rather than
an abstract recommendation.

## Decision

Build the vulnerable cluster by taking the `aws-developer-platform` EKS base
(community module, already a public endpoint) and inverting each hardening
control from the paved road: IMDSv1 + hop limit 2, a broad node IAM role, a
cluster-admin ServiceAccount binding, no etcd encryption, no admission control.
Each weakness carries a comment naming its hardened counterpart, and the
`defend/` overlay restores it.

## Alternatives rejected

| Option | Why not |
| ------ | ------- |
| Use an off-the-shelf vuln tool (kube-goat, CloudGoat) | Someone else's scenario; no before/after against my own paved road, and less to write about |
| Hand-roll a cluster from scratch | Reinvents the module wiring I already have; the inversion is the interesting part, not the boilerplate |
| Disable control-plane audit logging too | Would make the blue-team half impossible; the lab needs the attack to be visible |

## Consequences

The fleet guardrails (Trivy, Checkov, OPA) will flag the intentional weaknesses,
so the repo carries a documented `.trivyignore` and Checkov baseline that accept
exactly those findings and nothing else. Audit logging stays on, which costs a
little CloudWatch spend during a run. If the paved-road cluster's settings
change, the inversion comments here go stale and should be re-checked against it.
