# ADR-0004: AKS port of the attack range, design level

- **Status:** accepted
- **Date:** 2026-11-11

## Context

The EKS lab chains five weaknesses (command injection, node metadata reachable
from pods, a broad node role, a cluster-admin ServiceAccount, a plaintext
Secret) and proves that each fix breaks the chain. EKS Session A on 2026-11-11
(`evidence/aws-run1`) ended with stage 3 fixed so it exercises the real control,
all five hardening controls holding, and two honest detection misses.

- GuardDuty did not raise the credential-exfiltration finding inside the
  session window.
- The documented audit queries for stages 4 and 5 matched nothing, because the
  demo evaluates those stages with `kubectl auth can-i --as`. That is a
  SubjectAccessReview under the operator's identity, and EKS's default audit
  policy does not log that verb at all. It is a structural gap between the
  detection method and the assume-breach test method, not a transient miss.

This ADR is deliberately design level. It maps each EKS control to its AKS
equivalent and records the choices around them. The attack-stage mechanics for
AKS are implemented in code later, behind the same per-stage `exploited`,
`blocked` or `error` contract, and are not described here.

Facts read from Microsoft Learn on 2026-11-11.

- By default every pod on AKS can reach the Azure Instance Metadata Service.
  Microsoft's IMDS restriction for non host network pods is a preview feature,
  implemented as node iptables rules AKS manages, and it is incompatible with
  some cluster extensions.
- Microsoft states that pods should rely on Microsoft Entra Workload ID once
  metadata access is restricted.
- The `kube-audit-admin` log category excludes `get` and `list` verbs.
  `kube-audit` keeps everything and costs more to ingest.
- The self-healing lab's own AKS run on 2026-11-07 recorded that Defender for
  Containers raised no alert naming the attacked pod within 3600 seconds on
  either profile. That is the prior this port starts from.

## Decision

1. **Control mapping.**

   | # | EKS weakness | EKS fix | AKS equivalent |
   | - | ------------ | ------- | -------------- |
   | 1 | Command injection | Input validation, no shell | Unchanged, same hardened image |
   | 2 | Metadata reachable from pods | Hop limit 1 plus egress deny | No hop limit exists on Azure, so the fix is a pod egress policy denying the link-local metadata address |
   | 3 | Broad node role | Minimal node role, scoped IRSA | Kubelet managed identity holds an intentionally broad role over a lab-only Key Vault in the baseline, and only AcrPull in hardened |
   | 4 | cluster-admin SA, token automount | Least-privilege RBAC | Unchanged, plus Azure RBAC for Kubernetes stays on |
   | 5 | Plaintext key Secret | Keyless or External Secrets | Workload identity federated to one ServiceAccount, nothing stored in the pod |

2. **Egress policy engine for control 2.** Azure CNI overlay with the managed
   Cilium dataplane, which enforces L3/L4 policy without the paid ACNS add-on
   (ADR-0006 covers why the netseg lab brings its own Cilium instead). This
   lab only needs an L3/L4 egress deny, so the managed engine is enough and
   keeps the baseline close to a default AKS cluster. The Microsoft IMDS
   restriction preview is not used, because it is preview and because the
   policy deny is the control this lab demonstrates. It is recorded as a
   further hardening option.
3. **Workload identity.** The cluster enables the OIDC issuer and workload
   identity. The hardened path gives the summarizer its own user-assigned
   identity, federated to exactly one ServiceAccount, with one role on one
   resource. The baseline leaves it off and relies on the kubelet identity.
   The pattern follows the self-healing lab's `identity.tf`, with direct role
   assignments and no groups.
4. **Loot and blast radius.** The decoy secret lives in a lab-only Key Vault
   holding an obviously fake value. The baseline kubelet identity gets read on
   that vault only, never on anything the lab did not create, so the account
   stays safe to share. Vault diagnostic logging is on so the secret read is
   attributable.
5. **Detection, recorded honestly beside each other.**
   - Falco is the judged detector, installed at the version the self-healing
     lab pinned, with the existing rules adapted to the AKS namespace and the
     metadata address. A Falco hit counts only when it names the attacked pod.
   - Defender for Containers is enabled and recorded next to it. The expected
     outcome is no alert inside the window, based on the 2026-11-07 result. If
     that repeats it is written up as a platform limitation, with no retuning
     of the window to manufacture a pass.
   - Control plane audit uses `kube-audit`, not `kube-audit-admin`, for the
     session, because the admin category drops the verbs stage 4 and 5 queries
     need. The cost is bounded by the session and stated in the plan.
   - The SubjectAccessReview gap found on EKS is carried forward as a documented
     limitation, to be confirmed on AKS rather than assumed. The documented
     queries only catch a real call made with the ServiceAccount's own token,
     never the `can-i` simulation. The lab keeps the simulation for the
     assume-breach stages and says so in the detection write-up.
   - Key Vault audit events are added as a detection source for the secret
     read, which is the closest analogue to the CloudTrail view on EKS.
6. **Registry.** Azure Container Registry (Basic) replaces ECR. Nodes pull
   through the kubelet identity with AcrPull, and images are built with
   `az acr build`. The public load balancer and its endpoint scoping change
   shape from the NLB version. The API server stays limited to the operator's
   single IPv4 address through a plan-time variable with no default, and a
   validation refuses `0.0.0.0/0`, as in `variables.tf` today.
7. **Capacity.** The subscription has 10 regional vCPUs, DSv3 is deprecated and
   not raisable, and Dsv6 is available. The cluster is one small system pool
   plus one small workload pool, sized from current quota at plan time and not
   copied from the self-healing layout. Kubernetes defaults to 1.36 and is
   confirmed against the server before any stage runs.
8. **Teardown safety.** Every node pool sets a drain timeout so a stranded pod
   cannot hang destroy, which happened for about 45 minutes in the
   self-healing lab. The app and its load balancer are removed before the
   destroy plan, the destroy is a saved plan the operator applies, and
   `verify-gone` checks cluster, node resource group, load balancer, registry,
   Key Vault (including purge protection state), Log Analytics workspace and
   Defender plan.
9. **Sequence.** No kind variant exists for this lab, as on EKS. Offline, the
   unit tests (29 today), Terraform validate and the security scanners, and
   manifest rendering stay green. The live proof is one paid session, which
   runs baseline, then harden, then verify, with nothing else touching the
   cluster. Credentialed apply and destroy are run by the operator from saved
   plans after the cost estimate.

## Alternatives rejected

| Option | Why not |
| ------ | ------- |
| Enable the IMDS restriction preview as the fix | Preview feature, blocks some extensions, and replaces the policy control the lab teaches with a platform switch. Kept as an extra option. |
| Bring-your-own Cilium (ADR-0006 path) for this lab | Needed there for L7 and DNS parity. Here only an L3/L4 egress deny is needed, and the managed engine keeps the baseline closer to a default cluster. |
| Defender for Containers as the judged detector | Missed in the 2026-11-07 run, and a judged detector that is known to miss would turn every run into a fail by construction. It is recorded, not judged. |
| `kube-audit-admin` for cost | Drops the get and list verbs the stage 4 and 5 queries depend on. |
| Copy the self-healing node layout | Quota and workload shape differ, so sizing is taken from current quota at plan time. |

## Consequences

The lab gains a Key Vault, a registry and a user-assigned identity, so the
destroy and `verify-gone` surface is larger than on EKS and soft-deleted vault
state needs an explicit check. Detection results on AKS are likely to include at
least one honest miss (Defender), and the audit-visibility limitation may
repeat. Both are recorded beside the results and not smoothed over.

Open items for the live session.

- Whether the managed Cilium engine drops the metadata address under the
  chosen egress policy form, since the docs note limits on selecting node and
  pod IPs with `ipBlock`. If not, the policy is expressed as a Cilium policy
  instead.
- Whether the AKS audit stream logs the SubjectAccessReview verb, which decides
  whether the EKS gap repeats.
- Whether Falco's modern eBPF driver on the chosen node image sees the metadata
  connection from inside the pod.
- Key Vault diagnostic log delay compared with the session window.

Revisit if Microsoft moves the IMDS restriction to general availability, which
would make it a candidate baseline control, or if Defender's container alerting
becomes reliable enough inside a bounded window to be judged.
