# ADR-0003: Synthetic canary trophy, code-level hardening, per-stage demo

- **Status:** accepted
- **Date:** 2026-11-06
- **Supersedes:** rule 2 of [ADR-0002](0002-throwaway-key-as-trophy.md)

## Context

A review of the lab found three claims running ahead of the code:

1. The hardened overlay only patched Kubernetes objects. The hardened pod still
   ran the baseline image, so the command-injection and SSRF weaknesses remained
   live in code. The app comment claimed defend "removes all three weaknesses,"
   which was false: it removed the cluster-side ones only.
2. The trophy was a real throwaway Anthropic key, revoked by hand in a vendor
   console. ADR-0002 accepted the residual "operator must remember to revoke" as
   the cost of realism, and the key was also a dependency (`ANTHROPIC_API_KEY`)
   for every deploy.
3. The demo ran under `set -euo pipefail`, so one blocked stage aborted the
   script and hid whether the later controls held. `make test` checked only two
   of the five controls.

## Decision

1. **A separate hardened application image.** The baseline image keeps all three
   weaknesses on purpose. A second image (`app/hardened/`) removes them in code:
   `/tools/diagnose` validates the host as an IP or DNS name and runs ping with
   an argument vector and no shell; `/summarize` fetches one fixed, operator-set
   upstream and accepts no caller URL, method or headers; it holds no key.
   `make harden` switches the summarizer to this image and applies the overlay,
   so the hardened posture is proven at the app layer as well as the cluster.
2. **A synthetic canary trophy plus an in-cluster receiver.** The trophy is a
   per-run canary token minted by `make app`, mounted from the same plaintext
   Secret (weakness 1 is unchanged), and accepted only by the lab receiver
   (`app/receiver/`). The red team proves the stolen Secret is a usable
   credential by getting a 200 from the receiver, and every use is logged, so
   the token is observably a canary. This keeps ADR-0002's "the key is actually
   used" realism while removing the real key, the `ANTHROPIC_API_KEY` deploy
   dependency, and the manual console-revoke step. The node-role IMDS credentials
   stolen in stage 2 stay real but remain scoped to the existing decoy secret.
3. **One authoritative hardening procedure.** `make harden` applies the image and
   overlay, explicitly deletes the obsolete ClusterRoleBinding and Secret, waits
   for rollout, and runs `make verify-hardened`, which checks all five controls.
4. **A per-stage demo (`attack/demo.py`).** Each stage runs and is judged on its
   own and reports `exploited`, `blocked`, or `error`; an `error` (a stage that
   could not be evaluated) is never rendered as `blocked`. The Kubernetes-identity
   stages are evaluated with `kubectl auth can-i --as=<the app ServiceAccount>`,
   the assume-breach fixture, so the RBAC controls are tested even on a hardened
   run where RCE is already blocked. The stage-classification logic is pure and
   unit-tested (`attack/test_demo.py`), and the tests run in `make check` and CI.

## Alternatives rejected

| Option | Why not |
| ------ | ------- |
| Keep the overlay-only hardening | Leaves the app weaknesses live in the hardened pod; the central claim stays false |
| Keep the real throwaway key | Keeps a manual revoke step nothing enforces, and a real-credential dependency on every deploy |
| Rewrite the one app with a hardened flag | A single image that is both the vulnerable and the fixed build blurs the before/after; two images keep the diff legible |
| Keep the bash killchain, just set `+e` | Ad-hoc; a typed status per stage with pure, tested classification is what stops an `error` masquerading as a `blocked` |

## Consequences

The lab now builds three images (baseline, receiver, hardened) instead of one,
so a deploy is slightly slower. The hardened image is a real second codebase to
keep current. The earlier live-run results in the README describe the old suite
and will be replaced after a fresh live run against this one.
