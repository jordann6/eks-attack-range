| Stage | Name | Baseline | Hardened | Control layer |
|---|---|---|---|---|
| 0 | Recon | info | info | n/a (discovery) |
| 1 | Foothold via RCE | exploited | blocked | app (input validation) |
| 2 | SSRF to IMDS | exploited | blocked | app (fixed upstream) + cloud (IMDS hop limit) |
| 3 | Lateral move with node creds | exploited | error | cloud (scoped node IAM role) |
| 4 | Privilege escalation via SA token | exploited | blocked | kubernetes (RBAC + automount) |
| 5 | Trophy: read the canary Secret | exploited | blocked | kubernetes (RBAC) + no secret in env |
