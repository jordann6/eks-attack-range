| Stage | Name | Status | Control layer | Detail |
|---|---|---|---|---|
| 0 | Recon | info | n/a (discovery) | healthz 200 |
| 1 | Foothold via RCE | blocked | app (input validation) | HTTP 400 |
| 2 | SSRF to IMDS | blocked | app (fixed upstream) + cloud (IMDS hop limit) | HTTP 200 |
| 3 | Lateral move with node creds | error | cloud (scoped node IAM role) | needs stolen node creds |
| 4 | Privilege escalation via SA token | blocked | kubernetes (RBAC + automount) | can-i list secrets -A: False |
| 5 | Trophy: read the canary Secret | blocked | kubernetes (RBAC) + no secret in env | can-i get secret: False, secret exists: False |
