# Red team: the kill chain

`killchain.sh` runs the whole chain against the lab you deployed. It is the
cloud translation of the freeCodeCamp course *How Ethical Hackers Actually Break
Into Systems*: the video runs recon, exploitation, privilege escalation and
automation against a local VulnHub VM; this runs the same lifecycle against a
deliberately-vulnerable EKS cluster.

Every stage works only because of a planted misconfiguration. The `../defend`
overlay removes each one and the chain then fails at that stage.

## Stage map

| Stage | Video step | What it does here | Planted weakness | ATT&CK (Containers) |
|------|-----------|-------------------|------------------|---------------------|
| 0 Recon | Nmap, Dirsearch, WhatWeb | Pull `/healthz` and the OpenAPI schema to map routes | Debug schema exposed | T1595 Active Scanning |
| 1 Foothold | Exploit to reverse shell | Command injection in `/tools/diagnose` for RCE in the pod | Unsanitised shell call | T1190 Exploit Public-Facing App |
| 2 IMDS creds | Burp intercept/modify | SSRF in `/summarize` reaches `169.254.169.254`, steals node role creds | IMDSv1 + hop limit 2 | T1552.005 Cloud Instance Metadata API |
| 3 Lateral move | Pivot to other hosts | Stolen node creds read Secrets Manager account-wide | Broad node IAM role | T1078.004 Valid Cloud Accounts |
| 4 Privesc | Escalate to root | Auto-mounted SA token drives the API as cluster-admin | cluster-admin binding + automount | T1134 Access Token Manipulation |
| 5 Trophy | Capture the flag | `get secret` the plaintext Claude API key | Secret in env, no etcd encryption | T1552.001 Credentials In Files |

## Running it

```bash
APP_URL=http://<summarizer-loadbalancer-hostname> ./killchain.sh
```

Needs `curl`, `jq`, `kubectl`, `aws` on the attack box, and `kubectl` pointed at
the cluster for the API server URL (the chain supplies its own token, not your
admin credentials). Stages 4 and 5 use the *stolen* token on purpose, to prove
the SA token alone is enough.

## Authorization

This is an authorized exercise against infrastructure you own, in an isolated
account, with the control-plane endpoint scoped to your own IP. The trophy is a
throwaway Anthropic key that is revoked the moment the chain finishes. Nothing
here targets a system you do not control.
