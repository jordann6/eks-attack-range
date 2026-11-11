# Red team: the kill chain

`demo.py` runs the whole chain against the lab you deployed. It is the cloud
translation of a host-centric ethical-hacking course: the course runs recon,
exploitation, privilege escalation and automation against a local VM; this runs
the same lifecycle against a deliberately-vulnerable EKS cluster.

Every stage works only because of a planted misconfiguration. The hardened image
and the `../defend` overlay remove each one, and each stage is judged on its own
so a blocked stage never hides whether the later controls hold. Each stage
reports `exploited`, `blocked`, or `error` (could not be evaluated); an `error`
is never shown as `blocked`.

## Stage map

| Stage | Video step | What it does here | Planted weakness | ATT&CK (Containers) |
|------|-----------|-------------------|------------------|---------------------|
| 0 Recon | Nmap, Dirsearch, WhatWeb | Pull `/healthz` and the OpenAPI schema to map routes | Debug schema exposed | T1595 Active Scanning |
| 1 Foothold | Exploit to reverse shell | Command injection in `/tools/diagnose` for RCE in the pod | Unsanitised shell call | T1190 Exploit Public-Facing App |
| 2 IMDS creds | Burp intercept/modify | SSRF in `/summarize` does the IMDSv2 handshake to `169.254.169.254`, steals node role creds | IMDS reachable at hop limit 2 | T1552.005 Cloud Instance Metadata API |
| 3 Lateral move | Pivot to other hosts | Stolen node creds read Secrets Manager account-wide | Broad node IAM role | T1078.004 Valid Cloud Accounts |
| 4 Privesc | Escalate to root | Auto-mounted SA token drives the API as cluster-admin | cluster-admin binding + automount | T1134 Access Token Manipulation |
| 5 Trophy | Capture the flag | read the canary token Secret | Secret in env, no etcd encryption | T1552.001 Credentials In Files |

## Running it

```bash
APP_URL=http://<summarizer-loadbalancer-hostname> python3 demo.py
```

Needs `python3`, `kubectl` and `aws` on the attack box, with `kubectl` pointed at
the cluster. Stages 4 and 5 are evaluated with `kubectl auth can-i
--as=system:serviceaccount:summarizer:summarizer`: we ask what the app's identity
is allowed to do, independent of whether stage 1's RCE succeeded. That is the
assume-breach fixture, so the RBAC controls are tested even on a hardened run
where the earlier stages are blocked.

## Authorization

This is an authorized exercise against infrastructure you own, in an isolated
account, with the control-plane endpoint scoped to your own IP. The trophy is a
synthetic canary token minted per run and accepted only by the in-cluster lab
receiver, so nothing real is ever exposed and there is nothing to revoke.
Nothing here targets a system you do not control.
