# ADR-0002: A throwaway Anthropic key is the trophy, scoped endpoint, no 0.0.0.0/0

- **Status:** accepted
- **Date:** 2026-11-03

## Context

The lab stands up a cluster that holds genuinely stealable credentials: a node
IAM role that can read Secrets Manager, a cluster-admin ServiceAccount token, and
an API key. Realism is the point, but a cluster with those weaknesses must never
actually be reachable by anyone but me, and nothing valuable can be exposed if
something goes wrong.

## Decision

Three safety rules, enforced in code, not just documented:

1. The control-plane public endpoint is scoped to the operator's own /32.
   `variables.tf` refuses `0.0.0.0/0` with a validation error, and `make deploy`
   injects `curl ifconfig.me` automatically.
2. The trophy is a throwaway Anthropic key created for the run and revoked in the
   blue-team step. No key that matters is ever used, and no key is committed: the
   Secret is created imperatively at deploy time, never stored in git.
3. The Secrets Manager "loot" is an obviously fake decoy value, so even the
   planted secret carries nothing real.

## Alternatives rejected

| Option | Why not |
| ------ | ------- |
| Public endpoint open to 0.0.0.0/0 for demo convenience | A cluster with live stealable creds in front of the internet is indefensible, even briefly |
| A fake placeholder key, never a real one | Loses the "an app actually used this key" realism that makes the secrets-management lesson land |
| Store the key in a committed tfvars/secret file | Puts a credential in git history; the imperative-create path avoids it entirely |

## Consequences

The endpoint allow-list is tied to the operator's current IP, so a run started on
one network and resumed on another needs a re-apply to update the /32. The
throwaway-key discipline depends on the operator actually revoking it; the runbook
and `make harden` both prompt for it, but nothing technical forces revocation.
That residual step is accepted as the cost of using a real key for realism.
