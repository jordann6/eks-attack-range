"""In-cluster responder: quarantine the pod an alert record attributes.

The alert Lambda writes alerts/<decoy>/<day>.json to S3 and never touches
Kubernetes. This Deployment polls that prefix, resolves the record to pods,
labels them security.attack-range/quarantine=true (a deny-all NetworkPolicy
selects that label), and writes quarantine/<decoy>/<day>.json with what it did
and when. Keeping the response inside the cluster means nothing in AWS needs
cluster credentials: no VPC Lambda, no private endpoint, no access entry.

Least privilege:
  Kubernetes  a Role in the summarizer namespace that can get, list and patch
              pods. Nothing else, no Secrets.
  AWS         an IRSA role that can read alerts/* and write quarantine/* in the
              one bucket.

Resolution never guesses. A record it cannot resolve to a pod in an allowed
namespace is still written, with pods [] and the reason, so the demo reports
"detected, not quarantined" instead of silently claiming containment.
"""
from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request

LABEL = "security.attack-range/quarantine"
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
API = "https://kubernetes.default.svc"

BUCKET = os.environ.get("BUCKET", "")
POLL_S = float(os.environ.get("POLL_S", "2"))
ALLOWED_NAMESPACES = set(filter(None, os.environ.get("ALLOWED_NAMESPACES", "summarizer").split(",")))


# ----------------------------------------------------------------------------
# Pure logic (unit-tested)
# ----------------------------------------------------------------------------

def quarantine_key(alert_key: str) -> str:
    return "quarantine/" + alert_key.split("/", 1)[1] if alert_key.startswith("alerts/") else ""


def _mounts_secret(pod: dict, secret: str) -> bool:
    for v in (pod.get("spec") or {}).get("volumes") or []:
        if ((v.get("secret") or {}).get("secretName")) == secret:
            return True
        for src in ((v.get("projected") or {}).get("sources") or []):
            if ((src.get("secret") or {}).get("name")) == secret:
                return True
    return False


def resolve_targets(attr: dict, pods: list[dict], allowed: set[str] = ALLOWED_NAMESPACES) -> tuple[list[str], str]:
    """Pod names to quarantine for one alert's attribution, and how they were found.

    pods is the pod list of attr["namespace"]. Running pods only: a completed
    or deleted pod has nothing left to contain.
    """
    method = attr.get("method")
    ns = attr.get("namespace", "")
    if method == "none":
        return [], f"unattributed: {attr.get('reason', 'no attribution')}"
    if ns not in allowed:
        return [], f"namespace {ns!r} outside the responder's scope"
    live = [p for p in pods if (p.get("status") or {}).get("phase") == "Running"]

    if method == "secret-mount":
        names = sorted(p["metadata"]["name"] for p in live if _mounts_secret(p, attr.get("secret", "")))
        return names, f"pods mounting secret {attr.get('secret')}" if names else "no running pod mounts the secret"

    if method == "source-ip":
        ip = attr.get("pod_ip", "")
        by_ip = sorted(p["metadata"]["name"] for p in live if (p.get("status") or {}).get("podIP") == ip)
        want = attr.get("pod_name")
        if want:
            if by_ip and want not in by_ip:
                # The bound token says one pod, the IP says another. Do not
                # pick one: report the conflict and quarantine nothing.
                return [], f"conflict: source IP {ip} is {by_ip}, token pod-name is {want}"
            if not by_ip and any(p["metadata"]["name"] == want for p in live):
                return [want], f"token pod-name {want} (source IP {ip} matched no pod)"
        if by_ip:
            return by_ip, f"source IP {ip}" + (" and token pod-name agree" if want else "")
        return [], f"source IP {ip} matched no running pod in {ns}"

    return [], f"unknown attribution method {method!r}"


def quarantine_record(alert: dict, alert_key: str, pods: list[str], how: str, now: float) -> dict:
    return {
        "alert_key": alert_key,
        "decoy": alert.get("decoy"),
        "event_id": alert.get("event_id"),
        "pods": pods,
        "how": how,
        "quarantined": bool(pods),
        "quarantined_at": now,
    }


# ----------------------------------------------------------------------------
# I/O
# ----------------------------------------------------------------------------

def _kube(method: str, path: str, body: dict | None = None, content_type: str = "application/json"):
    with open(f"{SA_DIR}/token") as f:
        token = f.read().strip()
    ctx = ssl.create_default_context(cafile=f"{SA_DIR}/ca.crt")
    req = urllib.request.Request(API + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": content_type})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:  # noqa: S310
        return json.loads(r.read())


def _label(ns: str, pod: str, decoy: str) -> None:
    patch = {"metadata": {"labels": {LABEL: "true"},
                          "annotations": {f"{LABEL}-reason": f"credential tripwire {decoy}"}}}
    _kube("PATCH", f"/api/v1/namespaces/{ns}/pods/{pod}", patch, "application/merge-patch+json")


def handle(s3, key: str) -> dict | None:
    qkey = quarantine_key(key)
    try:
        s3.head_object(Bucket=BUCKET, Key=qkey)
        return None  # already handled (restart-safe)
    except s3.exceptions.ClientError:
        pass
    alert = json.loads(s3.get_object(Bucket=BUCKET, Key=key)["Body"].read())
    attr = alert.get("attribution") or {"method": "none", "reason": "record has no attribution"}
    pods: list[dict] = []
    if attr.get("method") != "none" and attr.get("namespace") in ALLOWED_NAMESPACES:
        pods = _kube("GET", f"/api/v1/namespaces/{attr['namespace']}/pods").get("items", [])
    names, how = resolve_targets(attr, pods)
    for n in names:
        _label(attr["namespace"], n, alert.get("decoy", ""))
    rec = quarantine_record(alert, key, names, how, time.time())
    s3.put_object(Bucket=BUCKET, Key=qkey, Body=json.dumps(rec).encode(), ContentType="application/json")
    print(json.dumps(rec), flush=True)
    return rec


def main() -> None:
    import boto3

    s3 = boto3.client("s3")
    print(json.dumps({"responder": "started", "bucket": BUCKET, "namespaces": sorted(ALLOWED_NAMESPACES)}), flush=True)
    while True:
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix="alerts/"):
                for obj in page.get("Contents", []):
                    try:
                        handle(s3, obj["Key"])
                    except (urllib.error.URLError, OSError, ValueError) as e:
                        print(json.dumps({"error": str(e), "key": obj["Key"]}), flush=True)
        except Exception as e:  # noqa: BLE001  keep polling through transient S3 errors
            print(json.dumps({"poll_error": str(e)}), flush=True)
        time.sleep(POLL_S)


if __name__ == "__main__":
    main()
