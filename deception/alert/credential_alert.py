"""Turn any use of a planted credential into one alert record per decoy per UTC day.

Three planted credentials, two telemetry sources, one function:

  D1  AWS access key on a zero-policy IAM user, mounted into the summarizer pod
      at /root/.aws/credentials. Any API call signed with it reaches this
      function from CloudTrail through an EventBridge rule in the
      ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS state (a plain ENABLED rule
      never sees read-only calls like sts:GetCallerIdentity).
  D3  Kubernetes Secret prod-db-backup-creds. A ServiceAccount reading it by
      name reaches this function from the EKS audit log through a CloudWatch
      Logs subscription filter.
  D4  ServiceAccount backup-operator, which nothing legitimate ever runs as.
      Any request authenticated with its token is logged, even a 403.

Same shape as aws-incident-forensics/app/decoy_tripwire.py: parse, attribute,
dedupe, alert. Two differences. The record is written to S3 with a create-only
put (If-None-Match: *) on alerts/<decoy>/<UTC day>.json, so the first event
wins and every repeat that day is a no-op, the same trick as the Step
Functions execution name there. And this function never touches Kubernetes:
the in-cluster responder reads the record and quarantines the pod, so nothing
in AWS needs credentials for the cluster API.

Attribution:
  D1  CloudTrail sees the caller's IP (the attacker's box or a NAT gateway),
      never the pod. The map /<prefix>/<access key id> names the Secret the key
      was planted in; the responder finds the pods that mount it.
  D3, D4  The audit event carries sourceIPs. With the VPC CNI, in-VPC traffic
      to the API server is not SNATed, so a call made from inside a pod shows
      the pod's own IP. A bound token also carries the pod name in user.extra,
      which is used as a cross-check when present. A legacy token (D4) has no
      pod binding, so the IP is all there is.

Nothing here fabricates an event. A record exists only because CloudTrail or
the audit log delivered one, and it carries that event's own id and time.
"""
from __future__ import annotations

import base64
import gzip
import json
import os
import time

D1, D3, D4 = "D1", "D3", "D4"

DECOY_USER = os.environ.get("DECOY_USER", "svc-backup-sync")
DECOY_SECRET = os.environ.get("DECOY_SECRET", "prod-db-backup-creds")
DECOY_SA = os.environ.get("DECOY_SA", "system:serviceaccount:summarizer:backup-operator")
DECOY_NAMESPACE = os.environ.get("DECOY_NAMESPACE", "summarizer")
MAP_PREFIX = os.environ.get("MAP_PREFIX", "")
BUCKET = os.environ.get("BUCKET", "")
TOPIC_ARN = os.environ.get("TOPIC_ARN", "")
KMS_KEY_ARN = os.environ.get("KMS_KEY_ARN", "")

POD_NAME_EXTRA = "authentication.kubernetes.io/pod-name"
SA_PREFIX = "system:serviceaccount:"


# ----------------------------------------------------------------------------
# Pure parsing (unit-tested, no AWS calls)
# ----------------------------------------------------------------------------

def parse_cloudtrail(event: dict, decoy_user: str = DECOY_USER) -> dict | None:
    """D1. The EventBridge rule already filters on the user name; check it
    again so a mis-scoped rule can never turn someone else's call into an
    alert."""
    detail = event.get("detail") or {}
    ident = detail.get("userIdentity") or {}
    if ident.get("userName") != decoy_user:
        return None
    return {
        "decoy": D1,
        "source": "cloudtrail",
        "event_id": detail.get("eventID", ""),
        "event_time": detail.get("eventTime", ""),
        "event_name": detail.get("eventName", ""),
        "event_source": detail.get("eventSource", ""),
        "source_ip": detail.get("sourceIPAddress", ""),
        "user_agent": detail.get("userAgent", ""),
        "outcome": detail.get("errorCode") or "Success",
        "principal": ident.get("arn", ""),
        "access_key_id": ident.get("accessKeyId", ""),
    }


def decode_awslogs(event: dict) -> dict:
    """The subscription payload is {"awslogs": {"data": base64(gzip(json))}}."""
    raw = base64.b64decode(event["awslogs"]["data"])
    return json.loads(gzip.decompress(raw))


def classify_audit(audit: dict, decoy_secret: str = DECOY_SECRET,
                   decoy_sa: str = DECOY_SA, namespace: str = DECOY_NAMESPACE) -> str | None:
    """Which decoy, if any, one audit event trips.

    D4 wins over D3: a request made AS backup-operator is the stronger signal.
    D3 needs a ServiceAccount caller. The operator's own kubectl apply of the
    decoy (a human or IAM-mapped user) must never fire it, and neither must the
    control plane's own components.
    """
    user = (audit.get("user") or {}).get("username", "")
    if user == decoy_sa:
        return D4
    obj = audit.get("objectRef") or {}
    if (obj.get("resource") == "secrets" and obj.get("name") == decoy_secret
            and obj.get("namespace") == namespace and user.startswith(SA_PREFIX)
            and not user.startswith(SA_PREFIX + "kube-system:")):
        return D3
    return None


def audit_record(audit: dict, decoy: str) -> dict:
    user = audit.get("user") or {}
    extra = user.get("extra") or {}
    pod_names = extra.get(POD_NAME_EXTRA) or []
    ips = audit.get("sourceIPs") or []
    obj = audit.get("objectRef") or {}
    return {
        "decoy": decoy,
        "source": "eks-audit",
        "event_id": audit.get("auditID", ""),
        "event_time": audit.get("requestReceivedTimestamp", ""),
        "event_name": f"{audit.get('verb') or ''} {obj.get('resource') or ''}/{obj.get('name') or ''}".rstrip("/"),
        "source_ip": ips[0] if ips else "",
        "user_agent": audit.get("userAgent", ""),
        "outcome": str((audit.get("responseStatus") or {}).get("code", "")),
        "principal": user.get("username", ""),
        "pod_name": pod_names[0] if pod_names else "",
    }


def parse_audit_payload(payload: dict) -> list[dict]:
    """D3 and D4 records from one decoded subscription payload.

    CONTROL_MESSAGE is CloudWatch Logs checking the destination is reachable.
    It is never an event and never a detection.
    """
    if payload.get("messageType") != "DATA_MESSAGE":
        return []
    out = []
    for le in payload.get("logEvents") or []:
        try:
            audit = json.loads(le.get("message", ""))
        except (TypeError, ValueError):
            continue
        decoy = classify_audit(audit)
        if decoy:
            out.append(audit_record(audit, decoy))
    return out


def attribution(record: dict, mapped_secret: str | None) -> dict:
    """What the responder needs to find the pod. Never guesses."""
    if record["decoy"] == D1:
        if mapped_secret:
            ns, _, name = mapped_secret.partition("/")
            return {"method": "secret-mount", "namespace": ns, "secret": name}
        return {"method": "none", "reason": "no map entry for this access key"}
    if record.get("source_ip"):
        attr = {"method": "source-ip", "namespace": DECOY_NAMESPACE, "pod_ip": record["source_ip"]}
        if record.get("pod_name"):
            attr["pod_name"] = record["pod_name"]
        return attr
    return {"method": "none", "reason": "audit event has no source IP"}


def record_key(decoy: str, event_time: str) -> str:
    """alerts/<decoy>/<YYYYMMDD>.json, the dedupe key. The event's own day,
    not the invocation's, so a late delivery still lands on the right day."""
    day = (event_time or "unknown")[:10].replace("-", "") or "unknown"
    return f"alerts/{decoy}/{day}.json"


# ----------------------------------------------------------------------------
# Handler (AWS calls)
# ----------------------------------------------------------------------------

def handler(event, _context):
    import boto3
    from botocore.exceptions import ClientError

    s3 = boto3.client("s3")
    sns = boto3.client("sns")
    ssm = boto3.client("ssm")

    if "awslogs" in event:
        records = parse_audit_payload(decode_awslogs(event))
    else:
        r = parse_cloudtrail(event)
        records = [r] if r else []

    results = []
    for rec in records:
        mapped = None
        if rec["decoy"] == D1 and rec.get("access_key_id") and MAP_PREFIX:
            try:
                mapped = ssm.get_parameter(Name=f"{MAP_PREFIX}/{rec['access_key_id']}")["Parameter"]["Value"]
            except ClientError:
                mapped = None
        rec["attribution"] = attribution(rec, mapped)
        rec["alerted_at"] = time.time()
        key = record_key(rec["decoy"], rec["event_time"])
        put = dict(Bucket=BUCKET, Key=key, Body=json.dumps(rec).encode(),
                   ContentType="application/json", IfNoneMatch="*")
        if KMS_KEY_ARN:
            # The account's SCP denies PutObject without an explicit SSE-KMS
            # header, even when bucket default encryption would apply it.
            put.update(ServerSideEncryption="aws:kms", SSEKMSKeyId=KMS_KEY_ARN)
        try:
            s3.put_object(**put)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in ("PreconditionFailed", "ConditionalRequestConflict"):
                print(json.dumps({"duplicate": key, "event_id": rec["event_id"]}))
                results.append({"key": key, "duplicate": True})
                continue
            raise
        if TOPIC_ARN:
            sns.publish(TopicArn=TOPIC_ARN, Subject=f"[CREDENTIAL TRIPWIRE] {rec['decoy']} {rec['event_name']}"[:100],
                        Message=json.dumps(rec, indent=2))
        print(json.dumps({"alerted": key, **{k: rec[k] for k in ("decoy", "event_id", "event_name")}}))
        results.append({"key": key, "duplicate": False})
    return {"records": results}
