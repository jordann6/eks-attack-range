"""
summarizer (HARDENED) — the fixed application image for the EKS Attack Range lab.

This is the code-level half of the blue team. The baseline image in ../main.py
keeps all three planted weaknesses on purpose; this image removes them in code,
so the hardened run proves the fix at the application layer, not only with
Kubernetes and cloud controls:

  1. No secret in env       There is no API key in this image. The keyless path
                            is assumed (short-lived STS/Bedrock via IRSA), so the
                            pod holds nothing to exfiltrate.
  2. No SSRF (/summarize)   The outbound fetch targets ONE fixed, operator-set
                            upstream (SUMMARY_UPSTREAM). The caller cannot set the
                            URL, method or headers, so the request can never be
                            steered at 169.254.169.254.
  3. No command injection   /tools/diagnose validates the host as a literal IP or
     (/tools/diagnose)      DNS name and runs ping with an argument vector and no
                            shell, so caller input is never handed to a shell.

The deployment that runs this image is produced by the ../../defend/hardened
kustomize overlay (non-root, restricted PodSecurity, no SA token, no binding).
Code fixes here plus those cluster controls are the full hardened posture.
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import urllib.request

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="summarizer (LAB, hardened)")

# The one upstream this app is allowed to reach. Operator-set, never caller-set.
# Defaults to the in-cluster lab receiver; there is no way for a request to
# change it, so the SSRF-to-IMDS path in the baseline is closed in code.
SUMMARY_UPSTREAM = os.environ.get(
    "SUMMARY_UPSTREAM", "http://receiver.summarizer.svc.cluster.local:80/fetch"
)

# A DNS label per RFC 1123, or a dotted/colon IP literal. Anything else is
# rejected before it reaches ping. No shell metacharacters survive this.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class SummarizeRequest(BaseModel):
    # Only the text to summarize. No url/method/headers: the upstream is fixed.
    text: str = ""


@app.get("/healthz")
def healthz():
    # No key to report: the hardened image holds no static credential.
    return {"status": "ok", "hardened": True}


@app.post("/summarize")
def summarize(req: SummarizeRequest):
    """Summarize text via the one fixed, operator-set upstream.

    FIX (SSRF): the caller supplies only text. The URL, method and headers are
    not caller-controlled, so a request can never be pointed at the instance
    metadata endpoint or any other host. Only SUMMARY_UPSTREAM is ever fetched.
    """
    try:
        r = urllib.request.Request(  # noqa: S310 (fixed, operator-set host)
            SUMMARY_UPSTREAM,
            data=req.text.encode("utf-8")[:4096],
            method="POST",
            headers={"content-type": "text/plain"},
        )
        with urllib.request.urlopen(r, timeout=5) as resp:  # noqa: S310
            body = resp.read(4096).decode("utf-8", "replace")
        return {"upstream": SUMMARY_UPSTREAM, "body": body}
    except Exception as exc:  # noqa: BLE001 (lab)
        return {"upstream": SUMMARY_UPSTREAM, "error": str(exc)}


def _valid_host(host: str) -> bool:
    """A host is valid only if it is an IP literal or a DNS name. No metachars."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(host))


@app.get("/tools/diagnose")
def diagnose(host: str = "127.0.0.1"):
    """Network diagnostic helper.

    FIX (command injection): the host is validated as a literal IP or DNS name,
    then ping is run with an argument vector and shell=False, so caller input is
    never parsed by a shell. `?host=127.0.0.1;id` is rejected with 400.
    """
    if not _valid_host(host):
        raise HTTPException(status_code=400, detail="host must be an IP or DNS name")
    out = subprocess.run(  # noqa: S603 (argument vector, no shell)
        ["ping", "-c", "1", host], capture_output=True, text=True, timeout=10
    )
    return {"cmd": f"ping -c 1 {host}", "stdout": out.stdout, "stderr": out.stderr}
