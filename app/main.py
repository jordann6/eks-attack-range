"""
summarizer — a DELIBERATELY VULNERABLE web app for the EKS Attack Range lab.

DO NOT deploy this anywhere but the isolated lab. It is vulnerable BY DESIGN,
the same way DVWA or OWASP Juice Shop are, so the kill chain has something real
to exploit. It ships three planted weaknesses, each tied to one step of the
attack:

  1. Secret in env         CANARY_TOKEN read straight from the environment,
                           injected from a plaintext Kubernetes Secret. This is
                           the trophy the attacker exfiltrates. It is a SYNTHETIC
                           canary minted per run, accepted only by the in-cluster
                           lab receiver, so nothing real is ever exposed.
  2. SSRF (/summarize)     Fetches any caller-supplied URL server-side with no
                           allow-list, so a request can reach 169.254.169.254
                           and read the EC2 node's IMDS credentials.
  3. Command injection     /tools/diagnose shells out with the caller's input,
     (/tools/diagnose)     giving remote code execution inside the pod (the
                           initial foothold).

The hardened image in ./hardened/main.py removes all three weaknesses in code,
and the ../defend/hardened overlay adds the cluster-side controls on top.
"""
from __future__ import annotations

import os
import subprocess
import urllib.request

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="summarizer (LAB, vulnerable by design)")

# WEAKNESS 1: the trophy lives in the environment, injected from a plaintext k8s
# Secret. Anyone with RCE in this pod, or read on the Secret, walks away with it.
# The value is a synthetic per-run canary token, not a real vendor key.
CANARY_TOKEN = os.environ.get("CANARY_TOKEN", "")


class SummarizeRequest(BaseModel):
    url: str
    # Caller-controlled method and headers make this a full SSRF proxy. That is
    # realistic (plenty of "fetch this URL" features let the method or headers
    # through) and it is what lets the attack complete the IMDSv2 token handshake
    # against 169.254.169.254, which a GET-only SSRF could not do.
    method: str = "GET"
    headers: dict[str, str] = {}


@app.get("/healthz")
def healthz():
    return {"status": "ok", "token_loaded": bool(CANARY_TOKEN)}


@app.post("/summarize")
def summarize(req: SummarizeRequest):
    """Fetch a URL and 'summarize' it.

    WEAKNESS 2 (SSRF): the URL is fetched server-side with no scheme or host
    allow-list, and the method and headers are caller-controlled. Do the IMDSv2
    dance: PUT http://169.254.169.254/latest/api/token with the ttl header to get
    a token, then GET the security-credentials path with that token to read the
    node instance-profile credentials. In a real app this is where the content
    would go to Claude; here we return what we fetched so the lab can show it.
    """
    try:
        r = urllib.request.Request(req.url, method=req.method)  # noqa: S310 (intentional)
        for key, value in req.headers.items():
            r.add_header(key, value)
        with urllib.request.urlopen(r, timeout=5) as resp:  # noqa: S310 (intentional)
            body = resp.read(4096).decode("utf-8", "replace")
        return {"fetched": req.url, "body": body}
    except Exception as exc:  # noqa: BLE001 (lab)
        return {"fetched": req.url, "error": str(exc)}


@app.get("/tools/diagnose")
def diagnose(host: str = "127.0.0.1"):
    """'Network diagnostic' helper.

    WEAKNESS 3 (command injection): host is passed to a shell unsanitised, so
    `?host=127.0.0.1;id` runs arbitrary commands in the pod. This is the initial
    RCE foothold, the cloud analogue of the video's reverse shell.
    """
    out = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=10
    )
    return {"cmd": f"ping -c 1 {host}", "stdout": out.stdout, "stderr": out.stderr}
