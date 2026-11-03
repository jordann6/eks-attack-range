"""
summarizer — a DELIBERATELY VULNERABLE web app for the EKS Attack Range lab.

DO NOT deploy this anywhere but the isolated lab. It is vulnerable BY DESIGN,
the same way DVWA or OWASP Juice Shop are, so the kill chain has something real
to exploit. It ships three planted weaknesses, each tied to one step of the
attack:

  1. Secret in env         ANTHROPIC_API_KEY read straight from the environment,
                           injected from a plaintext Kubernetes Secret. This is
                           the trophy the attacker exfiltrates.
  2. SSRF (/summarize)     Fetches any caller-supplied URL server-side with no
                           allow-list, so a request can reach 169.254.169.254
                           and read the EC2 node's IMDS credentials.
  3. Command injection     /tools/diagnose shells out with the caller's input,
     (/tools/diagnose)     giving remote code execution inside the pod (the
                           initial foothold).

The blue-team overlay in ../defend replaces this with the keyless Bedrock
pattern from aws-golden-path-copilot and removes all three weaknesses.
"""
from __future__ import annotations

import os
import subprocess
import urllib.request

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="summarizer (LAB, vulnerable by design)")

# WEAKNESS 1: the key lives in the environment, injected from a plaintext k8s
# Secret. Anyone with RCE in this pod, or read on the Secret, walks away with it.
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")


class SummarizeRequest(BaseModel):
    url: str


@app.get("/healthz")
def healthz():
    return {"status": "ok", "key_loaded": bool(ANTHROPIC_API_KEY)}


@app.post("/summarize")
def summarize(req: SummarizeRequest):
    """Fetch a URL and 'summarize' it.

    WEAKNESS 2 (SSRF): the URL is fetched server-side with no scheme or host
    allow-list. Point it at http://169.254.169.254/latest/meta-data/iam/
    security-credentials/ to read the node instance-profile credentials. In a
    real app this is where the content would go to Claude; here we just return
    what we fetched so the lab can show the metadata response.
    """
    try:
        with urllib.request.urlopen(req.url, timeout=5) as resp:  # noqa: S310 (intentional)
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
