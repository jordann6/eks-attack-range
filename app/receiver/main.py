"""
receiver — the in-cluster lab receiver for the EKS Attack Range trophy.

This replaces the old trophy of a real throwaway Anthropic key revoked by hand
in a vendor console. Instead the lab mints a synthetic canary token per run and
stores it in the summarizer-key Secret. This service is the only thing that
accepts that token.

Two roles:

  * It is the fixed upstream the HARDENED summarizer fetches on /summarize, so
    the hardened app has a real, controlled host to reach (POST /fetch).

  * It is the trophy oracle (POST /v1/messages). It accepts a request ONLY when
    the x-api-key header equals the canary token minted for this run. The red
    team proves the stolen Secret is a usable credential by getting a 200 here,
    and every use is logged with the caller marker, so the token is observably a
    canary. Nothing real is ever exposed, and there is no external service and
    no console step.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="lab receiver (canary oracle + fixed upstream)")

# The synthetic canary token for this run, injected from the same Secret the
# summarizer mounts. Empty means "no token configured": every auth attempt then
# fails closed rather than accepting anything.
CANARY_TOKEN = os.environ.get("CANARY_TOKEN", "")


class FetchBody(BaseModel):
    pass


@app.get("/healthz")
def healthz():
    return {"status": "ok", "canary_configured": bool(CANARY_TOKEN)}


@app.post("/fetch")
async def fetch():
    # The hardened summarizer's one allowed upstream. Returns a canned summary so
    # the hardened /summarize path has something real to return.
    return {"summary": "lab receiver: upstream reached", "ok": True}


@app.post("/v1/messages")
def messages(x_api_key: str = Header(default="")):
    """Trophy oracle. 200 only if the caller presents this run's canary token.

    A 200 here is the proof that the exfiltrated Secret is a working credential.
    The use is logged so the token is observably a canary, not a real key.
    """
    if not CANARY_TOKEN or x_api_key != CANARY_TOKEN:
        raise HTTPException(status_code=401, detail="invalid canary token")
    marker = x_api_key[:8]
    print(f"CANARY_USED token_prefix={marker} — synthetic trophy token presented", flush=True)
    return {"accepted": True, "note": "synthetic canary token accepted", "token_prefix": marker}
