"""HTTP client for the GPL hcaptcha-challenger sidecar.

LICENSE: this file is MIT (captcha-solver-max). It only speaks HTTP to a
separate process — no GPL imports, no GPL source.

Env:
  HCAPTCHA_SIDECAR_URL      default http://127.0.0.1:8878
  HCAPTCHA_SIDECAR_FALLBACK 1 = after free vision fails, try sidecar
  HCAPTCHA_SIDECAR_TIMEOUT  client timeout seconds (default 200)
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

log = logging.getLogger(__name__)

_DEFAULT_URL = "http://127.0.0.1:8878"


def sidecar_enabled() -> bool:
    return os.getenv("HCAPTCHA_SIDECAR_FALLBACK", "0").strip() in ("1", "true", "yes", "on")


def sidecar_first() -> bool:
    """If true, try GPL sidecar before free vision path (adversarial grids)."""
    return os.getenv("HCAPTCHA_SIDECAR_FIRST", "0").strip() in ("1", "true", "yes", "on")


def sidecar_base() -> str:
    return (os.getenv("HCAPTCHA_SIDECAR_URL") or _DEFAULT_URL).rstrip("/")


def sidecar_health(timeout: float = 5.0) -> dict[str, Any]:
    url = f"{sidecar_base()}/health"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"status": "down", "error": str(e)[:120]}


def run_via_sidecar(
    sitekey: str,
    url: str | None = None,
    timeout_s: float | None = None,
    proxy: str | None = None,
) -> dict[str, Any]:
    """POST /solve on the GPL sidecar. Returns dict with token/error.

    Never raises for business failures — returns {error: ...}.
    """
    base = sidecar_base()
    client_to = float(timeout_s or os.getenv("HCAPTCHA_SIDECAR_TIMEOUT", "200"))
    body: dict[str, Any] = {"sitekey": sitekey, "timeout_s": client_to}
    if url:
        body["url"] = url
    if proxy:
        body["proxy"] = proxy

    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{base}/solve",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=client_to + 40) as r:
            out = json.loads(r.read().decode())
            if not isinstance(out, dict):
                return {"error": "sidecar bad response", "elapsed": 0}
            # normalize
            if out.get("token") and "solved" not in out:
                out["solved"] = True
            out.setdefault("method", "gpl-sidecar")
            return out
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:200]
        except Exception:
            pass
        log.warning("sidecar HTTP %s: %s", e.code, detail[:120])
        return {"error": f"sidecar HTTP {e.code}: {detail}", "elapsed": 0}
    except Exception as e:
        log.warning("sidecar call failed: %s", e)
        return {"error": f"sidecar: {e}", "elapsed": 0}
