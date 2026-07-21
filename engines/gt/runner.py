"""CSM engine runner — challenge execution for this vendor."""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional

log = logging.getLogger("geetest")

_SUPPORTED_RISKS = ("slide", "icon", "gobang", "winlinze", "ai", "invisible")


def run_gt(
    captcha_id: str,
    risk_type: str = "slide",
    proxy: Optional[str] = None,
    timeout_s: int = 60,
) -> dict[str, Any]:
    """Solve Geetest v4 via pure HTTP protocol.

    Args:
        captcha_id: public captcha id (from page / network `verify` request)
        risk_type: slide | icon | gobang | winlinze | ai | invisible
        proxy: optional http(s) proxy URL for curl_cffi
        timeout_s: soft deadline (best-effort; underlying client uses per-request timeouts)
    """
    captcha_id = (captcha_id or "").strip()
    risk_type = (risk_type or "slide").strip().lower()
    if not captcha_id:
        return {
            "solved": False, "token": "", "method": "geetest_v4",
            "error": "captcha_id required", "risk_type": risk_type,
        }
    if risk_type not in _SUPPORTED_RISKS:
        return {
            "solved": False, "token": "", "method": "geetest_v4",
            "error": f"unsupported risk_type={risk_type}; use one of {_SUPPORTED_RISKS}",
            "risk_type": risk_type,
        }

    t0 = time.time()
    try:
        # Prefer vendored package path
        from engines.gt.gtproto import GtClient
    except Exception:
        try:
            from .gtproto import GtClient
        except Exception as e:
            return {
                "solved": False, "token": "", "method": "geetest_v4",
                "error": f"gtc import failed: {e}", "risk_type": risk_type,
            }

    kwargs: dict[str, Any] = {"verify": False}
    if proxy:
        # curl_cffi Session accepts proxy=str or proxies=dict
        kwargs["proxy"] = proxy
    # allow env override
    if not proxy:
        env_p = os.getenv("GEETEST_PROXY") or os.getenv("SOLVER_PROXY")
        if env_p:
            kwargs["proxy"] = env_p

    try:
        gtc = GtClient(captcha_id, risk_type, **kwargs)
        seccode = gtproto.solve()
    except NotImplementedError as e:
        return {
            "solved": False, "token": "", "method": "geetest_v4",
            "error": str(e), "risk_type": risk_type,
            "elapsed_s": round(time.time() - t0, 2),
        }
    except Exception as e:
        log.warning("geetest solve failed captcha_id=%s risk=%s: %s",
                    captcha_id[:12], risk_type, e)
        return {
            "solved": False, "token": "", "method": "geetest_v4",
            "error": str(e)[:300], "risk_type": risk_type,
            "elapsed_s": round(time.time() - t0, 2),
        }

    # seccode is typically a dict with captcha_id, lot_number, pass_token, ...
    if not isinstance(seccode, dict):
        return {
            "solved": False, "token": str(seccode or ""),
            "method": "geetest_v4", "error": "unexpected seccode type",
            "risk_type": risk_type, "raw": seccode,
            "elapsed_s": round(time.time() - t0, 2),
        }

    pass_token = seccode.get("pass_token") or seccode.get("captcha_output") or ""
    ok = bool(pass_token or seccode.get("lot_number"))
    return {
        "solved": ok,
        "token": pass_token if isinstance(pass_token, str) else str(pass_token),
        "method": "geetest_v4",
        "error": None if ok else "empty seccode",
        "risk_type": risk_type,
        "captcha_id": seccode.get("captcha_id") or captcha_id,
        "lot_number": seccode.get("lot_number"),
        "pass_token": seccode.get("pass_token"),
        "gen_time": seccode.get("gen_time"),
        "captcha_output": seccode.get("captcha_output"),
        "seccode": seccode,
        "elapsed_s": round(time.time() - t0, 2),
    }
