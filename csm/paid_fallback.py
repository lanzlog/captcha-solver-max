"""Paid captcha backends — optional safety net + A/B reference issuer.

Tier order when free browser fails (or when called directly for A/B):
  1. CapSolver   — CAPSOLVER_API_KEY  (AntiTurnstileTaskProxyLess + optional metadata)
  2. 2captcha    — TWOCAPTCHA_API_KEY (TurnstileTaskProxyless / TurnstileTask + action/data/pagedata)
  3. YesCaptcha  — YESCAPTCHA_API_KEY (comma-separated OK)

Supports challenge-mode fields for pure-API research:
  action, cdata (→ CapSolver metadata.cdata / 2cap data), pagedata (2cap only)

When proxy_url is provided, 2captcha/yescaptcha use TurnstileTask (proxy-bound);
CapSolver Turnstile stays ProxyLess (no proxy task type in their Turnstile docs).

Disabled automatically when no keys are present. Stdlib only.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.parse
import urllib.request
from urllib.parse import urlparse

log = logging.getLogger("paid_fallback")

_CAPSOLVER = "https://api.capsolver.com"
_TWOCAPTCHA = "https://api.2captcha.com"
_YESCAPTCHA = "https://api.yescaptcha.com"
_POLL_S = int(os.getenv("PAID_FALLBACK_POLL_S", "120"))
_POLL_EVERY = 5


def _capsolver_key() -> str | None:
    k = os.getenv("CAPSOLVER_API_KEY", "").strip()
    return k or None


def _twocaptcha_key() -> str | None:
    k = os.getenv("TWOCAPTCHA_API_KEY", "").strip()
    return k or None


def _yescaptcha_keys() -> list[str]:
    raw = os.getenv("YESCAPTCHA_API_KEY", "")
    return [k.strip() for k in raw.split(",") if k.strip()]


def available() -> dict:
    """Report which paid backends have keys configured (no secrets)."""
    return {
        "capsolver": bool(_capsolver_key()),
        "twocaptcha": bool(_twocaptcha_key()),
        "yescaptcha": bool(_yescaptcha_keys()),
    }


def _post_json(url: str, body: dict, timeout: int = 30) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def parse_proxy_url(proxy_url: str | None) -> dict | None:
    """Parse http://user:pass@host:port → 2captcha proxy fields."""
    if not proxy_url:
        return None
    p = urlparse(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
    if not p.hostname or not p.port:
        return None
    scheme = (p.scheme or "http").lower()
    if scheme not in ("http", "socks4", "socks5", "https"):
        scheme = "http"
    # 2captcha uses http/socks4/socks5; map https→http for auth proxy
    if scheme == "https":
        scheme = "http"
    out = {
        "proxyType": scheme,
        "proxyAddress": p.hostname,
        "proxyPort": int(p.port),
    }
    if p.username:
        out["proxyLogin"] = urllib.parse.unquote(p.username)
    if p.password:
        out["proxyPassword"] = urllib.parse.unquote(p.password)
    return out


def _task_for(
    provider: str,
    captcha_type: str,
    sitekey: str,
    pageurl: str,
    action: str | None,
    cdata: str | None,
    version: str | None,
    pagedata: str | None = None,
    proxy_url: str | None = None,
) -> dict:
    """Build provider-specific task object."""
    if captcha_type == "turnstile":
        if provider == "capsolver":
            # CapSolver only documents ProxyLess for Turnstile token task.
            task: dict = {
                "type": "AntiTurnstileTaskProxyLess",
                "websiteURL": pageurl,
                "websiteKey": sitekey,
            }
            meta = {}
            if action:
                meta["action"] = action
            if cdata:
                meta["cdata"] = cdata
            # CapSolver docs have no pagedata field for Turnstile; ignore if present
            if meta:
                task["metadata"] = meta
            return task

        # 2captcha / yescaptcha CapSolver-compat style
        proxy_fields = parse_proxy_url(proxy_url)
        if proxy_fields:
            task = {
                "type": "TurnstileTask",
                "websiteURL": pageurl,
                "websiteKey": sitekey,
                **proxy_fields,
            }
        else:
            task = {
                "type": "TurnstileTaskProxyless",
                "websiteURL": pageurl,
                "websiteKey": sitekey,
            }
        if action:
            task["action"] = action
        if cdata:
            task["data"] = cdata
        if pagedata:
            task["pagedata"] = pagedata
        return task

    if captcha_type == "hcaptcha":
        return {
            "type": "HCaptchaTaskProxyless",
            "websiteURL": pageurl,
            "websiteKey": sitekey,
        }

    if captcha_type == "recaptcha":
        if version == "v3":
            return {
                "type": "ReCaptchaV3TaskProxyLess" if provider == "capsolver"
                else "RecaptchaV3TaskProxyless",
                "websiteURL": pageurl,
                "websiteKey": sitekey,
                "pageAction": action or "verify",
                "minScore": 0.3,
            }
        ttype = ("ReCaptchaV2TaskProxyLess" if provider == "capsolver"
                 else "RecaptchaV2TaskProxyless")
        return {
            "type": ttype,
            "websiteURL": pageurl,
            "websiteKey": sitekey,
        }

    raise ValueError(f"paid fallback unsupported type: {captcha_type}")


def _extract_solution(sol: dict) -> tuple[str | None, dict]:
    """Return (token, extra meta: userAgent etc.)."""
    if not sol:
        return None, {}
    token = (
        sol.get("token")
        or sol.get("gRecaptchaResponse")
        or sol.get("cf_clearance")  # not turnstile but harmless
    )
    extra = {}
    if sol.get("userAgent"):
        extra["user_agent"] = sol["userAgent"]
    if sol.get("user_agent"):
        extra["user_agent"] = sol["user_agent"]
    return token, extra


async def _poll(base: str, client_key: str, task_id, poll_s: int) -> tuple[str | None, dict]:
    deadline = asyncio.get_event_loop().time() + poll_s
    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(_POLL_EVERY)
        try:
            rj = await asyncio.to_thread(
                _post_json, f"{base}/getTaskResult",
                {"clientKey": client_key, "taskId": task_id})
        except Exception as e:
            log.warning("poll error: %s", e)
            continue
        if rj.get("errorId") not in (0, None):
            log.warning("getTaskResult error: %s %s",
                        rj.get("errorCode"), rj.get("errorDescription"))
            return None, {}
        if rj.get("status") == "ready":
            sol = rj.get("solution") or {}
            return _extract_solution(sol)
    log.warning("poll timeout after %ss", poll_s)
    return None, {}


async def _solve_one(base: str, client_key: str, task: dict,
                     poll_s: int) -> tuple[str | None, dict]:
    try:
        cj = await asyncio.to_thread(
            _post_json, f"{base}/createTask",
            {"clientKey": client_key, "task": task})
    except Exception as e:
        log.warning("createTask failed: %s", e)
        return None, {}
    if cj.get("errorId") not in (0, None):
        log.warning("createTask error: %s %s",
                    cj.get("errorCode"), cj.get("errorDescription"))
        return None, {}
    task_id = cj.get("taskId")
    if not task_id:
        log.warning("createTask no taskId: %s", cj)
        return None, {}
    log.info("task created id=%s base=%s type=%s action=%s has_data=%s has_pagedata=%s has_proxy=%s",
             task_id, base, task.get("type"), task.get("action") or (task.get("metadata") or {}).get("action"),
             bool(task.get("data") or (task.get("metadata") or {}).get("cdata")),
             bool(task.get("pagedata")),
             bool(task.get("proxyAddress")))
    return await _poll(base, client_key, task_id, poll_s)


async def run_paid(
    captcha_type: str,
    sitekey: str,
    pageurl: str,
    *,
    action: str | None = None,
    cdata: str | None = None,
    pagedata: str | None = None,
    version: str | None = None,
    proxy_url: str | None = None,
    poll_s: int | None = None,
    prefer: str | None = None,
) -> dict:
    """Try CapSolver → 2captcha → YesCaptcha.

    prefer: force single backend 'capsolver'|'twocaptcha'|'yescaptcha' (A/B).
    proxy_url: if set, 2captcha/yescaptcha use TurnstileTask (proxy-bound mint).
    Returns {solved, token, method, usage, user_agent, proxy, error, task_type}.
    """
    poll = poll_s or _POLL_S
    backends: list[tuple[str, str, str]] = []  # name, base, key

    cs = _capsolver_key()
    tc = _twocaptcha_key()
    yks = _yescaptcha_keys()

    if prefer == "capsolver" and cs:
        backends = [("capsolver", _CAPSOLVER, cs)]
    elif prefer == "twocaptcha" and tc:
        backends = [("twocaptcha", _TWOCAPTCHA, tc)]
    elif prefer == "yescaptcha" and yks:
        backends = [("yescaptcha", _YESCAPTCHA, yks[0])]
    else:
        if cs:
            backends.append(("capsolver", _CAPSOLVER, cs))
        if tc:
            backends.append(("twocaptcha", _TWOCAPTCHA, tc))
        for yk in yks:
            backends.append(("yescaptcha", _YESCAPTCHA, yk))

    if not backends:
        return {
            "solved": False, "token": "", "method": "none",
            "usage": "unknown",
            "error": "no paid keys (CAPSOLVER_API_KEY / TWOCAPTCHA_API_KEY / YESCAPTCHA_API_KEY)",
        }

    last_err = "all paid backends failed"
    for name, base, key in backends:
        try:
            task = _task_for(
                name if name != "yescaptcha" else "yescaptcha",
                captcha_type, sitekey, pageurl,
                action, cdata, version,
                pagedata=pagedata,
                proxy_url=proxy_url if name != "capsolver" else None,
            )
        except ValueError as e:
            return {"solved": False, "token": "", "method": "paid",
                    "usage": "unknown", "error": str(e)}
        log.info("trying %s for %s task=%s", name, captcha_type, task.get("type"))
        token, extra = await _solve_one(base, key, task, poll)
        if token:
            return {
                "solved": True,
                "token": token,
                "method": name,
                "task_type": task.get("type"),
                "usage": "portable_claimed",
                "user_agent": extra.get("user_agent"),
                "proxy": proxy_url if task.get("proxyAddress") else None,
                "action": action,
                "error": None,
            }
        last_err = f"{name} failed task={task.get('type')}"

    return {"solved": False, "token": "", "method": "paid",
            "usage": "unknown", "error": last_err}
