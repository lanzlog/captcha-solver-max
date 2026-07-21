"""CSM engine runner — challenge execution for this vendor."""
import asyncio
import json
import logging
import re
import time

import cloakbrowser

from csm.browser import browser_kwargs

log = logging.getLogger(__name__)
_solve_lock = asyncio.Lock()

_DD_ENDPOINT = "api-js.datadome.co/js/"


def _kwargs(proxy: str = None) -> dict:
    kw = browser_kwargs("TURNSTILE")     # shares TURNSTILE_PROXY / _HEADLESS / _GEOIP
    if proxy:
        kw["proxy"] = proxy              # per-request override wins
    return kw


def _parse_dd_cookie(body: str) -> dict:
    """Parse {"status":200,"cookie":"datadome=VAL; Max-Age=...; Domain=...; ..."}.
    Returns {value, domain, max_age, raw, status} or {} when absent/failed."""
    try:
        data = json.loads(body)
    except Exception:
        return {}
    ck = data.get("cookie", "") or ""
    m = re.search(r"datadome=([^;]+)", ck)
    if not m:
        return {"status": data.get("status")}
    out = {"value": m.group(1), "status": data.get("status"), "raw": ck}
    dm = re.search(r"Domain=([^;]+)", ck)
    ma = re.search(r"Max-Age=([0-9]+)", ck)
    out["domain"] = dm.group(1) if dm else None
    out["max_age"] = int(ma.group(1)) if ma else None
    return out


async def run_dd(url: str = None, referer: str = None,
                         proxy: str = None, timeout_s: int = 60) -> dict:
    """Harvest a DataDome clearance cookie.

    url     : REQUIRED. The DataDome-fronted page/iframe that loads tags.js. The caller
              builds this (including any site-specific query params like origin_page).
    referer : optional framing Referer so DataDome serves the same config/scoring as the
              real flow (the caller supplies its own site's referer, e.g. github.com).
    proxy   : REQUIRED for a usable token — the cookie is bound to the exit IP.
    """
    t0 = time.monotonic()
    if not url:
        return {"success": False, "method": "datadome-silent-pass",
                "error": "url is required (the DataDome-fronted page that loads tags.js)"}

    captured: dict = {"cookie": None, "endpoint_status": None, "raw_json": None}

    async with _solve_lock:
        async with await cloakbrowser.launch_async(**_kwargs(proxy)) as browser:
            ctx = await browser.new_context()
            page = await ctx.new_page()

            async def on_response(resp):
                if _DD_ENDPOINT in resp.url and resp.request.method == "POST":
                    try:
                        body = await resp.text()
                        captured["raw_json"] = body[:500]
                        parsed = _parse_dd_cookie(body)
                        captured["endpoint_status"] = parsed.get("status")
                        if parsed.get("value"):
                            captured["cookie"] = parsed
                    except Exception as e:
                        captured["resp_err"] = str(e)

            page.on("response", lambda r: asyncio.create_task(on_response(r)))
            if referer:  # match the framing Referer so DataDome scores the same config
                await page.set_extra_http_headers({"Referer": referer})

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=45000)
            except Exception as e:
                log.warning("datadome goto: %s", e)

            deadline = time.monotonic() + timeout_s
            while time.monotonic() < deadline and not captured["cookie"]:
                await asyncio.sleep(1)

            ua = await page.evaluate("() => navigator.userAgent")
            ck = captured["cookie"] or {}
            result = {
                "datadome_cookie": ck.get("value"),
                "cookie_domain": ck.get("domain"),
                "cookie_max_age": ck.get("max_age"),
                "endpoint_status": captured["endpoint_status"],
                "success": bool(ck.get("value")),
                "user_agent": ua,
                "proxy": proxy or None,
                "method": "datadome-silent-pass",
                "elapsed": round(time.monotonic() - t0, 1),
                "warning": ("datadome cookie is IP + UA bound. Replay ONLY from the same "
                            "proxy IP with this exact User-Agent, as Cookie: "
                            "datadome=<value> on the protected request."),
            }
            if not ck.get("value"):
                result["error"] = ("no datadome cookie (endpoint_status="
                                   f"{captured['endpoint_status']}); DataDome may have "
                                   "returned a challenge — check raw_json")
                result["raw_json"] = captured["raw_json"]
            await page.close()
            return result
