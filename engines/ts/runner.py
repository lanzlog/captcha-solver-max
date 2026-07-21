"""CSM engine runner — challenge execution for this vendor."""
from __future__ import annotations

import asyncio
import re
import json
import logging
import os
import time
from pathlib import Path

import cloakbrowser

from csm.browser import (
    browser_kwargs,
    run_pre_actions,
    run_post_fetch,
    fetch_from_page,
    route_glob,
)

log = logging.getLogger(__name__)
def _max_concurrent() -> int:
    """Bounded browser concurrency (paid solvers run many in parallel)."""
    try:
        n = int(os.getenv("TURNSTILE_MAX_CONCURRENT", "2"))
    except ValueError:
        n = 2
    return max(1, min(n, 8))


_solve_sem = asyncio.Semaphore(_max_concurrent())
# back-compat alias if anything imports _solve_lock
_solve_lock = _solve_sem


# ── Browser pool (cut cold launch ~1s when proxy matches) ─────────────
# Token IP-binding requires same proxy on the leased browser. We key by
# (proxy, headless, humanize). Disable with TURNSTILE_BROWSER_POOL=0.


def _pool_enabled() -> bool:
    return os.getenv("TURNSTILE_BROWSER_POOL", "1") != "0"


def _pool_max() -> int:
    try:
        n = int(os.getenv("TURNSTILE_BROWSER_POOL_SIZE", "0"))
    except ValueError:
        n = 0
    if n <= 0:
        n = _max_concurrent()
    return max(1, min(n, 8))


_pool_lock = asyncio.Lock()
_pool_idle: dict[tuple, list] = {}  # key -> [browser, ...]
_pool_live = 0


def _pool_key(bkw: dict) -> tuple:
    return (
        bkw.get("proxy") or "",
        bool(bkw.get("headless", True)),
        bool(bkw.get("humanize", False)),
        bool(bkw.get("geoip", False)),
    )


async def _browser_pool_acquire(bkw: dict):
    """Return (browser, from_pool: bool). Caller must release/close."""
    global _pool_live
    if not _pool_enabled():
        browser = await cloakbrowser.launch_async(**bkw)
        return browser, False
    key = _pool_key(bkw)
    async with _pool_lock:
        stack = _pool_idle.get(key) or []
        while stack:
            browser = stack.pop()
            try:
                # cheap liveness: contexts list
                _ = browser.contexts
                _pool_idle[key] = stack
                log.info("browser pool hit key_proxy=%s idle_left=%d",
                         (key[0].split("@")[-1] if key[0] else "none")[:40],
                         len(stack))
                return browser, True
            except Exception:
                _pool_live = max(0, _pool_live - 1)
                try:
                    await browser.close()
                except Exception:
                    pass
        _pool_idle[key] = stack
        # bound live launches to pool max * 2 (in-flight + idle)
        if _pool_live >= _pool_max() * 2:
            log.warning("browser pool live high=%d — still launching", _pool_live)
        _pool_live += 1
    browser = await cloakbrowser.launch_async(**bkw)
    log.info("browser pool miss launch live=%d", _pool_live)
    return browser, True  # pool-managed (must release via pool)




def browser_pool_stats() -> dict:
    idle_n = sum(len(v) for v in _pool_idle.values())
    return {
        "enabled": _pool_enabled(),
        "max": _pool_max(),
        "idle": idle_n,
        "live": _pool_live,
        "keys": len(_pool_idle),
    }


class _PooledBrowser:
    """Async CM: pool-aware CloakBrowser lease."""

    def __init__(self, bkw: dict):
        self.bkw = bkw
        self.browser = None
        self._from_pool = False

    async def __aenter__(self):
        self.browser, self._from_pool = await _browser_pool_acquire(self.bkw)
        return self.browser

    async def __aexit__(self, exc_type, exc, tb):
        await _browser_pool_release(self.browser, self.bkw, self._from_pool)
        self.browser = None
        return False


async def _browser_pool_release(browser, bkw: dict, from_pool: bool) -> None:
    global _pool_live
    if not from_pool or not _pool_enabled():
        try:
            await browser.close()
        except Exception:
            pass
        return
    # close leftover pages/contexts except keep browser process
    try:
        for ctx in list(browser.contexts):
            try:
                await ctx.close()
            except Exception:
                pass
    except Exception:
        try:
            await browser.close()
        except Exception:
            pass
        async with _pool_lock:
            _pool_live = max(0, _pool_live - 1)
        return

    key = _pool_key(bkw)
    async with _pool_lock:
        stack = _pool_idle.setdefault(key, [])
        # total idle across keys + keep under pool max
        idle_n = sum(len(v) for v in _pool_idle.values())
        if idle_n < _pool_max():
            stack.append(browser)
            log.info("browser pool store key_proxy=%s idle=%d live=%d",
                     (key[0].split("@")[-1] if key[0] else "none")[:40],
                     idle_n + 1, _pool_live)
            return
    # pool full — close
    try:
        await browser.close()
    except Exception:
        pass
    async with _pool_lock:
        _pool_live = max(0, _pool_live - 1)
_TEMPLATE_PATH = Path(__file__).parent / "template.html"
HTML_TEMPLATE = _TEMPLATE_PATH.read_text()

# Explicit-render page: callback writes token → #tok / window.__ts_token
EXPLICIT_HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Turnstile</title>
<style>body{margin:0;background:#1a1a1a;display:flex;justify-content:center;align-items:center;min-height:100vh}</style>
</head><body>
<div id="cf-widget"></div>
<input type="hidden" name="cf-turnstile-response" id="tok" value=""/>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit" async defer></script>
<script>
window.__ts_token = '';
window.__ts_err = null;
window.__ts_sitekey = __SITEKEY__;
window.__ts_action = __ACTION__;
window.__ts_cdata = __CDATA__;
window.__ts_size = __SIZE__;
function __boot(){
  if (!window.turnstile) { setTimeout(__boot, 100); return; }
  var opts = {
    sitekey: window.__ts_sitekey,
    callback: function(t){ window.__ts_token = t || ''; document.getElementById('tok').value = t || ''; },
    'error-callback': function(e){ window.__ts_err = String(e); },
    'expired-callback': function(){ window.__ts_token = ''; document.getElementById('tok').value = ''; },
    theme: 'auto'
  };
  if (window.__ts_action) opts.action = window.__ts_action;
  if (window.__ts_cdata) opts.cData = window.__ts_cdata;
  if (window.__ts_size) opts.size = window.__ts_size;
  try { turnstile.render('#cf-widget', opts); } catch (e) { window.__ts_err = String(e); }
}
__boot();
</script>
</body></html>
"""



def _classify_token(token: str) -> str:
    """Rough token class for consumers (not a security claim)."""
    if not token:
        return "empty"
    if token.startswith("XXXX.DUMMY") or token == "XXXX.DUMMY.TOKEN.XXXX":
        return "cf_testing_dummy"
    # Production Turnstile tokens are long and typically version-prefixed.
    if (token.startswith("0.") or token.startswith("1.")) and len(token) >= 100:
        return "turnstile_v0"
    if len(token) >= 200:
        return "opaque_long"
    return "reject_not_turnstile"


def _is_plausible_turnstile_token(token: str) -> bool:
    """Reject dashboard junk (short base64 session blobs) that is not a Turnstile token."""
    if not token:
        return False
    if token.startswith("XXXX.DUMMY") or token == "XXXX.DUMMY.TOKEN.XXXX":
        return True
    # Real tokens observed: ~700-900 chars, often start with 0. or 1.
    if (token.startswith("0.") or token.startswith("1.")) and len(token) >= 100:
        return True
    # Some sites return long opaque tokens without version prefix
    if len(token) >= 200 and "." in token:
        return True
    return False



def _pack_result(token: str, method: str, extra: dict) -> dict:
    out = {
        "token": token,
        "token_class": _classify_token(token),
        "method": method,
        "usage": _usage_for_method(method),
        **extra,
    }
    return out


def _usage_for_method(method: str) -> str:
    """Honest consumer contract: local mint is session-class unless proven portable."""
    if method in ("route", "real-page", "real_page", "explicit"):
        return "same_session_only"
    return "unknown"


def _browser_kwargs(proxy: str | None = None, sticky_key: str | None = None) -> dict:
    """Prefer explicit proxy; else sticky/rotate pool. Default headful (xvfb).

    humanize: default OFF for speed (TURNSTILE_HUMANIZE=1 to enable). Phase timing
    showed managed click path faster without humanize; stealth still via CloakBrowser.
    """
    # Code default 0 = headful; env TURNSTILE_HEADLESS=1 forces headless.
    headless = os.getenv("TURNSTILE_HEADLESS", "0") != "0"
    humanize = os.getenv("TURNSTILE_HUMANIZE", "0") == "1"
    if proxy:
        return {"humanize": humanize, "headless": headless, "proxy": proxy, "geoip": True}
    kw = browser_kwargs("TURNSTILE", sticky_key=sticky_key)
    # Force our headless policy (browser_kwargs historically defaulted TURNSTILE headless=1)
    kw["headless"] = headless
    kw["humanize"] = os.getenv("TURNSTILE_HUMANIZE", "0") == "1"
    if kw.get("proxy"):
        kw["geoip"] = True
    return kw


def _error_codes(body: str) -> list:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return []
    return data.get("error-codes") or data.get("details") or []


def _explicit_page(sitekey: str, action: str | None = None, cdata: str | None = None,
                   size: str | None = None) -> str:
    def js_str(v: str | None) -> str:
        if v is None or v == "":
            return "null"
        return json.dumps(v)

    return (
        EXPLICIT_HTML
        .replace("__SITEKEY__", js_str(sitekey))
        .replace("__ACTION__", js_str(action))
        .replace("__CDATA__", js_str(cdata))
        .replace("__SIZE__", js_str(size))
    )




async def _attach_token_sniffer(page) -> None:
    """Best-effort network token sniffer → window.__ts_net_token / __ts_token."""

    async def _on_response(resp):
        try:
            url = resp.url or ""
            if "challenges.cloudflare.com" not in url and "turnstile" not in url:
                return
            headers = resp.headers or {}
            ct = (headers.get("content-type") or "").lower()
            if not any(x in ct for x in ("json", "text", "javascript")):
                return
            if resp.status != 200:
                return
            body = await resp.text()
            if not body or len(body) > 20000:
                return
            m = re.search(r"\b([01]\.[A-Za-z0-9_\-]{100,})\b", body)
            if not m:
                m = re.search(r'"token"\s*:\s*"([^"]{100,})"', body)
            if not m:
                return
            tok = m.group(1)
            if _is_plausible_turnstile_token(tok):
                try:
                    await page.evaluate(
                        "(t) => { window.__ts_net_token = t; "
                        "if (!window.__ts_token) window.__ts_token = t; }",
                        tok,
                    )
                except Exception:
                    pass
        except Exception:
            return

    try:
        page.on("response", lambda r: asyncio.create_task(_on_response(r)))
    except Exception:
        pass



async def _wait_token(page, timeout_s: float = 15.0) -> str:
    """Tight poll of token sinks (callback / fields / net sniffer).

    Prefer evaluate-loop over wait_for_function — the latter was observed to
    burn full timeouts (~10s) even when a subsequent harvest would succeed,
    stacking managed mints to ~18s.
    """
    timeout_s = max(0.3, float(timeout_s))
    deadline = time.monotonic() + timeout_s
    js = """() => {
      const ok = (t) => {
        if (!t || typeof t !== 'string') return false;
        if (t.startsWith('XXXX.DUMMY')) return true;
        if ((t.startsWith('0.') || t.startsWith('1.')) && t.length >= 100) return true;
        if (t.length >= 200 && t.includes('.')) return true;
        return false;
      };
      const sinks = [];
      try {
        const a = document.querySelector('[name=cf-turnstile-response]');
        if (a && ok(a.value)) sinks.push(a.value);
      } catch (e) {}
      try {
        const b = document.querySelector('[name=g-recaptcha-response]');
        if (b && ok(b.value)) sinks.push(b.value);
      } catch (e) {}
      if (ok(window.__ts_token)) sinks.push(window.__ts_token);
      if (ok(window.__ts_net_token)) sinks.push(window.__ts_net_token);
      try {
        if (window.turnstile && turnstile.getResponse) {
          const t = turnstile.getResponse();
          if (ok(t)) sinks.push(t);
        }
      } catch (e) {}
      sinks.sort((a,b) => b.length - a.length);
      return sinks[0] || '';
    }"""
    while time.monotonic() < deadline:
        try:
            token = await page.evaluate(js)
        except Exception:
            token = ""
        if token and _is_plausible_turnstile_token(token):
            return token
        await asyncio.sleep(0.12)
    return ""



async def _harvest_token(page, max_wait_s: float = 45.0) -> str:
    """Poll multiple token sinks until a *plausible Turnstile* token appears."""
    deadline = time.monotonic() + max(1.0, max_wait_s)
    js = """() => {
      const ok = (t) => {
        if (!t || typeof t !== 'string') return false;
        if (t.startsWith('XXXX.DUMMY')) return true;
        if ((t.startsWith('0.') || t.startsWith('1.')) && t.length >= 100) return true;
        if (t.length >= 200 && t.includes('.')) return true;
        return false;
      };
      const sinks = [];
      const byName = document.querySelector('[name=cf-turnstile-response]');
      if (byName && ok(byName.value)) sinks.push(byName.value);
      const byG = document.querySelector('[name=g-recaptcha-response]');
      if (byG && ok(byG.value)) sinks.push(byG.value);
      if (ok(window.__ts_token)) sinks.push(window.__ts_token);
      try {
        if (window.turnstile && turnstile.getResponse) {
          const t = turnstile.getResponse();
          if (ok(t)) sinks.push(t);
        }
      } catch (e) {}
      // Prefer named turnstile fields only — do NOT vacuum arbitrary long hiddens
      // (CF dash pages stash short base64 blobs that are NOT turnstile tokens).
      sinks.sort((a,b) => b.length - a.length);
      return sinks[0] || '';
    }"""
    while time.monotonic() < deadline:
        try:
            token = await page.evaluate(js)
        except Exception:
            token = ""
        if token and _is_plausible_turnstile_token(token):
            return token
        await asyncio.sleep(0.25)
    return ""


async def _human_click_iframe(page, fr) -> bool:
    try:
        el = await fr.frame_element()
        box = await el.bounding_box()
    except Exception:
        return False
    if not box or box["width"] < 20:
        return False
    # checkbox is near left edge of the widget
    x = box["x"] + min(30, max(12, box["width"] * 0.15))
    y = box["y"] + box["height"] / 2
    await page.mouse.move(x, y)
    await asyncio.sleep(0.02 + 0.03 * (time.time() % 1))
    await page.mouse.click(x, y)
    return True


async def _click_turnstile_checkbox(page, attempts: int = 15) -> bool:
    for _ in range(attempts):
        for fr in page.frames:
            if "challenges.cloudflare.com" in (fr.url or ""):
                if await _human_click_iframe(page, fr):
                    return True
                for sel in ("input[type=checkbox]", "label", "body"):
                    try:
                        await fr.click(sel, timeout=700)
                        return True
                    except Exception:
                        continue
        # also try host widget
        try:
            await page.click(".cf-turnstile, [data-sitekey]", timeout=600)
            return True
        except Exception:
            pass
        await asyncio.sleep(0.15)
    return False



async def _wait_challenge_frame(page, timeout_s: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for fr in page.frames:
            if "challenges.cloudflare.com" in (fr.url or ""):
                return True
        # widget may auto-solve without durable frame url
        try:
            n = await page.evaluate(
                "() => document.querySelectorAll('iframe').length"
            )
            if n:
                return True
        except Exception:
            pass
        await asyncio.sleep(0.12)
    return False


async def _page_meta(page) -> dict:
    ua = None
    try:
        ua = await page.evaluate("() => navigator.userAgent")
    except Exception:
        pass
    cookies = []
    try:
        cookies = await page.context.cookies()
    except Exception:
        pass
    clearance = None
    for c in cookies:
        if c.get("name") == "cf_clearance":
            clearance = c
            break
    return {"user_agent": ua, "cookies": cookies, "cf_clearance": clearance}


# ── Route-intercept (Theyka-style auto widget) ──────────────────────

async def _get_turnstile_response_route(page, max_attempts: int = 30) -> str:
    for i in range(max_attempts):
        try:
            token = await _harvest_token(page, max_wait_s=1.0)
            if token:
                return token
            if i % 3 == 0:
                try:
                    await page.click(".cf-turnstile, //div[@class='cf-turnstile']", timeout=2000)
                except Exception:
                    pass
                await _click_turnstile_checkbox(page, attempts=2)
        except Exception:
            pass
        await asyncio.sleep(0.5)
    raise TimeoutError("Token not received via route-intercept")


async def run_ts(sitekey: str, url: str, action: str = None,
                          cdata: str = None, proxy: str = None) -> dict:
    """Solve via route intercept (implicit widget)."""
    t0 = time.monotonic()
    async with _solve_sem:
        target = url
        div = (f'<div class="cf-turnstile" data-sitekey="{sitekey}"'
               + (f' data-action="{action}"' if action else '')
               + (f' data-cdata="{cdata}"' if cdata else '')
               + '></div>')
        page_data = HTML_TEMPLATE.replace("<!-- cf turnstile -->", div)
        bkw = _browser_kwargs(proxy=proxy, sticky_key=url or sitekey)

        async with _PooledBrowser(bkw) as browser:
            page = await browser.new_page()
            try:
                await _attach_token_sniffer(page)
                await page.route(route_glob(target), lambda r: r.fulfill(
                    body=page_data, status=200, content_type="text/html"))
                await page.goto(target, wait_until="domcontentloaded", timeout=45000)
                token = await _get_turnstile_response_route(page)
                meta = await _page_meta(page)
                return {
                    "token": token,
                    "expires_in": 300,
                    "elapsed": round(time.monotonic() - t0, 1),
                    "method": "route",
                    "usage": _usage_for_method("route"),
                    "user_agent": meta["user_agent"],
                    "proxy": bkw.get("proxy"),
                    "cookies": meta["cookies"],
                    "cf_clearance": meta["cf_clearance"],
                }
            finally:
                await page.close()


async def run_ts_explicit(sitekey: str, url: str, action: str = None,
                                   cdata: str = None, proxy: str = None,
                                   timeout_s: int = 60) -> dict:
    """Route-intercept + turnstile.render(explicit) + callback (stronger mint path).

    Fast path: invisible / non-interactive widgets auto-fire callback — harvest
    immediately after load, do NOT burn 10+ click attempts first (was ~60s+ on
    peet invisible). Managed widgets still get a limited click+harvest loop.
    """
    t0 = time.monotonic()
    async with _solve_sem:
        target = url
        # Auto size for invisible demos / widgets (faster, no checkbox surface)
        size = None
        u = (url or "").lower()
        if "invisible" in u or "size=invisible" in u:
            size = "invisible"
        page_data = _explicit_page(sitekey, action, cdata, size=size)
        bkw = _browser_kwargs(proxy=proxy, sticky_key=url or sitekey)

        async with _PooledBrowser(bkw) as browser:
            page = await browser.new_page()
            try:
                await _attach_token_sniffer(page)
                await page.route(route_glob(target), lambda r: r.fulfill(
                    body=page_data, status=200, content_type="text/html"))
                t_goto0 = time.monotonic()
                await page.goto(target, wait_until="domcontentloaded", timeout=45000)
                log.info("phase goto=%.2f pool=%s", time.monotonic() - t0, True)

                # Concurrent wait + light click (2026-07-16 night):
                # Always poll token sinks; frame/click runs alongside, not before
                # a long exclusive harvest. Avoids early-click-only regression and
                # stacked wait_for_function full timeouts.
                token = ""
                clicked = False
                budget = max(6.0, float(timeout_s) - (time.monotonic() - t0) - 1.0)

                async def _token_poll(max_s: float) -> str:
                    return await _wait_token(page, timeout_s=max_s)

                async def _frame_and_click() -> bool:
                    did = False
                    try:
                        await _wait_challenge_frame(page, timeout_s=5)
                    except Exception:
                        pass
                    # light clicks only; token poll is concurrent
                    did = await _click_turnstile_checkbox(page, attempts=4)
                    if not did:
                        await asyncio.sleep(0.12)
                        did = await _click_turnstile_checkbox(page, attempts=3) or did
                    return did

                # Phase 1: race short auto-token vs frame+click (max ~5s wall)
                t_task = asyncio.create_task(_token_poll(min(5.0, budget)))
                c_task = asyncio.create_task(_frame_and_click())
                done, pending = await asyncio.wait(
                    {t_task, c_task}, return_when=asyncio.FIRST_COMPLETED
                )
                if t_task in done:
                    try:
                        token = t_task.result() or ""
                    except Exception:
                        token = ""
                if c_task in done:
                    try:
                        clicked = bool(c_task.result())
                    except Exception:
                        clicked = False
                # If token not ready yet, finish the other task with remaining budget
                if not token:
                    if not t_task.done():
                        try:
                            token = await asyncio.wait_for(t_task, timeout=min(6.0, budget)) or ""
                        except Exception:
                            token = ""
                            if not t_task.done():
                                t_task.cancel()
                    else:
                        try:
                            token = t_task.result() or ""
                        except Exception:
                            token = ""
                if not c_task.done():
                    try:
                        clicked = bool(await asyncio.wait_for(c_task, timeout=2.0)) or clicked
                    except Exception:
                        c_task.cancel()
                else:
                    try:
                        clicked = bool(c_task.result()) or clicked
                    except Exception:
                        pass

                log.info("Explicit render: concurrent token=%s clicked=%s phase=%.2f",
                         bool(token), clicked, time.monotonic() - t0)

                # Phase 2 residual: short re-click + poll if still empty
                remain = max(2.0, timeout_s - (time.monotonic() - t0))
                deadline = time.monotonic() + remain
                while time.monotonic() < deadline and not token:
                    if not clicked:
                        clicked = await _click_turnstile_checkbox(page, attempts=2) or clicked
                    else:
                        await _click_turnstile_checkbox(page, attempts=1)
                    token = await _wait_token(page, timeout_s=1.5)
                    if token:
                        break

                if not token:
                    err = None
                    try:
                        err = await page.evaluate("() => window.__ts_err")
                    except Exception:
                        pass
                    raise TimeoutError(
                        f"Token not received via explicit render (err={err})")
                meta = await _page_meta(page)
                return {
                    "token": token,
                    "expires_in": 300,
                    "elapsed": round(time.monotonic() - t0, 1),
                    "method": "explicit",
                    "usage": _usage_for_method("explicit"),
                    "user_agent": meta["user_agent"],
                    "proxy": bkw.get("proxy"),
                    "cookies": meta["cookies"],
                    "cf_clearance": meta["cf_clearance"],
                    "clicked": clicked,
                }
            finally:
                await page.close()


# ── run_ts_verify ────────────────────────────────────────────────

async def run_ts_verify(sitekey: str, verify_url: str,
                           verify_payload: dict = None,
                           action: str = None, cdata: str = None,
                           page_url: str = None) -> dict:
    """Explicit mint then verify from the same browser session."""
    t0 = time.monotonic()
    async with _solve_sem:
        target = page_url or verify_url
        page_data = _explicit_page(sitekey, action, cdata, size=("invisible" if "invisible" in (target or "").lower() else None))
        bkw = _browser_kwargs(sticky_key=target or sitekey)

        async with _PooledBrowser(bkw) as browser:
            page = await browser.new_page()
            try:
                await _attach_token_sniffer(page)
                await page.route(route_glob(target), lambda r: r.fulfill(
                    body=page_data, status=200, content_type="text/html"))
                await page.goto(target, wait_until="domcontentloaded", timeout=30000)
                await _wait_challenge_frame(page, 15)
                await _click_turnstile_checkbox(page, attempts=10)
                token = await _harvest_token(page, max_wait_s=45)
                if not token:
                    raise TimeoutError("Token not received for run_ts_verify")
                log.info("run_ts_verify: token in %.1fs", time.monotonic() - t0)

                payload = dict(verify_payload or {})
                payload["token"] = token
                result = await fetch_from_page(
                    page, verify_url, "POST", json.dumps(payload))
                codes = _error_codes(result["body"])
                log.info("run_ts_verify: status=%d codes=%s",
                         result["status"], codes)
                meta = await _page_meta(page)
                return {
                    "token": token,
                    "expires_in": 300,
                    "verify_status": result["status"],
                    "verify_body": result["body"],
                    "verify_error_codes": codes,
                    "method": "explicit",
                    "usage": _usage_for_method("explicit"),
                    "user_agent": meta["user_agent"],
                    "proxy": bkw.get("proxy"),
                    "cookies": meta["cookies"],
                    "elapsed": round(time.monotonic() - t0, 1),
                }
            finally:
                await page.close()


# ── Real-page solver ────────────────────────────────────────────────

_WIDGET_INJECT_JS = (
    "(k) => {"
    "  const root = document.body || document.documentElement;"
    "  if (!root) throw new Error('no document root for turnstile inject');"
    "  const d = document.createElement('div');"
    "  d.className = 'cf-turnstile';"
    "  d.setAttribute('data-sitekey', k);"
    "  root.prepend(d);"
    "}"
)


async def _inject_turnstile_widget(page, sitekey: str) -> None:
    # SPA pages can momentarily have null body during client navigation.
    for _ in range(20):
        try:
            ready = await page.evaluate(
                "() => !!(document.body || document.documentElement)")
            if ready:
                await page.evaluate(_WIDGET_INJECT_JS, sitekey)
                return
        except Exception as e:
            last = e
        await asyncio.sleep(0.25)
    raise RuntimeError(f"turnstile inject failed: {last if 'last' in dir() else 'no root'}")


async def run_ts_realpage(url: str, sitekey: str = None,
                                   timeout_s: int = 90,
                                   pre_actions: list = None,
                                   post_fetch: list = None,
                                   proxy: str = None) -> dict:
    """Navigate real page, click CF Turnstile, harvest token + cookies.

    timeout_s is the *solve budget* for harvest after load; caller/server should
    allow extra wall time for browser launch.
    """
    t0 = time.monotonic()
    timeout_s = timeout_s or 90

    async with _solve_sem:
        bkw = _browser_kwargs(proxy=proxy, sticky_key=url or sitekey)
        async with _PooledBrowser(bkw) as browser:
            page = await browser.new_page()
            try:
                await _attach_token_sniffer(page)
                await page.goto(url, wait_until="domcontentloaded", timeout=45000)

                if pre_actions:
                    await run_pre_actions(page, pre_actions)
                    await asyncio.sleep(1.5)
                    # SPA post-action: wait for a document root again
                    for _ in range(20):
                        try:
                            if await page.evaluate(
                                    "() => !!(document.body || document.documentElement)"):
                                break
                        except Exception:
                            pass
                        await asyncio.sleep(0.25)

                has_widget = False
                try:
                    has_widget = bool(await page.evaluate(
                        "() => !!(document.querySelector("
                        "'.cf-turnstile,[name=cf-turnstile-response],"
                        "iframe[src*=\"challenges.cloudflare.com\"],[data-sitekey]'))"
                    ))
                except Exception:
                    has_widget = False

                if sitekey and not has_widget:
                    try:
                        await _inject_turnstile_widget(page, sitekey)
                        await asyncio.sleep(2)
                    except Exception as e:
                        log.warning("Real-page inject failed (continue harvest): %s", e)
                elif sitekey and has_widget:
                    log.info("Real-page: existing Turnstile surface — skip inject")

                await _wait_challenge_frame(page, timeout_s=12)
                clicked = await _click_turnstile_checkbox(page, attempts=12)
                log.info("Real-page checkbox clicked=%s", clicked)

                # Budget remaining wall for harvest (leave 2s for packaging)
                used = time.monotonic() - t0
                remain = max(8.0, float(timeout_s) - used)
                token = ""
                deadline = time.monotonic() + remain
                n = 0
                while time.monotonic() < deadline:
                    token = await _harvest_token(page, max_wait_s=1.5)
                    if token:
                        break
                    n += 1
                    # re-click every ~3s even if first click "succeeded"
                    if n % 2 == 0:
                        await _click_turnstile_checkbox(page, attempts=2)
                    await asyncio.sleep(0.3)

                meta = await _page_meta(page)
                result = {
                    "token": token,
                    "verify_success": bool(token),
                    "cookies": meta["cookies"],
                    "cf_clearance": meta["cf_clearance"],
                    "method": "real-page",
                    "usage": _usage_for_method("real-page"),
                    "user_agent": meta["user_agent"],
                    "proxy": bkw.get("proxy"),
                    "elapsed": round(time.monotonic() - t0, 1),
                }
                if not token:
                    result["error"] = "token_empty_after_realpage"

                if post_fetch and token:
                    result["post_fetch"] = await run_post_fetch(page, post_fetch, token)

                return result
            finally:
                await page.close()
