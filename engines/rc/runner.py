"""CSM engine runner — challenge execution for this vendor."""
import asyncio
import logging
import os
import time
from pathlib import Path

import cloakbrowser

from csm.browser import browser_kwargs, run_pre_actions, run_post_fetch, route_glob
from csm.mistral import KeyPool
from .vision import run_image_challenge

log = logging.getLogger(__name__)

_KEYFILE = Path(__file__).resolve().parent.parent.parent / "csm" / "apikey.txt"
_keypool = None


def _get_keypool():
    """Lazy shared vision key pool (only built if an image challenge appears).

    Keys: DASHSCOPE_API_KEY / VISION_API_KEY / MISTRAL_API_KEY env, or
    csm/apikey.txt. Model: RECAPTCHA_MISTRAL_MODEL → VISION_MODEL → auto
    (qwen-vl-plus when DASHSCOPE present, else mistral-medium-latest).
    """
    global _keypool
    if _keypool is None:
        model = (os.getenv("RECAPTCHA_MISTRAL_MODEL")
                 or os.getenv("VISION_MODEL")
                 or None)
        _keypool = KeyPool(str(_KEYFILE), model=model, start_index=os.getpid())
    return _keypool

_TEMPLATE_PATH = Path(__file__).parent / "template.html"
_HTML_TEMPLATE = _TEMPLATE_PATH.read_text()

_solve_lock = asyncio.Lock()

# Address the iframes by title so frame_locator re-resolves them on every action —
# immune to reCAPTCHA reloading the iframe.
_ANCHOR_IFRAME = "iframe[title='reCAPTCHA']"
_BFRAME_IFRAME = "iframe[title*='recaptcha challenge']"

# v3 / invisible / Enterprise page: load the render lib then execute(). Built inline
# (structure differs from the v2 template). Enterprise just swaps in enterprise.js and
# the grecaptcha.enterprise namespace.
_V3_PAGE = """<!DOCTYPE html><html><head>
<script src="https://www.google.com/recaptcha/__LIB__?render=__SITEKEY__"></script>
</head><body><div id="out">waiting</div>
<script>
  window.__token = ""; window.__err = "";
  var gre = __NS__;
  gre.ready(function () {
    gre.execute("__SITEKEY__", {action: "__ACTION__"})
      .then(function (t) { window.__token = t; })
      .catch(function (e) { window.__err = String(e); });
  });
</script></body></html>"""


def _browser_kwargs() -> dict:
    return browser_kwargs("RECAPTCHA")


def _build_v2_page(sitekey: str, enterprise: bool = False) -> str:
    # enterprise.js auto-renders the same .g-recaptcha checkbox as api.js.
    lib = "enterprise.js" if enterprise else "api.js"
    return _HTML_TEMPLATE.replace("__SITEKEY__", sitekey).replace("__LIB__", lib)


async def _find_frame(page, pattern: str):
    for fr in page.frames:
        if pattern in (fr.url or ""):
            return fr
    return None


# ── v3 / invisible: execute() ───────────────────────────────────────

async def _solve_via_execute(sitekey: str, url: str, action: str,
                             enterprise: bool = False) -> dict:
    """Mint a token via grecaptcha[.enterprise].execute() on a route-intercepted page."""
    t0 = time.monotonic()
    lib = "enterprise.js" if enterprise else "api.js"
    ns = "grecaptcha.enterprise" if enterprise else "grecaptcha"
    body = (_V3_PAGE.replace("__LIB__", lib).replace("__NS__", ns)
            .replace("__SITEKEY__", sitekey).replace("__ACTION__", action))
    async with _solve_lock:
        async with await cloakbrowser.launch_async(**_browser_kwargs()) as browser:
            page = await browser.new_page()
            try:
                await page.route(route_glob(url), lambda r: r.fulfill(body=body, status=200))
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                for _ in range(20):
                    await asyncio.sleep(1)
                    token = await page.evaluate("() => window.__token || ''")
                    if token:
                        return {"token": token, "action": action,
                                "elapsed": round(time.monotonic() - t0, 1),
                                "method": "enterprise" if enterprise else "execute"}
                    err = await page.evaluate("() => window.__err || ''")
                    if err:
                        return {"error": f"execute() failed: {err}",
                                "elapsed": round(time.monotonic() - t0, 1)}
                return {"error": "execute() timed out (no token)",
                        "elapsed": round(time.monotonic() - t0, 1)}
            finally:
                await page.close()


def _siteverify(token: str, secret: str) -> dict:
    """Read the v3 score via Google siteverify. Needs the TARGET's secret key
    (only the site owner has it) — that's the only way a score exists."""
    import urllib.parse
    import urllib.request
    data = urllib.parse.urlencode({"secret": secret, "response": token}).encode()
    req = urllib.request.Request(
        "https://www.google.com/recaptcha/api/siteverify", data=data)
    with urllib.request.urlopen(req, timeout=15) as r:
        import json as _json
        return _json.loads(r.read())


async def run_rc_v3(sitekey: str, url: str, action: str = "submit",
                             secret: str = None, enterprise: bool = False) -> dict:
    """Solve reCAPTCHA v3 (score-based). Returns {token, action, elapsed}.

    The token's *score* is decided server-side by Google. Pass `secret` (the
    target site's secret key) to also run siteverify and return the score —
    without a secret no score exists, only a token. `enterprise=True` loads
    enterprise.js + grecaptcha.enterprise (score read via Cloud Assessment API,
    not the public siteverify endpoint, so `secret` is ignored for Enterprise).
    """
    res = await _solve_via_execute(sitekey, url, action, enterprise=enterprise)
    if secret and not enterprise and res.get("token"):
        try:
            v = await asyncio.to_thread(_siteverify, res["token"], secret)
            res["score"] = v.get("score")
            res["verify"] = v
        except Exception as e:
            res["verify_error"] = str(e)
    return res


async def run_rc_invisible(sitekey: str, url: str, action: str = "submit",
                                    enterprise: bool = False) -> dict:
    """Solve invisible reCAPTCHA v2. Identical mechanism to v3 (execute())."""
    return await _solve_via_execute(sitekey, url, action, enterprise=enterprise)


# ── v3 / invisible on the REAL page (higher score) ──────────────────

# Load the render lib on the REAL page, wait for the namespace, then execute — passing
# sitekey/action/lib/ns as evaluate() args (never interpolated into JS source).
_V3_REALPAGE_JS = """
({sitekey, action, lib, ns}) => {
  window.__rc_token = ""; window.__rc_err = "";
  const getGre = () => ns === 'enterprise'
    ? (window.grecaptcha && window.grecaptcha.enterprise)
    : window.grecaptcha;
  const run = () => {
    const gre = getGre();
    gre.ready(() => {
      gre.execute(sitekey, {action})
        .then(t => { window.__rc_token = t; })
        .catch(e => { window.__rc_err = String(e); });
    });
  };
  const s = document.createElement('script');
  s.src = `https://www.google.com/recaptcha/${lib}?render=${sitekey}`;
  s.onerror = () => { window.__rc_err = 'lib load failed'; };
  s.onload = () => {
    let tries = 0;
    const iv = setInterval(() => {
      const gre = getGre();
      if (gre && gre.execute) { clearInterval(iv); run(); }
      else if (++tries > 100) { clearInterval(iv); window.__rc_err = 'grecaptcha not ready'; }
    }, 100);
  };
  document.head.appendChild(s);
}
"""


async def _simulate_behavior(page):
    """Light behavioral signal (mouse path + scroll + dwell) so execute() runs with
    real interaction history — the score input the route-intercept fake page lacks."""
    try:
        for x, y in [(150, 200), (420, 360), (640, 260), (320, 520), (500, 300)]:
            await page.mouse.move(x, y, steps=10)
            await asyncio.sleep(0.35)
        await page.mouse.wheel(0, 450)
        await asyncio.sleep(0.6)
        await page.mouse.wheel(0, -220)
        await asyncio.sleep(0.5)
    except Exception:
        pass


async def run_rc_v3_realpage(url: str, sitekey: str, action: str = "submit",
                                      enterprise: bool = False, timeout_s: int = 90,
                                      pre_actions: list = None) -> dict:
    """Mint a v3/Enterprise token on the REAL page (no route intercept).

    Navigates the genuine URL (real DOM, real cookies, real origin), runs optional
    pre_actions, simulates brief interaction, then loads the render lib and calls
    grecaptcha[.enterprise].execute() in that context. The behavioral + DOM signals a
    route-intercepted blank page can't provide are the main score lever — use this for
    strict sitekeys where the fast execute() path scores too low. Returns {token, ...}.
    """
    t0 = time.monotonic()
    lib = "enterprise.js" if enterprise else "api.js"
    ns = "enterprise" if enterprise else "standard"
    async with _solve_lock:
        async with await cloakbrowser.launch_async(**_browser_kwargs()) as browser:
            page = await browser.new_page()
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=45000)
                if pre_actions:
                    await run_pre_actions(page, pre_actions)
                await asyncio.sleep(2)
                await _simulate_behavior(page)

                await page.evaluate(_V3_REALPAGE_JS,
                                    {"sitekey": sitekey, "action": action, "lib": lib, "ns": ns})
                method = "enterprise-realpage" if enterprise else "execute-realpage"
                deadline = time.monotonic() + timeout_s
                while time.monotonic() < deadline:
                    await asyncio.sleep(1)
                    token = await page.evaluate("() => window.__rc_token || ''")
                    if token:
                        return {"token": token, "action": action,
                                "elapsed": round(time.monotonic() - t0, 1), "method": method}
                    err = await page.evaluate("() => window.__rc_err || ''")
                    if err:
                        return {"error": f"execute() failed: {err}",
                                "elapsed": round(time.monotonic() - t0, 1)}
                return {"error": "execute() timed out (no token)",
                        "elapsed": round(time.monotonic() - t0, 1)}
            finally:
                await page.close()


# ── v2 checkbox: click + (best-effort) audio fallback ───────────────

async def _anchor_class(page) -> str:
    try:
        return await page.frame_locator(_ANCHOR_IFRAME).locator(
            "#recaptcha-anchor").get_attribute("class", timeout=3000) or ""
    except Exception:
        return ""


async def _get_token(page, polls: int = 1, delay: float = 0.20) -> str:
    """Harvest reCAPTCHA token from multiple sinks.

    v36: default is non-blocking-ish. Callers explicitly request long poll only
    when no next grid is visible / checkbox is checked.
    """
    js = r"""() => {
      const valid = (v) => {
        if (typeof v !== 'string') return '';
        v = v.trim();
        // Recaptcha tokens are long opaque strings; avoid random page values.
        return v.length >= 100 ? v : '';
      };
      const sels = [
        '#g-recaptcha-response',
        'textarea[name="g-recaptcha-response"]',
        'textarea[id^="g-recaptcha-response"]',
        'input[name="g-recaptcha-response"]'
      ];
      for (const sel of sels) {
        for (const el of document.querySelectorAll(sel)) {
          const v = valid(el.value || el.textContent || '');
          if (v) return {token:v, sink:'dom:' + sel};
        }
      }
      for (const k of ['__rc_token','__recaptcha_token','__token']) {
        const v = valid(window[k]);
        if (v) return {token:v, sink:'window:' + k};
      }
      // grecaptcha internal client tree sometimes holds the response before DOM sync.
      const root = window.___grecaptcha_cfg?.clients;
      const seen = new WeakSet();
      let budget = 2500;
      const walk = (x, depth, path) => {
        if (!x || budget-- <= 0 || depth > 8) return null;
        if (typeof x !== 'object' && typeof x !== 'function') return null;
        if (seen.has(x)) return null;
        seen.add(x);
        let keys=[];
        try { keys = Object.keys(x).slice(0,120); } catch(e) { return null; }
        keys.sort((a,b) => /response|token/i.test(b) - /response|token/i.test(a));
        for (const k of keys) {
          let v;
          try { v=x[k]; } catch(e) { continue; }
          const kp = path ? path + '.' + k : k;
          // v36b: never accept arbitrary deep strings. The v36 smoke's 188-char
          // value after a failed grid was a false positive from unrelated cfg data.
          if (typeof v === 'string' && /(^|[_.-])(response|token)([_.-]|$)/i.test(k)) {
            const got=valid(v);
            if (got && got.length >= 500) return {token:got, path:kp};
          }
          const got=walk(v, depth+1, kp);
          if (got) return got;
        }
        return null;
      };
      const cfg = walk(root, 0, 'clients');
      return cfg ? {token:cfg.token, sink:'___grecaptcha_cfg:' + cfg.path} : {token:'', sink:''};
    }"""
    n = max(1, int(polls or 1))
    for i in range(n):
        try:
            got = await page.evaluate(js)
            token = (got or {}).get("token", "") if isinstance(got, dict) else ""
            if token:
                log.info("v36 token harvested sink=%s len=%d poll=%d/%d",
                         (got or {}).get("sink", "unknown"), len(token), i + 1, n)
                return token
        except Exception as e:
            if i == 0:
                log.debug("v36 harvest evaluate: %s", str(e).splitlines()[0])
        if i + 1 < n:
            await asyncio.sleep(delay)
    return ""


async def _audio_blocked(page) -> bool:
    """True if reCAPTCHA is denying the audio fallback (IP/automation block)."""
    fr = await _find_frame(page, "/bframe")
    if not fr:
        return False
    try:
        txt = (await fr.locator("body").inner_text(timeout=2000)).lower()
    except Exception:
        return False
    return any(s in txt for s in ("automated queries", "try again later",
                                  "sending automated"))


async def run_rc_v2(sitekey: str, url: str,
                              max_attempts: int = 4,
                              enterprise: bool = False,
                              timeout_s: int | None = None) -> dict:
    """Solve reCAPTCHA v2 checkbox via route intercept.

    Clicks the checkbox; returns the token immediately if the session is low-risk
    (no challenge). If an image grid opens, solves it via Mistral vision. Set
    `enterprise=True` for Enterprise checkbox keys (loads enterprise.js — the widget
    and challenge are otherwise identical). Returns {token, attempts, elapsed} or
    {error, elapsed}.
    """
    t0 = time.monotonic()
    page_data = _build_v2_page(sitekey, enterprise=enterprise)
    # Client timeout_s is overall; free path must leave budget for paid_fallback.
    free_budget = None
    if timeout_s and timeout_s > 0:
        paid_ready = False
        try:
            from csm.paid_fallback import available as _paid_available
            paid_ready = any(_paid_available().values())
        except Exception:
            paid_ready = False
        # No paid keys / FORCE free-only → use full client timeout for free path.
        force_free = os.getenv("FREE_RC_NO_RESERVE", "").strip() in ("1", "true", "yes")
        if force_free or not paid_ready:
            free_budget = timeout_s
            reserve = 0
        else:
            # CapSolver often needs 40-90s. Prefer paid reliability over burning free attempts.
            reserve = max(50, int(timeout_s * 0.55)) if timeout_s >= 90 else max(30, int(timeout_s * 0.4))
            free_budget = max(20, min(45, timeout_s - reserve))
            if free_budget <= 50:
                max_attempts = min(max_attempts, 2)
        log.info("v2 free budget=%ss attempts=%s (timeout_s=%s reserve=%s paid=%s)",
                 free_budget, max_attempts, timeout_s, reserve, paid_ready and not force_free)

    async with _solve_lock:
        async with await cloakbrowser.launch_async(**_browser_kwargs()) as browser:
            page = await browser.new_page()
            try:
                await page.route(route_glob(url), lambda r: r.fulfill(body=page_data, status=200))
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                await asyncio.sleep(3)

                for attempt in range(1, max_attempts + 1):
                    if free_budget is not None and (time.monotonic() - t0) >= free_budget:
                        log.info("v2 free budget exhausted after %.1fs — yield to paid",
                                 time.monotonic() - t0)
                        return {"error": f"free budget exhausted after {attempt-1} attempts",
                                "elapsed": round(time.monotonic() - t0, 1)}
                    log.info("v2 attempt %d/%d", attempt, max_attempts)
                    # Ensure anchor iframe is present before click
                    try:
                        await page.wait_for_selector(_ANCHOR_IFRAME, timeout=12000)
                    except Exception as e:
                        log.warning("anchor iframe missing: %s", str(e).splitlines()[0])
                        # hard reload route page
                        try:
                            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                            await asyncio.sleep(2.5)
                        except Exception as e2:
                            log.warning("reload: %s", str(e2).splitlines()[0])
                    try:
                        await page.frame_locator(_ANCHOR_IFRAME).locator(
                            "#recaptcha-anchor").click(timeout=10000)
                    except Exception as e:
                        log.warning("checkbox click: %s", str(e).splitlines()[0])
                        # try JS click inside anchor frame
                        try:
                            fr = await _find_frame(page, "/anchor")
                            if fr:
                                await fr.evaluate(
                                    "() => document.querySelector('#recaptcha-anchor')?.click()")
                        except Exception as e2:
                            log.warning("checkbox js: %s", str(e2).splitlines()[0])

                    # Poll: checked (no-challenge win) OR an image grid opens.
                    challenge = False
                    for pi in range(20):
                        await asyncio.sleep(1)
                        if "recaptcha-checkbox-checked" in await _anchor_class(page):
                            token = await _get_token(page)
                            if token:
                                return {"token": token, "attempts": attempt,
                                        "elapsed": round(time.monotonic() - t0, 1),
                                        "method": "checkbox-no-challenge"}
                        # bframe with table OR any challenge body
                        try:
                            bf = await _find_frame(page, "/bframe")
                            if bf:
                                has_table = await page.frame_locator(_BFRAME_IFRAME).locator(
                                    "table").count() > 0
                                # also detect tile grid without waiting full table selector
                                if not has_table:
                                    try:
                                        has_table = await bf.evaluate(
                                            """() => !!document.querySelector(
                                              'table.rc-imageselect-table, .rc-imageselect-target, .rc-imageselect-tile')""")
                                    except Exception:
                                        has_table = False
                                if has_table:
                                    challenge = True
                                    break
                        except Exception:
                            pass
                        if pi == 10:
                            # mid-poll re-click checkbox once
                            try:
                                await page.frame_locator(_ANCHOR_IFRAME).locator(
                                    "#recaptcha-anchor").click(timeout=3000)
                            except Exception:
                                pass
                    if not challenge:
                        log.info("v2 attempt %d: no challenge/token after poll", attempt)
                        # reload for next attempt to clear stuck widget
                        if attempt < max_attempts:
                            try:
                                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                                await asyncio.sleep(2.0)
                            except Exception as e:
                                log.warning("post-dead reload: %s", str(e).splitlines()[0])

                    if free_budget is not None and (time.monotonic() - t0) >= free_budget:
                        log.info("v2 free budget hit mid-attempt — yield to paid")
                        return {"error": "free budget exhausted mid-attempt",
                                "elapsed": round(time.monotonic() - t0, 1)}
                    # Image-solve (audio is IP-blocked). Vision via free YOLO+VL pool.
                    # reCAPTCHA often CHAINS multiple image grids before minting a token.
                    # Keep solving while a grid is present and no token yet.
                    if challenge:
                        max_grids = int(os.getenv("RC_MAX_CHAINED_GRIDS", "10"))
                        ok_streak = 0
                        for gi in range(max_grids):
                            if free_budget is not None and (time.monotonic() - t0) >= free_budget:
                                log.info("v2 free budget mid image-chain")
                                break
                            # still a grid?
                            try:
                                has_table = await page.frame_locator(_BFRAME_IFRAME).locator(
                                    "table").count() > 0
                            except Exception:
                                has_table = False
                            if not has_table and gi > 0:
                                # wait briefly for next grid or token
                                await asyncio.sleep(1.5)
                                try:
                                    has_table = await page.frame_locator(_BFRAME_IFRAME).locator(
                                        "table").count() > 0
                                except Exception:
                                    has_table = False
                            if not has_table:
                                break
                            log.info("v2 image grid chain %d/%d", gi + 1, max_grids)
                            try:
                                ok = await run_image_challenge(page, _get_keypool())
                                log.info("image-solve grid %d ok=%s", gi + 1, ok)
                            except Exception as e:
                                log.warning("image-solve: %s", str(e).splitlines()[0])
                                ok = False
                            # error banner / failed verify → stop chain, fresh attempt
                            if ok is False:
                                log.info("image grid failed — break chain, new attempt")
                                break
                            ok_streak += 1
                            # v36: immediate multi-sink harvest, then inspect state.
                            # Never run a 15s token poll while the next grid is already visible.
                            await asyncio.sleep(0.35)
                            token = await _get_token(page, polls=1)
                            if token:
                                return {"token": token, "attempts": attempt,
                                        "elapsed": round(time.monotonic() - t0, 1),
                                        "method": "image"}

                            checked = "recaptcha-checkbox-checked" in await _anchor_class(page)
                            try:
                                next_grid = await page.frame_locator(_BFRAME_IFRAME).locator(
                                    "table").count() > 0
                            except Exception:
                                next_grid = False
                            log.info("v36 post-grid state gi=%d ok_streak=%d checked=%s next_grid=%s",
                                     gi + 1, ok_streak, checked, next_grid)

                            if checked:
                                token = await _get_token(page, polls=15, delay=0.20)
                                if token:
                                    return {"token": token, "attempts": attempt,
                                            "elapsed": round(time.monotonic() - t0, 1),
                                            "method": "image"}
                                log.warning("v36 checkbox checked but token empty")
                                break
                            if next_grid:
                                continue

                            # Transition gap: no table yet and not checked. Brief bounded poll
                            # for token or next grid, max ~3s.
                            for _tw in range(12):
                                await asyncio.sleep(0.25)
                                token = await _get_token(page, polls=1)
                                if token:
                                    return {"token": token, "attempts": attempt,
                                            "elapsed": round(time.monotonic() - t0, 1),
                                            "method": "image"}
                                try:
                                    if await page.frame_locator(_BFRAME_IFRAME).locator(
                                            "table").count() > 0:
                                        break
                                except Exception:
                                    pass
                        token = await _get_token(page, polls=20, delay=0.20)
                        if token:
                            return {"token": token, "attempts": attempt,
                                    "elapsed": round(time.monotonic() - t0, 1),
                                    "method": "image"}
                    if attempt < max_attempts:
                        await asyncio.sleep(3 * attempt)  # backoff between attempts

                return {"error": f"failed after {max_attempts} attempts",
                        "elapsed": round(time.monotonic() - t0, 1)}
            finally:
                await page.close()


async def run_rc_v2_realpage(url: str, sitekey: str = None,
                                      pre_actions: list = None,
                                      post_fetch: list = None,
                                      timeout_s: int = 60) -> dict:
    """Solve v2 on the REAL page (no route intercept) — the realistic production path.

    Navigates the actual site, runs optional pre_actions, clicks the checkbox in the
    cross-origin iframe, harvests the token, and optionally runs post_fetch API calls
    from the SAME browser session. Mirrors turnstile.run_ts_realpage.

    Use __TOKEN__ in post_fetch bodies to inject the solved token.
    """
    t0 = time.monotonic()
    async with _solve_lock:
        async with await cloakbrowser.launch_async(**_browser_kwargs()) as browser:
            page = await browser.new_page()
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=45000)
                if pre_actions:
                    await run_pre_actions(page, pre_actions)
                    await asyncio.sleep(2)
                if sitekey:  # inject our widget if the page doesn't embed one
                    await page.evaluate(
                        "(k) => { const d=document.createElement('div');"
                        " d.className='g-recaptcha'; d.setAttribute('data-sitekey',k);"
                        " document.body.prepend(d);"
                        " const s=document.createElement('script');"
                        " s.src='https://www.google.com/recaptcha/api.js';"
                        " document.head.appendChild(s); }", sitekey)
                    await asyncio.sleep(3)

                try:
                    await page.frame_locator(_ANCHOR_IFRAME).locator(
                        "#recaptcha-anchor").click(timeout=8000)
                except Exception as e:
                    log.warning("realpage checkbox click: %s", str(e).splitlines()[0])

                token = ""
                deadline = time.monotonic() + timeout_s
                while time.monotonic() < deadline:
                    await asyncio.sleep(1)
                    token = await page.evaluate(
                        "() => document.querySelector('#g-recaptcha-response')?.value || ''")
                    if token:
                        break
                    if await _audio_blocked(page):
                        break

                cookies = await page.context.cookies()
                result = {"token": token, "verify_success": bool(token),
                          "cookies": cookies, "method": "real-page",
                          "elapsed": round(time.monotonic() - t0, 1)}
                if not token and await _audio_blocked(page):
                    result["error"] = "audio-blocked"

                if post_fetch and token:
                    result["post_fetch"] = await run_post_fetch(page, post_fetch, token)
                return result
            finally:
                await page.close()
