"""CSM HTTP gateway — multi-engine captcha task API."""
import asyncio
import ipaddress
import itertools
import json
import logging
import os
import socket
import sys
import time
from collections import deque
from typing import Any, Optional
from urllib.parse import urlparse

from fastapi import Body, Depends, FastAPI, HTTPException, Query
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("csm.gateway")

_DESCRIPTION = """
**CSM** — free-first multi-engine captcha task service.
Browser challenges run through **CloakBrowser** (self-hosted anti-detect Chromium);
OCR/slider/geetest use local free runners with optional paid fallback.

**Supported:** Turnstile · reCAPTCHA (v2 / v3 / invisible, incl. Enterprise) · hCaptcha ·
Cloudflare clearance (`cf_clearance` — full-page Managed / JS challenge) ·
AWS WAF (`aws-waf-token` — silent JS challenge).

Dispatch is by the `type` field of `POST /v1/task` (alias: `/solve`); optional fields select the variant
(`version`, `real_page`, `verify_url`, …). `/v1/health` is public; behind the public
domain every other path needs a Bearer token (enforced at the Caddy layer).

Caller-supplied URLs (`url`, `verify_url`, `page_url`, `post_fetch[].url`) are fetched
from the browser session and are **SSRF-guarded**: private/loopback/link-local targets
are rejected unless `SOLVER_ALLOW_PRIVATE=1`.
"""

_TAGS = [
    {"name": "solve", "description": "Solve a captcha challenge."},
    {"name": "monitoring", "description": "Liveness, current tasks, recent solve log."},
]

# Public base URL shown in the OpenAPI docs (contact + servers dropdown). The repo ships a
# neutral placeholder; the live service injects its real domain at runtime via SOLVER_PUBLIC_URL.
_PUBLIC_URL = os.getenv("SOLVER_PUBLIC_URL", "https://solver.example.com")

app = FastAPI(
    title="CSM Task API",
    description=_DESCRIPTION,
    version="2.2.0",
    openapi_tags=_TAGS,
    contact={"name": "solver", "url": _PUBLIC_URL},
    servers=[
        {"url": _PUBLIC_URL, "description": "Public (Bearer token required)"},
        {"url": "http://127.0.0.1:8877", "description": "Local (no auth)"},
    ],
    swagger_ui_parameters={
        "docExpansion": "list",
        "persistAuthorization": True,     # keep the Bearer token across reloads
        "tryItOutEnabled": True,
        "displayRequestDuration": True,
        "filter": True,
    },
)

# Non-enforcing Bearer scheme: makes Swagger UI show an Authorize button and forward the
# token on "Try it out". auto_error=False means a missing/malformed token yields None and
# the endpoint proceeds — real enforcement stays at the Caddy layer (public domain only).
_bearer = HTTPBearer(auto_error=False, description="Bearer token (required on the public "
                     "domain; enforced by the reverse proxy). Ignored for local calls.")
SUPPORTED = ["turnstile", "recaptcha", "hcaptcha", "cloudflare", "awswaf", "botguard", "datadome", "perimeterx", "akamai", "aliyun", "image_text", "math", "slider", "geetest"]
# Page-level solvers that harvest a cookie/token from the live page (no sitekey needed).
_PAGE_LEVEL = ("cloudflare", "awswaf", "botguard", "datadome", "perimeterx", "akamai")
# Solvers that supply their own canonical URL (caller need not pass `url`).
# datadome is NOT here: the caller passes the DataDome-fronted url (+ referer) itself.
# geetest is pure-HTTP protocol (captcha_id only) — no page url required.
_SELF_URL = ("botguard", "perimeterx", "aliyun", "geetest")
# Allow private/loopback targets only when explicitly opted in (dev/testing).
_ALLOW_PRIVATE = os.getenv("SOLVER_ALLOW_PRIVATE") == "1"

# ── Monitoring ring buffer ───────────────────────────────────────────
_solve_log = deque(maxlen=100)
# Concurrent solves of different types can run at once (per-type locks), so track
# current tasks by id rather than a single global that they'd clobber.
_solve_current: dict = {}
_task_ids = itertools.count(1)


def _is_solved(result: dict) -> bool:
    """The ONE success predicate for every solver type — the single source of truth for
    the injected `solved` field + logs. Token solvers signal via truthy `token`, realpage
    variants via `verify_success`, page-level cookie solvers via `success`/`cf_clearance`;
    a truthy value in ANY of these = solved.
    """
    return bool(result.get("token") or result.get("cf_clearance")
                or result.get("verify_success") or result.get("success"))


async def _with_paid_fallback(req: "SolveRequest", r: dict) -> dict:
    """If free browser solve failed and a paid key is configured, try 2captcha → YesCaptcha.

    No-op when free path already solved, or when no paid keys are set. Only applies to
    token-based types (turnstile / recaptcha / hcaptcha) — page-level cookie solvers
    (cloudflare clearance, awswaf, ...) are IP-bound and can't be farmed via paid APIs.
    """
    if _is_solved(r):
        return r
    if req.type not in ("turnstile", "recaptcha", "hcaptcha"):
        return r
    if not req.sitekey or not req.url:
        return r
    try:
        from csm.paid_fallback import available, run_paid
    except Exception as e:
        log.warning("paid_fallback import failed: %s", e)
        return r
    if not any(available().values()):
        return r
    log.info("free solve failed for %s — trying paid fallback", req.type)
    paid = await run_paid(
        req.type, req.sitekey, req.url,
        action=req.action, cdata=req.cdata, version=req.version)
    if paid.get("solved") and paid.get("token"):
        return {"token": paid["token"], "method": paid["method"], "error": None}
    # keep original free-path error; annotate that paid also failed
    err = r.get("error") or "free solve failed"
    paid_err = paid.get("error") or "paid failed"
    r = dict(r)
    r["error"] = f"{err} | paid: {paid_err}"
    return r



def _pure_http_turnstile_siteverify(
    token: str,
    secret: str,
    remoteip: str | None = None,
    proxy: str | None = None,
) -> dict:
    """Official CF siteverify outside the mint browser (portable / SIM-asli bar).

    Prefer routing siteverify through the same mint proxy when available so
    remote IP reputation matches the challenge session. Tokens are single-use —
    this call consumes the token for later replay.
    """
    import urllib.parse
    import urllib.request

    form = {"secret": secret, "response": token}
    if remoteip:
        form["remoteip"] = remoteip
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "captcha-solver-max/siteverify",
        },
        method="POST",
    )
    handlers = []
    if proxy:
        # accept http://user:pass@host:port
        handlers.append(urllib.request.ProxyHandler({
            "http": proxy,
            "https": proxy,
        }))
    opener = urllib.request.build_opener(*handlers) if handlers else urllib.request.build_opener()
    try:
        with opener.open(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
            return {"http_status": resp.status, "body": body, "via_proxy": bool(proxy)}
    except Exception as e:
        # fallback direct if proxy path fails
        if proxy:
            try:
                with urllib.request.urlopen(req, timeout=25) as resp:
                    body = json.loads(resp.read().decode())
                    return {
                        "http_status": resp.status,
                        "body": body,
                        "via_proxy": False,
                        "proxy_error": str(e),
                    }
            except Exception as e2:
                return {"http_status": 0, "error": f"proxy:{e}; direct:{e2}", "body": {}}
        return {"http_status": 0, "error": str(e), "body": {}}


def _log_solve(type_: str, sitekey: Optional[str], url: str, result: dict):
    """Push a solve event to the ring buffer."""
    sitekey = sitekey or ""  # cloudflare has no sitekey
    url = url or ""          # self-hosted solvers (aliyun, botguard, ...) carry no url
    solved = _is_solved(result)
    _solve_log.appendleft({
        "type": type_,
        "sitekey": sitekey[:12] + ("..." if len(sitekey) > 12 else ""),
        "url": url[:60] + ("..." if len(url) > 60 else ""),
        "token": solved,
        "error": result.get("error"),
        "elapsed": result.get("elapsed"),
        "method": result.get("method"),
        "timestamp": time.time(),
        "success": solved and not result.get("error"),
    })


def _assert_public_url(raw: str, field: str):
    """Reject non-http(s) schemes and private/loopback/link-local/reserved hosts.

    Guards the SSRF surface: /solve navigates and fetches caller-supplied URLs from
    the server's browser session (credentials:'include'). ponytail: validate-then-
    fetch has a DNS-rebinding TOCTOU window; add pinned resolution if it matters.
    """
    if not raw:
        return
    u = urlparse(raw)
    if u.scheme not in ("http", "https"):
        raise HTTPException(400, f"{field}: only http/https URLs allowed")
    host = u.hostname
    if not host:
        raise HTTPException(400, f"{field}: URL has no host")
    if _ALLOW_PRIVATE:
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise HTTPException(400, f"{field}: host does not resolve")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise HTTPException(400, f"{field}: private/loopback host blocked")


def _validate_urls(req: "SolveRequest"):
    _assert_public_url(req.url, "url")
    _assert_public_url(req.verify_url, "verify_url")
    _assert_public_url(req.page_url, "page_url")
    for pf in (req.post_fetch or []):
        _assert_public_url(pf.url, "post_fetch.url")


class PreAction(BaseModel):
    """One UI step to run before the captcha appears (real_page mode)."""
    type: str = Field(..., description="click | fill | select | press | wait",
                      examples=["click"])
    selector: Optional[str] = Field(
        None, description="Target selector. Formats: CSS (default), XPath (//…), "
        "text=…, regex=…, role=name[name='…']", examples=["text=Continue with Email"])
    value: Optional[str] = Field(
        None, description="Value for fill/select/press, or seconds for wait")
    timeout: Optional[int] = Field(10000, description="Element wait timeout (ms)")


class PostFetch(BaseModel):
    """An API call fired from the SAME browser session after solving."""
    url: str = Field(..., description="Endpoint to call (SSRF-guarded, same as top-level url)",
                     examples=["https://target.com/api/verify"])
    method: Optional[str] = Field("POST", examples=["POST"])
    body: Optional[dict] = Field(
        None, description="JSON body. Use the literal __TOKEN__ anywhere to inject the "
        "solved token.", examples=[{"token": "__TOKEN__"}])



# CF dash signup widget sitekey (factory Path A) — empirically portable pure-HTTP create
# even across other IP / direct when action=signup (2026-07-16 P2 matrix).
_CF_DASH_SIGNUP_SITEKEY = "0x4AAAAAAAJel0iaAR3mgkjp"


def _turnstile_consumer_fields(req, r: dict) -> dict:
    """Attach honest portable_scopes + consumer_contract (under-claim safe).

    usage stays same_session_only unless secret siteverify upgraded it.
    Do not set usage=portable from these scopes alone.
    """
    if not isinstance(r, dict):
        return r
    token = (r.get("token") or "")
    usage = r.get("usage") or "same_session_only"
    scopes: list[str] = []
    notes: list[str] = []

    # Testing-key pipeline
    if r.get("token_class") == "cf_testing_dummy" or (
        token.startswith("XXXX.DUMMY") or token == "XXXX.DUMMY.TOKEN.XXXX"
    ):
        scopes.append("cf_testing_key_siteverify")
        scopes.append("workers_demo_pipeline")
        notes.append(
            "Testing keys only — proves plumbing, not production portable SIM."
        )

    # CF dash signup hard bar (local product claim cf_dash_create_portable)
    sk = (getattr(req, "sitekey", None) or "") if req is not None else ""
    action = (getattr(req, "action", None) or "") if req is not None else ""
    if sk == _CF_DASH_SIGNUP_SITEKEY and str(action).lower() == "signup" and len(token) > 100:
        scopes.append("cf_dash_user_create")
        notes.append(
            "Empirically: pure-HTTP POST /api/v4/user/create OK same IP, other IP, and direct "
            "when action=signup + mint UA; prefer mint proxy; AsyncSession warmup GET /sign-up "
            "recommended (bare POST may 403 WAF). usage label may still be same_session_only "
            "without real secret siteverify — that is under-claim, not a create failure."
        )

    # If secret path already marked portable*
    if usage in ("portable", "portable_testing_key"):
        if usage == "portable" and "siteverify_real_secret" not in scopes:
            scopes.append("siteverify_real_secret")
        if usage == "portable_testing_key" and "cf_testing_key_siteverify" not in scopes:
            scopes.append("cf_testing_key_siteverify")

    if scopes:
        # de-dupe preserve order
        seen = set()
        scopes = [s for s in scopes if not (s in seen or seen.add(s))]
        r["portable_scopes"] = scopes
    if notes:
        r["consumer_contract"] = " ".join(notes)
    elif usage == "same_session_only" and token:
        r.setdefault(
            "consumer_contract",
            "Default usage=same_session_only: pure-HTTP replay not guaranteed for arbitrary "
            "sitekeys. Replay with same user_agent + mint proxy when possible. Pass secret "
            "for server siteverify upgrade to portable / portable_testing_key.",
        )
    return r


class SolveRequest(BaseModel):
    # Required
    type: str = Field(..., description="Captcha type — dispatch key.",
                      examples=["turnstile"])
    sitekey: Optional[str] = Field(
        None, description="Site key from the target page. Required for engines/ts/engines/rc/"
        "hcaptcha; not used for type=cloudflare (page-level clearance).",
        examples=["0x4AAAAAAA..."])
    url: Optional[str] = Field(None, description="Page the captcha is on (also the intercept origin). "
                     "Required for all types except botguard (which defaults to the Google sign-in page).",
                     examples=["https://target.com"])

    # All-captcha optional
    action: Optional[str] = Field(
        None, description="Turnstile action, or reCAPTCHA v3/invisible action. "
        "For hCaptcha, the literal \"invisible\" selects the invisible-execute path.")
    cdata: Optional[str] = Field(None, description="Turnstile customer data bound into the token.")
    mint_method: Optional[str] = Field(
        None, description="Turnstile mint path: explicit (default) | route. "
        "Use real_page:true for live-page harvest.")
    real_page: Optional[bool] = Field(
        False, description="Solve on the live target page (navigate + drive) instead of a stub.")
    timeout_s: Optional[int] = Field(
        180, description="Overall solve deadline (seconds). Default 180s (vision grids need headroom). "
        "Enforced server-side; on expiry the call returns 408 and the browser is released.")
    pre_actions: Optional[list[PreAction]] = Field(None, description="Steps to run before solving (real_page).")
    post_fetch: Optional[list[PostFetch]] = Field(None, description="API calls after solving (real_page).")
    proxy: Optional[str] = Field(
        None, description="Per-request proxy (scheme://user:pass@host:port). Honored for "
        "type=cloudflare and type=awswaf (overrides the shared TURNSTILE_PROXY env fallback); "
        "their cookies are IP-bound, so replay from this same proxy IP. For engines/ts/recaptcha "
        "set TURNSTILE_PROXY / RECAPTCHA_PROXY instead — the per-request field is not wired for "
        "those.")

    # image_text / math / slider
    image: Optional[str] = Field(
        None, description="Base64 image (optionally a data: URL) for type=image_text or "
        "type=math. Free cascade: ddddocr → ppllocr → Tesseract → optional vision LLM.")
    target_image: Optional[str] = Field(
        None, description="Slider only: base64 of the puzzle piece (small gap tile).")
    background_image: Optional[str] = Field(
        None, description="Slider only: base64 of the full background with the gap.")
    simple: Optional[bool] = Field(
        None, description="Slider only: force simple_target mode for ddddocr.slide_match. "
        "None (default) tries both modes; True/False locks one.")

    # reCAPTCHA-only
    version: Optional[str] = Field(None, description="reCAPTCHA only: v2 | v3 | invisible (default v2).")
    secret: Optional[str] = Field(
        None, description="reCAPTCHA v3 score secret, OR Turnstile siteverify secret. "
        "When set for type=turnstile, server runs pure-HTTP siteverify outside the mint "
        "browser and upgrades usage to portable on success (SIM-asli bar).")
    enterprise: Optional[bool] = Field(False, description="reCAPTCHA only: load enterprise.js / grecaptcha.enterprise.")

    # solve-and-verify (turnstile)
    verify_url: Optional[str] = Field(None, description="Turnstile: verify the token from the same session at this URL.")
    verify_payload: Optional[dict] = Field(None, description="Turnstile: body for verify_url; token is injected as \"token\".")
    page_url: Optional[str] = Field(None, description="Turnstile: origin to intercept (defaults to verify_url).")

    # botguard-only (Google OAuth token extraction)
    email: Optional[str] = Field(None, description="BotGuard: account email to enter — drives the sign-in flow to the token-bearing RPC.")
    password: Optional[str] = Field(None, description="BotGuard: optional password — if set, drives to the password step and grabs the B4hajb hard-gate token instead of the MI613e lookup token.")

    # datadome-only (DataDome bot-management clearance cookie)
    referer: Optional[str] = Field(None, description="datadome: optional framing Referer so DataDome serves the same config/scoring as the real flow. The caller supplies its own site's referer (e.g. https://github.com/ when harvesting via octocaptcha). Pair with a `url` pointing at the DataDome-fronted page that loads tags.js.")

    # perimeterx-only (HUMAN/PerimeterX 'Press & Hold')
    render_flow: Optional[str] = Field(None, description="perimeterx: named site trigger that makes the gate render when it doesn't show on plain load (default 'outlook_signup'). Throwaway navigation only — NOT account creation. Pass null with a `url` for deployments whose gate renders on goto(). Harvests the _px3 clearance cookie (bound to _pxvid+IP+UA; replay under the same proxy+UA within TTL).")

    # aliyun-only (Aliyun Captcha 2.0 slide-puzzle). No sitekey — the challenge identity
    # is scene_id + prefix (prefix selects the captcha-open endpoint). Harvest-only:
    # returns {sceneId, certifyId, deviceToken, data}; the caller replays it immediately
    # into VerifyCaptchaV3 (token is session-bound + one-time-use, deviceToken time-bound).
    scene_id: Optional[str] = Field(None, description="aliyun: the SceneId of the target site's captcha (e.g. read from the page config). Required for type=aliyun.")
    prefix: Optional[str] = Field(None, description="aliyun: the captcha-open endpoint prefix (e.g. '13lbkb' -> <prefix>.captcha-open-southeast.aliyuncs.com). Required for type=aliyun.")
    region: Optional[str] = Field(None, description="aliyun: captcha region — 'sgp' (default), 'cn', or 'intl'.")

    # geetest-only (Geetest v4 pure-HTTP). captcha_id is the public id; sitekey is accepted as alias.
    captcha_id: Optional[str] = Field(
        None, description="geetest: public captcha_id (from page network `load`/`verify`). "
        "sitekey is accepted as an alias. Required for type=geetest.")
    risk_type: Optional[str] = Field(
        "slide", description="geetest: risk type — slide | icon | gobang | winlinze | ai | invisible. Default slide.")


# Named request examples → Swagger UI renders these as a dropdown picker on /solve.
_SOLVE_EXAMPLES = {
    "turnstile": {
        "summary": "Turnstile (route-intercept)",
        "value": {"type": "turnstile", "sitekey": "0x4AAAAAAA...", "url": "https://target.com"},
    },
    "recaptcha_v3": {
        "summary": "reCAPTCHA v3 Enterprise (score)",
        "value": {"type": "recaptcha", "version": "v3", "enterprise": True,
                  "sitekey": "6Lc...", "url": "https://target.com", "action": "login"},
    },
    "recaptcha_v2": {
        "summary": "reCAPTCHA v2 checkbox",
        "value": {"type": "recaptcha", "version": "v2", "sitekey": "6Lf...", "url": "https://target.com/form"},
    },
    "hcaptcha": {
        "summary": "hCaptcha (checkbox)",
        "value": {"type": "hcaptcha", "sitekey": "10000000-ffff-ffff-ffff-000000000001",
                  "url": "https://target.com"},
    },
    "turnstile_realpage": {
        "summary": "Turnstile on the live page (pre_actions + post_fetch)",
        "value": {"type": "turnstile", "real_page": True, "url": "https://app.example.com/login",
                  "pre_actions": [{"type": "fill", "selector": "input[type=email]", "value": "u@ex.com"},
                                  {"type": "click", "selector": "button[type=submit]"}],
                  "post_fetch": [{"url": "https://app.example.com/api/verify",
                                  "body": {"token": "__TOKEN__"}}]},
    },
    "cloudflare_clearance": {
        "summary": "Cloudflare clearance (cf_clearance — Managed or JS challenge)",
        "value": {"type": "cloudflare", "url": "https://protected.example.com",
                  "proxy": "http://user:pass@ip:port"},
    },
    "aws_waf": {
        "summary": "AWS WAF token (silent JS challenge → aws-waf-token)",
        "value": {"type": "awswaf", "url": "https://protected.example.com/waitlist",
                  "proxy": "http://user:pass@ip:port"},
    },
    "botguard": {
        "summary": "BotGuard (Google OAuth bgRequest token + session cookies)",
        "value": {"type": "botguard", "email": "user@example.com",
                  "password": "optional-for-hard-gate-token"},
    },
    "datadome": {
        "summary": "DataDome clearance cookie — caller passes the DataDome-fronted url (+ referer)",
        "value": {"type": "datadome",
                  "url": "https://octocaptcha.com/datadome?origin_page=github_signup_redesign",
                  "referer": "https://github.com/",
                  "proxy": "http://user:pass@ip:port"},
    },
    "akamai": {
        "summary": "Harvest an Akamai Bot Manager _abck clearance cookie (caller passes the Akamai-fronted url)",
        "value": {"type": "akamai",
                  "url": "https://www.example-akamai-site.com/",
                  "proxy": "http://user:pass@ip:port"},
    },
    "perimeterx": {
        "summary": "PerimeterX/HUMAN 'Press & Hold' → harvest _px3 clearance cookie (render_flow trigger)",
        "value": {"type": "perimeterx", "render_flow": "outlook_signup",
                  "proxy": "http://user:pass@ip:port"},
    },
    "slider": {
        "summary": "Slider gap (ddddocr → YOLO → Canny cascade)",
        "value": {"type": "slider",
                  "target_image": "<base64 puzzle piece>",
                  "background_image": "<base64 background>"},
    },
    "geetest": {
        "summary": "Geetest v4 pure-HTTP (slide/icon/gobang/ai) — captcha_id only",
        "value": {"type": "geetest",
                  "captcha_id": "54088bb07d2df3c46b79f80300b0abbe",
                  "risk_type": "slide"},
    },
}


# ── Response models (documentation shapes; solvers return supersets) ──
class SolveResponse(BaseModel):
    type: str = Field(..., description="Echoes the request type — the dispatch discriminator.",
                      examples=["turnstile"])
    solved: bool = Field(..., description="THE success signal. True iff the captcha was solved, "
                         "uniform across every type — read this instead of branching per-type.")
    token: Optional[str] = Field(None, description="Solved token for token types (engines/ts/"
                                 "engines/rc/hcaptcha). Absent for type=cloudflare (see cf_clearance); "
                                 "empty string on a failed/realpage solve — trust `solved`, not this.")
    method: Optional[str] = Field(None, description="Which path solved it (route | execute | real-page | image | …).")
    usage: Optional[str] = Field(
        None,
        description="Honesty label: portable | portable_testing_key | same_session_only | unknown. "
                    "Default same_session_only until pure-HTTP siteverify with secret upgrades it. "
                    "For CF dash signup (sitekey Jel0… + action=signup) see portable_scopes — "
                    "create may still work pure-HTTP across IP while usage stays same_session_only "
                    "(under-claim without real secret).",
        examples=["same_session_only", "portable_testing_key", "portable"],
    )
    portable_scopes: Optional[list[str]] = Field(
        None,
        description="Narrow empirically proven pure-HTTP scopes for this mint (not universal). "
                    "e.g. cf_dash_user_create, workers_demo_pipeline, cf_testing_key_siteverify, "
                    "siteverify_real_secret. Empty/absent = no extra proven scope beyond usage.",
        examples=[["cf_dash_user_create"]],
    )
    consumer_contract: Optional[str] = Field(
        None,
        description="How to consume this token safely (warmup, UA, proxy, scope limits).",
    )
    elapsed: Optional[float] = Field(None, description="Solve time (seconds).")
    error: Optional[str] = Field(None, description="Set when the solve failed but returned 200.")
    # Per-type success/detail discriminators (present only for their type):
    verify_success: Optional[bool] = Field(None, description="realpage variants: token harvested + verified.")
    success: Optional[bool] = Field(None, description="Page-level (engines/cf/awswaf): cookie obtained.")
    cf_clearance: Optional[dict] = Field(None, description="type=cloudflare: the cf_clearance cookie record.")
    user_agent: Optional[str] = Field(None, description="UA used during mint — replay with same UA when possible.")
    proxy: Optional[str] = Field(None, description="Proxy used during mint (IP-bound cookies / sticky).")
    model_config = {"extra": "allow"}  # solvers add expires_in, score, cookies, post_fetch, …


class ErrorResponse(BaseModel):
    detail: str = Field(..., description="Human-readable error message")


# Schematized non-2xx responses for /solve (422 is auto-documented by FastAPI).
_SOLVE_ERROR_RESPONSES = {
    400: {"model": ErrorResponse, "description": "Bad request — unsupported type, missing sitekey for a widget type, or an SSRF-rejected URL"},
    408: {"model": ErrorResponse, "description": "Global deadline (timeout_s) exceeded before a result"},
    500: {"model": ErrorResponse, "description": "Unhandled solver error"},
}


class HealthResponse(BaseModel):
    status: str = Field(examples=["ok"])
    supported_types: list[str] = Field(examples=[["turnstile", "recaptcha", "hcaptcha"]])
    ocr_engines: Optional[dict] = None
    compat: Optional[dict] = None
    model_config = {"extra": "allow"}


class StatusResponse(BaseModel):
    services: dict[str, str]
    current: list[dict[str, Any]] = Field(description="Currently running solve tasks.")


class LogsResponse(BaseModel):
    logs: list[dict[str, Any]]
    total: int


@app.get("/v1/health", response_model=HealthResponse, tags=["monitoring"],
         operation_id="health",
         summary="Liveness + supported types (public, no auth)")
async def health():
    """Public liveness probe. Lists the captcha types this service can solve."""
    out = {"status": "ok", "supported_types": SUPPORTED}
    try:
        from csm.imagesolve import engines_status
        out["ocr_engines"] = engines_status()
    except Exception:
        pass
    try:
        from csm.mistral import vision_status
        out["vision"] = vision_status()
    except Exception as e:
        out["vision"] = {"ready": False, "error": str(e)[:80]}
    try:
        from csm.proxypool import proxy_stats
        out["proxy"] = proxy_stats()
        try:
            from engines.ts.runner import _max_concurrent
            out["turnstile_max_concurrent"] = _max_concurrent()
            from engines.ts.runner import browser_pool_stats
            out["browser_pool"] = browser_pool_stats()
        except Exception:
            pass
    except Exception as e:
        out["proxy"] = {"count": 0, "error": str(e)[:80]}
    # Optional GPL hcaptcha-challenger sidecar (process boundary, not source merge)
    try:
        from csm.hcaptcha_sidecar_client import (
            sidecar_enabled, sidecar_health, sidecar_base,
        )
        h = sidecar_health(timeout=2.0)
        out["hcaptcha_sidecar"] = {
            "enabled": sidecar_enabled(),
            "url": sidecar_base(),
            **h,
        }
    except Exception as e:
        out["hcaptcha_sidecar"] = {"enabled": False, "error": str(e)[:80]}
    # Advertise YesCaptcha-compatible facade paths
    out["compat"] = {
        "yescaptcha": ["/v1/createTask", "/v1/getTaskResult", "/v1/getBalance"],
        "native": ["/v1/task", "/v1/health", "/v1/status", "/v1/logs"],
        "hcaptcha_sidecar": "optional GPL process :8878 (HCAPTCHA_SIDECAR_FALLBACK=1)",
    }
    return out


def _extract(req: SolveRequest):
    """Unpack pre_actions + post_fetch for realpage endpoints."""
    actions = [a.model_dump() for a in req.pre_actions] if req.pre_actions else None
    fetches = [f.model_dump() for f in req.post_fetch] if req.post_fetch else None
    return actions, fetches


async def _dispatch(req: SolveRequest) -> dict:
    """Run the actual solver for req.type/version and return its result dict.

    Result always carries a top-level "type"; the caller logs + returns it.
    """
    if req.type in ("image_text", "math"):
        # Free local OCR cascade (ddddocr → ppllocr → Tesseract → optional VL).
        from csm.imagesolve import run_image
        import asyncio as _asyncio
        r = await _asyncio.to_thread(run_image, req.image or "", req.type)
        # Cap/Yes clients expect solution.text; native clients often read .text too.
        if r.get("token") and not r.get("text"):
            r = {**r, "text": r.get("token")}
        return {"type": req.type, **r}

    if req.type == "slider":
        from csm.imagesolve import run_slider
        import asyncio as _asyncio
        # simple=None → dual-try both simple_target modes (free hit-rate max)
        simple_arg = req.simple if req.simple is not None else None
        r = await _asyncio.to_thread(
            run_slider,
            req.target_image or req.image or "",
            req.background_image or "",
            simple_arg,
        )
        return {"type": "slider", **r}

    if req.type == "turnstile":
        from engines.ts.runner import (
            run_ts,
            run_ts_explicit,
            run_ts_verify,
            run_ts_realpage,
        )
        # route/explicit/realpage raise TimeoutError on no-token; catch so we return
        # uniform 200 {error} instead of colliding with the outer asyncio deadline (408).
        method_hint = "route"
        try:
            mode = (getattr(req, "mint_method", None) or "").strip().lower()
            # also accept body field via extra: real_page / explicit
            if req.verify_url and req.verify_payload is not None:
                method_hint = "explicit"
                r = await run_ts_verify(
                    req.sitekey, req.verify_url, req.verify_payload, req.action,
                    cdata=req.cdata, page_url=req.page_url)
            elif req.real_page:
                method_hint = "real-page"
                actions, fetches = _extract(req)
                # Reserve ~25s of wall for browser launch under outer timeout_s.
                # Client timeout_s is overall; realpage harvest uses the same budget.
                r = await run_ts_realpage(
                    req.url, req.sitekey, req.timeout_s or 90, actions, fetches,
                    proxy=req.proxy)
            else:
                # Default mint path: explicit render+callback (more reliable than bare
                # implicit widget). Set method=route to force legacy intercept.
                use_explicit = mode not in ("route", "legacy", "intercept")
                if use_explicit:
                    method_hint = "explicit"
                    r = await run_ts_explicit(
                        req.sitekey, req.url, req.action, req.cdata,
                        proxy=req.proxy, timeout_s=req.timeout_s or 60)
                else:
                    method_hint = "route"
                    r = await run_ts(
                        req.sitekey, req.url, req.action, req.cdata, proxy=req.proxy)
        except TimeoutError as e:
            r = {"token": "", "error": str(e), "method": method_hint,
                 "usage": "same_session_only"}
        r = await _with_paid_fallback(req, r)
        # Portable / SIM-asli probe: pure-HTTP siteverify outside mint browser.
        # Consumes the token (single-use). Only when caller supplies secret.
        token = (r or {}).get("token") or ""
        if token and req.secret:
            mint_proxy = (r or {}).get("proxy") or req.proxy
            sv = await asyncio.to_thread(
                _pure_http_turnstile_siteverify,
                token,
                req.secret,
                None,  # remoteip optional; proxy path carries source IP
                mint_proxy,
            )
            body = sv.get("body") or {}
            r["siteverify"] = body
            r["siteverify_http"] = sv.get("http_status")
            r["siteverify_via_proxy"] = sv.get("via_proxy")
            # token class for consumers
            if token.startswith("XXXX.DUMMY") or token == "XXXX.DUMMY.TOKEN.XXXX":
                r["token_class"] = "cf_testing_dummy"
            else:
                r.setdefault("token_class", "turnstile_v0" if len(token) > 50 else "opaque")
            if body.get("success"):
                # Dummy testing keys prove pipeline only — not production portable SIM.
                if r.get("token_class") == "cf_testing_dummy":
                    r["usage"] = "portable_testing_key"
                    r["portable"] = True
                    r["sim_note"] = "cf_testing_key_only"
                else:
                    r["usage"] = "portable"
                    r["portable"] = True
            else:
                r["portable"] = False
                r.setdefault("usage", "same_session_only")
                if sv.get("error"):
                    r["siteverify_error"] = sv["error"]
                if sv.get("proxy_error"):
                    r["siteverify_proxy_error"] = sv["proxy_error"]
        r = _turnstile_consumer_fields(req, r or {})
        return {"type": "turnstile", **r}

    if req.type == "hcaptcha":
        from engines.hc.runner import run_hc, run_hc_invisible, run_hc_realpage
        if req.action == "invisible":
            r = await run_hc_invisible(req.sitekey, req.url)
        elif req.real_page:
            actions, fetches = _extract(req)
            r = await run_hc_realpage(
                req.url, req.sitekey, req.timeout_s, actions, fetches)
        else:
            r = await run_hc(req.sitekey, req.url)
        r = await _with_paid_fallback(req, r)
        return {"type": "hcaptcha", **r}

    if req.type == "cloudflare":
        from engines.cf.runner import run_cf_clearance
        actions, fetches = _extract(req)
        r = await run_cf_clearance(req.url, req.proxy, req.timeout_s, actions, fetches)
        return {"type": "cloudflare", **r}

    if req.type == "awswaf":
        from engines.aw.runner import run_aw_waf
        actions, fetches = _extract(req)
        r = await run_aw_waf(req.url, req.proxy, req.timeout_s, actions, fetches)
        return {"type": "awswaf", **r}

    if req.type == "botguard":
        from engines.bg.runner import run_bg
        actions, _ = _extract(req)
        r = await run_bg(
            url=req.url, email=req.email, password=req.password,
            proxy=req.proxy, timeout_s=req.timeout_s or 90, pre_actions=actions)
        return {"type": "botguard", **r}

    if req.type == "datadome":
        from engines.dd.runner import run_dd
        r = await run_dd(
            url=req.url, referer=req.referer,
            proxy=req.proxy, timeout_s=req.timeout_s or 60)
        return {"type": "datadome", **r}

    if req.type == "perimeterx":
        from engines.px.runner import run_px
        r = await run_px(
            url=req.url, render_flow=req.render_flow or "outlook_signup",
            proxy=req.proxy, timeout_s=req.timeout_s or 200)
        return {"type": "perimeterx", **r}

    if req.type == "akamai":
        from engines.ak.runner import run_ak
        actions, fetches = _extract(req)
        r = await run_ak(req.url, req.proxy, req.timeout_s or 90, actions, fetches)
        return {"type": "akamai", **r}

    if req.type == "aliyun":
        # Dispatch to a SUBPROCESS (aliyun._run), not an inline await. The drag trajectory
        # depends on precise CDP Input.dispatchMouseEvent timing that is fidelity-sensitive
        # to running on the MAIN thread with a clean event loop. Proven empirically:
        #   asyncio.run(run_ay) on main thread   -> 3/3 T001
        #   awaited on uvicorn's loop                  -> 0/12 F001
        #   asyncio.run inside asyncio.to_thread       -> 0/12 F001 (off main thread)
        # A subprocess runs its own main-thread asyncio.run, exactly reproducing the
        # working direct-call conditions -> T001.
        import os as _os
        _to = req.timeout_s or 90
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "engines.ay._run",
            req.scene_id or "", req.prefix or "", req.region or "sgp",
            str(_to), req.proxy or "",
            cwd=_os.path.dirname(_os.path.abspath(__file__)),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=_to + 30)
        except asyncio.TimeoutError:
            proc.kill()
            return {"type": "aliyun", "solved": False, "error": "subprocess deadline"}
        r = {"solved": False, "error": "no result from runner"}
        for line in (out or b"").decode(errors="replace").splitlines():
            if line.startswith("__ALIYUN_RESULT__"):
                r = json.loads(line[len("__ALIYUN_RESULT__"):])
                break
        return {"type": "aliyun", **r}

    if req.type == "geetest":
        from engines.gt.runner import run_gt
        import asyncio as _asyncio
        cid = (req.captcha_id or req.sitekey or "").strip()
        risk = (req.risk_type or "slide").strip().lower()
        r = await _asyncio.to_thread(
            run_gt, cid, risk, req.proxy, req.timeout_s or 60)
        return {"type": "geetest", **r}

    # reCAPTCHA
    from engines.rc.runner import (
        run_rc_v3, run_rc_v3_realpage, run_rc_invisible,
        run_rc_v2, run_rc_v2_realpage,
    )
    version = req.version or "v2"  # default v2 (checkbox)
    if version == "v3":
        if req.real_page:
            actions, _ = _extract(req)
            r = await run_rc_v3_realpage(
                req.url, req.sitekey, req.action or "submit",
                enterprise=req.enterprise, timeout_s=req.timeout_s, pre_actions=actions)
        else:
            r = await run_rc_v3(
                req.sitekey, req.url, req.action or "submit",
                req.secret, enterprise=req.enterprise)
    elif version == "invisible":
        r = await run_rc_invisible(
            req.sitekey, req.url, req.action or "submit", enterprise=req.enterprise)
    elif version == "v2":
        if req.real_page:
            actions, fetches = _extract(req)
            r = await run_rc_v2_realpage(
                req.url, req.sitekey, actions, fetches, timeout_s=req.timeout_s)
        else:
            r = await run_rc_v2(req.sitekey, req.url, enterprise=req.enterprise, timeout_s=req.timeout_s)
    else:
        raise HTTPException(400, f"Unknown version: {version}. Use v3|invisible|v2")
    r = await _with_paid_fallback(req, r)
    return {"type": "recaptcha", **r}


@app.post("/v1/task", response_model=SolveResponse, tags=["solve"],
          operation_id="solve",
          dependencies=[Depends(_bearer)],
          summary="Solve a captcha (dispatch by type)",
          responses=_SOLVE_ERROR_RESPONSES)
async def solve(req: SolveRequest = Body(..., openapi_examples=_SOLVE_EXAMPLES)):
    """Solve any supported captcha and return the token.

    Dispatch is by `type`; the variant is selected by optional fields:

    - **Turnstile** — default route-intercept; `verify_url`+`verify_payload` to
      solve-and-verify; `real_page:true` to drive the live page (pre_actions/post_fetch).
    - **reCAPTCHA** — `version`: `v2` (checkbox + Mistral image fallback, `real_page` supported),
      `v3` (score; pass `secret` to also return the score), `invisible`. `enterprise:true`
      for Enterprise keys.
    - **hCaptcha** — default checkbox (Mistral image/drag fallback); `action:"invisible"`
      for the execute path; `real_page:true` for the live page.
    - **cloudflare** — pass the full-page Cloudflare interstitial (Managed or JS challenge)
      and return the `cf_clearance` cookie + `user_agent` + all cookies. No `sitekey`;
      pass `proxy` so the cookie is bound to a replayable IP. See the README for the
      replay contract (IP + JA3 + UA must match).
    - **awswaf** — navigate an AWS-WAF-protected URL, let the silent JS challenge set
      `aws-waf-token`, and return it + `user_agent` + all cookies. No `sitekey`; pass
      `proxy` (same IP-bound replay contract as cloudflare). Silent challenge only —
      no interactive visual-puzzle support.

    **Success signal:** every response carries a uniform top-level `solved` bool — read
    it and don't branch per-type. Type-specific detail still rides along (`token`,
    `cf_clearance`, `score`, `expires_in`, `cookies`, `user_agent`, `post_fetch`, …).

    **Error contract (two rules):** a solve that ran but didn't succeed returns **200**
    with `solved:false` + `error` set. A **4xx/5xx** means the request never solved —
    FastAPI's `{detail}` envelope (400 bad input, 408 timeout, 422 schema, 500 crash).
    So: 2xx → read `solved`; non-2xx → read `detail`. Never both.
    """
    if req.type not in SUPPORTED:
        raise HTTPException(400, f"Unsupported type: {req.type}. Supported: {SUPPORTED}")
    # Self-URL solvers default their own canonical URL so downstream logging has a str.
    if req.type == "botguard" and not req.url:
        req.url = "https://accounts.google.com/signin/v2/identifier?flowName=GlifWebSignIn"
    if req.type == "perimeterx" and not req.url:
        # PerimeterX press-hold gate is reached via the new-@outlook.com-mailbox flow.
        req.url = ("https://go.microsoft.com/fwlink/p/?linkid=2125440"
                   "&clcid=0x409&culture=en-us&country=us")
    # Image solvers need no url/sitekey — just base64 payload(s).
    _is_image = req.type in ("image_text", "math", "slider")
    if req.type in ("image_text", "math") and not req.image:
        raise HTTPException(400, f"image (base64) is required for type={req.type}")
    if req.type == "slider":
        tgt = req.target_image or req.image
        bg = req.background_image
        if not tgt or not bg:
            raise HTTPException(
                400, "slider requires target_image (or image) + background_image (base64)")
    if req.type == "geetest":
        cid = (req.captcha_id or req.sitekey or "").strip()
        if not cid:
            raise HTTPException(400, "captcha_id (or sitekey) is required for type=geetest")
        # normalize so logs / dispatch see captcha_id
        req.captcha_id = cid
    if not _is_image and not req.url and req.type not in _SELF_URL:  # goto("") is meaningless
        raise HTTPException(400, "url is required")
    if req.type == "aliyun" and (not req.scene_id or not req.prefix):
        raise HTTPException(400, "scene_id and prefix are required for type=aliyun")
    if (not _is_image and req.type not in _PAGE_LEVEL and req.type != "aliyun"
            and req.type != "geetest" and not req.sitekey):
        raise HTTPException(400, f"sitekey is required for type={req.type}")
    if not _is_image and req.type != "geetest":
        _validate_urls(req)

    sk = req.sitekey or ""  # cloudflare has no sitekey
    log.info("Solve: type=%s sitekey=%s url=%s", req.type, sk[:12], req.url)

    task_id = next(_task_ids)
    _url = req.url or ""   # self-hosted solvers (aliyun, botguard, ...) carry no url
    _solve_current[task_id] = {
        "type": req.type,
        "sitekey": sk[:12] + ("..." if len(sk) > 12 else ""),
        "url": _url[:60] + ("..." if len(_url) > 60 else ""),
        "version": req.version or None,
        "started_at": time.time(),
    }
    try:
        # Global deadline: a hung browser can't wedge the per-type lock forever — the
        # timeout cancels the coroutine, releasing the lock (caller sees 408). A solver's
        # own no-token TimeoutError is caught INSIDE _dispatch, so a bare TimeoutError
        # here is only ever the real deadline.
        async with asyncio.timeout(req.timeout_s or 180):
            result = await _dispatch(req)
        # ONE success signal for every type — callers read result["solved"], never branch.
        result["solved"] = _is_solved(result)
        _log_solve(req.type, req.sitekey, req.url, result)
        return result
    except (TimeoutError, asyncio.TimeoutError):
        raise HTTPException(408, f"solve timed out after {req.timeout_s or 180}s")
    except HTTPException:
        raise
    except Exception as e:
        log.error("Solve failed: %s", e, exc_info=True)
        raise HTTPException(500, str(e))
    finally:
        _solve_current.pop(task_id, None)


@app.get("/v1/logs", response_model=LogsResponse, tags=["monitoring"],
         operation_id="getLogs",
         dependencies=[Depends(_bearer)],
         summary="Recent solve events (ring buffer)")
async def get_logs(lines: int = Query(50, ge=1, le=200, description="How many recent events (max 200)")):
    """Last N solve events (max 200). Tokens are recorded as a boolean, never stored.
    `total` is the full ring-buffer size; `logs` is the requested slice of it."""
    # lines is already clamped to [1,200] by Query(ge/le) — no re-clamp needed.
    return {"logs": list(_solve_log)[:lines], "total": len(_solve_log)}


@app.get("/v1/status", response_model=StatusResponse, tags=["monitoring"],
         operation_id="status",
         dependencies=[Depends(_bearer)],
         summary="Service status + currently running tasks")
async def solver_status():
    """Per-type online status and the list of in-flight solve tasks."""
    return {
        "services": {t: "online" for t in SUPPORTED},
        "current": list(_solve_current.values()),
    }


# ── YesCaptcha / CapSolver-compatible facade (MIT original) ──────────
# Lets existing clients that speak createTask/getTaskResult point here
# without code changes. Free-first: routes into the same /solve dispatch.

class _YesBody(BaseModel):
    clientKey: Optional[str] = None
    task: Optional[dict] = None
    taskId: Optional[str] = None
    model_config = {"extra": "allow"}


async def _solve_from_dict(body: dict) -> dict:
    """Build SolveRequest from a plain dict and run _dispatch + solved flag."""
    req = SolveRequest(**{k: v for k, v in body.items()
                          if k in SolveRequest.model_fields})
    # Minimal validation (image types skip url/sitekey)
    _is_image = req.type in ("image_text", "math", "slider")
    if req.type in ("image_text", "math") and not req.image:
        return {"type": req.type, "solved": False, "error": "image required"}
    if req.type == "slider":
        tgt = req.target_image or req.image
        bg = req.background_image
        if not tgt or not bg:
            return {"type": "slider", "solved": False,
                    "error": "slider needs target_image + background_image"}
    if not _is_image and not req.url and req.type not in _SELF_URL:
        return {"type": req.type, "solved": False, "error": "url required"}
    if not _is_image and req.type not in _PAGE_LEVEL and req.type != "aliyun" and not req.sitekey:
        return {"type": req.type, "solved": False, "error": "sitekey required"}
    try:
        result = await _dispatch(req)
        result["solved"] = _is_solved(result)
        return result
    except Exception as e:
        log.error("compat solve failed: %s", e, exc_info=True)
        return {"type": req.type, "solved": False, "error": str(e)}


@app.post("/v1/createTask", tags=["solve"],
          summary="YesCaptcha-compatible createTask",
          operation_id="createTask")
async def create_task(body: _YesBody = Body(...)):
    """CapSolver/YesCaptcha protocol: create a task, returns taskId immediately.

    Poll `/getTaskResult` until status=ready. Free-first; same engines as `/solve`.
    Optional `SOLVER_CLIENT_KEY` env enforces clientKey if set.
    """
    from csm.yescaptcha_api import create_task as _ct
    return await _ct(body.clientKey, body.task or {}, _solve_from_dict)


@app.post("/v1/getTaskResult", tags=["solve"],
          summary="YesCaptcha-compatible getTaskResult",
          operation_id="getTaskResult")
async def get_task_result(body: _YesBody = Body(...)):
    """Poll task status. Returns processing | ready(+solution) | error envelope."""
    from csm.yescaptcha_api import get_task_result as _gtr
    return _gtr(body.clientKey, body.taskId)


@app.post("/v1/getBalance", tags=["monitoring"],
          summary="YesCaptcha-compatible getBalance (symbolic for free service)",
          operation_id="getBalance")
async def get_balance(body: _YesBody = Body(default=_YesBody())):
    from csm.yescaptcha_api import get_balance as _gb
    return _gb(body.clientKey if body else None)




# --- legacy path aliases (local ops / older clients) ---
@app.get("/health", include_in_schema=False, tags=["monitoring"])
async def legacy_health():
    return await health()

@app.post("/solve", include_in_schema=False, tags=["solve"])
async def legacy_solve(req: SolveRequest):
    return await solve(req)

@app.get("/logs", include_in_schema=False, tags=["monitoring"])
async def legacy_logs():
    return await get_logs()

@app.get("/status", include_in_schema=False, tags=["monitoring"])
async def legacy_status():
    return await solver_status()

@app.post("/createTask", include_in_schema=False, tags=["solve"])
async def legacy_create_task(body: dict = Body(...)):
    return await create_task(_YesBody(**(body or {})))

@app.post("/getTaskResult", include_in_schema=False, tags=["solve"])
async def legacy_get_task_result(body: dict = Body(...)):
    return await get_task_result(_YesBody(**(body or {})))

@app.post("/getBalance", include_in_schema=False, tags=["monitoring"])
async def legacy_get_balance(body: dict = Body(None)):
    return await get_balance(_YesBody(**(body or {})))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8877"))
    uvicorn.run(app, host="0.0.0.0", port=port)
