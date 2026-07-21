#!/usr/bin/env python3
"""Hard-bar only: paid vs local token → CF user/create via curl_cffi impersonate.

Mirrors ~/cf-factory/factory.py TLS fingerprint (chrome146) so we measure
token class (1201) not WAF HTML 403 from bare urllib.
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import string
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# load .env if present
envp = ROOT / ".env"
if envp.exists():
    for line in envp.read_text().splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

from curl_cffi.requests import AsyncSession

CF_SK = "0x4AAAAAAAJel0iaAR3mgkjp"
CF_URL = "https://dash.cloudflare.com/sign-up"
CF_CREATE = "https://dash.cloudflare.com/api/v4/user/create"
IMPERSONATE = "chrome146"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
SOLVER = "http://127.0.0.1:8877"


def pick_proxy() -> str | None:
    try:
        from csm.proxypool import next_proxy
        return next_proxy()
    except Exception:
        pf = os.getenv("SOLVER_PROXY_FILE", "")
        if pf and Path(pf).exists():
            lines = [l.strip() for l in Path(pf).read_text().splitlines() if l.strip() and not l.startswith("#")]
            if not lines:
                return None
            raw = random.choice(lines)
            # host:port:user:pass → http://user:pass@host:port
            parts = raw.split(":")
            if len(parts) == 4:
                host, port, user, pw = parts
                return f"http://{user}:{pw}@{host}:{port}"
            if "://" in raw:
                return raw
        return None


async def mint_paid(provider: str) -> dict:
    from csm.paid_fallback import run_paid
    t0 = time.time()
    r = await run_paid("turnstile", CF_SK, CF_URL, prefer=provider, poll_s=150)
    r["_wall"] = round(time.time() - t0, 1)
    return r


async def mint_local() -> dict:
    import urllib.request
    body = {
        "type": "turnstile",
        "sitekey": CF_SK,
        "url": CF_URL,
        "timeout_s": 120,
        "mint_method": "explicit",
    }
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{SOLVER}/solve", data=data,
        headers={"Content-Type": "application/json"}, method="POST")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=160) as resp:
            r = json.loads(resp.read().decode())
    except Exception as e:
        r = {"solved": False, "token": "", "error": str(e)}
    r["_wall"] = round(time.time() - t0, 1)
    r["method"] = r.get("method") or "local"
    return r


async def create_with_token(token: str, ua: str | None, proxy: str | None) -> dict:
    email = "ab_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10)) + "@ilalangliar.xyz"
    password = "Kx9!" + "".join(random.choices(string.ascii_letters + string.digits, k=14)) + "#zQ2"
    payload = {
        "email": email,
        "password": password,
        "mrk_optin": True,
        "security_token": "",
        "method": "Onboarding: New_v2",
        "locale": "en-US",
        "legal_stamp": "",
        "opt_ins": {},
        "mrktCheckboxDisplayed": False,
        "hCaptchaDisplayed": False,
        "cf_challenge_response": token,
    }
    proxies = {"http": proxy, "https": proxy} if proxy else None
    async with AsyncSession(impersonate=IMPERSONATE, proxies=proxies, headers={"User-Agent": ua or UA}) as s:
        r = await s.post(
            CF_CREATE,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": ua or UA,
                "Origin": "https://dash.cloudflare.com",
                "Referer": "https://dash.cloudflare.com/sign-up",
            },
            timeout=40,
        )
        try:
            data = r.json()
        except Exception:
            data = {"raw": (r.text or "")[:300]}
        return {
            "http": r.status_code,
            "email": email,
            "success": data.get("success"),
            "errors": data.get("errors"),
            "result": data.get("result"),
            "raw_prefix": (r.text or "")[:120],
        }


async def run_one(name: str, mint_coro) -> dict:
    print(f"\n=== {name} ===", flush=True)
    m = await mint_coro
    tok = m.get("token") or ""
    print(f"mint solved={m.get('solved')} method={m.get('method')} len={len(tok)} "
          f"prefix={tok[:40]} wall={m.get('_wall')} err={m.get('error')}", flush=True)
    if len(tok) < 100:
        return {"case": name, "mint": False, "token_len": len(tok), "sim": "MINT_FAIL",
                "error": m.get("error")}

    # always residential for CF create (factory rule)
    proxy = m.get("proxy") or pick_proxy()
    ua = m.get("user_agent") or UA
    print(f"create proxy={(proxy or '')[-40:]} ua={ua[:50]}", flush=True)
    cr = await create_with_token(tok, ua, proxy)
    errs = cr.get("errors") or []
    code = errs[0].get("code") if errs and isinstance(errs[0], dict) else None
    msg = errs[0].get("message") if errs and isinstance(errs[0], dict) else cr.get("raw_prefix")
    print(f"create http={cr.get('http')} success={cr.get('success')} code={code} msg={str(msg)[:100]}", flush=True)

    if cr.get("success") is True:
        sim = "SIM_ASLI_portable"
    elif code == 1201:
        sim = "SIM_FOTOKOPI_1201"
    elif code:
        sim = f"CF_ERR_{code}"
    else:
        sim = f"CF_HTTP_{cr.get('http')}"

    return {
        "case": name,
        "mint": True,
        "token_len": len(tok),
        "token_prefix": tok[:40],
        "method": m.get("method"),
        "usage": m.get("usage"),
        "create_http": cr.get("http"),
        "create_success": cr.get("success"),
        "create_code": code,
        "create_msg": str(msg)[:120],
        "sim": sim,
        "email": cr.get("email"),
    }


async def main():
    from csm.paid_fallback import available
    print("paid", available(), flush=True)
    results = []
    # paid first (known mint), then local
    results.append(await run_one("capsolver", mint_paid("capsolver")))
    results.append(await run_one("twocaptcha", mint_paid("twocaptcha")))
    results.append(await run_one("local_explicit", mint_local()))

    print("\n==== HARD BAR SUMMARY ====")
    for r in results:
        print(json.dumps(r))
    asli = [r for r in results if r.get("sim") == "SIM_ASLI_portable"]
    if asli:
        print("\n*** SIM ASLI FOUND ***", [r["case"] for r in asli])
    else:
        print("\nNo SIM_ASLI yet. Codes:", [(r["case"], r.get("sim"), r.get("create_code")) for r in results])


if __name__ == "__main__":
    import json
    asyncio.run(main())
