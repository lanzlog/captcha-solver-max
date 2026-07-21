#!/usr/bin/env python3
"""CF create hard bar WITHOUT residential proxy — isolate token class (1201) vs WAF."""
from __future__ import annotations

import asyncio
import json
import os
import random
import string
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
envp = ROOT / ".env"
if envp.exists():
    for line in envp.read_text().splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

from curl_cffi.requests import AsyncSession
from csm.paid_fallback import run_paid

CF_SK = "0x4AAAAAAAJel0iaAR3mgkjp"
CF_URL = "https://dash.cloudflare.com/sign-up"
CF_CREATE = "https://dash.cloudflare.com/api/v4/user/create"
IMP = "chrome146"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)


async def create(token: str, label: str, proxy: str | None = None):
    email = (
        "ab_"
        + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        + "@ilalangliar.xyz"
    )
    password = (
        "Kx9!"
        + "".join(random.choices(string.ascii_letters + string.digits, k=14))
        + "#zQ2"
    )
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
    async with AsyncSession(
        impersonate=IMP, proxies=proxies, headers={"User-Agent": UA}
    ) as s:
        r = await s.post(
            CF_CREATE,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": UA,
                "Origin": "https://dash.cloudflare.com",
                "Referer": "https://dash.cloudflare.com/sign-up",
            },
            timeout=40,
        )
        text = r.text or ""
        try:
            data = r.json()
        except Exception:
            data = {"raw": text[:150]}
        errs = data.get("errors") or []
        code = errs[0].get("code") if errs and isinstance(errs[0], dict) else None
        msg = (
            errs[0].get("message")
            if errs and isinstance(errs[0], dict)
            else str(data.get("raw") or text[:80])
        )
        print(
            f"{label}: http={r.status_code} success={data.get('success')} "
            f"code={code} msg={str(msg)[:120]}",
            flush=True,
        )
        return {
            "label": label,
            "http": r.status_code,
            "success": data.get("success"),
            "code": code,
            "msg": str(msg)[:120],
            "token_len": len(token),
        }


async def main():
    results = []
    print("=== invalid no-proxy (baseline) ===", flush=True)
    results.append(await create("INVALID", "invalid_direct", None))

    print("=== capsolver mint + direct create ===", flush=True)
    m = await run_paid("turnstile", CF_SK, CF_URL, prefer="capsolver", poll_s=90)
    tok = m.get("token") or ""
    print("mint len", len(tok), "prefix", tok[:40], flush=True)
    if len(tok) >= 100:
        results.append(await create(tok, "capsolver_direct", None))

    print("=== 2captcha mint + direct create ===", flush=True)
    m2 = await run_paid("turnstile", CF_SK, CF_URL, prefer="twocaptcha", poll_s=120)
    tok2 = m2.get("token") or ""
    print("mint len", len(tok2), "prefix", tok2[:40], flush=True)
    if len(tok2) >= 100:
        results.append(await create(tok2, "2captcha_direct", None))

    print("=== local mint + direct create ===", flush=True)
    body = {
        "type": "turnstile",
        "sitekey": CF_SK,
        "url": CF_URL,
        "timeout_s": 120,
        "mint_method": "explicit",
    }
    req = urllib.request.Request(
        "http://127.0.0.1:8877/solve",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=160) as r:
            d = json.loads(r.read().decode())
    except Exception as e:
        d = {"error": str(e), "token": ""}
    tok3 = d.get("token") or ""
    print(
        "mint len",
        len(tok3),
        "method",
        d.get("method"),
        "prefix",
        tok3[:40],
        flush=True,
    )
    if len(tok3) >= 100:
        results.append(await create(tok3, "local_direct", None))

    print("\n==== TOKEN CLASS (no-proxy) ====", flush=True)
    for r in results:
        print(r, flush=True)
    asli = [r for r in results if r.get("success") is True]
    if asli:
        print("*** SIM ASLI ***", asli)
    else:
        print(
            "No success. 1201=fotokopi token; other codes=other; "
            "HTML/None=WAF not token class"
        )


if __name__ == "__main__":
    asyncio.run(main())
