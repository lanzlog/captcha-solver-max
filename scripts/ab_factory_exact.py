#!/usr/bin/env python3
"""Factory-exact CF create hard bar (headers/payload match cf-factory/factory.py)."""
from __future__ import annotations

import asyncio
import os
import random
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, "/home/ubuntu/cf-factory")

envp = ROOT / ".env"
if envp.exists():
    for line in envp.read_text().splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

from curl_cffi.requests import AsyncSession
from config import CF_API, IMPERSONATE, USER_AGENT
from csm.paid_fallback import run_paid
from csm.proxypool import next_proxy

CF_SK = "0x4AAAAAAAJel0iaAR3mgkjp"
CF_URL = "https://dash.cloudflare.com/sign-up"


async def factory_create(token: str, proxy: str | None, label: str):
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
        impersonate=IMPERSONATE,
        proxies=proxies,
        headers={"User-Agent": USER_AGENT},
    ) as s:
        r = await s.post(
            f"{CF_API}/api/v4/user/create",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
            timeout=40,
        )
        text = r.text or ""
        try:
            data = r.json()
        except Exception:
            data = {"raw": text[:200]}
        errs = data.get("errors") or []
        code = errs[0].get("code") if errs and isinstance(errs[0], dict) else None
        msg = (
            errs[0].get("message")
            if errs and isinstance(errs[0], dict)
            else text[:100]
        )
        success = data.get("success")
        print(
            f"{label}: http={r.status_code} success={success} code={code} msg={msg}",
            flush=True,
        )
        return {
            "label": label,
            "http": r.status_code,
            "success": success,
            "code": code,
            "msg": str(msg)[:120],
            "token_len": len(token),
        }


async def main():
    print("CF_API", CF_API, "IMP", IMPERSONATE, "UA", USER_AGENT[:60], flush=True)
    results = []

    results.append(await factory_create("INVALID", None, "invalid_factory_exact"))

    proxy = next_proxy()
    print("proxy", (proxy or "")[-40:], flush=True)

    m = await run_paid("turnstile", CF_SK, CF_URL, prefer="capsolver", poll_s=90)
    tok = m.get("token") or ""
    print("capsolver len", len(tok), "prefix", tok[:40], flush=True)
    if len(tok) >= 100:
        results.append(await factory_create(tok, None, "cap_noproxy_factory"))
        m2 = await run_paid(
            "turnstile", CF_SK, CF_URL, prefer="capsolver", poll_s=90
        )
        tok2 = m2.get("token") or ""
        print("capsolver2 len", len(tok2), flush=True)
        if len(tok2) >= 100:
            results.append(await factory_create(tok2, proxy, "cap_proxy_factory"))

    m3 = await run_paid(
        "turnstile", CF_SK, CF_URL, prefer="twocaptcha", poll_s=120
    )
    tok3 = m3.get("token") or ""
    print(
        "2cap len",
        len(tok3),
        "prefix",
        tok3[:40],
        "ua",
        m3.get("user_agent"),
        flush=True,
    )
    if len(tok3) >= 100:
        results.append(await factory_create(tok3, None, "2cap_noproxy_factory"))
        m4 = await run_paid(
            "turnstile", CF_SK, CF_URL, prefer="twocaptcha", poll_s=120
        )
        tok4 = m4.get("token") or ""
        print("2cap2 len", len(tok4), flush=True)
        if len(tok4) >= 100:
            results.append(await factory_create(tok4, proxy, "2cap_proxy_factory"))

    # local
    import json
    import urllib.request

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
    tok5 = d.get("token") or ""
    print(
        "local len",
        len(tok5),
        "method",
        d.get("method"),
        "prefix",
        tok5[:40],
        flush=True,
    )
    if len(tok5) >= 100:
        results.append(await factory_create(tok5, None, "local_noproxy_factory"))
        # local with its mint proxy
        mproxy = d.get("proxy") or proxy
        body2 = dict(body)
        req2 = urllib.request.Request(
            "http://127.0.0.1:8877/solve",
            data=json.dumps(body2).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req2, timeout=160) as r:
                d2 = json.loads(r.read().decode())
        except Exception as e:
            d2 = {"token": "", "error": str(e)}
        tok6 = d2.get("token") or ""
        print("local2 len", len(tok6), flush=True)
        if len(tok6) >= 100:
            results.append(
                await factory_create(
                    tok6, d2.get("proxy") or mproxy, "local_proxy_factory"
                )
            )

    print("\n==== FACTORY-EXACT SUMMARY ====", flush=True)
    for r in results:
        print(r, flush=True)
    asli = [r for r in results if r.get("success") is True]
    if asli:
        print("*** SIM ASLI FOUND ***", asli)
    else:
        codes = [(r["label"], r.get("code"), r.get("http")) for r in results]
        print("No SIM_ASLI. (label, code, http):", codes)


if __name__ == "__main__":
    asyncio.run(main())
