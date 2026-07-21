#!/usr/bin/env python3
"""Probe CF create WAF vs token class with curl_cffi warm session."""
from __future__ import annotations

import asyncio
import os
import random
import string
import sys
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
from csm.proxypool import next_proxy

CF_SK = "0x4AAAAAAAJel0iaAR3mgkjp"
CF_URL = "https://dash.cloudflare.com/sign-up"
CF_CREATE = "https://dash.cloudflare.com/api/v4/user/create"
IMP = "chrome146"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)


def gen_creds():
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
    return email, password


async def try_create(label: str, token: str, proxy: str | None, warm: bool = True):
    email, password = gen_creds()
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
        if warm:
            try:
                r0 = await s.get(CF_URL, timeout=30)
                print(
                    f"  warm GET status={r0.status_code} cookies={len(s.cookies)}",
                    flush=True,
                )
            except Exception as e:
                print(f"  warm fail {e}", flush=True)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": UA,
            "Origin": "https://dash.cloudflare.com",
            "Referer": "https://dash.cloudflare.com/sign-up",
            "Accept": "application/json, text/plain, */*",
        }
        r = await s.post(CF_CREATE, json=payload, headers=headers, timeout=40)
        text = r.text or ""
        try:
            data = r.json()
        except Exception:
            data = {"raw": text[:200]}
        errs = data.get("errors") or []
        code = errs[0].get("code") if errs and isinstance(errs[0], dict) else None
        msg = errs[0].get("message") if errs and isinstance(errs[0], dict) else text[:80]
        print(
            f"{label}: http={r.status_code} success={data.get('success')} "
            f"code={code} msg={str(msg)[:120]}",
            flush=True,
        )
        return {
            "http": r.status_code,
            "success": data.get("success"),
            "code": code,
            "msg": str(msg)[:120],
        }


async def main():
    proxy = next_proxy()
    print("proxy", (proxy or "")[-50:], flush=True)

    m = await run_paid(
        "turnstile", CF_SK, CF_URL, prefer="capsolver", poll_s=90
    )
    tok = m.get("token") or ""
    print("capsolver token len", len(tok), "prefix", tok[:40], flush=True)
    if len(tok) < 100:
        print("mint fail", m)
        return
    await try_create("warm+create", tok, proxy, warm=True)

    m2 = await run_paid(
        "turnstile", CF_SK, CF_URL, prefer="capsolver", poll_s=90
    )
    tok2 = m2.get("token") or ""
    print("capsolver2 len", len(tok2), flush=True)
    if len(tok2) >= 100:
        await try_create("cold+create", tok2, proxy, warm=False)

    m3 = await run_paid(
        "turnstile", CF_SK, CF_URL, prefer="twocaptcha", poll_s=120
    )
    tok3 = m3.get("token") or ""
    print("2captcha len", len(tok3), flush=True)
    if len(tok3) >= 100:
        await try_create("2cap warm+create", tok3, proxy, warm=True)


if __name__ == "__main__":
    asyncio.run(main())
