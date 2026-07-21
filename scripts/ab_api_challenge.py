#!/usr/bin/env python3
"""Pure-API hard bar: paid Turnstile with action/cdata/pagedata + proxy-bound mint → CF create.

NO local browser mint. Focus:
  - CapSolver AntiTurnstileTaskProxyLess + metadata.action(=signup)
  - 2Captcha TurnstileTaskProxyless / TurnstileTask with action + optional data/pagedata
  - factory-exact create (chrome146, no Origin) with mint UA + same proxy when available

Does NOT harvest pagedata via browser — that would violate operator "bukan browser mode".
If pagedata is required and unknown, report residual blocker honestly.
"""
from __future__ import annotations

import asyncio
import json
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
# Factory solver historically passes action=signup (no cData/pagedata known for dash widget)
ACTIONS = ["signup", "managed", ""]


def _email():
    return (
        "ab_"
        + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        + "@ilalangliar.xyz"
    )


def _password():
    return (
        "Kx9!"
        + "".join(random.choices(string.ascii_letters + string.digits, k=14))
        + "#zQ2"
    )


async def factory_create(
    token: str,
    proxy: str | None,
    label: str,
    ua: str | None = None,
):
    email = _email()
    password = _password()
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
    use_ua = ua or USER_AGENT
    proxies = {"http": proxy, "https": proxy} if proxy else None
    async with AsyncSession(
        impersonate=IMPERSONATE,
        proxies=proxies,
        headers={"User-Agent": use_ua},
    ) as s:
        r = await s.post(
            f"{CF_API}/api/v4/user/create",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": use_ua,
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
        uid = (data.get("result") or {}).get("id") if isinstance(data.get("result"), dict) else None
        print(
            f"{label}: http={r.status_code} success={success} code={code} "
            f"msg={msg} uid={uid} token_len={len(token)} proxy={bool(proxy)}",
            flush=True,
        )
        return {
            "label": label,
            "http": r.status_code,
            "success": success,
            "code": code,
            "msg": str(msg)[:120],
            "token_len": len(token),
            "user_id": uid,
            "email": email if success else None,
        }


async def mint_and_create(
    *,
    prefer: str,
    action: str | None,
    proxy: str | None,
    use_proxy_on_mint: bool,
    cdata: str | None = None,
    pagedata: str | None = None,
    results: list,
):
    act_label = action if action else "NOACTION"
    mint_proxy = proxy if use_proxy_on_mint else None
    label_base = f"{prefer}|act={act_label}|mint_proxy={bool(mint_proxy)}|cdata={bool(cdata)}|pd={bool(pagedata)}"
    print(f"\n--- mint {label_base} ---", flush=True)
    m = await run_paid(
        "turnstile",
        CF_SK,
        CF_URL,
        prefer=prefer,
        action=action or None,
        cdata=cdata,
        pagedata=pagedata,
        proxy_url=mint_proxy,
        poll_s=120,
    )
    tok = m.get("token") or ""
    ua = m.get("user_agent")
    print(
        f"mint ok={m.get('solved')} len={len(tok)} method={m.get('method')} "
        f"task={m.get('task_type')} ua={(ua or '')[:50]} err={m.get('error')}",
        flush=True,
    )
    if len(tok) < 100:
        results.append({
            "label": label_base + "|mint_fail",
            "http": None,
            "success": False,
            "code": "MINT_FAIL",
            "msg": str(m.get("error"))[:120],
            "token_len": len(tok),
        })
        return

    # Create on same proxy as mint when mint used proxy; else try factory residential
    create_proxy = mint_proxy or proxy
    # 1) same proxy + mint UA
    results.append(
        await factory_create(
            tok, create_proxy, label_base + "|create_same_proxy_mint_ua", ua=ua
        )
    )
    # If first failed with 1201 and we have budget, don't re-mint — try factory UA same proxy
    last = results[-1]
    if last.get("success") is True:
        return
    if last.get("code") == 1201 and ua and ua != USER_AGENT:
        # Need fresh token for second create attempt (tokens are single-use)
        m2 = await run_paid(
            "turnstile",
            CF_SK,
            CF_URL,
            prefer=prefer,
            action=action or None,
            cdata=cdata,
            pagedata=pagedata,
            proxy_url=mint_proxy,
            poll_s=120,
        )
        tok2 = m2.get("token") or ""
        print(f"remint factory-UA len={len(tok2)}", flush=True)
        if len(tok2) >= 100:
            results.append(
                await factory_create(
                    tok2,
                    create_proxy,
                    label_base + "|create_same_proxy_factory_ua",
                    ua=USER_AGENT,
                )
            )


async def main():
    print(
        "PURE-API challenge hard bar",
        "CF_API", CF_API,
        "IMP", IMPERSONATE,
        "UA", USER_AGENT[:50],
        flush=True,
    )
    results: list = []

    # baseline invalid
    results.append(await factory_create("INVALID", None, "invalid_baseline"))

    proxy = next_proxy()
    print("sticky_proxy_tail", (proxy or "")[-50:], flush=True)

    # CapSolver: action variants, ProxyLess only (docs)
    for act in ["signup", "managed", None]:
        await mint_and_create(
            prefer="capsolver",
            action=act,
            proxy=proxy,
            use_proxy_on_mint=False,  # CapSolver has no Turnstile proxy task
            results=results,
        )
        if any(r.get("success") is True for r in results):
            break

    # 2captcha: proxyless + proxy-bound, action variants
    if not any(r.get("success") is True for r in results):
        for act in ["signup", "managed", None]:
            # proxy-bound first (IP align hypothesis)
            await mint_and_create(
                prefer="twocaptcha",
                action=act,
                proxy=proxy,
                use_proxy_on_mint=True,
                results=results,
            )
            if any(r.get("success") is True for r in results):
                break
            await mint_and_create(
                prefer="twocaptcha",
                action=act,
                proxy=proxy,
                use_proxy_on_mint=False,
                results=results,
            )
            if any(r.get("success") is True for r in results):
                break

    print("\n==== PURE-API CHALLENGE SUMMARY ====", flush=True)
    for r in results:
        print(r, flush=True)
    asli = [r for r in results if r.get("success") is True]
    if asli:
        print("*** SIM ASLI FOUND ***", json.dumps(asli, default=str)[:500], flush=True)
    else:
        codes = [(r["label"], r.get("code"), r.get("http")) for r in results]
        print("No SIM_ASLI. (label, code, http):", codes, flush=True)
        print(
            "NOTE: pagedata/cData not harvested (no browser). "
            "If CF dash is challenge-page class, pure-API needs those values "
            "from a non-browser source (HAR/network dump) or remains blocked.",
            flush=True,
        )

    out = Path("/tmp/ab_api_challenge_out.json")
    out.write_text(json.dumps(results, indent=2, default=str))
    print("wrote", out, flush=True)


if __name__ == "__main__":
    asyncio.run(main())
