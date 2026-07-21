#!/usr/bin/env python3
"""Full A/B: local vs CapSolver vs 2Captcha on peet + CF dash hard bar.

SIM asli bar for production:
  pure-HTTP accept outside mint browser.
  Hard exam: CF dash POST /api/v4/user/create (code 1201 = not portable).

Never prints API keys. Token prefix+len only.
"""
from __future__ import annotations

import asyncio
import csv
import json
import os
import random
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SOLVER = os.getenv("SOLVER_URL", "http://127.0.0.1:8877")
OUTDIR = Path(os.getenv("BENCH_OUT", "bench_results"))

PEET_SK = "0x4AAAAAAABS7TtLxsNa7Z2e"
PEET_URL = "https://peet.ws/turnstile-test/managed.html"
CF_SK = "0x4AAAAAAAJel0iaAR3mgkjp"  # factory.py CF_TURNSTILE_SITEKEY
CF_URL = "https://dash.cloudflare.com/sign-up"
CF_CREATE = "https://dash.cloudflare.com/api/v4/user/create"


def post_json(url: str, body: dict, timeout: int = 200, headers: dict | None = None) -> dict:
    data = json.dumps(body).encode()
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"http": resp.status, **json.loads(resp.read().decode())}
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            j = json.loads(raw)
        except Exception:
            j = {"raw": raw[:400]}
        return {"http": e.code, "error": str(e.reason), **j}
    except Exception as e:
        return {"http": 0, "error": str(e)}


def token_meta(tok: str) -> dict:
    if not tok:
        return {"len": 0, "prefix": "", "class": "empty"}
    if tok.startswith("XXXX.DUMMY"):
        cls = "cf_testing_dummy"
    elif (tok.startswith("0.") or tok.startswith("1.")) and len(tok) >= 100:
        cls = "turnstile_v0"
    elif len(tok) >= 200:
        cls = "opaque_long"
    else:
        cls = "short_reject"
    return {"len": len(tok), "prefix": tok[:40], "class": cls}


async def mint_paid(provider: str, sitekey: str, url: str, poll_s: int = 120) -> dict:
    from csm.paid_fallback import run_paid
    t0 = time.time()
    r = await run_paid("turnstile", sitekey, url, prefer=provider, poll_s=poll_s)
    r["_wall"] = round(time.time() - t0, 1)
    r["_issuer"] = provider
    return r


def mint_local(sitekey: str, url: str, *, real_page=False, timeout_s=120) -> dict:
    body = {
        "type": "turnstile",
        "sitekey": sitekey,
        "url": url,
        "timeout_s": timeout_s,
    }
    if real_page:
        body["real_page"] = True
    else:
        body["mint_method"] = "explicit"
    t0 = time.time()
    r = post_json(f"{SOLVER}/solve", body, timeout=timeout_s + 50)
    r["_wall"] = round(time.time() - t0, 1)
    r["_issuer"] = "local"
    return r


def cf_create_pure_http(token: str, ua: str | None = None, proxy: str | None = None) -> dict:
    """Hard bar: pure-HTTP CF signup create with turnstile token.

    Payload shape mirrors ~/cf-factory/factory.py (field: cf_challenge_response).
    """
    email = "ab_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10)) + "@ilalangliar.xyz"
    # avoid common "compromised password" lists
    password = "Kx9!" + "".join(random.choices(string.ascii_letters + string.digits, k=14)) + "#zQ"
    headers = {
        "Content-Type": "application/json",
        "User-Agent": ua or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "Origin": "https://dash.cloudflare.com",
        "Referer": "https://dash.cloudflare.com/sign-up",
        "Accept": "application/json",
    }
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
    data = json.dumps(payload).encode()
    req = urllib.request.Request(CF_CREATE, data=data, headers=headers, method="POST")
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers) if handlers else urllib.request.build_opener()
    try:
        with opener.open(req, timeout=40) as resp:
            raw = resp.read().decode(errors="replace")
            try:
                j = json.loads(raw)
            except Exception:
                j = {"raw": raw[:300]}
            return {"http": resp.status, "email": email, **j}
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            j = json.loads(raw)
        except Exception:
            j = {"raw": raw[:300]}
        return {"http": e.code, "email": email, **j}
    except Exception as e:
        return {"http": 0, "error": str(e), "email": email}


def classify(row: dict) -> str:
    mint_ok = row["token_len"] >= 100 and row["token_class"] in ("turnstile_v0", "opaque_long")
    if not mint_ok:
        return "MINT_FAIL"
    cf = row.get("cf_create_code")
    if row.get("cf_create_success") is True:
        return "SIM_ASLI_portable"  # pure-HTTP CF accept
    if cf in (1201, "1201") or (isinstance(cf, list) and 1201 in cf):
        return "SIM_FOTOKOPI_1201"
    if row["issuer"] in ("capsolver", "twocaptcha") and mint_ok:
        if row.get("cf_create_http"):
            return f"PAID_MINT_CF_HTTP_{row['cf_create_http']}"
        return "PAID_MINT_NO_HARD_TEST"
    return "SIM_FOTOKOPI_same_session"


async def main():
    stages = set(sys.argv[1:] or ["peet", "hard"])
    OUTDIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = OUTDIR / f"ab_sim_{ts}.csv"
    rows = []

    from csm.paid_fallback import available
    print("paid available", available(), flush=True)

    jobs = []
    if "peet" in stages:
        jobs += [
            ("peet_local_explicit", "local", PEET_SK, PEET_URL, False),
            ("peet_local_realpage", "local", PEET_SK, PEET_URL, True),
            ("peet_capsolver", "capsolver", PEET_SK, PEET_URL, False),
            ("peet_twocaptcha", "twocaptcha", PEET_SK, PEET_URL, False),
        ]
    if "hard" in stages:
        jobs += [
            ("cfdash_local_explicit", "local", CF_SK, CF_URL, False),
            ("cfdash_capsolver", "capsolver", CF_SK, CF_URL, False),
            ("cfdash_twocaptcha", "twocaptcha", CF_SK, CF_URL, False),
        ]

    for name, issuer, sk, url, real_page in jobs:
        print(f"\n=== {name} ===", flush=True)
        if issuer == "local":
            r = mint_local(sk, url, real_page=real_page, timeout_s=150)
        else:
            r = await mint_paid(issuer, sk, url, poll_s=150)

        tok = r.get("token") or ""
        tm = token_meta(tok)
        row = {
            "case": name,
            "issuer": issuer,
            "solved": r.get("solved"),
            "method": r.get("method"),
            "usage": r.get("usage"),
            "token_len": tm["len"],
            "token_prefix": tm["prefix"],
            "token_class": tm["class"],
            "wall": r.get("_wall") or r.get("elapsed"),
            "error": str(r.get("error") or "")[:100],
            "ua_tail": (r.get("user_agent") or "")[-50:],
            "proxy_tail": (r.get("proxy") or "")[-40:],
            "cf_create_http": "",
            "cf_create_success": "",
            "cf_create_code": "",
            "cf_create_msg": "",
            "sim_class": "",
        }

        # Hard bar only for CF dash sitekey mints
        if sk == CF_SK and tm["len"] >= 100:
            print("  -> CF create pure-HTTP hard bar...", flush=True)
            # try without proxy first, then with local mint proxy if any
            proxies = [None]
            if r.get("proxy"):
                proxies.append(r.get("proxy"))
            # also try first pool proxy if exists
            try:
                from csm.proxypool import next_proxy
                p = next_proxy()
                if p and p not in proxies:
                    proxies.append(p)
            except Exception:
                pass
            best = {}
            for px in proxies:
                cr = cf_create_pure_http(tok, ua=r.get("user_agent"), proxy=px)
                print("  create via", "direct" if not px else "proxy", 
                      "http", cr.get("http"), "success", cr.get("success"),
                      "errors", cr.get("errors") or cr.get("error"), flush=True)
                best = cr
                if cr.get("success") is True:
                    break
                # stop if clear 1201
                errs = cr.get("errors") or []
                codes = [e.get("code") for e in errs if isinstance(e, dict)]
                if 1201 in codes or "1201" in codes:
                    break
            row["cf_create_http"] = best.get("http")
            row["cf_create_success"] = best.get("success")
            errs = best.get("errors") or []
            if errs and isinstance(errs, list) and isinstance(errs[0], dict):
                row["cf_create_code"] = errs[0].get("code")
                row["cf_create_msg"] = str(errs[0].get("message") or "")[:80]
            else:
                row["cf_create_msg"] = str(best.get("error") or best.get("raw") or "")[:80]
            # token is single-use; after create attempt it's spent

        row["sim_class"] = classify(row)
        rows.append(row)
        print(json.dumps(row, indent=2), flush=True)

    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print("\n==== SIM A/B SUMMARY ====")
    print(f"csv={out}")
    for r in rows:
        print(f"  {r['case']}: {r['sim_class']} len={r['token_len']} "
              f"cf={r['cf_create_code']}/{r['cf_create_http']} usage={r['usage']}")
    asli = [r for r in rows if r["sim_class"] == "SIM_ASLI_portable"]
    if asli:
        print("\n*** SIM ASLI FOUND ***", [r["case"] for r in asli])
    else:
        print("\n(no SIM_ASLI_portable yet — paid mint may still 1201 same as local)")


if __name__ == "__main__":
    asyncio.run(main())
