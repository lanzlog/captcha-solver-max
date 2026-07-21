#!/usr/bin/env python3
"""A/B: local issuer vs CapSolver vs 2Captcha — SIM fotokopi vs SIM asli bar.

Measures per issuer:
  mint success / token shape
  pure-HTTP workers accept (demo.turnstile.workers.dev via proxy if available)
  pure-HTTP siteverify (dummy secret only)
  optional CF dash create hard bar (stage hard) — expensive, off by default

Never prints full API keys. Tokens only prefix+len in logs.
"""
from __future__ import annotations

import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOLVER = os.getenv("SOLVER_URL", "http://127.0.0.1:8877")
OUTDIR = Path(os.getenv("BENCH_OUT", "bench_results"))

DUMMY_SK = "1x00000000000000000000AA"
DUMMY_SECRET = "1x0000000000000000000000000000000AA"
PEET_SK = "0x4AAAAAAABS7TtLxsNa7Z2e"
PEET_URL = "https://peet.ws/turnstile-test/managed.html"
WORKERS_URL = "https://demo.turnstile.workers.dev/"
CF_DASH_SK = "0x4AAAAAAAJel0iaAR3mgkjp"
CF_DASH_URL = "https://dash.cloudflare.com/sign-up"


def post_json(url: str, body: dict, timeout: int = 200) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"http": resp.status, **json.loads(resp.read().decode())}
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            j = json.loads(raw)
        except Exception:
            j = {"raw": raw[:300]}
        return {"http": e.code, "error": str(e.reason), **j}
    except Exception as e:
        return {"http": 0, "error": str(e)}


def pure_http_siteverify(token: str, secret: str) -> dict:
    form = urllib.parse.urlencode({"secret": secret, "response": token}).encode()
    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"success": False, "error": str(e)}


def workers_accept(token: str, proxy: str | None = None, ua: str | None = None) -> dict:
    form = urllib.parse.urlencode({"cf-turnstile-response": token}).encode()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": ua
        or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "Origin": "https://demo.turnstile.workers.dev",
        "Referer": "https://demo.turnstile.workers.dev/",
    }
    req = urllib.request.Request(
        "https://demo.turnstile.workers.dev/",
        data=form, headers=headers, method="POST",
    )
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers) if handlers else urllib.request.build_opener()
    try:
        with opener.open(req, timeout=30) as resp:
            text = resp.read().decode(errors="replace")
            low = text.lower()
            compact = text.replace(" ", "").lower()
            invalid = (
                "not valid" in low
                or "invalid-input" in low
                or '"success":false' in compact
            )
            validated = (
                "successfuly validated" in low
                or "successfully validated" in low
                or '"success":true' in compact
                or "thank you" in low
            )
            ok = validated and not invalid
            return {"success": ok, "status": resp.status, "text": text[:200]}
    except Exception as e:
        return {"success": False, "error": str(e)[:120]}


def mint_local(sitekey: str, url: str, *, real_page=False, mint_method=None,
               secret=None, timeout_s=100) -> dict:
    body = {"type": "turnstile", "sitekey": sitekey, "url": url, "timeout_s": timeout_s}
    if real_page:
        body["real_page"] = True
    if mint_method:
        body["mint_method"] = mint_method
    if secret:
        body["secret"] = secret
    t0 = time.time()
    r = post_json(f"{SOLVER}/solve", body, timeout=timeout_s + 50)
    r["_wall"] = round(time.time() - t0, 1)
    r["_issuer"] = "local"
    return r


def mint_paid_direct(provider: str, sitekey: str, url: str, timeout_s: int = 120) -> dict:
    """Call paid API directly (not via local free-first) for clean A/B."""
    # use solver venv code
    import asyncio
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from csm.paid_fallback import run_paid

    t0 = time.time()
    r = asyncio.get_event_loop().run_until_complete(
        run_paid("turnstile", sitekey, url, prefer=provider, poll_s=timeout_s)
    )
    r["_wall"] = round(time.time() - t0, 1)
    r["_issuer"] = provider
    r["http"] = 200 if r.get("solved") else 0
    return r


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
    return {"len": len(tok), "prefix": tok[:36], "class": cls}


def run_row(name: str, issuer: str, sitekey: str, url: str, **kw) -> dict:
    print(f"\n=== {name} ({issuer}) ===", flush=True)
    if issuer == "local":
        r = mint_local(sitekey, url, **kw)
    else:
        r = mint_paid_direct(issuer, sitekey, url, timeout_s=kw.get("timeout_s", 120))

    tok = r.get("token") or ""
    tm = token_meta(tok)
    row = {
        "case": name,
        "issuer": issuer,
        "http": r.get("http"),
        "solved": r.get("solved"),
        "method": r.get("method"),
        "usage": r.get("usage"),
        "token_len": tm["len"],
        "token_prefix": tm["prefix"],
        "token_class": tm["class"],
        "elapsed": r.get("elapsed") or r.get("_wall"),
        "wall": r.get("_wall"),
        "error": str(r.get("error") or "")[:100],
        "ua_tail": (r.get("user_agent") or "")[-40:],
        "proxy_tail": (r.get("proxy") or "")[-40:],
        "workers_ok": "",
        "siteverify_ok": "",
        "sim_class": "unknown",
    }

    # workers pure-HTTP for dummy sitekey only (workers uses testing secret)
    if tok and sitekey == DUMMY_SK:
        w = workers_accept(tok, proxy=r.get("proxy"), ua=r.get("user_agent"))
        row["workers_ok"] = bool(w.get("success"))
        # also siteverify
        sv = pure_http_siteverify(tok, DUMMY_SECRET)
        row["siteverify_ok"] = bool(sv.get("success"))

    mint_ok = tm["len"] > 10 and tm["class"] not in ("empty", "short_reject")
    pure_ok = row["workers_ok"] is True or row["siteverify_ok"] is True or r.get("usage") in (
        "portable", "portable_testing_key", "portable_claimed"
    )
    if mint_ok and pure_ok and tm["class"] == "cf_testing_dummy":
        row["sim_class"] = "SIM_ASLI_testing_key"
    elif mint_ok and pure_ok:
        row["sim_class"] = "SIM_ASLI_portable"
    elif mint_ok and issuer in ("capsolver", "twocaptcha", "yescaptcha"):
        # paid claim without pure-HTTP proof on this target
        row["sim_class"] = "PAID_MINT_UNVERIFIED_PORTABLE"
    elif mint_ok:
        row["sim_class"] = "SIM_FOTOKOPI_same_session"
    else:
        row["sim_class"] = "MINT_FAIL"

    print(json.dumps(row, indent=2), flush=True)
    return row


def main():
    stages = sys.argv[1:] or ["dummy", "peet"]
    OUTDIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = OUTDIR / f"ab_paid_local_{ts}.csv"
    rows = []

    # health / keys present
    h = post_json  # noqa
    try:
        with urllib.request.urlopen(f"{SOLVER}/health", timeout=10) as r:
            health = json.loads(r.read().decode())
        print("health ok", health.get("status"), "paid?", 
              {k: health.get(k) for k in list(health) if "paid" in k.lower() or "fallback" in k.lower()})
    except Exception as e:
        print("health fail", e)

    # import available
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    try:
        from csm.paid_fallback import available
        print("paid available", available())
    except Exception as e:
        print("paid import", e)

    if "dummy" in stages:
        for issuer in ("local", "capsolver", "twocaptcha"):
            rows.append(run_row(
                f"dummy_{issuer}", issuer, DUMMY_SK, WORKERS_URL,
                mint_method="explicit", timeout_s=90))

    if "peet" in stages:
        for issuer in ("local", "capsolver", "twocaptcha"):
            rows.append(run_row(
                f"peet_{issuer}", issuer, PEET_SK, PEET_URL,
                mint_method="explicit", timeout_s=120))
        # local real_page peet
        rows.append(run_row(
            "peet_local_realpage", "local", PEET_SK, PEET_URL,
            real_page=True, timeout_s=120))

    if "hard" in stages:
        # CF dash sitekey mint only (no create spam) — expensive paid
        for issuer in ("local", "capsolver", "twocaptcha"):
            rows.append(run_row(
                f"cfdash_{issuer}", issuer, CF_DASH_SK, CF_DASH_URL,
                mint_method="explicit", timeout_s=150))

    if not rows:
        return 1
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print("\n==== A/B SUMMARY ====")
    print(f"csv={out}")
    for r in rows:
        print(f"  {r['case']}: {r['sim_class']} len={r['token_len']} "
              f"usage={r['usage']} method={r['method']} w={r['workers_ok']} sv={r['siteverify_ok']}")
    return 0


if __name__ == "__main__":
    # asyncio loop for paid
    try:
        import asyncio
        asyncio.set_event_loop(asyncio.new_event_loop())
    except Exception:
        pass
    raise SystemExit(main())
