#!/usr/bin/env python3
"""Portable / SIM-asli bar bench for Turnstile issuer.

Measures:
  mint success
  pure-HTTP siteverify (server-side secret path → usage=portable*)
  pure-HTTP third-party accept (workers demo via mint proxy+UA)
  same-session post_fetch (not portable)

SIM fotokopi = mint OK + usage same_session_only
SIM asli     = mint OK + pure-HTTP accept outside mint browser
               (usage=portable or portable_testing_key for CF dummy keys)
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

DUMMY_PASS_SK = "1x00000000000000000000AA"
DUMMY_PASS_SECRET = "1x0000000000000000000000000000000AA"
DUMMY_INTERACTIVE_SK = "3x00000000000000000000FF"
PEET_SK = "0x4AAAAAAABS7TtLxsNa7Z2e"
CF_DASH_SK = "0x4AAAAAAAJel0iaAR3mgkjp"


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
            j = {"raw": raw[:400]}
        return {"http": e.code, "error": str(e.reason), **j}
    except Exception as e:
        return {"http": 0, "error": str(e)}


def pure_http_siteverify(token: str, secret: str, proxy: str | None = None) -> dict:
    form = urllib.parse.urlencode({"secret": secret, "response": token}).encode()
    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers) if handlers else urllib.request.build_opener()
    try:
        with opener.open(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
            return {"ok": True, "body": body}
    except Exception as e:
        return {"ok": False, "error": str(e), "body": {}}


def workers_handler_accept(
    token: str, proxy: str | None = None, ua: str | None = None
) -> dict:
    """Submit token to official CF demo worker (pure HTTP, not mint browser).

    Prefer mint proxy + mint UA — VPS IP alone often gets CF 1010/403.
    POST / (not /handler) with Origin/Referer matching the demo.
    """
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
        data=form,
        headers=headers,
        method="POST",
    )
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = (
        urllib.request.build_opener(*handlers)
        if handlers
        else urllib.request.build_opener()
    )
    try:
        with opener.open(req, timeout=30) as resp:
            text = resp.read().decode(errors="replace")
            # CF returns HTTP 200 for both pass and fail — parse body.
            # Empty error-codes:[] is OK; "success":false / not valid / invalid-input-* = fail.
            low = text.lower()
            compact = text.replace(" ", "").lower()
            invalid = (
                "not valid" in low
                or "invalid-input" in low
                or '"success":false' in compact
            )
            validated = (
                "successfuly validated" in low  # CF typo
                or "successfully validated" in low
                or '"success":true' in compact
                or "thank you" in low
            )
            success = validated and not invalid
            return {"ok": True, "status": resp.status, "success": success, "text": text[:300]}
    except urllib.error.HTTPError as e:
        text = e.read().decode(errors="replace")
        return {"ok": False, "status": e.code, "success": False, "text": text[:300]}
    except Exception as e:
        return {"ok": False, "success": False, "error": str(e)}


CASES = [
    {
        "name": "dummy_pass_explicit_server_sv",
        "body": {
            "type": "turnstile",
            "sitekey": DUMMY_PASS_SK,
            "url": "https://example.com",
            "timeout_s": 90,
            "mint_method": "explicit",
            "secret": DUMMY_PASS_SECRET,
        },
        "external_sv_secret": None,
        "workers_replay": False,
    },
    {
        "name": "dummy_pass_route_external_sv",
        "body": {
            "type": "turnstile",
            "sitekey": DUMMY_PASS_SK,
            "url": "https://example.com",
            "timeout_s": 90,
            "mint_method": "route",
        },
        "external_sv_secret": DUMMY_PASS_SECRET,
        "workers_replay": False,
    },
    {
        "name": "dummy_pass_workers_portable",
        "body": {
            "type": "turnstile",
            "sitekey": DUMMY_PASS_SK,
            "url": "https://demo.turnstile.workers.dev/",
            "timeout_s": 90,
            "mint_method": "explicit",
        },
        "external_sv_secret": None,
        "workers_replay": True,
    },
    {
        "name": "dummy_interactive_sitekey_sv_1x",
        "body": {
            "type": "turnstile",
            "sitekey": DUMMY_INTERACTIVE_SK,
            "url": "https://example.com",
            "timeout_s": 100,
            "mint_method": "explicit",
            # 3x sitekey still mints XXXX.DUMMY; siteverify with 1x secret (CF docs)
            "secret": DUMMY_PASS_SECRET,
        },
        "external_sv_secret": None,
        "workers_replay": False,
    },
    {
        "name": "peet_realpage_mint",
        "body": {
            "type": "turnstile",
            "sitekey": PEET_SK,
            "url": "https://peet.ws/turnstile-test/managed.html",
            "real_page": True,
            "timeout_s": 120,
        },
        "external_sv_secret": None,
        "workers_replay": False,
    },
    {
        "name": "peet_explicit_mint",
        "body": {
            "type": "turnstile",
            "sitekey": PEET_SK,
            "url": "https://peet.ws/turnstile-test/managed.html",
            "timeout_s": 100,
            "mint_method": "explicit",
        },
        "external_sv_secret": None,
        "workers_replay": False,
    },
    {
        "name": "cf_dash_explicit_mint",
        "body": {
            "type": "turnstile",
            "sitekey": CF_DASH_SK,
            "url": "https://dash.cloudflare.com",
            "timeout_s": 120,
            "mint_method": "explicit",
        },
        "external_sv_secret": None,
        "workers_replay": False,
    },
]


def run_case(case: dict) -> dict:
    name = case["name"]
    body = case["body"]
    t0 = time.time()
    r = post_json(f"{SOLVER}/solve", body, timeout=int(body.get("timeout_s", 100)) + 50)
    wall = round(time.time() - t0, 1)
    token = r.get("token") or ""
    row = {
        "case": name,
        "http": r.get("http"),
        "solved": r.get("solved"),
        "method": r.get("method"),
        "usage_api": r.get("usage"),
        "portable_api": r.get("portable"),
        "token_class": r.get("token_class"),
        "token_len": len(token),
        "token_prefix": token[:32],
        "elapsed_api": r.get("elapsed"),
        "elapsed_wall": wall,
        "error": str(r.get("error") or r.get("detail") or "")[:100],
        "siteverify_success": "",
        "siteverify_codes": "",
        "workers_success": "",
        "sim_class": "unknown",
    }
    sv = r.get("siteverify") or {}
    if sv:
        row["siteverify_success"] = bool(sv.get("success"))
        row["siteverify_codes"] = ",".join(sv.get("error-codes") or [])

    if token and case.get("external_sv_secret"):
        ext = pure_http_siteverify(token, case["external_sv_secret"], proxy=r.get("proxy"))
        body_sv = ext.get("body") or {}
        row["siteverify_success"] = bool(body_sv.get("success"))
        row["siteverify_codes"] = ",".join(body_sv.get("error-codes") or [])
        token = ""  # consumed

    if token and case.get("workers_replay"):
        w = workers_handler_accept(token, proxy=r.get("proxy"), ua=r.get("user_agent"))
        row["workers_success"] = bool(w.get("success"))
        if not w.get("success"):
            row["error"] = (
                row["error"]
                + " | workers:"
                + str(w.get("text") or w.get("error") or "")[:80]
            )[:160]

    mint_ok = row["token_len"] > 10
    pure_ok = (
        row["siteverify_success"] is True
        or row["workers_success"] is True
        or r.get("usage") in ("portable", "portable_testing_key")
        or r.get("portable") is True
    )
    if mint_ok and pure_ok:
        if r.get("token_class") == "cf_testing_dummy" or row["token_len"] < 50:
            row["sim_class"] = "SIM_ASLI_testing_key"
        else:
            row["sim_class"] = "SIM_ASLI_portable"
    elif mint_ok:
        row["sim_class"] = "SIM_FOTOKOPI_same_session"
    else:
        row["sim_class"] = "MINT_FAIL"
    return row


def main():
    only = [x for x in (sys.argv[1:] or []) if x]
    OUTDIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = OUTDIR / f"portable_sim_{ts}.csv"
    rows = []
    for case in CASES:
        if only and not any(o.lower() in case["name"].lower() for o in only):
            continue
        print(f"\n=== {case['name']} ===", flush=True)
        row = run_case(case)
        rows.append(row)
        print(json.dumps(row, indent=2), flush=True)

    if not rows:
        return 1
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    asli = sum(1 for r in rows if r["sim_class"].startswith("SIM_ASLI"))
    foto = sum(1 for r in rows if "FOTOKOPI" in r["sim_class"])
    fail = sum(1 for r in rows if r["sim_class"] == "MINT_FAIL")
    print("\n==== SIM SUMMARY ====")
    print(f"asli={asli} fotokopi={foto} mint_fail={fail} total={len(rows)}")
    print(f"csv={out}")
    for r in rows:
        print(
            f"  {r['case']}: {r['sim_class']} method={r['method']} "
            f"usage={r['usage_api']} tok={r['token_len']} "
            f"w={r['workers_success']} sv={r['siteverify_success']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
