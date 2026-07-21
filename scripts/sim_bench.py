#!/usr/bin/env python3
"""Quick SIM-progress bench: mint quality across methods + pure-HTTP siteverify.

Stages:
  A  CF dummy always-pass sitekey → mint + pure-HTTP siteverify (portable bar for dummies)
  B  peet managed real_page harvest
  C  peet managed via default mint (explicit)
  D  demo.turnstile.workers.dev via explicit
  E  CF dash public sitekey mint only

Outputs CSV + summary. Labels usage honestly.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOLVER = os.getenv("SOLVER_URL", "http://127.0.0.1:8877")
OUTDIR = Path(os.getenv("BENCH_OUT", "bench_results"))

# Official CF testing secrets (developers.cloudflare.com/engines/ts/troubleshooting/testing/)
DUMMY = {
    "always_pass": ("1x00000000000000000000AA", "1x0000000000000000000000000000000AA"),
    "always_block": ("2x00000000000000000000AB", "2x0000000000000000000000000000000AA"),
    "force_interactive": ("3x00000000000000000000FF", "3x0000000000000000000000000000000AA"),
}

CASES = [
    # name, body, siteverify_secret_or_None
    ("A_dummy_pass_explicit", {
        "type": "turnstile",
        "sitekey": DUMMY["always_pass"][0],
        "url": "https://example.com",
        "timeout_s": 90,
        "mint_method": "explicit",
    }, DUMMY["always_pass"][1]),
    ("A_dummy_pass_route", {
        "type": "turnstile",
        "sitekey": DUMMY["always_pass"][0],
        "url": "https://example.com",
        "timeout_s": 90,
        "mint_method": "route",
    }, DUMMY["always_pass"][1]),
    ("B_peet_realpage", {
        "type": "turnstile",
        "sitekey": "0x4AAAAAAABS7TtLxsNa7Z2e",
        "url": "https://peet.ws/turnstile-test/managed.html",
        "real_page": True,
        "timeout_s": 120,
    }, None),
    ("C_peet_explicit", {
        "type": "turnstile",
        "sitekey": "0x4AAAAAAABS7TtLxsNa7Z2e",
        "url": "https://peet.ws/turnstile-test/managed.html",
        "timeout_s": 100,
        "mint_method": "explicit",
    }, None),
    ("D_workers_explicit", {
        "type": "turnstile",
        "sitekey": "1x00000000000000000000AA",  # workers demo often uses dummy; try peet-like
        "url": "https://demo.turnstile.workers.dev",
        "timeout_s": 100,
    }, DUMMY["always_pass"][1]),
    ("E_cf_dash_explicit", {
        "type": "turnstile",
        "sitekey": "0x4AAAAAAAJel0iaAR3mgkjp",
        "url": "https://dash.cloudflare.com",
        "timeout_s": 100,
    }, None),
]


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
            j = {"raw": raw[:500]}
        return {"http": e.code, "error": str(e), **j}
    except Exception as e:
        return {"http": 0, "error": str(e)}


def pure_http_siteverify(token: str, secret: str, remoteip: str | None = None) -> dict:
    """Official CF siteverify from this host (NOT mint browser) = portable bar."""
    form = f"secret={urllib.request.quote(secret)}&response={urllib.request.quote(token)}"
    if remoteip:
        form += f"&remoteip={urllib.request.quote(remoteip)}"
    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=form.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
            return {"ok": True, "status": resp.status, "body": body}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def run_case(name: str, body: dict, secret: str | None) -> dict:
    t0 = time.time()
    r = post_json(f"{SOLVER}/solve", body, timeout=int(body.get("timeout_s", 100)) + 40)
    elapsed = round(time.time() - t0, 1)
    token = r.get("token") or ""
    row = {
        "case": name,
        "http": r.get("http"),
        "solved": r.get("solved"),
        "method": r.get("method"),
        "usage": r.get("usage"),
        "token_len": len(token),
        "token_prefix": token[:28] if token else "",
        "elapsed_api": r.get("elapsed"),
        "elapsed_wall": elapsed,
        "error": (r.get("error") or r.get("detail") or "")[:120],
        "proxy_tail": (r.get("proxy") or "")[-40:],
        "ua_tail": (r.get("user_agent") or "")[-40:],
        "pure_http_success": "",
        "pure_http_codes": "",
        "portable_class": "unknown",
    }
    if token and secret:
        sv = pure_http_siteverify(token, secret)
        body_sv = sv.get("body") or {}
        success = bool(body_sv.get("success"))
        row["pure_http_success"] = success
        row["pure_http_codes"] = ",".join(body_sv.get("error-codes") or [])
        # dummy pass + pure http success = portable for that key class
        row["portable_class"] = "portable_dummy" if success else "not_portable"
    elif token:
        row["portable_class"] = "mint_only_unverified"  # no secret to prove
    else:
        row["portable_class"] = "mint_fail"
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="comma substr filter on case names")
    args = ap.parse_args()
    only = [x.strip() for x in args.only.split(",") if x.strip()]

    OUTDIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = OUTDIR / f"sim_bench_{ts}.csv"

    rows = []
    for name, body, secret in CASES:
        if only and not any(o.lower() in name.lower() for o in only):
            continue
        print(f"\n=== {name} ===", flush=True)
        row = run_case(name, body, secret)
        rows.append(row)
        print(json.dumps(row, indent=2), flush=True)

    if not rows:
        print("no cases")
        return 1

    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    mint_ok = sum(1 for r in rows if r["token_len"] > 50)
    pure_ok = sum(1 for r in rows if r["pure_http_success"] is True)
    print("\n==== SUMMARY ====")
    print(f"mint_ok={mint_ok}/{len(rows)} pure_http_ok={pure_ok}")
    print(f"csv={out}")
    for r in rows:
        print(f"  {r['case']}: token={r['token_len']} method={r['method']} "
              f"class={r['portable_class']} err={r['error']!r}")
    return 0 if mint_ok else 2


if __name__ == "__main__":
    sys.exit(main())
