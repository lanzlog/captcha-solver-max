#!/usr/bin/env python3
"""Turnstile paid-class benchmark harness (P0).

Stages (from checkpoint RESUME):
  A. CF test sitekeys 1xAA / 3xFF     → engine hidup?
  B. Public Turnstile demos           → mint rate
  C. siteverify / verify_url          → server accept?
  D. cross-client replay              → portable? (curl siteverify after mint)
  E. hard: CF dash signup sitekey     → mint only (no pure-API create spam)

Output CSV: sitekey | stage | method | mint | verify | replay | latency | proxy | notes

Usage (on VPS kerja, solver running :8877):
  cd ~/captcha-build/captcha-solver
  ./venv/bin/python scripts/paid_class_bench.py
  ./venv/bin/python scripts/paid_class_bench.py --stages A,B,C,D
  ./venv/bin/python scripts/paid_class_bench.py --stages E --timeout 120
  ./venv/bin/python scripts/paid_class_bench.py --methods route,real_page

Env:
  SOLVER_URL   default http://127.0.0.1:8877
  BENCH_OUT    default ./bench_results/turnstile_paid_class_<ts>.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SOLVER_URL = os.environ.get("SOLVER_URL", "http://127.0.0.1:8877").rstrip("/")

# Cloudflare official dummy keys
# https://developers.cloudflare.com/engines/ts/troubleshooting/testing/
# https://developers.cloudflare.com/engines/ts/troubleshooting/testing/
TEST_ALWAYS_PASS = "1x00000000000000000000AA"
TEST_ALWAYS_BLOCK = "2x00000000000000000000AB"
TEST_FORCE_INTERACTIVE = "3x00000000000000000000FF"
# Secrets (NOT same suffix as sitekeys):
TEST_SECRET_PASS = "1x0000000000000000000000000000000AA"
TEST_SECRET_FAIL = "2x0000000000000000000000000000000AA"
TEST_SECRET_SPENT = "3x0000000000000000000000000000000AA"  # second verify → token-already-spent
# Dummy widget tokens (XXXX.DUMMY.TOKEN.XXXX) verify with SECRET_PASS.

SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


@dataclass
class Case:
    stage: str
    name: str
    sitekey: str
    url: str
    secret: Optional[str] = None  # for official siteverify
    real_page: bool = False
    hard: bool = False
    notes: str = ""


@dataclass
class Row:
    stage: str
    name: str
    sitekey: str
    method: str
    mint: str  # ok|fail|skip
    verify: str  # ok|fail|skip|n/a
    replay: str  # ok|fail|skip|n/a  (portable pure-HTTP)
    latency_s: float
    token_len: int
    proxy: str
    usage_guess: str  # portable | same_session_only | unknown
    error: str
    notes: str
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def http_json(
    method: str,
    url: str,
    body: Optional[dict] = None,
    timeout: float = 180,
    headers: Optional[dict] = None,
) -> tuple[int, Any, str]:
    data = None
    hdrs = {"User-Agent": "captcha-solver-max-bench/1.0", "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(raw), raw
            except json.JSONDecodeError:
                return r.status, None, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw), raw
        except Exception:
            return e.code, None, raw
    except Exception as e:
        return 0, None, str(e)


def http_form(url: str, form: dict, timeout: float = 30) -> tuple[int, Any, str]:
    from urllib.parse import urlencode

    data = urlencode(form).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": "captcha-solver-max-bench/1.0",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(raw), raw
            except json.JSONDecodeError:
                return r.status, None, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw), raw
        except Exception:
            return e.code, None, raw
    except Exception as e:
        return 0, None, str(e)


def solver_health() -> dict:
    code, data, raw = http_json("GET", f"{SOLVER_URL}/health", timeout=15)
    if code != 200 or not isinstance(data, dict):
        raise SystemExit(f"solver health failed: {code} {raw[:200]}")
    return data


def mint_turnstile(
    sitekey: str,
    url: str,
    *,
    real_page: bool = False,
    timeout_s: int = 90,
    proxy: Optional[str] = None,
) -> tuple[dict, float]:
    body: dict[str, Any] = {
        "type": "turnstile",
        "sitekey": sitekey,
        "url": url,
        "timeout_s": timeout_s,
    }
    if real_page:
        body["real_page"] = True
    if proxy:
        body["proxy"] = proxy
    t0 = time.monotonic()
    code, data, raw = http_json("POST", f"{SOLVER_URL}/solve", body, timeout=timeout_s + 30)
    elapsed = round(time.monotonic() - t0, 2)
    if not isinstance(data, dict):
        return {
            "solved": False,
            "error": f"http_{code}: {raw[:300]}",
            "token": "",
            "method": "real-page" if real_page else "route",
        }, elapsed
    data.setdefault("http_status", code)
    return data, elapsed


def siteverify(secret: str, token: str, remoteip: Optional[str] = None) -> tuple[bool, dict, str]:
    form = {"secret": secret, "response": token}
    if remoteip:
        form["remoteip"] = remoteip
    code, data, raw = http_form(SITEVERIFY_URL, form, timeout=30)
    ok = bool(isinstance(data, dict) and data.get("success") is True)
    return ok, (data if isinstance(data, dict) else {"raw": raw, "http": code}), raw


def classify_usage(mint_ok: bool, verify_ok: Optional[bool], replay_ok: Optional[bool]) -> str:
    if not mint_ok:
        return "unknown"
    if replay_ok is True:
        return "portable"
    if verify_ok is True and replay_ok is False:
        return "same_session_only"
    if verify_ok is True and replay_ok is None:
        return "unknown"
    if mint_ok and (verify_ok is False or verify_ok is None) and (replay_ok is False or replay_ok is None):
        # minted but couldn't prove portable
        return "same_session_only" if replay_ok is False else "unknown"
    return "unknown"


def cases_for(stages: set[str]) -> list[Case]:
    out: list[Case] = []
    if "A" in stages:
        out += [
            Case("A", "cf_test_always_pass", TEST_ALWAYS_PASS,
                 "https://example.com", secret=TEST_SECRET_PASS,
                 notes="official dummy always-pass; siteverify secret 1x…AA"),
            Case("A", "cf_test_force_interactive", TEST_FORCE_INTERACTIVE,
                 "https://example.com", secret=TEST_SECRET_PASS,
                 notes="official dummy forces interactive checkbox; dummy token still verifies with secret 1x…AA"),
        ]
    if "B" in stages:
        out += [
            Case("B", "peet_managed", "0x4AAAAAAABS7TtLxsNa7Z2e",
                 "https://peet.ws/turnstile-test/managed.html",
                 notes="public demo managed"),
            Case("B", "peet_noninteractive", "0x4AAAAAAABS7vwvV6VFfMcD",
                 "https://peet.ws/turnstile-test/non-interactive.html",
                 notes="public demo non-interactive"),
            Case("B", "peet_invisible", "0x4AAAAAAABS78iP9t4tO6NV",
                 "https://peet.ws/turnstile-test/invisible.html",
                 notes="public demo invisible"),
            Case("B", "cf_workers_demo_page", TEST_ALWAYS_PASS,
                 "https://demo.turnstile.workers.dev/",
                 secret=TEST_SECRET_PASS,
                 notes="workers dummy login page (test sitekey)"),
        ]
    if "C" in stages or "D" in stages:
        # C/D use secrets on A/B cases that have them; also explicit verify targets
        if "A" not in stages:
            out += [
                Case("C", "siteverify_always_pass", TEST_ALWAYS_PASS,
                     "https://example.com", secret=TEST_SECRET_PASS,
                     notes="mint+siteverify portable test"),
            ]
    if "E" in stages:
        out += [
            Case("E", "cf_dash_signup_sitekey", "0x4AAAAAAAJel0iaAR3mgkjp",
                 "https://dash.cloudflare.com/sign-up",
                 hard=True,
                 notes="hard bar mint only — no pure-API create (1201 known)"),
        ]
    return out


def run_case(case: Case, method: str, timeout_s: int) -> Row:
    real_page = method == "real_page"
    print(f"\n→ [{case.stage}] {case.name} method={method} sitekey={case.sitekey[:24]}…", flush=True)

    result, elapsed = mint_turnstile(
        case.sitekey, case.url, real_page=real_page, timeout_s=timeout_s
    )
    token = (result.get("token") or "").strip()
    mint_ok = bool(token) and result.get("solved", True) is not False and not result.get("error")
    # realpage may set verify_success without solved field
    if not mint_ok and token:
        mint_ok = True
    if result.get("error") and not token:
        mint_ok = False

    method_used = str(result.get("method") or method)
    proxy = str(result.get("proxy") or "")
    err = str(result.get("error") or "")
    if not mint_ok and not err:
        err = f"no_token http={result.get('http_status')} keys={list(result.keys())}"

    verify_s = "n/a"
    replay_s = "n/a"
    verify_ok: Optional[bool] = None
    replay_ok: Optional[bool] = None

    # C + D: official siteverify is pure-HTTP → first call = portable proof
    if mint_ok and case.secret:
        ok1, body1, _ = siteverify(case.secret, token)
        verify_ok = ok1
        verify_s = "ok" if ok1 else f"fail:{body1.get('error-codes') or body1}"
        # Second pure-HTTP call: tokens are often single-use; portable means FIRST
        # pure-HTTP accept. Second call documents single-use behavior.
        ok2, body2, _ = siteverify(case.secret, token)
        # Replay definition (paid-class): consumer curl (not mint browser) accepted once.
        replay_ok = ok1
        replay_s = "ok" if ok1 else f"fail:{body1.get('error-codes') or body1}"
        if ok1 and not ok2:
            replay_s = "ok(single-use)"
        elif ok1 and ok2:
            replay_s = "ok(reuse-ok)"
        print(f"  mint={mint_ok} verify1={ok1} verify2={ok2} len={len(token)} {elapsed}s", flush=True)
    elif mint_ok:
        # No secret: cannot siteverify. Mark verify/replay unknown; mint only.
        verify_s = "skip_no_secret"
        replay_s = "skip_no_secret"
        print(f"  mint={mint_ok} len={len(token)} {elapsed}s (no siteverify secret)", flush=True)
    else:
        print(f"  MINT FAIL {err[:120]} {elapsed}s", flush=True)

    usage = classify_usage(mint_ok, verify_ok, replay_ok)

    return Row(
        stage=case.stage,
        name=case.name,
        sitekey=case.sitekey,
        method=method_used,
        mint="ok" if mint_ok else "fail",
        verify=verify_s if mint_ok else "skip",
        replay=replay_s if mint_ok else "skip",
        latency_s=elapsed,
        token_len=len(token),
        proxy=proxy[:80],
        usage_guess=usage,
        error=err[:240],
        notes=case.notes,
    )


def write_csv(path: Path, rows: list[Row]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(asdict(rows[0]).keys()) if rows else [
        "stage", "name", "sitekey", "method", "mint", "verify", "replay",
        "latency_s", "token_len", "proxy", "usage_guess", "error", "notes", "ts",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))


def summarize(rows: list[Row]) -> str:
    lines = ["", "=== SUMMARY ==="]
    by_stage: dict[str, list[Row]] = {}
    for r in rows:
        by_stage.setdefault(r.stage, []).append(r)
    for st in sorted(by_stage):
        rs = by_stage[st]
        mint_ok = sum(1 for r in rs if r.mint == "ok")
        port = sum(1 for r in rs if r.usage_guess == "portable")
        same = sum(1 for r in rs if r.usage_guess == "same_session_only")
        lines.append(
            f"stage {st}: {mint_ok}/{len(rs)} mint_ok | portable={port} same_session={same}"
        )
    lines.append("")
    lines.append("detail:")
    for r in rows:
        lines.append(
            f"  [{r.stage}] {r.name:28} method={r.method:10} mint={r.mint:4} "
            f"verify={r.verify[:24]:24} replay={r.replay[:16]:16} "
            f"usage={r.usage_guess:18} {r.latency_s}s len={r.token_len}"
        )
        if r.error:
            lines.append(f"           err: {r.error[:100]}")
    # paid-class bar
    lines.append("")
    portable_n = sum(1 for r in rows if r.usage_guess == "portable")
    total_with_secret = sum(1 for r in rows if r.verify not in ("n/a", "skip", "skip_no_secret") or r.replay.startswith("ok"))
    lines.append(
        f"PAID-CLASS SIGNAL: portable={portable_n} "
        f"(need siteverify secret cases; hard E is mint-only)"
    )
    lines.append(
        "Interpretation: portable = pure-HTTP siteverify accepted token from local mint. "
        "That is the 'SIM' bar for dummy keys. Real hard sites need target-specific verify."
    )
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Turnstile paid-class benchmark (P0)")
    ap.add_argument("--stages", default="A,B,C,D,E",
                    help="Comma stages A-E (default all). C/D auto-run via secrets on cases.")
    ap.add_argument("--methods", default="route",
                    help="Comma: route,real_page (default route). real_page slower.")
    ap.add_argument("--timeout", type=int, default=90, help="Per-solve timeout_s")
    ap.add_argument("--out", default="", help="CSV path")
    ap.add_argument("--skip-hard", action="store_true", help="Skip stage E")
    args = ap.parse_args()

    stages = {s.strip().upper() for s in args.stages.split(",") if s.strip()}
    if args.skip_hard:
        stages.discard("E")
    # C and D are evaluation axes on cases with secrets, not separate case lists only
    methods = [m.strip() for m in args.methods.split(",") if m.strip()]
    for m in methods:
        if m not in ("route", "real_page"):
            raise SystemExit(f"unknown method {m}")

    health = solver_health()
    print(f"solver ok types={health.get('supported_types')} proxy={health.get('proxy')}")
    print(f"stages={sorted(stages)} methods={methods} timeout={args.timeout}")

    cases = cases_for(stages)
    if not cases:
        raise SystemExit("no cases for selected stages")

    rows: list[Row] = []
    for case in cases:
        # Stage C/D are folded into secret-bearing cases; still run all selected cases
        if case.stage == "E" and "E" not in stages:
            continue
        for method in methods:
            # real_page on pure test key + example.com is less meaningful but allowed
            try:
                row = run_case(case, method, args.timeout)
            except Exception as e:
                row = Row(
                    stage=case.stage,
                    name=case.name,
                    sitekey=case.sitekey,
                    method=method,
                    mint="fail",
                    verify="skip",
                    replay="skip",
                    latency_s=0.0,
                    token_len=0,
                    proxy="",
                    usage_guess="unknown",
                    error=f"exception:{e}",
                    notes=case.notes,
                )
            rows.append(row)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(args.out) if args.out else Path(
        os.environ.get("BENCH_OUT", f"bench_results/turnstile_paid_class_{ts}.csv")
    )
    if not out.is_absolute():
        out = Path.cwd() / out
    write_csv(out, rows)
    summary = summarize(rows)
    print(summary)
    sum_path = out.with_suffix(".summary.txt")
    sum_path.write_text(summary + "\n", encoding="utf-8")
    print(f"\nCSV: {out}")
    print(f"SUMMARY: {sum_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
