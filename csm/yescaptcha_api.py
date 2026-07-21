"""YesCaptcha / CapSolver-compatible API facade (MIT, original).

Exposes createTask + getTaskResult so existing clients that speak the
YesCaptcha/CapSolver protocol can point at this free-first solver without
code changes.

Supported task types (mapped to internal /solve types):
  TurnstileTaskProxyless / TurnstileTask
  RecaptchaV2TaskProxyless / RecaptchaV2Task / RecaptchaV2EnterpriseTaskProxyless
  RecaptchaV3TaskProxyless / RecaptchaV3Task
  HCaptchaTaskProxyless / HCaptchaTask
  ImageToTextTask
  MathCaptchaTask  (non-standard extension → type=math)
  SliderTask / GapMatchTask  (non-standard → type=slider)

clientKey is accepted but NOT validated (local free service). Set
SOLVER_CLIENT_KEY to enforce a shared secret if you expose publicly.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from typing import Any, Optional

log = logging.getLogger("yescaptcha_api")

# In-memory task store. Fine for single-process uvicorn. Cleared after TTL.
_TASKS: dict[str, dict] = {}
_TASK_TTL_S = int(os.getenv("SOLVER_TASK_TTL_S", "600"))
_MAX_TASKS = int(os.getenv("SOLVER_MAX_TASKS", "500"))

# Map CapSolver/YesCaptcha task type → (our type, version, notes)
_TYPE_MAP = {
    "AntiTurnstileTaskProxyless": ("turnstile", None),
    "ReCaptchaV3TaskProxyLess": ("recaptcha", "v3"),
    "ReCaptchaV2TaskProxyless": ("recaptcha", "v2"),
    "ReCaptchaV2TaskProxyLess": ("recaptcha", "v2"),
    "TurnstileTaskProxyless": ("turnstile", None),
    "TurnstileTask": ("turnstile", None),
    # CapSolver aliases (paid drop-in)
    "AntiTurnstileTaskProxyLess": ("turnstile", None),
    "AntiTurnstileTask": ("turnstile", None),
    "TurnstileTaskProxyLess": ("turnstile", None),  # casing variant
    "RecaptchaV2TaskProxyless": ("recaptcha", "v2"),
    "RecaptchaV2Task": ("recaptcha", "v2"),
    "RecaptchaV2EnterpriseTaskProxyless": ("recaptcha", "v2"),
    "RecaptchaV2EnterpriseTask": ("recaptcha", "v2"),
    "RecaptchaV3TaskProxyless": ("recaptcha", "v3"),
    "RecaptchaV3Task": ("recaptcha", "v3"),
    "RecaptchaV3EnterpriseTaskProxyless": ("recaptcha", "v3"),
    "HCaptchaTaskProxyless": ("hcaptcha", None),
    "HCaptchaTask": ("hcaptcha", None),
    "ImageToTextTask": ("image_text", None),
    "MathCaptchaTask": ("math", None),
    "SliderTask": ("slider", None),
    "GapMatchTask": ("slider", None),
    "GeeTestTaskProxyless": ("geetest", None),
    "GeeTestTask": ("geetest", None),
    "GeetestTaskProxyless": ("geetest", None),
    "GeetestTask": ("geetest", None),
}


def _check_client_key(client_key: Optional[str]) -> Optional[dict]:
    """Return error envelope if key required and missing/wrong, else None."""
    required = os.getenv("SOLVER_CLIENT_KEY", "").strip()
    if not required:
        return None
    if (client_key or "").strip() != required:
        return {
            "errorId": 1,
            "errorCode": "ERROR_KEY_DOES_NOT_EXIST",
            "errorDescription": "clientKey invalid or missing",
        }
    return None


def _gc_tasks() -> None:
    now = time.time()
    dead = [tid for tid, t in _TASKS.items()
            if now - t.get("created", 0) > _TASK_TTL_S]
    for tid in dead:
        _TASKS.pop(tid, None)
    # hard cap
    if len(_TASKS) > _MAX_TASKS:
        oldest = sorted(_TASKS.items(), key=lambda kv: kv[1].get("created", 0))
        for tid, _ in oldest[: len(_TASKS) - _MAX_TASKS]:
            _TASKS.pop(tid, None)


def task_to_solve_request(task: dict) -> dict:
    """Convert YesCaptcha task body → internal SolveRequest kwargs dict."""
    ttype = task.get("type") or ""
    mapped = _TYPE_MAP.get(ttype)
    if not mapped:
        raise ValueError(f"unsupported task type: {ttype}")
    our_type, version = mapped

    # Common field aliases
    sitekey = (task.get("websiteKey") or task.get("sitekey")
               or task.get("siteKey") or task.get("websitePublicKey"))
    url = (task.get("websiteURL") or task.get("pageurl")
           or task.get("pageUrl") or task.get("url"))
    proxy = task.get("proxy") or task.get("proxyAddress")
    if proxy and not str(proxy).startswith(("http://", "https://", "socks")):
        # host:port:user:pass → http://user:pass@host:port
        parts = str(proxy).split(":")
        if len(parts) >= 4:
            proxy = f"http://{parts[2]}:{':'.join(parts[3:])}@{parts[0]}:{parts[1]}"
        elif len(parts) == 2:
            proxy = f"http://{parts[0]}:{parts[1]}"

    body: dict[str, Any] = {"type": our_type}
    if our_type in ("turnstile", "recaptcha", "hcaptcha"):
        body["sitekey"] = sitekey
        body["url"] = url
        if version:
            body["version"] = version
        if task.get("isEnterprise") or "Enterprise" in ttype:
            body["enterprise"] = True
        # CapSolver uses metadata.action / metadata.cdata; YesCaptcha uses pageAction
        meta = task.get("metadata") if isinstance(task.get("metadata"), dict) else {}
        action = (
            task.get("pageAction")
            or task.get("action")
            or meta.get("action")
            or meta.get("pageAction")
        )
        if action:
            body["action"] = action
        cdata = (
            task.get("data")
            or task.get("cdata")
            or meta.get("cdata")
            or meta.get("data")
        )
        if cdata:
            body["cdata"] = cdata
        # optional pagedata (challenge pages)
        pagedata = task.get("pagedata") or meta.get("pagedata")
        if pagedata:
            body["pagedata"] = pagedata
        if proxy:
            body["proxy"] = proxy
        elif our_type in ("turnstile", "recaptcha", "hcaptcha", "cloudflare") and (
            "ProxyLess" in ttype or "Proxyless" in ttype
        ):
            # Paid ProxyLess = solver provides egress. Local free solver injects pool.
            ap = None
            try:
                from csm.proxypool import next_proxy
                ap = next_proxy()
            except Exception:
                try:
                    from proxypool import next_proxy  # type: ignore
                    ap = next_proxy()
                except Exception:
                    ap = os.getenv("SOLVER_DEFAULT_PROXY")
            if ap:
                body["proxy"] = ap
                log.info("auto_proxy_from_pool type=%s", ttype)
        # invisible hcaptcha
        if task.get("isInvisible") and our_type == "hcaptcha":
            body["action"] = "invisible"
        if our_type == "recaptcha" and task.get("isInvisible"):
            body["version"] = "invisible"
    elif our_type in ("image_text", "math"):
        img = (task.get("body") or task.get("image")
               or task.get("images") or "")
        if isinstance(img, list):
            img = img[0] if img else ""
        body["image"] = img
    elif our_type == "slider":
        body["target_image"] = (task.get("target") or task.get("target_image")
                                or task.get("slideImage") or task.get("image")
                                or "")
        body["background_image"] = (task.get("background")
                                    or task.get("background_image")
                                    or task.get("bgImage") or task.get("image_bg")
                                    or "")
        if task.get("simple") is not None:
            body["simple"] = bool(task.get("simple"))
    elif our_type == "geetest":
        body["captcha_id"] = (task.get("gt") or task.get("captchaId")
                              or task.get("captcha_id") or task.get("websiteKey")
                              or task.get("sitekey") or "")
        risk = task.get("risk_type") or task.get("riskType")
        init_p = task.get("initParameters")
        if not risk and isinstance(init_p, dict):
            risk = init_p.get("riskType") or init_p.get("risk_type")
        if not risk:
            risk = task.get("version") or "slide"
        body["risk_type"] = str(risk or "slide")
        if proxy:
            body["proxy"] = proxy
        if url:
            body["url"] = url
    return body


def result_to_solution(our_type: str, result: dict) -> dict:
    """Map internal solve result → YesCaptcha solution object."""
    if our_type in ("turnstile", "recaptcha", "hcaptcha"):
        sol = {
            "gRecaptchaResponse": result.get("token") or "",
            "token": result.get("token") or "",
            "userAgent": result.get("user_agent") or result.get("userAgent"),
            "proxy": result.get("proxy"),
        }
        # Honest paid-compat: session-bound vs portable (default same_session_only for local mint)
        if result.get("usage"):
            sol["usage"] = result.get("usage")
        if result.get("method"):
            sol["method"] = result.get("method")
        # P2 consumer contract — facade parity with native /v1/task
        if result.get("portable_scopes") is not None:
            sol["portable_scopes"] = result.get("portable_scopes")
        if result.get("consumer_contract") is not None:
            sol["consumer_contract"] = result.get("consumer_contract")
        if result.get("portable") is not None:
            sol["portable"] = result.get("portable")
        if result.get("token_class") is not None:
            sol["token_class"] = result.get("token_class")
        return sol
    if our_type in ("image_text", "math"):
        return {
            "text": result.get("token") or "",
            "answers": [result.get("token") or ""],
        }
    if our_type == "slider":
        return {
            "text": result.get("token") or "",
            "target_x": result.get("target_x"),
            "box": result.get("box"),
            "raw": result.get("raw"),
            "method": result.get("method"),
            "cascade": result.get("cascade"),
        }
    if our_type == "geetest":
        return {
            "token": result.get("token") or result.get("pass_token") or "",
            "pass_token": result.get("pass_token"),
            "lot_number": result.get("lot_number"),
            "captcha_output": result.get("captcha_output"),
            "gen_time": result.get("gen_time"),
            "captcha_id": result.get("captcha_id"),
            "seccode": result.get("seccode"),
            "risk_type": result.get("risk_type"),
        }
    # page-level leftovers (not typically in YesCaptcha API)
    return {
        "token": result.get("token") or result.get("cf_clearance") or "",
        "cookies": result.get("cookies"),
        "userAgent": result.get("user_agent"),
        "cf_clearance": result.get("cf_clearance"),
        "proxy": result.get("proxy"),
        "usage": result.get("usage"),
        "method": result.get("method"),
    }


async def create_task(client_key: Optional[str], task: dict,
                      solve_fn) -> dict:
    """Register task, kick off solve in background, return taskId.

    solve_fn: async callable(SolveRequest-like dict) → result dict
              Must inject `solved` bool itself or we derive it.
    """
    err = _check_client_key(client_key)
    if err:
        return err
    if not isinstance(task, dict) or not task.get("type"):
        return {
            "errorId": 1,
            "errorCode": "ERROR_TASK_ABSENT",
            "errorDescription": "task.type is required",
        }
    try:
        body = task_to_solve_request(task)
    except ValueError as e:
        return {
            "errorId": 1,
            "errorCode": "ERROR_TASK_NOT_SUPPORTED",
            "errorDescription": str(e),
        }

    _gc_tasks()
    task_id = str(uuid.uuid4())
    _TASKS[task_id] = {
        "created": time.time(),
        "status": "processing",
        "our_type": body["type"],
        "result": None,
        "error": None,
    }

    async def _run():
        try:
            result = await solve_fn(body)
            solved = bool(
                result.get("solved")
                or result.get("token")
                or result.get("cf_clearance")
                or result.get("success")
                or result.get("verify_success")
            )
            entry = _TASKS.get(task_id)
            if not entry:
                return
            if solved:
                entry["status"] = "ready"
                entry["result"] = result
            else:
                entry["status"] = "failed"
                entry["error"] = result.get("error") or "solve failed"
                entry["result"] = result
        except Exception as e:
            log.exception("createTask background solve failed")
            entry = _TASKS.get(task_id)
            if entry:
                entry["status"] = "failed"
                entry["error"] = str(e)

    asyncio.create_task(_run())
    return {"errorId": 0, "taskId": task_id}


def get_task_result(client_key: Optional[str], task_id: Optional[str]) -> dict:
    err = _check_client_key(client_key)
    if err:
        return err
    if not task_id:
        return {
            "errorId": 1,
            "errorCode": "ERROR_TASKID_INVALID",
            "errorDescription": "taskId required",
        }
    entry = _TASKS.get(str(task_id))
    if not entry:
        return {
            "errorId": 1,
            "errorCode": "ERROR_TASKID_INVALID",
            "errorDescription": "task not found or expired",
        }
    status = entry["status"]
    if status == "processing":
        return {"errorId": 0, "status": "processing"}
    if status == "failed":
        return {
            "errorId": 1,
            "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
            "errorDescription": entry.get("error") or "unsolvable",
            "status": "failed",
        }
    # ready
    result = entry.get("result") or {}
    our_type = entry.get("our_type") or result.get("type") or ""
    solution = result_to_solution(our_type, result)
    return {
        "errorId": 0,
        "status": "ready",
        "solution": solution,
        "cost": "0.000",
        "ip": "",
        "createTime": int(entry.get("created", 0)),
        "endTime": int(time.time()),
        "solveCount": 1,
    }


def get_balance(client_key: Optional[str]) -> dict:
    err = _check_client_key(client_key)
    if err:
        return err
    # Free-first local service — report a symbolic balance so clients don't quit.
    return {"errorId": 0, "balance": 9999.0}
