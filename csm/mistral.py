"""Vision key pool — round-robin + auto-failover over many API keys.

Shared by the reCAPTCHA and hCaptcha image solvers. Exposes `classify` (yes/no),
`classify_custom`, and `ask` (free-form, e.g. numbered-grid cell picks).

Keys can come from:
  1. keyfile (default csm/apikey.txt, one key per line) — MISTRAL_KEYFILE
  2. env VISION_API_KEY / DASHSCOPE_API_KEY / MISTRAL_API_KEY (comma-separated OK)

When DASHSCOPE_API_KEY is set and VISION_ENDPOINT/MODEL are unset, defaults flip
to Qwen Cloud international (dashscope-intl + qwen-vl-plus) — free-tier friendly.

Sync + stdlib only (urllib) — call from async via asyncio.to_thread.
"""
import itertools
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)

# Qwen Cloud free-tier defaults (used when DASHSCOPE_API_KEY present and no override).
_QWEN_ENDPOINT = (
    "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions"
)
_QWEN_MODEL = "qwen-vl-plus"


def _resolve_backend() -> str:
    """qwen | mistral | gemini — auto prefers gemini when key present + VISION_BACKEND=auto/gemini."""
    forced = (os.getenv("VISION_BACKEND") or os.getenv("RC_VISION_BACKEND") or "auto").strip().lower()
    has_gemini = bool(
        (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "").strip()
    )
    has_dash = bool(os.getenv("DASHSCOPE_API_KEY", "").strip())
    if forced in ("gemini", "google"):
        return "gemini"
    if forced in ("qwen", "dashscope"):
        return "qwen"
    if forced in ("mistral",):
        return "mistral"
    # auto
    if forced in ("auto", ""):
        # Prefer qwen by default (stable multi-key free). Gemini optional via
        # VISION_PREFER_GEMINI=1 or VISION_BACKEND=gemini.
        prefer_g = os.getenv("VISION_PREFER_GEMINI", "0").strip().lower() in (
            "1", "true", "yes")
        if prefer_g and has_gemini:
            return "gemini"
        if has_dash:
            return "qwen"
        if has_gemini:
            return "gemini"
        return "mistral"
    return forced


def _resolve_endpoint_model() -> tuple[str, str]:
    backend = _resolve_backend()
    ep = os.getenv("VISION_ENDPOINT", "").strip()
    model = os.getenv("VISION_MODEL", "").strip()
    has_dash = bool(os.getenv("DASHSCOPE_API_KEY", "").strip())
    if backend == "gemini":
        # Always native Google endpoint — ignore VISION_ENDPOINT (often dashscope)
        model = (
            os.getenv("GEMINI_MODEL", "").strip()
            or (model if model.startswith("gemini") else "")
            or "gemini-2.0-flash"
        )
        ep = "https://generativelanguage.googleapis.com/v1beta"
        return ep, model
    if not ep:
        ep = _QWEN_ENDPOINT if (backend == "qwen" or has_dash) else "https://api.mistral.ai/v1/chat/completions"
    if not model or model.startswith("gemini"):
        model = _QWEN_MODEL if (backend == "qwen" or has_dash) else "mistral-medium-latest"
    return ep, model


_ENDPOINT, _DEFAULT_MODEL = _resolve_endpoint_model()
# Per-key failures worth rotating past; 5xx is transient (try next key).
_ROTATE_STATUS = {401, 403, 429}
# Body substrings (lowercased) that mean "this key is dead / empty / unpaid" —
# park long so the rest of the pool keeps serving.
_PARK_BODY_MARKERS = (
    "accessdenied.unpurchased",
    "unpurchased",
    "insufficient_quota",
    "quota exceeded",
    "quota_exceeded",
    "arrears",
    "invalid_api_key",
    "invalidapikey",
    "unauthorized",
    "permissiondenied",
    "throttling.ratequota",
    "allocationquota.free",
)
_COOLDOWN_S = 60          # short park (401/403/429 generic)
_COOLDOWN_HARD_S = 900    # long park for unpurchased / empty free tier
# Qwen VL rejects tiny tiles (InternalError.Algo.InvalidParameter image length).
# Upscale any decoded PNG/JPEG below this edge before send.
_MIN_VISION_EDGE = 64


def _ensure_min_image(image_b64: str, min_edge: int = _MIN_VISION_EDGE) -> str:
    """Upscale tiny base64 images so DashScope/Qwen VL accepts them.

    reCAPTCHA/hCaptcha tiles can be <32px after crop; Qwen returns 400 on those.
    Returns original b64 on any failure (caller still tries).
    """
    if not image_b64:
        return image_b64
    raw = image_b64
    if raw.startswith("data:"):
        # data:image/png;base64,XXXX
        raw = raw.split(",", 1)[-1]
    try:
        import base64
        import io
        from PIL import Image
        data = base64.b64decode(raw)
        img = Image.open(io.BytesIO(data)).convert("RGB")
        w, h = img.size
        if w >= min_edge and h >= min_edge:
            return image_b64 if not image_b64.startswith("data:") else raw
        scale = max(min_edge / max(w, 1), min_edge / max(h, 1))
        # nearest keeps captcha edges crisp for classification
        nw, nh = max(min_edge, int(w * scale)), max(min_edge, int(h * scale))
        img = img.resize((nw, nh), Image.Resampling.NEAREST)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        log.debug("vision upscale skipped: %s", e)
        return raw if image_b64.startswith("data:") else image_b64


def vision_status() -> dict:
    """Non-secret snapshot for /health — key count, endpoint host, model."""
    try:
        keys = _collect_keys(None)
        ep, model = _resolve_endpoint_model()
        host = ""
        try:
            from urllib.parse import urlsplit
            host = urlsplit(ep).netloc
        except Exception:
            host = ep[:40]
        return {
            "keys": len(keys),
            "endpoint_host": host,
            "model": model,
            "backend": _resolve_backend(),
            "ready": len(keys) > 0,
        }
    except Exception as e:
        return {"keys": 0, "ready": False, "error": str(e)[:80]}


def _collect_keys(keyfile: str | None) -> list[str]:
    """Merge env keys + keyfile keys (deduped, env first)."""
    keys: list[str] = []
    for envn in (
        "VISION_API_KEY", "DASHSCOPE_API_KEY", "MISTRAL_API_KEY",
        "GEMINI_API_KEY", "GOOGLE_API_KEY",
    ):
        raw = os.getenv(envn, "")
        for k in raw.split(","):
            k = k.strip()
            if k:
                keys.append(k)
    path = keyfile or os.getenv(
        "MISTRAL_KEYFILE", str(Path(__file__).parent / "apikey.txt")
    )
    try:
        if path and Path(path).exists():
            for line in Path(path).read_text().splitlines():
                k = line.strip()
                if k and not k.startswith("#"):
                    keys.append(k)
    except Exception as e:
        log.warning("keyfile read failed (%s): %s", path, e)
    # dedupe preserve order
    seen: set[str] = set()
    out = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


class KeyPool:
    def __init__(self, keyfile: str | None = None, model: str | None = None,
                 start_index: int = 0, keys: list[str] | None = None):
        # Re-resolve endpoint/model each construct so late env changes work
        global _ENDPOINT, _DEFAULT_MODEL
        _ENDPOINT, _DEFAULT_MODEL = _resolve_endpoint_model()
        if keys is not None:
            self.keys = keys
        else:
            all_keys = _collect_keys(keyfile)
            backend = _resolve_backend()
            if backend == "gemini":
                # Only Google keys — never send DashScope sk- to Gemini REST
                gem_env = []
                for envn in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
                    raw = os.getenv(envn, "")
                    for k in raw.split(","):
                        k = k.strip()
                        if k:
                            gem_env.append(k)
                gem = [k for k in all_keys if k.startswith("AIza") or k.startswith("AQ.")]
                # de-dupe preserve order
                seen = set()
                merged = []
                for k in gem_env + gem:
                    if k not in seen and not k.startswith("sk-"):
                        seen.add(k)
                        merged.append(k)
                self.keys = merged or gem_env
                if not self.keys:
                    raise ValueError(
                        "VISION_BACKEND=gemini but no GEMINI_API_KEY/GOOGLE_API_KEY found"
                    )
            elif backend == "qwen":
                dash = [k for k in all_keys if k.startswith("sk-")]
                self.keys = dash or [k for k in all_keys if not k.startswith("AIza")]
            else:
                self.keys = all_keys
        if not self.keys:
            raise ValueError(
                f"no vision keys (checked env VISION/DASHSCOPE/MISTRAL/GEMINI + {keyfile})"
            )
        self.model = model or _DEFAULT_MODEL
        self._lock = threading.Lock()
        # round-robin cursor, started at a caller-chosen offset to spread load
        n = len(self.keys)
        self._cursor = itertools.cycle(
            self.keys[start_index % n:] + self.keys[:start_index % n])
        self._dead: dict[str, float] = {}   # key -> monotonic time it's live again

    def _next_live_key(self) -> str:
        with self._lock:
            now = time.monotonic()
            for _ in range(len(self.keys)):
                k = next(self._cursor)
                if self._dead.get(k, 0.0) <= now:
                    return k
            # all parked — clear cooldowns and take the next
            self._dead.clear()
            return next(self._cursor)

    def _park(self, key: str, cooldown: float = _COOLDOWN_S):
        with self._lock:
            self._dead[key] = time.monotonic() + cooldown

    def _call_openai_compat(self, image_b64: str, prompt: str,
                              max_keys: int, timeout: int, max_tokens: int) -> str:
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": prompt},
                {"type": "image_url",
                 "image_url": f"data:image/png;base64,{image_b64}"}]}],
            "max_tokens": max_tokens, "temperature": 0,
        }).encode()

        last_err = None
        n_try = min(max(max_keys, len(self.keys)), len(self.keys))
        for _ in range(n_try):
            key = self._next_live_key()
            req = urllib.request.Request(
                _ENDPOINT, data=body,
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer " + key})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = json.loads(r.read())
                if isinstance(data, dict) and data.get("error") and not data.get("choices"):
                    err_s = json.dumps(data.get("error")).lower()
                    last_err = err_s[:120]
                    hard = any(m in err_s for m in _PARK_BODY_MARKERS)
                    self._park(key, _COOLDOWN_HARD_S if hard else _COOLDOWN_S)
                    continue
                txt = data["choices"][0]["message"]["content"]
                if isinstance(txt, list):
                    txt = " ".join(p.get("text", "") for p in txt if isinstance(p, dict))
                return txt.strip().lower()
            except urllib.error.HTTPError as e:
                body_txt = ""
                try:
                    body_txt = e.read().decode("utf-8", "replace")[:400]
                except Exception:
                    body_txt = ""
                last_err = f"HTTP {e.code} {body_txt[:80]}"
                low = body_txt.lower()
                hard = any(m in low for m in _PARK_BODY_MARKERS)
                if e.code in _ROTATE_STATUS or hard:
                    self._park(key, _COOLDOWN_HARD_S if hard else _COOLDOWN_S)
                    continue
                if 500 <= e.code < 600:
                    continue
                self._park(key, _COOLDOWN_S)
                continue
            except Exception as e:
                last_err = str(e).splitlines()[0]
                continue
        log.warning("_call openai-compat failed for %r: %s", prompt[:60], last_err)
        return ""

    def _call_gemini(self, image_b64: str, prompt: str,
                     max_keys: int, timeout: int, max_tokens: int) -> str:
        """Native Gemini generateContent REST (no openai package needed)."""
        last_err = None
        n_try = min(max(max_keys, len(self.keys)), len(self.keys))
        model = self.model
        if model.startswith("models/"):
            model = model.split("/", 1)[1]
        base = _ENDPOINT.rstrip("/")
        for _ in range(n_try):
            key = self._next_live_key()
            url = f"{base}/models/{model}:generateContent?key={key}"
            body = json.dumps({
                "contents": [{
                    "role": "user",
                    "parts": [
                        {"text": prompt},
                        {"inline_data": {
                            "mime_type": "image/png",
                            "data": image_b64,
                        }},
                    ],
                }],
                "generationConfig": {
                    "temperature": 0,
                    "maxOutputTokens": max_tokens,
                },
            }).encode()
            req = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = json.loads(r.read())
                if isinstance(data, dict) and data.get("error"):
                    err_s = json.dumps(data.get("error")).lower()
                    last_err = err_s[:160]
                    hard = any(m in err_s for m in _PARK_BODY_MARKERS) or "api_key" in err_s
                    self._park(key, _COOLDOWN_HARD_S if hard else _COOLDOWN_S)
                    continue
                cands = data.get("candidates") or []
                if not cands:
                    last_err = "no candidates " + json.dumps(data)[:120]
                    # safety block etc — try next key
                    continue
                parts = (((cands[0] or {}).get("content") or {}).get("parts") or [])
                txt = " ".join(
                    (p.get("text") or "") for p in parts if isinstance(p, dict)
                )
                return txt.strip().lower()
            except urllib.error.HTTPError as e:
                body_txt = ""
                try:
                    body_txt = e.read().decode("utf-8", "replace")[:400]
                except Exception:
                    body_txt = ""
                last_err = f"HTTP {e.code} {body_txt[:100]}"
                low = body_txt.lower()
                hard = any(m in low for m in _PARK_BODY_MARKERS) or e.code in (400, 401, 403)
                if e.code in _ROTATE_STATUS or hard:
                    self._park(key, _COOLDOWN_HARD_S if hard else _COOLDOWN_S)
                    continue
                if 500 <= e.code < 600:
                    continue
                self._park(key, _COOLDOWN_S)
                continue
            except Exception as e:
                last_err = str(e).splitlines()[0]
                continue
        log.warning("_call gemini failed for %r: %s", prompt[:60], last_err)
        return ""

    def _call(self, image_b64: str, prompt: str,
              max_keys: int, timeout: int, max_tokens: int) -> str:
        """Call vision API, return raw response string (lowercased, stripped).

        Rotates keys on 401/403/429 (parks dead) and 5xx (transient).
        Upscales tiny images so Qwen VL does not 400 on short edge.
        Returns '' on total failure.
        If VISION_BACKEND=gemini fails entirely and DashScope keys exist,
        auto-fallback to qwen once (quota/429 common on free Gemini).
        """
        image_b64 = _ensure_min_image(image_b64)
        backend = _resolve_backend()
        if backend == "gemini":
            out = self._call_gemini(image_b64, prompt, max_keys, timeout, max_tokens)
            if out:
                return out
            # auto-fallback to qwen/openai-compat if dashscope keys present
            if os.getenv("VISION_FALLBACK_QWEN", "1").strip().lower() not in (
                    "0", "false", "no"):
                dash = []
                for envn in ("DASHSCOPE_API_KEY", "VISION_API_KEY"):
                    raw = os.getenv(envn, "")
                    for k in raw.split(","):
                        k = k.strip()
                        if k and k.startswith("sk-"):
                            dash.append(k)
                # also keyfile sk-
                try:
                    kf = Path(os.getenv(
                        "MISTRAL_KEYFILE",
                        str(Path(__file__).parent / "apikey.txt")))
                    if kf.exists():
                        for line in kf.read_text().splitlines():
                            k = line.strip()
                            if k and not k.startswith("#") and k.startswith("sk-"):
                                dash.append(k)
                except Exception:
                    pass
                # dedupe
                seen = set(); dash2 = []
                for k in dash:
                    if k not in seen:
                        seen.add(k); dash2.append(k)
                if dash2:
                    log.warning("gemini empty — fallback qwen (%d keys)", len(dash2))
                    # temporarily swap endpoint/model/keys for one openai-compat call
                    global _ENDPOINT, _DEFAULT_MODEL
                    old_ep, old_model, old_keys = _ENDPOINT, self.model, self.keys
                    try:
                        _ENDPOINT = _QWEN_ENDPOINT
                        self.model = os.getenv("QWEN_FALLBACK_MODEL", "qwen-vl-max").strip() or "qwen-vl-max"
                        self.keys = dash2
                        # rebuild cursor
                        import itertools as _it
                        self._cursor = _it.cycle(self.keys)
                        return self._call_openai_compat(
                            image_b64, prompt, max_keys, timeout, max_tokens)
                    finally:
                        _ENDPOINT, self.model, self.keys = old_ep, old_model, old_keys
                        self._cursor = _it.cycle(self.keys)
            return ""
        return self._call_openai_compat(image_b64, prompt, max_keys, timeout, max_tokens)

    def _classify_with_prompt(self, image_b64: str, prompt: str,
                               max_keys: int, timeout: int) -> bool:
        return self._call(image_b64, prompt, max_keys, timeout, 8).startswith("y")

    def classify(self, image_b64: str, target: str,
                 max_keys: int = 0, timeout: int = 40) -> bool:
        """Yes/no: does this tile contain `target`? Rotates keys on failure.

        Returns False if every tried key fails (caller treats as 'not a match').
        max_keys=0 → try entire pool (fallback-friendly for multi-key DashScope).
        """
        if max_keys <= 0:
            max_keys = len(self.keys)
        # reCAPTCHA tiles are deliberately partial/cropped — accept partial object
        prompt = (
            f'Does this image show a {target} (or a clear visible part of one, '
            f'even if cropped/partial)? Answer ONLY "yes" or "no".'
        )
        return self._classify_with_prompt(image_b64, prompt, max_keys, timeout)

    def classify_custom(self, image_b64: str, prompt: str,
                        max_keys: int = 0, timeout: int = 40) -> bool:
        """Yes/no for a custom prompt. Use when the target is a full instruction."""
        if max_keys <= 0:
            max_keys = len(self.keys)
        return self._classify_with_prompt(image_b64, prompt, max_keys, timeout)

    def ask(self, image_b64: str, prompt: str,
            max_keys: int = 0, timeout: int = 40, max_tokens: int = 512) -> str:
        """Ask a free-form question, return the model's full response text.

        Use for numbered-grid challenges (classify → cell number) where
        the answer is a token or short phrase, not just yes/no.
        Returns '' on total failure.
        max_keys=0 → try entire pool.
        """
        if max_keys <= 0:
            max_keys = len(self.keys)
        return self._call(image_b64, prompt, max_keys, timeout, max_tokens)


# self-check: pool loads, rotates, and a 1x1 red tile classifies without crashing.
if __name__ == "__main__":
    pool = KeyPool(str(Path(__file__).parent / "apikey.txt"))
    print("keys loaded:", len(pool.keys))
    red = ("iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAAEUlEQVR42mP8"
           "z8BQz0AEYBxVSFXyW3aBAAAAAElFTkSuQmCC")
    print("classify(red, 'red square') ->", pool.classify(red, "red square"))
