"""Free local image-captcha solver — ddddocr first, then ppllocr / Tesseract / LLM.

Handles image/text/math captchas and slider/gap matching without paid APIs.

Tier order for text/math (all FREE unless LLM keys present):
  1. ddddocr  — ONNX general captcha OCR (MIT), strongest on distorted text
  2. ppllocr  — ONNX anti-noise OCR (MIT), good on math operators
  3. Tesseract — classical OCR fallback
  4. optional vision LLM (VISION_*/MISTRAL_KEYFILE) if keys configured

Slider (type=slider):
  ddddocr.slide_match(target_bytes, background_bytes) → gap distance / box

All deps optional at import time — missing engines just skip that tier.
"""
from __future__ import annotations

import base64
import io
import logging
import os
import re
import threading
from pathlib import Path

log = logging.getLogger("imagesolve")

_ALNUM_RE = re.compile(r"^[A-Za-z0-9]+$")
_BARE_NUM_RE = re.compile(r"^-?\d+$")
_MATH_CHARS_RE = re.compile(r"^[0-9+\-*/xX=?()]+$")

_OCR_SCALE = int(os.getenv("OCR_SCALE", "3"))
_OCR_THRESHOLD = int(os.getenv("OCR_THRESHOLD", "160"))
_OCR_PSM = int(os.getenv("OCR_PSM", "7"))
_OCR_CONF_MIN = float(os.getenv("OCR_CONF_MIN", "60"))
_WHITELIST = os.getenv(
    "OCR_WHITELIST",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
)

# Lazy singletons — ddddocr model load is ~hundreds of ms once.
_lock = threading.Lock()
_dddd_ocr = None
_dddd_slide = None
_ppll = None
_dddd_ok = None
_ppll_ok = None


def _strip_data_url(s: str) -> str:
    if s.startswith("data:"):
        return s.split(",", 1)[-1]
    return s


def _b64_to_bytes(image_b64: str) -> bytes:
    return base64.b64decode(_strip_data_url(image_b64))


def _decode_math(expr: str) -> str | None:
    expr = expr.replace("x", "*").replace("X", "*").replace("÷", "/").replace("×", "*")
    expr = re.sub(r"[^0-9+\-*/()]", "", expr)
    if not expr or not re.search(r"[0-9]", expr):
        return None
    try:
        val = eval(expr, {"__builtins__": {}}, {})  # digits+ops only
        if isinstance(val, float) and val == int(val):
            val = int(val)
        return str(val)
    except Exception:
        return None


def _get_dddd():
    global _dddd_ocr, _dddd_ok
    if _dddd_ok is False:
        return None
    if _dddd_ocr is not None:
        return _dddd_ocr
    with _lock:
        if _dddd_ocr is not None:
            return _dddd_ocr
        try:
            import ddddocr
            _dddd_ocr = ddddocr.DdddOcr(show_ad=False)
            _dddd_ok = True
            log.info("ddddocr engine ready")
            return _dddd_ocr
        except Exception as e:
            _dddd_ok = False
            log.warning("ddddocr unavailable: %s", e)
            return None


def _get_dddd_slide():
    global _dddd_slide
    if _dddd_slide is not None:
        return _dddd_slide
    with _lock:
        if _dddd_slide is not None:
            return _dddd_slide
        try:
            import ddddocr
            # det=False, ocr=False → slide-only instance (lighter)
            _dddd_slide = ddddocr.DdddOcr(det=False, ocr=False, show_ad=False)
            return _dddd_slide
        except Exception as e:
            log.warning("ddddocr slide engine unavailable: %s", e)
            return None


def _get_ppll():
    global _ppll, _ppll_ok
    if _ppll_ok is False:
        return None
    if _ppll is not None:
        return _ppll
    with _lock:
        if _ppll is not None:
            return _ppll
        try:
            import ppllocr
            # API varies slightly across versions — try common constructors
            if hasattr(ppllocr, "Ppllocr"):
                _ppll = ppllocr.Ppllocr()
            elif hasattr(ppllocr, "OCR"):
                _ppll = ppllocr.OCR()
            else:
                _ppll = ppllocr
            _ppll_ok = True
            log.info("ppllocr engine ready")
            return _ppll
        except Exception as e:
            _ppll_ok = False
            log.warning("ppllocr unavailable: %s", e)
            return None


def ocr_dddd(image_b64: str) -> str | None:
    eng = _get_dddd()
    if not eng:
        return None
    try:
        raw = eng.classification(_b64_to_bytes(image_b64))
        text = (raw or "").strip()
        return text or None
    except Exception as e:
        log.warning("ddddocr failed: %s", e)
        return None


def ocr_ppll(image_b64: str) -> str | None:
    eng = _get_ppll()
    if not eng:
        return None
    try:
        data = _b64_to_bytes(image_b64)
        if hasattr(eng, "classification"):
            raw = eng.classification(data)
        elif hasattr(eng, "recognize"):
            raw = eng.recognize(data)
        elif hasattr(eng, "ocr"):
            raw = eng.ocr(data)
        elif callable(eng):
            raw = eng(data)
        else:
            return None
        if isinstance(raw, dict):
            raw = raw.get("text") or raw.get("result") or ""
        text = str(raw or "").strip()
        return text or None
    except Exception as e:
        log.warning("ppllocr failed: %s", e)
        return None


def _tesseract_once(img, captcha_type: str) -> tuple[str | None, float]:
    import pytesseract
    if captcha_type == "math":
        whitelist = "0123456789+-*/xX=?()"
    else:
        whitelist = _WHITELIST
    # Try primary PSM then 8 (single word) as secondary
    for psm in (_OCR_PSM, 8 if _OCR_PSM != 8 else 7):
        config = f"--psm {psm} -c tessedit_char_whitelist={whitelist}"
        try:
            data = pytesseract.image_to_data(
                img, config=config, output_type=pytesseract.Output.DICT)
        except Exception as e:
            log.warning("tesseract psm=%s failed: %s", psm, e)
            continue
        best_text, best_conf = "", -1.0
        words = data.get("text", [])
        confs = data.get("conf", [0] * len(words))
        # Prefer concatenating non-empty words on one line over single best word
        parts = []
        conf_acc = []
        for i, word in enumerate(words):
            word = (word or "").strip()
            try:
                conf = float(confs[i])
            except (ValueError, IndexError):
                conf = -1.0
            if not word or conf < 0:
                continue
            parts.append(word)
            conf_acc.append(conf)
            if conf > best_conf:
                best_conf, best_text = conf, word
        joined = re.sub(r"\s+", "", "".join(parts))
        if joined and conf_acc:
            avg = sum(conf_acc) / len(conf_acc)
            # Prefer joined if longer (handles split chars)
            if len(joined) >= len(best_text or ""):
                return joined, max(avg, 0.0)
        if best_text:
            return re.sub(r"\s+", "", best_text), max(best_conf, 0.0)
    return None, 0.0


def ocr_tesseract(image_b64: str, captcha_type: str) -> tuple[str | None, float]:
    """Tesseract with multi-preprocess: scale+threshold, invert, optional scale2."""
    try:
        import pytesseract  # noqa: F401
        from PIL import Image, ImageOps
    except ImportError:
        return None, 0.0
    try:
        raw = Image.open(io.BytesIO(_b64_to_bytes(image_b64))).convert("L")
    except Exception as e:
        log.warning("image decode failed: %s", e)
        return None, 0.0

    variants = []
    # primary: scale + binary threshold
    img = raw
    if _OCR_SCALE != 1:
        img = img.resize((img.width * _OCR_SCALE, img.height * _OCR_SCALE), Image.LANCZOS)
    thr = img.point(lambda p: 0 if p < _OCR_THRESHOLD else 255)
    variants.append(thr)
    # inverted (dark text on light vs light on dark)
    variants.append(ImageOps.invert(thr))
    # softer scale if primary scale is aggressive
    if _OCR_SCALE >= 3:
        mild = raw.resize((raw.width * 2, raw.height * 2), Image.LANCZOS)
        variants.append(mild.point(lambda p: 0 if p < _OCR_THRESHOLD else 255))

    best_text, best_conf = None, -1.0
    for v in variants:
        text, conf = _tesseract_once(v, captcha_type)
        if text and conf > best_conf:
            best_text, best_conf = text, conf
    return best_text, max(best_conf, 0.0)


def _plausible(text: str, captcha_type: str) -> bool:
    if not text:
        return False
    if captcha_type == "math":
        return bool(_decode_math(text) is not None or _BARE_NUM_RE.fullmatch(text))
    if captcha_type == "image_text":
        if not (2 <= len(text) <= 12):
            return False
        if not _ALNUM_RE.fullmatch(text):
            return False
        return len(set(text)) > 1
    return bool(text.strip())


def _mistral_fallback(image_b64: str, captcha_type: str) -> str | None:
    """Optional vision LLM fallback. Keys from env (DASHSCOPE/VISION/MISTRAL) or keyfile."""
    keyfile = os.getenv("MISTRAL_KEYFILE", str(Path(__file__).parent / "apikey.txt"))
    try:
        from csm.mistral import KeyPool, _collect_keys
    except Exception as e:
        log.warning("mistral module unavailable: %s", e)
        return None
    # Skip early if no keys at all (env + file)
    try:
        if not _collect_keys(keyfile):
            return None
        pool = KeyPool(keyfile)
    except Exception as e:
        log.debug("vision pool not available: %s", e)
        return None
    try:
        if captcha_type == "math":
            q = ("Solve the arithmetic in this image. Reply with ONLY the integer "
                 "result, no words.")
        else:
            q = ("Read the distorted text in this image. Reply with ONLY the "
                 "characters you see, no spaces, no explanation.")
        ans = pool.ask(image_b64=_strip_data_url(image_b64), prompt=q)
        if not ans:
            return None
        ans = ans.strip()
        if captcha_type == "math":
            return _decode_math(ans) or (ans if _BARE_NUM_RE.fullmatch(ans) else None)
        return re.sub(r"[^A-Za-z0-9]", "", ans) or None
    except Exception as e:
        log.warning("vision fallback failed: %s", e)
        return None


def _finalize_text(text: str | None, captcha_type: str, method: str,
                   conf: float = 0.0) -> dict | None:
    """Return a solved dict if text is usable for captcha_type, else None."""
    if not text:
        return None
    text = text.strip()
    if captcha_type == "math":
        result = _decode_math(text)
        if result is not None:
            return {"solved": True, "token": result, "method": method,
                    "confidence": conf, "error": None, "raw": text}
        # Bare number only accepted if it looks like an already-computed answer
        # (short) — long digit dumps usually mean operators were stripped.
        if _BARE_NUM_RE.fullmatch(text) and len(text) <= 4:
            return {"solved": True, "token": text, "method": method,
                    "confidence": conf, "error": None, "raw": text,
                    "_bare": True}
        return None
    if captcha_type == "image_text":
        # ddddocr often lowercases Latin letters; captchas are usually case-insensitive
        # for submission, but we keep a cleaned alnum form. Prefer original casing when
        # mixed; otherwise accept lower/upper as-is.
        cleaned = re.sub(r"[^A-Za-z0-9]", "", text)
        if _plausible(cleaned, "image_text") or _plausible(cleaned.upper(), "image_text"):
            return {"solved": True, "token": cleaned, "method": method,
                    "confidence": conf, "error": None}
        return None
    return None


def _score_candidate(token: str, method: str, conf: float = 0.0) -> float:
    """Higher is better. Prefers longer mixed-case alnum from stronger engines."""
    base = {"ddddocr": 3.0, "ppllocr": 2.5, "tesseract": 1.5, "vision_llm": 1.0}.get(method, 1.0)
    # reward mixed case + digits (more captcha-like than all-lower garbage)
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    has_digit = any(c.isdigit() for c in token)
    variety = sum([has_upper, has_lower, has_digit]) * 0.3
    return base + variety + min(len(token), 8) * 0.05 + conf / 200.0


def _repair_dropped_double(short: str, long: str) -> str | None:
    """If ddddocr drops a doubled letter (hello5→helo5), recover from longer candidate.

    Returns repaired string when long looks like short with exactly one extra
    consecutive-duplicate char; else None.
    """
    if not short or not long:
        return None
    if long.lower() == short.lower():
        return None
    if abs(len(long) - len(short)) != 1:
        return None
    a, b = (short, long) if len(short) < len(long) else (long, short)
    # a shorter, b longer by 1
    i = j = 0
    extra_at = -1
    while i < len(a) and j < len(b):
        if a[i].lower() == b[j].lower():
            i += 1
            j += 1
        else:
            if extra_at >= 0:
                return None
            extra_at = j
            j += 1
    if i == len(a) and j == len(b) - 1 and extra_at < 0:
        extra_at = j
    if extra_at < 0 or i != len(a):
        return None
    # extra char should be a double of neighbor
    ch = b[extra_at]
    left = b[extra_at - 1] if extra_at > 0 else None
    right = b[extra_at + 1] if extra_at + 1 < len(b) else None
    if (left and left.lower() == ch.lower()) or (right and right.lower() == ch.lower()):
        return b  # prefer longer with preserved casing
    return None


def run_image(image_b64: str, captcha_type: str = "image_text") -> dict:
    """Solve image_text or math captcha. Multi-engine free cascade with voting."""
    if captcha_type not in ("image_text", "math"):
        return {"solved": False, "token": "", "method": "none",
                "confidence": 0.0, "error": f"unsupported type {captcha_type}"}

    candidates: list[dict] = []

    for method, fn in (
        ("ddddocr", lambda: ocr_dddd(image_b64)),
        ("ppllocr", lambda: ocr_ppll(image_b64)),
    ):
        r = _finalize_text(fn(), captcha_type, method)
        if r:
            candidates.append(r)

    text, conf = ocr_tesseract(image_b64, captcha_type)
    if captcha_type == "math":
        r = _finalize_text(text, captcha_type, "tesseract", conf)
        if r:
            candidates.append(r)
    elif text and conf >= _OCR_CONF_MIN:
        r = _finalize_text(text, captcha_type, "tesseract", conf)
        if r:
            candidates.append(r)
    elif text:
        # low conf still kept as weak candidate for double-letter repair
        r = _finalize_text(text, captcha_type, "tesseract", conf)
        if r:
            r["_weak"] = True
            candidates.append(r)

    if captcha_type == "math":
        if candidates:
            # Prefer candidates that actually parsed an expression (have operator
            # in raw) over bare-number dumps like "93" for "9-3".
            with_ops = []
            bare = []
            for c in candidates:
                raw = str(c.get("raw") or c.get("token") or "")
                if re.search(r"[+\-*/xX]", raw):
                    with_ops.append(c)
                else:
                    bare.append(c)
            return (with_ops or bare)[0]
    else:
        if candidates:
            # double-letter repair across engine pairs
            repaired = None
            for i, a in enumerate(candidates):
                for b in candidates[i + 1:]:
                    fixed = _repair_dropped_double(a["token"], b["token"])
                    if fixed:
                        # prefer method of the longer source
                        src = a if len(a["token"]) >= len(b["token"]) else b
                        repaired = {
                            "solved": True, "token": fixed,
                            "method": f"{src['method']}+repair",
                            "confidence": src.get("confidence") or 0.0,
                            "error": None,
                        }
                        break
                if repaired:
                    break
            if repaired:
                return repaired

            strong = [c for c in candidates if not c.get("_weak")]
            pool = strong or candidates
            best = max(pool, key=lambda c: _score_candidate(
                c["token"], c["method"], c.get("confidence") or 0.0))
            # casing repair: if ddddocr lower and tesseract same letters with case
            for c in pool:
                if c["method"] == "tesseract" and c["token"].lower() == best["token"].lower():
                    if c.get("confidence", 0) >= _OCR_CONF_MIN and any(
                            ch.isupper() for ch in c["token"]):
                        best = c
                        break
            best = {k: v for k, v in best.items() if not k.startswith("_")}
            return best

    llm = _mistral_fallback(image_b64, captcha_type)
    if llm:
        return {"solved": True, "token": llm, "method": "vision_llm",
                "confidence": 0.0, "error": None}

    return {"solved": False, "token": text or "", "method": "cascade",
            "confidence": conf if text else 0.0,
            "error": "all free OCR engines failed / no vision key"}


def _parse_slide_result(res) -> dict:
    """Normalize ddddocr.slide_match return into our response shape."""
    if not res:
        return {"solved": False, "token": "", "method": "ddddocr_slide",
                "confidence": 0.0, "error": "empty slide_match result"}
    if isinstance(res, dict):
        dist = res.get("target_x")
        if dist is None:
            dist = res.get("x")
        if dist is None:
            tgt = res.get("target")
            if isinstance(tgt, (list, tuple)) and tgt:
                dist = tgt[0]
            elif isinstance(tgt, (int, float)):
                dist = tgt
        if dist is None:
            box = res.get("box") or res.get("target")
            if isinstance(box, (list, tuple)) and len(box) >= 1:
                dist = box[0]
        return {
            "solved": dist is not None,
            "token": str(dist) if dist is not None else "",
            "method": "ddddocr_slide",
            "confidence": 0.0,
            "error": None if dist is not None else "no distance in result",
            "raw": res,
            "target_x": dist,
            "box": res.get("target") or res.get("box"),
        }
    return {"solved": True, "token": str(res), "method": "ddddocr_slide",
            "confidence": 0.0, "error": None, "raw": res}


def _slide_dddd(target: bytes, background: bytes,
                simple: bool | None = None) -> dict:
    """Tier 1: ddddocr.slide_match dual-try."""
    eng = _get_dddd_slide() or _get_dddd()
    if not eng or not hasattr(eng, "slide_match"):
        return {"solved": False, "token": "", "method": "ddddocr_slide",
                "confidence": 0.0, "error": "ddddocr slide unavailable"}
    modes = [bool(simple)] if simple is not None else [False, True]
    last_err = None
    last_res = None
    for mode in modes:
        try:
            res = eng.slide_match(target, background, simple_target=mode)
            parsed = _parse_slide_result(res)
            parsed["simple_target"] = mode
            if parsed.get("solved"):
                return parsed
            last_res = parsed
        except Exception as e:
            last_err = str(e)
            log.warning("slide_match simple_target=%s failed: %s", mode, e)
    if last_res:
        if last_err and not last_res.get("error"):
            last_res["error"] = last_err
        return last_res
    return {"solved": False, "token": "", "method": "ddddocr_slide",
            "confidence": 0.0, "error": last_err or "slide_match failed both modes"}


_yolo_slider = None
_yolo_ok = None


def _get_yolo_slider():
    """Lazy captcha-recognizer (chenwei-zhao) YOLO gap detector — optional."""
    global _yolo_slider, _yolo_ok
    if _yolo_ok is False:
        return None
    if _yolo_slider is not None:
        return _yolo_slider
    with _lock:
        if _yolo_slider is not None:
            return _yolo_slider
        try:
            from captcha_recognizer.slider import Slider  # type: ignore
            _yolo_slider = Slider()
            _yolo_ok = True
            log.info("captcha-recognizer YOLO slider ready")
            return _yolo_slider
        except Exception as e:
            _yolo_ok = False
            log.info("captcha-recognizer unavailable (optional): %s", e)
            return None


def _slide_yolo(background: bytes, min_conf: float = 0.35) -> dict:
    """Tier 2: YOLO ONNX gap detect on background (or full image)."""
    eng = _get_yolo_slider()
    if not eng:
        return {"solved": False, "token": "", "method": "yolo_slider",
                "confidence": 0.0, "error": "yolo slider unavailable"}
    try:
        offset, conf = eng.identify_offset(background)
        conf = float(conf or 0.0)
        if offset and conf >= min_conf:
            return {
                "solved": True,
                "token": str(int(round(float(offset)))),
                "method": "yolo_slider",
                "confidence": conf,
                "error": None,
                "target_x": float(offset),
                "box": None,
            }
        return {
            "solved": False, "token": str(int(round(float(offset or 0)))),
            "method": "yolo_slider", "confidence": conf,
            "error": f"low conf {conf:.3f} < {min_conf}",
            "target_x": float(offset or 0),
        }
    except Exception as e:
        log.warning("yolo slider failed: %s", e)
        return {"solved": False, "token": "", "method": "yolo_slider",
                "confidence": 0.0, "error": str(e)[:160]}


def _slide_canny(target: bytes, background: bytes) -> dict:
    """Tier 3: OpenCV Canny + matchTemplate (zero model).

    Pattern from glizzykingdreko / GeekedTest SlideSolver / PuzzleCaptchaSolver
    (MIT ideas). Returns left-edge x of the gap match.
    """
    try:
        import cv2
        import numpy as np
    except Exception as e:
        return {"solved": False, "token": "", "method": "canny_match",
                "confidence": 0.0, "error": f"opencv missing: {e}"}
    try:
        piece = cv2.imdecode(np.frombuffer(target, np.uint8), cv2.IMREAD_COLOR)
        bg = cv2.imdecode(np.frombuffer(background, np.uint8), cv2.IMREAD_COLOR)
        if piece is None or bg is None:
            return {"solved": False, "token": "", "method": "canny_match",
                    "confidence": 0.0, "error": "decode failed"}
        # Drop near-transparent / pure-white padding on the piece if present
        if piece.shape[2] == 4:
            piece = piece[:, :, :3]
        edge_p = cv2.Canny(piece, 100, 200)
        edge_b = cv2.Canny(bg, 100, 200)
        edge_p = cv2.cvtColor(edge_p, cv2.COLOR_GRAY2RGB)
        edge_b = cv2.cvtColor(edge_b, cv2.COLOR_GRAY2RGB)
        if edge_p.shape[0] > edge_b.shape[0] or edge_p.shape[1] > edge_b.shape[1]:
            return {"solved": False, "token": "", "method": "canny_match",
                    "confidence": 0.0, "error": "piece larger than background"}
        res = cv2.matchTemplate(edge_b, edge_p, cv2.TM_CCOEFF_NORMED)
        min_v, max_v, min_loc, max_loc = cv2.minMaxLoc(res)
        # TM_CCOEFF_NORMED → higher is better
        conf = float(max_v)
        top_left = max_loc
        h, w = edge_p.shape[:2]
        # left edge of match (gap start); center-based offset used by some GT clients
        left_x = int(top_left[0])
        center_x = left_x + w // 2
        if conf < 0.25:
            return {
                "solved": False, "token": str(left_x), "method": "canny_match",
                "confidence": conf, "error": f"low match conf {conf:.3f}",
                "target_x": left_x, "center_x": center_x,
                "box": [left_x, top_left[1], left_x + w, top_left[1] + h],
            }
        return {
            "solved": True,
            "token": str(left_x),
            "method": "canny_match",
            "confidence": conf,
            "error": None,
            "target_x": left_x,
            "center_x": center_x,
            "box": [left_x, int(top_left[1]), left_x + w, int(top_left[1] + h)],
        }
    except Exception as e:
        log.warning("canny match failed: %s", e)
        return {"solved": False, "token": "", "method": "canny_match",
                "confidence": 0.0, "error": str(e)[:160]}


def run_slider(target_b64: str, background_b64: str,
                 simple: bool | None = None) -> dict:
    """Find slider gap via free cascade:

      1. ddddocr.slide_match (dual simple_target) — fastest, good on many tiles
      2. captcha-recognizer YOLO ONNX (optional pip) — real multi-style gaps
      3. OpenCV Canny + matchTemplate — zero-model fallback

    `simple` only affects tier-1 ddddocr mode lock.
    """
    try:
        target = _b64_to_bytes(target_b64)
        background = _b64_to_bytes(background_b64)
    except Exception as e:
        return {"solved": False, "token": "", "method": "slider_cascade",
                "confidence": 0.0, "error": f"bad base64: {e}"}
    if not target or not background:
        return {"solved": False, "token": "", "method": "slider_cascade",
                "confidence": 0.0, "error": "empty target or background"}

    attempts: list[dict] = []

    r1 = _slide_dddd(target, background, simple=simple)
    attempts.append({"method": r1.get("method"), "solved": r1.get("solved"),
                     "conf": r1.get("confidence"), "err": r1.get("error")})
    if r1.get("solved"):
        r1["cascade"] = attempts
        return r1

    r2 = _slide_yolo(background)
    attempts.append({"method": r2.get("method"), "solved": r2.get("solved"),
                     "conf": r2.get("confidence"), "err": r2.get("error")})
    if r2.get("solved"):
        r2["cascade"] = attempts
        return r2

    r3 = _slide_canny(target, background)
    attempts.append({"method": r3.get("method"), "solved": r3.get("solved"),
                     "conf": r3.get("confidence"), "err": r3.get("error")})
    if r3.get("solved"):
        r3["cascade"] = attempts
        return r3

    # Prefer the best partial (highest conf) for debugging
    best = max(
        [r1, r2, r3],
        key=lambda r: float(r.get("confidence") or 0.0),
    )
    best = dict(best)
    best["solved"] = False
    best["method"] = "slider_cascade"
    best["cascade"] = attempts
    if not best.get("error"):
        best["error"] = "all slider tiers failed"
    return best


def engines_status() -> dict:
    """Report which free OCR engines are importable (for /health enrichment)."""
    yolo = _get_yolo_slider() is not None
    return {
        "ddddocr": _get_dddd() is not None,
        "ppllocr": _get_ppll() is not None,
        "tesseract": True,  # verified at deploy; import cost left lazy
        "slide": (_get_dddd_slide() or _get_dddd()) is not None,
        "slide_yolo": yolo,
        "slide_canny": True,  # opencv already a hard dep
    }
