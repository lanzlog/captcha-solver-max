"""Solve the reCAPTCHA v2 IMAGE challenge with a vision model.

Audio fallback is IP-blocked; image grid opens normally. Strategy (2026-07-17):
  1. whole-grid VL with numbered cells (primary context)
  2. dual whole-grid pass + intersection when both non-empty
  3. per-tile yes/no hybrid consensus
  4. dynamic grids: re-classify after reloads
  5. reject over-select (≥ N²-1) unless tiles agree

Success = reCAPTCHA accepts verify (token/checkbox), not our confidence.
"""
import asyncio
import base64
import io
import logging
import os
import re
from pathlib import Path
try:
    from engines.rc.yolo_onnx import get_yolo
except Exception:  # pragma: no cover
    get_yolo = None  # type: ignore

from PIL import Image, ImageDraw, ImageFont

log = logging.getLogger(__name__)

_BFRAME = "/bframe"
_VERIFY = "#recaptcha-verify-button"
_MAX_DYNAMIC_ROUNDS = 6
_CLASSIFY_CONCURRENCY = 6


async def _find_bframe(page):
    for fr in page.frames:
        if _BFRAME in (fr.url or ""):
            return fr
    return None


async def _challenge_meta(bf) -> dict:
    return await bf.evaluate("""() => {
        const t = document.querySelector('table');
        const desc = document.querySelector(
            '.rc-imageselect-desc-no-canonical, .rc-imageselect-desc');
        const strong = desc?.querySelector('strong')?.innerText;
        const rows = t ? t.rows.length : 0;
        const cols = t && t.rows[0] ? t.rows[0].cells.length : 0;
        const body = (desc?.innerText || '');
        return {
            target: strong || (desc ? desc.innerText.split('\\n')[0] : ''),
            rows, cols,
            dynamic: !!document.querySelector(
                '.rc-imageselect-dynamic-selected') ||
                /click verify once there are none/i.test(body) ||
                /none left/i.test(body),
            has_table: !!t,
            desc_full: body.slice(0, 200),
        };
    }""")


def _parse_cell_indices(text: str, n: int) -> list:
    """Parse model answer into 0-based tile indices. Accepts 1-based or 0-based."""
    if not text:
        return []
    low = text.lower().strip()
    if re.search(r"\b(none|no tiles|nothing|empty|n/a|no match)\b", low):
        # allow explicit none even if digits appear elsewhere
        if not re.search(r"\b\d+\b", low) or re.match(r"^\s*(none|no)\b", low):
            return []
    nums = [int(x) for x in re.findall(r"\d+", text)]
    if not nums:
        return []
    max_n = n * n
    # prefer 1-based (1..N) if any number in that range and none > max_n
    if any(1 <= x <= max_n for x in nums) and all(x <= max_n for x in nums):
        return sorted({x - 1 for x in nums if 1 <= x <= max_n})
    return sorted({x for x in nums if 0 <= x < max_n})


def _overlay_cell_numbers(grid_png: bytes, n: int) -> bytes:
    """Draw 1..N cell numbers on grid so VL can reference cells reliably."""
    img = Image.open(io.BytesIO(grid_png)).convert("RGB")
    draw = ImageDraw.Draw(img)
    W, H = img.size
    tw, th = W // n, H // n
    size = max(14, min(tw, th) // 4)
    try:
        font = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", size)
    except Exception:
        try:
            font = ImageFont.load_default()
        except Exception:
            font = None
    for r in range(n):
        for c in range(n):
            num = r * n + c + 1
            x0, y0 = c * tw, r * th
            label = str(num)
            pad = max(2, size // 6)
            if font is not None:
                try:
                    bbox = draw.textbbox((0, 0), label, font=font)
                    twt, tht = bbox[2] - bbox[0], bbox[3] - bbox[1]
                except Exception:
                    twt, tht = size, size
            else:
                twt, tht = size, size
            bx1, by1 = x0 + 2, y0 + 2
            bx2, by2 = bx1 + twt + pad * 2, by1 + tht + pad * 2
            draw.rectangle([bx1, by1, bx2, by2], fill=(0, 0, 0))
            draw.rectangle([bx1, by1, bx2, by2], outline=(255, 255, 0),
                           width=max(1, size // 12))
            draw.text((bx1 + pad, by1 + pad), label, fill=(255, 255, 0), font=font)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def _prompts(target: str, n: int) -> list[str]:
    max_n = n * n
    t = target
    return [
        (
            f"You are solving Google reCAPTCHA. Image is a {n}x{n} grid. "
            f"Yellow number badges label cells 1..{max_n} left-to-right, top-to-bottom. "
            f"Select EVERY cell that contains any part of: {t}. "
            f"Include cropped/partial edges of {t}. Exclude pure sky/road/empty. "
            f"If zero cells match, reply NONE. "
            f"Reply ONLY comma-separated cell numbers (example: 1,5,9) or NONE."
        ),
        (
            f"reCAPTCHA {n}x{n}. Cells numbered 1-{max_n}. "
            f"List all cells with {t} (full or partial). "
            f"Be thorough on edges/corners of objects. "
            f"Output format strictly: 2,3,7 or NONE. No words."
        ),
        (
            f"Grid {n}x{n}, badges 1..{max_n}. Target object class: '{t}'. "
            f"Return cells where the object appears even slightly. "
            f"Numbers only, comma-separated, or NONE."
        ),
    ]


async def _classify_grid_whole(bf, keypool, target: str, n: int,
                               grid_png: bytes, pass_idx: int = 0) -> list | None:
    labeled = _overlay_cell_numbers(grid_png, n)
    b64 = base64.b64encode(labeled).decode()
    prompts = _prompts(target, n)
    prompt = prompts[pass_idx % len(prompts)]
    try:
        text = await asyncio.to_thread(keypool.ask, b64, prompt)
    except Exception as e:
        log.warning("whole-grid ask p%d failed: %s", pass_idx, str(e).splitlines()[0])
        return None
    if not text:
        return None
    idxs = _parse_cell_indices(text, n)
    log.info("whole-grid p%d raw=%r -> %s", pass_idx, (text or "")[:140], idxs)
    return idxs


async def _classify_grid_tiles(bf, keypool, target: str, n: int,
                               img: Image.Image) -> list:
    W, H = img.size
    tw, th = W // n, H // n
    sem = asyncio.Semaphore(_CLASSIFY_CONCURRENCY)

    async def judge(idx, r, c):
        tile = img.crop((c * tw, r * th, (c + 1) * tw, (r + 1) * th))
        buf = io.BytesIO()
        tile.save(buf, "PNG")
        b64 = base64.b64encode(buf.getvalue()).decode()
        async with sem:
            yes = await asyncio.to_thread(keypool.classify, b64, target)
        return idx if yes else None

    tasks = [judge(r * n + c, r, c) for r in range(n) for c in range(n)]
    results = await asyncio.gather(*tasks)
    return [i for i in results if i is not None]


def _consensus(whole_a, whole_b, tiles, n: int) -> tuple[list, str]:
    """Merge dual whole-grid + tiles into final pick list.

    Bias: dual whole-grid agreement is stronger than per-tile yes/no.
    dual-intersect-tiles often under-selects (tiles miss partial objects).
    Prefer dual-inter when tiles cut more than half of dual agreement.
    """
    wholes = [w for w in (whole_a, whole_b) if w is not None]
    if len(wholes) == 2:
        whole_inter = sorted(set(wholes[0]) & set(wholes[1]))
        whole_union = sorted(set(wholes[0]) | set(wholes[1]))
    elif len(wholes) == 1:
        whole_inter = wholes[0]
        whole_union = wholes[0]
    else:
        whole_inter, whole_union = [], []

    tiles = tiles or []
    max_n = n * n

    if whole_a is not None and whole_b is not None:
        # dual both answered (possibly empty)
        if whole_inter:
            if tiles:
                hi = sorted(set(whole_inter) & set(tiles))
                # tiles exist: if whole is large, trust tiles more (VL over-selects)
                if tiles and len(whole_inter) >= max(4, max_n // 3):
                    if len(tiles) <= max_n // 2 + 1:
                        return tiles, "tiles-vs-large-whole"
                if hi and len(hi) >= max(1, (len(whole_inter) + 1) // 2):
                    return hi, "dual-and-tiles"
                # whole big, tiles smaller non-empty → tiles
                if tiles and len(tiles) < len(whole_inter) and len(tiles) <= max_n // 2:
                    return tiles, "tiles-smaller-than-whole"
            # prefer union when passes mostly agree but one adds partials
            if whole_union and len(whole_union) <= max_n // 2 + 1:
                if len(whole_union) - len(whole_inter) <= max(2, n // 2):
                    return whole_union, "dual-union-near"
            if len(whole_inter) <= max_n // 2 + 1:
                return whole_inter, "dual-inter"
            # whole_inter too large without tile support → drop to empty (better skip)
            if not tiles and len(whole_inter) > max_n // 2 + 1:
                return [], "whole-overselect-drop"
        elif whole_union and len(whole_union) <= max_n // 2:
            return whole_union, "dual-union-only"

    whole = whole_inter or whole_union
    if whole and tiles:
        inter = sorted(set(whole) & set(tiles))
        if inter and len(inter) >= max(1, (len(whole) + 1) // 2):
            return inter, "intersect"
        if len(whole) >= max_n - 1 and len(tiles) <= n:
            return tiles, "tiles-cap-whole"
        if len(tiles) >= max_n - 1 and len(whole) <= n:
            return whole, "whole-cap-tiles"
        if whole and len(whole) <= max_n // 2 + 2:
            return whole, "whole-prefer"
        if tiles:
            return tiles, "tiles-fallback"
        return whole, "whole-disagree"
    if whole:
        if len(whole) >= max_n - 1:
            return [], "whole-overselect-drop"
        return whole, "whole-only"
    if tiles:
        if len(tiles) >= max_n - 1:
            return [], "tiles-overselect-drop"
        return tiles, "tiles-only"
    return [], "empty"



def cv2_bgr_from_png(png: bytes):
    import numpy as np
    import cv2
    arr = np.frombuffer(png, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        # PIL fallback
        im = Image.open(io.BytesIO(png)).convert("RGB")
        return np.array(im)[:, :, ::-1].copy()
    return img

def _upscale_png(png: bytes, min_edge: int = 512) -> bytes:
    """Upscale grid for better VL accuracy (free models struggle on small grids)."""
    try:
        im = Image.open(io.BytesIO(png)).convert("RGB")
        w, h = im.size
        edge = min(w, h)
        if edge >= min_edge:
            return png
        scale = min_edge / max(1, edge)
        nw, nh = int(w * scale), int(h * scale)
        im = im.resize((nw, nh), Image.Resampling.LANCZOS)
        buf = io.BytesIO()
        im.save(buf, "PNG")
        return buf.getvalue()
    except Exception:
        return png


async def _classify_grid(bf, keypool, target: str, n: int) -> list:
    table = await bf.query_selector("table")
    if not table:
        return []
    grid_png = await table.screenshot()

    # --- YOLO for COCO-mapped targets (hybrid with VL, not sole authority) ---
    yolo_hits = None  # None=unmapped, list=mapped result (maybe empty)
    if get_yolo is not None and os.getenv("RC_YOLO", "1").strip() not in ("0", "false", "no"):
        try:
            bgr = cv2_bgr_from_png(grid_png)
            yolo = get_yolo()
            yolo_hits = yolo.tiles_combined(bgr, target, n)
            if yolo_hits is not None and yolo_hits:
                log.info("yolo-hits %r n=%d -> %s", target, n, yolo_hits)
            elif yolo_hits is not None and not yolo_hits:
                # v26: empty often = tiles not fully painted yet — one hard retry
                t_low = (target or "").lower()
                if any(k in t_low for k in (
                    "bus", "car", "bicycle", "bike", "motor", "hydrant", "truck",
                )):
                    import time as _t
                    await asyncio.sleep(1.2)
                    try:
                        table2 = await bf.query_selector("table")
                        if table2:
                            grid_png = await table2.screenshot()
                            bgr2 = cv2_bgr_from_png(grid_png)
                            y2 = yolo.tiles_combined(bgr2, target, n)
                            log.info("yolo-retry empty→%s target=%r", y2, target)
                            if not y2:
                                # last ditch: very low conf per-cell only
                                try:
                                    y2 = yolo.tiles_per_cell(bgr2, target, n, conf_tile=0.03) or []
                                    if y2:
                                        log.info("yolo-retry lowconf-per →%s target=%r", y2, target)
                                except Exception:
                                    y2 = y2 or []
                            if y2:
                                yolo_hits = y2
                                # keep fresher png for VL
                    except Exception as e2:
                        log.warning("yolo-retry: %s", str(e2).splitlines()[0])
        except Exception as e:
            log.warning("yolo path: %s", str(e).splitlines()[0])
            yolo_hits = None

    # Crosswalk heuristic when YOLO unmapped (None) or empty on crosswalk targets
    tnorm = (target or "").strip().lower()
    if ("crosswalk" in tnorm) and (yolo_hits is None or yolo_hits == []):
        try:
            from engines.rc.yolo_onnx import crosswalk_tiles
            bgr2 = cv2_bgr_from_png(grid_png)
            cw = crosswalk_tiles(bgr2, n)
            if cw:
                log.info("crosswalk-heuristic hits=%s", cw)
                yolo_hits = cw  # treat as mapped hits for fastpath/merge
        except Exception as e:
            log.warning("crosswalk heuristic: %s", str(e).splitlines()[0])

    # FAST PATH v20/v22: YOLO non-empty → skip VL for COCO-mapped.
    # v22: YOLO EMPTY on bus/car/bicycle → cheap 1-pass VL only (not 3+tiles).
    tnorm2 = (target or "").strip().lower()
    is_cross = "crosswalk" in tnorm2
    is_bus = any(k in tnorm2 for k in ("bus", "buses"))
    is_vehicle = any(k in tnorm2 for k in ("bus", "car", "truck", "bicycle", "motorcycle"))
    # v24: bicycle empty is dominant fail — force cheap VL even if YOLO mapped empty
    skip_vl = (
        yolo_hits is not None
        and bool(yolo_hits)
        and not is_cross
        and os.getenv("RC_YOLO_SKIP_VL", "1").strip() not in ("0", "false", "no")
        and len(yolo_hits) <= (n * n) // 2 + 2
    )
    if skip_vl:
        log.info("yolo-fastpath skip VL target=%r hits=%s", target, yolo_hits)
        return list(yolo_hits)
    if is_cross:
        log.info("crosswalk: VL path (no yolo-fastpath) heuristic=%s", yolo_hits)
    # flag for cheap VL
    is_bike = any(k in tnorm2 for k in ("bicycle", "bicycles", "bike"))
    is_bus_t = any(k in tnorm2 for k in ("bus", "buses"))
    is_car_t = any(k in tnorm2 for k in ("car", "cars", "truck"))
    # v27: ALL hard vehicles empty on 3x3 → FULL VL (cheap 1-pass was useless)
    full_vl_empty = (
        yolo_hits is not None
        and not yolo_hits
        and (is_bike or is_bus_t or is_car_t)
        and not is_cross
        and n == 3
    )
    cheap_vl = (
        yolo_hits is not None
        and not yolo_hits
        and is_vehicle
        and not is_cross
        and not full_vl_empty
        and n == 3
    )
    # v35speed: hard-cap VL path for free rate recovery.
    # RC_SPEED=1 → max 1 whole pass on vehicle-empty; skip per-tile except bicycle rescue.
    speed = os.getenv("RC_SPEED", "0").strip().lower() in ("1", "true", "yes", "on")
    if speed and (cheap_vl or full_vl_empty):
        # force single-pass whole VL budget; bicycle may still do one per-tile rescue below
        cheap_vl = True
        full_vl_empty = is_bike  # only bike keeps full_vl_empty branch for per-tile rescue
        log.info("v35speed vehicle-empty hard-cap VL target=%r bike=%s", target, is_bike)
    if cheap_vl:
        log.info("yolo-empty vehicle → cheap 1-pass VL target=%r", target)
    if full_vl_empty:
        log.info("yolo-empty hard-vehicle → FULL VL target=%r", target)

    grid_png_hi = _upscale_png(grid_png, 560)
    img = Image.open(io.BytesIO(grid_png_hi)).convert("RGB")
    grid_png = grid_png_hi  # use hi-res for VL too

    # VL path: unmapped targets, or YOLO empty/miss
    # v20: crosswalk → 1 whole pass only (3 passes × slow VL was killing budget)
    from collections import Counter
    wholes = []
    # v41: dynamic 3x3 crosswalk needs recall consensus. One-pass live miss
    # [2] from GT [0,2,5,8], then replacements ended in reject. Keep static
    # 4x4 crosswalk at one pass to control latency.
    n_passes = 2 if (is_cross and n == 3) else (1 if (is_cross or cheap_vl or full_vl_empty) else 2)
    for pi in range(n_passes):
        w = await _classify_grid_whole(bf, keypool, target, n, grid_png, pi)
        if w is not None:
            wholes.append(w)
    if len(wholes) >= 2:
        cnt = Counter()
        for w in wholes:
            cnt.update(set(w))  # set per pass so multi-count within pass ignored
        # majority: appear in >=2 passes; if all empty, empty
        maj = sorted(i for i, c in cnt.items() if c >= 2)
        if maj:
            whole_a, whole_b = maj, maj
        else:
            # no majority — use union of non-empty if small
            union = sorted(set().union(*wholes)) if wholes else []
            if union and len(union) <= (n * n) // 2 + 1:
                whole_a, whole_b = union, union
            else:
                whole_a = wholes[0]
                whole_b = wholes[1] if len(wholes) > 1 else wholes[0]
    elif len(wholes) == 1:
        whole_a, whole_b = wholes[0], wholes[0]
    else:
        whole_a, whole_b = None, None

    if is_cross or cheap_vl:
        tiles = []  # v20/v22: skip per-tile VL for crosswalk + cheap empty-vehicle
    elif full_vl_empty:
        # v42: bicycles are tiny in whole-grid. Latest honest dump GT [2,8]
        # produced YOLO=[] and whole-VL=NONE, so the old skip made recovery
        # impossible. Run one bounded per-tile rescue for bicycle only.
        if any(wholes) or is_bike:
            tiles = await _classify_grid_tiles(bf, keypool, target, n, img)
            if is_bike and not any(wholes):
                log.info("v42 bicycle hard-empty per-tile rescue -> %s", tiles)
        else:
            tiles = []
            log.info("v35 skip per-tile VL (wholes empty) target=%r", target)
    else:
        tiles = await _classify_grid_tiles(bf, keypool, target, n, img)

    chosen, mode = _consensus(whole_a, whole_b, tiles, n)

    # Merge YOLO if mapped
    # v20: YOLO-primary pure when hits. Crosswalk = VL only (heuristic only if VL empty).
    if is_cross:
        max_n = n * n
        lim = max_n // 3 + 2  # v26 slightly looser
        vl = list(chosen) if chosen else []
        cv = list(yolo_hits) if yolo_hits else []
        if vl and cv:
            uni = sorted(set(vl) | set(cv))
            if 0 < len(uni) <= lim + 1:
                log.info("crosswalk final %s mode=vl∪cv vl=%s cv=%s", uni, vl, cv)
                return uni
        if vl and 0 < len(vl) <= lim:
            log.info("crosswalk final %s mode=crosswalk-vl", vl)
            return vl
        if cv and 0 < len(cv) <= lim:
            log.info("crosswalk final heuristic-only %s", cv)
            return cv
        log.info("crosswalk final empty (vl=%s cv=%s)", vl, cv)
        return []
    if yolo_hits is not None:
        max_n = n * n
        if yolo_hits:
            if len(yolo_hits) <= max_n // 2 + 2:
                chosen, mode = yolo_hits, "yolo-primary"
            else:
                # absurdly large — keep VL if small, else empty
                if chosen and len(chosen) <= max_n // 2:
                    mode = mode + "+yolo-large-keep-vl"
                else:
                    chosen, mode = [], "yolo-too-large"
        elif not yolo_hits and chosen:
            # Mapped class but YOLO saw nothing. VL is noisy — trust small sets.
            # v22: allow up to 4 for vehicle empty (bus often 3 tiles)
            lim = 5 if (cheap_vl or is_bus or is_bike or is_bus_t or is_car_t) else 2
            if len(chosen) <= lim:
                mode = mode + "+yolo-empty-keep-tiny-vl"
            else:
                chosen, mode = [], "yolo-empty-drop-vl"
        else:
            chosen, mode = [], "yolo+vl-empty"

    # v40: stairs are an unmapped diagonal structure. VL commonly returns
    # three corners of a contiguous 2x2 footprint (observed [5,6,10], GT
    # [5,6,9,10]). Fill only the missing fourth corner; no broad expansion.
    if n == 4 and "stair" in tnorm2 and chosen:
        ss = set(chosen)
        added = []
        for rr in range(3):
            for cc in range(3):
                block = {rr * 4 + cc, rr * 4 + cc + 1,
                         (rr + 1) * 4 + cc, (rr + 1) * 4 + cc + 1}
                if len(ss & block) == 3:
                    miss = list(block - ss)[0]
                    ss.add(miss); added.append(miss)
        if added and len(ss) <= 6:
            chosen = sorted(ss)
            mode += "+v40-stairs-continuity"
            log.info("v40 stairs continuity +%s -> %s", sorted(set(added)), chosen)

    log.info("hybrid mode=%s wholes=%s tiles=%s yolo=%s -> %s",
             mode, wholes, tiles, yolo_hits, chosen)
    return chosen


async def _tiles(bf):
    return await bf.query_selector_all("td[role=button], .rc-imageselect-tile")


def _normalize_target(raw: str) -> str:
    t = (raw or "").strip()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"^(a|an|the)\s+", "", t, flags=re.I)
    t = re.split(r"[.\n]", t)[0].strip()
    # common reCAPTCHA instruction prefixes
    t = re.sub(
        r"^(select all (squares?|images?) (with|containing)\s+)+",
        "", t, flags=re.I).strip()
    return t or (raw or "").strip()


async def _error_banner(bf) -> bool:
    try:
        txt = (await bf.locator("body").inner_text(timeout=1500)).lower()
    except Exception:
        return False
    return any(s in txt for s in (
        "please try again", "try again", "incorrect", "select all matching",
    ))


async def run_image_challenge(page, keypool, max_rounds: int = _MAX_DYNAMIC_ROUNDS) -> bool:
    """Run the image challenge to a submit. Returns True if we pressed verify
    without an obvious error (caller confirms via token/checkbox)."""
    bf = await _find_bframe(page)
    if not bf:
        return False
    meta = await _challenge_meta(bf)
    if not meta.get("has_table") or not meta.get("target"):
        log.info("no image grid present")
        return False
    n = meta["rows"]
    if not n:
        await asyncio.sleep(1.5)
        meta = await _challenge_meta(bf)
        n = meta.get("rows") or 0
        if not n:
            log.warning("grid rows unreadable — skipping to avoid mis-slice")
            return False
    target = _normalize_target(meta.get("target") or "")
    log.info("image challenge v35: target=%r (raw=%r) grid=%dx%d dynamic=%s desc=%r",
             target, meta.get("target"), n, meta["cols"], meta["dynamic"],
             (meta.get("desc_full") or "")[:80])
    try:
        import time as _time
        dump = Path("/tmp/rc_challenge_dumps")
        dump.mkdir(parents=True, exist_ok=True)
        table0 = await bf.query_selector("table")
        if table0:
            # wait briefly for tile images
            try:
                # v26: wait for FULL grid images, not just 1 (partial load → YOLO empty)
                need = max(1, int(n) * int(n) if n else 1)
                await bf.wait_for_function(
                    """(need) => {
                      const imgs = document.querySelectorAll(
                        '.rc-image-tile-wrapper img, .rc-imageselect-tile img, table img');
                      if (!imgs.length) return false;
                      let ok=0;
                      for (const im of imgs) {
                        if (im.complete && im.naturalWidth > 20) ok++;
                      }
                      return ok >= Math.min(need, imgs.length) && ok >= Math.max(1, Math.floor(need * 0.8));
                    }""",
                    arg=need,
                    timeout=8000,
                )
            except Exception:
                await asyncio.sleep(1.5)
            png0 = await table0.screenshot()
            if png0 and len(png0) > 5000:
                (dump / f"ch_{int(_time.time())}_{n}x{n}_{target.replace(' ','_')[:30]}.png").write_bytes(png0)
    except Exception:
        pass

    # v39: v38 fixed source-change tracking. The old hard cap=4 now submits
    # while replacement positives are still present (observed cars/bus round 4),
    # guaranteeing an error banner. Continue bounded rounds until empty/unchanged.
    # v35speed: lower dynamic cap so empty/error fails fast instead of 12 VL rounds.
    _dyn_default = "6" if os.getenv("RC_SPEED", "0").strip().lower() in ("1", "true", "yes", "on") else "12"
    dyn_cap = int(os.getenv("RC_DYNAMIC_MAX_ROUNDS", _dyn_default))
    if os.getenv("RC_SPEED", "0").strip().lower() in ("1", "true", "yes", "on"):
        dyn_cap = min(dyn_cap, int(os.getenv("RC_SPEED_DYNAMIC_MAX", "6")))
        log.info("v35speed dynamic cap=%s", dyn_cap)
    rounds = min(max(4, dyn_cap), max(4, max_rounds, dyn_cap)) if meta["dynamic"] else 1
    clicked_any = False
    empty_streak = 0
    last_pos = None
    same_pos_streak = 0
    for rnd in range(rounds):
        positives = await _classify_grid(bf, keypool, target, n)
        # v35: no full re-classify second-chance (burned 360s budgets → 0% free)
        # one cheap YOLO retry only
        if (not positives) and n == 3:
            tlow = (target or "").lower()
            if any(k in tlow for k in (
                "bus", "car", "bicycle", "bike", "motor", "hydrant", "truck",
            )):
                await asyncio.sleep(0.8)
                bf = await _find_bframe(page) or bf
                try:
                    if get_yolo is not None:
                        table = await bf.query_selector("table")
                        if table:
                            png = await table.screenshot()
                            y2 = get_yolo().tiles_combined(cv2_bgr_from_png(png), target, n) or []
                            log.info("v35 second-chance YOLO-only %r →%s", target, y2)
                            if y2 and len(y2) <= (n * n) // 2 + 1:
                                positives = y2
                except Exception as e_sc:
                    log.warning("v35 second-chance: %s", str(e_sc).splitlines()[0])
        log.info("round %d/%d: %d/%d tiles match %r -> %s",
                 rnd + 1, rounds, len(positives), n * n, target, positives)
        # v38: same tile index across rounds is valid when Google replaced that
        # image with another positive. Source-change state below is authoritative.
        if positives and last_pos is not None and list(positives) == list(last_pos):
            same_pos_streak += 1
            log.info("v38 same positive indices %s x%d — defer to src-change",
                     positives, same_pos_streak + 1)
        else:
            same_pos_streak = 0
        last_pos = list(positives) if positives else last_pos
        if not positives:
            empty_streak += 1
            # v20: after ANY prior click, first empty → verify (none left). Don't wait 2x.
            if meta["dynamic"] and clicked_any:
                log.info("dynamic empty after prior clicks — treat as none-left")
                break
            # first round empty: one reload retry then verify/skip
            if meta["dynamic"] and empty_streak < 2 and rnd + 1 < rounds and not clicked_any:
                await asyncio.sleep(1.2)
                bf = await _find_bframe(page) or bf
                continue
            break
        empty_streak = 0
        tiles = await _tiles(bf)
        n_tiles = len(tiles) if tiles else 0
        if n_tiles == 0:
            # JS fallback query — Playwright handle list sometimes empty mid-reload
            try:
                n_tiles = await bf.evaluate(
                    """() => document.querySelectorAll(
                         'td[role=button], .rc-imageselect-tile').length""")
            except Exception:
                n_tiles = 0
            log.warning("playwright tiles empty; js count=%s positives=%s",
                        n_tiles, positives)

        # v38: snapshot dynamic image srcs BEFORE clicks. Previously this was
        # captured after clicking, so replacement images were compared to themselves
        # and valid same-index replacements looked stuck/unchanged.
        pre_srcs = []
        if meta["dynamic"]:
            try:
                pre_srcs = await bf.evaluate(
                    """() => Array.from(document.querySelectorAll(
                         '.rc-image-tile-wrapper img, .rc-imageselect-tile img'))
                         .map(im => im.src || im.getAttribute('src') || '')""")
            except Exception:
                pre_srcs = []

        clicked_this_round = 0
        for idx in positives:
            ok = False
            if tiles and idx < len(tiles):
                try:
                    await tiles[idx].click(timeout=3000, force=True)
                    ok = True
                except Exception as e:
                    log.warning("tile %d pw-click: %s", idx, str(e).splitlines()[0])
            if not ok:
                # JS click by index in bframe — more reliable than stale handles
                # Skip already-selected tiles (re-click would DESELECT).
                try:
                    js_ok = await bf.evaluate(
                        """(i) => {
                          const sels = document.querySelectorAll(
                            'td[role=button], .rc-imageselect-tile');
                          if (i < 0 || i >= sels.length) return false;
                          const el = sels[i];
                          const cls = (el.className || '') + ' ' +
                            ((el.querySelector && el.querySelector('.rc-imageselect-tile')) || el).className;
                          if (cls.includes('tileselected') || cls.includes('selected')) {
                            return 'already';
                          }
                          el.scrollIntoView({block:'center'});
                          el.click();
                          return true;
                        }""",
                        idx,
                    )
                    if js_ok == 'already':
                        log.info("tile %d already selected — skip re-click", idx)
                        js_ok = True  # count as success without toggle-off
                    ok = bool(js_ok)
                    if not ok:
                        log.warning("tile %d js-click miss (n=%s)", idx, n_tiles)
                except Exception as e:
                    log.warning("tile %d js-click: %s", idx, str(e).splitlines()[0])
            if ok:
                clicked_any = True
                clicked_this_round += 1
                await asyncio.sleep(0.18)
        log.info("clicked %d/%d positives this round (tiles=%s)",
                 clicked_this_round, len(positives), n_tiles)
        if not meta["dynamic"]:
            break
        # Dynamic: wait until clicked tile IMAGES actually swap (src change),
        # not just im.complete on the OLD image. pre_srcs was captured before click.
        await asyncio.sleep(0.8)
        try:
            await bf.wait_for_function(
                """(pre) => {
                  const imgs = Array.from(document.querySelectorAll(
                    '.rc-image-tile-wrapper img, .rc-imageselect-tile img'));
                  if (!imgs.length) return false;
                  let ready = 0, changed = 0;
                  for (let i = 0; i < imgs.length; i++) {
                    const im = imgs[i];
                    const src = im.src || im.getAttribute('src') || '';
                    if (im.complete && im.naturalWidth > 10) ready++;
                    if (pre && pre[i] !== undefined && src && src !== pre[i]) changed++;
                  }
                  // success if majority ready AND at least one src changed
                  // (or all ready after 1st paint when pre empty)
                  if (!pre || !pre.length) return ready >= imgs.length * 0.8;
                  return ready >= imgs.length * 0.8 && changed >= 1;
                }""",
                arg=pre_srcs,
                timeout=6000,
            )
        except Exception:
            log.warning("dynamic src-change wait timeout — tiles may not have swapped")
            await asyncio.sleep(2.0)
        # if src didn't change, break to verify rather than re-click same tiles
        try:
            post_srcs = await bf.evaluate(
                """() => Array.from(document.querySelectorAll(
                     '.rc-image-tile-wrapper img, .rc-imageselect-tile img'))
                     .map(im => im.src || im.getAttribute('src') || '')""")
            if pre_srcs and post_srcs and pre_srcs == post_srcs and clicked_this_round:
                log.info("dynamic images unchanged after click — verify")
                break
        except Exception:
            pass
        await asyncio.sleep(0.5)
        bf = await _find_bframe(page) or bf
        # re-read dynamic flag / target if challenge refreshed
        try:
            meta2 = await _challenge_meta(bf)
            if meta2.get("rows"):
                n = meta2["rows"]
            if meta2.get("target"):
                target = _normalize_target(meta2["target"]) or target
            meta["dynamic"] = meta2.get("dynamic", meta["dynamic"])
        except Exception:
            pass

    if not clicked_any:
        log.info("no tiles matched %r", target)

    # If instruction allows skip and we matched nothing, press SKIP not VERIFY
    allow_skip = False
    try:
        desc = (meta.get("desc_full") or "") + " " + (meta.get("target") or "")
        allow_skip = bool(re.search(
            r"if there are none|click skip|none, click skip", desc, re.I))
    except Exception:
        allow_skip = False

    # v21: empty + non-skip = we MISSED the objects. Don't verify empty (always error banner).
    if not clicked_any and not allow_skip:
        log.info("empty non-skip target=%r — fail grid without verify", target)
        return False

    clicked = False
    if not clicked_any and allow_skip:
        try:
            bf_s = await _find_bframe(page)
            if bf_s:
                skipped = await bf_s.evaluate("""() => {
                  const btns = Array.from(
                    document.querySelectorAll('button, .rc-button'));
                  for (const b of btns) {
                    const t = (b.innerText || b.value || '').toLowerCase();
                    if (t.includes('skip')) { b.click(); return 'skip-text'; }
                  }
                  const v = document.querySelector('#recaptcha-verify-button');
                  if (v) {
                    const t = (v.innerText || '').toLowerCase();
                    if (t.includes('skip')) { v.click(); return 'verify-as-skip'; }
                  }
                  return '';
                }""")
                if skipped:
                    log.info("pressed skip (%s) for empty match target=%r",
                             skipped, target)
                    clicked = True
                    await asyncio.sleep(3)
                    return True
        except Exception as e:
            log.warning("skip click: %s", str(e).splitlines()[0])

    try:
        loc = page.frame_locator(
            "iframe[title*='recaptcha challenge']").locator(_VERIFY)
        await loc.click(timeout=5000, force=True, no_wait_after=True)
        clicked = True
    except Exception as e:
        log.warning("verify click force: %s", str(e).splitlines()[0])
        try:
            bf2 = await _find_bframe(page)
            if bf2:
                await bf2.evaluate("""() => {
                      const b = document.querySelector('#recaptcha-verify-button');
                      if (b) b.click();
                    }""")
                clicked = True
        except Exception as e2:
            log.warning("verify js click: %s", str(e2).splitlines()[0])
    if not clicked:
        return False
    # poll up to ~6s for either error banner or challenge gone / checkbox checked
    for _pw in range(6):
        await asyncio.sleep(1.0)
        bf3 = await _find_bframe(page)
        if bf3 and await _error_banner(bf3):
            break
        # challenge table gone → likely accepted
        try:
            if bf3:
                has = await bf3.evaluate(
                    "() => !!document.querySelector('table.rc-imageselect-table')")
                if not has:
                    log.info("challenge table gone after verify — likely ok")
                    return True
        except Exception:
            pass
    # if error banner, soft-fail so caller can retry
    bf3 = await _find_bframe(page)
    if bf3 and await _error_banner(bf3):
        log.info("post-verify error banner — attempt likely rejected")
        try:
            import time as _time
            dump = Path("/tmp/rc_fail_dumps")
            dump.mkdir(parents=True, exist_ok=True)
            ts = int(_time.time())
            png = await bf3.screenshot()
            (dump / f"fail_{ts}_{target.replace(' ','_')[:40]}.png").write_bytes(png)
            log.info("dumped fail grid -> %s", dump)
        except Exception as e:
            log.debug("dump fail: %s", e)
        return False
    return True
