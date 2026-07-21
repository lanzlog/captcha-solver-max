"""Solve the hCaptcha IMAGE challenge with a vision model using numbered-grid classification.

hCaptcha renders images on a <canvas>. Instead of slicing the canvas into tiles and
classifying each tile individually (which fails on reasoning-style challenges like
"click the flower the bee never lands on"), we overlay a numbered grid on the full
canvas and ask the vision model: "which cell number?" This turns an expensive
grounding problem into a simple classification problem — the VLM chooses from N²
labels instead of guessing pixel coordinates, and it costs ONE API call per page
instead of 16.

Grid-overlay also enables drag challenges: ask for two cells (source, target) and
execute a programmatic drag via page.mouse.
"""
import asyncio
import base64
import io
import logging
import re

from PIL import Image, ImageDraw

log = logging.getLogger(__name__)

_GRID = 4  # default; runtime may switch to 3 when meta detects 3x3
_SKIP_SEL = ".button-submit"
_VERIFY_WORDS = ("verify", "verifizieren", "verificar", "vahvista", "확인", "验证")
_SKIP_WORDS = ("skip", "跳过", "huppel", "ohita", "überspringen", "überspringe", "passer")


# Challenge-detection JS. RAW string so \b / \n stay literal for JS
# (bare \b in a normal """ string becomes Python backspace 0x08).
_CHALLENGE_META_JS = r"""() => {
        const txt = document.body.innerText || '';
        const lines = txt.split('\n').map(l => l.trim()).filter(Boolean);
        const task = lines.find(l =>
            !l.includes('try again') && !l.match(/^(Skip|Verify|Next|EN|Please try again)$/i) && l.length > 5
        ) || '';
        // Extra context lines often hold the count / example ("Please click 3 images", icons row)
        const extras = lines.filter(l => l !== task && l.length > 1 && l.length < 80).slice(0, 6);
        const c = document.querySelector('canvas');
        const r = c ? c.getBoundingClientRect() : null;
        const hasDrag = /\bdrag\b/i.test(task) || /help the (creature|monkey|robot|character)/i.test(task)
            || /missing .+ piece|matching gap|drag .+ to|put the|place the/i.test(task);
        const btn = document.querySelector('.button-submit');
        // Detect img-tile layouts (some challenges use <img> grid, not canvas)
        const imgs = Array.from(document.querySelectorAll('.task-image img, .image, [class*="task"] img, .challenge-image, .task-grid .image'))
          .filter(el => el.width > 20 && el.height > 20);
        // Infer grid size: class hints, image count, or canvas aspect
        let grid = 4;
        const body = (document.body.className || '') + ' ' + (document.documentElement.innerHTML || '').slice(0, 4000);
        if (/3x3|grid-3|challenge-grid-3|task-grid-3/i.test(body)) grid = 3;
        else if (imgs.length === 9) grid = 3;
        else if (imgs.length === 16) grid = 4;
        else if (r && r.width > 0) {
          // many 3x3 challenges are squarer / smaller; leave 4 as default
          const area = r.width * r.height;
          if (imgs.length === 0 && area > 0 && area < 90000) grid = 3;
        }
        return {
            target: task,
            extras: extras,
            canvasRect: r ? {x: r.x, y: r.y, w: c.width, h: c.height, cssW: r.width, cssH: r.height} : null,
            isDrag: hasDrag,
            buttonText: btn ? btn.innerText.trim() : '',
            imgCount: imgs.length,
            bodyLen: txt.length,
            grid: grid,
        };
    }"""


async def _challenge_meta(fr) -> dict:
    """Extract challenge task text + detect layout."""
    return await fr.evaluate(_CHALLENGE_META_JS)


async def _wait_challenge_ready(fr, timeout_s: float = 8.0) -> dict:
    """Poll until canvas/images + task text are present (challenge paint is async)."""
    deadline = asyncio.get_event_loop().time() + timeout_s
    last = {}
    while asyncio.get_event_loop().time() < deadline:
        last = await _challenge_meta(fr)
        if last.get("target") and (last.get("canvasRect") or last.get("imgCount", 0) >= 4):
            # brief settle so canvas pixels are painted
            await asyncio.sleep(0.6)
            return await _challenge_meta(fr)
        await asyncio.sleep(0.4)
    return last


async def _get_canvas_b64(fr) -> str:
    """Get the full canvas as a base64-encoded PNG data URL."""
    return await fr.evaluate("""() => {
        const c = document.querySelector('canvas');
        if (!c) return '';
        try {
          // blank-guard: skip empty/transparent canvases
          const ctx = c.getContext('2d');
          if (ctx) {
            const d = ctx.getImageData(0, 0, Math.min(c.width, 8), Math.min(c.height, 8)).data;
            let sum = 0;
            for (let i = 0; i < d.length; i += 4) sum += d[i] + d[i+1] + d[i+2];
            if (sum < 10) return '';
          }
        } catch (e) {}
        return c.toDataURL('image/png').split(',')[1];
    }""")


async def _get_challenge_b64(fr, prefer_body: bool = False) -> str:
    """Canvas preferred (unless prefer_body); fall back to screenshot of frame body.

    Count/example-strip challenges need the full body so the VLM can see the
    icon strip above the grid — set prefer_body=True for those.
    """
    b64 = ""
    if not prefer_body:
        b64 = await _get_canvas_b64(fr)
        if b64 and len(b64) > 200:
            return b64
    try:
        # whole challenge view (includes prompt icons + grid)
        png = await fr.locator("body").screenshot(type="png")
        return base64.b64encode(png).decode()
    except Exception as e:
        log.warning("challenge screenshot failed: %s", str(e).splitlines()[0])
        if prefer_body and not b64:
            b64 = await _get_canvas_b64(fr)
        return b64 or ""


def _grid_overlay(b64: str, grid: int = _GRID) -> str:
    """Overlay a numbered grid on a base64 PNG, return base64 PNG.

    Each cell is labelled with its index (0..grid²-1) in a yellow box.
    Grid lines in red. Turns pixel-grounding into cell-classification.
    """
    img = Image.open(io.BytesIO(base64.b64decode(b64))).convert("RGB")
    w, h = img.size
    cw, ch = w // grid, h // grid
    draw = ImageDraw.Draw(img)
    n = 0
    for r in range(grid):
        for c in range(grid):
            x0, y0 = c * cw, r * ch
            draw.rectangle([x0, y0, x0 + cw, y0 + ch], outline="red", width=3)
            tx, ty = x0 + 6, y0 + 6
            draw.rectangle([tx - 2, ty - 2, tx + 38, ty + 26], fill="yellow")
            draw.text((tx, ty), str(n), fill="black")
            n += 1
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def _resolve_grid(meta: dict | None, default: int = _GRID) -> int:
    """Pick 3 or 4 from challenge meta; fall back to default."""
    try:
        g = int((meta or {}).get("grid") or default)
    except (TypeError, ValueError):
        g = default
    return 3 if g == 3 else 4


def _parse_cell_nums(text: str, grid: int) -> list[int]:
    N = grid * grid
    nums = []
    for m in re.finditer(r"\d+", text or ""):
        v = int(m.group())
        if 0 <= v < N:
            nums.append(v)
    seen = set()
    return [x for x in nums if not (x in seen or seen.add(x))]


def _is_countish(target: str, extras: list | None = None) -> bool:
    t = target or ""
    if re.search(
        r"\b(times|how many|number of|count|exactly|specified number|"
        r"please click \d+|select \d+|find all .+ icons)\b",
        t, re.I,
    ):
        return True
    return bool(re.search(r"\b\d+\b", " ".join(extras or [])))


def _build_pick_prompt(target: str, extras: list, grid: int, pass_n: int = 1) -> str:
    N = grid * grid
    extra = ""
    if extras:
        extra = " Extra UI text: " + " | ".join(extras[:5]) + "."
    countish = _is_countish(target, extras)
    if countish:
        count_hint = (
            " COUNTING challenge: look at the EXAMPLE ICON STRIP above the grid "
            "(small reference icons) AND any number in the prompt. "
            "A cell matches if it contains the same animal/object as those examples "
            "the required number of times. Pick EVERY matching cell. Do not under-pick. "
            "Ignore cells that only have unrelated icons."
        )
    else:
        count_hint = (
            " Prefer precision over recall: only pick cells that clearly match the task."
        )
    retry = ""
    if pass_n > 1:
        retry = (
            " Second pass: re-check every cell carefully, include borderline matches, "
            "and re-read the example icons at the top of the image."
        )
    return (
        f"This image has a {grid}x{grid} numbered grid (cells 0..{N - 1}, yellow label "
        f"top-left of each cell; red borders). Task: \"{target}\".{extra}{count_hint}{retry} "
        f"Reply ONLY the cell number(s) that satisfy the task, comma-separated "
        f"(e.g. `3` or `1,4,9`), or `none` if none match. No other words."
    )


async def _pick_cells(fr, keypool, target: str, grid: int = _GRID,
                      extras: list | None = None, passes: int = 2,
                      prefer_body: bool = False) -> list[int]:
    """Ask the vision model which numbered-grid cells satisfy *target*.

    Up to `passes` VLM calls. For count challenges: prefer the *first non-empty*
    pass (union of all passes over-picks badly). For simple tasks: early-exit on
    first non-empty, optional second pass only if first empty.
    """
    b64 = await _get_challenge_b64(fr, prefer_body=prefer_body)
    if not b64:
        return []
    gridded = _grid_overlay(b64, grid)
    countish = _is_countish(target, extras)
    first: list[int] = []
    second: list[int] = []
    for p in range(1, max(1, passes) + 1):
        prompt = _build_pick_prompt(target, extras or [], grid, pass_n=p)
        text = await asyncio.to_thread(keypool.ask, gridded, prompt)
        log.info("_pick_cells pass%d(%r) -> %s", p, target, (text or "")[:120])
        nums = _parse_cell_nums(text, grid)
        if p == 1:
            first = nums
            # simple tasks: one good pass is enough
            if first and not countish:
                return first
            # count: if first pass is reasonable (1..half grid), trust it
            if first and countish and 1 <= len(first) <= (grid * grid) // 2:
                return first
        else:
            second = nums
        if p < passes:
            await asyncio.sleep(0.3)

    if not first and not second:
        return []
    if not first:
        return second
    if not second:
        return first
    # both non-empty: prefer intersection if non-empty, else the smaller set
    inter = [x for x in first if x in set(second)]
    if inter:
        log.info("_pick_cells intersection first∩second -> %s", inter)
        return inter
    pick = first if len(first) <= len(second) else second
    log.info("_pick_cells prefer smaller set -> %s", pick)
    return pick


async def _classify_tiles(fr, keypool, target: str) -> list[int]:
    """DEPRECATED — use _pick_cells instead."""
    return await _pick_cells(fr, keypool, target)


async def _click_tiles(page, fr, indices: list[int], grid: int = _GRID) -> None:
    """Click matching tile positions on the canvas via page.mouse.

    page.mouse.click dispatches real OS-level events that hCaptcha respects.
    """
    cbox = await fr.locator("canvas").bounding_box()
    if not cbox:
        return
    tw = cbox["width"] / grid
    th = cbox["height"] / grid
    for idx in indices:
        col = idx % grid
        row = idx // grid
        x = cbox["x"] + (col + 0.5) * tw
        y = cbox["y"] + (row + 0.5) * th
        try:
            await page.mouse.click(x, y)
            await asyncio.sleep(0.35)
        except Exception as e:
            log.debug("tile %d click: %s", idx, str(e).splitlines()[0])


def _cell_center(cbox: dict, idx: int, grid: int = _GRID) -> tuple[float, float]:
    """Return (x, y) center pixel of cell `idx` within the canvas bounding box."""
    tw = cbox["width"] / grid
    th = cbox["height"] / grid
    col = idx % grid
    row = idx // grid
    return (cbox["x"] + (col + 0.5) * tw, cbox["y"] + (row + 0.5) * th)


async def _solve_drag(fr, page, keypool, grid: int = _GRID, target: str = "") -> bool:
    """Solve a drag challenge: identify source and target cells, then drag.

    Numbered-grid ask for TWO cells (source=grab, target=drop). Programmatic
    drag with ease-in-out steps + slight overshoot (more human-like).
    Best-effort — adversarial spiral/gap challenges may still fail.
    """
    b64 = await _get_challenge_b64(fr)
    if not b64:
        b64 = await _get_canvas_b64(fr)
    if not b64:
        return False
    gridded = _grid_overlay(b64, grid)
    task = (target or "drag the matching piece into the gap").strip()
    prompt = (
        f"This image has a {grid}x{grid} numbered grid (cells 0..{grid * grid - 1}, "
        f"yellow label top-left, red borders). Task: \"{task}\". "
        f"Identify which cell holds the piece to MOVE (source) and which cell is "
        f"the empty gap / destination (target). "
        f"Reply ONLY two numbers: `source,target` (e.g. `4,10`). No other words."
    )
    text = await asyncio.to_thread(keypool.ask, gridded, prompt)
    log.info("_solve_drag grid=%d -> %s", grid, (text or "")[:100])
    nums = _parse_cell_nums(text, grid)
    if len(nums) < 2:
        # retry once with canvas-only crop
        await asyncio.sleep(0.4)
        b64c = await _get_canvas_b64(fr)
        if b64c:
            gridded = _grid_overlay(b64c, grid)
            text = await asyncio.to_thread(keypool.ask, gridded, prompt)
            log.info("_solve_drag retry -> %s", (text or "")[:100])
            nums = _parse_cell_nums(text, grid)
    if len(nums) < 2:
        log.warning("_solve_drag: couldn't parse source/target from %r", (text or "")[:80])
        return False
    src, tgt = nums[0], nums[1]
    if src == tgt:
        log.warning("_solve_drag: source==target %d", src)
        return False
    cbox = await fr.locator("canvas").bounding_box()
    if not cbox:
        return False
    sx, sy = _cell_center(cbox, src, grid)
    tx, ty = _cell_center(cbox, tgt, grid)
    try:
        await page.mouse.move(sx, sy)
        await asyncio.sleep(0.15)
        await page.mouse.down()
        await asyncio.sleep(0.08)
        # ease-in-out steps + slight overshoot then settle
        steps = 16
        for i in range(1, steps + 1):
            t = i / steps
            # smoothstep
            e = t * t * (3 - 2 * t)
            # overshoot last 15%
            if t > 0.85:
                e = 1.0 + 0.06 * (1.0 - (1.0 - t) / 0.15)
            fx = sx + (tx - sx) * e
            fy = sy + (ty - sy) * e
            await page.mouse.move(fx, fy)
            await asyncio.sleep(0.03)
        # settle on true target
        await page.mouse.move(tx, ty)
        await asyncio.sleep(0.08)
        await page.mouse.up()
        await asyncio.sleep(1.0)
        log.info("_solve_drag: %d -> %d done", src, tgt)
        return True
    except Exception as e:
        log.warning("_solve_drag failed: %s", str(e).splitlines()[0])
        return False


async def _click_submit(fr) -> bool:
    """Click the submit button (Skip/Next/Verify). Returns True if clicked."""
    try:
        btn = await fr.query_selector(_SKIP_SEL)
        if btn:
            text = await btn.inner_text()
            log.info("submit button: %r", text)
            await btn.click(timeout=5000)
            await asyncio.sleep(2)
            return True
    except Exception as e:
        log.warning("submit click: %s", str(e).splitlines()[0])
    return False


async def run_hc_challenge(fr, page, keypool, max_pages: int = 6) -> bool:
    """Run the hCaptcha image challenge through all pages to completion.

    Returns True if Verify was pressed (caller checks for token).
    """
    meta = await _wait_challenge_ready(fr)
    if not meta.get("canvasRect") and meta.get("imgCount", 0) < 4:
        log.info("no challenge canvas/images found meta=%s",
                 {k: meta.get(k) for k in ("target", "imgCount", "bodyLen", "grid")})
        return False

    target0 = (meta.get("target") or "")
    grid = _resolve_grid(meta)
    # Detect drag even if meta flag lagged (task text is authoritative)
    is_drag = bool(meta.get("isDrag")) or bool(
        re.search(
            r"\bdrag\b|missing .+ piece|matching gap|drag .+ to|put the|place the",
            target0, re.I,
        )
    )
    if is_drag:
        log.warning("drag challenge — best-effort via grid=%d target=%r", grid, target0)
        solved = await _solve_drag(fr, page, keypool, grid=grid, target=target0)
        if solved:
            # Only click submit if button is Verify/Next (not Skip)
            try:
                meta_btn = await _challenge_meta(fr)
                btn = (meta_btn.get("buttonText") or "").lower()
            except Exception:
                btn = ""
            if btn in _VERIFY_WORDS or btn == "next":
                await _click_submit(fr)
            else:
                log.info("drag finished but button=%r — not clicking Skip", btn)
        else:
            # don't auto-Skip on failed drag (wastes the attempt); let caller retry
            log.info("drag unsolved — leaving challenge open for retry")
        return solved

    target = target0
    if not target:
        log.info("no challenge target found")
        return False

    log.info("challenge: target=%r extras=%s btn=%r grid=%d",
             target, meta.get("extras"), meta.get("buttonText"), grid)

    for page_num in range(1, max_pages + 1):
        fr = _find_challenge_frame(page)
        if not fr:
            log.warning("challenge frame lost")
            return False
        meta = await _wait_challenge_ready(fr, timeout_s=5.0)
        target = meta.get("target", "") or target
        extras = meta.get("extras") or []
        # filter noise extras (language / button labels / try-again banner)
        extras = [e for e in extras if not re.match(
            r"^(Skip|Verify|Next|EN|Please try again\.?\s*⚠️?)$", e or "", re.I
        )]
        btn_text = meta.get("buttonText", "")
        grid = _resolve_grid(meta, grid)
        has_canvas = bool(meta.get("canvasRect")) or (meta.get("imgCount") or 0) >= 4

        log.info("page %d/%d: target=%r extras=%s btn=%r grid=%d canvas=%s",
                 page_num, max_pages, target, extras, btn_text, grid, has_canvas)

        # No content left to pick — just click Verify if present
        if not has_canvas and (btn_text or "").lower() in _VERIFY_WORDS:
            log.info("no grid left, pressing Verify")
            await _click_submit(fr)
            return True

        # Classify tiles and click matches — ALWAYS pick when canvas+target exist,
        # even if the button already says Verify (last page still needs picks).
        positives: list[int] = []
        if target and has_canvas:
            countish = _is_countish(target, extras)
            positives = await _pick_cells(
                fr, keypool, target, grid=grid, extras=extras,
                passes=2, prefer_body=countish,
            )
            log.info("grid pick -> %s", positives)
            if not positives:
                await asyncio.sleep(1.0)
                positives = await _pick_cells(
                    fr, keypool, target, grid=grid, extras=extras,
                    passes=1, prefer_body=True,
                )
                log.info("grid pick retry -> %s", positives)
            if positives:
                await _click_tiles(page, fr, positives, grid=grid)
            elif countish:
                # empty pick on count challenge is almost always wrong — don't submit
                log.info("empty pick on count challenge — abort page (caller retries)")
                return False
        elif not target:
            log.info("no target text on this page — clicking first row as guess")
            await _click_tiles(page, fr, list(range(grid)), grid=grid)
            positives = list(range(grid))

        await asyncio.sleep(2)

        # Re-read button AFTER tile clicks — hCaptcha flips Skip → Next/Verify
        # when enough cells are selected.
        try:
            meta_now = await _challenge_meta(fr)
            btn_now = (meta_now.get("buttonText") or "").strip()
        except Exception:
            btn_now = btn_text
        log.info("post-pick button=%r (was %r)", btn_now, btn_text)

        btn_low = btn_now.lower()
        if not positives and btn_low in _SKIP_WORDS:
            log.info("empty pick + Skip button — not auto-skipping (would fail solve)")
            return False

        clicked = await _click_submit(fr)
        if not clicked:
            return False
        if btn_low in _SKIP_WORDS:
            return False  # truly skipped, not solved

        # After Verify click, we're done (success/fail decided by token mint)
        if btn_low in _VERIFY_WORDS:
            await asyncio.sleep(1.5)
            return True
        await asyncio.sleep(2)

    # After last page, check for "Verify" button
    fr = _find_challenge_frame(page)
    if fr:
        meta = await _challenge_meta(fr)
        log.info("final state: btn=%r", meta.get("buttonText"))
        btn_final = (meta.get("buttonText") or "").lower()
        if btn_final not in _SKIP_WORDS:
            await _click_submit(fr)

    return True


def _find_challenge_frame(page):
    """Return the hCaptcha challenge frame, or None."""
    for fr in page.frames:
        u = fr.url or ""
        if "#frame=challenge" in u and "hcaptcha" in u:
            return fr
    return None
