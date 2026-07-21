#!/usr/bin/env python3
"""Local YOLO-ONNX detector for reCAPTCHA image grids (free, no VL).

Uses ultralytics-export YOLOv8n ONNX (COCO 80) via onnxruntime + opencv.
Maps COCO labels → reCAPTCHA target phrases (bus/bicycle/hydrant/...).

Public model: yolov8n.onnx (~12MB) from GitHub releases / mirror.
"""
from __future__ import annotations

import logging
import os
import urllib.request
from pathlib import Path

import cv2
import numpy as np

log = logging.getLogger(__name__)

# COCO 80 class names (YOLOv8 order)
_COCO = [
    "person", "bicycle", "car", "motorcycle", "airplane", "bus", "train",
    "truck", "boat", "traffic light", "fire hydrant", "stop sign",
    "parking meter", "bench", "bird", "cat", "dog", "horse", "sheep", "cow",
    "elephant", "bear", "zebra", "giraffe", "backpack", "umbrella", "handbag",
    "tie", "suitcase", "frisbee", "skis", "snowboard", "sports ball", "kite",
    "baseball bat", "baseball glove", "skateboard", "surfboard", "tennis racket",
    "bottle", "wine glass", "cup", "fork", "knife", "spoon", "bowl", "banana",
    "apple", "sandwich", "orange", "broccoli", "carrot", "hot dog", "pizza",
    "donut", "cake", "chair", "couch", "potted plant", "bed", "dining table",
    "toilet", "tv", "laptop", "mouse", "remote", "keyboard", "cell phone",
    "microwave", "oven", "toaster", "sink", "refrigerator", "book", "clock",
    "vase", "scissors", "teddy bear", "hair drier", "toothbrush",
]

# reCAPTCHA target phrase → set of COCO class names
_TARGET_MAP: dict[str, set[str]] = {
    "bus": {"bus"},  # truck handled as fallback in detect path
    "buses": {"bus"},
    "bicycle": {"bicycle"},
    "bicycles": {"bicycle"},
    "bike": {"bicycle"},
    "bikes": {"bicycle"},
    "motorcycle": {"motorcycle"},
    "motorcycles": {"motorcycle"},
    "motorbike": {"motorcycle"},
    "motorbikes": {"motorcycle"},
    "car": {"car"},
    "cars": {"car"},
    "truck": {"truck"},
    "trucks": {"truck"},
    "fire hydrant": {"fire hydrant"},
    "fire hydrants": {"fire hydrant"},
    "a fire hydrant": {"fire hydrant"},
    "traffic light": {"traffic light"},
    "traffic lights": {"traffic light"},
    "crosswalk": set(),  # no direct COCO — leave to VL
    "crosswalks": set(),
    "bridge": set(),
    "bridges": set(),
    "boat": {"boat"},
    "boats": {"boat"},
    "palm tree": {"potted plant"},  # weak
    "palm trees": {"potted plant"},
    "mountain": set(),
    "mountains": set(),
    "chimney": set(),
    "chimneys": set(),
    "stairs": set(),
    "stair": set(),
    "taxi": {"car"},
    "taxis": {"car"},
    "parking meter": {"parking meter"},
    "parking meters": {"parking meter"},
}

_MODEL_URLS = [
    # prefer s (better recall) then n
    "https://github.com/ultralytics/yolov5/releases/download/v7.0/yolov5s.onnx",
    "https://github.com/ultralytics/yolov5/releases/download/v7.0/yolov5n.onnx",
]

_DEFAULT_PATH = Path(os.getenv(
    "RC_YOLO_ONNX",
    str(Path(__file__).resolve().parent.parent.parent / "models" / "yolov5m.onnx"),
))


class YoloOnnx:
    def __init__(self, model_path: Path | None = None, conf: float = 0.18, iou: float = 0.45):
        self.model_path = Path(model_path or _DEFAULT_PATH)
        self.conf = float(os.getenv("RC_YOLO_CONF", conf if conf is not None else 0.18))
        self.iou = iou
        self._session = None
        self._input_name = None
        self._in_h = 640
        self._in_w = 640

    def ensure(self) -> bool:
        if self._session is not None:
            return True
        if not self.model_path.exists():
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            ok = False
            for url in _MODEL_URLS:
                try:
                    log.info("downloading YOLO onnx from %s", url)
                    urllib.request.urlretrieve(url, self.model_path)
                    if self.model_path.stat().st_size > 1_000_000:
                        ok = True
                        break
                except Exception as e:
                    log.warning("download fail %s: %s", url, e)
            if not ok:
                return False
        try:
            import onnxruntime as ort
            so = ort.SessionOptions()
            so.intra_op_num_threads = int(os.getenv("RC_YOLO_THREADS", "2"))
            self._session = ort.InferenceSession(
                str(self.model_path), sess_options=so,
                providers=["CPUExecutionProvider"],
            )
            inp = self._session.get_inputs()[0]
            self._input_name = inp.name
            shape = inp.shape  # [1,3,H,W] or dynamic
            if len(shape) == 4:
                if isinstance(shape[2], int) and shape[2] > 0:
                    self._in_h = int(shape[2])
                if isinstance(shape[3], int) and shape[3] > 0:
                    self._in_w = int(shape[3])
            log.info("YOLO onnx ready path=%s in=%dx%d", self.model_path, self._in_w, self._in_h)
            return True
        except Exception as e:
            log.warning("YOLO session fail: %s", e)
            self._session = None
            return False

    def _preprocess(self, bgr: np.ndarray):
        h0, w0 = bgr.shape[:2]
        # letterbox
        r = min(self._in_h / h0, self._in_w / w0)
        nh, nw = int(round(h0 * r)), int(round(w0 * r))
        resized = cv2.resize(bgr, (nw, nh), interpolation=cv2.INTER_LINEAR)
        canvas = np.full((self._in_h, self._in_w, 3), 114, dtype=np.uint8)
        top = (self._in_h - nh) // 2
        left = (self._in_w - nw) // 2
        canvas[top:top + nh, left:left + nw] = resized
        rgb = canvas[:, :, ::-1].astype(np.float32) / 255.0
        blob = np.transpose(rgb, (2, 0, 1))[None, ...]  # 1,3,H,W
        # some public onnx exports are fp16-only
        try:
            inp = self._session.get_inputs()[0]
            if "float16" in str(inp.type):
                blob = blob.astype(np.float16)
        except Exception:
            pass
        meta = {"r": r, "left": left, "top": top, "h0": h0, "w0": w0}
        return blob, meta

    def _nms(self, boxes, scores, idxs):
        if len(boxes) == 0:
            return []
        # cv2.dnn.NMSBoxes wants TLWH
        tlwh = [[b[0], b[1], b[2] - b[0], b[3] - b[1]] for b in boxes]
        pick = cv2.dnn.NMSBoxes(tlwh, scores, self.conf, self.iou)
        if pick is None or len(pick) == 0:
            return []
        flat = np.array(pick).reshape(-1).tolist()
        return flat

    def detect(self, bgr: np.ndarray) -> list[dict]:
        """Return list of {cls, name, conf, xyxy} in original image coords.

        Supports:
          - YOLOv5 onnx: (1, N, 85) = cx,cy,w,h,obj,80cls
          - YOLOv8 onnx: (1, 84, N) or (1, N, 84) = cx,cy,w,h,80cls (no obj)
        """
        if not self.ensure():
            return []
        blob, meta = self._preprocess(bgr)
        out = self._session.run(None, {self._input_name: blob})[0]
        pred = np.array(out)
        pred = np.squeeze(pred)
        if pred.ndim == 3:
            pred = pred[0]
        if pred.ndim != 2:
            return []
        # normalize to (N, C)
        if pred.shape[0] < pred.shape[1] and pred.shape[0] <= 85:
            pred = pred.T  # (C,N) -> (N,C)

        boxes, scores, cls_ids = [], [], []
        nc = pred.shape[1]
        has_obj = nc in (85, 6)  # 4+1+80 or toy
        for row in pred:
            if has_obj:
                obj = float(row[4])
                cls_scores = row[5:]
                if cls_scores.size == 0:
                    continue
                cid = int(np.argmax(cls_scores))
                sc = obj * float(cls_scores[cid])
            else:
                cls_scores = row[4:]
                if cls_scores.size == 0:
                    continue
                cid = int(np.argmax(cls_scores))
                sc = float(cls_scores[cid])
            if sc < self.conf:
                continue
            cx, cy, w, h = map(float, row[:4])
            x1, y1 = cx - w / 2, cy - h / 2
            x2, y2 = cx + w / 2, cy + h / 2
            x1 = (x1 - meta["left"]) / meta["r"]
            x2 = (x2 - meta["left"]) / meta["r"]
            y1 = (y1 - meta["top"]) / meta["r"]
            y2 = (y2 - meta["top"]) / meta["r"]
            x1 = max(0, min(meta["w0"] - 1, x1))
            x2 = max(0, min(meta["w0"] - 1, x2))
            y1 = max(0, min(meta["h0"] - 1, y1))
            y2 = max(0, min(meta["h0"] - 1, y2))
            if x2 <= x1 or y2 <= y1:
                continue
            boxes.append([x1, y1, x2, y2])
            scores.append(sc)
            cls_ids.append(cid)
        keep = self._nms(boxes, scores, cls_ids)
        dets = []
        for i in keep:
            cid = cls_ids[i]
            name = _COCO[cid] if 0 <= cid < len(_COCO) else str(cid)
            dets.append({
                "cls": cid, "name": name, "conf": scores[i],
                "xyxy": boxes[i],
            })
        return dets

    def tiles_for_target(self, bgr: np.ndarray, target: str, n: int,
                         min_overlap: float = 0.08) -> list[int] | None:
        """Return 0-based tile indices that contain target objects.

        Returns None if target has no COCO mapping (caller should use VL).
        Returns [] if mapping exists but nothing detected.
        """
        t = (target or "").strip().lower()
        t = " ".join(t.split())
        classes = _TARGET_MAP.get(t)
        if classes is None:
            # fuzzy contains
            classes = set()
            for k, v in _TARGET_MAP.items():
                if k in t or t in k:
                    classes |= v
        if not classes:
            return None  # unmapped → VL
        if not self.ensure():
            return None
        dets = self.detect(bgr)
        wanted = [d for d in dets if d["name"] in classes]
        # v25: bicycle ← motorcycle mislabel (4x4 static too)
        if "bicycle" in classes:
            motos = [d for d in dets if d["name"] == "motorcycle" and d["conf"] >= float(os.getenv("RC_YOLO_BIKE_MOTO_CONF", "0.18"))]
            if motos:
                log.info("yolo bike←moto whole n=%d", len(motos))
                wanted = list(wanted) + motos
        # bus: always merge truck (reCAPTCHA "bus" often truck-labeled); keep pure bus first
        if classes == {"bus"} or classes <= {"bus"}:
            trucks = [d for d in dets if d["name"] == "truck" and d["conf"] >= float(os.getenv("RC_YOLO_BUS_TRUCK_CONF", "0.28"))]
            if trucks:
                # prefer bus boxes; add trucks that don't heavily overlap existing bus
                if wanted:
                    log.info("yolo bus+truck merge bus=%d truck=%d", len(wanted), len(trucks))
                    wanted = list(wanted) + trucks
                else:
                    log.info("yolo bus←truck fallback n=%d", len(trucks))
                    wanted = trucks
            # large car boxes (school-bus / van mislabel): tall-wide vehicles
            if len(wanted) < 2:
                H0, W0 = bgr.shape[:2]
                img_area = float(H0 * W0)
                large_cars = []
                for d in dets:
                    if d["name"] != "car":
                        continue
                    x1, y1, x2, y2 = d["xyxy"]
                    bw, bh = max(1.0, x2 - x1), max(1.0, y2 - y1)
                    ar = bw / bh
                    area = bw * bh
                    # bus-like: wide-ish, decent size, conf not tiny
                    if d["conf"] >= float(os.getenv("RC_YOLO_BUS_CAR_CONF", "0.28")) and area / img_area >= 0.015 and 1.1 <= ar <= 5.0:
                        large_cars.append(d)
                if large_cars:
                    log.info("yolo bus←large-car n=%d", len(large_cars))
                    wanted = list(wanted) + large_cars
        # class conf floors — motorcycle boxes often bleed into person/road tiles
        # v19: lower moto floor (0.22) — 4x4 static under-selected at 0.28
        if classes <= {"motorcycle"} or classes == {"motorcycle"}:
            floor = float(os.getenv("RC_YOLO_MOTO_CONF", "0.22"))
            wanted = [d for d in wanted if d["conf"] >= floor]
            # v19c: 4x4 static scooter — expand moto box downward (fairing under body)
            # and only link person boxes that OVERLAP the moto (not floating head tiles).
            if n >= 4 and wanted and False:  # v20c disabled person-link; asymmetric expand below
                expanded = []
                for m in wanted:
                    x1, y1, x2, y2 = m["xyxy"]
                    bh = max(1.0, y2 - y1)
                    # push bottom 40% further down for underbody/fairing tiles
                    y2e = min(float(bgr.shape[0]), y2 + bh * 0.35)
                    y1e = max(0.0, y1 - bh * 0.35)  # up for handlebars/rider
                    mm = dict(m)
                    mm["xyxy"] = (x1, y1e, x2, y2e)
                    expanded.append(mm)
                wanted = expanded
                persons = [d for d in dets if d["name"] == "person" and d["conf"] >= 0.25]
                linked = []
                for p in persons:
                    px1, py1, px2, py2 = p["xyxy"]
                    pcx, pcy = (px1 + px2) / 2.0, (py1 + py2) / 2.0
                    for m in wanted:
                        mx1, my1, mx2, my2 = m["xyxy"]
                        mcx, mcy = (mx1 + mx2) / 2.0, (my1 + my2) / 2.0
                        ix1, iy1 = max(px1, mx1), max(py1, my1)
                        ix2, iy2 = min(px2, mx2), min(py2, my2)
                        inter = max(0.0, ix2 - ix1) * max(0.0, iy2 - iy1)
                        p_area = max(1.0, (px2 - px1) * (py2 - py1))
                        near = abs(pcx - mcx) < (mx2 - mx1) * 0.85 and pcy <= mcy + (my2 - my1) * 0.2
                        if inter / p_area >= 0.08 or near:
                            # keep lower 70% of person (torso/hands on bars), drop pure head
                            ph = py2 - py1
                            pp = dict(p)
                            pp["xyxy"] = (px1, py1 + ph * 0.25, px2, min(float(bgr.shape[0]), my2))
                            linked.append(pp)
                            break
                if linked:
                    log.info("yolo moto←rider-person n=%d", len(linked))
                    wanted = list(wanted) + linked
        if "traffic light" in classes:
            floor = float(os.getenv("RC_YOLO_TL_CONF", "0.15"))
            wanted = [d for d in wanted if d["conf"] >= floor]
        H, W = bgr.shape[:2]
        tw, th = W / n, H / n
        # Expand boxes slightly so partial objects near borders still hit neighbor tiles.
        expand = float(os.getenv("RC_YOLO_BOX_EXPAND", "0.08"))
        # class-specific expand
        if any(c in ("fire hydrant",) for c in classes):
            # v19: 4x4 static hydrant over-expanded (5 tiles for 1 hydrant) → tight
            if n >= 4:
                expand = float(os.getenv("RC_YOLO_EXPAND_HYDRANT_4", "0.02"))
            else:
                expand = float(os.getenv("RC_YOLO_EXPAND_HYDRANT", "0.10"))
        if any(c in ("motorcycle", "bicycle") for c in classes):
            # v19: 4x4 moto under-select → more expand; 3x3 dynamic keep tight
            if n >= 4:
                expand = float(os.getenv("RC_YOLO_EXPAND_MOTO_4", "0.14"))
            else:
                expand = float(os.getenv("RC_YOLO_EXPAND_MOTO", "0.04"))
        if "traffic light" in classes:
            expand = float(os.getenv("RC_YOLO_EXPAND_TL", "0.02" if n >= 4 else "0.08"))
        if classes == {"bus"} or classes <= {"bus"}:
            # v23: 3x3 independent photos — low expand (collage bleed was killing bus)
            if n >= 4:
                expand = float(os.getenv("RC_YOLO_EXPAND_BUS_4", "0.10"))
            else:
                expand = float(os.getenv("RC_YOLO_EXPAND_BUS", "0.02"))
        if classes == {"car"} or classes <= {"car"}:
            if n >= 4:
                expand = float(os.getenv("RC_YOLO_EXPAND_CAR_4", "0.06"))
            else:
                expand = float(os.getenv("RC_YOLO_EXPAND_CAR", "0.02"))
        hits = set()
        for d in wanted:
            x1, y1, x2, y2 = d["xyxy"]
            bw, bh = max(1.0, x2 - x1), max(1.0, y2 - y1)
            # expand from center
            cx, cy = (x1 + x2) / 2.0, (y1 + y2) / 2.0
            x1e = max(0.0, cx - bw * (0.5 + expand))
            x2e = min(float(W), cx + bw * (0.5 + expand))
            y1e = max(0.0, cy - bh * (0.5 + expand))
            y2e = min(float(H), cy + bh * (0.5 + expand))
            area = max(1.0, (x2e - x1e) * (y2e - y1e))
            # center tile always
            cr = min(n - 1, max(0, int(cy / th)))
            cc = min(n - 1, max(0, int(cx / tw)))
            hits.add(cr * n + cc)
            for r in range(n):
                for c in range(n):
                    tx1, ty1 = c * tw, r * th
                    tx2, ty2 = tx1 + tw, ty1 + th
                    ix1, iy1 = max(x1e, tx1), max(y1e, ty1)
                    ix2, iy2 = min(x2e, tx2), min(y2e, ty2)
                    iw, ih = max(0.0, ix2 - ix1), max(0.0, iy2 - iy1)
                    inter = iw * ih
                    tile_area = tw * th
                    if inter / area >= min_overlap or inter / tile_area >= min_overlap:
                        hits.add(r * n + c)
        # v20c moto 4x4: asymmetric expand on pure moto boxes only (no person).
        # v36rate offline GT tightened knobs (UP0.30/DOWN0.18/COV0.18/MAX6/EXP4 0.06) LIVE regressed 4/10->2/10; defaults restored to v35; use env override for research.
        if n >= 4 and any(c in ("motorcycle",) for c in classes) and wanted:
            pure = [d for d in wanted if d.get("name") == "motorcycle"] or wanted
            hits_m = set()
            up = float(os.getenv("RC_YOLO_MOTO_UP", "0.70"))
            down = float(os.getenv("RC_YOLO_MOTO_DOWN", "0.35"))
            side = float(os.getenv("RC_YOLO_MOTO_SIDE", "0.05"))
            cov = float(os.getenv("RC_YOLO_MOTO_TILE_COV", "0.12"))
            for d in pure:
                x1, y1, x2, y2 = d["xyxy"]
                bw, bh = max(1.0, x2 - x1), max(1.0, y2 - y1)
                x1e = max(0.0, x1 - bw * side)
                x2e = min(float(W), x2 + bw * side)
                y1e = max(0.0, y1 - bh * up)
                y2e = min(float(H), y2 + bh * down)
                cx, cy = (x1 + x2) / 2.0, (y1 + y2) / 2.0
                hits_m.add(min(n - 1, max(0, int(cy / th))) * n + min(n - 1, max(0, int(cx / tw))))
                for r in range(n):
                    for c in range(n):
                        tx1, ty1 = c * tw, r * th
                        tx2, ty2 = tx1 + tw, ty1 + th
                        ix1, iy1 = max(x1e, tx1), max(y1e, ty1)
                        ix2, iy2 = min(x2e, tx2), min(y2e, ty2)
                        inter = max(0.0, ix2 - ix1) * max(0.0, iy2 - iy1)
                        if inter / (tw * th) >= cov:
                            hits_m.add(r * n + c)
            if hits_m:
                # cap over-select: keep tiles with highest coverage of expanded moto box
                max_m = int(os.getenv("RC_YOLO_MOTO_MAX_TILES", "8"))
                if len(hits_m) > max_m:
                    scored = []
                    for idx in hits_m:
                        rr, cc = divmod(idx, n)
                        tx1, ty1 = cc * tw, rr * th
                        best = 0.0
                        for d in pure:
                            x1, y1, x2, y2 = d["xyxy"]
                            bw, bh = max(1.0, x2 - x1), max(1.0, y2 - y1)
                            x1e = max(0.0, x1 - bw * side); x2e = min(float(W), x2 + bw * side)
                            y1e = max(0.0, y1 - bh * up); y2e = min(float(H), y2 + bh * down)
                            inter = max(0.0, min(x2e, tx1 + tw) - max(x1e, tx1)) * max(0.0, min(y2e, ty1 + th) - max(y1e, ty1))
                            best = max(best, inter / (tw * th))
                        scored.append((best, idx))
                    scored.sort(reverse=True)
                    hits_m = set(i for _, i in scored[:max_m])
                log.info("yolo moto-4x4 asym %s -> %s", sorted(hits), sorted(hits_m))
                hits = hits_m
        # v21 traffic light 4x4: only tiles with substantial signal-head coverage
        # (tall thin boxes otherwise paint empty sky/pole tiles as hits)
        if n >= 4 and "traffic light" in classes and wanted:
            hits_tl = set()
            cov_tl = float(os.getenv("RC_YOLO_TL_TILE_COV", "0.20"))
            for d in wanted:
                x1, y1, x2, y2 = d["xyxy"]
                cx, cy = (x1 + x2) / 2.0, (y1 + y2) / 2.0
                hits_tl.add(min(n - 1, max(0, int(cy / th))) * n + min(n - 1, max(0, int(cx / tw))))
                for rr in range(n):
                    for cc in range(n):
                        tx1, ty1 = cc * tw, rr * th
                        tx2, ty2 = tx1 + tw, ty1 + th
                        inter = max(0.0, min(x2, tx2) - max(x1, tx1)) * max(0.0, min(y2, ty2) - max(y1, ty1))
                        if inter / (tw * th) >= cov_tl:
                            hits_tl.add(rr * n + cc)
            if hits_tl:
                log.info("yolo tl-4x4 trim %s -> %s", sorted(hits), sorted(hits_tl))
                hits = hits_tl
        # v19 hydrant 4x4: prefer center-in-tile + high inter/tile (avoid grass bleed)
        if n >= 4 and any(c in ("fire hydrant",) for c in classes) and wanted:
            hits_h = set()
            for d in wanted:
                x1, y1, x2, y2 = d["xyxy"]
                cx, cy = (x1 + x2) / 2.0, (y1 + y2) / 2.0
                cr = min(n - 1, max(0, int(cy / th)))
                cc = min(n - 1, max(0, int(cx / tw)))
                hits_h.add(cr * n + cc)
                for r in range(n):
                    for c in range(n):
                        tx1, ty1 = c * tw, r * th
                        tx2, ty2 = tx1 + tw, ty1 + th
                        ix1, iy1 = max(x1, tx1), max(y1, ty1)
                        ix2, iy2 = min(x2, tx2), min(y2, ty2)
                        iw, ih = max(0.0, ix2 - ix1), max(0.0, iy2 - iy1)
                        inter = iw * ih
                        tile_area = tw * th
                        # require substantial coverage of the TILE (hydrant body in cell)
                        if inter / tile_area >= float(os.getenv("RC_YOLO_HYDRANT_TILE_COV", "0.18")):
                            hits_h.add(r * n + c)
            if hits_h:
                log.info("yolo hydrant-4x4 trim %s -> %s", sorted(hits), sorted(hits_h))
                hits = hits_h
        # 4x4 over-select guard: if too many tiles, drop low-conf dets and recompute without expand
        # v20d: skip for motorcycle — asym expand intentionally spans ~7 tiles; generic trim
        # collapses back to body-only [8,9,10] and fails reCAPTCHA.
        if n >= 4 and len(hits) > max(8, n + 2) and not any(c in ("motorcycle",) for c in classes):
            strong = [d for d in wanted if d["conf"] >= max(0.25, self.conf + 0.08)]
            if strong:
                hits2 = set()
                for d in strong:
                    x1, y1, x2, y2 = d["xyxy"]
                    cx, cy = (x1 + x2) / 2.0, (y1 + y2) / 2.0
                    cr = min(n - 1, max(0, int(cy / th)))
                    cc = min(n - 1, max(0, int(cx / tw)))
                    hits2.add(cr * n + cc)
                    bw, bh = max(1.0, x2 - x1), max(1.0, y2 - y1)
                    area = bw * bh
                    for r in range(n):
                        for c in range(n):
                            tx1, ty1 = c * tw, r * th
                            tx2, ty2 = tx1 + tw, ty1 + th
                            ix1, iy1 = max(x1, tx1), max(y1, ty1)
                            ix2, iy2 = min(x2, tx2), min(y2, ty2)
                            iw, ih = max(0.0, ix2 - ix1), max(0.0, iy2 - iy1)
                            inter = iw * ih
                            if inter / area >= min_overlap or inter / (tw * th) >= min_overlap:
                                hits2.add(r * n + c)
                if hits2 and len(hits2) < len(hits):
                    log.info("yolo 4x4 overselect trim %s -> %s", sorted(hits), sorted(hits2))
                    hits = hits2
        log.info("yolo target=%r classes=%s dets=%d hits=%s expand=%.2f",
                 t, sorted(classes), len(wanted), sorted(hits), expand)
        return sorted(hits)


    def tiles_per_cell(self, bgr: np.ndarray, target: str, n: int,
                       conf_tile: float | None = None) -> list[int] | None:
        """Classify each grid cell independently (correct for 3x3 dynamic).

        Each reCAPTCHA dynamic tile is a separate photo, so whole-image boxes
        mis-attribute. Crop each cell → detect → hit if any wanted class.
        Returns None if target unmapped.
        """
        t = (target or "").strip().lower()
        t = " ".join(t.split())
        classes = _TARGET_MAP.get(t)
        if classes is None:
            classes = set()
            for k, v in _TARGET_MAP.items():
                if k in t or t in k:
                    classes |= v
        if not classes:
            return None
        if not self.ensure():
            return None
        H, W = bgr.shape[:2]
        tw, th = W // n, H // n
        # slight inset to avoid grid borders
        inset = max(1, min(tw, th) // 20)
        old_conf = self.conf
        if conf_tile is not None:
            self.conf = conf_tile
        hits = []
        try:
            for r in range(n):
                for c in range(n):
                    x1 = c * tw + inset
                    y1 = r * th + inset
                    x2 = (c + 1) * tw - inset
                    y2 = (r + 1) * th - inset
                    if x2 <= x1 or y2 <= y1:
                        continue
                    crop = bgr[y1:y2, x1:x2]
                    if crop.size == 0:
                        continue
                    # upscale crops — YOLOv5n/s weak on ~100px reCAPTCHA tiles
                    ch, cw = crop.shape[:2]
                    min_edge = int(os.getenv("RC_YOLO_CROP_EDGE", "416"))
                    if min(ch, cw) < min_edge:
                        scale = min_edge / max(1, min(ch, cw))
                        crop = cv2.resize(
                            crop,
                            (int(cw * scale), int(ch * scale)),
                            interpolation=cv2.INTER_CUBIC,
                        )
                    dets = self.detect(crop)
                    ok = any(d["name"] in classes for d in dets)
                    # v25: bicycle often labeled motorcycle
                    if not ok and ("bicycle" in classes):
                        ok = any(
                            d["name"] == "motorcycle" and d["conf"] >= float(os.getenv("RC_YOLO_BIKE_MOTO_CONF", "0.18"))
                            for d in dets
                        )
                    # bus per-cell: truck counts; large car weak signal
                    if not ok and (classes == {"bus"} or classes <= {"bus"}):
                        ok = any(
                            (d["name"] == "truck" and d["conf"] >= 0.15)
                            or (d["name"] == "car" and d["conf"] >= 0.22)
                            or (d["name"] == "bus" and d["conf"] >= 0.10)
                            for d in dets
                        )
                    if ok:
                        hits.append(r * n + c)
        finally:
            self.conf = old_conf
        log.info("yolo-per-cell target=%r n=%d hits=%s", t, n, hits)
        return hits


    def tiles_center_only(self, bgr: np.ndarray, target: str, n: int) -> list[int] | None:
        """Map detections to tiles by box CENTER only (no expand / overlap bleed).

        Correct for 3x3 dynamic collages of independent photos: a bus fully
        inside one cell must not mark neighbors. Returns None if unmapped.
        """
        t = (target or "").strip().lower()
        t = " ".join(t.split())
        classes = _TARGET_MAP.get(t)
        if classes is None:
            classes = set()
            for k, v in _TARGET_MAP.items():
                if k in t or t in k:
                    classes |= v
        if not classes:
            return None
        if not self.ensure():
            return None
        dets = self.detect(bgr)
        wanted = [d for d in dets if d["name"] in classes]
        # v25: bicycle ← motorcycle mislabel
        if "bicycle" in classes:
            motos = [d for d in dets if d["name"] == "motorcycle" and d["conf"] >= float(os.getenv("RC_YOLO_BIKE_MOTO_CONF", "0.18"))]
            if motos:
                log.info("yolo bike←moto n=%d", len(motos))
                wanted = list(wanted) + motos
        # bus aliases — same as tiles_for_target but no expand
        if classes == {"bus"} or classes <= {"bus"}:
            trucks = [d for d in dets if d["name"] == "truck" and d["conf"] >= float(os.getenv("RC_YOLO_BUS_TRUCK_CONF", "0.25"))]
            if trucks:
                wanted = list(wanted) + trucks
            if len(wanted) < 2:
                H0, W0 = bgr.shape[:2]
                img_area = float(H0 * W0)
                for d in dets:
                    if d["name"] != "car":
                        continue
                    x1, y1, x2, y2 = d["xyxy"]
                    bw, bh = max(1.0, x2 - x1), max(1.0, y2 - y1)
                    ar = bw / bh
                    area = bw * bh
                    if d["conf"] >= float(os.getenv("RC_YOLO_BUS_CAR_CONF", "0.25")) and area / img_area >= 0.012 and 1.1 <= ar <= 5.0:
                        wanted.append(d)
        if classes <= {"motorcycle"} or classes == {"motorcycle"}:
            floor = float(os.getenv("RC_YOLO_MOTO_CONF", "0.22"))
            wanted = [d for d in wanted if d["conf"] >= floor]
        if "traffic light" in classes:
            floor = float(os.getenv("RC_YOLO_TL_CONF", "0.15"))
            wanted = [d for d in wanted if d["conf"] >= floor]
        H, W = bgr.shape[:2]
        tw, th = W / n, H / n
        hits = set()
        for d in wanted:
            x1, y1, x2, y2 = d["xyxy"]
            cx, cy = (x1 + x2) / 2.0, (y1 + y2) / 2.0
            # reject tiny boxes that are noise
            bw, bh = max(1.0, x2 - x1), max(1.0, y2 - y1)
            if (bw * bh) / float(H * W) < float(os.getenv("RC_YOLO_CENTER_MIN_AREA", "0.002")):
                continue
            cr = min(n - 1, max(0, int(cy / th)))
            cc = min(n - 1, max(0, int(cx / tw)))
            hits.add(cr * n + cc)
        hits_l = sorted(hits)
        log.info("yolo-center-only target=%r n=%d hits=%s dets=%d", t, n, hits_l, len(wanted))
        return hits_l

    def tiles_combined(self, bgr: np.ndarray, target: str, n: int) -> list[int] | None:
        """Grid-aware YOLO tile pick (v27).

        - 4x4 static: WHOLE-image box→tile (expand OK).
        - 3x3 dynamic independent photos:
            * bus: center-primary; if empty → whole high-overlap (0.20)
            * fire hydrant: whole∪per
            * car: center∪per; whole only if both are empty
            * bicycle: center∪per + person-assist
            * motorcycle: center∪per
            * other: center then per
        """
        t = (target or "").strip().lower()
        t = " ".join(t.split())
        classes = _TARGET_MAP.get(t)
        if classes is None:
            classes = set()
            for k, v in _TARGET_MAP.items():
                if k in t or t in k:
                    classes |= v
        if not classes:
            return None

        if n >= 4:
            # v45: bus lower-edge bleed at overlap .05 selected [4,8,12]
            # while honest GT was [4,8]. Offline sweep: .08-.30 all exact.
            ov_default = "0.08" if (classes == {"bus"} or classes <= {"bus"}) else "0.05"
            ov_key = "RC_YOLO_MIN_OVERLAP_BUS_4" if (classes == {"bus"} or classes <= {"bus"}) else "RC_YOLO_MIN_OVERLAP"
            whole = self.tiles_for_target(
                bgr, target, n,
                min_overlap=float(os.getenv(ov_key, ov_default)),
            )
            if whole is None:
                return None
            log.info("yolo-combined 4x4 whole-only target=%r -> %s", target, whole)
            return whole

        is_bus = classes == {"bus"} or classes <= {"bus"}
        is_hydrant = "fire hydrant" in classes
        is_car = "car" in classes and not is_bus
        is_bike = "bicycle" in classes
        is_moto = "motorcycle" in classes and not is_bike

        if is_hydrant:
            whole = self.tiles_for_target(
                bgr, target, n,
                min_overlap=float(os.getenv("RC_YOLO_MIN_OVERLAP_HYDRANT_3", "0.08")),
            ) or []
            per = self.tiles_per_cell(
                bgr, target, n,
                conf_tile=float(os.getenv("RC_YOLO_TILE_CONF", "0.08")),
            ) or []
            hits = sorted(set(whole) | set(per))
            log.info("yolo-combined 3x3 hydrant whole∪per target=%r whole=%s per=%s -> %s",
                     target, whole, per, hits)
            return hits

        if is_bus:
            center = self.tiles_center_only(bgr, target, n) or []
            if center:
                log.info("yolo-combined 3x3 bus center-primary target=%r -> %s", target, center)
                return center
            per = self.tiles_per_cell(
                bgr, target, n,
                conf_tile=float(os.getenv("RC_YOLO_TILE_CONF", "0.08")),
            ) or []
            max_per = int(os.getenv("RC_YOLO_BUS_PER_MAX_3", "4"))
            if per and len(per) <= max_per:
                log.info("yolo-combined 3x3 bus per-fallback target=%r per=%s", target, per)
                return per
            if len(per) > max_per:
                log.info("v37 reject noisy bus per-fallback target=%r per=%s max=%d",
                         target, per, max_per)
            # high-overlap whole (less bleed than expand)
            whole = self.tiles_for_target(
                bgr, target, n,
                min_overlap=float(os.getenv("RC_YOLO_MIN_OVERLAP_BUS_3", "0.20")),
            ) or []
            log.info("yolo-combined 3x3 bus whole-hi-ov target=%r whole=%s", target, whole)
            return whole

        if is_car or is_bike or is_moto:
            conf_p = float(os.getenv("RC_YOLO_TILE_CONF_CAR", "0.05"))
            center = self.tiles_center_only(bgr, target, n) or []
            per = self.tiles_per_cell(bgr, target, n, conf_tile=conf_p) or []
            # v46 offline gate: when broad bicycle center is noisy, a strict
            # non-empty per-cell subset improves precision without recall loss.
            if is_bike and len(center) > 3 and per and set(per) < set(center):
                log.info("v46 bicycle noisy-center trim center=%s per=%s", center, per)
                center = per
            # v44: bicycle center-primary. Offline honest dumps:
            # GT/pred center: [3,6,8]/exact, [0,6,8]/exact,
            # [2,3]/[2,3,4]. Union-per added two more FPs (5,7)
            # without recovering any TP. Keep per only as center-empty fallback.
            hits = set(center if (is_bike and center) else (center + per))
            if is_bike and center:
                log.info("v44 bicycle center-primary center=%s per=%s", center, per)
            if is_car and not hits:
                whole = self.tiles_for_target(
                    bgr, target, n,
                    min_overlap=float(os.getenv("RC_YOLO_MIN_OVERLAP_CAR_3", "0.15")),
                ) or []
                hits = set(whole)
                log.info("v37 car whole fallback center/per empty -> %s", whole)
            if is_bike and not center and len(hits) < 2:
                extra = self._bike_person_assist(bgr, n, conf_p)
                if extra:
                    hits |= set(extra)
                    log.info("yolo bike←person-assist +%s", extra)
            hits_l = sorted(hits)
            log.info("yolo-combined 3x3 car/bike/moto target=%r center=%s per=%s -> %s",
                     target, center, per, hits_l)
            return hits_l

        center = self.tiles_center_only(bgr, target, n)
        if center is None:
            return None
        if center:
            log.info("yolo-combined 3x3 center-primary target=%r -> %s", target, center)
            return center
        per = self.tiles_per_cell(
            bgr, target, n,
            conf_tile=float(os.getenv("RC_YOLO_TILE_CONF", "0.08")),
        ) or []
        log.info("yolo-combined 3x3 center-empty per-fallback target=%r per=%s",
                 target, per)
        return per

    def _bike_person_assist(self, bgr: np.ndarray, n: int, conf_tile: float) -> list[int]:
        """Per-cell: bicycle OR (person + motorcycle low) as bicycle signal."""
        if not self.ensure():
            return []
        H, W = bgr.shape[:2]
        tw, th = W // n, H // n
        inset = max(1, min(tw, th) // 20)
        old = self.conf
        self.conf = conf_tile
        hits = []
        try:
            for r in range(n):
                for c in range(n):
                    x1 = c * tw + inset
                    y1 = r * th + inset
                    x2 = (c + 1) * tw - inset
                    y2 = (r + 1) * th - inset
                    if x2 <= x1 or y2 <= y1:
                        continue
                    crop = bgr[y1:y2, x1:x2]
                    if crop.size == 0:
                        continue
                    ch, cw = crop.shape[:2]
                    min_edge = int(os.getenv("RC_YOLO_CROP_EDGE", "416"))
                    if min(ch, cw) < min_edge:
                        scale = min_edge / max(1, min(ch, cw))
                        crop = cv2.resize(crop, (int(cw * scale), int(ch * scale)),
                                          interpolation=cv2.INTER_CUBIC)
                    dets = self.detect(crop)
                    names = {d["name"] for d in dets}
                    if "bicycle" in names:
                        hits.append(r * n + c)
                        continue
                    # person riding often labels motorcycle/person not bicycle
                    has_person = any(d["name"] == "person" and d["conf"] >= 0.20 for d in dets)
                    has_moto = any(d["name"] == "motorcycle" and d["conf"] >= 0.15 for d in dets)
                    if has_person and has_moto:
                        hits.append(r * n + c)
        finally:
            self.conf = old
        return hits


_GLOBAL: YoloOnnx | None = None


def get_yolo() -> YoloOnnx:
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = YoloOnnx(conf=float(os.getenv("RC_YOLO_CONF", "0.18")))
    return _GLOBAL


def yolo_status() -> dict:
    y = get_yolo()
    ok = y.ensure()
    return {
        "ready": ok,
        "path": str(y.model_path),
        "size": y.model_path.stat().st_size if y.model_path.exists() else 0,
        "conf": y.conf,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(yolo_status())
    y = get_yolo()
    # synthetic: green rect as "object" — just ensure detect runs
    img = np.zeros((400, 400, 3), dtype=np.uint8)
    img[:] = (180, 180, 180)
    cv2.rectangle(img, (50, 50), (200, 300), (0, 0, 255), -1)
    print("dets", y.detect(img)[:5])


def crosswalk_tiles(bgr: np.ndarray, n: int) -> list[int]:
    """Zebra/crosswalk tiles via white-stripe PERIODICITY (v19).

    v17 white+edge energy was fooled by white cars / overpass concrete.
    v19: require horizontal projection with multiple peaks (stripe bars).
    If no strong periodic tiles → return [] so VL path runs (don't fastpath junk).
    """
    if bgr is None or bgr.size == 0 or n < 2:
        return []
    H, W = bgr.shape[:2]
    tw, th = W // n, H // n
    scores = []
    for r in range(n):
        for c in range(n):
            x1, y1 = c * tw, r * th
            crop = bgr[y1:y1 + th, x1:x1 + tw]
            if crop.size == 0:
                scores.append(0.0)
                continue
            gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
            # focus on bright road paint
            mask = (gray > 160).astype(np.uint8) * 255
            # row-mean of bright pixels → stripe projection
            proj = mask.mean(axis=1).astype(np.float32) / 255.0  # length th
            if proj.size < 8:
                scores.append(0.0)
                continue
            # smooth
            k = max(3, th // 20 | 1)
            ker = np.ones(k, dtype=np.float32) / k
            sm = np.convolve(proj, ker, mode="same")
            # peaks: local maxima above mean
            thr_p = float(sm.mean() + 0.08)
            peaks = 0
            for i in range(2, len(sm) - 2):
                if sm[i] >= thr_p and sm[i] >= sm[i - 1] and sm[i] >= sm[i + 1]:
                    if sm[i] - sm[i - 2] > 0.03 and sm[i] - sm[i + 2] > 0.03:
                        peaks += 1
            white = float(np.mean(gray > 170))
            # horizontal edge energy
            edges = cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3)
            e_h = float(np.mean(np.abs(edges)) / 255.0)
            edges_v = cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3)
            e_v = float(np.mean(np.abs(edges_v)) / 255.0)
            # v26: periodicity gate peaks>=2 (was 3; missed partial zebra)
            if peaks < 2:
                score = 0.0
            else:
                score = (
                    min(peaks, 8) / 8.0 * 0.50
                    + white * 0.20
                    + e_h * 0.20
                    + max(0.0, e_h - e_v) * 0.15
                )
            scores.append(score)
    if not scores:
        return []
    arr = np.array(scores, dtype=np.float32)
    # strict: only clear periodic stripes
    thr = max(0.22, float(np.median(arr) + 0.10), float(arr.max() * 0.55) if arr.max() > 0 else 1.0)
    hits = [i for i, s in enumerate(scores) if s >= thr and s > 0.25]
    if len(hits) > max(1, (n * n) // 3):
        order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        hits = sorted(order[: max(1, (n * n) // 4)])
    log.info("crosswalk-v19 n=%d thr=%.3f hits=%s scores=%s",
             n, thr, hits, [round(s, 3) for s in scores])
    # if weak/empty → [] so VL handles (critical: don't fastpath wrong tiles)
    return hits
