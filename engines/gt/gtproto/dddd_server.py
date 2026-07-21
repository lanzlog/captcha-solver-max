"""ddddocr wrappers for Geetest v4 icon challenges.

Vendored from xKiian/GeekedTest (MIT). Model paths fixed for package layout:
  engines/gt/gtproto/models/{geetest_v4_icon.onnx,charsets.json}
"""
from __future__ import annotations

import pathlib
import threading

_here = pathlib.Path(__file__).resolve().parent
onnx_path = str(_here / "models" / "geetest_v4_icon.onnx")
charsets_path = str(_here / "models" / "charsets.json")

_lock = threading.Lock()
_svc = None
_svc_err = None


class DdddService:
    def __init__(self):
        import ddddocr
        if not pathlib.Path(onnx_path).is_file():
            raise FileNotFoundError(f"geetest icon onnx missing: {onnx_path}")
        self.det = ddddocr.DdddOcr(det=True, show_ad=False)
        self.cnn = ddddocr.DdddOcr(
            det=False, ocr=False, show_ad=False,
            import_onnx_path=onnx_path,
            charsets_path=charsets_path,
        )

    def detection(self, img):
        return self.det.detection(img)

    def classification(self, img):
        return self.cnn.classification(img)


def _get() -> DdddService:
    global _svc, _svc_err
    if _svc is not None:
        return _svc
    if _svc_err is not None:
        raise RuntimeError(_svc_err)
    with _lock:
        if _svc is not None:
            return _svc
        try:
            _svc = DdddService()
            return _svc
        except Exception as e:
            _svc_err = str(e)
            raise


class _LazyProxy:
    def detection(self, img):
        return _get().detection(img)

    def classification(self, img):
        return _get().classification(img)


# icon.py does: from .dddd_server import dddd_service
dddd_service = _LazyProxy()
