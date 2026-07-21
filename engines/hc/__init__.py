"""hCaptcha solver package — checkbox and invisible modes."""
from .runner import (
    run_hc,
    run_hc_invisible,
    run_hc_realpage,
)

__all__ = [
    "run_hc",
    "run_hc_invisible",
    "run_hc_realpage",
]
