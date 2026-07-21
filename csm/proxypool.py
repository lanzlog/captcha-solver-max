"""Proxy pool — round-robin rotation over a proxy list file.

Reads a proxy file (one proxy per line) and hands out proxies round-robin so
successive browser-based solves exit from different residential IPs. This keeps
Cloudflare/Turnstile from fingerprinting a single exit IP across many solves.

Supported line formats (auto-detected):
  - host:port:user:pass            (OwlProxy "Extract Lines" format)
  - user:pass@host:port
  - http://user:pass@host:port
  - host:port                      (no auth)

All are normalized to a full URL: http://user:pass@host:port

Env:
  SOLVER_PROXY_FILE   path to the proxy list (default: ~/proxies.txt)
  SOLVER_PROXY_SCHEME url scheme to emit (default: http)

Thread-safe. Sync + stdlib only.
"""
import itertools
import logging
import os
import threading
from pathlib import Path

log = logging.getLogger("proxypool")

_DEFAULT_SCHEME = os.getenv("SOLVER_PROXY_SCHEME", "http")


def _normalize(line: str, scheme: str = _DEFAULT_SCHEME) -> str | None:
    """Normalize a proxy line to `scheme://user:pass@host:port` (or None if junk)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # already a URL
    if "://" in line:
        return line
    # user:pass@host:port
    if "@" in line:
        return f"{scheme}://{line}"
    parts = line.split(":")
    if len(parts) == 4:
        host, port, user, pw = parts
        return f"{scheme}://{user}:{pw}@{host}:{port}"
    if len(parts) == 2:
        host, port = parts
        return f"{scheme}://{host}:{port}"
    log.warning("unparseable proxy line: %r", line[:40])
    return None


class ProxyPool:
    """Round-robin + sticky-session proxy pool loaded from a file."""

    def __init__(self, path: str, scheme: str = _DEFAULT_SCHEME):
        self.path = Path(path).expanduser()
        self.scheme = scheme
        self._lock = threading.Lock()
        self.proxies: list[str] = []
        self._cursor = None
        # sticky: session_key -> proxy URL (cf_clearance / multi-step flows)
        self._sticky: dict[str, str] = {}
        self.reload()

    def reload(self) -> int:
        """(Re)load proxies from the file. Returns count loaded."""
        if not self.path.exists():
            log.warning("proxy file not found: %s", self.path)
            with self._lock:
                self.proxies = []
                self._cursor = itertools.cycle([None])
                self._sticky.clear()
            return 0
        raw = self.path.read_text().splitlines()
        proxies = []
        seen = set()
        for line in raw:
            norm = _normalize(line, self.scheme)
            if norm and norm not in seen:
                seen.add(norm)
                proxies.append(norm)
        with self._lock:
            self.proxies = proxies
            self._cursor = itertools.cycle(proxies) if proxies else itertools.cycle([None])
            # drop sticky entries whose proxy left the file
            alive = set(proxies)
            self._sticky = {k: v for k, v in self._sticky.items() if v in alive}
        log.info("proxy pool loaded: %d proxies from %s", len(proxies), self.path)
        return len(proxies)

    def next(self) -> str | None:
        """Get the next proxy URL round-robin. None if pool empty."""
        with self._lock:
            if not self.proxies:
                return None
            return next(self._cursor)

    def sticky(self, session_key: str) -> str | None:
        """Same session_key → same proxy for the life of this process.

        Use for IP-bound cookies (cf_clearance) and multi-step flows that must
        exit from one residential IP. Key is opaque (url host, client id, …).
        First call pins a round-robin pick; later calls reuse it.
        """
        if not session_key:
            return self.next()
        with self._lock:
            if not self.proxies:
                return None
            hit = self._sticky.get(session_key)
            if hit is not None:
                return hit
            pick = next(self._cursor)
            self._sticky[session_key] = pick
            return pick

    def release_sticky(self, session_key: str) -> None:
        """Forget a sticky pin (e.g. after failed solve / explicit rotate)."""
        with self._lock:
            self._sticky.pop(session_key, None)

    def __len__(self) -> int:
        return len(self.proxies)

    def stats(self) -> dict:
        with self._lock:
            return {
                "count": len(self.proxies),
                "sticky_sessions": len(self._sticky),
                "path": str(self.path),
            }


# ── module-level singleton, lazily initialized ──────────────────────
_pool: ProxyPool | None = None
_pool_lock = threading.Lock()


def get_pool() -> ProxyPool:
    """Return the shared pool, initializing from SOLVER_PROXY_FILE on first use."""
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                path = os.getenv("SOLVER_PROXY_FILE", str(Path.home() / "proxies.txt"))
                _pool = ProxyPool(path)
    return _pool


def next_proxy() -> str | None:
    """Convenience: next proxy from the shared pool, or None if disabled/empty."""
    if os.getenv("SOLVER_PROXY_ROTATE", "0") != "1":
        return None
    return get_pool().next()


def sticky_proxy(session_key: str) -> str | None:
    """Sticky proxy for session_key when rotation is enabled; else None."""
    if os.getenv("SOLVER_PROXY_ROTATE", "0") != "1":
        return None
    return get_pool().sticky(session_key)


def proxy_stats() -> dict:
    """Pool size / sticky count for /health (no secrets)."""
    try:
        return get_pool().stats()
    except Exception as e:
        return {"count": 0, "error": str(e)[:80]}
