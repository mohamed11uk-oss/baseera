"""Shared plumbing for the optional key-gated sources (URLhaus, urlscan.io, VirusTotal).

Each source is off unless its SOURCE_* flag is on AND its key is set AND the app is in live mode.
Keys only go in request headers, never in URLs, logs, errors or /api/health output.
"""
from __future__ import annotations

from .cache import JsonCache


class KeyedSource:
    name = "source"          # status / cache name
    flag_env = "SOURCE_X"    # for human-readable status
    key_env = "X_API_KEY"
    ok_ttl_s = 3600.0

    def __init__(self, settings, key: str | None, flag: bool, client=None):
        self.settings = settings
        self.key = key
        self.flag = flag
        self._client = client  # injected httpx.Client (tests use MockTransport)
        self.cache = JsonCache(settings.cache_dir / f"{self.name}_cache.json" if client is None else None)
        self.last_error: str | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.key) and self.flag and not self.settings.offline

    def why_off(self) -> str | None:
        if not self.flag:
            return f"{self.flag_env}=off"
        if not self.key:
            return f"no {self.key_env}"
        if self.settings.offline:
            return "offline"
        return None

    def status(self) -> str:
        off = self.why_off()
        if off:
            return f"off ({off})"
        return "on" if not self.last_error else f"on (last error: {self.last_error})"

    def _request(self, method: str, url: str, **kw):
        """One HTTP call with the configured timeout. Raises on transport errors (callers fail soft)."""
        if self._client is not None:
            return self._client.request(method, url, timeout=self.settings.timeout_s, **kw)
        import httpx
        with httpx.Client(timeout=self.settings.timeout_s) as c:
            return c.request(method, url, **kw)

    def _fail(self, e: Exception) -> str:
        """Short, key-free error text."""
        self.last_error = str(e) if isinstance(e, RuntimeError) else type(e).__name__
        return self.last_error
