"""In-process runtime status per optional source (last success / last failure), shown by /api/health.

Only the outcome and a short error class are kept: never URLs, page content or API keys.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

SOURCES = ("redirects", "rdap", "tls", "whois_ae", "crtsh", "feeds", "gsb", "urlhaus", "urlscan", "sandbox", "virustotal")
_lock = threading.Lock()
_state: dict[str, dict] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def record(source: str, ok: bool, error: str | None = None) -> None:
    with _lock:
        st = _state.setdefault(source, {"ok": 0, "failed": 0, "last_ok": None, "last_error": None, "last_error_at": None,
                                        "last": None})
        if ok:
            st["ok"] += 1
            st["last_ok"] = _now()
            st["last"] = "ok"
        else:
            st["failed"] += 1
            st["last_error"] = (error or "error")[:200]
            st["last_error_at"] = _now()
            st["last"] = "failed"


def get(source: str) -> dict:
    with _lock:
        return dict(_state.get(source) or {"ok": 0, "failed": 0, "last_ok": None, "last_error": None,
                                           "last_error_at": None, "last": None})


def reset() -> None:
    with _lock:
        _state.clear()
