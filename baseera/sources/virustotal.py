"""VirusTotal v3 URL report: MANUAL 'deep check' only (POST /api/deep-check/virustotal), never in /api/analyze.

- Off unless SOURCE_VT=on and VT_API_KEY is set (header x-apikey).
- GET https://www.virustotal.com/api/v3/urls/<base64url(url) without padding> reads the existing report.
  404 = VirusTotal has no report (found=false). Baseera never submits URLs to VirusTotal (no POST /urls).
- Free public API allows 4 requests/minute: in-process sliding-window limiter (VT_PER_MINUTE, default 4).
  Cache hits do not count. Reports cached 1h. Never raises.
- The result is shown next to the verdict, it does NOT change the score.
"""
from __future__ import annotations

import base64
import collections
import re
import threading
import time
from datetime import datetime, timezone

from .keyed import KeyedSource

API = "https://www.virustotal.com/api/v3/urls/"


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class RateLimiter:
    """At most `n` calls per `window_s` seconds (sliding window)."""

    def __init__(self, n: int, window_s: float = 60.0, clock=time.monotonic):
        self.n, self.window_s, self.clock = n, window_s, clock
        self._calls: collections.deque[float] = collections.deque()
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """0.0 if the call may go ahead (and is counted), else seconds to wait."""
        with self._lock:
            now = self.clock()
            while self._calls and now - self._calls[0] >= self.window_s:
                self._calls.popleft()
            if len(self._calls) >= self.n:
                return round(self.window_s - (now - self._calls[0]), 1)
            self._calls.append(now)
            return 0.0


class VTClient(KeyedSource):
    name = "virustotal"
    flag_env = "SOURCE_VT"
    key_env = "VT_API_KEY"

    def __init__(self, settings, client=None, clock=time.monotonic):
        super().__init__(settings, settings.vt_api_key, settings.source_vt, client)
        self.limiter = RateLimiter(settings.vt_per_minute, 60.0, clock)

    def report(self, url: str) -> dict:
        """{'available', 'found', 'stats', 'malicious', 'suspicious', 'engines', 'last_analysis_date', 'permalink',
        'error'?, 'retry_after_s'?}."""
        if not self.enabled:
            return {"available": False, "error": self.status()}
        hit = self.cache.get(url)
        if hit is not None:
            return {**hit, "cached": True}
        wait = self.limiter.acquire()
        if wait > 0:
            return {"available": False, "error": f"VirusTotal rate limit ({self.settings.vt_per_minute}/min): "
                                                 f"retry in {wait:.0f}s", "retry_after_s": wait}
        try:
            r = self._request("GET", API + url_id(url), headers={"x-apikey": self.key or ""})
            if r.status_code == 404:
                out = {"available": True, "found": False}
            elif r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}")
            else:
                d = r.json().get("data") or {}
                a = d.get("attributes") or {}
                stats = {k: int(v) for k, v in (a.get("last_analysis_stats") or {}).items() if isinstance(v, int)}
                ts = a.get("last_analysis_date")
                rid = str(d.get("id") or "")
                out = {"available": True, "found": True, "stats": stats,
                       "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                       "engines": sum(stats.values()),
                       "last_analysis_date": datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")
                       if isinstance(ts, (int, float)) else None,
                       "permalink": f"https://www.virustotal.com/gui/url/{rid}" if re.fullmatch(r"[0-9a-f]{64}", rid)
                       else None}
            self.cache.put(url, out, self.ok_ttl_s)
            self.last_error = None
            return out
        except Exception as e:  # noqa: BLE001
            return {"available": False, "error": f"VirusTotal unavailable: {self._fail(e)}"}


def summary(res: dict) -> tuple[str, str]:
    """(Arabic, English) one-liners for the UI, built only from the report numbers."""
    if not res.get("available"):
        return (f"فحص VirusTotal غير متاح الحين ({res.get('error', '')})", f"VirusTotal check unavailable: {res.get('error', '')}")
    if not res.get("found"):
        return ("ما عند VirusTotal تقرير سابق لهالرابط، وهذا ما يعني إنه آمن",
                "VirusTotal has no existing report for this URL (not a sign of safety)")
    m, s, n = res.get("malicious", 0), res.get("suspicious", 0), res.get("engines", 0)
    return (f"{m} من {n} محرك فحص (engines) في VirusTotal صنّفوا الرابط خبيث، و{s} مشبوه",
            f"{m}/{n} VirusTotal engines flag this URL as malicious, {s} as suspicious")
