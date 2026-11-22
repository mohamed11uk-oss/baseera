"""Google Safe Browsing Lookup API v4 (threatMatches.find). Off unless GSB_API_KEY is set. Fails soft.

- batches up to 500 URLs per request
- caches matches for the cacheDuration returned by the API; negative results for NEGATIVE_TTL_S (VERIFY)
- persistent daily request counter with a hard stop at GSB_DAILY_LIMIT
- ATTRIBUTION / DISCLAIMER must be shown wherever a GSB result is displayed (CLAUDE.md rule 9)
"""
from __future__ import annotations

import re
import threading
from datetime import datetime, timezone

from .. import __version__
from .cache import JsonCache

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
BATCH = 500
NEGATIVE_TTL_S = 300  # API returns no cacheDuration for "no match"; short local cache (VERIFY against current docs)
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
ATTRIBUTION_EN = "Advisory provided by Google"
ATTRIBUTION_AR = "تنبيه مقدَّم من Google (Advisory provided by Google)"
ADVISORY_URL = "https://developers.google.com/safe-browsing/v4/advisory"
DISCLAIMER_EN = ("Google works to provide the most accurate and up-to-date information about unsafe web resources. "
                 "However, Google cannot guarantee that its information is comprehensive and error-free: some risky sites "
                 "may not be identified, and some safe sites may be identified in error.")
DISCLAIMER_AR = ("تعمل Google على توفير أدق المعلومات وأحدثها عن المواقع غير الآمنة، لكنها لا تضمن (not guaranteed) أن "
                 "تكون معلوماتها كاملة وخالية من الأخطاء: قد لا تُكتشف بعض المواقع الخطرة، وقد تُصنَّف مواقع آمنة بالخطأ.")
THREAT_AR = {"MALWARE": "برمجيات خبيثة (Malware)", "SOCIAL_ENGINEERING": "تصيّد/هندسة اجتماعية (Social engineering)",
             "UNWANTED_SOFTWARE": "برمجيات غير مرغوبة (Unwanted software)",
             "POTENTIALLY_HARMFUL_APPLICATION": "تطبيق قد يكون ضاراً (Potentially harmful application)"}


def notice() -> dict:
    return {"attribution_en": ATTRIBUTION_EN, "attribution_ar": ATTRIBUTION_AR, "advisory_url": ADVISORY_URL,
            "disclaimer_en": DISCLAIMER_EN, "disclaimer_ar": DISCLAIMER_AR}


def _duration_s(s) -> float:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)s", str(s or ""))
    return float(m.group(1)) if m else NEGATIVE_TTL_S


class GSBClient:
    def __init__(self, settings, client=None, today=None):
        self.settings = settings
        self.key = settings.gsb_api_key
        self._client = client
        self._today = today or (lambda: datetime.now(timezone.utc).date().isoformat())
        self.cache = JsonCache(settings.cache_dir / "gsb_cache.json" if client is None else None)
        self._lock = threading.Lock()
        self.last_error: str | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.key) and self.settings.source_gsb and not self.settings.offline

    def usage(self) -> dict:
        c = self.cache.raw("daily", {})
        n = c.get("requests", 0) if c.get("date") == self._today() else 0
        return {"date": self._today(), "requests": n, "limit": self.settings.gsb_daily_limit}

    def _count(self) -> bool:
        """Increment today's counter; False if the daily budget is exhausted."""
        with self._lock:
            u = self.usage()
            if u["requests"] >= u["limit"]:
                return False
            self.cache.set_raw("daily", {"date": u["date"], "requests": u["requests"] + 1})
            return True

    def status(self) -> dict:
        if not self.key:
            st = "off (no GSB_API_KEY)"
        elif not self.settings.source_gsb:
            st = "off (SOURCE_GSB=off)"
        elif self.settings.offline:
            st = "off (offline)"
        else:
            st = "on" if not self.last_error else f"on (last error: {self.last_error})"
        return {"status": st, "usage": self.usage(), **notice()}

    def check(self, urls: list[str]) -> dict:
        """{'available': bool, 'matches': {url: [threatType, ...]}, 'error'?: str}. Never raises."""
        if not self.enabled:
            return {"available": False, "matches": {}, "error": self.status()["status"]}
        matches: dict[str, list[str]] = {}
        todo = []
        for u in dict.fromkeys(urls):
            hit = self.cache.get(u)
            if hit is None:
                todo.append(u)
            elif hit:
                matches[u] = hit
        own = self._client is None
        client = self._client
        try:
            if todo and own:
                import httpx
                client = httpx.Client(timeout=self.settings.timeout_s)
            for i in range(0, len(todo), BATCH):
                chunk = todo[i:i + BATCH]
                if not self._count():
                    raise RuntimeError("daily GSB budget exhausted")
                body = {"client": {"clientId": "baseera", "clientVersion": __version__},
                        "threatInfo": {"threatTypes": THREAT_TYPES, "platformTypes": ["ANY_PLATFORM"],
                                       "threatEntryTypes": ["URL"], "threatEntries": [{"url": u} for u in chunk]}}
                r = client.post(ENDPOINT, params={"key": self.key}, json=body, timeout=self.settings.timeout_s)
                if r.status_code != 200:
                    raise RuntimeError(f"HTTP {r.status_code}")
                found: dict[str, tuple[list[str], float]] = {}
                for m in r.json().get("matches", []) or []:
                    u = (m.get("threat") or {}).get("url")
                    if u in chunk:
                        types, ttl = found.get(u, ([], 1e9))
                        types.append(str(m.get("threatType")))
                        found[u] = (types, min(ttl, _duration_s(m.get("cacheDuration"))))
                for u in chunk:
                    if u in found:
                        matches[u] = sorted(set(found[u][0]))
                        self.cache.put(u, matches[u], found[u][1])
                    else:
                        self.cache.put(u, [], NEGATIVE_TTL_S)
            self.last_error = None
            return {"available": True, "matches": matches}
        except Exception as e:  # noqa: BLE001 - never break /api/analyze (never log the key)
            self.last_error = str(e) if isinstance(e, RuntimeError) else type(e).__name__
            return {"available": False, "matches": matches, "error": f"Safe Browsing unavailable: {self.last_error}"}
        finally:
            if own and client is not None:
                client.close()
