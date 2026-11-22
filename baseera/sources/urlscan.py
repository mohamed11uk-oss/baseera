"""urlscan.io Search API: read EXISTING scans of a host. Off unless SOURCE_URLSCAN=on and URLSCAN_API_KEY is set.

- GET https://urlscan.io/api/v1/search/?q=page.domain:"<host>"&size=10, header API-Key.
- Read-only: this module never submits a scan. If submission is ever added it MUST send
  "visibility": "unlisted" (SUBMIT_VISIBILITY) so a victim's link is not published on urlscan.io.
- Informational signal only (weight 0): urlscan results are other people's scans, not a verdict.
- Results cached 6h (errors not cached); never raises.
"""
from __future__ import annotations

import re

from .keyed import KeyedSource

SEARCH = "https://urlscan.io/api/v1/search/"
SUBMIT_VISIBILITY = "unlisted"  # the only visibility allowed if a submit call is ever added
HOST_RE = re.compile(r"^[a-z0-9.-]{1,253}$")


class URLscanClient(KeyedSource):
    name = "urlscan"
    flag_env = "SOURCE_URLSCAN"
    key_env = "URLSCAN_API_KEY"
    ok_ttl_s = 6 * 3600.0

    def __init__(self, settings, client=None):
        super().__init__(settings, settings.urlscan_api_key, settings.source_urlscan, client)

    def search_host(self, host: str) -> dict:
        """{'available', 'total', 'first_seen', 'last_seen', 'malicious', 'results': [...], 'error'?}."""
        if not self.enabled:
            return {"available": False, "error": self.status()}
        host = (host or "").lower()
        if not HOST_RE.match(host):  # normalized hosts are ASCII/punycode; anything else is not queried
            return {"available": False, "error": "urlscan: host not searchable"}
        hit = self.cache.get(host)
        if hit is not None:
            return hit
        try:
            r = self._request("GET", SEARCH, params={"q": f'page.domain:"{host}"', "size": 10},
                              headers={"API-Key": self.key or ""})
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}")
            j = r.json()
            rows = []
            for x in j.get("results") or []:
                task, page = x.get("task") or {}, x.get("page") or {}
                rid = str(x.get("_id") or "")
                rows.append({"time": task.get("time"), "url": page.get("url") or task.get("url"),
                             "visibility": task.get("visibility"),
                             "result_url": f"https://urlscan.io/result/{rid}/" if re.fullmatch(r"[0-9a-f-]{36}", rid) else None,
                             # verdicts shape on search results: VERIFY against current urlscan docs
                             "malicious": bool(((x.get("verdicts") or {}).get("overall") or {}).get("malicious"))})
            times = sorted(t for t in (r_["time"] for r_ in rows) if t)
            out = {"available": True, "total": int(j.get("total") or len(rows)), "results": rows,
                   "first_seen": times[0] if times else None, "last_seen": times[-1] if times else None,
                   "malicious": sum(r_["malicious"] for r_ in rows)}
            self.cache.put(host, out, self.ok_ttl_s)
            self.last_error = None
            return out
        except Exception as e:  # noqa: BLE001
            return {"available": False, "error": f"urlscan.io unavailable: {self._fail(e)}"}
