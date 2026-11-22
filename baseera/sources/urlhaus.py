"""abuse.ch URLhaus lookup (malware-distribution URLs). Off unless SOURCE_URLHAUS=on and URLHAUS_AUTH_KEY is set.

- POST https://urlhaus-api.abuse.ch/v1/url/  (form: url=...)   exact URL lookup
- POST https://urlhaus-api.abuse.ch/v1/host/ (form: host=...)  host lookup (skipped for shared platforms)
- Auth-Key header from env; results cached 1h (errors are not cached); never raises.
Response fields used: query_status, url_status, threat, tags, date_added, urlhaus_reference, url_count, urls[].
"""
from __future__ import annotations

from .keyed import KeyedSource

API = "https://urlhaus-api.abuse.ch/v1/"


class URLhausClient(KeyedSource):
    name = "urlhaus"
    flag_env = "SOURCE_URLHAUS"
    key_env = "URLHAUS_AUTH_KEY"

    def __init__(self, settings, client=None):
        super().__init__(settings, settings.urlhaus_auth_key, settings.source_urlhaus, client)

    def _post(self, kind: str, value: str) -> dict:
        ck = f"{kind}:{value}"
        hit = self.cache.get(ck)
        if hit is not None:
            return hit
        r = self._request("POST", API + kind + "/", data={kind: value}, headers={"Auth-Key": self.key or ""})
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        j = r.json()
        qs = j.get("query_status")
        if qs not in ("ok", "no_results"):
            raise RuntimeError(f"query_status {str(qs)[:40]}")
        self.cache.put(ck, j, self.ok_ttl_s)
        return j

    def lookup(self, url: str, host: str | None) -> dict:
        """{'available', 'url_hit': dict|None, 'host_hit': dict|None, 'error'?}. host=None skips the host lookup."""
        if not self.enabled:
            return {"available": False, "url_hit": None, "host_hit": None, "error": self.status()}
        try:
            u = self._post("url", url)
            url_hit = None
            if u.get("query_status") == "ok":
                url_hit = {k: u.get(k) for k in ("url", "url_status", "threat", "tags", "date_added", "urlhaus_reference")}
            host_hit = None
            if host and not url_hit:
                h = self._post("host", host)
                urls = h.get("urls") or []
                if h.get("query_status") == "ok" and (urls or int(h.get("url_count") or 0) > 0):
                    host_hit = {"host": host, "url_count": int(h.get("url_count") or len(urls)),
                                "online": sum(1 for x in urls if x.get("url_status") == "online"),
                                "firstseen": h.get("firstseen"), "urlhaus_reference": h.get("urlhaus_reference"),
                                "threats": sorted({str(x.get("threat")) for x in urls if x.get("threat")})}
            self.last_error = None
            return {"available": True, "url_hit": url_hit, "host_hit": host_hit}
        except Exception as e:  # noqa: BLE001 - never break /api/analyze (and never echo the key)
            return {"available": False, "url_hit": None, "host_hit": None,
                    "error": f"URLhaus unavailable: {self._fail(e)}"}
