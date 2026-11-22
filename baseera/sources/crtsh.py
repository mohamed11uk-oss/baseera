"""crt.sh certificate-transparency lookup: first-seen certificate date, issuer, SAN count, issued in last 7 days.

crt.sh is a free community service and is often overloaded: 6s timeout, 2 retries with backoff, 24h cache,
fail soft ({"available": False, "error": ...}). Used as a documented domain-age PROXY when RDAP/WHOIS have no
creation date (a domain is at least as old as its first logged certificate; it may be much older).
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from .cache import JsonCache

CRTSH_URL = "https://crt.sh/"
TTL_OK = 86400
TTL_FAIL = 900  # do not hammer an overloaded service: remember failures for 15 min
_caches: dict[str, JsonCache] = {}


def _cache(settings) -> JsonCache:
    key = str(settings.cache_dir)
    if key not in _caches:
        _caches[key] = JsonCache(settings.cache_dir / "crtsh_cache.json")
    return _caches[key]


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def summarize(rows: list, now: datetime | None = None) -> dict:
    """Reduce crt.sh JSON rows to the fields we use. Rows are UNTRUSTED data: only known keys are read."""
    now = now or datetime.now(timezone.utc)
    certs: dict = {}
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        nb = _dt(r.get("not_before")) or _dt(r.get("entry_timestamp"))
        if not nb:
            continue
        cid = r.get("id") or r.get("min_cert_id") or (r.get("serial_number"), r.get("not_before"))
        c = certs.setdefault(str(cid), {"not_before": nb, "issuer": r.get("issuer_name"), "names": set()})
        for name in str(r.get("name_value") or "").split("\n"):
            if name.strip():
                c["names"].add(name.strip().lower())
        cn = r.get("common_name")
        if isinstance(cn, str) and cn.strip():
            c["names"].add(cn.strip().lower())
    if not certs:
        return {"available": False, "error": "no certificates logged in crt.sh"}
    first = min(certs.values(), key=lambda c: c["not_before"])
    latest = max(certs.values(), key=lambda c: c["not_before"])
    return {
        "available": True,
        "first_seen": first["not_before"].isoformat(),
        "latest_not_before": latest["not_before"].isoformat(),
        "issuer": _short_issuer(latest["issuer"]),
        "san_count": len(latest["names"]),
        "cert_count": len(certs),
        "issued_last_7d": latest["not_before"] >= now - timedelta(days=7),
    }


def _short_issuer(dn) -> str | None:
    """'C=US, O=Let's Encrypt, CN=R3' -> "Let's Encrypt" (falls back to the full DN)."""
    if not isinstance(dn, str):
        return None
    parts = dict(p.strip().split("=", 1) for p in dn.split(",") if "=" in p)
    return (parts.get("O") or parts.get("CN") or dn)[:120]


def lookup(domain: str, settings, client=None, sleep=time.sleep) -> dict:
    """Never raises. `client` (httpx.Client) and `sleep` are injectable for offline tests."""
    domain = domain.lower().strip(".")
    c = _cache(settings)
    hit = c.get(domain)
    if hit is not None:
        return {**hit, "cached": True}
    own = client is None
    err = "unknown"
    try:
        if own:
            import httpx
            client = httpx.Client(timeout=settings.crtsh_timeout_s, headers={"User-Agent": "baseera/0.1"})
        for attempt in range(settings.crtsh_retries + 1):
            if attempt:
                sleep(0.5 * 2 ** (attempt - 1))  # 0.5s, 1s
            try:
                r = client.get(CRTSH_URL, params={"q": domain, "output": "json"}, timeout=settings.crtsh_timeout_s)
            except Exception as e:  # noqa: BLE001
                err = f"crt.sh unavailable: {type(e).__name__}"
                continue
            if r.status_code != 200:
                err = f"crt.sh HTTP {r.status_code}"
                if r.status_code < 500 and r.status_code != 429:
                    break
                continue
            try:
                out = summarize(r.json())
            except ValueError:
                err = "crt.sh returned invalid JSON"
                continue
            c.put(domain, out, TTL_OK)
            return out
    except Exception as e:  # noqa: BLE001
        err = f"crt.sh unavailable: {type(e).__name__}"
    finally:
        if own and client is not None:
            client.close()
    out = {"available": False, "error": err}
    c.put(domain, out, TTL_FAIL)
    return out
