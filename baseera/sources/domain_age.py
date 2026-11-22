"""Domain age with a documented fallback chain (Prompt 2.4). Fail soft, cached, 4s timeout.

Chain: RDAP (rdap.org bootstrap) -> .ae only: WHOIS whois.aeda.net.ae (RDAP has no .ae data)
       -> crt.sh first logged certificate (a PROXY: the domain is at least this old, it may be much older).
If nothing yields a parsable date the signal is available=false. The evidence string always names the path
used and why each earlier step was skipped, e.g. "... (RDAP: RDAP HTTP 404; .ae WHOIS: no creation date ...)".
All registry responses are UNTRUSTED data: only known fields are read.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import quote

from ..normalize import ssrf_check
from ..schemas import Signal
from . import crtsh, whois_ae
from . import status as source_status
from .cache import JsonCache

RDAP_URL = "https://rdap.org/domain/"
TTL_OK = 86400
_caches: dict[str, JsonCache] = {}


def _cache(settings) -> JsonCache:
    key = str(settings.cache_dir)
    if key not in _caches:
        _caches[key] = JsonCache(settings.cache_dir / "rdap_cache.json")
    return _caches[key]


def parse_dt(s: str) -> datetime | None:
    """Parse the date formats seen in RDAP/WHOIS output. Returns an aware UTC datetime or None."""
    s = str(s).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d", "%d-%b-%Y"):
        try:
            d = datetime.strptime(s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def parse_rdap(j) -> dict:
    """Reduce an RDAP domain object to {'created','registrar','nameservers'}."""
    if not isinstance(j, dict):
        return {"error": "RDAP returned a non-object"}
    created = next((ev.get("eventDate") for ev in j.get("events", []) or []
                    if isinstance(ev, dict) and ev.get("eventAction") == "registration"), None)
    registrar = None
    for ent in j.get("entities", []) or []:
        if isinstance(ent, dict) and "registrar" in (ent.get("roles") or []):
            v = (ent.get("vcardArray") or [None, []])
            v = v[1] if len(v) > 1 and isinstance(v[1], list) else []
            registrar = next((x[3] for x in v if isinstance(x, list) and len(x) > 3 and x[0] == "fn"), None) \
                or ent.get("handle")
    ns = sorted({n.get("ldhName", "").lower() for n in j.get("nameservers", []) or []
                 if isinstance(n, dict) and n.get("ldhName")})
    return {"created": created, "registrar": registrar, "nameservers": ns}


def rdap_lookup(domain: str, settings, transport=None) -> dict:
    """Never raises. Returns {'created','registrar','nameservers'} or {'error': ...}.

    `transport` (httpx transport) is injectable for offline tests. rdap.org redirects to the registry's RDAP
    server, so every hop is SSRF-checked.
    """
    c = _cache(settings)
    hit = c.get(domain)
    if hit is not None:
        return hit
    import httpx

    def guard(request):
        ssrf_check(request.url.host)
    try:
        with httpx.Client(timeout=settings.timeout_s, follow_redirects=True, transport=transport,
                          event_hooks={"request": [guard]}, headers={"Accept": "application/rdap+json"}) as cl:
            r = cl.get(RDAP_URL + quote(domain, safe=".-"))
        if r.status_code != 200:
            return {"error": f"RDAP HTTP {r.status_code}"}
        out = parse_rdap(r.json())
    except Exception as e:  # noqa: BLE001 - fail soft by design
        return {"error": f"RDAP unavailable: {type(e).__name__}"}
    if "error" not in out:
        c.put(domain, out, TTL_OK)
    return out


def _age_severity(age_days: int) -> float:
    return 1.0 if age_days < 30 else 0.5 if age_days < 180 else 0.0


def domain_age_signal(domain: str, settings, infra: dict, now: datetime) -> Signal:
    """The `new_domain` signal. Raw source results are stored in `infra` (clustering + evidence pack)."""
    if settings.offline:
        return Signal(id="new_domain", source="rdap", score=0, available=False,
                      evidence="Domain age not checked (offline/replay mode)")
    path: list[str] = []
    if settings.source_rdap:
        r = rdap_lookup(domain, settings)
        source_status.record("rdap", "error" not in r, r.get("error"))
        infra["rdap"] = r
        created = parse_dt(r["created"]) if r.get("created") else None
        if created:
            age = (now - created).days
            return Signal(id="new_domain", source="rdap", score=_age_severity(age),
                          data={"age_days": age, "path": "rdap"},
                          evidence=f"Domain registered {created.date()} ({age} days ago) per RDAP")
        path.append(f"RDAP: {r.get('error', 'no registration date')}")
    else:
        path.append("RDAP: off")
    if whois_ae.is_ae(domain):
        if settings.source_whois_ae:
            w = whois_ae.lookup(domain, settings)
            source_status.record("whois_ae", "error" not in w or "no creation date" in w["error"], w.get("error"))
            infra["whois_ae"] = w
            created = parse_dt(w["created"]) if w.get("created") else None
            if created:
                age = (now - created).days
                return Signal(id="new_domain", source="whois", score=_age_severity(age),
                              data={"age_days": age, "path": "rdap>whois_ae"},
                              evidence=f"Domain registered {created.date()} ({age} days ago) per .ae WHOIS "
                                       f"({whois_ae.WHOIS_HOST}); {path[0]}")
            path.append(f".ae WHOIS: {w.get('error') or 'creation date unparsable'}")
        else:
            path.append(".ae WHOIS: off")
    if settings.source_crtsh:
        c = crtsh.lookup(domain, settings)
        source_status.record("crtsh", c.get("available", False) or c.get("error") == "no certificates logged in crt.sh",
                             c.get("error"))
        infra["crtsh"] = c
        if c.get("available"):
            first = datetime.fromisoformat(c["first_seen"])
            age = (now - first).days
            # Proxy: a domain is at least as old as its first certificate, so cap severity at 0.5 (never "proven new").
            return Signal(id="new_domain", source="crt.sh", score=0.5 if age < 30 else 0.0,
                          data={"age_days": age, "path": "proxy:crt.sh", "proxy": True},
                          evidence=f"Registration date unavailable ({'; '.join(path)}); first certificate for the domain "
                                   f"logged {first.date()} ({age} days ago) per crt.sh (proxy: the domain is at least this old)")
        path.append(f"crt.sh: {c.get('error')}")
    else:
        path.append("crt.sh: off")
    return Signal(id="new_domain", source="rdap", score=0, available=False, data={"path": "none"},
                  evidence=f"Domain age unavailable ({'; '.join(path)})")
