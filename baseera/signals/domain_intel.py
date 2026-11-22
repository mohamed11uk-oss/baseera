"""Network intelligence: domain age (chain in sources/domain_age.py) and TLS certificate age. Fail soft, cached, 4s timeout.

In offline mode (tests, eval, replay) these return available=false signals and never touch the network.
"""
from __future__ import annotations

import json
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

from ..config import DATA, Settings
from ..normalize import SSRFBlocked, ssrf_check
from ..schemas import Signal
from ..sources import domain_age
from ..sources import status as source_status

CACHE = DATA / "runtime" / "intel_cache.json"
_mem: dict[str, dict] = {}


def _cache_get(key: str, ttl: int = 86400) -> dict | None:
    if not _mem and CACHE.exists():
        try:
            _mem.update(json.loads(CACHE.read_text()))
        except Exception:
            pass
    v = _mem.get(key)
    if v and time.time() - v.get("_t", 0) < ttl:
        return v
    return None


def _cache_put(key: str, v: dict) -> None:
    v["_t"] = time.time()
    _mem[key] = v
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(_mem))
    except Exception:
        pass


def tls_lookup(host: str, settings: Settings) -> dict:
    cached = _cache_get("tls:" + host)
    if cached:
        return cached
    try:
        ips = ssrf_check(host)
        ctx = ssl.create_default_context()
        # Connect to the checked IP (no second DNS lookup = no rebinding); SNI + cert check still use the hostname.
        with socket.create_connection((ips[0], 443), timeout=settings.timeout_s) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
    except SSRFBlocked as e:
        return {"error": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"error": f"TLS unavailable: {type(e).__name__}"}
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    nb = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    out = {"not_before": nb.isoformat(), "issuer": issuer.get("organizationName") or issuer.get("commonName"),
           "san_count": len(sans), "ips": ips}
    _cache_put("tls:" + host, out)
    return out


def intel_signals(registrable_domain: str, host: str, settings: Settings, is_official: bool) -> tuple[list[Signal], dict]:
    """Returns signals + raw infra dict (for clustering and the evidence pack)."""
    infra: dict = {}
    sigs: list[Signal] = []
    now = datetime.now(timezone.utc)
    sigs.append(domain_age.domain_age_signal(registrable_domain, settings, infra, now))
    if settings.offline or not settings.source_tls:
        sigs.append(Signal(id="new_certificate", source="tls", score=0, available=False,
                           evidence="TLS certificate not checked (offline/replay mode)"))
    else:
        t = tls_lookup(host, settings)
        source_status.record("tls", "error" not in t, t.get("error"))
        infra["tls"] = t
        if t.get("not_before"):
            age = (now - datetime.fromisoformat(t["not_before"])).days
            sigs.append(Signal(id="new_certificate", source="tls", score=1.0 if age < 7 else 0.0, data={"age_days": age},
                               evidence=f"TLS certificate issued {age} days ago by {t.get('issuer')}"))
        elif (infra.get("crtsh") or {}).get("available"):
            c = infra["crtsh"]
            age = (now - datetime.fromisoformat(c["latest_not_before"])).days
            sigs.append(Signal(id="new_certificate", source="crt.sh", score=1.0 if c["issued_last_7d"] else 0.0,
                               data={"age_days": age},
                               evidence=f"TLS handshake failed ({t.get('error')}); latest logged certificate issued {age} "
                                        f"days ago by {c.get('issuer')} per crt.sh"))
        else:
            sigs.append(Signal(id="new_certificate", source="tls", score=0, available=False,
                               evidence=f"TLS certificate unavailable ({t.get('error')})"))
    if is_official:  # never let infra noise raise an official domain
        for s in sigs:
            s.score = 0
    return sigs, infra


def load_feed(path: Path | None = None) -> set[str]:
    """Local blocklist feed (one host or URL per line). Ships with a SYNTHETIC demo feed only."""
    path = path or DATA / "blocklist" / "synthetic_feed.txt"
    if not path.exists():
        return set()
    return {ln.strip().lower() for ln in path.read_text().splitlines() if ln.strip() and not ln.startswith("#")}
