"""Optional .ae WHOIS (whois.aeda.net.ae, TCP 43). RDAP has no .ae data, so this is tried before crt.sh.

Whether the .ae WHOIS output contains a creation date is UNVERIFIED (port 43 was blocked on the build machine):
the parser looks for common 'Creation Date' style labels and returns available=false if none is found.
Fails soft on timeout / blocked port. Response is UNTRUSTED text: parsed with regexes only, size-capped.
"""
from __future__ import annotations

import re
import socket
import time

from .cache import JsonCache

WHOIS_HOST = "whois.aeda.net.ae"
MAX_BYTES = 64 * 1024
_CREATED = re.compile(r"^\s*(?:creation date|created(?: on)?|registered(?: on)?|registration date|domain registration date)"
                      r"\s*:\s*(.+?)\s*$", re.I | re.M)
_REGISTRAR = re.compile(r"^\s*registrar(?: name)?\s*:\s*(.+?)\s*$", re.I | re.M)
_NS = re.compile(r"^\s*name ?server(?:\s*\d*)?\s*:\s*(\S+)", re.I | re.M)
_caches: dict[str, JsonCache] = {}


def is_ae(domain: str) -> bool:
    return domain.lower().rstrip(".").endswith(".ae")


def parse(text: str) -> dict:
    m = _CREATED.search(text)
    reg = _REGISTRAR.search(text)
    ns = sorted({n.lower().rstrip(".") for n in _NS.findall(text)})
    out = {"created": m.group(1)[:64] if m else None, "registrar": reg.group(1)[:120] if reg else None, "nameservers": ns}
    if not m:
        out["error"] = "no creation date in .ae WHOIS response"
    return out


def query(domain: str, timeout: float = 4.0, connect=socket.create_connection) -> str:
    deadline = time.monotonic() + timeout
    with connect((WHOIS_HOST, 43), timeout=timeout) as s:
        s.sendall(domain.encode("idna") + b"\r\n")
        buf = b""
        while len(buf) < MAX_BYTES:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            s.settimeout(left)
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    return buf[:MAX_BYTES].decode("utf-8", "replace")


def lookup(domain: str, settings, connect=socket.create_connection) -> dict:
    """Never raises. Returns {'created','registrar','nameservers'} or {'error': ...}."""
    key = str(settings.cache_dir)
    if key not in _caches:
        _caches[key] = JsonCache(settings.cache_dir / "whois_ae_cache.json")
    c = _caches[key]
    hit = c.get(domain)
    if hit is not None:
        return hit
    try:
        out = parse(query(domain, settings.timeout_s, connect))
        c.put(domain, out, 86400)
    except Exception as e:  # noqa: BLE001 - port 43 often blocked
        out = {"error": f".ae WHOIS unavailable: {type(e).__name__}"}
        c.put(domain, out, 900)
    return out
