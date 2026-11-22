"""URL normalisation, registrable-domain extraction and SSRF guard."""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import tldextract

# Offline extractor: bundled Public Suffix List snapshot, never downloads.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
_EXTRACT_ICANN = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

TRACKING = re.compile(r"^(utm_.*|gclid|fbclid|msclkid|mc_eid|igshid|yclid|ref_src)$", re.I)


@dataclass
class NormalizedURL:
    original: str
    url: str
    scheme: str
    host: str               # ascii (punycode) host
    host_unicode: str       # decoded IDN for display / homoglyph checks
    registrable_domain: str  # e.g. adpolice.gov.ae (ICANN suffixes)
    label: str              # registrable label without suffix, e.g. adpolice
    suffix: str
    subdomain: str
    private_suffix: str | None  # e.g. netlify.app if hosted on a shared platform
    path: str
    query: str
    is_ip: bool
    is_punycode: bool
    redirect_chain: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


DEFANG = [(r"hxxps?", lambda m: m.group(0).replace("xx", "tt")), (r"\[\.\]|\(\.\)|\{\.\}", "."), (r"\[:\]", ":")]


def refang(s: str) -> str:
    s = s.strip()
    for pat, rep in DEFANG:
        s = re.sub(pat, rep, s, flags=re.I)
    return s


def normalize(raw: str) -> NormalizedURL:
    s = refang(raw)
    if not re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        s = "http://" + s if not s.lower().startswith("www.") else "http://" + s
    parts = urlsplit(s)
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise ValueError("no host in URL")
    is_ip = _is_ip(host)
    try:
        host_ascii = host if is_ip else host.encode("idna").decode("ascii")
    except UnicodeError:
        host_ascii = host
    try:
        host_unicode = host_ascii.encode("ascii").decode("idna") if "xn--" in host_ascii else host
    except UnicodeError:
        host_unicode = host
    is_puny = "xn--" in host_ascii or any(ord(c) > 127 for c in host)
    if is_ip:
        reg, label, suffix, sub, priv = host_ascii, host_ascii, "", "", None
    else:
        icann = _EXTRACT_ICANN(host_ascii)
        full = _EXTRACT(host_ascii)
        reg = icann.top_domain_under_public_suffix or host_ascii
        label, suffix, sub = icann.domain, icann.suffix, icann.subdomain
        priv = full.suffix if full.is_private else None
    q = urlencode([(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if not TRACKING.match(k)])
    port = f":{parts.port}" if parts.port else ""
    clean = urlunsplit((parts.scheme.lower(), host_ascii + port, parts.path or "/", q, ""))
    return NormalizedURL(raw, clean, parts.scheme.lower(), host_ascii, host_unicode, reg, label, suffix, sub, priv,
                         parts.path or "/", q, is_ip, is_puny)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d+", host))  # decimal-encoded IPs like http://3232235521


# ---------------------------------------------------------------- SSRF guard
_META = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("100.100.100.200")}


def _allowlist() -> list:
    """BASEERA_SSRF_ALLOW: comma-separated CIDRs to allow despite being non-public. Only for sandboxes whose DNS
    returns fake-IP proxy addresses (e.g. 198.18.0.0/15). Never put RFC1918 or metadata ranges here."""
    import os
    return [ipaddress.ip_network(c.strip()) for c in os.getenv("BASEERA_SSRF_ALLOW", "").split(",") if c.strip()]


def ip_is_forbidden(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    if a not in _META and any(a in n for n in _allowlist()):
        return False
    return (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved
            or a.is_unspecified or a in _META or (a.version == 6 and a.ipv4_mapped is not None
                                                   and ip_is_forbidden(str(a.ipv4_mapped))))


class SSRFBlocked(Exception):
    pass


def ssrf_check(host: str, resolver=socket.getaddrinfo) -> list[str]:
    """Resolve host and raise SSRFBlocked if ANY address is internal. Returns the resolved IPs."""
    h = host.strip("[]")
    if re.fullmatch(r"\d+", h):
        raise SSRFBlocked(f"numeric host {h} refused")
    if h in ("localhost",) or h.endswith((".localhost", ".internal", ".local")):
        raise SSRFBlocked(f"internal hostname {h}")
    try:  # IP literals are judged directly, never via the resolver
        lit = str(ipaddress.ip_address(h))
    except ValueError:
        lit = None
    if lit is not None:
        if ip_is_forbidden(lit):
            raise SSRFBlocked(f"forbidden address {lit}")
        return [lit]
    try:
        ips = sorted({ai[4][0] for ai in resolver(h, None)})
    except (socket.gaierror, UnicodeError, OSError) as e:
        raise SSRFBlocked(f"cannot resolve {h}: {e}") from e
    for ip in ips:
        if ip_is_forbidden(ip):
            raise SSRFBlocked(f"{h} resolves to forbidden address {ip}")
    return ips


# ------------------------------------------------ DNS pinning (closes the DNS-rebinding TOCTOU gap)
def _pin_key(host: str) -> str:
    return host.strip("[]").rstrip(".").lower()


def url_host(url: str) -> str:
    """The exact host httpx/httpcore will connect to (IDN -> punycode, IPv6 without brackets). '' if unparsable."""
    import httpx
    try:
        return httpx.URL(url).raw_host.decode("ascii")
    except Exception:  # noqa: BLE001 - '' is then refused by ssrf_check
        return ""


def _pinned_backend_cls():
    import httpcore

    class PinnedBackend(httpcore.NetworkBackend):
        """httpcore network backend that connects ONLY to IPs ssrf_check approved for that host.

        httpcore calls connect_tcp(host=<URL hostname>) and later start_tls(server_hostname=<URL hostname>). We swap
        the hostname for the pinned IP only at the TCP level, so the Host header, TLS SNI and certificate verification
        all still use the original hostname. A host that was never checked is refused (fail closed): there is no
        second DNS lookup an attacker could rebind."""

        def __init__(self, inner=None):
            self.pins: dict[str, list[str]] = {}
            self._inner = inner or httpcore.SyncBackend()

        def pin(self, host: str, ips: list[str]) -> None:
            v4 = [i for i in ips if ":" not in i]
            self.pins[_pin_key(host)] = (v4 + [i for i in ips if ":" in i])[:3]  # IPv4 first, at most 3 attempts

        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            ips = self.pins.get(_pin_key(host))
            if not ips:
                raise httpcore.ConnectError(f"{host} was not SSRF-checked; refusing to resolve it again")
            err: Exception | None = None
            for ip in ips:
                if ip_is_forbidden(ip):  # defence in depth; ssrf_check already refused these
                    raise httpcore.ConnectError(f"pinned address {ip} is forbidden")
                try:
                    return self._inner.connect_tcp(ip, port, timeout=timeout, local_address=local_address,
                                                   socket_options=socket_options)
                except (httpcore.ConnectError, httpcore.ConnectTimeout) as e:
                    err = e
            raise err  # type: ignore[misc]

        def connect_unix_socket(self, path, timeout=None, socket_options=None):
            raise httpcore.ConnectError("unix sockets are not allowed")

        def sleep(self, seconds: float) -> None:
            self._inner.sleep(seconds)

    return PinnedBackend


def pinned_client(timeout: float, headers: dict | None = None, network_backend=None):
    """httpx.Client whose connections go only to pinned (SSRF-checked) IPs. Returns (client, backend);
    call backend.pin(host, ssrf_check(host)) before each request. `network_backend` is the real socket layer
    (tests inject an httpcore.MockBackend subclass, so nothing touches the network).

    A custom transport also means httpx ignores HTTP(S)_PROXY env vars: a proxy would resolve the name itself."""
    import httpcore
    import httpx

    backend = _pinned_backend_cls()(network_backend)
    transport = httpx.HTTPTransport(retries=0)
    pool = getattr(transport, "_pool", None)
    # httpx 0.28 has no public network_backend hook; fail closed if its internals ever change.
    if not isinstance(pool, httpcore.ConnectionPool) or not hasattr(pool, "_network_backend"):
        raise RuntimeError("httpx/httpcore layout changed: cannot pin DNS, refusing to fetch")
    pool._network_backend = backend
    return httpx.Client(transport=transport, follow_redirects=False, timeout=timeout, headers=headers), backend


def follow_redirects(url: str, max_hops: int = 5, timeout: float = 4.0, client=None, resolver=socket.getaddrinfo,
                     network_backend=None) -> list[str]:
    """Follow HTTP redirects WITHOUT executing JavaScript; SSRF-check every hop. Never submits anything.

    With our own client (client=None, the production path) every hop connects to the IP that was checked
    (pinned_client). A caller-supplied client (tests with httpx.MockTransport) is not pinned."""
    chain = [url]
    own = client is None
    backend = None
    if own:
        client, backend = pinned_client(timeout, {"User-Agent": "Baseera-Scanner/0.1 (+hackathon research)"},
                                        network_backend)
    try:
        import httpx

        cur = url
        for _ in range(max_hops):
            host = url_host(cur)
            ips = ssrf_check(host, resolver=resolver)
            if backend is not None:
                backend.pin(host, ips)
            with client.stream("GET", cur) as r:  # stream: do not download bodies
                loc = r.headers.get("location")
                if r.status_code not in (301, 302, 303, 307, 308) or not loc:
                    break
            cur = str(httpx.URL(cur).join(loc))
            chain.append(cur)
    finally:
        if own:
            client.close()
    return chain


# ------------------------------------------------------- guarded body fetch
MAX_BODY_BYTES = 2 * 1024 * 1024  # never read more than 2 MB (decoded) of any response


class FetchRefused(Exception):
    """Response refused: too large, too slow, or SSRF. The reason is safe to show."""


@dataclass
class FetchedResponse:
    url: str
    status: int
    headers: dict
    body: bytes


def safe_fetch(url: str, *, method: str = "GET", headers: dict | None = None, client=None, timeout: float = 4.0,
               deadline_s: float = 10.0, max_bytes: int = MAX_BODY_BYTES, resolver=socket.getaddrinfo,
               network_backend=None) -> FetchedResponse:
    """One HTTP request (redirects NOT followed: the caller re-checks every hop).

    - SSRF guard on the host before connecting; with our own client (client=None) the connection is pinned to the
      checked IP (no second DNS lookup => no rebinding window). Host header, SNI and cert checks keep the hostname.
    - Content-Length above max_bytes => refused without reading the body.
    - Body counted AFTER decompression (gzip/br/deflate bombs are cut at max_bytes).
    - Wall-clock deadline over the whole body (slow-loris: a server dribbling bytes cannot hold us past deadline_s).
    """
    import time

    import httpx

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchRefused(f"scheme {parts.scheme!r} not allowed")
    host = url_host(url)
    try:
        ips = ssrf_check(host, resolver=resolver)
    except SSRFBlocked as e:
        raise FetchRefused(f"SSRF guard: {e}") from e
    own = client is None
    if own:
        client, backend = pinned_client(timeout, network_backend=network_backend)
        backend.pin(host, ips)
    t0 = time.monotonic()
    try:
        with client.stream(method, url, headers=headers or {}) as r:
            cl = r.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > max_bytes:
                raise FetchRefused(f"response too large ({int(cl)} bytes > {max_bytes})")
            buf = bytearray()
            for chunk in r.iter_bytes():
                buf += chunk
                if len(buf) > max_bytes:
                    raise FetchRefused(f"response body exceeds {max_bytes} bytes (after decompression)")
                if time.monotonic() - t0 > deadline_s:
                    raise FetchRefused(f"response too slow (> {deadline_s}s)")
            hdrs = {k.lower(): v for k, v in r.headers.items()
                    if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")}
            return FetchedResponse(str(r.url), r.status_code, hdrs, bytes(buf))
    except httpx.TimeoutException as e:
        raise FetchRefused(f"timeout ({type(e).__name__})") from e
    finally:
        if own:
            client.close()
