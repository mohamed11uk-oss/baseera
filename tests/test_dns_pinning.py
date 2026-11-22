"""Prompt 4.6: DNS-rebinding TOCTOU. The resolver answers a public IP on the check and a private IP afterwards;
the connection must go to the CHECKED IP and DNS must not be asked again. Fully offline: httpcore.MockBackend
replaces the socket layer, so no packet leaves the machine."""
import socket
import ssl
from types import SimpleNamespace

import httpcore
import httpx
import pytest

from baseera.normalize import FetchRefused, follow_redirects, pinned_client, safe_fetch

OK = [b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"]


def rebinding_resolver(public: dict[str, str], later: str = "127.0.0.1"):
    """First lookup of each host -> its public IP; every later lookup -> `later` (the rebinding attack)."""
    calls: list[str] = []

    def r(host, port):
        ip = public[host] if host not in calls else later
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
    r.calls = calls
    return r


class _Stream(httpcore.MockStream):
    def __init__(self, buffer, owner):
        super().__init__(buffer)
        self.owner = owner

    def write(self, buffer, timeout=None):
        self.owner.written.append(buffer)

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.owner.tls.append({"sni": server_hostname, "check_hostname": ssl_context.check_hostname,
                               "verify_mode": ssl_context.verify_mode})
        return self


class RecordingBackend(httpcore.MockBackend):
    """Fake socket layer: records the address every TCP connection is opened to; replies per IP."""

    def __init__(self, replies: dict[str, list[bytes]]):
        super().__init__([])
        self.replies, self.connects, self.tls, self.written = replies, [], [], []

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.connects.append((host, port))
        if host not in self.replies:
            raise httpcore.ConnectError(f"test: unexpected connect to {host}")
        return _Stream(list(self.replies[host]), self)


def test_safe_fetch_connects_to_checked_ip_not_rebound_one():
    res = rebinding_resolver({"victim.example": "93.184.216.34"})
    be = RecordingBackend({"93.184.216.34": OK})
    r = safe_fetch("https://victim.example/login", resolver=res, network_backend=be)
    assert r.status == 200 and r.body == b"hello"
    assert be.connects == [("93.184.216.34", 443)]  # the checked IP, never 127.0.0.1
    assert res.calls == ["victim.example"]  # resolved exactly once: no second lookup to rebind
    # TLS still verifies the ORIGINAL hostname (SNI + certificate), and Host header is unchanged.
    assert be.tls == [{"sni": "victim.example", "check_hostname": True, "verify_mode": ssl.CERT_REQUIRED}]
    assert b"Host: victim.example" in b"".join(be.written)


def test_redirect_follower_pins_every_hop():
    res = rebinding_resolver({"short.example": "93.184.216.34", "dest.example": "93.184.216.35"})
    be = RecordingBackend({
        "93.184.216.34": [b"HTTP/1.1 302 Found\r\nLocation: https://dest.example/landing\r\nContent-Length: 0\r\n\r\n"],
        "93.184.216.35": OK,
    })
    chain = follow_redirects("http://short.example/a", resolver=res, network_backend=be)
    assert chain == ["http://short.example/a", "https://dest.example/landing"]
    assert be.connects == [("93.184.216.34", 80), ("93.184.216.35", 443)]
    assert res.calls == ["short.example", "dest.example"]
    assert be.tls[0]["sni"] == "dest.example"


def test_private_answer_on_check_is_still_refused_before_connecting():
    def private(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 0))]
    be = RecordingBackend({})
    with pytest.raises(FetchRefused, match="SSRF"):
        safe_fetch("http://intra.example/", resolver=private, network_backend=be)
    assert be.connects == []


def test_unpinned_host_is_refused_fail_closed():
    """A host that was never SSRF-checked cannot be connected to (no fallback to a fresh DNS lookup)."""
    be = RecordingBackend({"93.184.216.34": OK})
    client, pins = pinned_client(2.0, network_backend=be)
    with client:
        with pytest.raises(httpx.ConnectError, match="not SSRF-checked"):
            client.get("http://never-checked.example/")
        pins.pin("ok.example", ["10.0.0.1"])  # even a bad pin cannot reach an internal address
        with pytest.raises(httpx.ConnectError, match="forbidden"):
            client.get("http://ok.example/")
    assert be.connects == []


def test_env_proxy_does_not_bypass_pinning(monkeypatch):
    """With HTTP(S)_PROXY set, a proxy would do its own DNS lookup. The pinned client must ignore it."""
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    res = rebinding_resolver({"victim.example": "93.184.216.34"})
    be = RecordingBackend({"93.184.216.34": OK})
    assert safe_fetch("http://victim.example/", resolver=res, network_backend=be).status == 200
    assert be.connects == [("93.184.216.34", 80)]


def test_tls_lookup_connects_to_checked_ip(monkeypatch):
    from baseera.signals import domain_intel

    seen = []
    monkeypatch.setattr(domain_intel, "ssrf_check", lambda host: ["93.184.216.34"])

    def conn(addr, timeout=None):
        seen.append(addr)
        raise OSError("test: stop here")
    monkeypatch.setattr(domain_intel.socket, "create_connection", conn)
    out = domain_intel.tls_lookup("rebind-tls.example", SimpleNamespace(timeout_s=1.0))
    assert "error" in out and seen == [("93.184.216.34", 443)]
