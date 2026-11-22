import socket

import httpx
import pytest

from baseera.normalize import SSRFBlocked, follow_redirects, normalize, refang, ssrf_check


def test_basic_normalize():
    n = normalize("HTTPS://WWW.AdPolice.gov.ae/en/?utm_source=x&id=5")
    assert n.host == "www.adpolice.gov.ae"
    assert n.registrable_domain == "adpolice.gov.ae"
    assert n.label == "adpolice" and n.suffix == "gov.ae"
    assert "utm_source" not in n.url and "id=5" in n.url


def test_refang():
    assert refang("hxxps://evil[.]example[.]com/x") == "https://evil.example.com/x"


def test_idn_decoded():
    n = normalize("https://аdpolice.com/")  # Cyrillic а
    assert n.is_punycode and n.host.startswith("xn--") and n.host_unicode == "аdpolice.com"


def test_private_suffix_detected():
    assert normalize("https://rta-pay.netlify.app/").private_suffix == "netlify.app"


def test_bad_url():
    with pytest.raises(ValueError):
        normalize("http://")


def fake_resolver(mapping):
    def r(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[host], 0))]
    return r


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "172.16.0.1", "0.0.0.0"])
def test_ssrf_blocks_internal(ip):
    with pytest.raises(SSRFBlocked):
        ssrf_check("victim.example", resolver=fake_resolver({"victim.example": ip}))


def test_ssrf_allows_public():
    assert ssrf_check("ok.example", resolver=fake_resolver({"ok.example": "93.184.216.34"})) == ["93.184.216.34"]


def test_ssrf_blocks_localhost_name_and_numeric():
    for h in ("localhost", "foo.localhost", "3232235521"):
        with pytest.raises(SSRFBlocked):
            ssrf_check(h)


def test_redirect_to_private_ip_is_blocked():
    """A public URL that redirects to an internal address must be refused at the second hop."""
    import httpx

    def handler(request):
        if request.url.host == "short.example":
            return httpx.Response(302, headers={"location": "http://internal.example/admin"})
        return httpx.Response(200, text="should never be reached")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    resolver = fake_resolver({"short.example": "93.184.216.34", "internal.example": "10.1.2.3"})
    with pytest.raises(SSRFBlocked):
        follow_redirects("http://short.example/a", client=client, resolver=resolver)


def test_redirect_chain_recorded():
    import httpx

    def handler(request):
        if request.url.host == "short.example":
            return httpx.Response(301, headers={"location": "https://dest.example/landing"})
        return httpx.Response(200, text="ok")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    resolver = fake_resolver({"short.example": "93.184.216.34", "dest.example": "93.184.216.35"})
    chain = follow_redirects("http://short.example/a", client=client, resolver=resolver)
    assert chain == ["http://short.example/a", "https://dest.example/landing"]


def test_allowlist_env_only_affects_listed_range(monkeypatch):
    from baseera.normalize import ip_is_forbidden
    monkeypatch.setenv("BASEERA_SSRF_ALLOW", "198.18.0.0/15")
    assert not ip_is_forbidden("198.18.0.1")
    assert ip_is_forbidden("10.0.0.1") and ip_is_forbidden("169.254.169.254")
    monkeypatch.delenv("BASEERA_SSRF_ALLOW")
    assert ip_is_forbidden("198.18.0.1")


# ------------------------------------------------- Prompt 4.6: internal IPs, 2 MB cap, slow responses
def _public(host, port):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]


def test_ip_literal_checked_without_resolver():
    """A lying resolver must not be able to approve 127.0.0.1 / metadata IPs given as literals."""
    for h in ("127.0.0.1", "169.254.169.254", "[::1]", "10.1.2.3"):
        with pytest.raises(SSRFBlocked):
            ssrf_check(h, resolver=_public)
    assert ssrf_check("93.184.216.34", resolver=lambda *a: pytest.fail("resolver used for a literal")) == ["93.184.216.34"]


class _Never(httpx.SyncByteStream):
    """Body stream that fails the test if anyone reads it."""
    def __iter__(self):
        raise AssertionError("body was read")


def _client(handler):
    import httpx
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_safe_fetch_refuses_internal_before_connecting():
    from baseera.normalize import FetchRefused, safe_fetch
    c = _client(lambda r: pytest.fail("connected to an internal host"))
    for u in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://intra.example/"):
        with pytest.raises(FetchRefused, match="SSRF"):
            safe_fetch(u, client=c, resolver=fake_resolver({"intra.example": "192.168.0.10"}))
    with pytest.raises(FetchRefused, match="scheme"):
        safe_fetch("file:///etc/passwd", client=c)


def test_safe_fetch_refuses_big_content_length_without_reading():
    import httpx

    from baseera.normalize import FetchRefused, safe_fetch
    c = _client(lambda r: httpx.Response(200, headers={"content-length": str(3 * 1024 * 1024)}, stream=_Never()))
    with pytest.raises(FetchRefused, match="too large"):
        safe_fetch("http://big.example/", client=c, resolver=_public)


def test_safe_fetch_caps_streamed_body_at_2mb():
    import httpx

    from baseera.normalize import MAX_BODY_BYTES, FetchRefused, safe_fetch
    read = []

    class Endless(httpx.SyncByteStream):
        def __iter__(self):
            while True:
                read.append(1)
                yield b"x" * 65536

    c = _client(lambda r: httpx.Response(200, stream=Endless()))
    with pytest.raises(FetchRefused, match="exceeds"):
        safe_fetch("http://chunked.example/", client=c, resolver=_public)
    assert len(read) * 65536 <= MAX_BODY_BYTES + 2 * 65536  # stopped right after the cap


def test_safe_fetch_cuts_decompression_bomb():
    import gzip

    import httpx

    from baseera.normalize import FetchRefused, safe_fetch
    bomb = gzip.compress(b"\0" * (8 * 1024 * 1024))  # ~8 KB on the wire, 8 MB decoded
    assert len(bomb) < 100_000
    c = _client(lambda r: httpx.Response(200, headers={"content-encoding": "gzip"}, content=bomb))
    with pytest.raises(FetchRefused, match="after decompression"):
        safe_fetch("http://bomb.example/", client=c, resolver=_public)


def test_safe_fetch_deadline_stops_slow_loris():
    import time

    import httpx

    from baseera.normalize import FetchRefused, safe_fetch

    class Drip(httpx.SyncByteStream):
        def __iter__(self):
            for _ in range(100):
                time.sleep(0.05)
                yield b"a"

    c = _client(lambda r: httpx.Response(200, stream=Drip()))
    t = time.monotonic()
    with pytest.raises(FetchRefused, match="too slow"):
        safe_fetch("http://slow.example/", client=c, resolver=_public, deadline_s=0.3)
    assert time.monotonic() - t < 1.5


def test_safe_fetch_maps_timeouts():
    import httpx

    from baseera.normalize import FetchRefused, safe_fetch

    def h(r):
        raise httpx.ReadTimeout("slow", request=r)
    with pytest.raises(FetchRefused, match="timeout"):
        safe_fetch("http://hang.example/", client=_client(h), resolver=_public)


def test_safe_fetch_ok_small_body():
    import httpx

    from baseera.normalize import safe_fetch
    r = safe_fetch("http://ok.example/", client=_client(lambda r: httpx.Response(200, text="hello")), resolver=_public)
    assert r.status == 200 and r.body == b"hello"


def test_redirect_follower_never_reads_bodies_and_times_out():
    import httpx
    c = _client(lambda r: httpx.Response(200, headers={"content-length": str(50 * 1024 * 1024)}, stream=_Never()))
    assert follow_redirects("http://big.example/", client=c, resolver=_public) == ["http://big.example/"]

    def h(r):
        raise httpx.ReadTimeout("slow", request=r)
    with pytest.raises(httpx.TimeoutException):
        follow_redirects("http://hang.example/", client=_client(h), resolver=_public)
