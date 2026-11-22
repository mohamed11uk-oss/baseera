"""crt.sh client, .ae WHOIS and the domain-age fallback chain (no network: MockTransport / fakes)."""
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from baseera.config import Settings
from baseera.explain import _ar
from baseera.signals import domain_intel
from baseera.sources import crtsh, domain_age, whois_ae

ROWS = json.loads((Path(__file__).parent / "fixtures" / "crtsh_sample.json").read_text())


@pytest.fixture
def st(tmp_path):
    s = Settings()
    s.mode = "live"
    s.cache_dir = tmp_path
    s.source_redirects = s.source_tls = False
    return s


def mock(responses, calls):
    it = iter(responses)

    def h(req):
        calls.append(req.url.params.get("q"))
        r = next(it)
        if isinstance(r, Exception):
            raise r
        return r
    return httpx.Client(transport=httpx.MockTransport(h))


def test_summarize():
    s = crtsh.summarize(ROWS, now=datetime(2026, 11, 19, tzinfo=timezone.utc))
    assert s["available"] and s["first_seen"].startswith("2026-11-01") and s["latest_not_before"].startswith("2026-11-15")
    assert s["issuer"] == "Let's Encrypt" and s["san_count"] == 2 and s["cert_count"] == 2 and s["issued_last_7d"]
    assert crtsh.summarize([])["available"] is False
    assert crtsh.summarize([{"junk": 1}, "x"])["available"] is False


def test_lookup_retries_with_backoff_then_succeeds_and_caches(st):
    calls, sleeps = [], []
    c = mock([httpx.Response(503), httpx.ReadTimeout("slow"), httpx.Response(200, json=ROWS)], calls)
    r = crtsh.lookup("Demo-Lookalike.ae", st, client=c, sleep=sleeps.append)
    assert r["available"] and len(calls) == 3 and sleeps == [0.5, 1.0] and calls[0] == "demo-lookalike.ae"
    again = crtsh.lookup("demo-lookalike.ae", st, client=mock([], calls), sleep=sleeps.append)
    assert again["cached"] and len(calls) == 3


def test_lookup_fails_soft_after_retries(st):
    calls = []
    r = crtsh.lookup("down.example", st, client=mock([httpx.Response(502)] * 3, calls), sleep=lambda s: None)
    assert r == {"available": False, "error": "crt.sh HTTP 502"} and len(calls) == 3  # 1 + 2 retries
    calls2 = []
    r2 = crtsh.lookup("bad.example", st, client=mock([httpx.Response(200, content=b"<html>")] * 3, calls2),
                      sleep=lambda s: None)
    assert r2["available"] is False and "invalid JSON" in r2["error"]


def test_whois_parse_and_fail_soft(st):
    text = "Domain Name: demo.ae\nRegistrar Name: Demo Registrar\nName Server: NS1.DEMO.AE\nName Server: ns2.demo.ae\n"
    p = whois_ae.parse(text)
    assert p["created"] is None and "no creation date" in p["error"] and p["nameservers"] == ["ns1.demo.ae", "ns2.demo.ae"]
    assert whois_ae.parse("Creation Date: 2026-11-10T00:00:00Z\n")["created"] == "2026-11-10T00:00:00Z"

    def blocked(addr, timeout):
        raise TimeoutError("port 43 blocked")
    assert whois_ae.lookup("x-demo.ae", st, connect=blocked) == {"error": ".ae WHOIS unavailable: TimeoutError"}


def test_whois_query_reads_socket(st):
    class FakeSock:
        def __init__(self):
            self.chunks = [b"Creation Date: 2026-11-10\n", b""]
            self.sent = b""

        def sendall(self, b):
            self.sent += b

        def settimeout(self, t):
            pass

        def recv(self, n):
            return self.chunks.pop(0)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    fs = FakeSock()
    out = whois_ae.lookup("y-demo.ae", st, connect=lambda addr, timeout: fs)
    assert out["created"] == "2026-11-10" and fs.sent == b"y-demo.ae\r\n"


def test_domain_age_ae_falls_back_rdap_whois_crtsh(st, monkeypatch):
    monkeypatch.setattr(domain_age, "rdap_lookup", lambda d, s: {"error": "RDAP HTTP 404"})
    monkeypatch.setattr(whois_ae, "lookup", lambda d, s: {"error": ".ae WHOIS unavailable: TimeoutError"})
    first = datetime.now(timezone.utc).replace(microsecond=0)
    monkeypatch.setattr(crtsh, "lookup", lambda d, s: {"available": True, "first_seen": first.isoformat(),
                                                        "latest_not_before": first.isoformat(), "issuer": "Let's Encrypt",
                                                        "san_count": 1, "issued_last_7d": True})
    sigs, infra = domain_intel.intel_signals("demo-lookalike.ae", "demo-lookalike.ae", st, False)
    s = next(x for x in sigs if x.id == "new_domain")
    assert s.source == "crt.sh" and s.score == 0.5 and s.data["proxy"] and s.data["path"] == "proxy:crt.sh"
    assert "RDAP: RDAP HTTP 404" in s.evidence and ".ae WHOIS: " in s.evidence and "per crt.sh" in s.evidence
    assert "crtsh" in infra and "whois_ae" in infra
    assert "crt.sh" in _ar(s, _Reg())


def test_domain_age_whois_used_for_ae_when_it_has_a_date(st, monkeypatch):
    monkeypatch.setattr(domain_age, "rdap_lookup", lambda d, s: {"error": "RDAP HTTP 404"})
    monkeypatch.setattr(whois_ae, "lookup", lambda d, s: {"created": "2020-01-01", "registrar": "R", "nameservers": []})
    monkeypatch.setattr(crtsh, "lookup", lambda d, s: pytest.fail("crt.sh must not be called"))
    s = domain_intel.intel_signals("old-demo.ae", "old-demo.ae", st, False)[0][0]
    assert s.source == "whois" and s.score == 0 and s.data["path"] == "rdap>whois_ae" and "per .ae WHOIS" in s.evidence


def test_domain_age_non_ae_skips_whois_and_reports_all_paths(st, monkeypatch):
    monkeypatch.setattr(domain_age, "rdap_lookup", lambda d, s: {"error": "RDAP unavailable: ConnectError"})
    monkeypatch.setattr(whois_ae, "lookup", lambda d, s: pytest.fail("whois only for .ae"))
    monkeypatch.setattr(crtsh, "lookup", lambda d, s: {"available": False, "error": "crt.sh HTTP 502"})
    s = domain_intel.intel_signals("demo.top", "demo.top", st, False)[0][0]
    assert not s.available and s.evidence == "Domain age unavailable (RDAP: RDAP unavailable: ConnectError; crt.sh: crt.sh HTTP 502)"


def test_rdap_hit_wins(st, monkeypatch):
    monkeypatch.setattr(domain_age, "rdap_lookup", lambda d, s: {"created": "2026-11-10T00:00:00Z"})
    monkeypatch.setattr(crtsh, "lookup", lambda d, s: pytest.fail("no fallback needed"))
    s = domain_intel.intel_signals("fresh.top", "fresh.top", st, False)[0][0]
    assert s.source == "rdap" and s.score == 1.0 and "per RDAP" in s.evidence


def test_offline_never_calls_sources(monkeypatch):
    s = Settings()
    s.mode = "offline"
    for mod, fn in ((domain_age, "rdap_lookup"), (whois_ae, "lookup"), (crtsh, "lookup")):
        monkeypatch.setattr(mod, fn, lambda *a, **k: pytest.fail("network in offline mode"))
    sigs, _ = domain_intel.intel_signals("demo.ae", "demo.ae", s, False)
    assert all(not x.available for x in sigs)


class _Reg:
    by_id: dict = {}
