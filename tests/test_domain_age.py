"""sources/domain_age.py: RDAP -> .ae WHOIS -> crt.sh proxy, one test per path. Offline: MockTransport + fixtures."""
import json
from datetime import datetime, timezone
from functools import partial
from pathlib import Path

import httpx
import pytest

from baseera.config import Settings
from baseera.normalize import SSRFBlocked, ssrf_check
from baseera.sources import crtsh, domain_age, whois_ae

FIX = Path(__file__).parent / "fixtures"
RDAP = json.loads((FIX / "rdap_sample.json").read_text())
WHOIS_LEGACY = (FIX / "whois_ae_sample.txt").read_text()
WHOIS_DATED = (FIX / "whois_ae_sample_dated.txt").read_text()
CRT_ROWS = json.loads((FIX / "crtsh_sample.json").read_text())
NOW = datetime(2026, 11, 19, tzinfo=timezone.utc)


@pytest.fixture
def st(tmp_path, monkeypatch):
    s = Settings()
    s.mode = "live"
    s.cache_dir = tmp_path
    s.source_rdap = s.source_whois_ae = s.source_crtsh = True
    # rdap.org would need DNS; IP literals still go through the real guard.
    monkeypatch.setattr(domain_age, "ssrf_check", lambda h: ["93.184.215.14"] if h == "rdap.org" else ssrf_check(h))
    return s


def rdap_transport(status=200, body=None, seen=None):
    def h(req):
        if seen is not None:
            seen.append(str(req.url))
        if status != 200:
            return httpx.Response(status)
        return httpx.Response(200, json=RDAP if body is None else body)
    return httpx.MockTransport(h)


def wire(monkeypatch, *, rdap=None, whois_text=None, crt_rows=None):
    """Route each source through its real parser with a canned offline response."""
    real_rdap, real_crt = domain_age.rdap_lookup, crtsh.lookup
    monkeypatch.setattr(domain_age, "rdap_lookup", partial(real_rdap, transport=rdap or rdap_transport(404)))
    if whois_text is not None:
        monkeypatch.setattr(whois_ae, "query", lambda d, t, c: whois_text)
    else:
        monkeypatch.setattr(whois_ae, "query", lambda d, t, c: pytest.fail("WHOIS is only for .ae"))
    if crt_rows is not None:
        client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=crt_rows)))
        monkeypatch.setattr(crtsh, "lookup", partial(real_crt, client=client, sleep=lambda s: None))
    else:
        monkeypatch.setattr(crtsh, "lookup", lambda d, s: pytest.fail("crt.sh must not be called"))


# --- parsers ---------------------------------------------------------------------------------------------

def test_whois_ae_parser_on_aeda_layout_without_dates():
    p = whois_ae.parse(WHOIS_LEGACY)
    assert p["created"] is None and p["error"] == "no creation date in .ae WHOIS response"
    assert p["registrar"] == "Demo Registrar FZ-LLC"  # not 'Registrar ID'
    assert p["nameservers"] == ["ns1.demo-dns.ae", "ns2.demo-dns.ae"]


def test_whois_ae_parser_on_dated_layout():
    p = whois_ae.parse(WHOIS_DATED)
    assert p == {"created": "2019-06-14T10:22:03Z", "registrar": "Demo Registrar FZ-LLC",
                 "nameservers": ["ns1.demo-dns.ae", "ns2.demo-dns.ae"]}  # Updated/Expiry dates ignored


def test_parse_dt_formats():
    for s in ("2019-06-14T10:22:03Z", "2019-06-14T10:22:03+00:00", "2019-06-14T10:22:03.5Z", "2019-06-14", "14-Jun-2019"):
        assert domain_age.parse_dt(s).date().isoformat() == "2019-06-14", s
    assert domain_age.parse_dt("sometime last year") is None


def test_rdap_lookup_parses_and_caches(st):
    seen = []
    r = domain_age.rdap_lookup("fresh-demo.top", st, transport=rdap_transport(seen=seen))
    assert r == {"created": "2026-11-10T03:14:15Z", "registrar": "Demo Registrar Ltd",
                 "nameservers": ["ns1.demo-dns.top", "ns2.demo-dns.top"]}
    assert seen == ["https://rdap.org/domain/fresh-demo.top"]
    again = domain_age.rdap_lookup("fresh-demo.top", st, transport=rdap_transport(500))
    assert again == r  # served from cache


def test_rdap_lookup_fails_soft(st):
    assert domain_age.rdap_lookup("gone.top", st, transport=rdap_transport(404)) == {"error": "RDAP HTTP 404"}
    bad = httpx.MockTransport(lambda req: httpx.Response(200, content=b"<html>"))
    assert domain_age.rdap_lookup("bad.top", st, transport=bad)["error"].startswith("RDAP unavailable")
    assert domain_age.parse_rdap(["junk"]) == {"error": "RDAP returned a non-object"}
    assert domain_age.parse_rdap({"events": ["x", {"eventAction": "registration"}], "entities": [{"roles": "x"}]}) == \
        {"created": None, "registrar": None, "nameservers": []}


def test_rdap_redirect_to_metadata_ip_is_blocked(st):
    def h(req):
        if req.url.host == "rdap.org":
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        pytest.fail("redirect hop must be refused before it is sent")
    r = domain_age.rdap_lookup("evil.top", st, transport=httpx.MockTransport(h))
    assert r == {"error": f"RDAP unavailable: {SSRFBlocked.__name__}"}


# --- the chain: one test per path -----------------------------------------------------------------------

def test_path_rdap(st, monkeypatch):
    wire(monkeypatch, rdap=rdap_transport())
    infra = {}
    s = domain_age.domain_age_signal("fresh-demo.top", st, infra, NOW)
    assert s.available and s.source == "rdap" and s.score == 1.0 and s.data == {"age_days": 8, "path": "rdap"}
    assert s.evidence == "Domain registered 2026-11-10 (8 days ago) per RDAP"
    assert infra["rdap"]["registrar"] == "Demo Registrar Ltd"


def test_path_rdap_then_ae_whois(st, monkeypatch):
    wire(monkeypatch, whois_text=WHOIS_DATED)
    infra = {}
    s = domain_age.domain_age_signal("old-demo.ae", st, infra, NOW)
    assert s.source == "whois" and s.score == 0 and s.data["path"] == "rdap>whois_ae"
    assert s.evidence.startswith("Domain registered 2019-06-14 (")
    assert s.evidence.endswith("per .ae WHOIS (whois.aeda.net.ae); RDAP: RDAP HTTP 404")
    assert infra["whois_ae"]["registrar"] == "Demo Registrar FZ-LLC"


def test_path_ae_whois_without_date_falls_back_to_crtsh_proxy(st, monkeypatch):
    wire(monkeypatch, whois_text=WHOIS_LEGACY, crt_rows=CRT_ROWS)
    s = domain_age.domain_age_signal("demo-lookalike.ae", st, {}, NOW)
    assert s.source == "crt.sh" and s.score == 0.5 and s.data == {"age_days": 17, "path": "proxy:crt.sh", "proxy": True}
    assert s.evidence.startswith("Registration date unavailable (RDAP: RDAP HTTP 404; "
                                 ".ae WHOIS: no creation date in .ae WHOIS response); first certificate")
    assert "per crt.sh (proxy: the domain is at least this old)" in s.evidence


def test_path_gtld_rdap_without_date_goes_straight_to_crtsh(st, monkeypatch):
    wire(monkeypatch, rdap=rdap_transport(body={"objectClassName": "domain", "events": []}), crt_rows=CRT_ROWS)
    s = domain_age.domain_age_signal("demo.top", st, {}, NOW)
    assert s.data["path"] == "proxy:crt.sh" and "(RDAP: no registration date); first certificate" in s.evidence


def test_nothing_parses_returns_unavailable(st, monkeypatch):
    wire(monkeypatch, whois_text="Domain Name: x-demo.ae\nCreation Date: sometime last year\n", crt_rows=[])
    s = domain_age.domain_age_signal("x-demo.ae", st, {}, NOW)
    assert not s.available and s.score == 0 and s.data == {"path": "none"}
    assert s.evidence == ("Domain age unavailable (RDAP: RDAP HTTP 404; .ae WHOIS: creation date unparsable; "
                          "crt.sh: no certificates logged in crt.sh)")


def test_all_sources_off(st, monkeypatch):
    wire(monkeypatch)
    monkeypatch.setattr(domain_age, "rdap_lookup", lambda d, s: pytest.fail("RDAP is off"))
    st.source_rdap = st.source_whois_ae = st.source_crtsh = False
    s = domain_age.domain_age_signal("demo.ae", st, {}, NOW)
    assert not s.available and s.evidence == "Domain age unavailable (RDAP: off; .ae WHOIS: off; crt.sh: off)"


def test_offline_mode_touches_nothing(st, monkeypatch):
    wire(monkeypatch)
    monkeypatch.setattr(domain_age, "rdap_lookup", lambda d, s: pytest.fail("network in offline mode"))
    st.mode = "offline"
    s = domain_age.domain_age_signal("demo.ae", st, {}, NOW)
    assert not s.available and "offline" in s.evidence
