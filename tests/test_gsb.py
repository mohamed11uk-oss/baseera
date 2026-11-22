"""Google Safe Browsing v4 client: off without key, cacheDuration, daily counter, batching, fail soft, attribution."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from baseera.analyze import Analyzer
from baseera.api import create_app
from baseera.config import Settings
from baseera.sources import gsb
from baseera.sources.gsb import GSBClient

BAD = "http://enbd-secure-login.top/verify"


@pytest.fixture
def st(tmp_path):
    s = Settings()
    s.mode = "live"
    s.cache_dir = tmp_path
    s.gsb_api_key = "TESTKEY"
    s.source_gsb = True
    s.source_redirects = s.source_rdap = s.source_tls = s.source_crtsh = s.source_whois_ae = False
    return s


def client(calls, status=200, bad=(BAD,), dur="300s"):
    def h(req):
        body = json.loads(req.content)
        calls.append(body)
        if status != 200:
            return httpx.Response(status, json={"error": {"message": "nope"}})
        urls = [e["url"] for e in body["threatInfo"]["threatEntries"]]
        return httpx.Response(200, json={"matches": [
            {"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM", "threatEntryType": "URL",
             "threat": {"url": u}, "cacheDuration": dur} for u in urls if u in bad]} if any(u in bad for u in urls) else {})
    return httpx.Client(transport=httpx.MockTransport(h))


def test_off_without_key_or_offline(st):
    st.gsb_api_key = None
    g = GSBClient(st)
    assert not g.enabled and g.status()["status"] == "off (no GSB_API_KEY)"
    assert g.check([BAD])["available"] is False
    st.gsb_api_key, st.mode = "K", "offline"
    assert GSBClient(st).status()["status"] == "off (offline)"


def test_match_cache_and_counter(st):
    calls = []
    g = GSBClient(st, client=client(calls), today=lambda: "2026-11-19")
    r = g.check([BAD, "https://example.com/"])
    assert r == {"available": True, "matches": {BAD: ["SOCIAL_ENGINEERING"]}}
    assert calls[0]["client"]["clientId"] == "baseera" and len(calls[0]["threatInfo"]["threatEntries"]) == 2
    assert g.check([BAD, "https://example.com/"])["matches"] == {BAD: ["SOCIAL_ENGINEERING"]}  # served from cache
    assert len(calls) == 1 and g.usage() == {"date": "2026-11-19", "requests": 1, "limit": 10000}


def test_cache_duration_honoured(st):
    calls = []
    g = GSBClient(st, client=client(calls, dur="0s"))
    g.check([BAD])
    g.check([BAD])  # cacheDuration 0s -> must ask again
    assert len(calls) == 2
    assert gsb._duration_s("12.5s") == 12.5 and gsb._duration_s(None) == gsb.NEGATIVE_TTL_S


def test_batches_of_500_and_daily_limit(st):
    calls = []
    st.gsb_daily_limit = 2
    g = GSBClient(st, client=client(calls), today=lambda: "2026-11-19")
    assert g.check([f"https://e{i}.example/" for i in range(501)])["available"]
    assert [len(c["threatInfo"]["threatEntries"]) for c in calls] == [500, 1]
    r = g.check(["https://new.example/"])
    assert r["available"] is False and "budget exhausted" in r["error"] and len(calls) == 2
    g2 = GSBClient(st, client=client(calls), today=lambda: "2026-11-20")  # new day resets (counter is per date)
    g2.cache = g.cache
    assert g2.usage()["requests"] == 0


def test_http_error_fails_soft_without_leaking_key(st):
    g = GSBClient(st, client=client([], status=500))
    r = g.check([BAD])
    assert r["available"] is False and "TESTKEY" not in json.dumps(r) and "TESTKEY" not in json.dumps(g.status())


def test_analyzer_gsb_match_high_with_attribution(st, reg):
    an = Analyzer(settings=st, registry=reg, feed=set(), feeds=None, gsb=GSBClient(st, client=client([])))
    v = an.analyze_url(BAD)
    s = next(s for s in v.signals if s.id == "gsb_match")
    assert v.level == "high" and s.score == 1 and "Advisory provided by Google" in s.evidence
    assert s.data["disclaimer_en"].startswith("Google works") and "not guaranteed" in s.evidence
    assert "Google" in v.explanation_ar and "not guaranteed" in v.explanation_ar


def test_analyzer_gsb_no_match_and_failure(st, reg):
    an = Analyzer(settings=st, registry=reg, feed=set(), feeds=None, gsb=GSBClient(st, client=client([])))
    s = next(s for s in an.analyze_url("https://example.com/").signals if s.id == "gsb_match")
    assert s.score == 0 and s.available and "Not listed" in s.evidence
    an2 = Analyzer(settings=st, registry=reg, feed=set(), feeds=None, gsb=GSBClient(st, client=client([], status=503)))
    v = an2.analyze_url(BAD)
    s2 = next(s for s in v.signals if s.id == "gsb_match")
    assert not s2.available and v.risk >= 0  # verdict still returned


def test_official_domain_gsb_match_stays_low(st, reg):
    off = "https://www.adpolice.gov.ae/en"
    an = Analyzer(settings=st, registry=reg, feed=set(), feeds=None, gsb=GSBClient(st, client=client([], bad=(off,))))
    v = an.analyze_url(off)
    assert v.level == "low" and next(s for s in v.signals if s.id == "gsb_match").score == 0


def test_health_exposes_gsb_notice():
    s = Settings()
    s.mode = "offline"
    h = TestClient(create_app(settings=s, db_path=":memory:")).get("/api/health").json()["sources"]
    g = h["gsb"]
    assert g["attribution_en"] == "Advisory provided by Google" and "cannot guarantee" in g["disclaimer_en"]
    assert "not guaranteed" in g["disclaimer_ar"] and g["status"].startswith("off")
    assert {"feeds", "crtsh", "whois_ae", "serpapi"} <= set(h)
