"""Prompt 2.5: URLhaus, urlscan.io (read-only) and VirusTotal (manual deep check). All offline via MockTransport."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from baseera.analyze import Analyzer
from baseera.api import create_app
from baseera.config import Settings
from baseera.sources import urlscan as urlscan_mod
from baseera.sources.urlhaus import URLhausClient
from baseera.sources.urlscan import URLscanClient
from baseera.sources.virustotal import RateLimiter, VTClient, url_id

KEY = "TEST-ONLY-KEY"
BAD = "http://malware-drop-site.top/payload"
HOST_ONLY = "http://other-path-site.top/x"
VT_ID = "a" * 64


@pytest.fixture
def st(tmp_path):
    s = Settings()
    s.mode, s.seed_demo, s.cache_dir = "live", False, tmp_path
    s.source_redirects = s.source_rdap = s.source_tls = s.source_crtsh = s.source_whois_ae = s.source_gsb = False
    s.source_feeds, s.source_sandbox = False, "off"
    s.source_urlhaus, s.urlhaus_auth_key = True, KEY
    s.source_urlscan, s.urlscan_api_key = True, KEY
    s.source_vt, s.vt_api_key = True, KEY
    return s


def mock(handler, calls):
    def h(req):
        calls.append(req)
        return handler(req)
    return httpx.Client(transport=httpx.MockTransport(h))


def boom(req):
    raise AssertionError(f"unexpected network call: {req.url}")


# ------------------------------------------------------------------ defaults
def test_all_three_default_off(monkeypatch):
    for k in ("SOURCE_URLHAUS", "SOURCE_URLSCAN", "SOURCE_VT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("URLHAUS_AUTH_KEY", KEY)
    monkeypatch.setenv("URLSCAN_API_KEY", KEY)
    monkeypatch.setenv("VT_API_KEY", KEY)
    s = Settings()
    s.mode = "live"
    assert (s.source_urlhaus, s.source_urlscan, s.source_vt) == (False, False, False)
    for c in (URLhausClient(s), URLscanClient(s), VTClient(s)):
        assert not c.enabled and c.status().startswith("off (SOURCE_")


def test_off_without_key_or_offline(st):
    st.urlhaus_auth_key = None
    assert URLhausClient(st).status() == "off (no URLHAUS_AUTH_KEY)"
    assert URLhausClient(st).lookup(BAD, "x.top")["available"] is False
    st.mode = "offline"
    assert URLscanClient(st).status() == "off (offline)" and VTClient(st).report(BAD)["available"] is False


# ------------------------------------------------------------------- URLhaus
def urlhaus_handler(req):
    form = dict(x.split("=", 1) for x in req.content.decode().split("&"))
    form = {k: httpx.QueryParams(f"{k}={v}")[k] for k, v in form.items()}
    if req.url.path == "/v1/url/":
        if form["url"] == BAD:
            return httpx.Response(200, json={"query_status": "ok", "url": BAD, "url_status": "online",
                                             "threat": "malware_download", "tags": ["exe"], "date_added": "2026-11-18 10:00:00 UTC",
                                             "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"})
        return httpx.Response(200, json={"query_status": "no_results"})
    if form["host"] == "other-path-site.top":
        return httpx.Response(200, json={"query_status": "ok", "url_count": "2", "firstseen": "2026-11-01 00:00:00 UTC",
                                         "urls": [{"url": "http://other-path-site.top/a", "url_status": "online",
                                                   "threat": "malware_download"},
                                                  {"url": "http://other-path-site.top/b", "url_status": "offline"}]})
    return httpx.Response(200, json={"query_status": "no_results"})


def an_with(st, calls, uh=urlhaus_handler, us=None):
    return Analyzer(settings=st, feed=set(), feeds=None, gsb=None, sandbox=None,
                    urlhaus=URLhausClient(st, client=mock(uh, calls)),
                    urlscan=URLscanClient(st, client=mock(us, calls)) if us else None,
                    vt=VTClient(st, client=mock(boom, calls)))


def sig(v, sid):
    return next(s for s in v.signals if s.id == sid)


def test_urlhaus_exact_url_forces_high_with_auth_header(st):
    calls = []
    v = an_with(st, calls).analyze_url(BAD)
    s = sig(v, "urlhaus_match")
    assert s.score == 1.0 and s.contribution == 60 and v.level == "high" and "malware_download" in s.evidence
    assert calls[0].headers["Auth-Key"] == KEY and calls[0].method == "POST"
    assert len(calls) == 1  # exact hit: no host lookup needed
    assert "URLhaus" in v.explanation_ar


def test_urlhaus_host_hit_is_partial_and_not_an_override(st):
    calls = []
    v = an_with(st, calls).analyze_url(HOST_ONLY)
    s = sig(v, "urlhaus_match")
    assert s.score == 0.5 and s.data["online"] == 1 and s.data["url_count"] == 2
    assert [c.url.path for c in calls] == ["/v1/url/", "/v1/host/"]


def test_urlhaus_no_result_cache_and_shared_host(st):
    calls = []
    a = an_with(st, calls)
    assert sig(a.analyze_url("https://clean-site.com/"), "urlhaus_match").score == 0
    a.analyze_url("https://clean-site.com/")
    assert len(calls) == 2  # url + host, second analyze served from cache
    calls.clear()
    s = sig(a.analyze_url("https://someone.github.io/x"), "urlhaus_match")
    assert "shared platform" in s.evidence and [c.url.path for c in calls] == ["/v1/url/"]


def test_urlhaus_error_fails_soft_without_key_leak(st):
    calls = []
    v = an_with(st, calls, uh=lambda r: httpx.Response(401, json={"query_status": "unknown_auth_key"})).analyze_url(BAD)
    s = sig(v, "urlhaus_match")
    assert s.available is False and s.contribution == 0 and "HTTP 401" in s.evidence and KEY not in s.evidence
    v = an_with(st, calls, uh=lambda r: httpx.Response(200, json={"query_status": "invalid_url"})).analyze_url(BAD)
    assert sig(v, "urlhaus_match").available is False


def test_urlhaus_hit_on_official_domain_stays_low(st):
    calls = []
    ok = lambda r: httpx.Response(200, json={"query_status": "ok", "url": "x", "url_status": "offline",  # noqa: E731
                                             "threat": "malware_download"})
    v = an_with(st, calls, uh=ok).analyze_url("https://www.adpolice.gov.ae/")
    assert v.level == "low" and sig(v, "urlhaus_match").score == 0


# ------------------------------------------------------------------- urlscan
RID = "0b1e2c3d-4e5f-6071-8293-a4b5c6d7e8f9"


def urlscan_handler(req):
    return httpx.Response(200, json={"total": 2, "results": [
        {"_id": RID, "task": {"time": "2026-11-10T08:00:00.000Z", "visibility": "public", "url": "http://x"},
         "page": {"domain": "clean-site.com", "url": "https://clean-site.com/"}, "verdicts": {"overall": {"malicious": True}}},
        {"_id": "not-a-uuid", "task": {"time": "2026-11-01T08:00:00.000Z"}, "page": {"url": "https://clean-site.com/a"}}]})


def test_urlscan_reads_existing_scans_only_and_is_not_scored(st):
    calls = []
    v = an_with(st, calls, uh=lambda r: httpx.Response(200, json={"query_status": "no_results"}),
                us=urlscan_handler).analyze_url("https://clean-site.com/")
    s = sig(v, "urlscan_seen")
    assert s.available and s.score == 0 and s.contribution == 0 and "informational" in s.evidence
    assert s.data["total"] == 2 and s.data["first_seen"].startswith("2026-11-01") and s.data["malicious"] == 1
    assert s.data["results"][0]["result_url"] == f"https://urlscan.io/result/{RID}/"
    assert s.data["results"][1]["result_url"] is None  # untrusted ids are never turned into links
    us_calls = [c for c in calls if c.url.host == "urlscan.io"]
    assert [c.method for c in us_calls] == ["GET"] and us_calls[0].url.path == "/api/v1/search/"
    assert us_calls[0].url.params["q"] == 'page.domain:"clean-site.com"' and us_calls[0].headers["API-Key"] == KEY
    assert urlscan_mod.SUBMIT_VISIBILITY == "unlisted"


def test_urlscan_cache_error_and_bad_host(st):
    calls = []
    c = URLscanClient(st, client=mock(urlscan_handler, calls))
    c.search_host("clean-site.com")
    c.search_host("clean-site.com")
    assert len(calls) == 1
    assert c.search_host("bad host/../x")["available"] is False and len(calls) == 1
    e = URLscanClient(st, client=mock(lambda r: httpx.Response(429), calls)).search_host("x.com")
    assert e == {"available": False, "error": "urlscan.io unavailable: HTTP 429"}


# ---------------------------------------------------------------- VirusTotal
def vt_handler(req):
    if req.url.path.endswith(url_id("https://unknown-site.com/")):
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
    return httpx.Response(200, json={"data": {"id": VT_ID, "attributes": {
        "last_analysis_date": 1763500000,
        "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 20, "timeout": 0}}}})


def test_vt_url_id_is_unpadded_base64url():
    assert url_id("http://a.b/") == "aHR0cDovL2EuYi8" and "=" not in url_id("https://x.y/?q=1")


def test_vt_report_parse_404_and_cache(st):
    calls = []
    vt = VTClient(st, client=mock(vt_handler, calls))
    r = vt.report("https://bad-site.com/")
    assert r["found"] and r["malicious"] == 7 and r["engines"] == 88 and r["permalink"].endswith(VT_ID)
    assert r["last_analysis_date"].startswith("2025-11-18")
    assert calls[0].method == "GET" and calls[0].headers["x-apikey"] == KEY
    assert calls[0].url.path == "/api/v3/urls/" + url_id("https://bad-site.com/")
    assert vt.report("https://bad-site.com/")["cached"] is True and len(calls) == 1
    assert vt.report("https://unknown-site.com/") == {"available": True, "found": False}


def test_vt_rate_limiter_4_per_minute(st):
    now = [1000.0]
    calls = []
    vt = VTClient(st, client=mock(vt_handler, calls), clock=lambda: now[0])
    for i in range(4):
        assert vt.report(f"https://s{i}.com/")["available"]
    r = vt.report("https://s9.com/")
    assert r["available"] is False and "rate limit" in r["error"] and r["retry_after_s"] == 60.0 and len(calls) == 4
    assert vt.report("https://s0.com/")["available"]  # cache hit: allowed and not counted
    now[0] += 60
    assert vt.report("https://s9.com/")["available"] and len(calls) == 5
    lim = RateLimiter(1, 60, clock=lambda: 0.0)
    assert lim.acquire() == 0.0 and lim.acquire() == 60.0


def test_vt_endpoint_and_never_in_analyze(st):
    calls = []
    app = create_app(settings=st, db_path=":memory:")
    a = app.state.analyzer
    a.urlhaus, a.urlscan = None, None
    a.vt = VTClient(st, client=mock(vt_handler, calls))
    c = TestClient(app)
    assert c.post("/api/analyze", json={"url": "https://bad-site.com/"}).status_code == 200
    assert calls == []  # the hot path never calls VirusTotal
    r = c.post("/api/deep-check/virustotal", json={"url": "hxxps://bad-site[.]com/"}).json()
    assert r["url"] == "https://bad-site.com/" and r["malicious"] == 7 and "محرك فحص" in r["summary_ar"]
    assert "does not change" in r["note_en"] and len(calls) == 1
    h = c.get("/api/health").json()
    assert h["per_source"]["virustotal"]["status"] == "ok" and "manual deep check" in h["sources"]["virustotal"]
    assert KEY not in json.dumps(h)
    assert c.post("/api/deep-check/virustotal", json={"url": ""}).status_code == 422


def test_vt_endpoint_off_by_default(tmp_path):
    s = Settings()
    s.seed_demo, s.cache_dir = False, tmp_path
    r = TestClient(create_app(settings=s, db_path=":memory:")).post("/api/deep-check/virustotal",
                                                                    json={"url": "https://x.com/"}).json()
    assert r["available"] is False and r["error"].startswith("off")
