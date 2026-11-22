"""Prompt 6.3: graceful degradation. Every optional source is made to fail (timeouts / errors via mocks, no real
network) and /api/analyze must still return a verdict with that source's signal marked available=false, while
/api/health reports the source as degraded. Real network is blocked for the whole module.
"""
import json
import socket
import sqlite3

import httpx
import pytest
from fastapi.testclient import TestClient

from baseera import normalize as normalize_mod
from baseera import sandbox as sandbox_mod
from baseera.api import create_app
from baseera.config import Settings
from baseera.signals import domain_intel
from baseera.sources import feeds as feeds_mod
from baseera.sources import status as source_status
from baseera.sources import whois_ae

URL = "https://degrade-check-site.com/login"
AE_URL = "https://degrade-check-site.ae/"
FAKE_KEY = "TEST-ONLY-NOT-A-KEY"
ALL = ("redirects", "rdap", "tls", "whois_ae", "crtsh", "feeds", "gsb", "urlhaus", "urlscan", "sandbox", "virustotal")
HOT = tuple(k for k in ALL if k != "virustotal")  # VirusTotal is a manual endpoint, never in /api/analyze


def _timeout_handler(request):
    raise httpx.ReadTimeout("simulated timeout", request=request)


class _TimeoutClient(httpx.Client):
    """Any httpx.Client the code under test creates: every request times out."""

    def __init__(self, *a, **kw):
        kw.pop("transport", None)
        super().__init__(*a, transport=httpx.MockTransport(_timeout_handler), **kw)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """All network paths fail like a timeout. TestClient keeps working (it subclasses the real httpx.Client)."""
    source_status.reset()
    monkeypatch.setattr(httpx, "Client", _TimeoutClient)

    def _get(*a, **kw):
        raise httpx.ConnectTimeout("simulated timeout")
    monkeypatch.setattr(httpx, "get", _get)

    def _conn(*a, **kw):
        raise TimeoutError("simulated TLS connect timeout")
    monkeypatch.setattr(domain_intel.socket, "create_connection", _conn)
    # Pretend DNS resolved to a public address so the failure happens at the source, not at the SSRF guard.
    monkeypatch.setattr(domain_intel, "ssrf_check", lambda host, **kw: ["93.184.215.14"])
    monkeypatch.setattr(normalize_mod, "ssrf_check", lambda host, **kw: ["93.184.215.14"])

    def _whois(*a, **kw):
        raise socket.timeout("simulated port-43 timeout")
    monkeypatch.setattr(whois_ae, "query", _whois)
    monkeypatch.setattr(sandbox_mod, "chrome_binary", lambda: "/usr/bin/fake-chrome")

    def _scan(url, **kw):
        raise TimeoutError("simulated navigation timeout")
    monkeypatch.setattr(sandbox_mod, "scan", _scan)
    yield
    source_status.reset()


def _settings(tmp_path, only: str | None) -> Settings:
    """Live mode with exactly one optional source on (or all of them with only='all')."""
    s = Settings()
    s.mode = "live"
    s.seed_demo = False
    s.cache_dir = tmp_path
    s.screenshot_dir = tmp_path / "shots"
    s.crtsh_retries = 0
    s.serpapi_key = None
    on = set(ALL) if only == "all" else {only}
    s.source_redirects, s.source_rdap, s.source_tls = "redirects" in on, "rdap" in on, "tls" in on
    s.source_whois_ae, s.source_crtsh, s.source_feeds = "whois_ae" in on, "crtsh" in on, "feeds" in on
    s.source_gsb = "gsb" in on
    s.gsb_api_key = FAKE_KEY if "gsb" in on else None
    s.source_urlhaus, s.urlhaus_auth_key = "urlhaus" in on, FAKE_KEY
    s.source_urlscan, s.urlscan_api_key = "urlscan" in on, FAKE_KEY
    s.source_vt, s.vt_api_key = "virustotal" in on, FAKE_KEY
    s.source_sandbox = "request" if "sandbox" in on else "off"
    s.feeds_db = tmp_path / "feeds.db"
    if "feeds" in on:
        feeds_mod.FeedStore(s.feeds_db).db.close()  # the DB file exists...
    return s


@pytest.fixture
def broken_feed_db(monkeypatch):
    """...but every query fails (locked / corrupt DB)."""
    def boom(*a, **kw):
        raise sqlite3.OperationalError("database is locked")
    for m in ("match_exact", "match_host", "meta"):
        monkeypatch.setattr(feeds_mod.FeedStore, m, boom)


# source -> (url, signal id that must be available=false, text expected in its evidence)
CASES = {
    "redirects": (URL, "redirects", "ReadTimeout"),
    "rdap": (URL, "new_domain", "RDAP unavailable"),
    "tls": (URL, "new_certificate", "TLS unavailable"),
    "whois_ae": (AE_URL, "new_domain", ".ae WHOIS unavailable"),
    "crtsh": (URL, "new_domain", "crt.sh unavailable"),
    "feeds": (URL, "blocklist_hit", "threat-feed DB unavailable"),
    "gsb": (URL, "gsb_match", "Safe Browsing unavailable"),
    "urlhaus": (URL, "urlhaus_match", "URLhaus unavailable"),
    "urlscan": (URL, "urlscan_seen", "urlscan.io unavailable"),
    "sandbox": (URL, "sandbox", "TimeoutError"),
}


@pytest.mark.parametrize("source", HOT)
def test_each_source_failing_still_returns_verdict(tmp_path, broken_feed_db, source):
    url, sig_id, ev = CASES[source]
    c = TestClient(create_app(settings=_settings(tmp_path, source), db_path=":memory:"))
    r = c.post("/api/analyze", json={"url": url, "deep": source == "sandbox"})
    assert r.status_code == 200, r.text
    v = r.json()
    assert v["level"] in ("low", "medium", "high") and 0 <= v["risk"] <= 100 and v["explanation_ar"]
    sigs = [s for s in v["signals"] if s["id"] == sig_id]
    assert sigs and all(s["available"] is False and s["contribution"] == 0 for s in sigs), sigs
    assert any(ev in s["evidence"] for s in sigs), [s["evidence"] for s in sigs]

    h = c.get("/api/health").json()
    row = h["per_source"][source]
    assert row["enabled"] is True and row["status"] == "degraded" and row["calls_failed"] >= 1 and row["last_error"]
    assert h["status"] == "degraded" and h["data_mode"] == "live"
    others = [k for k in ALL if k != source]
    assert all(h["per_source"][k]["status"] == "off" for k in others)


def test_all_sources_failing_at_once(tmp_path, broken_feed_db):
    c = TestClient(create_app(settings=_settings(tmp_path, "all"), db_path=":memory:"))
    for url, deep in ((URL, True), (AE_URL, False)):
        r = c.post("/api/analyze", json={"url": url, "deep": deep})
        assert r.status_code == 200 and r.json()["level"] in ("low", "medium", "high")
    # a known look-alike is still caught by the offline rules while every source is down
    v = c.post("/api/analyze", json={"url": "https://adpolice-fines-pay.com/pay"}).json()
    assert v["level"] == "high"
    # text and listing inputs too
    assert c.post("/api/analyze", json={"text": "عاجل https://degrade-check-site.com/pay"}).status_code == 200
    assert c.post("/api/analyze", json={"listing": {"title": "Abu Dhabi Police", "displayed_url": URL}}).status_code == 200
    vt = c.post("/api/deep-check/virustotal", json={"url": URL})
    assert vt.status_code == 200 and vt.json()["available"] is False and "VirusTotal unavailable" in vt.json()["error"]
    h = c.get("/api/health")
    assert FAKE_KEY not in h.text and FAKE_KEY not in vt.text  # never leak keys in health output
    per = h.json()["per_source"]
    assert {k for k, v in per.items() if v["status"] == "degraded"} == set(ALL)


def test_official_domain_stays_low_when_sources_fail(tmp_path, broken_feed_db):
    c = TestClient(create_app(settings=_settings(tmp_path, "all"), db_path=":memory:"))
    v = c.post("/api/analyze", json={"url": "https://www.adpolice.gov.ae/en/login", "deep": True}).json()
    assert v["level"] == "low" and v["matched_entity"]["relation"] == "official"


def test_health_offline_is_replay_and_sources_off(tmp_path):
    s = _settings(tmp_path, "all")
    s.mode = "offline"
    h = TestClient(create_app(settings=s, db_path=":memory:")).get("/api/health").json()
    assert h["data_mode"] == "replay" and "SYNTHETIC" in h["search_maps_data"]
    for k in ("redirects", "rdap", "tls", "whois_ae", "crtsh", "gsb", "urlhaus", "urlscan", "sandbox", "virustotal"):
        assert h["per_source"][k]["status"] == "off", (k, h["per_source"][k])
    assert h["per_source"]["feeds"]["status"] == "ready"  # local SQLite lookups also work offline
    assert set(h["per_source"]) == set(ALL) and h["status"] == "ok"


def test_health_ok_after_success(tmp_path, monkeypatch):
    """A source that answers is reported 'ok' (redirect follower answering with a 200)."""
    monkeypatch.setattr("baseera.analyze.follow_redirects", lambda url, timeout: [url])
    c = TestClient(create_app(settings=_settings(tmp_path, "redirects"), db_path=":memory:"))
    assert c.post("/api/analyze", json={"url": URL}).status_code == 200
    row = c.get("/api/health").json()["per_source"]["redirects"]
    assert row["status"] == "ok" and row["calls_ok"] == 1 and row["last_error"] is None
    assert json.dumps(row)  # JSON-serialisable
