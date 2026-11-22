"""PhishTank / OpenPhish feed import + matching + Analyzer integration (small SYNTHETIC fixture files, no network)."""
import argparse
from pathlib import Path

import httpx
import pytest

from baseera.analyze import Analyzer
from baseera.config import Settings
from baseera.sources import feeds
from baseera.sources.feeds import FeedStore, parse_openphish, parse_phishtank, url_key

FX = Path(__file__).parent / "fixtures"
PT = (FX / "phishtank_sample.json").read_bytes()
OP = (FX / "openphish_sample.txt").read_bytes()


@pytest.fixture
def store():
    s = FeedStore(":memory:")
    s.import_rows("phishtank", parse_phishtank(PT), now=1000.0)
    s.import_rows("openphish", parse_openphish(OP), now=1000.0)
    return s


def test_parsers():
    pt = parse_phishtank(PT)
    assert len(pt) == 4  # unverified row dropped
    assert pt[0]["target"] == "Emirates NBD" and pt[0]["first_seen"].startswith("2026-11-17")
    assert pt[1]["target"] is None  # "Other" is not a target
    assert [r["url"] for r in parse_openphish(OP)][0] == "https://rta-fines-refund.click/login"
    assert parse_phishtank(b'{"not": "a list"}') == []


@pytest.mark.parametrize("a,b", [
    ("https://enbd-secure-login.top/verify/", "http://ENBD-secure-login.top/verify"),
    ("https://www.x.top/a?b=1", "https://x.top/a?b=1"),
    ("https://x.top:443/", "x.top"),
])
def test_url_key_equivalence(a, b):
    assert url_key(a)[0] == url_key(b)[0]


def test_match_exact_and_host(store):
    hits = store.match_exact("http://enbd-secure-login.top/verify")
    assert {h["source"] for h in hits} == {"phishtank", "openphish"}
    assert store.match_exact("https://enbd-secure-login.top/other") == []
    assert store.match_host("ENBD-secure-login.top")[0]["target"] == "Emirates NBD"
    assert store.match_host("adpolice-fine-portal.xyz")  # stored without www
    assert store.counts() == {"openphish": 3, "phishtank": 4}


def test_snapshot_replace_keeps_first_seen_and_drops_stale(store):
    store.import_rows("openphish", [{"url": "http://salik-topup-demo.top/"}], now=5000.0)
    assert store.counts()["openphish"] == 1
    assert store.match_exact("https://rta-fines-refund.click/login") == []
    first = store.match_exact("salik-topup-demo.top")[0]["first_seen"]
    assert first.startswith("1970-01-01")  # first import time preserved


def _transport(calls, status=200, body=OP):
    def h(req):
        calls.append(str(req.url))
        return httpx.Response(status, content=body)
    return httpx.Client(transport=httpx.MockTransport(h))


def test_refresh_respects_cadence_and_fails_soft():
    s = FeedStore(":memory:")
    calls = []
    r = s.refresh("openphish", client=_transport(calls), now=0.0)
    assert r == {"source": "openphish", "status": "ok", "count": 3} and calls == [feeds.OPENPHISH_URL]
    assert s.refresh("openphish", client=_transport(calls), now=3600.0)["status"] == "skipped (cadence)"
    assert len(calls) == 1
    # 12h later it is due; the server fails -> previous snapshot is kept, status recorded
    r = s.refresh("openphish", client=_transport(calls, status=503), now=12 * 3600.0)
    assert r["status"] == "error: HTTP 503" and r["count"] == 3
    assert s.meta()["openphish"]["status"] == "error: HTTP 503"
    assert s.refresh("openphish", client=_transport(calls), now=12 * 3600.0 + 1)["status"] == "skipped (cadence)"
    assert s.refresh("openphish", client=_transport(calls), now=12 * 3600.0 + 2, force=True)["status"] == "ok"


def test_phishtank_refresh_uses_app_key_and_hourly_cadence():
    s = FeedStore(":memory:")
    calls = []
    r = s.refresh("phishtank", app_key="K123", client=_transport(calls, body=PT), now=0.0)
    assert r["count"] == 4 and calls == ["https://data.phishtank.com/data/K123/online-valid.json"]
    assert "K123" not in str(s.meta())
    assert not s.due("phishtank", 3599.0) and s.due("phishtank", 3600.0)
    assert feeds.phishtank_url(None) == "https://data.phishtank.com/data/online-valid.json"
    bad = s.refresh("phishtank", client=_transport(calls, body=b"{broken"), force=True, now=4000.0)
    assert bad["status"].startswith("error") and bad["count"] == 4


def _an(reg, store):
    st = Settings()
    st.mode = "offline"
    return Analyzer(settings=st, registry=reg, feed=set(), feeds=store, gsb=None)


def test_analyzer_feed_hit_is_high_with_source_evidence(reg, store):
    v = _an(reg, store).analyze_url("https://enbd-secure-login.top/verify")
    s = next(s for s in v.signals if s.id == "blocklist_hit")
    assert v.level == "high" and s.score == 1.0 and "PhishTank" in s.evidence and "exact URL" in s.evidence
    # other path on the same (dedicated) phishing host: host match
    v2 = _an(reg, store).analyze_url("https://enbd-secure-login.top/card")
    assert v2.level == "high" and "same host" in next(s for s in v2.signals if s.id == "blocklist_hit").evidence


def test_shared_host_not_flagged_by_host_match(reg, store):
    an = _an(reg, store)
    assert not any(s.id == "blocklist_hit" for s in an.analyze_url("https://sites.google.com/view/my-bakery").signals)
    assert any(s.id == "blocklist_hit" and s.score == 1
               for s in an.analyze_url("https://sites.google.com/view/fab-rewards-demo").signals)


def test_official_domain_listed_in_feed_stays_low(reg, store):
    """FP guard: a feed row on an official registry domain never overrides the registry (analyst reviews it)."""
    v = _an(reg, store).analyze_url("https://www.bankfab.com/en-ae/compromised-page-demo")
    s = next(s for s in v.signals if s.id == "blocklist_hit")
    assert v.level == "low" and s.score == 0 and "analyst review" in s.evidence


def test_broken_feed_store_never_breaks_analyze(reg):
    class Boom:
        def match_exact(self, url):
            raise RuntimeError("db locked")
    v = _an(reg, Boom()).analyze_url("https://example.com/")
    assert v.level == "low"


def test_open_store_only_when_enabled_and_present(tmp_path):
    st = Settings()
    st.feeds_db = tmp_path / "feeds.db"
    assert feeds.open_store(st) is None  # never created implicitly
    FeedStore(st.feeds_db)
    st.source_feeds = True
    assert feeds.open_store(st) is not None
    st.source_feeds = False
    assert feeds.open_store(st) is None


def test_cli_refresh_and_count(tmp_path, monkeypatch, capsys):
    from baseera.__main__ import feeds_cli
    monkeypatch.setenv("BASEERA_FEEDS_DB", str(tmp_path / "f.db"))
    monkeypatch.delenv("PHISHTANK_APP_KEY", raising=False)
    assert feeds_cli(argparse.Namespace(action="refresh", source="openphish", force=False)) == 2  # offline: no download
    monkeypatch.setenv("BASEERA_MODE", "live")
    assert feeds_cli(argparse.Namespace(action="refresh", source="openphish", force=False), client=_transport([])) == 0
    feeds_cli(argparse.Namespace(action="count", source="all", force=False))
    out = capsys.readouterr().out
    assert "openphish  ok" in out and "      3 entries" in out and "phishtank        0 entries" in out
