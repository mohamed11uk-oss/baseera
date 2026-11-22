"""queries.yaml, SerpAPI parsing, recorder script (MockTransport) and 'recorded <date>' labelling."""
import importlib.util
import json
from pathlib import Path

import httpx
import yaml
from fastapi.testclient import TestClient

from baseera import serp
from baseera.api import create_app
from baseera.config import DATA, Settings

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("record_demo_fixtures", ROOT / "scripts" / "record_demo_fixtures.py")
rec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rec)

RAW_SEARCH = {"search_parameters": {"q": "x", "api_key": "SECRETKEY"},
              "search_metadata": {"json_endpoint": "https://serpapi.com/searches/abc.json?api_key=SECRETKEY"},
              "ads": [{"position": 1, "title": "Demo ad", "link": "https://demo-ad.example/", "description": "d"}],
              "organic_results": [{"position": 1, "title": "Official", "link": "https://www.emiratesnbd.com/en/contact-us"}]}
RAW_MAPS = {"local_results": [{"position": 1, "title": "Demo branch", "website": "https://www.emiratesnbd.com",
                               "phone": "600 54 0000", "address": "Demo address"}]}


def test_queries_yaml_brands_exist_and_templates_bilingual(reg):
    cfg = yaml.safe_load((DATA / "queries.yaml").read_text(encoding="utf-8"))
    assert 8 <= len(cfg["demo_brands"]) <= 10 and all(b in reg.by_id for b in cfg["demo_brands"])
    assert cfg["templates"]["en"] and cfg["templates"]["ar"]
    items = rec.plan(["enbd", "adpolice"], 1, ["en", "ar"])
    assert {i["engine"] for i in items} == {"google", "google_maps"} and len(items) == 8
    assert any("بنك الإمارات دبي الوطني" in i["query"] or "رقم خدمة العملاء" in i["query"] for i in items)
    assert any(i["query"].endswith("pay fine") for i in rec.plan(["adpolice"], 4, ["en"]))
    assert not any(i["query"].endswith("pay fine") for i in rec.plan(["enbd"], 4, ["en"]))  # category filter


def test_parsers():
    s = serp.parse_search(RAW_SEARCH, "q")
    assert s[0].is_ad and s[0].displayed_url == "https://demo-ad.example/" and s[1].rank == 1 and not s[1].is_ad
    m = serp.parse_maps(RAW_MAPS, "q")
    assert m[0].source == "maps" and m[0].phone == "600 54 0000"


def test_no_key_prints_clear_message(monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("SERPAPI_KEY", raising=False)
    monkeypatch.delenv("SERPAPI_API_KEY", raising=False)
    assert rec.main(["--brands", "enbd", "--out", str(tmp_path)]) == 2
    assert "SERPAPI_KEY is not set: nothing recorded" in capsys.readouterr().out
    assert not list(tmp_path.iterdir())


def test_record_with_key_writes_labelled_scrubbed_file(monkeypatch, tmp_path):
    monkeypatch.setenv("SERPAPI_KEY", "SECRETKEY")
    seen = []

    def h(req):
        seen.append(dict(req.url.params))
        return httpx.Response(200, json=RAW_MAPS if req.url.params["engine"] == "google_maps" else RAW_SEARCH)
    c = httpx.Client(transport=httpx.MockTransport(h))
    assert rec.main(["--brands", "enbd", "--langs", "en", "--out", str(tmp_path)], client=c) == 0
    assert {p["engine"] for p in seen} == {"google", "google_maps"} and seen[0]["gl"] == "ae"
    text = (tmp_path / "enbd.json").read_text(encoding="utf-8")
    assert "SECRETKEY" not in text
    doc = json.loads(text)
    assert doc["data_label"] == "recorded" and doc["recorded_on"] and len(doc["listings"]) == 3


def test_recorded_fixture_wins_and_is_labelled(monkeypatch, tmp_path):
    (tmp_path / "enbd.json").write_text(json.dumps({"data_label": "recorded", "recorded_on": "2026-11-20", "listings": [
        {"source": "maps", "title": "Emirates NBD", "displayed_url": "https://www.emiratesnbd.com"}]}))
    monkeypatch.setattr(serp, "RECORDED", tmp_path)
    ls, kind = serp.load_fixture("enbd")
    assert kind == "recorded 2026-11-20" and len(ls) == 1
    assert serp.load_fixture("fab")[1] == "synthetic"
    st = Settings()
    st.mode = "offline"
    r = TestClient(create_app(settings=st, db_path=":memory:")).post("/api/scan-brand", json={"brand": "enbd"}).json()
    assert "recorded 2026-11-20" in r["data_label"] and "NOT live" in r["data_label"] and "Synthetic" not in r["data_label"]
    r2 = TestClient(create_app(settings=st, db_path=":memory:")).post("/api/scan-brand", json={"brand": "fab"}).json()
    assert "Synthetic" in r2["data_label"]


def test_live_serpapi_failure_falls_back_to_replay(monkeypatch):
    import baseera.api as api_mod
    st = Settings()
    st.mode, st.serpapi_key, st.gsb_api_key = "live", "K", None
    st.source_redirects = st.source_rdap = st.source_tls = st.source_crtsh = st.source_whois_ae = False  # no network

    def boom(*a, **k):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(api_mod, "serpapi_listings", boom)
    r = TestClient(create_app(settings=st, db_path=":memory:")).post("/api/scan-brand", json={"brand": "fab"})
    assert r.status_code == 200 and r.json()["data_label"].startswith("SerpAPI unavailable (ConnectError)")
