"""SerpAPI key names + .env loading (offline: SerpAPI is mocked, the key is never printed)."""
import os

import httpx
from fastapi.testclient import TestClient

import baseera.api as api_mod
from baseera import config, serp
from baseera.api import create_app
from baseera.config import Settings, load_dotenv, serpapi_key_from_env


def test_serpapi_key_accepts_both_names(monkeypatch):
    monkeypatch.delenv("SERPAPI_KEY", raising=False)
    monkeypatch.delenv("SERPAPI_API_KEY", raising=False)
    assert serpapi_key_from_env() is None and Settings().serpapi_key is None
    monkeypatch.setenv("SERPAPI_API_KEY", "from-api-key-name")
    assert Settings().serpapi_key == "from-api-key-name"
    monkeypatch.setenv("SERPAPI_KEY", "")            # empty value falls through to SERPAPI_API_KEY
    assert Settings().serpapi_key == "from-api-key-name"
    monkeypatch.setenv("SERPAPI_KEY", "primary")
    assert Settings().serpapi_key == "primary"


def test_load_dotenv_parses_and_never_overrides(monkeypatch, tmp_path):
    f = tmp_path / ".env"
    f.write_text("# comment\n\nexport T_A=1\nT_B='quoted # not a comment'\nT_C=val  # trailing comment\n"
                 "T_D=   # only a comment\nT_E=keep\nnot a line\nT_F=\"dq\"\n", encoding="utf-8")
    for k in ("T_A", "T_B", "T_C", "T_D", "T_F"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("T_E", "from-env")
    names = load_dotenv(f)
    assert sorted(names) == ["T_A", "T_B", "T_C", "T_D", "T_F"]  # names only, never values
    assert (os.environ["T_A"], os.environ["T_B"], os.environ["T_C"], os.environ["T_D"], os.environ["T_F"]) == \
        ("1", "quoted # not a comment", "val", "", "dq")
    assert os.environ["T_E"] == "from-env"            # real environment wins
    for k in names:
        monkeypatch.delenv(k)


def test_load_dotenv_missing_file_is_noop(tmp_path):
    assert load_dotenv(tmp_path / "nope.env") == []


def test_dotenv_serpapi_api_key_enables_live_scan(monkeypatch, tmp_path):
    """A .env with only SERPAPI_API_KEY (the user's setup) => scan-brand calls SerpAPI with that key."""
    (tmp_path / ".env").write_text("SERPAPI_API_KEY=test-key-123\n", encoding="utf-8")
    monkeypatch.delenv("SERPAPI_KEY", raising=False)
    monkeypatch.delenv("SERPAPI_API_KEY", raising=False)
    load_dotenv(tmp_path / ".env")
    st = Settings()
    assert st.serpapi_key == "test-key-123"
    st.mode, st.gsb_api_key = "live", None
    st.source_redirects = st.source_rdap = st.source_tls = st.source_crtsh = st.source_whois_ae = False  # no network
    seen = []

    def handler(req):
        seen.append(dict(req.url.params))
        return httpx.Response(200, json={"organic_results": [], "local_results": []})
    mock = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(api_mod, "serpapi_listings", lambda q, s: serp.serpapi_listings(q, s, client=mock))
    r = TestClient(create_app(settings=st, db_path=":memory:")).post("/api/scan-brand", json={"brand": "fab"})
    assert r.status_code == 200
    assert r.json()["data_label"] == "live (SerpAPI)"
    assert seen and all(p.get("api_key") == "test-key-123" for p in seen)
    assert "test-key-123" not in r.text                 # key never echoed to the client
    monkeypatch.delenv("SERPAPI_API_KEY")


def test_tests_do_not_load_local_dotenv():
    assert os.environ.get("BASEERA_DOTENV") == "off"
    assert config.ROOT.joinpath(".gitignore").read_text().splitlines().count(".env") == 1
