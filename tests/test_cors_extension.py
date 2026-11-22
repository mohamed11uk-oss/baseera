from fastapi.testclient import TestClient

from baseera.api import create_app
from baseera.config import Settings

EXT = "chrome-extension://" + "a" * 32


def _client(monkeypatch, origins=None):
    if origins is None:
        monkeypatch.delenv("BASEERA_CORS_ORIGINS", raising=False)
    else:
        monkeypatch.setenv("BASEERA_CORS_ORIGINS", origins)
    s = Settings()
    s.mode = "offline"
    return TestClient(create_app(settings=s, db_path=":memory:"))


def _preflight(c, origin):
    return c.options("/api/analyze", headers={"Origin": origin, "Access-Control-Request-Method": "POST",
                                              "Access-Control-Request-Headers": "content-type"})


def test_extension_origin_allowed(monkeypatch):
    c = _client(monkeypatch)
    r = _preflight(c, EXT)
    assert r.status_code == 200 and r.headers["access-control-allow-origin"] == EXT
    r = c.post("/api/analyze", json={"url": "https://www.adpolice.gov.ae/en", "save_case": False}, headers={"Origin": EXT})
    assert r.headers.get("access-control-allow-origin") == EXT and r.json()["level"] == "low"


def test_web_origin_refused(monkeypatch):
    c = _client(monkeypatch)
    r = _preflight(c, "https://evil.example")
    assert "access-control-allow-origin" not in r.headers


def test_override(monkeypatch):
    c = _client(monkeypatch, "https://dash.example")
    assert _preflight(c, "https://dash.example").headers["access-control-allow-origin"] == "https://dash.example"
    assert "access-control-allow-origin" not in _preflight(c, EXT).headers


def test_extension_files_valid():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "extension"
    m = json.loads((root / "manifest.json").read_text())
    assert m["manifest_version"] == 3 and set(m["permissions"]) == {"activeTab", "storage"}
    js = (root / "popup.js").read_text()
    assert "innerHTML" not in js and "eval(" not in js
