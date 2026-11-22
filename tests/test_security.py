"""Prompt 6.4: cheap hardening. Optional analyst token, body size limit, security headers, escaping, path safety."""
import re
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from baseera.api import create_app
from baseera.config import Settings
from baseera.evidence import build_zip

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "test-analyst-token-0123456789"


def make(token=None, **kw):
    s = Settings()
    s.mode = "offline"
    s.analyst_token = token
    for k, v in kw.items():
        setattr(s, k, v)
    return TestClient(create_app(settings=s, db_path=":memory:"))


def protected_paths(c, headers=None):
    cid = c.get("/api/cases", headers=headers).json()[0]["id"]
    return [f"/api/cases/{cid}", "/api/cases", "/api/clusters", f"/api/cases/{cid}/evidence.json",
            f"/api/cases/{cid}/evidence.html", f"/api/cases/{cid}/evidence.zip"]


def test_open_by_default_when_no_token():
    c = make()
    assert c.get("/api/analyst/session").json() == {"required": False, "authenticated": True}
    for p in protected_paths(c):
        assert c.get(p).status_code == 200, p


def test_token_protects_analyst_endpoints():
    c = make(TOKEN)
    good = {"Authorization": f"Bearer {TOKEN}"}
    paths = protected_paths(c, good)
    for p in paths + ["/api/cases/CASE-NOPE/evidence.pdf"]:
        r = c.get(p)
        assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer", p
        assert c.get(p, headers={"Authorization": "Bearer wrong"}).status_code == 401
    for p in paths:
        assert c.get(p, headers=good).status_code == 200, p
        assert c.get(p, headers={"X-Analyst-Token": TOKEN}).status_code == 200, p
    # the public citizen flow stays open
    assert c.post("/api/analyze", json={"url": "https://adpolice-fines-pay.com/pay"}).json()["level"] == "high"
    for p in ("/", "/api/health", "/api/brands", "/api/registry"):
        assert c.get(p).status_code == 200, p


def test_cookie_session_login_logout():
    c = make(TOKEN)
    assert c.get("/api/analyst/session").json() == {"required": True, "authenticated": False}
    assert c.post("/api/analyst/session", json={"token": "nope"}).status_code == 401
    r = c.post("/api/analyst/session", json={"token": TOKEN})
    assert r.status_code == 200
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "samesite=strict" in sc and TOKEN.lower() not in sc  # cookie holds an HMAC, not the token
    assert c.get("/api/clusters").status_code == 200
    assert c.get("/api/analyst/session").json()["authenticated"] is True
    c.delete("/api/analyst/session")
    c.cookies.clear()
    assert c.get("/api/clusters").status_code == 401


def test_request_body_limit():
    c = make(max_body_bytes=1024)
    assert c.post("/api/analyze", json={"text": "x" * 2000}).status_code == 413
    assert c.post("/api/analyze", content=b"{" + b" " * 5000 + b"}",
                  headers={"Content-Type": "application/json"}).status_code == 413

    def chunks():  # no Content-Length: streamed (chunked) body is counted too
        yield b'{"text": "'
        for _ in range(20):
            yield b"y" * 100
        yield b'"}'
    assert c.post("/api/analyze", content=chunks(), headers={"Content-Type": "application/json"}).status_code == 413
    assert c.post("/api/analyze", json={"url": "https://example.com"}).status_code == 200


def test_security_headers_and_csp():
    c = make()
    r = c.get("/")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
    assert "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert c.get("/static/app.js").headers["content-security-policy"]
    assert c.get("/api/health").headers["referrer-policy"] == "no-referrer"


def test_evidence_html_escapes_untrusted_input_and_has_no_script():
    c = make()
    evil = "https://evil-adpolice-pay.top/<script>alert(1)</script>?q=\"><img src=x onerror=alert(2)>"
    v = c.post("/api/analyze", json={"url": evil}).json()
    assert v["case_id"]
    r = c.get(f"/api/cases/{v['case_id']}/evidence.html")
    assert "default-src 'none'" in r.headers["content-security-policy"]
    body = r.text
    assert "<script" not in body.lower() and "<img src=x" not in body.lower()
    assert "&lt;script&gt;" in body or "%3Cscript%3E" in body


def test_frontend_has_no_inline_handlers_and_escapes():
    js = (ROOT / "frontend" / "app.js").read_text()
    html = (ROOT / "frontend" / "index.html").read_text()
    assert not re.search(r"\bon(click|error|load|mouseover)\s*=\s*\"", js + html), "inline handlers break the CSP / XSS-prone"
    assert "<script>" not in html  # only <script src=...>
    assert ".slice(0, 80))" in js and "esc(c.input).slice" not in js  # escape AFTER truncation


def test_trusted_hosts_optional():
    c = make(allowed_hosts=["127.0.0.1", "localhost", "testserver"])
    assert c.get("/api/health").status_code == 200
    assert c.get("/api/health", headers={"Host": "attacker.example"}).status_code == 400


def test_zip_never_builds_path_from_non_hex_sha(tmp_path):
    c = make()
    cid = c.get("/api/cases").json()[0]["id"]
    pack = c.get(f"/api/cases/{cid}/evidence.json").json()
    shots = tmp_path / "shots"
    shots.mkdir()
    (tmp_path / "secret.png").write_bytes(b"SECRET")  # one level above the screenshot dir
    pack["deep_scan"] = {"available": True, "screenshot_sha256": "../secret", "inputs": [], "form_domains": []}
    import io
    import zipfile
    z = zipfile.ZipFile(io.BytesIO(build_zip(pack, screenshot_dir=shots)))
    assert "screenshot.png" not in z.namelist()
    assert all(b"SECRET" not in z.read(n) for n in z.namelist())


def test_no_secrets_tracked_in_git():
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    assert ".env" not in files and not any(f.endswith((".pem", ".key")) for f in files)
    assert ".env" in (ROOT / ".gitignore").read_text().split() and ".env" in (ROOT / ".dockerignore").read_text().split()
