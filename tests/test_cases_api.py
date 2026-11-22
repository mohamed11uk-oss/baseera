import json
import zipfile
from io import BytesIO

from fastapi.testclient import TestClient

from baseera.api import create_app
from baseera.cases import CaseStore, cluster_cases
from baseera.config import Settings
from baseera.schemas import Verdict


def _v(domain, entity):
    return Verdict(input="https://" + domain, kind="url", risk=70, level="high", signals=[], explanation_ar="", explanation_en="",
                   matched_entity={"id": entity}, normalized={"registrable_domain": domain})


def test_six_synthetic_cases_form_two_clusters():
    s = CaseStore(":memory:")
    infra = [
        ("a1.com", "adpolice", {"ips": ["203.0.113.1"]}),
        ("a2.com", "adpolice", {"ips": ["203.0.113.1"], "phones": ["0560001111"]}),
        ("a3.com", "adpolice", {"phones": ["+971 56 000 1111"]}),           # same phone as a2 -> chained
        ("b1.com", "enbd", {"registrar": "R-B", "path": "/kyc/123"}),
        ("b2.com", "enbd", {"registrar": "R-B", "path": "/kyc/456"}),      # 2 weak keys (registrar+path) + target
        ("b3.com", "enbd", {"nameservers": ["ns9.x"], "registrar": "R-B"}),  # registrar + target = 2 weak keys
    ]
    for d, e, i in infra:
        s.add_verdict(_v(d, e), infra=i)
    s.add_verdict(_v("lonely.com", "fab"), infra={"ips": ["198.51.100.9"]})
    cl = cluster_cases(s.all())
    groups = sorted(sorted(c.domains) for c in cl)
    assert groups == [["a1.com", "a2.com", "a3.com"], ["b1.com", "b2.com", "b3.com"]]


def test_weak_key_alone_does_not_cluster():
    s = CaseStore(":memory:")
    s.add_verdict(_v("x1.com", "fab"), infra={})
    s.add_verdict(_v("x2.com", "fab"), infra={})  # only shared target entity (1 weak key)
    assert cluster_cases(s.all()) == []


def client():
    st = Settings()
    st.mode = "offline"
    return TestClient(create_app(settings=st, db_path=":memory:"))


def test_api_main_flows():
    c = client()
    assert c.get("/").status_code == 200
    h = c.get("/api/health").json()
    assert h["status"] == "ok" and h["mode"] == "offline" and h["cases"] == 9

    r = c.post("/api/analyze", json={"url": "https://adpolice-fines-pay.com/pay"}).json()
    assert r["level"] == "high" and r["case_id"] and r["explanation_ar"].startswith("الخطر")
    r2 = c.post("/api/analyze", json={"url": "https://www.adpolice.gov.ae/en"}).json()
    assert r2["level"] == "low" and r2["case_id"] is None

    t = c.post("/api/analyze", json={"text": "عاجل أدخل رمز التحقق hxxps://emiratesnbd-verify[.]top/otp"}).json()
    assert t["kind"] == "text" and t["level"] == "high"

    sb = c.post("/api/scan-brand", json={"brand": "enbd"}).json()
    assert "Synthetic" in sb["data_label"]
    assert any(x["official"] for x in sb["results"]) and sb["results"][0]["verdict"]["risk"] >= sb["results"][-1]["verdict"]["risk"]

    clusters = c.get("/api/clusters").json()
    assert len(clusters) >= 2 and any(cl["synthetic"] for cl in clusters)
    # the live case joins the seeded synthetic fines campaign (shared path + target)
    assert any(r["case_id"] in cl["case_ids"] for cl in clusters)
    assert c.get("/api/cases?level=high").status_code == 200


def test_evidence_pack():
    c = client()
    cid = c.get("/api/cases").json()[0]["id"]
    j = c.get(f"/api/cases/{cid}/evidence.json").json()
    assert j["case"]["id"] == cid and len(j["pack_sha256"]) == 64 and j["artifacts"][0]["sha256"]
    assert "human analyst" in j["disclaimer_en"] and j["synthetic_demo_data"] is True
    html = c.get(f"/api/cases/{cid}/evidence.html").text
    assert "ملف الأدلة" in html and "<script" not in html
    z = zipfile.ZipFile(BytesIO(c.get(f"/api/cases/{cid}/evidence.zip").content))
    assert set(z.namelist()) == {"evidence.json", "evidence.html", "MANIFEST.sha256"}
    assert json.loads(z.read("evidence.json"))["case"]["id"] == cid


def test_xss_input_is_escaped_in_evidence():
    c = client()
    r = c.post("/api/analyze", json={"url": "https://adpolice-fines-pay.com/<script>alert(1)</script>"}).json()
    html = c.get(f"/api/cases/{r['case_id']}/evidence.html").text
    assert "<script>alert(1)" not in html


def test_empty_request_422():
    assert client().post("/api/analyze", json={}).status_code == 422


def test_evidence_pdf_renders_when_chrome_available():
    import pytest

    from baseera.evidence import chrome_binary
    if not chrome_binary():
        pytest.skip("headless Chrome not installed")
    r = client().get("/api/cases/DEMO-001/evidence.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
