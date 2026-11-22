"""Parallel API requests must not fail: the shared SQLite connection is serialised by CaseStore._lock."""
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from baseera.api import create_app
from baseera.cases import CaseStore
from baseera.config import Settings
from baseera.schemas import Verdict


def _client(tmp_path):
    st = Settings()
    st.mode = "offline"
    return TestClient(create_app(settings=st, db_path=str(tmp_path / "cases.db")))


def test_parallel_mixed_requests_never_500(tmp_path):
    c = _client(tmp_path)
    reqs = []
    for i in range(30):
        reqs.append(("post", "/api/analyze", {"url": f"https://adpolice-fines-{i}.top/pay"}))
        reqs.append(("get", "/api/cases", None))
        reqs.append(("get", "/api/clusters", None))
        reqs.append(("get", "/api/health", None))
        reqs.append(("post", "/api/scan-brand", {"brand": "enbd"}))

    def call(r):
        method, url, body = r
        return (c.post(url, json=body) if method == "post" else c.get(url)).status_code

    with ThreadPoolExecutor(max_workers=16) as ex:
        codes = list(ex.map(call, reqs))
    assert codes.count(200) == len(reqs), {code: codes.count(code) for code in set(codes)}
    assert len(c.get("/api/cases").json()) >= 30


def test_casestore_concurrent_writes_and_reads(tmp_path):
    s = CaseStore(tmp_path / "c.db")
    errors = []

    def work(i):
        try:
            v = Verdict(input=f"https://x{i}.com", kind="url", risk=50, level="medium", signals=[], explanation_ar="",
                        explanation_en="", normalized={"registrable_domain": f"x{i}.com"})
            s.add_verdict(v)
            s.list()
            s.count()
        except Exception as e:  # pragma: no cover - only on regression
            errors.append(repr(e))

    threads = [threading.Thread(target=work, args=(i,)) for i in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert s.count() == 40
