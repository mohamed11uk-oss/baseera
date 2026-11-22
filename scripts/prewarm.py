"""Pre-warm caches for every demo input in docs/demo.md and time each one against a 5 s budget (Prompt 7.2).

Usage:
  .venv/bin/python scripts/prewarm.py                      # replay/offline, in-process app, writes docs/timings.md
  .venv/bin/python scripts/prewarm.py --mode live          # live lookups in-process: warms data/runtime/*.json caches
  .venv/bin/python scripts/prewarm.py --base-url http://127.0.0.1:8000   # hit the running demo server (warms ITS caches)

Each step is run twice: "cold" (first call) and "warm" (second call, what the audience sees after pre-warming).
PASS = HTTP 200, the expected outcome from docs/demo.md, and warm time < 5 s. Cold time is reported, not judged.

The step list below is the single source for the demo inputs. tests/test_prewarm.py checks that it matches the
table in docs/demo.md row by row, and that the SMS text equals the example link in frontend/index.html.
In-process runs use a throwaway case DB so the real data/runtime/baseera.db is not touched.
"""
from __future__ import annotations

import argparse
import os
import platform
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

BUDGET_S = 5.0
SMS_EXAMPLE = ("عاجل: تم تعليق بطاقتك من بنك الإمارات دبي الوطني. حدّث بياناتك وأدخل رمز التحقق على "
               "hxxps://emiratesnbd-verify[.]top/otp أو اتصل 0500001234")


@dataclass
class Step:
    label: str
    method: str
    path: str  # may contain {cid} / {brand}, filled at run time
    body: dict | None = None
    expect: str | None = None  # "high" / "low" for verdicts, "synthetic" for scan labels, "clusters" etc.
    optional: bool = False  # e.g. PDF needs headless Chrome: 503 is reported as SKIP, not FAIL


@dataclass
class Row:
    tab: str  # Tab column of docs/demo.md (blank cells inherit the row above)
    input: str  # Input column of docs/demo.md, verbatim
    steps: list[Step] = field(default_factory=list)
    skip_reason: str | None = None  # rows that are not an API call (slides) or cannot run here


TAB_LINK, TAB_SERP, TAB_DASH, TAB_HEALTH = "فحص رابط أو رسالة", "نتائج البحث والخرائط", "لوحة المحلل", "الحالة والسجل"

DEMO_ROWS: list[Row] = [
    Row("—", "Problem slide", skip_reason="slide, no API call"),
    Row(TAB_LINK, "click example `adpolice-fines-pay.com`",
        [Step("analyze adpolice-fines-pay.com", "POST", "/api/analyze", {"url": "https://adpolice-fines-pay.com/pay"}, "high")]),
    Row(TAB_LINK, "click example `adpolice.gov.ae`",
        [Step("analyze adpolice.gov.ae", "POST", "/api/analyze", {"url": "https://www.adpolice.gov.ae/en"}, "low")]),
    Row(TAB_LINK, 'click example "رسالة SMS"',
        [Step("analyze SMS example", "POST", "/api/analyze", {"text": SMS_EXAMPLE}, "high")]),
    Row(TAB_SERP, "Emirates NBD → افحص النتائج",
        [Step("scan-brand enbd", "POST", "/api/scan-brand", {"brand": "enbd", "country": "AE"}, "synthetic")]),
    Row(TAB_DASH, "open campaign CMP-…",
        [Step("clusters", "GET", "/api/clusters", expect="clusters"),
         Step("cases", "GET", "/api/cases"),
         Step("evidence.html", "GET", "/api/cases/{cid}/evidence.html"),
         Step("evidence.zip", "GET", "/api/cases/{cid}/evidence.zip"),
         Step("evidence.pdf", "GET", "/api/cases/{cid}/evidence.pdf", optional=True)]),
    Row(TAB_LINK, "tick «فحص معمّق (Deep scan)» on a page you control",
        skip_reason="optional; needs a live page you control and headless Chrome, not timed here"),
    Row(TAB_HEALTH, "—", [Step("health", "GET", "/api/health"), Step("registry", "GET", "/api/registry")]),
]


def demo_brand_steps(brands: list[dict]) -> list[Step]:
    """'The demo brands': every registry entity with Search/Maps replay data (has_fixture), besides the scripted one."""
    return [Step(f"scan-brand {b['id']}", "POST", "/api/scan-brand", {"brand": b["id"], "country": "AE"}, "synthetic")
            for b in brands if b.get("has_fixture") and b["id"] != "enbd"]


def make_client(args):
    """Return (client, mode_label). In-process FastAPI TestClient, or httpx against a running server."""
    headers = {"x-analyst-token": os.environ["ANALYST_TOKEN"]} if os.getenv("ANALYST_TOKEN") else {}
    if args.base_url:
        import httpx
        return httpx.Client(base_url=args.base_url.rstrip("/"), headers=headers, timeout=60), f"server {args.base_url}"
    os.environ["BASEERA_MODE"] = args.mode
    from fastapi.testclient import TestClient

    from baseera.api import create_app
    from baseera.config import Settings

    s = Settings()
    s.mode = args.mode
    s.allowed_hosts = []  # TestClient host is "testserver"
    db = Path(tempfile.mkdtemp(prefix="baseera-prewarm-")) / "cases.db"
    return TestClient(create_app(settings=s, db_path=str(db)), headers=headers), f"in-process, {args.mode}"


def check(step: Step, resp) -> tuple[bool, str]:
    """(expected outcome met, short result text)."""
    if step.expect in ("high", "low"):
        j = resp.json()
        return j.get("level") == step.expect, f"{j.get('level')} {j.get('risk')}"
    if step.expect == "synthetic":
        j = resp.json()
        ok = "synthetic" in j.get("data_label", "").lower() or "recorded" in j.get("data_label", "").lower()
        return ok, f"{len(j.get('results', []))} listings, labelled"
    if step.expect == "clusters":
        n = len(resp.json())
        return n > 0, f"{n} campaigns"
    if resp.headers.get("content-type", "").startswith("application/json"):
        j = resp.json()
        return True, f"{len(j)} items" if isinstance(j, list) else "ok"
    return True, f"{len(resp.content)} bytes"


def timed(client, step: Step, ctx: dict):
    path = step.path.format(**ctx)
    t = time.perf_counter()
    r = client.request(step.method, path, json=step.body) if step.body is not None else client.request(step.method, path)
    return r, time.perf_counter() - t


def run(client) -> list[dict]:
    rows_out = []
    ctx: dict = {}
    brands = client.get("/api/brands").json()
    plan = [(row, row.steps) for row in DEMO_ROWS] + [(Row("(demo brands)", "brand scan"), demo_brand_steps(brands))]
    for row, steps in plan:
        shown = row.input if row.input != "—" else f"({row.tab} tab)"
        if row.skip_reason:
            rows_out.append({"row": shown, "step": "", "cold": None, "warm": None, "result": row.skip_reason,
                             "status": "SKIP"})
            continue
        for st in steps:
            if "{cid}" in st.path and "cid" not in ctx:
                cl = client.get("/api/clusters").json()
                if not cl:
                    rows_out.append({"row": shown, "step": st.label, "cold": None, "warm": None,
                                     "result": "no campaign to open", "status": "FAIL"})
                    continue
                ctx["cid"] = cl[0]["case_ids"][0]
            r1, cold = timed(client, st, ctx)
            r2, warm = timed(client, st, ctx)
            if st.optional and r2.status_code == 503:
                rows_out.append({"row": shown, "step": st.label, "cold": cold, "warm": warm,
                                 "result": "503: renderer unavailable here", "status": "SKIP"})
                continue
            if r2.status_code != 200:
                ok, res = False, f"HTTP {r2.status_code}"
            else:
                ok, res = check(st, r2)
                if not ok:
                    res = f"unexpected: {res} (wanted {st.expect})"
            status = "PASS" if ok and warm < BUDGET_S else "FAIL"
            rows_out.append({"row": shown, "step": st.label, "cold": cold, "warm": warm, "result": res, "status": status})
    return rows_out


LIVE_NOTE = """Live mode: NOT measured in this run. The build box has no API keys and limited egress, so live lookups
(RDAP, TLS, crt.sh, .ae WHOIS, SerpAPI) could not be timed honestly. Before presenting, on the demo laptop run
`./run.sh` in one terminal, then `.venv/bin/python scripts/prewarm.py --base-url http://127.0.0.1:8000 --out docs/timings-live.md`
(warms the running server's caches; first live lookups can take 10 to 25 s, warm times are what counts)."""


def fmt_s(x):
    return "" if x is None else f"{x:.3f}"


def table(rows: list[dict]) -> str:
    out = ["| Demo row (docs/demo.md) | Step | Cold (s) | Warm (s) | Result | < 5 s |", "|---|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['row']} | {r['step']} | {fmt_s(r['cold'])} | {fmt_s(r['warm'])} | {r['result']} | {r['status']} |")
    return "\n".join(out)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--mode", choices=["offline", "live"], default="offline", help="in-process mode (ignored with --base-url)")
    p.add_argument("--base-url", help="time a running server instead of an in-process app")
    p.add_argument("--out", default=str(ROOT / "docs" / "timings.md"), help="Markdown output ('' to skip writing)")
    args = p.parse_args(argv)
    client, label = make_client(args)
    data_mode = client.get("/api/health").json().get("data_mode", "?")
    label += f", data_mode={data_mode}"
    rows = run(client)
    tbl = table(rows)
    print(tbl)
    fails = sum(r["status"] == "FAIL" for r in rows)
    passed = sum(r["status"] == "PASS" for r in rows)
    summary = f"{passed} PASS, {fails} FAIL, {sum(r['status'] == 'SKIP' for r in rows)} SKIP (budget {BUDGET_S:.0f} s, judged on warm time)"
    print("\n" + summary)
    if args.out:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        doc = f"""# Demo timings (generated by scripts/prewarm.py, do not edit by hand)

Run: {now} | target: {label} | Python {platform.python_version()} on {platform.system()} {platform.machine()}

{summary}

{tbl}

How to read this:
* Each step runs twice. Cold = first call, Warm = second call (what the audience sees after pre-warming).
  PASS needs HTTP 200, the outcome docs/demo.md expects, and a warm time under 5 s.
* Replay/offline numbers measure the engine only: no network lookups, Search/Maps rows are SYNTHETIC fixtures.
* SKIP rows are not API calls (slides) or need things not available on the build box (a live page you control,
  headless Chrome for PDF).

{LIVE_NOTE if data_mode != "live" else "This run used live lookups (see target above)."}
"""
        Path(args.out).write_text(doc, encoding="utf-8")
        print(f"wrote {args.out}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
