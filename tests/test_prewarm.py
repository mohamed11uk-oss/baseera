"""scripts/prewarm.py must time exactly the demo inputs listed in docs/demo.md (Prompt 7.2). Fast: no app is started."""
import html
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _prewarm():
    spec = importlib.util.spec_from_file_location("prewarm", ROOT / "scripts" / "prewarm.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["prewarm"] = mod  # dataclasses resolve their module via sys.modules
    spec.loader.exec_module(mod)
    return mod


def _demo_rows():
    """(tab, input) per row of the demo table; a blank Tab cell inherits the row above."""
    rows, tab = [], None
    for line in (ROOT / "docs" / "demo.md").read_text(encoding="utf-8").splitlines():
        if not line.startswith("|") or line.startswith("|---") or line.startswith("| Time"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        tab = cells[1] or tab
        rows.append((tab, cells[2]))
    return rows


def test_script_rows_match_demo_md():
    pw = _prewarm()
    demo = _demo_rows()
    assert len(demo) >= 6
    assert [(r.tab, r.input) for r in pw.DEMO_ROWS] == demo


def test_example_domains_are_the_ones_requested():
    for row in _prewarm().DEMO_ROWS:
        for dom in re.findall(r"`([^`]+)`", row.input):
            assert row.steps and all(dom in (s.body or {}).get("url", "") for s in row.steps), row.input


def test_sms_text_matches_frontend_example():
    pw = _prewarm()
    exs = [html.unescape(x) for x in re.findall(r'data-ex="([^"]+)"', (ROOT / "frontend" / "index.html").read_text(encoding="utf-8"))]
    assert pw.SMS_EXAMPLE in exs
    urls = {(s.body or {}).get("url") for r in pw.DEMO_ROWS for s in r.steps}
    assert {x for x in exs if x.startswith("http")} <= urls


def test_every_row_is_timed_or_explicitly_skipped():
    for row in _prewarm().DEMO_ROWS:
        assert bool(row.steps) != bool(row.skip_reason), row.input


def test_demo_brand_is_in_registry_with_fixture(reg):
    assert reg.match_name("Emirates NBD").id == "enbd"
    assert (ROOT / "data" / "fixtures" / "serp" / "enbd.json").exists()
