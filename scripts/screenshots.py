"""Capture UI screenshots into docs/screenshots (needs a running server: BASE_URL, default http://127.0.0.1:8000)."""
from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path

from playwright.async_api import async_playwright

BASE = os.getenv("BASE_URL", "http://127.0.0.1:8000")
OUT = Path(__file__).resolve().parent.parent / "docs" / "screenshots"


async def main():
    OUT.mkdir(parents=True, exist_ok=True)
    exe = shutil.which("google-chrome") or shutil.which("chromium")
    async with async_playwright() as pw:
        b = await pw.chromium.launch(executable_path=exe, headless=True, args=["--no-sandbox"])
        ctx = await b.new_context(viewport={"width": 1280, "height": 900}, bypass_csp=True)  # CSP blocks wait_for_function
        p = await ctx.new_page()
        p.set_default_timeout(90000)  # live mode: first lookups can take several seconds

        async def shot(name, full=True):
            await p.wait_for_timeout(600)
            await p.screenshot(path=str(OUT / f"{name}.png"), full_page=full)
            print("saved", name)

        await p.goto(BASE + "/#analyze")
        await p.click("a[data-ex*='adpolice-fines-pay']")
        await p.wait_for_selector(".gauge")
        await p.click("#result summary")
        await shot("01_analyze_fake_link_high")
        await p.click("a[data-ex*='adpolice.gov.ae']")
        await p.wait_for_function("document.querySelector('.gauge small') && document.querySelector('.gauge small').textContent.includes('منخفض')")
        await shot("02_analyze_official_low")
        await p.click("a[data-ex^='عاجل']")
        await p.wait_for_function("document.querySelectorAll('#result li').length > 0")
        await shot("03_analyze_sms_message")
        await p.click("button[data-tab='scan']")
        await p.select_option("#brand", "enbd")
        await p.click("#scan_go")
        await p.wait_for_selector("#scan_out table")
        await shot("04_search_maps_enbd")
        await p.select_option("#brand", "adpolice")
        await p.click("#scan_go")
        await p.wait_for_function("document.querySelector('#scan_out b') && document.querySelector('#scan_out b').textContent.includes('شرطة')")
        await shot("05_search_maps_adpolice")
        await p.click("button[data-tab='dash']")
        await p.wait_for_selector(".cl svg")
        await shot("06_analyst_dashboard")
        await p.click(".cl .row button")
        await p.wait_for_selector("#modal:not(.hidden) .gauge")
        await shot("07_case_detail", full=False)
        await p.click("#close")
        await p.click("button[data-tab='health']")
        await p.wait_for_selector("#registry_out table")
        await shot("08_health_registry")
        await p.click("#lang")
        await p.click("button[data-tab='analyze']")
        await p.click("a[data-ex*='adpolice-fines-pay']")
        await p.wait_for_selector(".gauge")
        await shot("09_english_toggle")
        cid = await p.evaluate("fetch('/api/cases').then(r=>r.json()).then(c=>c.find(x=>x.id.startsWith('DEMO')).id)")
        await p.goto(f"{BASE}/api/cases/{cid}/evidence.html")
        await shot("10_evidence_pack")
        await b.close()


if __name__ == "__main__":
    asyncio.run(main())
