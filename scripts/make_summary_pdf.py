"""Render docs/summary_src/summary.html to docs/Baseera_summary.pdf (A4) with the system Chrome via Playwright."""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parent.parent
SRC, OUT = ROOT / "docs" / "summary_src" / "summary.html", ROOT / "docs" / "Baseera_summary.pdf"


async def main() -> None:
    exe = shutil.which("google-chrome") or shutil.which("chromium")
    async with async_playwright() as pw:
        b = await pw.chromium.launch(executable_path=exe, headless=True, args=["--no-sandbox"])
        p = await b.new_page()
        await p.goto(SRC.as_uri())
        await p.pdf(path=str(OUT), format="A4", print_background=True, prefer_css_page_size=True)
        await b.close()
    print("saved", OUT)


if __name__ == "__main__":
    asyncio.run(main())
