"""Search + Maps listings for a brand: replay fixtures (default) or SerpAPI live (optional, key from env).

Shipped fixtures are SYNTHETIC examples written by the team (not recorded from Google). The UI labels them.
"""
from __future__ import annotations

import json

from .config import DATA, Settings
from .schemas import Listing

FIXTURES = DATA / "fixtures" / "serp"
RECORDED = FIXTURES / "recorded"
SYNTH_LABEL_AR = "بيانات تجريبية مصنوعة (Synthetic) — ليست نتائج حقيقية من قوقل"
SYNTH_LABEL_EN = "Synthetic example data written by the team, NOT recorded from Google"
SERPAPI_URL = "https://serpapi.com/search.json"
BASE_PARAMS = {"gl": "ae", "hl": "en", "location": "Abu Dhabi, United Arab Emirates"}


def recorded_label(recorded_on: str) -> tuple[str, str]:
    return (f"نتائج مسجّلة (Recorded) من SerpAPI بتاريخ {recorded_on} — ليست مباشرة (not live)",
            f"recorded {recorded_on} via SerpAPI — replayed, NOT live")


def available_fixtures() -> list[str]:
    return sorted({p.stem for p in FIXTURES.glob("*.json")} | {p.stem for p in RECORDED.glob("*.json")})


def load_fixture(entity_id: str, fixtures_dir=None, recorded_dir=None) -> tuple[list[Listing], str]:
    """Recorded (real, dated) data wins over synthetic. Returns (listings, kind) where kind is
    'recorded <YYYY-MM-DD>', 'synthetic' or 'none'."""
    fixtures_dir = fixtures_dir or FIXTURES
    recorded_dir = recorded_dir or RECORDED
    rp = recorded_dir / f"{entity_id}.json"
    if rp.exists():
        doc = json.loads(rp.read_text(encoding="utf-8"))
        return [Listing(**x) for x in doc["listings"]], f"recorded {doc.get('recorded_on', 'unknown date')}"
    p = fixtures_dir / f"{entity_id}.json"
    if not p.exists():
        return [], "none"
    doc = json.loads(p.read_text(encoding="utf-8"))
    return [Listing(**x) for x in doc["listings"]], doc.get("data_label", "synthetic")


def parse_search(raw: dict, query: str) -> list[Listing]:
    """SerpAPI engine=google response -> Listings (ads first, then up to 8 organic results)."""
    out: list[Listing] = []
    for i, a in enumerate(raw.get("ads", []) or [], 1):
        out.append(Listing(source="search", query=query, rank=a.get("position") or i, is_ad=True, title=a.get("title", ""),
                           displayed_url=a.get("link") or a.get("displayed_link"), snippet=a.get("description"),
                           phone=a.get("phone")))
    for o in (raw.get("organic_results", []) or [])[:8]:
        out.append(Listing(source="search", query=query, rank=o.get("position"), title=o.get("title", ""),
                           displayed_url=o.get("link"), snippet=o.get("snippet")))
    return out


def parse_maps(raw: dict, query: str) -> list[Listing]:
    """SerpAPI engine=google_maps response -> Listings (up to 8 local results)."""
    return [Listing(source="maps", query=query, rank=lr.get("position") or i, title=lr.get("title", ""),
                    displayed_url=lr.get("website"), phone=lr.get("phone"), address=lr.get("address"))
            for i, lr in enumerate((raw.get("local_results", []) or [])[:8], 1)]


def fetch_raw(query: str, engine: str, api_key: str, client, timeout: float = 15) -> dict:
    params = {**BASE_PARAMS, "engine": engine, "q": query, "api_key": api_key}
    if engine == "google_maps":
        params["type"] = "search"
    r = client.get(SERPAPI_URL, params=params, timeout=timeout)
    r.raise_for_status()
    return r.json()


def serpapi_listings(query: str, settings: Settings, client=None) -> list[Listing]:
    """Live SerpAPI lookup (Google Search ads/organic + Google Maps local results)."""
    import httpx

    own = client is None
    client = client or httpx.Client()
    try:
        out = parse_search(fetch_raw(query, "google", settings.serpapi_key, client), query)
        out += parse_maps(fetch_raw(query, "google_maps", settings.serpapi_key, client), query)
        return out
    finally:
        if own:
            client.close()
