"""Record real Search + Maps results for the demo brands ONCE via SerpAPI, for replay mode (Prompt 3.6).

  SERPAPI_KEY=... .venv/bin/python scripts/record_demo_fixtures.py [--brands enbd,fab] [--per-lang 1] [--dry-run]

Writes data/fixtures/serp/recorded/<brand>.json with data_label "recorded" + recorded_on date; the API/UI then label
that data "recorded <date>" (never "live"). Without SERPAPI_KEY it prints a clear message and records nothing.
Each (query, engine) pair costs one SerpAPI search: check your plan's quota before running (docs/DECISIONS.md).
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from baseera.config import DATA, serpapi_key_from_env  # noqa: E402
from baseera.registry import default_registry  # noqa: E402
from baseera.serp import RECORDED, fetch_raw, parse_maps, parse_search  # noqa: E402

NO_KEY_MSG = ("SERPAPI_KEY is not set: nothing recorded. (SERPAPI_API_KEY is accepted too, also from .env.)\n"
              "Replay mode keeps using the SYNTHETIC fixtures in data/fixtures/serp/ (labelled 'synthetic').\n"
              "To record real results once: export SERPAPI_KEY=<your key> and re-run this script.")


def plan(brands: list[str], per_lang: int, langs: list[str], queries_path: Path = DATA / "queries.yaml") -> list[dict]:
    cfg = yaml.safe_load(queries_path.read_text(encoding="utf-8"))
    reg = default_registry()
    out = []
    for b in brands:
        ent = reg.by_id.get(b)
        if not ent:
            raise SystemExit(f"unknown registry id: {b}")
        for lang in langs:
            tmpls = [t for t in cfg["templates"][lang] if not t.get("categories") or ent.category in t["categories"]]
            for t in tmpls[:per_lang]:
                q = t["q"].format(name_en=ent.entity_name_en, name_ar=ent.entity_name_ar)
                for eng in t["engines"]:
                    out.append({"brand": b, "lang": lang, "query": q, "engine": eng})
    return out


def _scrub(obj, secret: str):
    """Remove the API key anywhere it might be echoed back in a raw response."""
    if isinstance(obj, dict):
        return {k: _scrub(v, secret) for k, v in obj.items() if k != "api_key"}
    if isinstance(obj, list):
        return [_scrub(v, secret) for v in obj]
    if isinstance(obj, str) and secret and secret in obj:
        return obj.replace(secret, "***")
    return obj


def record(items: list[dict], api_key: str, client, out_dir: Path = RECORDED, today: str | None = None) -> list[Path]:
    today = today or datetime.now(timezone.utc).date().isoformat()
    by_brand: dict[str, dict] = {}
    for it in items:
        doc = by_brand.setdefault(it["brand"], {
            "data_label": "recorded", "recorded_on": today, "source": "SerpAPI (Google Search + Google Maps, gl=ae)",
            "note": f"REAL results recorded via SerpAPI on {today} for replay. Replayed data is NOT live.",
            "queries": [], "errors": [], "listings": [], "raw": []})
        try:
            raw = fetch_raw(it["query"], it["engine"], api_key, client)
        except Exception as e:  # noqa: BLE001 - record what we can, report the rest
            doc["errors"].append({"query": it["query"], "engine": it["engine"], "error": type(e).__name__})
            continue
        doc["queries"].append({"query": it["query"], "engine": it["engine"], "lang": it["lang"]})
        parsed = parse_maps(raw, it["query"]) if it["engine"] == "google_maps" else parse_search(raw, it["query"])
        doc["listings"] += [x.model_dump() for x in parsed]
        doc["raw"].append({"query": it["query"], "engine": it["engine"], "response": _scrub(raw, api_key)})
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for b, doc in by_brand.items():
        if not doc["listings"]:
            print(f"{b}: no listings recorded ({len(doc['errors'])} errors); file not written")
            continue
        p = out_dir / f"{b}.json"
        p.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
        paths.append(p)
        print(f"{b}: {len(doc['listings'])} listings from {len(doc['queries'])} searches -> {p}")
    return paths


def main(argv=None, client=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    cfg = yaml.safe_load((DATA / "queries.yaml").read_text(encoding="utf-8"))
    ap.add_argument("--brands", default=",".join(cfg["demo_brands"]))
    ap.add_argument("--langs", default="en,ar")
    ap.add_argument("--per-lang", type=int, default=1, help="templates per language per brand")
    ap.add_argument("--out", default=str(RECORDED))
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    items = plan([b.strip() for b in a.brands.split(",") if b.strip()], a.per_lang, a.langs.split(","))
    print(f"plan: {len(items)} SerpAPI searches for {len({i['brand'] for i in items})} brands")
    if a.dry_run:
        for i in items:
            print(f"  {i['brand']:12s} {i['engine']:12s} {i['query']}")
        return 0
    key = serpapi_key_from_env()
    if not key:
        print(NO_KEY_MSG)
        return 2
    own = client is None
    if own:
        import httpx
        client = httpx.Client(timeout=20)
    try:
        record(items, key, client, Path(a.out))
    finally:
        if own:
            client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
