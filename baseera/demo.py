"""Seed the case store with SYNTHETIC demo cases (clearly flagged synthetic=True)."""
from __future__ import annotations

import json

from .analyze import Analyzer
from .cases import CaseStore
from .config import DATA, Settings


def seed(store: CaseStore, analyzer: Analyzer | None = None) -> int:
    if store.count(synthetic=True):
        return 0
    s = Settings()
    s.mode = "offline"
    a = Analyzer(settings=s, registry=analyzer.registry if analyzer else None, feed=analyzer.feed if analyzer else None)
    doc = json.loads((DATA / "samples" / "demo_cases.json").read_text(encoding="utf-8"))
    n = 0
    for i, c in enumerate(doc["cases"], 1):
        v = a.analyze_url(c["input"])
        store.add_verdict(v, infra=c["infra"], synthetic=True, created_at=c["created_at"], case_id=f"DEMO-{i:03d}")
        n += 1
    return n
