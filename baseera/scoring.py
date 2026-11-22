"""Explainable weighted scoring with hard overrides. Weights live in data/weights.yaml."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from .config import DATA
from .schemas import Signal


@lru_cache(maxsize=4)
def load_weights(path: str | None = None) -> dict:
    return yaml.safe_load(Path(path or DATA / "weights.yaml").read_text())


def level_for(score: int, w: dict) -> str:
    t = w["thresholds"]
    return "high" if score >= t["high"] else "medium" if score >= t["medium"] else "low"


def score(signals: list[Signal], *, official: bool = False, blocklisted: bool = False,
          weights: dict | None = None, disabled: set[str] | None = None) -> tuple[int, str]:
    """Fill weight/contribution on each signal and return (risk 0..100, level).

    Overrides: blocklist hit => at least 'high'; exact official domain => 'low'.
    `disabled` lets the evaluator run ablations.
    """
    w = weights or load_weights()
    disabled = disabled or set()
    total = 0.0
    for s in signals:
        s.weight = float(w["weights"].get(s.id, 0))
        s.contribution = round(s.weight * s.score, 2) if s.available and s.id not in disabled else 0.0
        total += s.contribution
    risk = int(round(max(0.0, min(100.0, total))))
    if blocklisted and "blocklist_hit" not in disabled:
        risk = max(risk, w["thresholds"]["high"])
    if official:
        risk = min(risk, w["thresholds"]["medium"] - 1)
        return risk, "low"
    return risk, level_for(risk, w)
