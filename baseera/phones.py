"""UAE phone normalisation and classification (no external dependency)."""
from __future__ import annotations

import re

PHONE_RE = re.compile(r"(?:\+|00)?(?:971[\s-]?)?\(?0?\d{1,3}\)?(?:[\s-]?\d){3,9}")


def canonical(number: str) -> str:
    """Return the national significant number for UAE numbers: '+971 2 691 5555' -> '26915555',
    '600 54 0000' -> '600540000', '+971600522222' -> '600522222', short codes unchanged ('999')."""
    d = re.sub(r"\D", "", number or "")
    if d.startswith("00971"):
        d = d[5:]
    elif d.startswith("971") and len(d) > 9:
        d = d[3:]
    if d.startswith("0") and len(d) >= 9:
        d = d[1:]
    return d


def classify(number: str) -> str:
    d = canonical(number)
    if len(d) <= 5:
        return "short_code"
    if d.startswith("800"):
        return "toll_free"
    if d.startswith("600"):
        return "unified"
    if d.startswith("900"):
        return "premium"
    if d.startswith("5") and len(d) == 9:
        return "mobile"
    if len(d) == 8 and d[0] in "234679":
        return "landline"
    if len(d) > 9:
        return "international"
    return "unknown"


def e164(number: str) -> str:
    d = canonical(number)
    if classify(number) in ("short_code", "international"):
        return d if classify(number) == "short_code" else "+" + re.sub(r"\D", "", number).lstrip("0")
    return "+971" + d


def extract_phones(text: str) -> list[str]:
    out = []
    for m in PHONE_RE.finditer(text or ""):
        s = m.group().strip()
        digits = re.sub(r"\D", "", s)
        if 7 <= len(digits) <= 14 and s not in out:
            out.append(s)
    return out
