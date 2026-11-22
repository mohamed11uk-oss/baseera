"""Lookalike detection against official entity domains.

Techniques: typosquat (edit distance), homoglyph/confusable skeleton, brand keyword in another domain,
TLD swap, brand in sub-domain of an unrelated domain.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from ..normalize import NormalizedURL
from ..registry import Entity, Registry
from ..schemas import Signal

# Confusables -> latin skeleton (subset of Unicode TR39 that matters for latin brand names + leetspeak)
CONFUSABLE = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ӏ": "l", "ј": "j", "ԁ": "d",
    "ѕ": "s", "һ": "h", "ԛ": "q", "ԝ": "w", "ɑ": "a", "ο": "o", "ν": "v", "τ": "t", "κ": "k", "ι": "i", "ϲ": "c",
    "0": "o", "1": "l", "i": "l", "!": "l", "|": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a",
    "$": "s",
}
MULTI = [("rn", "m"), ("vv", "w"), ("cl", "d")]


def skeleton(s: str) -> str:
    s = unicodedata.normalize("NFKC", s.lower())
    s = "".join(CONFUSABLE.get(c, c) for c in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    for a, b in MULTI:
        s = s.replace(a, b)
    return re.sub(r"[^a-z0-9]", "", s)


def damerau(a: str, b: str) -> int:
    """Optimal string alignment distance."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


@dataclass
class Match:
    entity: Entity
    technique: str
    severity: float
    evidence: str
    official_domain: str = ""
    term: str = ""


def _tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9\u0600-\u06ff]+", s.lower()) if t]


def _brand_terms(e: Entity) -> list[str]:
    """Latin brand terms usable inside hostnames (no spaces)."""
    terms = set(e.labels)
    terms |= {k.replace(" ", "") for k in e.keywords if re.fullmatch(r"[a-z0-9 &]+", k)}
    return sorted(t for t in terms if t and "&" not in t)


def detect(n: NormalizedURL, registry: Registry) -> Match | None:
    if n.is_ip:
        return None
    if registry.official_for_host(n.host):
        return None
    label = n.label.lower()
    uni = n.host_unicode
    if n.suffix and uni.endswith("." + n.suffix):
        uni = uni[: -len(n.suffix) - 1]
    uni_label = uni.split(".")[-1]
    sk_label = skeleton(uni_label)
    sub_tokens = _tokens(n.subdomain)
    label_tokens = _tokens(label)
    best: Match | None = None

    def consider(m: Match):
        nonlocal best
        if best is None or m.severity > best.severity:
            best = m

    for e in registry.entities:
        for off_dom in e.official_domains:
            off_label = off_dom.split(".")[0]
            off_suffix = off_dom[len(off_label) + 1:]
            # (d) TLD swap: same label, different suffix
            if label == off_label and n.suffix != off_suffix:
                consider(Match(e, "tld_swap", 1.0,
                               f"'{n.registrable_domain}' copies the official name '{off_dom}' with a different ending (.{n.suffix})", off_dom))
                continue
            # (c) homoglyph skeleton equal but text differs
            if len(off_label) >= 4 and sk_label == skeleton(off_label) and uni_label != off_label:
                consider(Match(e, "homoglyph", 1.0,
                               f"'{n.host_unicode}' looks identical to '{off_dom}' using look-alike characters", off_dom))
                continue
            # (a) typosquat
            if len(off_label) >= 5 and label != off_label:
                dist = damerau(label, off_label)
                limit = 1 if len(off_label) < 7 else 2
                if 0 < dist <= limit:
                    consider(Match(e, "typosquat", 0.9 if dist == 1 else 0.8,
                                   f"'{n.registrable_domain}' is {dist} character edit(s) away from the official '{off_dom}'", off_dom))
        # (b) brand keyword inside another registrable domain / (e) brand in sub-domain
        for term in _brand_terms(e):
            if len(term) >= 5:
                in_label = term in label and label != term
                in_sub = any(term in t for t in sub_tokens)
            else:  # short brand names only as whole tokens to avoid false positives (dib vs adib)
                in_label = term in label_tokens and label != term
                in_sub = term in sub_tokens
            if not in_label and len(term) >= 6 and "-" in label and term in label.replace("-", ""):
                in_label = True  # emirates-post-parcel -> emiratespost
            if not in_sub and len(term) >= 5:
                in_sub = any(skeleton(t) == skeleton(term) for t in sub_tokens)
            if not in_label and len(term) >= 5 and label != term:
                in_label = any(skeleton(t) == skeleton(term) for t in label_tokens if t != label or "-" in label)
            if in_label:
                consider(Match(e, "brand_keyword", 0.9,
                               f"Domain '{n.registrable_domain}' contains the brand name '{term}' but is not an official {e.entity_name_en} domain", e.official_domains[0], term))
            elif in_sub:
                consider(Match(e, "brand_in_subdomain", 0.9,
                               f"Brand name '{term}' is used as a sub-domain of the unrelated domain '{n.registrable_domain}'", e.official_domains[0], term))
    return best


def lookalike_signal(n: NormalizedURL, registry: Registry) -> tuple[Signal | None, Match | None]:
    m = detect(n, registry)
    if not m:
        return None, None
    return Signal(id="lookalike", source="registry", score=m.severity, evidence=m.evidence,
                  data={"technique": m.technique, "entity_id": m.entity.id, "domain": n.registrable_domain,
                        "official_domain": m.official_domain, "host": n.host_unicode, "term": m.term}), m


def embedded_official_signal(n: NormalizedURL, registry: Registry) -> Signal | None:
    """An official registry domain written inside the path or query of a NON-official host
    (e.g. https://pay-fines.top/www.adpolice.gov.ae/fines or ?ref=https://www.rta.ae). Readers see the familiar
    name and stop reading. Legit redirectors (google.com/url?q=..., web.archive.org) also do this, so the weight is
    kept small: on its own it stays 'low'; it only tips a URL over when other lure signals are present."""
    from urllib.parse import unquote

    if not n.is_ip and registry.official_for_host(n.host):
        return None
    tail = unquote(unquote(f"{n.path}?{n.query}")).lower()
    for d, ent in registry._domains.items():
        if re.search(r"(?<![a-z0-9-])" + re.escape(d) + r"(?![a-z0-9-])", tail):
            return Signal(id="official_domain_in_url", source="registry", score=1.0,
                          data={"entity_id": ent.id, "official_domain": d, "host": n.host},
                          evidence=f"Official domain {d} ({ent.entity_name_en}) appears in the path/query of {n.host}, "
                                   f"which is not an official domain")
    return None
