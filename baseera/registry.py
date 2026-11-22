"""Official Entity Registry loader + lookups."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from .config import DATA
from .phones import canonical

REQUIRED = ("id", "entity_name_ar", "entity_name_en", "category", "official_domains", "source_url", "verified_on", "status")
CATEGORIES = {"telecom", "bank", "government", "police", "delivery", "utility", "airline", "retail"}


class RegistryError(ValueError):
    pass


@dataclass
class Entity:
    id: str
    entity_name_ar: str
    entity_name_en: str
    category: str
    official_domains: list[str]
    official_phones: list[dict]
    keywords: list[str]
    source_url: str
    verified_on: str
    status: str
    note: str = ""
    phone_set: set[str] = field(default_factory=set)

    @property
    def labels(self) -> list[str]:
        """Registrable labels of official domains, e.g. adpolice for adpolice.gov.ae."""
        from .normalize import normalize
        return sorted({normalize(d).label for d in self.official_domains})

    def public(self) -> dict:
        return {k: getattr(self, k) for k in ("id", "entity_name_ar", "entity_name_en", "category", "official_domains",
                                                "official_phones", "source_url", "verified_on", "status", "note")}


class Registry:
    def __init__(self, entities: list[Entity]):
        self.entities = entities
        self.by_id = {e.id: e for e in entities}
        self._domains = {d.lower(): e for e in entities for d in e.official_domains}
        self._phones = {p: e for e in entities for p in e.phone_set}

    def official_for_host(self, host: str) -> Entity | None:
        host = host.lower().rstrip(".")
        for d, e in self._domains.items():
            if host == d or host.endswith("." + d):
                return e
        return None

    def entity_for_phone(self, number: str) -> Entity | None:
        return self._phones.get(canonical(number))

    def match_name(self, text: str) -> Entity | None:
        """Find the entity a listing title / message claims to be (keyword match, longest first)."""
        t = " " + re.sub(r"[^\w&\u0600-\u06FF]+", " ", text.lower()) + " "
        best, best_len = None, 0
        for e in self.entities:
            for k in [*e.keywords, e.entity_name_en.lower(), e.entity_name_ar]:
                kk = " " + re.sub(r"[^\w&\u0600-\u06FF]+", " ", k.lower()).strip() + " "
                if len(kk.strip()) >= 2 and kk in t and len(kk) > best_len:
                    best, best_len = e, len(kk)
        return best


def _validate(raw: dict) -> Entity:
    missing = [k for k in REQUIRED if not raw.get(k)]
    if missing:
        raise RegistryError(f"registry entry {raw.get('id', '?')} missing {missing} (source_url + verified_on are mandatory)")
    if raw["category"] not in CATEGORIES:
        raise RegistryError(f"{raw['id']}: unknown category {raw['category']}")
    if raw["status"] not in ("verified", "domain_only", "example"):
        raise RegistryError(f"{raw['id']}: bad status {raw['status']}")
    phones = raw.get("official_phones") or []
    if raw["status"] == "domain_only" and phones:
        raise RegistryError(f"{raw['id']}: domain_only entries must not list phones")
    e = Entity(id=raw["id"], entity_name_ar=raw["entity_name_ar"], entity_name_en=raw["entity_name_en"],
               category=raw["category"], official_domains=[d.lower() for d in raw["official_domains"]],
               official_phones=phones, keywords=[k.lower() for k in raw.get("keywords", [])],
               source_url=raw["source_url"], verified_on=str(raw["verified_on"]), status=raw["status"],
               note=raw.get("note", ""))
    e.phone_set = {canonical(p["number"]) for p in phones}
    return e


def load_registry(path: Path | None = None) -> Registry:
    path = path or DATA / "registry" / "entities.yaml"
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    ents = [_validate(r) for r in doc.get("entities", [])]
    ids = [e.id for e in ents]
    if len(ids) != len(set(ids)):
        raise RegistryError("duplicate entity ids")
    return Registry(ents)


@lru_cache(maxsize=1)
def default_registry() -> Registry:
    return load_registry()
