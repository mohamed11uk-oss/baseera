"""API contract (from the plan) as pydantic v2 models."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Level = Literal["low", "medium", "high"]


class Signal(BaseModel):
    id: str
    source: str
    score: float = Field(ge=0, le=1, description="severity 0..1")
    weight: float = 0
    contribution: float = 0
    evidence: str = ""
    available: bool = True
    data: dict = Field(default_factory=dict)


class Listing(BaseModel):
    source: Literal["search", "maps", "manual"] = "manual"
    query: str | None = None
    rank: int | None = None
    is_ad: bool = False
    title: str
    displayed_url: str | None = None
    resolved_domain: str | None = None
    phone: str | None = None
    address: str | None = None
    snippet: str | None = None


class DeepCheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096, description="URL to look up in VirusTotal (manual deep check)")


class AnalyzeRequest(BaseModel):
    url: str | None = None
    text: str | None = None
    listing: Listing | None = None
    save_case: bool = True
    deep: bool = Field(False, description="Opt-in deep scan: open the URL in the headless Chrome sandbox "
                       "(screenshot + form fields). Needs live mode and SOURCE_SANDBOX != off.")


class Verdict(BaseModel):
    input: str
    kind: Literal["url", "text", "listing"]
    risk: int
    level: Level
    signals: list[Signal]
    explanation_ar: str
    explanation_en: str
    matched_entity: dict | None = None
    normalized: dict = Field(default_factory=dict)
    sub_verdicts: list["Verdict"] = Field(default_factory=list)
    campaign_id: str | None = None
    case_id: str | None = None
    screenshot_url: str | None = None
    mode: str = "live"
    analyzed_at: str = ""


class ListingVerdict(BaseModel):
    listing: Listing
    verdict: Verdict
    official: bool
    reason_ar: str
    reason_en: str


class AnalystLogin(BaseModel):
    token: str = Field(max_length=512)


class ScanBrandRequest(BaseModel):
    brand: str
    country: str = "AE"


class ScanBrandResponse(BaseModel):
    brand: str
    entity: dict | None
    data_label: str
    results: list[ListingVerdict]


class Case(BaseModel):
    id: str
    created_at: str
    input: str
    kind: str
    risk: int
    level: Level
    entity_id: str | None = None
    registrable_domain: str | None = None
    cluster_id: str | None = None
    synthetic: bool = False
    infra: dict = Field(default_factory=dict)
    verdict: dict = Field(default_factory=dict)


class Cluster(BaseModel):
    id: str
    case_ids: list[str]
    domains: list[str]
    entity_ids: list[str]
    shared: list[str]
    first_seen: str
    last_seen: str
    max_risk: int
    synthetic: bool = False
