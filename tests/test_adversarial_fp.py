"""Prompt 6.2: adversarial false-positive suite, driven by data/testset/labeled.csv.

Benign group 'adversarial' = real UAE sites, official domains with deep paths / query strings / odd casing, shared
platforms and shorteners. They must stay 'low', except rows the team documents as an expected false positive.
Group 'synthetic_adversarial' = SYNTHETIC fraud shapes built around the same tricks: they must reach at least 'medium'.
"""
import csv
from pathlib import Path

import pytest

from baseera.explain import _ar, explain
from baseera.normalize import normalize
from baseera.signals.lookalike import embedded_official_signal

CSV = Path(__file__).resolve().parent.parent / "data" / "testset" / "labeled.csv"


def _rows(group: str) -> list[dict]:
    with open(CSV, encoding="utf-8") as f:
        return [r for r in csv.DictReader(ln for ln in f if not ln.startswith("#")) if r["group"] == group]


ADV = _rows("adversarial")
EXPECTED_FP = [r["url"] for r in ADV if "expected false positive" in r["note"]]
BENIGN = [r["url"] for r in ADV if r["url"] not in EXPECTED_FP]
SYN_BAD = [r["url"] for r in _rows("synthetic_adversarial")]


def test_suite_is_big_enough_and_labelled():
    assert len(BENIGN) >= 30 and len(SYN_BAD) >= 6
    assert all(r["note"].startswith("SYNTHETIC") and r["label"] == "1" for r in _rows("synthetic_adversarial"))
    assert all(r["label"] == "0" for r in ADV)


@pytest.mark.parametrize("url", BENIGN)
def test_adversarial_benign_stays_low(an, url):
    v = an.analyze_url(url)
    assert v.level == "low", (url, v.risk, [(s.id, s.contribution) for s in v.signals if s.contribution])


@pytest.mark.parametrize("url", EXPECTED_FP)
def test_documented_expected_false_positive_is_medium_not_high(an, url):
    """Known limitation (docs/LIMITATIONS.md): a benign business name containing a brand. Never 'high'."""
    assert an.analyze_url(url).level == "medium"


@pytest.mark.parametrize("url", SYN_BAD)
def test_synthetic_adversarial_fraud_flagged(an, url):
    v = an.analyze_url(url)
    assert v.level in ("medium", "high"), (url, v.risk, [(s.id, s.contribution) for s in v.signals if s.contribution])


@pytest.mark.parametrize("url,hit", [
    ("https://secure-login.top/www.adpolice.gov.ae/fines", "adpolice.gov.ae"),
    ("https://pay-fines-now.top/?ref=https://www.adpolice.gov.ae", "adpolice.gov.ae"),
    ("https://example.com/q?x=https%3A%2F%2Fwww.rta.ae%2Fpay", "rta.ae"),       # percent-encoded
    ("https://example.com/notadpolice.gov.aeish", None),                     # not on a label boundary
    ("https://example.com/the-rta.aerial", None),
    ("https://www.adpolice.gov.ae/x?next=https://www.rta.ae", None),         # host itself is official
    ("https://eservices.rta.ae/?back=adpolice.gov.ae", None),
])
def test_embedded_official_domain_signal(reg, url, hit):
    s = embedded_official_signal(normalize(url), reg)
    assert (s.data["official_domain"] if s else None) == hit


def test_embedded_official_alone_stays_low_and_is_explained(an, reg):
    v = an.analyze_url("https://www.google.com/url?q=https://www.adpolice.gov.ae/")
    assert v.level == "low" and v.risk == 15
    v = an.analyze_url("https://secure-login.top/www.adpolice.gov.ae/fines")
    s = next(x for x in v.signals if x.id == "official_domain_in_url")
    ar = _ar(s, reg)
    assert "adpolice.gov.ae" in ar and "secure-login.top" in ar
    ar_full, en_full = explain(v.signals, v.level, reg)
    assert "secure-login.top" in en_full and "adpolice.gov.ae" in ar_full
