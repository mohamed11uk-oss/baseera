"""The explanation may only state facts that are present in the signals (no invented facts)."""
import re

import pytest

from baseera.explain import AMAN_AR, AMAN_EN
from baseera.schemas import Listing

INPUTS = ["https://adpolice-fines-pay.com/pay", "hxxps://emiratesnbd-verify[.]top/otp", "https://аdpolice.com/",
          "https://bankfab.ae/cards", "https://rta-fines-pay.netlify.app/", "https://www.adpolice.gov.ae/en"]


def facts(text: str) -> set[str]:
    """Domain-like tokens and numbers mentioned in a sentence."""
    return set(re.findall(r"[a-z0-9\u0400-\u04ff-]+(?:\.[a-z0-9-]+)+", text.lower())) | set(re.findall(r"\d{3,}", text))


def corpus(v) -> str:
    parts = [v.input]
    for s in v.signals:
        parts += [s.evidence, " ".join(str(x) for x in s.data.values())]
    if v.matched_entity:
        parts += v.matched_entity.get("official_domains", []) + [str(v.matched_entity.get("verified_on"))]
    return " ".join(parts).lower()


@pytest.mark.parametrize("url", INPUTS)
def test_explanation_cites_only_signal_facts(an, url):
    v = an.analyze_url(url)
    c = corpus(v)
    for text in (v.explanation_ar.replace(AMAN_AR, ""), v.explanation_en.replace(AMAN_EN, "")):
        for f in facts(text):
            assert f in c, f"explanation states '{f}' which is not in any signal for {url}"


def test_explanation_has_top3_and_arabic_first(an):
    v = an.analyze_url("https://adpolice-fines-pay.com/pay")
    lines = v.explanation_ar.splitlines()
    assert lines[0].startswith("الخطر")
    assert sum(1 for ln in lines if re.match(r"^\d\. ", ln)) <= 3
    assert "8002626" in v.explanation_ar  # Aman reporting line on medium/high


def test_listing_explanation_no_invented_facts(an):
    v, _ = an.analyze_listing(Listing(source="maps", title="Emirates NBD Card Support", phone="+971 50 000 1234",
                                      displayed_url="http://enbd-unblock.top"))
    c = corpus(v) + " " + " ".join(sv.input for sv in v.sub_verdicts)
    for f in facts(v.explanation_en.replace(AMAN_EN, "")):
        assert f in c
