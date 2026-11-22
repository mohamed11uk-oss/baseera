import pytest

from baseera.phones import canonical, classify, extract_phones
from baseera.schemas import Listing


@pytest.mark.parametrize("raw,canon,kind", [
    ("+971 2 691 5555", "26915555", "landline"),
    ("600 54 0000", "600540000", "unified"),
    ("+971600522222", "600522222", "unified"),
    ("800 90 90", "8009090", "toll_free"),
    ("0501234567", "501234567", "mobile"),
    ("+971 50 123 4567", "501234567", "mobile"),
    ("00971 4 284 4444", "42844444", "landline"),
    ("999", "999", "short_code"),
    ("2828", "2828", "short_code"),
])
def test_phone_normalisation(raw, canon, kind):
    assert canonical(raw) == canon and classify(raw) == kind


def test_extract_phones():
    assert extract_phones("call 0501234567 or +971 2 691 5555 now") == ["0501234567", "+971 2 691 5555"]


def test_listing_official(an):
    v, official = an.analyze_listing(Listing(source="maps", title="Emirates NBD", phone="600 54 0000",
                                             displayed_url="https://www.emiratesnbd.com/en"))
    assert official and v.level == "low"


def test_listing_official_site_but_unknown_phone_is_medium_not_fake(an):
    """Hijacked Maps pin: official website but a phone number not in the registry."""
    v, official = an.analyze_listing(Listing(source="maps", title="Emirates NBD Card Support", phone="+971 4 000 0000",
                                             displayed_url="https://www.emiratesnbd.com/en"))
    assert not official and v.level == "medium"
    assert "ممكن يكون ناقص" in v.explanation_ar          # says the registry may be incomplete
    assert "not proven fake" in " ".join(s.evidence for s in v.signals)


def test_listing_mobile_and_fake_site_high(an):
    v, official = an.analyze_listing(Listing(source="maps", title="Abu Dhabi Police Fines Office", phone="+971 56 000 4455",
                                             displayed_url="https://adpo1ice-gov.com/fines"))
    assert not official and v.level == "high"
    ids = {s.id for s in v.signals}
    assert {"listing_unofficial_site", "phone_unverified", "phone_mobile_for_brand", "lookalike"} <= ids


def test_listing_sponsored(an):
    v, _ = an.analyze_listing(Listing(source="search", is_ad=True, title="Emirates NBD Customer Care 24/7",
                                      displayed_url="https://emiratesnbd-helpdesk.com/contact"))
    assert any(s.id == "listing_sponsored_unofficial" for s in v.signals) and v.level == "high"


def test_listing_domain_only_entity_phone_unavailable(an):
    v, _ = an.analyze_listing(Listing(source="maps", title="Mashreq customer care", phone="0400000000"))
    s = next(x for x in v.signals if x.id == "phone_unverified")
    assert s.available is False


def test_phone_belongs_to_other_entity(an):
    v, _ = an.analyze_listing(Listing(source="maps", title="Emirates NBD help", phone="600 52 5500"))
    assert any(s.id == "phone_other_entity" for s in v.signals)


def test_text_message(an):
    v = an.analyze_text("عاجل: تم تعليق بطاقتك من بنك الإمارات دبي الوطني. أدخل رمز التحقق على hxxps://emiratesnbd-verify[.]top/otp أو اتصل 0500001234")
    assert v.level == "high"
    assert len(v.sub_verdicts) == 1 and v.sub_verdicts[0].level == "high"
    ids = {s.id for s in v.signals}
    assert {"text_urgency", "text_sensitive_request", "phone_unverified"} <= ids


def test_text_official_link_low(an):
    v = an.analyze_text("Visit https://www.adpolice.gov.ae/en for services")
    assert v.level == "low"
