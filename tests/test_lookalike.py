"""Table-driven look-alike tests. All suspicious domains are made up for testing (written defanged in docs)."""
import pytest

from baseera.normalize import normalize
from baseera.signals.lookalike import damerau, detect, skeleton

CASES = [
    # (url, expected entity id or None, expected technique or None)
    ("adpolice.com", "adpolice", "tld_swap"),
    ("adpolice.ae", "adpolice", "tld_swap"),
    ("emiratesnbd.co", "enbd", "tld_swap"),
    ("bankfab.ae", "fab", "tld_swap"),
    ("icp.com", "icp", "tld_swap"),
    ("adpollce.gov-uae.com", "adpolice", "brand_in_subdomain"),
    ("adpo1ice.com", "adpolice", "homoglyph"),
    ("аdpolice.com", "adpolice", "homoglyph"),          # Cyrillic а
    ("emiratesnbb.com", "enbd", "typosquat"),
    ("emiratsnbd.com", "enbd", "typosquat"),
    ("emiratesndb.com", "enbd", "typosquat"),             # transposition
    ("bankfabb.com", "fab", "typosquat"),
    ("centralbank.ae.verify-now.com", "cbuae", "brand_in_subdomain"),
    ("adpolice-fines-pay.com", "adpolice", "brand_keyword"),
    ("emiratesnbd-secure.xyz", "enbd", "brand_keyword"),
    ("bankfab-rewards.xyz", "fab", "brand_keyword"),
    ("abudhabipolice-fines.top", "adpolice", "brand_keyword"),
    ("etisalat-bill.com", "eand", "brand_keyword"),
    ("mashreq-online.help", "mashreq", "brand_keyword"),
    ("emiratespost-redelivery.com", "empost", "brand_keyword"),
    ("rta-fines-pay.netlify.app", "rta", "brand_in_subdomain"),
    ("salik-topup.site", "salik", "brand_keyword"),
    ("tamm.abudhabi.gov-services.com", "tamm", "brand_in_subdomain"),
    ("dewa.bill-pay.online", "dewa", "brand_in_subdomain"),
    ("adib.secure-login.top", "adib", "brand_in_subdomain"),
    # negatives: official, unrelated, short-brand collisions
    ("www.adpolice.gov.ae", None, None),
    ("eservices.adpolice.gov.ae", None, None),
    ("www.emiratesnbd.com", None, None),
    ("google.com", None, None),
    ("wikipedia.org", None, None),
    ("portal.example.com", None, None),           # 'rta' inside 'portal' must not match
    ("adibrands.com", None, None),               # 'adib' prefix of another word, not a token
    ("dubai.com", None, None),
    ("emirates-post-parcel.top", "empost", "brand_keyword"),
    ("visit-abu-dhabi.com", None, None),
    ("noon.com", None, None),
]


@pytest.mark.parametrize("url,entity,technique", CASES)
def test_lookalike_table(reg, url, entity, technique):
    m = detect(normalize(url), reg)
    if entity is None:
        assert m is None, f"unexpected match {m and (m.entity.id, m.technique)}"
    else:
        assert m is not None, "expected a match"
        assert (m.entity.id, m.technique) == (entity, technique)
        assert m.evidence


def test_skeleton_and_distance():
    assert skeleton("adpo1ice") == skeleton("adpolice")
    assert skeleton("rnashreq") == skeleton("mashreq")
    assert damerau("emiratesnbd", "emiratesndb") == 1
    assert damerau("abc", "abc") == 0


def test_at_least_25_cases():
    assert len(CASES) >= 25
