import pytest

from baseera.registry import RegistryError, load_registry


def test_registry_loads_and_every_entry_has_source(reg):
    assert len(reg.entities) >= 15
    for e in reg.entities:
        assert e.source_url.startswith("https://") and e.verified_on
        if e.status == "domain_only":
            assert not e.official_phones


def test_official_lookup(reg):
    assert reg.official_for_host("www.adpolice.gov.ae").id == "adpolice"
    assert reg.official_for_host("adpolice.gov.ae.evil.com") is None
    assert reg.entity_for_phone("+971 8002626").id == "adpolice"
    assert reg.entity_for_phone("600 54 0000").id == "enbd"


def test_match_name(reg):
    assert reg.match_name("Emirates NBD Customer Care").id == "enbd"
    assert reg.match_name("شرطة أبوظبي - سداد المخالفات").id == "adpolice"
    assert reg.match_name("ADIB card help").id == "adib"
    assert reg.match_name("random bakery") is None


def test_loader_fails_loudly_without_source(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text("entities:\n  - {id: x, entity_name_ar: س, entity_name_en: X, category: bank, official_domains: [x.ae], status: verified}\n")
    with pytest.raises(RegistryError, match="source_url"):
        load_registry(p)


def test_domain_only_cannot_list_phones(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text("entities:\n  - {id: x, entity_name_ar: س, entity_name_en: X, category: bank, official_domains: [x.ae],"
                 " official_phones: [{number: '600'}], source_url: 'https://x.ae', verified_on: '2026-11-19', status: domain_only}\n")
    with pytest.raises(RegistryError):
        load_registry(p)
