import pytest

from baseera.normalize import normalize
from baseera.schemas import Signal
from baseera.scoring import load_weights, score

W = load_weights()


@pytest.mark.parametrize("signals,official,blocked,level", [
    ([], False, False, "low"),
    ([Signal(id="lookalike", source="t", score=0.8)], False, False, "medium"),
    ([Signal(id="lookalike", source="t", score=1.0), Signal(id="sensitive_path", source="t", score=1.0)], False, False, "high"),
    ([Signal(id="lookalike", source="t", score=1.0), Signal(id="new_domain", source="t", score=1.0)], True, False, "low"),
    ([], False, True, "high"),                                  # blocklist hit => at least high
    ([Signal(id="ip_host", source="t", score=1.0, available=False)], False, False, "low"),  # unavailable never counts
])
def test_overrides(signals, official, blocked, level):
    _, lvl = score(signals, official=official, blocklisted=blocked)
    assert lvl == level


def test_contributions_explain_score():
    sigs = [Signal(id="lookalike", source="t", score=0.5), Signal(id="suspicious_tld", source="t", score=1.0)]
    risk, _ = score(sigs)
    assert risk == round(sum(s.contribution for s in sigs))
    assert all(s.weight == W["weights"][s.id] for s in sigs)


def test_clip_0_100():
    sigs = [Signal(id=k, source="t", score=1.0) for k in W["weights"]]
    assert score(sigs)[0] == 100
    assert score([Signal(id="gov_suffix", source="t", score=1.0)])[0] == 0


PATHS = ["/", "/en", "/ar/contact-us", "/en/login?next=/account", "/pay/fines?ref=123", "/eservices/verify-otp"]


def test_false_positive_guard_every_official_domain(an, reg):
    """Release blocker: no official domain (with sub-domain and deep paths) may score above 'low'."""
    for e in reg.entities:
        for d in e.official_domains:
            for host in (d, "www." + d, "eservices." + d):
                for p in PATHS:
                    for scheme in ("https://", "http://"):
                        v = an.analyze_url(scheme + host + p)
                        assert v.level == "low", (scheme + host + p, v.risk, [(s.id, s.contribution) for s in v.signals])
                        assert v.matched_entity["relation"] == "official"


@pytest.mark.parametrize("url", ["https://www.google.com", "https://en.wikipedia.org/wiki/Abu_Dhabi", "https://www.noon.com/uae-en/",
                                 "https://www.amazon.ae", "https://github.com", "https://www.khaleejtimes.com/uae"])
def test_popular_legit_sites_low(an, url):
    assert an.analyze_url(url).level == "low"


@pytest.mark.parametrize("url,minlevel", [
    ("https://adpolice-fines-pay.com/pay", "high"),
    ("hxxps://emiratesnbd-verify[.]top/otp", "high"),
    ("https://аdpolice.com/", "high"),
    ("http://enbd-unblock.top/card", "high"),   # in the test blocklist
    ("https://bankfab.ae/cards", "high"),
    ("https://emiratesnbd.co/update-kyc", "high"),
])
def test_known_bad_high(an, url, minlevel):
    v = an.analyze_url(url)
    assert v.level == minlevel, (v.risk, [(s.id, s.contribution) for s in v.signals])


def test_ip_and_shortener_signals(an):
    v = an.analyze_url("http://203.0.113.5/login")
    assert any(s.id == "ip_host" for s in v.signals)
    v = an.analyze_url("https://bit.ly/abc")
    assert any(s.id == "url_shortener" for s in v.signals)


def test_offline_intel_marked_unavailable(an):
    v = an.analyze_url("https://example-new-site.com")
    s = {x.id: x for x in v.signals}
    assert s["new_domain"].available is False and s["new_certificate"].available is False


def test_normalize_used(an):
    assert an.analyze_url("adpolice.gov.ae").normalized["registrable_domain"] == normalize("adpolice.gov.ae").registrable_domain
