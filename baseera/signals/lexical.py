"""Cheap lexical URL features (offline)."""
from __future__ import annotations

import re

from ..normalize import NormalizedURL
from ..schemas import Signal

SUSPICIOUS_TLDS = {"top", "xyz", "icu", "shop", "click", "live", "online", "site", "cyou", "buzz", "rest", "sbs",
                   "cfd", "lol", "mom", "quest", "support", "help", "info", "vip", "work", "tk", "ml", "ga", "cf", "gq"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at",
              "trimurl.link", "s.id", "rebrand.ly", "t.ly", "tiny.cc"}
FREE_HOSTING = {"netlify.app", "vercel.app", "web.app", "firebaseapp.com", "pages.dev", "github.io", "blogspot.com",
                "wixsite.com", "weebly.com", "glitch.me", "herokuapp.com", "000webhostapp.com", "sites.google.com",
                "workers.dev", "onrender.com", "ngrok-free.app", "ngrok.io", "r2.dev", "framer.website"}
SENSITIVE = re.compile(r"(log-?in|sign-?in|verify|verification|update|otp|secure|account|pay(ment)?|refund|fine|"
                       r"violation|mukhalaf|unlock|suspend|blocked|kyc|reward|prize|card|bank|wallet|tracking|"
                       r"redeliver|customs|emirates-?id)", re.I)
GOV_WORD = re.compile(r"(^|[^a-z])(gov|govt|government|moi|police)([^a-z]|$)|gov-?ae|ae-?gov", re.I)


def lexical_signals(n: NormalizedURL) -> list[Signal]:
    out: list[Signal] = []
    host = n.host

    def add(id_, sev, ev, **data):
        out.append(Signal(id=id_, source="lexical", score=sev, evidence=ev, data=data))

    if n.is_ip:
        add("ip_host", 1.0, f"Host is a raw IP address ({host})", host=host)
    if n.is_punycode:
        add("punycode", 1.0, f"Internationalised (IDN/punycode) host {host} shown as {n.host_unicode}", host_unicode=n.host_unicode)
    if n.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        add("suspicious_tld", 1.0, f"Top-level domain .{n.suffix} is frequently abused for throw-away sites", suffix=n.suffix)
    if n.private_suffix and n.private_suffix in FREE_HOSTING or any(host.endswith("." + f) for f in FREE_HOSTING):
        add("free_hosting", 1.0, f"Hosted on a free/shared platform ({n.private_suffix or host})", platform=n.private_suffix or host)
    if "@" in n.original.split("//", 1)[-1].split("/", 1)[0]:
        add("at_symbol", 1.0, "URL contains '@' before the host (classic disguise)")
    label_parts = n.label.split("-") if "-" in n.label else []
    m = SENSITIVE.search(n.subdomain + "/" + n.path + "?" + n.query + "/" + " ".join(label_parts))
    if m:
        add("sensitive_path", 1.0, f"URL contains the lure word '{m.group(0)}'", word=m.group(0))
    if n.registrable_domain in SHORTENERS:
        add("url_shortener", 1.0, f"URL shortener {n.registrable_domain} hides the real destination", domain=n.registrable_domain)
    depth = len([p for p in n.subdomain.split(".") if p])
    if depth >= 3:
        add("many_subdomains", min(1.0, depth / 4), f"{depth} sub-domain levels ({n.subdomain})", depth=depth)
    if len(n.url) > 100:
        add("long_url", min(1.0, len(n.url) / 200), f"Very long URL ({len(n.url)} characters)", length=len(n.url))
    if not n.is_ip and not n.is_punycode and (n.label.count("-") >= 2 or len(re.findall(r"\d", n.label)) >= 3):
        add("hyphen_digits", 1.0, f"Domain label '{n.label}' has many hyphens/digits", label=n.label)
    if n.original.strip().lower().startswith(("http://", "hxxp://")):
        add("no_tls", 0.5, "Link uses plain http:// (no encryption)")
    if not n.suffix.endswith("gov.ae") and GOV_WORD.search(n.host):
        add("gov_impersonation", 1.0, f"Domain {n.host} uses government/police wording but is not under .gov.ae", host=n.host)
    if n.suffix.endswith("gov.ae"):
        add("gov_suffix", 1.0, f"{n.registrable_domain} is under .gov.ae (registrable by UAE government only)", domain=n.registrable_domain)
    return out
