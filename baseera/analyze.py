"""Orchestrator: URL / pasted text / Search-Maps listing -> explainable Verdict. Never raises on a source failure."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import sandbox as sandbox_mod
from .config import Settings, get_settings
from .explain import explain
from .normalize import NormalizedURL, SSRFBlocked, follow_redirects, normalize
from .phones import canonical, classify, extract_phones
from .registry import Registry, default_registry
from .schemas import Listing, Signal, Verdict
from .scoring import score
from .signals.domain_intel import intel_signals, load_feed
from .signals.lexical import FREE_HOSTING, SHORTENERS, lexical_signals
from .signals.lookalike import embedded_official_signal, lookalike_signal
from .sources import feeds as feeds_mod
from .sources import gsb as gsb_mod
from .sources import status as source_status
from .sources import urlhaus as urlhaus_mod
from .sources import urlscan as urlscan_mod
from .sources import virustotal as vt_mod

URL_RE = re.compile(r"(?:h(?:tt|xx)ps?://|www\.)[^\s<>\"'،]+|\b(?:[a-z0-9-]+(?:\.|\[\.\]))+[a-z]{2,}(?:/[^\s<>\"'،]*)?",
                    re.I)
URGENCY = re.compile(r"(urgent|immediately|within 24 hours|last warning|final notice|suspended|blocked|expire[sd]?|"
                     r"عاجل|فوراً|فورا|خلال 24 ساعة|آخر فرصة|سيتم إيقاف|تم إيقاف|تم تعليق|موقوف|محظور|غرامة|مخالفة)", re.I)
SENSITIVE_REQ = re.compile(r"(otp|one[- ]time password|cvv|card number|pin\b|password|emirates id|"
                           r"رمز التحقق|الرمز السري|كلمة المرور|رقم البطاقة|بيانات البطاقة|الهوية الإماراتية|رقم الهوية)", re.I)
BIG_CATEGORIES = {"bank", "government", "police", "telecom", "utility"}
# Hosts shared by many unrelated users: a feed listing ONE phishing URL there must not flag the whole host.
SHARED_HOSTS = FREE_HOSTING | SHORTENERS | {
    "docs.google.com", "drive.google.com", "forms.gle", "storage.googleapis.com", "firebasestorage.googleapis.com",
    "github.com", "raw.githubusercontent.com", "dropbox.com", "dl.dropboxusercontent.com", "onedrive.live.com", "1drv.ms",
    "forms.office.com", "sharepoint.com", "ipfs.io", "dweb.link", "linktr.ee", "t.me", "wa.me", "telegra.ph"}
_DEFAULT = object()


class Analyzer:
    def __init__(self, settings: Settings | None = None, registry: Registry | None = None, feed: set[str] | None = None,
                 feeds=_DEFAULT, gsb=_DEFAULT, sandbox=_DEFAULT, urlhaus=_DEFAULT, urlscan=_DEFAULT, vt=_DEFAULT):
        """feed: local (synthetic) blocklist set. feeds: FeedStore (PhishTank/OpenPhish) or None.
        gsb: GSBClient or None. sandbox: callable(url) -> SandboxResult (deep scan) or None.
        urlhaus / urlscan: optional hot-path clients. vt: VirusTotal client for the manual deep check only.
        Defaults are built from settings (all optional, all fail soft)."""
        self.settings = settings or get_settings()
        self.registry = registry or default_registry()
        self.feed = load_feed() if feed is None else feed
        self.feeds = feeds_mod.open_store(self.settings) if feeds is _DEFAULT else feeds
        self.gsb = gsb_mod.GSBClient(self.settings) if gsb is _DEFAULT else gsb
        self.sandbox = sandbox_mod.Sandbox(self.settings) if sandbox is _DEFAULT else sandbox
        self.urlhaus = urlhaus_mod.URLhausClient(self.settings) if urlhaus is _DEFAULT else urlhaus
        self.urlscan = urlscan_mod.URLscanClient(self.settings) if urlscan is _DEFAULT else urlscan
        self.vt = vt_mod.VTClient(self.settings) if vt is _DEFAULT else vt  # never called from analyze_*

    def deep_enabled(self, requested: bool) -> bool:
        mode = self.settings.source_sandbox
        return self.sandbox is not None and mode != "off" and (requested or mode == "on")

    # ------------------------------------------------------------ blocklists
    def _feed_hits(self, n: NormalizedURL) -> list[dict]:
        self._feeds_error = None
        hits = []
        if any(k in self.feed for k in (n.url.lower(), n.host, n.registrable_domain)):
            hits.append({"source": "local", "label": "local synthetic demo feed", "match": "host"})
        if self.feeds is not None:
            try:
                rows = self.feeds.match_exact(n.url)
                match = "exact URL"
                if not rows and n.host not in SHARED_HOSTS and n.registrable_domain not in SHARED_HOSTS \
                        and (n.private_suffix or "") not in SHORTENERS:
                    rows, match = self.feeds.match_host(n.host), "same host"
                for r in rows:
                    hits.append({**r, "label": feeds_mod.SOURCES.get(r["source"], {}).get("label", r["source"]),
                                 "match": match})
                source_status.record("feeds", True)
            except Exception as e:  # noqa: BLE001 - a broken feed DB must never fail /api/analyze
                self._feeds_error = f"threat-feed DB unavailable ({type(e).__name__})"
                source_status.record("feeds", False, self._feeds_error)
        return hits

    def _blocklist_signals(self, n: NormalizedURL, official) -> tuple[list[Signal], bool]:
        sigs: list[Signal] = []
        blocked = False
        hits = self._feed_hits(n)
        if not hits and self._feeds_error:
            sigs.append(Signal(id="blocklist_hit", source="feed", score=0, available=False,
                               evidence=f"PhishTank/OpenPhish lookup not done: {self._feeds_error}"))
        if hits:
            local_only = all(h["source"] == "local" for h in hits)
            labels = ", ".join(dict.fromkeys(h["label"] for h in hits))
            if local_only:
                ev = f"{n.host} is listed in the local blocklist feed (synthetic demo feed)"
            else:
                h = next(h for h in hits if h["source"] != "local")
                ev = (f"{n.host} is listed in {labels} ({h['match']} match: {h['url']}"
                      f"{', first seen ' + h['first_seen'][:10] if h.get('first_seen') else ''}"
                      f"{', target ' + h['target'] if h.get('target') else ''})")
            data = {"feed": labels, "match": hits[0]["match"] if local_only else h["match"],
                    "sources": sorted({x["source"] for x in hits})}
            if official:  # official-domain FP guard: a feed listing never overrides the registry (analyst reviews it)
                sigs.append(Signal(id="blocklist_hit", source="feed", score=0, data=data,
                                   evidence=ev + "; host is an official registry domain, so the official verdict is kept "
                                                 "(possible feed error or compromised page: analyst review)"))
            else:
                sigs.append(Signal(id="blocklist_hit", source="feed", score=1.0, data=data, evidence=ev))
                blocked = True
        if self.gsb is not None and self.gsb.enabled:
            urls = list(dict.fromkeys([n.url] + (n.redirect_chain or [])))[:10]
            res = self.gsb.check(urls)
            source_status.record("gsb", res["available"], res.get("error"))
            note = gsb_mod.notice()
            if not res["available"]:
                sigs.append(Signal(id="gsb_match", source="gsb", score=0, available=False, data=note,
                                   evidence=f"{res.get('error')}. {gsb_mod.ATTRIBUTION_EN}"))
            elif res["matches"]:
                threats = sorted({t for ts in res["matches"].values() for t in ts})
                data = {**note, "threats": threats, "urls": list(res["matches"]),
                        "threats_ar": "، ".join(gsb_mod.THREAT_AR.get(t, t) for t in threats)}
                ev = (f"Google Safe Browsing lists {', '.join(res['matches'])} as {', '.join(threats)}. "
                      f"{gsb_mod.ATTRIBUTION_EN} (not guaranteed)")
                if official:
                    sigs.append(Signal(id="gsb_match", source="gsb", score=0, data=data,
                                       evidence=ev + "; host is an official registry domain: analyst review"))
                else:
                    sigs.append(Signal(id="gsb_match", source="gsb", score=1.0, data=data, evidence=ev))
                    blocked = True
            else:
                sigs.append(Signal(id="gsb_match", source="gsb", score=0, data=note,
                                   evidence=f"Not listed by Google Safe Browsing. {gsb_mod.ATTRIBUTION_EN} (not guaranteed)"))
        if self.urlhaus is not None and self.urlhaus.enabled:
            sig = self._urlhaus_signal(n, official)
            sigs.append(sig)
            blocked = blocked or _is_block(sig)
        return sigs, blocked

    def _urlhaus_signal(self, n: NormalizedURL, official) -> Signal:
        shared = n.host in SHARED_HOSTS or n.registrable_domain in SHARED_HOSTS or (n.private_suffix or "") in SHORTENERS
        res = self.urlhaus.lookup(n.url, None if shared else n.host)
        source_status.record("urlhaus", res["available"], res.get("error"))
        if not res["available"]:
            return Signal(id="urlhaus_match", source="urlhaus", score=0, available=False, evidence=str(res.get("error")))
        u, h = res["url_hit"], res["host_hit"]
        if u:
            data = {"match": "exact URL", "threat": u.get("threat"), "url_status": u.get("url_status"),
                    "reference": u.get("urlhaus_reference"), "tags": u.get("tags") or []}
            ev = (f"URLhaus (abuse.ch) lists this exact URL as {u.get('threat') or 'malicious'} "
                  f"(status {u.get('url_status')}, added {str(u.get('date_added') or '?')[:10]})")
            sev = 1.0
        elif h:
            data = {"match": "same host", "url_count": h["url_count"], "online": h["online"], "threats": h["threats"],
                    "reference": h.get("urlhaus_reference")}
            ev = (f"URLhaus (abuse.ch) lists {h['url_count']} malware URL(s) on {n.host} ({h['online']} online, "
                  f"first seen {str(h.get('firstseen') or '?')[:10]})")
            sev = 0.5 if h["online"] else 0.25  # team-chosen: host history is weaker than an exact URL hit
        else:
            return Signal(id="urlhaus_match", source="urlhaus", score=0,
                          evidence="Not listed by URLhaus" + (" (host lookup skipped: shared platform)" if shared else ""))
        if official:  # official-domain FP guard (same rule as the feeds and GSB)
            return Signal(id="urlhaus_match", source="urlhaus", score=0, data=data,
                          evidence=ev + "; host is an official registry domain: analyst review")
        return Signal(id="urlhaus_match", source="urlhaus", score=sev, data=data, evidence=ev)

    def _urlscan_signal(self, n: NormalizedURL) -> Signal:
        """Existing urlscan.io scans of this host: context for analysts, weight 0 (never moves the score)."""
        res = self.urlscan.search_host(n.host)
        source_status.record("urlscan", res["available"], res.get("error"))
        if not res["available"]:
            return Signal(id="urlscan_seen", source="urlscan", score=0, available=False, evidence=str(res.get("error")))
        data = {k: res.get(k) for k in ("total", "first_seen", "last_seen", "malicious")}
        data["results"] = [r for r in res.get("results", [])[:5]]
        if not res["total"]:
            return Signal(id="urlscan_seen", source="urlscan", score=0, data=data,
                          evidence=f"No existing urlscan.io scans visible for {n.host} (informational)")
        return Signal(id="urlscan_seen", source="urlscan", score=0, data=data,
                      evidence=(f"urlscan.io has {res['total']} existing scan(s) of {n.host}, first {str(res['first_seen'])[:10]}"
                                f", {res['malicious']} marked malicious in the latest 10 (informational, not scored)"))

    # ------------------------------------------------------------------ URL
    def analyze_url(self, raw: str, deep: bool = False) -> Verdict:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            n = normalize(raw)
        except ValueError as e:
            return Verdict(input=raw, kind="url", risk=0, level="low", signals=[], mode=self.settings.mode,
                           explanation_ar=f"ما قدرنا نقرأ الرابط: {e}", explanation_en=f"Could not parse URL: {e}",
                           analyzed_at=now)
        chain = [n.url]
        signals: list[Signal] = []
        if not self.settings.offline and self.settings.source_redirects and not n.is_ip:
            try:
                chain = follow_redirects(n.url, timeout=self.settings.timeout_s)
                source_status.record("redirects", True)
            except SSRFBlocked as e:  # policy refusal, not a source outage
                signals.append(Signal(id="redirects", source="http", score=0, available=False, evidence=f"Not fetched: {e}"))
            except Exception as e:  # noqa: BLE001
                source_status.record("redirects", False, type(e).__name__)
                signals.append(Signal(id="redirects", source="http", score=0, available=False,
                                      evidence=f"Redirects not followed ({type(e).__name__})"))
            if len(chain) > 1:
                final = normalize(chain[-1])
                if final.registrable_domain != n.registrable_domain and n.registrable_domain in SHORTENERS:
                    signals += lexical_signals(n)  # keep the shortener signal of the first hop
                    n = final
        n.redirect_chain = chain
        return self._url_verdict(raw, n, signals, now, deep=self.deep_enabled(deep))

    def _url_verdict(self, raw: str, n: NormalizedURL, signals: list[Signal], now: str, deep: bool = False) -> Verdict:
        reg = self.registry
        official = reg.official_for_host(n.host) if not n.is_ip else None
        bl, blocked = self._blocklist_signals(n, official)
        signals += bl
        signals += [s for s in lexical_signals(n) if not (official and s.id == "gov_suffix")]
        look, match = lookalike_signal(n, reg)
        if look:
            signals.append(look)
        emb = embedded_official_signal(n, reg)
        if emb:
            signals.append(emb)
        infra: dict = {}
        if not n.is_ip:
            sigs, infra = intel_signals(n.registrable_domain, n.host, self.settings, official is not None)
            signals += sigs
            if self.urlscan is not None and self.urlscan.enabled:
                signals.append(self._urlscan_signal(n))
        sb = None
        if deep:  # page content is UNTRUSTED: only fixed keyword/field checks, never interpreted
            try:
                sb = self.sandbox(n.url)
            except Exception as e:  # noqa: BLE001 - deep scan never fails /api/analyze
                sb = sandbox_mod.SandboxResult(url=n.url, available=False, error=f"sandbox error {type(e).__name__}")
            source_status.record("sandbox", sb.available, sb.error)
            signals += sandbox_mod.sandbox_signals(sb, n.host, reg, official)
        if official:  # official domains: lexical noise is informative only
            for s in signals:
                if s.id not in BLOCK_IDS:
                    s.score = 0.0 if s.id != "gov_suffix" else s.score
        risk, level = score(signals, official=official is not None and not blocked, blocklisted=blocked)
        ar, en = explain(signals, level, reg, official if (official and not blocked) else None, n.registrable_domain)
        ent = official or (match.entity if match else None)
        if ent is None and sb is not None:
            bp = next((s for s in signals if s.id == "brand_in_page" and s.score > 0), None)
            ent = reg.by_id.get(bp.data["entity_id"]) if bp else None
        extra = {"sandbox": sb.public()} if sb is not None else {}
        shot = f"/api/screenshots/{sb.screenshot_sha256}.png" if sb is not None and sb.screenshot_sha256 else None
        return Verdict(input=raw, kind="url", risk=risk, level=level, signals=signals, explanation_ar=ar, explanation_en=en,
                       matched_entity=({**ent.public(), "relation": "official" if official else "impersonated"} if ent else None),
                       normalized={**n.to_dict(), "infra": infra, **extra}, screenshot_url=shot, mode=self.settings.mode,
                       analyzed_at=now)

    # ----------------------------------------------------------------- TEXT
    def analyze_text(self, text: str) -> Verdict:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        urls = []
        for m in URL_RE.finditer(text):
            u = m.group(0).rstrip(".,;)")
            if u not in urls and not re.fullmatch(r"[\d.]+", u):
                urls.append(u)
        with ThreadPoolExecutor(max_workers=4) as ex:
            subs = list(ex.map(self.analyze_url, urls[:5]))
        signals: list[Signal] = []
        m = URGENCY.search(text)
        if m:
            signals.append(Signal(id="text_urgency", source="text", score=1.0, data={"word": m.group(0)},
                                  evidence=f"Message uses pressure wording '{m.group(0)}'"))
        m = SENSITIVE_REQ.search(text)
        if m:
            signals.append(Signal(id="text_sensitive_request", source="text", score=1.0, data={"word": m.group(0)},
                                  evidence=f"Message asks for sensitive data '{m.group(0)}'"))
        entity = self.registry.match_name(text)
        url_digits = {re.sub(r"\D", "", u) for u in urls}
        for p in extract_phones(text):
            if re.sub(r"\D", "", p) in url_digits:
                continue
            signals += self._phone_signals(p, entity)
        worst = max(subs, key=lambda v: v.risk, default=None)
        if worst:
            signals += [s.model_copy() for s in worst.signals]
        official = worst is not None and worst.matched_entity and worst.matched_entity.get("relation") == "official" \
            and worst.level == "low" and not any(s.id.startswith("phone_") and s.score > 0 for s in signals)
        risk, level = score(signals, official=False, blocklisted=_blocked(signals))
        if official and level == "low":
            risk = min(risk, worst.risk)
        ar, en = explain(signals, level, self.registry)
        ent = entity.public() if entity else (worst.matched_entity if worst else None)
        return Verdict(input=text, kind="text", risk=risk, level=level, signals=signals, explanation_ar=ar,
                       explanation_en=en, matched_entity=ent, sub_verdicts=subs, mode=self.settings.mode, analyzed_at=now,
                       normalized={"urls": urls, "phones": extract_phones(text)})

    # -------------------------------------------------------------- PHONES
    def _phone_signals(self, phone: str, entity) -> list[Signal]:
        reg = self.registry
        sigs: list[Signal] = []
        c = canonical(phone)
        owner = reg.entity_for_phone(phone)
        kind = classify(phone)
        if entity is None:
            if owner:
                sigs.append(Signal(id="phone_verified", source="registry", score=0, data={"phone": phone, "entity_id": owner.id},
                                   evidence=f"{phone} is an official number of {owner.entity_name_en}"))
            return sigs
        if c in entity.phone_set:
            sigs.append(Signal(id="phone_verified", source="registry", score=0, data={"phone": phone, "entity_id": entity.id},
                               evidence=f"{phone} matches the official registry for {entity.entity_name_en} ({entity.source_url})"))
            return sigs
        if owner and owner.id != entity.id:
            sigs.append(Signal(id="phone_other_entity", source="registry", score=1.0,
                               data={"phone": phone, "entity_id": entity.id, "other_ar": owner.entity_name_ar},
                               evidence=f"{phone} belongs to {owner.entity_name_en}, not {entity.entity_name_en}"))
        if entity.phone_set:
            sigs.append(Signal(id="phone_unverified", source="registry", score=1.0, data={"phone": phone, "entity_id": entity.id},
                               evidence=f"{phone} is not among {entity.entity_name_en}'s official numbers in the registry "
                                        f"(registry may be incomplete: unverified, not proven fake)"))
        else:
            sigs.append(Signal(id="phone_unverified", source="registry", score=0, available=False,
                               data={"phone": phone, "entity_id": entity.id},
                               evidence=f"Registry has no verified phone for {entity.entity_name_en}; {phone} cannot be checked"))
        if kind == "mobile" and entity.category in BIG_CATEGORIES:
            sigs.append(Signal(id="phone_mobile_for_brand", source="registry", score=1.0, data={"phone": phone, "entity_id": entity.id},
                               evidence=f"{phone} is a UAE mobile number presented as {entity.entity_name_en} customer service"))
        return sigs

    # ------------------------------------------------------------- LISTING
    def analyze_listing(self, listing: Listing) -> tuple[Verdict, bool]:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        reg = self.registry
        entity = reg.match_name(f"{listing.title} {listing.snippet or ''} {listing.query or ''}")
        site = listing.resolved_domain or listing.displayed_url
        signals: list[Signal] = []
        subs: list[Verdict] = []
        site_official = False
        domain = ""
        if site:
            uv = self.analyze_url(site)
            subs.append(uv)
            domain = uv.normalized.get("registrable_domain", site)
            site_official = bool(uv.matched_entity and uv.matched_entity.get("relation") == "official"
                                 and (entity is None or uv.matched_entity["id"] == entity.id))
            signals += [s.model_copy() for s in uv.signals if s.id != "gov_suffix"]
            if entity and not site_official:
                signals.append(Signal(id="listing_unofficial_site", source="listing", score=1.0,
                                      data={"entity_id": entity.id, "domain": domain},
                                      evidence=f"Listing claims {entity.entity_name_en} but links to {domain}, not an official domain "
                                               f"({', '.join(entity.official_domains)})"))
                if listing.is_ad:
                    signals.append(Signal(id="listing_sponsored_unofficial", source="listing", score=1.0,
                                          data={"entity_id": entity.id, "domain": domain},
                                          evidence=f"Sponsored result for {entity.entity_name_en} pointing to {domain}"))
        phone_ok = True
        if listing.phone:
            ps = self._phone_signals(listing.phone, entity)
            signals += ps
            phone_ok = not any(s.score > 0 for s in ps)
        official = bool(entity) and (site_official or not site) and phone_ok and (site_official or listing.phone)
        risk, level = score(signals, official=official, blocklisted=_blocked(signals))
        ar, en = explain(signals, level, reg, entity if official else None, domain or (listing.phone or ""))
        v = Verdict(input=listing.title, kind="listing", risk=risk, level=level, signals=signals, explanation_ar=ar,
                    explanation_en=en, matched_entity=entity.public() if entity else None, sub_verdicts=subs,
                    normalized={"listing": listing.model_dump(), "domain": domain}, mode=self.settings.mode, analyzed_at=now)
        return v, official


BLOCK_IDS = ("blocklist_hit", "gsb_match", "urlhaus_match")


def _is_block(s: Signal) -> bool:
    """Blocklist-grade hit (forces at least 'high'). URLhaus only for an exact-URL match (score 1.0)."""
    if s.id not in BLOCK_IDS or not s.available or s.score <= 0:
        return False
    return s.id != "urlhaus_match" or s.score >= 1.0


def _blocked(signals: list[Signal]) -> bool:
    return any(_is_block(s) for s in signals)
