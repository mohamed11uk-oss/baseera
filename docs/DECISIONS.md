# Data sources & decisions

| Source | Used for | Auth | Rate limit / terms | Cache | Fallback | Status in repo |
|---|---|---|---|---|---|---|
| Official Entity Registry (`data/registry/entities.yaml`) | official domains + phones, false-positive guard | none | read from each entity's own site; record source_url + verified_on | file | — | **live**: 9 verified, 10 domain-only (2026-11-19) |
| RDAP (rdap.org bootstrap, `baseera/sources/domain_age.py`) | domain registration date, registrar, name servers | none | VERIFY per registry | `data/runtime/rdap_cache.json` 24h (errors not cached) | .ae WHOIS (.ae only), then crt.sh proxy, else `available=false` | **live**; every redirect hop SSRF-checked |
| Direct TLS handshake | certificate issue date + issuer (stand-in for crt.sh) | none | one connection per host | JSON file, 24h | `available=false` | **live** |
| HTTP redirect follower | redirect chain (≤5 hops, no JS, no body download) | none | — | none | `available=false` | **live** |
| Local blocklist file (`data/blocklist/`) | exact host/URL hits | none | — | — | — | **synthetic demo feed only** (kept alongside the real feeds) |
| Google Safe Browsing v4 Lookup (`baseera/sources/gsb.py`) | blocklist (match ⇒ at least high, like a feed hit) | `GSB_API_KEY` (off without it), `SOURCE_GSB` | daily counter, hard stop at `GSB_DAILY_LIMIT` (default 10000 — VERIFY the real quota); Lookup API v4 is for non-commercial use (VERIFY current terms / v5 migration); attribution "Advisory provided by Google" + "not guaranteed" disclaimer shown in UI, /api/health and evidence pack (wording VERIFY against current terms) | matches cached for the API's `cacheDuration`; no-match cached 300s (VERIFY) — `data/runtime/gsb_cache.json` | `available=false` | **implemented, untested live (no key)**; tests use MockTransport |
| PhishTank verified-online JSON (`baseera/sources/feeds.py`) | blocklist: exact URL, else same host (shared platforms excluded) | `PHISHTANK_APP_KEY` (optional) | refresh at most **hourly** (stored last-attempt timestamp); keyless URL returned **HTTP 404** from the build box on 2026-11-19 — an app key is probably required (VERIFY; PhishTank registration status also VERIFY) | SQLite `data/runtime/feeds.db`, snapshot replaced per refresh, first_seen kept | previous snapshot kept; `available` via status | **implemented**, live download NOT verified (404 without key) |
| OpenPhish community feed (`baseera/sources/feeds.py`) | blocklist (no target brand in the community feed) | none | refresh at most every **12 h**; community-feed terms of use VERIFY (non-commercial?) | SQLite `data/runtime/feeds.db` | previous snapshot kept | **implemented, verified live 2026-11-19** (298 URLs imported) |
| URLhaus API (`baseera/sources/urlhaus.py`) | malware-distribution URLs: exact URL (1.0 + "at least high" override), else same host (0.5 if a listed URL is online, 0.25 if all offline; shared platforms skipped) | `URLHAUS_AUTH_KEY` in the `Auth-Key` header, `SOURCE_URLHAUS` (default **off**) | abuse.ch fair-use terms and rate limit VERIFY; one url + at most one host POST per analyzed URL | `data/runtime/urlhaus_cache.json` 1h (errors not cached) | `available=false` | **implemented, untested live (no key)**; tests use MockTransport |
| crt.sh (`baseera/sources/crtsh.py`) | first logged certificate date (domain-age **proxy**), latest issuer, SAN count, issued < 7 days | none | often overloaded: 6s timeout, 2 retries (0.5s/1s backoff); rate limit VERIFY | `data/runtime/crtsh_cache.json`: 24h ok, 15 min failures | `available=false` | **implemented, verified live 2026-11-19** |
| WHOIS whois.aeda.net.ae:43 (`baseera/sources/whois_ae.py`) | .ae creation date / registrar / NS (tried before crt.sh) | none | VERIFY; whether the output contains a creation date is UNVERIFIED | `data/runtime/whois_ae_cache.json` 24h / 15 min | crt.sh | **implemented, fails soft**; port 43 timed out from the build box (2026-11-19) |
| VirusTotal v3 URL report (`baseera/sources/virustotal.py`) | manual deep check only: `POST /api/deep-check/virustotal` + button in the verdict card; never in `/api/analyze`, never scored, never submits URLs | `VT_API_KEY` (`x-apikey` header), `SOURCE_VT` (default **off**) | free public API: 4 requests/min (in-process sliding window, `VT_PER_MINUTE`); daily quota and non-commercial terms VERIFY | `data/runtime/virustotal_cache.json` 1h; cache hits do not count against the limiter | `available=false` (rate limit returns `retry_after_s`) | **implemented, untested live (no key)**; tests use MockTransport |
| urlscan.io Search API (`baseera/sources/urlscan.py`) | existing scans of the host (count, first/last seen, malicious flag of the latest 10): informational, weight 0 | `URLSCAN_API_KEY` (`API-Key` header), `SOURCE_URLSCAN` (default **off**) | read-only GET search; no scan is ever submitted (if added, it must use `visibility=unlisted`, `SUBMIT_VISIBILITY`); search quota VERIFY; `verdicts` field shape on search results VERIFY | `data/runtime/urlscan_cache.json` 6h (errors not cached) | `available=false` | **implemented, untested live (no key)**; tests use MockTransport |
| SerpAPI (Google Search + Maps) | Search/Maps listings; `scripts/record_demo_fixtures.py` records 8–10 brands once into `data/fixtures/serp/recorded/` (labelled `recorded <date>`) | `SERPAPI_KEY` | free plan small (VERIFY); default recording = 10 brands × 2 langs × (Search+Maps) = 40 searches (`--dry-run` shows the plan) | recorded files | recorded → synthetic fixtures | client + recorder implemented, parsing tested on fixtures, **live untested (no key)** |
| Google Places Text Search | phone/website of Maps listings | API key | VERIFY SKU pricing | disk | — | TODO |
| Headless Chrome deep scan (`baseera/sandbox.py`, Playwright + system Chrome) | screenshot (SHA-256 + 64-bit dHash), title, form fields (password/OTP/card/Emirates ID/phone), form post domains | none | opt-in: only when `/api/analyze` gets `deep: true` (`SOURCE_SANDBOX=request`, default), every URL with `SOURCE_SANDBOX=on`, never with `off`; one page per request, ≤150 sub-requests, ≤10 MB total | screenshots `data/runtime/screenshots/<sha256>.png` (no expiry yet) | `sandbox` signal `available=false` | **implemented**; verified live 2026-11-19 on example.com only; tests use local HTML |
| Anthropic API (vision) | grey-zone page impersonation | API key | cost per call | content hash | rules only | TODO |

## Decisions
- **Rules + registry first, LLM later.** Every risk point maps to a named signal with evidence; this is what police
  analysts and judges can audit. An LLM is only planned for grey-zone pages (risk between thresholds).
- **Static frontend instead of Next.js.** One process, one command, no Node build; the hackathon demo cannot fail on a build step.
- **SQLite** for cases: zero setup; clustering is computed on read (fine for thousands of cases).
- **Offline PSL** (tldextract bundled snapshot) so URL parsing never needs network.
- **Unverified phone = medium, never "fake".** The registry is incomplete by design.
- **Thresholds** (`data/weights.yaml`): medium ≥ 30, high ≥ 55. Picked from the sweep in docs/eval.md on a SYNTHETIC set; re-tune on real data.
- **BASEERA_SSRF_ALLOW** exists only because some sandboxes resolve every host to a fake-IP proxy range (198.18.0.0/15). Leave empty on normal machines.
- **Feed hits on official domains never override the registry** (2026-11-19). A PhishTank/OpenPhish/GSB listing on a
  registry domain is shown as a 0-point signal "analyst review" (possible compromised page or feed error); the verdict
  stays low. Rationale: official-domain false positives are release blockers (CLAUDE.md rule 8).
- **Host-level feed matches skip shared platforms** (free hosting, shorteners, docs/drive/storage, etc.: `SHARED_HOSTS`
  in analyze.py). One phishing page on sites.google.com must not flag every page there; exact-URL matches still count.
- **Domain-age fallback chain:** RDAP → (.ae only) WHOIS → crt.sh first certificate. The crt.sh path is a proxy
  (a domain is at least as old as its first logged certificate), so its severity is capped at 0.5 (< 30 days) instead of 1.0.
  The `new_domain` evidence string lists every path tried and why it failed. The chain lives in
  `baseera/sources/domain_age.py` (moved out of signals/domain_intel.py, which only calls it).
- **New weight `gsb_match: 60`** (same as `blocklist_hit`, plus the same "at least high" override). Offline eval unchanged
  (GSB is off offline); docs/eval.md re-generated 2026-11-19 with identical P/R/F1/FPR.
- **URLhaus, urlscan.io and VirusTotal are off by default (2026-11-19).** Unlike GSB/feeds (on when a key exists), these
  need `SOURCE_*=on` AND a key. New weights: `urlhaus_match: 60` (exact URL forces at least high, like a feed hit; a
  same-host match is 0.5/0.25 and does not force anything; team-chosen, not facts) and `urlscan_seen: 0` (other
  people's scans are context, not a verdict). VirusTotal is kept out of the score and out of the analyze path because
  the free tier allows 4 requests/minute; it only reads existing reports so a victim's link is never shared with
  VirusTotal. The official-domain guard applies to URLhaus too. Offline eval is unchanged (all three are off offline).
- **Deep scan is opt-in and network-isolated (2026-11-19).** Chrome never opens a socket itself: `page.route` sends
  every request (document, redirect hop, iframe, script, image) through `safe_fetch` after `ssrf_check`; redirects
  are followed by us so every hop is re-checked; non-GET requests are aborted (nothing is ever posted); WebSockets
  are never connected; downloads refused; service workers blocked; 10 s navigation timeout. `safe_fetch` caps every
  body at 2 MB **after decompression** and applies a wall-clock deadline (slow-loris). `ssrf_check` now judges IP
  literals directly instead of trusting the resolver.
- **New weights `sensitive_form: 20` and `brand_in_page: 15`** (team-chosen starting values, not facts). `sensitive_form`
  is severity 1.0 for OTP/card/Emirates ID fields and 0.5 for a password-only form (ordinary login pages).
  `brand_in_page` ignores registry keywords shorter than 3 chars and needs ≥ 4 chars in body text (e.g. «تم» is a common
  Arabic word). Both are zeroed on official domains (FP guard). Deep scan is off in `make eval`, so docs/eval.md
  metrics are unchanged (re-generated 2026-11-19).
- **Page text is untrusted data:** only fixed regex/keyword checks run on it; it is not stored in the verdict, the
  case DB or the evidence pack (only title, field list, hashes). A test proves injected instructions do not move the verdict.
- **Screenshot hash = dHash of the top 1280×900 viewport** (not the full page), so the same phishing kit with a
  different page length still hashes alike. Stored as `infra.screenshot_phash` for clustering.
- **Feeds are refreshed by the CLI only** (`python -m baseera feeds refresh|count`), never inside /api/analyze; lookups are
  local SQLite and therefore also work offline. Tests force `SOURCE_FEEDS=off` and use in-memory stores.
- **official_domain_in_url = 15** (added by the Claude Code hardening session, 2026-11-19): an official registry domain
  appearing in the path/query of a non-official host (e.g. `evil.example/www.adpolice.gov.ae/login`). On the current
  test set (docs/eval.md): with the signal P 0.98 / R 0.95 / F1 0.96 / FPR 0.02; with it removed (ablation row)
  P 0.97 / R 0.91 / F1 0.94 / FPR 0.02. Thresholds unchanged.
- **CORS** is closed except for `chrome-extension://` origins (browser extension); override with `BASEERA_CORS_ORIGINS`.
