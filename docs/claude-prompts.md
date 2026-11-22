# Claude Code prompts for Baseera

Source: the team plan page «خطة بناء بصيرة» (stages 0–7). Prompts are copied verbatim; under each one is its **status in this repo** (built 2026-11-19 without Claude Code, see README › Build path).

How to continue in Claude Code: open the repo root (CLAUDE.md is loaded automatically), start a fresh session per stage, paste the next TODO/PARTIAL prompt, and finish each with: "run make check and show me the output". The Stop hook in `.claude/settings.json` blocks finishing while `make check` fails.

## Stage 0 — Setup & contract

### Prompt 0.1

```text
Read CLAUDE.md. Scaffold a monorepo: backend/ (FastAPI, pydantic v2, pytest, ruff), frontend/ (Next.js + Tailwind, RTL-ready, ar/en i18n), data/registry, data/testset, docs/. Add a Makefile with dev, test, lint, eval targets. No business logic yet. Run make test and make lint and show me the output.
```

**Status:** DONE (adapted): Python package `baseera/` + static RTL frontend instead of Next.js; Makefile has dev/test/lint/eval/check.

### Prompt 0.2

```text
Create backend/schemas.py with the API contract below (Signal, Verdict, Listing, ListingVerdict, Case, Cluster) and a mock /analyze + /scan-brand that return realistic fixture data, so the frontend developer can start immediately. Export the OpenAPI JSON to docs/openapi.json.
[paste the API contract from this page]
```

**Status:** DONE: `baseera/schemas.py`; real (not mock) /api/analyze and /api/scan-brand. `make openapi` writes docs/openapi.json.

### Prompt 0.3

```text
Add backend/config.py reading API keys from environment variables (GSB_API_KEY, SERPAPI_KEY, ANTHROPIC_API_KEY, URLHAUS_AUTH_KEY, PHISHTANK_APP_KEY, VT_API_KEY, URLSCAN_API_KEY) with a feature flag per source (SOURCE_GSB=on|off etc.). Add .env.example only. Make sure .env is in .gitignore.
```

**Status:** DONE (Claude Code), Anthropic caveat: `baseera/config.py` reads env vars; .env.example present; .env git-ignored. GSB + PhishTank keys and SOURCE_GSB/FEEDS/CRTSH/WHOIS_AE flags wired (Claude Code); URLHAUS_AUTH_KEY/VT_API_KEY/URLSCAN_API_KEY + SOURCE_URLHAUS/URLSCAN/VT (default off) wired for Prompt 2.5 (Claude Code). ANTHROPIC_API_KEY is read into Settings but nothing uses it yet.

### Prompt 0.4

```text
Set up a check that Claude Code runs before it says a task is done: a Makefile target 'check' (ruff + pytest) and a Claude Code Stop hook that runs it. Show me the exact settings file you changed.
```

**Status:** DONE: `make check` + `.claude/settings.json` Stop hook.

### Prompt 0.5

```text
Create docs/DECISIONS.md with a table: source, what we use it for, auth needed, rate limit/terms, our caching policy, fallback. Pre-fill rows for Google Safe Browsing, PhishTank, OpenPhish, URLhaus, crt.sh, WHOIS/RDAP, VirusTotal, urlscan.io, SerpAPI, Google Places, Anthropic API. Mark every limit you are not sure about as 'VERIFY'.
```

**Status:** DONE: docs/DECISIONS.md (limits marked VERIFY).

## Stage 1 — Core engine

### Prompt 1.1

```text
Implement backend/normalize.py: parse a URL, lowercase host, decode punycode/IDN, extract registrable domain with a public-suffix library, strip tracking params, and follow redirects up to 5 hops with a 4s timeout WITHOUT executing JavaScript. Return the full redirect chain. Add the SSRF guard from CLAUDE.md before every hop. Write tests, including a private-IP redirect that must be blocked.
```

**Status:** DONE: normalize.py (IDN, PSL offline, tracking params, redirects <=5 hops, 4s, SSRF guard each hop) + tests.

### Prompt 1.2

```text
Implement data/registry/schema.yaml plus backend/registry.py: entities with fields entity_name_ar, entity_name_en, category (telecom|bank|government|police|delivery|utility|airline|retail), official_domains[], official_phones[], official_apps[], source_url, verified_on. Loader must fail loudly if source_url or verified_on is missing. Seed it with 3 example entities marked EXAMPLE so tests can run; the real entries will be added by the product owner.
```

**Status:** DONE (YAML, no separate schema.yaml): data/registry/entities.yaml with REAL verified entries (no EXAMPLE rows) + loud loader.

### Prompt 1.3

```text
Implement backend/signals/lookalike.py: given a host and the registry, detect (a) edit distance <= 2 from an official domain, (b) brand keyword inside another domain (brand-login, brand-pay, brand-support), (c) homoglyph/confusable skeleton match, (d) TLD swap (.ae vs .com/.net/.top), (e) brand in subdomain of an unrelated domain. Return the matched entity, the technique and a one-line evidence string. Add at least 25 table-driven tests using defanged made-up domains.
```

**Status:** DONE: signals/lookalike.py, 37 table-driven cases.

### Prompt 1.4

```text
Implement backend/scoring.py: a pluggable signal list; weighted sum clipped to 0..100; hard overrides (blocklist hit => at least 'high'; exact official domain => 'low'); output per-signal contribution. Weights live in data/weights.yaml so we can tune without code changes. Table-driven tests for the overrides.
```

**Status:** DONE: scoring.py + data/weights.yaml + override tests.

### Prompt 1.5

```text
Add a CLI: python -m scamshield analyze <url> printing the JSON verdict and a human-readable summary, so we can test from the terminal while the UI is not ready.
```

**Status:** DONE: `python -m baseera analyze <url>`.

### Prompt 1.6

```text
Add a property test: every official domain and its common paths in the registry must never score above 'low'. Wire it into make check. This is our false-positive guard.
```

**Status:** DONE: false-positive guard test over every official domain x paths (tests/test_scoring_and_fp.py).

## Stage 2 — Threat-intel sources

### Prompt 2.1

```text
Implement backend/sources/gsb.py: Google Safe Browsing Lookup API v4 client (threatMatches.find, batch up to 500 URLs), honour cacheDuration with an on-disk cache, keep a daily request counter, and expose the attribution + 'not guaranteed' disclaimer text for the UI. Fail soft with available=false.
```

**Status:** DONE (Claude Code): `baseera/sources/gsb.py` (batches of 500, cacheDuration cache, daily counter + limit, fail soft); attribution + disclaimer in /api/health, UI and evidence pack. Live API untested (no key; MockTransport tests only).

### Prompt 2.2

```text
Implement backend/sources/feeds.py: download the PhishTank verified-online database using our app key (JSON) and the OpenPhish community feed, store url, host, target brand, first_seen in SQLite, refresh on each source's own cadence (PhishTank hourly, OpenPhish 12-hourly). Provide match_exact(url) and match_host(host). Add a CLI to refresh and print counts.
```

**Status:** DONE (Claude Code): `baseera/sources/feeds.py` + `python -m baseera feeds refresh|count`; cadence via stored timestamps; integrated into Analyzer next to the synthetic file. OpenPhish verified live; PhishTank keyless URL returned HTTP 404 (needs PHISHTANK_APP_KEY, unverified).

### Prompt 2.3

```text
Implement backend/sources/crtsh.py: query certificates for a domain via crt.sh JSON, return first-seen date, issuer, number of SAN names and whether the cert was issued in the last 7 days. crt.sh is often overloaded: 6s timeout, 2 retries with backoff, cache results, fail soft.
```

**Status:** DONE (Claude Code): `baseera/sources/crtsh.py` (6s, 2 retries with backoff, cache, fail soft); verified live 2026-11-19. Also fills new_certificate when the TLS handshake fails.

### Prompt 2.4

```text
Implement backend/sources/domain_age.py: for gTLDs use RDAP; for .ae use WHOIS on whois.aeda.net.ae and parse the creation date if present. If the registry data is missing or unparsable return available=false and fall back to the first crt.sh certificate date as a documented proxy. Log which path was used in the evidence string.
```

**Status:** DONE (Claude Code), one caveat: `baseera/sources/domain_age.py` runs RDAP, then .ae WHOIS (`baseera/sources/whois_ae.py`), then the crt.sh first-cert proxy, and returns available=false when nothing parses. The evidence string names the path used and why each earlier step failed. signals/domain_intel.py calls it. Offline tests for every path are in `tests/test_domain_age.py`. Caveat: the .ae WHOIS parser is tested only on SYNTHETIC samples shaped like the aeDA layout. Port 43 connected but returned no data from the build box (2026-11-19), so the real .ae output (and whether it includes a creation date) is still unverified.

### Prompt 2.5

```text
Implement backend/sources/urlhaus.py (Auth-Key header from env) and an optional urlscan.io lookup that uses UNLISTED scans only. Both optional behind feature flags. Do not add VirusTotal in the hot path; add it only as a manual 'deep check' button because the free tier is 4 requests/minute.
```

**Status:** DONE (Claude Code), untested live (no keys): `baseera/sources/urlhaus.py` (url + host lookup, `Auth-Key` header; exact URL hit = blocklist-grade, host hit partial), `baseera/sources/urlscan.py` (read-only search of existing scans, informational weight 0; never submits, `SUBMIT_VISIBILITY="unlisted"` if it ever does), `baseera/sources/virustotal.py` (existing report only, 4 req/min limiter) exposed only as `POST /api/deep-check/virustotal` + a button in the verdict card (shown when enabled), never in /api/analyze or the score. All behind `SOURCE_URLHAUS` / `SOURCE_URLSCAN` / `SOURCE_VT` (default off), cached, fail soft, listed in /api/health. Offline tests: `tests/test_optional_sources.py` + `tests/test_degradation.py`. The UI button was syntax-checked only, not clicked in a browser.

### Prompt 2.6

```text
Implement the orchestrator backend/analyze.py: run all enabled collectors concurrently with a 4s per-source timeout, collect Signals, tolerate partial failures (available=false, never an exception), compute the score, and return a Verdict. Add an integration test using recorded fixtures (no network).
```

**Status:** DONE: analyze.py orchestrator, fail-soft; offline tests. (Not async; threads.)

## Stage 3 — Search & Maps

### Prompt 3.1

```text
Define Listing in schemas.py: source (search|maps), query, rank, is_ad, title, displayed_url, resolved_domain, phone, address, snippet. Add data/queries.yaml with templates like '<brand> customer service number', '<brand> contact', '<brand> login' and Arabic equivalents; the product owner will fill the brand list.
```

**Status:** DONE (Claude Code): Listing schema + data/queries.yaml (English + Arabic templates; names filled from the registry; 10 demo brands).

### Prompt 3.2

```text
Implement backend/sources/serp.py using SerpAPI (key from env) for Google Search and Google Maps results for Abu Dhabi/UAE. The free plan is 250 searches/month and 50/hour, so: persistent disk cache keyed by query, a hard monthly budget counter in config, and a --record flag that saves raw responses to data/fixtures/ for replay mode. Replay mode must work with no network. If SerpAPI's Maps engine does not return phone numbers, fall back to Google Places Text Search (check which SKU/fields are needed and note the free allowance in DECISIONS.md).
```

**Status:** PARTIAL: serp.py has a SerpAPI client (UNTESTED, no key); replay uses SYNTHETIC fixtures in data/fixtures/serp/.

### Prompt 3.3

```text
Implement backend/phones.py with the phonenumbers library: normalize UAE numbers to E.164, classify toll-free (800), mobile, landline, premium, and compare against the registry official_phones. A brand named in the listing but a phone not in the registry => 'unverified customer-service number' signal (not automatically fake: the registry may be incomplete, so score it as medium, and say so in the explanation).
```

**Status:** DONE (own implementation, no phonenumbers lib): phones.py; unverified = medium, explanation says registry may be incomplete.

### Prompt 3.4

```text
Implement backend/listing_verifier.py: for each Listing, run the URL pipeline on its resolved domain, add listing-specific signals (is_ad, brand in title but domain not official, phone mismatch, address mismatch, very new domain), and output ListingVerdict with a short Arabic reason.
```

**Status:** DONE: listing verification inside analyze.py (analyze_listing).

### Prompt 3.5

```text
Add POST /scan-brand: for a brand, query Search + Maps (or replay fixtures), verify every listing, return the table sorted by risk with the official result clearly marked as 'verified official (source: registry)'. Add tests with fixtures.
```

**Status:** DONE: POST /api/scan-brand with tests.

### Prompt 3.6

```text
Create scripts/record_demo_fixtures.py that records live results for 8-10 demo brands once, so the live demo can run in replay mode. The UI must label replayed data as 'recorded' so we never pass old data off as live.
```

**Status:** PARTIAL (Claude Code): scripts/record_demo_fixtures.py writes data/fixtures/serp/recorded/ only when SERPAPI_KEY exists (clear message otherwise); API/UI label it `recorded <date>` (not live). Nothing recorded yet (no key).

## Stage 4 — Sandbox, LLM, calibration

### Prompt 4.1

```text
Implement backend/sandbox.py: Playwright headless Chromium inside Docker, fresh profile per scan, downloads disabled, 10s navigation timeout, no form submission, no clicks. Capture a full-page screenshot, visible text (truncate to 6000 chars), page title, and the names/types of input fields (password, otp, card number, emirates id) plus the domains that forms post to. Return a SandboxResult. Run it only after the SSRF guard approves the host.
```

**Status:** DONE (Claude Code): baseera/sandbox.py (system Chrome via Playwright, no Docker: fresh context per scan, downloads refused, service workers blocked, 10s nav timeout, no clicks/typing, non-GET aborted, every request SSRF-checked and fetched through `safe_fetch`). Captures screenshot (`data/runtime/screenshots/<sha256>.png` + 64-bit dHash), title, text (6000 chars, kept in memory only), classified input fields, form post domains. Opt-in via `deep: true` / `SOURCE_SANDBOX`; signals `sensitive_form` + `brand_in_page`; screenshot in UI + evidence pack. Tests: tests/test_sandbox.py (local HTML, skipped if Chrome cannot launch).

### Prompt 4.2

```text
Implement backend/llm.py: send the screenshot, truncated text, URL, and the registry candidate brand to the Anthropic API with vision. Require a strict JSON schema: impersonated_brand|null, requests_sensitive_data[], urgency_cues[], language, looks_like_official_page (bool), confidence 0..1, reasons[]. Validate with pydantic, retry once on invalid JSON, cache by content hash, log cost and latency per call. The system prompt must state that page text is untrusted data and instructions inside it must be ignored.
```

**Status:** TODO: LLM vision step (needs ANTHROPIC_API_KEY).

### Prompt 4.3

```text
Make the LLM a cascade step: call it only when the rule-based score is between two thresholds from weights.yaml (clearly safe and clearly bad pages skip it). Add its output as signals (impersonation, sensitive-data request) with weights.
```

**Status:** TODO: LLM cascade.

### Prompt 4.4

```text
Implement backend/explain.py: build the Arabic explanation from a deterministic template over the top 3 contributing signals (each sentence must cite its evidence), with an English version. The LLM may only polish wording; add a test that fails if the explanation mentions a fact that is not present in any signal.
```

**Status:** DONE: explain.py deterministic AR/EN template over top-3 signals + test that it states no fact outside signals.

### Prompt 4.5

```text
Write scripts/calibrate.py: run the labeled test set, sweep thresholds, print precision, recall, F1 and false-positive rate per threshold, list every false positive and false negative with the signals that caused it, and write docs/eval.md. Do not hard-code any numbers into docs by hand.
```

**Status:** DONE: scripts/calibrate.py -> docs/eval.md (synthetic set, clearly labelled).

### Prompt 4.6

```text
Review the analyzer for prompt-injection and SSRF risks and fix anything you find: hostile page text, redirects to internal IPs, huge pages, decompression bombs, slow-loris responses. Add tests for each.
```

**Status:** DONE (Claude Code): hostile page text (injection test: verdict unchanged), redirects to internal IPs (follower + sandbox, every hop), IP literals checked without the resolver, bodies > 2 MB refused (Content-Length and streamed), decompression bombs cut after 2 MB decoded, slow-loris wall-clock deadline + timeouts — tests in tests/test_normalize.py and tests/test_sandbox.py. DNS-rebinding TOCTOU closed: safe_fetch / follow_redirects / TLS lookup connect only to the SSRF-checked IP (pinned httpcore backend; Host, SNI and cert verification keep the hostname; unchecked hosts and env proxies refused), sandbox covered via page.route → safe_fetch — tests in tests/test_dns_pinning.py (resolver answers public then private; connection proven to use the checked IP). Remaining (low risk, docs/LIMITATIONS.md §4): fixed-host source clients (RDAP, feeds) are hook-checked, not pinned; pin relies on httpx 0.28 internals (fails closed).

## Stage 5 — UI, analyst dashboard, evidence pack

### Prompt 5.1

```text
In frontend/, build the Analyze page, Arabic-first with an English toggle: one input that accepts a URL, pasted message text, or a brand name; a verdict card with a risk gauge and a colour level; the 3-reason Arabic explanation; an expandable signal breakdown with sources; the sandbox screenshot; and a 'report to police' panel that shows the Aman channels (call 8002626, SMS 2828) as plain text. Use the mock API first, then the real one.
```

**Status:** DONE: Analyze tab (URL / text / manual listing), gauge, 3 reasons, signal breakdown, Aman panel. Deep-scan checkbox + sandbox screenshot in the verdict card (Claude Code, with Prompt 4.1).

### Prompt 5.2

```text
Build the Brand Scan page: choose a brand, call /scan-brand, show a table of Search and Maps results with the official result marked, suspicious ones highlighted, fake-looking customer-service numbers called out, and a 'recorded' badge in replay mode.
```

**Status:** DONE: Search & Maps tab (synthetic badge).

### Prompt 5.3

```text
Implement case storage and clustering in backend/cases.py: store each high/medium verdict as a Case; compute campaign clusters from shared signals: same name servers, same IP/ASN, same certificate issuer + overlapping SAN names, same registrar, and perceptual hash of the screenshot. Expose /cases and /clusters. Add a test with 6 synthetic cases forming 2 clusters.
```

**Status:** DONE: cases.py SQLite + clustering (phone, IP, NS, phash keys strong; registrar/issuer/path/target/creation-week weak) + 6-case test.

### Prompt 5.4

```text
Build the Analyst Dashboard: list of campaigns (brand targeted, number of domains, first/last seen), a cluster detail view with a simple node graph, a timeline, filters by brand and category, and a 'top campaigns' summary. Keep it fast to demo: 3 clicks maximum from landing to evidence pack.
```

**Status:** DONE: Analyst dashboard: KPIs, campaigns, SVG node graph, timeline, filters, evidence links.

### Prompt 5.5

```text
Implement the evidence pack: GET /cases/{id}/evidence.pdf and .json containing the URL and redirect chain, UTC timestamps, screenshot, SHA-256 hashes of every artifact, each signal with its source and raw evidence, WHOIS/RDAP/certificate data, cluster membership, and a recommended action section with a draft takedown/report text. The pack must say clearly which parts are automated findings and that a human analyst must confirm.
```

**Status:** DONE: evidence JSON / HTML / ZIP (SHA-256 manifest) / PDF (headless Chrome).

### Prompt 5.6

```text
Stretch only if everything above passes make check: a minimal Chrome Manifest V3 extension with a popup that sends the current tab URL to /analyze and shows the Arabic verdict. Do not spend more than one hour on it.
```

**Status:** DONE (direct, after the Claude Pro usage limit): `extension/` MV3 popup, CORS limited to chrome-extension origins, tests/test_cors_extension.py.

## Stage 6 — Evaluation, hardening, freeze

### Prompt 6.1

```text
Extend make eval: run the labeled set and print the confusion matrix, precision, recall, F1, false-positive rate, median and p95 latency, and an ablation table showing how metrics change when each signal is removed. Save to docs/eval.md and make the pitch deck read from this file.
```

**Status:** DONE: confusion matrix, P/R/F1/FPR, latency, ablation in docs/eval.md; scripts/make_pptx.py reads the metrics from docs/eval.md.

### Prompt 6.2

```text
Write an adversarial false-positive suite: official domains with deep paths, legitimate .com sites used by UAE brands, newly registered but legitimate domains, URL shorteners to legitimate pages, subdomains on shared platforms. List everything that scores medium or high and propose threshold or registry fixes. Do not change thresholds without showing the before/after metrics.
```

**Status:** DONE (Claude Code): tests/test_adversarial_fp.py + more adversarial rows; new weight official_domain_in_url (before/after in docs/DECISIONS.md).

### Prompt 6.3

```text
Add a /health page showing which data sources are up, their remaining daily budget and whether we are in live or replay mode. Add graceful degradation tests (disable each source and confirm /analyze still returns a verdict).
```

**Status:** DONE (Claude Code): per-source status in /api/health (baseera/sources/status.py) + tests/test_degradation.py.

### Prompt 6.4

```text
Run a security review of the whole repo: secrets in git history, SSRF, unsafe deserialization, CORS, unauthenticated admin endpoints, dependency issues. Fix what is cheap, and list what remains in docs/LIMITATIONS.md.
```

**Status:** DONE (Claude Code, docs finished directly): optional ANALYST_TOKEN, body-size limit, security headers/CSP, trusted hosts, requirements.lock; remaining items in docs/LIMITATIONS.md.

### Prompt 6.5

```text
Write README.md: what it does, architecture diagram, how to run (including replay mode), data sources and their terms, evaluation method and results (read from docs/eval.md), limitations, and what we would build next.
```

**Status:** DONE: README.md (refreshed directly after the usage limit).

### Prompt 6.6

```text
Freeze: create tag 'submission', run make check and make eval one last time from a clean clone, and list any failing item.
```

**Status:** TODO at the event.

## Stage 7 — Demo & submission

### Prompt 7.1

```text
Create a demo script runner (scripts/demo.md + a checklist page in the app) that lists the exact inputs for the 3-minute demo in order, with the expected result for each, so any teammate can run it. Use only real recorded results, labeled as recorded.
```

**Status:** DONE: docs/demo.md.

### Prompt 7.2

```text
Pre-warm caches for every demo input and verify each one returns in under 5 seconds in both live and replay modes; print a table of timings.
```

**Status:** PARTIAL (Claude Code): scripts/prewarm.py runs every docs/demo.md row plus every brand with replay data (cold + warm call each), prints the table and writes docs/timings.md; replay/offline run: 14 PASS, 0 FAIL, 2 SKIP (slide row; optional deep scan). tests/test_prewarm.py checks the script's inputs match docs/demo.md and the frontend examples. Live mode NOT measured (build box has no keys, limited egress): run `scripts/prewarm.py --base-url http://127.0.0.1:8000` on the demo laptop.

### Prompt 7.3

```text
Generate a one-page project summary (problem, solution, architecture, metrics from docs/eval.md, limitations, next steps) as Markdown and PDF for the submission form and the judges.
```

**Status:** DONE: docs/summary.md (+ draft docs/Baseera.pptx). PDF: print docs/summary.md or the evidence HTML with Chrome.

### Prompt 7.4

```text
Do a final end-to-end test from a fresh clone on a second laptop following the README only. Report every step that failed or was unclear and fix the README.
```

**Status:** TODO.

### Prompt 7.5

```text
Prepare the submission bundle checklist: repo link, demo video link, summary PDF, any form fields we know of. List what is still unknown about the submission format so the team can confirm it on the Podium+ page before the deadline.
```

**Status:** PARTIAL (Claude Code): docs/submission-checklist.md (bundle items with state, form fields, 13 unknowns marked UNKNOWN incl. team size, deadline, format). No remote, no video and no summary PDF exist yet; unknowns must be confirmed on the Podium+ page.

## API contract (from the plan)

```text
POST /analyze  { url?: string, text?: string, listing?: Listing }
  -> Verdict { risk: 0..100, level: 'low'|'medium'|'high', signals: Signal[], explanation_ar: string,
               explanation_en: string, campaign_id?: string, screenshot_url?: string, case_id: string }
POST /scan-brand { brand: string, country: 'AE' }  -> ListingVerdict[]  (Search + Maps results ranked by risk)
GET  /cases?brand=&level=  -> Case[]      GET /clusters -> Cluster[]      GET /cases/{id}/evidence.pdf
Signal { id, source, score: 0..1, weight, evidence: string, available: boolean }
```
