# بصيرة (Baseera) — fake link & fake listing detector for the UAE

> ScamShield AI hackathon (Abu Dhabi Police × 42 Abu Dhabi) — challenge: *detect fraudulent links and websites,
> including those appearing in search engines and Maps.*
> Prototype. Results are automated and must be confirmed by a human. Anything labelled **synthetic** is demo data.

## Quick start
```bash
./run.sh                          # Python 3.11+: creates .venv, installs deps, serves http://127.0.0.1:8000
BASEERA_MODE=offline ./run.sh     # same, with no network at all (deterministic; safest for a live demo)
```
Open http://127.0.0.1:8000 (Arabic UI, **English** button top-left). Tabs: link/SMS check, Search & Maps check,
analyst dashboard (campaigns + evidence packs), status & registry.

- **Demo video (submission):** [baseera_demo_v2.mp4 on Google Drive](https://drive.google.com/file/d/1YgBR549bf9J28h889s32-M9aGa0d0E1L/view?usp=drivesdk) (anyone with the link can view).
- **Pitch deck:** `docs/Baseera.pptx` (PNG previews in `docs/deck_preview/`). **Summary (2 pages):** `docs/Baseera_summary.pdf`.
- **Team Baseera:** Mohammed Nasser Albalushi (Team Lead), Hasan Al salami, Adnan Almarzooqi.

## Problem
Scammers impersonate UAE government entities, police, banks and telcos with look-alike websites, SMS links and
fake "customer service" numbers on Search and Maps. Abu Dhabi Police publicly warn about fake links in search results
and run the **Aman** reporting service (call **8002626**, SMS **2828** — listed on adpolice.gov.ae, checked 2026-11-19).
A resident needs a fast answer *"is this link / number really the official one?"*; an analyst needs to see that
twenty fake sites are one campaign and get an evidence pack.

## Solution
1. **Link & message check** — paste a URL or an SMS/WhatsApp text. Baseera extracts links and phone numbers and returns a
   0–100 risk, a level (low/medium/high) and the **top-3 reasons in Arabic** (English below), each tied to evidence.
2. **Official Entity Registry** — official domains and phone numbers of UAE entities, each with `source_url` +
   `verified_on`. Exact official domains can never score above *low* (false-positive guard, enforced by tests).
3. **Search & Maps listing verifier** — compares a listing's name, phone and website with the registry: look-alike
   site, sponsored ad to an unofficial domain, mobile number posing as bank support, hijacked Maps pin (official site but
   unknown phone ⇒ *unverified*, medium — never called "fake" because the registry can be incomplete).
4. **Analyst dashboard** — every medium/high verdict becomes a case; cases are **clustered into campaigns** by shared
   phone, IP, name servers, (screenshot hash), registrar, certificate issuer, URL path pattern, target and creation week.
5. **Evidence pack** — JSON, printable HTML, PDF (headless Chrome, Arabic-correct) and ZIP with SHA-256 manifest:
   URL + redirect chain, UTC timestamps, signals with sources, infrastructure, campaign, recommended action and a draft
   report text (never sent automatically).
6. **Deep scan (opt-in)** — headless Chrome sandbox: screenshot, perceptual hash, OTP/card/Emirates-ID form detection,
   brand text on a non-official domain. No clicks, no form posts, no downloads; every request passes the SSRF guard.
7. **Browser extension** (`extension/`, Chrome MV3) — checks the current tab against your Baseera server.
8. **Bilingual UI** — Arabic RTL first, one-click English; explanations generated in both languages.
9. **Offline mode** — `BASEERA_MODE=offline` never touches the network (tests, eval, demo replay).

Screenshots: `docs/screenshots/` (01–10). Pitch deck: `docs/Baseera.pptx`. Summary PDF: `docs/Baseera_summary.pdf`.
Demo script: `docs/demo.md`.

## Tools, APIs and data
**Core (no keys required):** Python 3.11+, FastAPI, SQLite, static vanilla JavaScript Arabic RTL UI, Chrome MV3 extension,
`./run.sh` or Docker. Scoring is rules + a verified Official Entity Registry (`data/registry/entities.yaml`) — no ML model
in the hot path.

**Optional live sources** (all fail-soft, 4 s timeout, cached; disable with `BASEERA_MODE=offline` or per-source flags):
RDAP, `.ae` WHOIS, crt.sh, TLS certificate age, PhishTank, OpenPhish, Google Safe Browsing v4, SerpAPI (Search & Maps),
URLhaus, urlscan.io (read existing scans only), VirusTotal (manual deep check only). Keys go in a git-ignored `.env`
(see `.env.example`). Headless Chrome is used only for the opt-in deep-scan sandbox and evidence PDFs.

**Data in the repo:** 19 UAE entities in the registry (9 with phones verified on the official site on 2026-11-19);
signal weights in `data/weights.yaml`; a synthetic labelled test set in `data/testset/labeled.csv`; synthetic Search/Maps
fixtures and demo campaign cases (documentation IP ranges), all labelled.

## Architecture
```
 Browser (Arabic RTL UI: frontend/)            CLI: python -m baseera analyze <url|text>
            │  JSON
            ▼
 FastAPI  baseera/api.py  ── /api/analyze /api/scan-brand /api/cases /api/clusters /api/cases/{id}/evidence.* /api/health
            │
            ▼
 Analyzer baseera/analyze.py ── url | text | listing
   ├─ normalize.py      IDN/punycode, offline Public Suffix List, tracking-param strip, redirects ≤5 hops + SSRF guard
   ├─ signals/lexical.py       IP host, punycode, abused TLD, free hosting, '@', lure words, shortener, gov wording…
   ├─ signals/lookalike.py     typosquat (Damerau), homoglyph skeleton, brand keyword, TLD swap, brand in sub-domain
   ├─ signals/domain_intel.py  TLS certificate age + domain age via sources/domain_age.py
   │                           (RDAP → .ae WHOIS → crt.sh proxy; live, cached, fail-soft)
   ├─ sources/feeds.py, gsb.py PhishTank/OpenPhish local SQLite blocklist; Google Safe Browsing v4 (key only)
   ├─ phones.py + registry.py  UAE number normalisation/classification vs official numbers
   ├─ scoring.py               weighted sum (data/weights.yaml) + hard overrides (blocklist ⇒ high, official ⇒ low)
   └─ explain.py               deterministic Arabic/English template over the top-3 signals
 cases.py   SQLite case store + union-find campaign clustering
 evidence.py JSON / HTML / ZIP (SHA-256) / PDF
 sandbox.py  opt-in headless Chrome deep scan (screenshot, dHash, sensitive forms, brand-in-page)
 security.py optional ANALYST_TOKEN, body-size limit, CSP/security headers
 serp.py    Search+Maps listings: SYNTHETIC replay fixtures, optional SerpAPI live client
```

## Technical choices & trade-offs
| Choice | Why | Trade-off |
|---|---|---|
| Rules + verified registry, no ML model in the hot path | Explainable to police and judges; every point of risk has evidence; works offline; ~1 ms per URL | Misses novel lures without a brand cue (see FNs in docs/eval.md) |
| Registry-based false-positive guard | Blocking the real police/bank site is the worst failure | Registry must be maintained; unregistered entities get no protection |
| "Unverified" not "fake" for unknown numbers | Registry is incomplete; avoids false accusations | Medium instead of high for some real scams |
| Deterministic explanations (no LLM) | No invented facts — a test fails if the text mentions anything not in a signal | Less natural wording |
| FastAPI + static vanilla JS (not Next.js) | One process, one command, no build step during a 24h demo | Less component reuse |
| SQLite, clustering on read | Zero setup | Fine for thousands of cases, not millions |
| All external sources optional, 4s timeout, cache, `offline` mode | Demo never breaks on a slow API; tests are deterministic | Offline verdicts lack domain age / TLS |
| Synthetic demo data, labelled everywhere | We did not have real recorded Search/Maps data or API keys; never pass fake data off as real | Metrics are not real-world accuracy |

### Privacy design
- No user accounts, no tracking; inputs are processed locally. Only medium/high verdicts are stored (SQLite, local file).
- Suspect pages are never logged into, no forms are submitted, nothing is downloaded (redirect follower streams headers only).
- SSRF guard on every hop (private, loopback, link-local, metadata IPs blocked).
- Secrets only via env vars (`.env.example`); `.env` is git-ignored.
- Evidence packs state clearly which parts are automated and require analyst confirmation.

## How to build and run
```bash
./run.sh                          # creates .venv, installs requirements, serves http://127.0.0.1:8000
# or
make install && make dev
BASEERA_MODE=offline ./run.sh     # no network at all (domain age/TLS shown as unavailable)
docker build -t baseera . && docker run -p 8000:8000 baseera   # optional
```
CLI: `.venv/bin/python -m baseera analyze "https://example.com/login"`
Threat feeds: `.venv/bin/python -m baseera feeds refresh` (PhishTank hourly / OpenPhish 12h cadence, local SQLite) and `... feeds count`.
Record real Search/Maps results once for replay: `SERPAPI_KEY=... .venv/bin/python scripts/record_demo_fixtures.py` (labelled *recorded YYYY-MM-DD*).
API docs (OpenAPI/Swagger): http://127.0.0.1:8000/docs — exported to `docs/openapi.json` with `make openapi`.

Environment (all optional): `BASEERA_MODE=live|offline`, `BASEERA_TIMEOUT=4`, `SOURCE_RDAP|SOURCE_TLS|SOURCE_REDIRECTS|SOURCE_FEEDS|SOURCE_CRTSH|SOURCE_WHOIS_AE|SOURCE_GSB=on|off`,
`SOURCE_SANDBOX=request|on|off` (deep scan: only on `deep: true` / every URL / never), `BASEERA_SCREENSHOT_DIR`,
`GSB_API_KEY`, `PHISHTANK_APP_KEY`, `SERPAPI_KEY` (or `SERPAPI_API_KEY`), `BASEERA_DB`, `BASEERA_SEED_DEMO=on|off`, `BASEERA_SSRF_ALLOW` (only for sandboxes whose DNS returns fake-IP proxy addresses).

Keys: copy `.env.example` to `.env` (git-ignored) and fill what you have. `.env` is loaded automatically at startup
(real environment variables win; values are never printed); `BASEERA_DOTENV=off` disables it, `BASEERA_ENV_FILE` points
elsewhere. With a SerpAPI key and `BASEERA_MODE=live`, the Search & Maps tab shows *live (SerpAPI)* results; without it
(or if SerpAPI fails) it falls back to labelled synthetic examples.

## Tests & evaluation
```bash
make check    # ruff + pytest (offline); without make: ./scripts/check.sh
make eval     # writes docs/eval.md: confusion matrix, P/R/F1/FPR, threshold sweep, ablation, every FP/FN
```
Results are in **docs/eval.md** (generated; on a *synthetic* labelled set — not real-world accuracy).

## Team
Team **Baseera (بصيرة)** — ScamShield AI hackathon, Abu Dhabi Police × 42 Abu Dhabi:
- Mohammed Nasser Albalushi — Team Lead
- Hasan Al salami
- Adnan Almarzooqi

## Limitations & next steps
See `docs/LIMITATIONS.md`. Next: real labelled data (PhishTank/OpenPhish rows for UAE brands), GSB/PhishTank/URLhaus keys,
recorded Search/Maps data (run the recorder with a SerpAPI key), LLM vision for grey-zone pages, complete registry phones,
near-duplicate screenshot clustering.
