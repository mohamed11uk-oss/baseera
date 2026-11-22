# بصيرة (Baseera) — one-page summary

**Challenge (ScamShield AI, Abu Dhabi Police × 42 Abu Dhabi):** detect fraudulent links and websites, including those in search engines and Maps.

**Problem.** Scammers impersonate UAE government entities, police, banks and telcos with look-alike domains, SMS links
and fake customer-service numbers in Search and Maps results. Residents need a fast, trustworthy answer; analysts need
to link many sites into one campaign and act with evidence. Report channel: Aman — call 8002626, SMS 2828 (adpolice.gov.ae, checked 2026-11-19).

**Solution.**
- Check a link, an SMS/WhatsApp message or a Search/Maps listing → 0–100 risk + top-3 reasons in Arabic (English below).
- Official Entity Registry with sources: official domains never score above *low*; unknown numbers are *unverified*, never "fake".
- Analyst dashboard: cases clustered into campaigns (shared phone, IP, name servers, screenshot hash, registrar, path, target).
- Evidence pack (JSON/HTML/PDF/ZIP, SHA-256, UTC timestamps, draft report). Opt-in sandbox deep scan. Chrome extension.

**Architecture.** Python/FastAPI API + static Arabic RTL UI, SQLite, rules + verified registry scoring
(weights in `data/weights.yaml`), optional sources (RDAP, TLS, crt.sh, OpenPhish/PhishTank, Safe Browsing, SerpAPI) with
4 s timeouts, caching and an offline mode. One command: `./run.sh`.

**Measured (docs/eval.md, `make eval`).** See docs/eval.md for precision, recall, F1, false-positive rate and latency.
The fraudulent examples in the test set are **synthetic**; the numbers show the engine behaves as designed, not real-world accuracy.

**Limitations.** Synthetic eval and Search/Maps data; 10 of 19 registry entities lack verified phones; no LLM step; brand-less lures
and raw-IP links under-scored; no rate limiting. Full list: docs/LIMITATIONS.md.

**Next steps.** Real labelled data from PhishTank/OpenPhish for UAE brands; complete registry phones with the entities;
record live Search/Maps data; LLM vision for grey-zone pages; pilot evidence packs with the Aman team.
