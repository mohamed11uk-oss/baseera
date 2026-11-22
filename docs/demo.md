# 3-minute demo script (all data labelled synthetic where it is)

Start: `./run.sh` → open http://127.0.0.1:8000

| Time | Tab | Input | Expected |
|---|---|---|---|
| 0:00–0:20 | — | Problem slide | Only verified facts; Aman 8002626 / SMS 2828 |
| 0:20–1:00 | فحص رابط أو رسالة | click example `adpolice-fines-pay.com` | HIGH, 3 Arabic reasons (brand keyword, lure word…), saved as case, joins synthetic fines campaign |
| | | click example `adpolice.gov.ae` | LOW, "official per registry, verified 2026-11-19" |
| | | click example "رسالة SMS" | HIGH: urgency + OTP request + unverified mobile number + look-alike link |
| 1:00–1:50 | نتائج البحث والخرائط | Emirates NBD → افحص النتائج | Purple "synthetic" badge; official rows green; sponsored look-alike + hijacked Maps pin (official site, mobile number) highlighted |
| 1:50–2:30 | لوحة المحلل | open campaign CMP-… | node graph (shared IP/NS/phone), timeline; Evidence → HTML/PDF/ZIP with SHA-256 |
| (optional) | فحص رابط أو رسالة | tick «فحص معمّق (Deep scan)» on a page you control | screenshot in the verdict card; OTP/card forms flagged |
| 2:30–3:00 | الحالة والسجل | — | registry with sources; docs/eval.md numbers + limits (synthetic set) |

Fallback if the network is down: `BASEERA_MODE=offline ./run.sh` (all flows still work; domain age/TLS shown as unavailable).

Pre-warm: with the server running, `.venv/bin/python scripts/prewarm.py --base-url http://127.0.0.1:8000 --out docs/timings-live.md` runs every input above twice and prints cold/warm times against 5 s (first live lookups can take 10 to 25 s; cached afterwards). Replay results: docs/timings.md.
Extension: load `extension/` unpacked in Chrome (see extension/README.md) and click the icon on any page.
