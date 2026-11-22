# Submission checklist (Prompt 7.5)

Status as of 2026-11-19. Nothing below about the hackathon's rules was read from the official page: every rule,
field or format that has not been confirmed on the Podium+ event page is marked **UNKNOWN**. Do not fill in an
UNKNOWN from memory or from another hackathon. Confirm it on Podium+ and write the source (page URL + date read).

## 1. Bundle items

| # | Item | Where it is now | State | Action before submitting |
|---|---|---|---|---|
| 1 | Repo link | Local git repo only. `git remote -v` shows **no remote** | TODO | Team creates the GitHub repo (public or private is UNKNOWN, see §3), pushes, pastes the URL here. Check `.env` is not tracked (only `.env.example` is). |
| 2 | Demo video link | Not recorded | TODO | Record the 3-minute flow in docs/demo.md. Run `scripts/prewarm.py` first (see docs/timings.md). Upload, paste link. Length limit, host and visibility: UNKNOWN. |
| 3 | Summary PDF | docs/summary.md exists. **No PDF yet** | TODO | Print docs/summary.md to PDF (Chrome: open the rendered Markdown, Print, Save as PDF). Check Arabic renders right to left. |
| 4 | Pitch deck | docs/Baseera.pptx (draft, `make pptx`) | PARTIAL | Add team names and the demo video link (docs/LIMITATIONS.md item 14). Only verified facts: Aman 8002626 / SMS 2828 (adpolice.gov.ae); any other statistic needs a source link. Required format (PPTX or PDF) and slide limit: UNKNOWN. |
| 5 | Screenshots | docs/screenshots/01 to 10 (`make screenshots`) | DONE | Re-run if the UI changes. |
| 6 | Evaluation numbers | docs/eval.md (`make eval`, synthetic test set) | DONE | Quote with the "synthetic labelled set" caveat. |
| 7 | Demo timings | docs/timings.md (`scripts/prewarm.py`, replay mode) | PARTIAL | Live mode not measured on the build box. Re-run against the live server on the demo laptop. |
| 8 | Freeze tag | Prompt 6.6 | TODO | At the event: tag `submission`, run `make check` and `make eval` from a clean clone. |

## 2. Known form fields

None are confirmed. The submission form has not been seen by whoever wrote this file, so the list of fields is
**UNKNOWN**. When the team opens the form, copy every field name here verbatim, with its limit:

| Field (verbatim from the form) | Limit | Our value | Ready? |
|---|---|---|---|
| UNKNOWN | UNKNOWN | | |

Likely candidates to prepare in advance (assumptions, not confirmed): project name (Baseera / بصيرة), one-line
description, challenge track (the official challenge statement is in CLAUDE.md), repo URL, video URL, team member
names and emails.

## 3. Unknowns to confirm on the Podium+ page

| # | Question | Answer | Source (URL + date read) |
|---|---|---|---|
| U1 | Team size rule. The team has heard "3 to 5 members": is that the actual rule, and is it a minimum, a maximum or both? | UNKNOWN | |
| U2 | Submission deadline: date, time and **time zone** (UAE GST or other) | UNKNOWN | |
| U3 | Submission format: form on Podium+, email, upload, or other | UNKNOWN | |
| U4 | Required items (repo, video, deck, summary, live URL?) and which are optional | UNKNOWN | |
| U5 | Repo: must it be public? Is a specific host (GitHub) required? Can we push after the deadline? | UNKNOWN | |
| U6 | Video: maximum length, host (YouTube, Drive, upload), visibility, language (Arabic, English, both) | UNKNOWN | |
| U7 | Deck: file format, slide limit, template | UNKNOWN | |
| U8 | Live demo: on stage, recorded only, or both; time slot length; is internet provided? | UNKNOWN | |
| U9 | Judging criteria and weights | UNKNOWN | |
| U10 | Rules on third-party APIs, synthetic data and pre-existing code | UNKNOWN | |
| U11 | IP / licence terms for submitted code | UNKNOWN | |
| U12 | Can the submission be edited after first submit? | UNKNOWN | |
| U13 | Contact for questions (organiser channel) | UNKNOWN | |

## 4. Final pass (day of submission)

- [ ] All U1 to U13 answered with a source, or explicitly accepted as unknown by the team
- [ ] `./scripts/check.sh` passes; `make eval` re-run; docs/eval.md committed
- [ ] `scripts/prewarm.py --base-url http://127.0.0.1:8000` run on the demo laptop, all warm times under 5 s
- [ ] Synthetic data is labelled as synthetic in the video and deck (purple badge visible)
- [ ] No secrets in the repo or in the video (no API keys on screen, no `.env`)
- [ ] Links in the form open from a logged-out browser
