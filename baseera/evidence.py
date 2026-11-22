"""Evidence pack for police analysts: JSON + printable HTML (+ ZIP with SHA-256 manifest, + PDF via headless Chrome)."""
from __future__ import annotations

import hashlib
import html
import io
import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .registry import Registry
from .schemas import Case, Cluster

DISCLAIMER_AR = ("هذه نتائج آلية من نظام «بصيرة» ولا تُعد دليلاً نهائياً. يجب أن يراجعها ويؤكدها محلل بشري قبل أي إجراء. "
                 "قد تكون أجزاء من البيانات تجريبية (Synthetic) كما هو موسوم.")
DISCLAIMER_EN = ("Automated findings produced by Baseera. NOT conclusive evidence: a human analyst must review and confirm "
                 "before any action. Items marked synthetic are demo data.")


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def build_pack(case: Case, cluster: Cluster | None, registry: Registry, screenshot_dir: Path | None = None) -> dict:
    v = case.verdict
    norm = v.get("normalized", {})
    ent = registry.by_id.get(case.entity_id or "")
    chain = norm.get("redirect_chain") or ([norm["url"]] if norm.get("url") else [])
    target = case.registrable_domain or case.input
    draft_ar = (f"إلى خدمة أمان - شرطة أبوظبي:\nنود الإبلاغ عن {'موقع' if case.kind != 'listing' else 'نتيجة بحث/خرائط'} "
                f"يُشتبه أنه ينتحل صفة {ent.entity_name_ar if ent else 'جهة رسمية'}: {target}.\n"
                f"درجة الخطر الآلية: {case.risk}/100 ({case.level}). رقم الحالة: {case.id}."
                + (f" ضمن حملة {cluster.id} تضم {len(cluster.case_ids)} حالات." if cluster else "")
                + "\nالأدلة الآلية مرفقة مع بصمات SHA-256، وتحتاج تأكيد محلل.")
    draft_en = (f"Report to Abu Dhabi Police Aman service: suspected impersonation of "
                f"{ent.entity_name_en if ent else 'an official entity'} at {target}. Automated risk {case.risk}/100 "
                f"({case.level}). Case {case.id}." + (f" Part of campaign {cluster.id} ({len(cluster.case_ids)} cases)." if cluster else "")
                + " Requires analyst confirmation. Suggested next step: takedown request to the registrar/host and to the "
                  "search/maps platform for the listing.")
    pack = {
        "pack_version": "1.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "disclaimer_ar": DISCLAIMER_AR, "disclaimer_en": DISCLAIMER_EN,
        "synthetic_demo_data": case.synthetic,
        "case": {"id": case.id, "created_at_utc": case.created_at, "kind": case.kind, "input": case.input,
                 "risk": case.risk, "level": case.level, "registrable_domain": case.registrable_domain},
        "targeted_entity": ent.public() if ent else None,
        "url": {"normalized": norm.get("url"), "host": norm.get("host"), "host_unicode": norm.get("host_unicode"),
                "redirect_chain": chain},
        "signals": [{k: s.get(k) for k in ("id", "source", "score", "weight", "contribution", "available", "evidence")}
                    for s in v.get("signals", [])],
        "infrastructure": {**case.infra, "live_lookups": norm.get("infra", {})},
        "explanation_ar": v.get("explanation_ar"), "explanation_en": v.get("explanation_en"),
        "campaign": cluster.model_dump() if cluster else None,
        "recommended_action": {
            "ar": "مراجعة المحلل ← تأكيد الانتحال ← طلب إيقاف من المسجّل/المستضيف ومن منصة البحث/الخرائط ← تحذير الجمهور",
            "en": "Analyst review -> confirm impersonation -> takedown request to registrar/host and search/maps platform -> public warning",
            "draft_report_ar": draft_ar, "draft_report_en": draft_en},
        "google_safe_browsing_notice": _gsb_notice(v),
        "deep_scan": _deep_scan(norm.get("sandbox")),
        "automated_vs_human": {"automated": ["signals", "risk", "campaign"], "requires_human": ["final determination", "takedown"]},
    }
    verdict_bytes = json.dumps(v, ensure_ascii=False, sort_keys=True).encode()
    pack["artifacts"] = [{"name": "verdict.json", "sha256": sha256(verdict_bytes)}]
    sb = norm.get("sandbox") or {}
    if sb.get("screenshot_sha256"):
        f = Path(screenshot_dir or "") / f"{sb['screenshot_sha256']}.png" if screenshot_dir else None
        pack["artifacts"].append({"name": "screenshot.png", "sha256": sb["screenshot_sha256"],
                                  "phash_dhash64": sb.get("screenshot_phash"),
                                  "file_present": bool(f and f.is_file())})
    body = json.dumps({k: pack[k] for k in pack if k != "pack_sha256"}, ensure_ascii=False, sort_keys=True).encode()
    pack["pack_sha256"] = sha256(body)
    return pack


def _deep_scan(sb: dict | None) -> dict | None:
    """Deep-scan facts for the analyst. Page text is untrusted and is NOT included (only title + field list)."""
    if not sb:
        return None
    keep = ("available", "error", "url", "final_url", "redirect_chain", "title", "sensitive_kinds", "form_actions",
            "form_domains", "screenshot_sha256", "screenshot_phash", "blocked_requests", "requests", "elapsed_ms")
    d = {k: sb.get(k) for k in keep}
    d["inputs"] = [{k: f.get(k) for k in ("name", "type", "placeholder", "autocomplete", "kind")} for f in sb.get("inputs", [])][:50]
    d["note"] = "Captured by Baseera's headless browser; page title/fields are untrusted content shown as data."
    return d


def _gsb_notice(v: dict) -> dict | None:
    """GSB terms: attribution + 'not guaranteed' disclaimer wherever a GSB result is shown (also in the pack)."""
    if not any(s.get("source") == "gsb" for s in v.get("signals", [])):
        return None
    from .sources.gsb import notice
    return notice()


def _e(x) -> str:
    return html.escape("" if x is None else str(x))


def _deep_html(d: dict | None) -> str:
    if not d:
        return ""
    if not d.get("available"):
        return f"<h2>الفحص المعمّق (Deep scan)</h2><p dir='ltr'>not available: {_e(d.get('error'))}</p>"
    img = (f"<img alt='screenshot' style='max-width:100%;max-height:600px;border:1px solid #ccc' "
           f"src='/api/screenshots/{_e(d['screenshot_sha256'])}.png'>") if d.get("screenshot_sha256") else ""
    fields = ", ".join(f"{f.get('name') or f.get('placeholder') or f.get('type')} [{f.get('kind') or '-'}]" for f in d["inputs"])
    return (f"<h2>الفحص المعمّق (Deep scan)</h2><p class='warn'>محتوى الصفحة غير موثوق ويُعرض كبيانات فقط "
            f"(untrusted page content, shown as data)</p><p dir='ltr'>title: {_e(d.get('title'))}<br>final URL: {_e(d.get('final_url'))}"
            f"<br>fields: {_e(fields) or '—'}<br>forms post to: {_e(', '.join(d.get('form_domains') or [])) or '—'}"
            f"<br>screenshot SHA-256: {_e(d.get('screenshot_sha256'))}<br>dHash (64-bit): {_e(d.get('screenshot_phash'))}"
            f"<br>blocked requests: {len(d.get('blocked_requests') or [])}</p>{img}")


def render_html(pack: dict) -> str:
    c = pack["case"]
    ent = pack.get("targeted_entity") or {}
    lvl = {"low": "منخفض", "medium": "متوسط", "high": "عالٍ"}[c["level"]]
    rows = "".join(f"<tr><td>{_e(s['id'])}</td><td>{_e(s['source'])}</td><td>{_e(s['contribution'])}</td>"
                   f"<td>{'✔' if s['available'] else '—'}</td><td dir='ltr'>{_e(s['evidence'])}</td></tr>" for s in pack["signals"])
    chain = "".join(f"<li dir='ltr'>{_e(u)}</li>" for u in pack["url"]["redirect_chain"]) or "<li>—</li>"
    camp = pack.get("campaign")
    camp_html = (f"<p>الحملة <b>{_e(camp['id'])}</b>: {len(camp['case_ids'])} حالات، نطاقات: <span dir='ltr'>{_e(', '.join(camp['domains']))}</span><br>"
                 f"المشترك: <span dir='ltr'>{_e(', '.join(camp['shared']))}</span></p>") if camp else "<p>غير مرتبطة بحملة.</p>"
    arts = "".join(f"<li dir='ltr'>{_e(a['name'])}: {_e(a['sha256'])}</li>" for a in pack["artifacts"])
    infra = _e(json.dumps(pack["infrastructure"], ensure_ascii=False, indent=1))
    g = pack.get("google_safe_browsing_notice")
    gsb_html = (f"<div class='warn'><b>{_e(g['attribution_ar'])}</b> — {_e(g['disclaimer_ar'])}<br><span dir='ltr'>"
                f"{_e(g['attribution_en'])} ({_e(g['advisory_url'])}) — {_e(g['disclaimer_en'])}</span></div>") if g else ""
    synth = "<div class='synth'>بيانات تجريبية (Synthetic demo data) — ليست قضية حقيقية</div>" if pack["synthetic_demo_data"] else ""
    return f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>ملف الأدلة {_e(c['id'])}</title>
<style>body{{font-family:'Noto Naskh Arabic','Segoe UI',Tahoma,sans-serif;margin:24px;color:#111}}h1{{margin:0}}
table{{border-collapse:collapse;width:100%;font-size:12px}}td,th{{border:1px solid #ccc;padding:4px;vertical-align:top}}
.warn{{background:#fff4e5;border:1px solid #f0a020;padding:8px;margin:8px 0}}.synth{{background:#fde2e2;border:1px solid #c00;padding:6px;font-weight:bold}}
pre{{white-space:pre-wrap;font-size:11px;background:#f6f6f6;padding:6px}} .lvl{{font-size:20px;font-weight:bold}}</style></head><body>
<h1>ملف الأدلة — بصيرة (Baseera Evidence Pack)</h1>{synth}
<div class="warn">{_e(pack['disclaimer_ar'])}<br><span dir="ltr">{_e(pack['disclaimer_en'])}</span></div>
<p>رقم الحالة: <b>{_e(c['id'])}</b> | وقت الإنشاء (UTC): <span dir="ltr">{_e(c['created_at_utc'])}</span> | وقت إصدار الملف (UTC): <span dir="ltr">{_e(pack['generated_at_utc'])}</span></p>
<p class="lvl">درجة الخطر: {_e(c['risk'])}/100 — {lvl}</p>
<p>المُدخل: <span dir="ltr">{_e(c['input'])}</span><br>الجهة المستهدفة: {_e(ent.get('entity_name_ar', '—'))} (<span dir="ltr">{_e(', '.join(ent.get('official_domains', [])))}</span>)</p>
<h2>الشرح</h2><pre>{_e(pack['explanation_ar'])}</pre><pre dir="ltr">{_e(pack['explanation_en'])}</pre>
<h2>سلسلة التحويل (Redirect chain)</h2><ol>{chain}</ol>
<h2>الإشارات والأدلة (Signals)</h2><table><tr><th>الإشارة</th><th>المصدر</th><th>المساهمة</th><th>متاح</th><th>الدليل</th></tr>{rows}</table>
{gsb_html}
{_deep_html(pack.get('deep_scan'))}
<h2>البنية التحتية (Infrastructure)</h2><pre dir="ltr">{infra}</pre>
<h2>الحملة (Campaign)</h2>{camp_html}
<h2>الإجراء الموصى به</h2><p>{_e(pack['recommended_action']['ar'])}</p>
<h3>مسودة بلاغ (لا تُرسل آلياً)</h3><pre>{_e(pack['recommended_action']['draft_report_ar'])}</pre><pre dir="ltr">{_e(pack['recommended_action']['draft_report_en'])}</pre>
<h2>البصمات (SHA-256)</h2><ul>{arts}<li dir="ltr">pack_sha256: {_e(pack['pack_sha256'])}</li></ul>
</body></html>"""


def build_zip(pack: dict, screenshot_dir: Path | None = None) -> bytes:
    j = json.dumps(pack, ensure_ascii=False, indent=2).encode()
    h = render_html(pack).encode()
    manifest = f"{sha256(j)}  evidence.json\n{sha256(h)}  evidence.html\n".encode()
    shot = None
    sha = (pack.get("deep_scan") or {}).get("screenshot_sha256")
    if sha and not re.fullmatch(r"[0-9a-f]{64}", str(sha)):  # never build a path from anything but a hex digest
        sha = None
    if sha and screenshot_dir and (Path(screenshot_dir) / f"{sha}.png").is_file():
        shot = (Path(screenshot_dir) / f"{sha}.png").read_bytes()
        manifest += f"{sha256(shot)}  screenshot.png\n".encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("evidence.json", j)
        z.writestr("evidence.html", h)
        if shot:
            z.writestr("screenshot.png", shot)
        z.writestr("MANIFEST.sha256", manifest)
    return buf.getvalue()


def chrome_binary() -> str | None:
    for b in ("google-chrome", "chromium", "chromium-browser", "google-chrome-stable"):
        p = shutil.which(b)
        if p:
            return p
    return None


def render_pdf(pack: dict) -> bytes | None:
    """Render the HTML with headless Chrome (handles Arabic shaping/RTL). None if Chrome is unavailable."""
    b = chrome_binary()
    if not b:
        return None
    with tempfile.TemporaryDirectory() as d:
        src, out = Path(d) / "e.html", Path(d) / "e.pdf"
        src.write_text(render_html(pack), encoding="utf-8")
        try:
            subprocess.run([b, "--headless=new", "--no-sandbox", "--disable-gpu",
                            "--disable-background-networking", "--no-pdf-header-footer",  # note: --blink-settings=scriptEnabled=false breaks print-to-pdf; the HTML has no scripts (all values escaped)
                            f"--print-to-pdf={out}", src.as_uri()], capture_output=True, timeout=60, check=False)
        except (subprocess.TimeoutExpired, OSError):
            return None
        return out.read_bytes() if out.exists() else None
