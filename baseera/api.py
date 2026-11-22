"""FastAPI app: JSON API under /api + static Arabic RTL UI at /."""
from __future__ import annotations

import hmac
import os
import re
import time

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .analyze import Analyzer
from .cases import CaseStore, cluster_cases
from .config import ROOT, Settings, get_settings
from .demo import seed
from .evidence import build_pack, build_zip, chrome_binary, render_html, render_pdf
from .normalize import normalize
from .schemas import (
    AnalystLogin,
    AnalyzeRequest,
    Cluster,
    DeepCheckRequest,
    ListingVerdict,
    ScanBrandRequest,
    ScanBrandResponse,
    Verdict,
)
from .security import COOKIE, EVIDENCE_CSP, BodyLimitMiddleware, add_security_headers, analyst_guard, presented_ok, session_value
from .serp import RECORDED, SYNTH_LABEL_AR, SYNTH_LABEL_EN, available_fixtures, load_fixture, recorded_label, serpapi_listings
from .sources import feeds as feeds_mod
from .sources import gsb as gsb_mod
from .sources import status as source_status
from .sources import virustotal as vt_mod


def create_app(settings: Settings | None = None, db_path: str | None = None) -> FastAPI:
    settings = settings or get_settings()
    analyzer = Analyzer(settings=settings)
    store = CaseStore(db_path or settings.db_path)
    if settings.seed_demo:
        seed(store, analyzer)
    app = FastAPI(title="Baseera API", version=__version__,
                  description="بصيرة: كشف الروابط والقوائم المزيفة (ScamShield AI hackathon prototype)")
    app.state.analyzer, app.state.store, app.state.settings = analyzer, store, settings
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)
    # CORS only for the browser extension (chrome-extension://<32-char id>) unless BASEERA_CORS_ORIGINS overrides it.
    cors = [o.strip() for o in os.getenv("BASEERA_CORS_ORIGINS", "").split(",") if o.strip()]
    app.add_middleware(CORSMiddleware, allow_origins=cors, allow_origin_regex=None if cors else r"^chrome-extension://[a-p]{32}$",
                       allow_methods=["GET", "POST"], allow_headers=["Content-Type"], allow_credentials=False)
    if settings.allowed_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        response = await call_next(request)
        add_security_headers(response, request.url.path)
        return response

    analyst = [Depends(analyst_guard(settings))]

    @app.get("/api/analyst/session")
    def analyst_session(request: Request):
        tok = settings.analyst_token
        return {"required": bool(tok), "authenticated": (not tok) or presented_ok(request, tok)}

    @app.post("/api/analyst/session")
    def analyst_login(body: AnalystLogin, request: Request):
        tok = settings.analyst_token
        if not tok:
            return {"required": False, "authenticated": True}
        if not hmac.compare_digest(body.token.encode(), tok.encode()):
            raise HTTPException(401, "wrong analyst token")
        r = JSONResponse({"required": True, "authenticated": True})
        r.set_cookie(COOKIE, session_value(tok), httponly=True, samesite="strict", path="/api",
                     secure=request.url.scheme == "https", max_age=12 * 3600)
        return r

    @app.delete("/api/analyst/session")
    def analyst_logout():
        r = JSONResponse({"authenticated": False})
        r.delete_cookie(COOKIE, path="/api")
        return r

    def _save(v: Verdict) -> Verdict:
        if v.level != "low":
            store.add_verdict(v)
            for cl in cluster_cases(store.all()):
                if v.case_id in cl.case_ids:
                    v.campaign_id = cl.id
        return v

    @app.post("/api/analyze", response_model=Verdict)
    def analyze(req: AnalyzeRequest):
        if req.listing:
            v, _ = analyzer.analyze_listing(req.listing)
        elif req.url and req.url.strip():
            v = analyzer.analyze_url(req.url.strip()[:2048], deep=req.deep)
        elif req.text and req.text.strip():
            v = analyzer.analyze_text(req.text[:5000])
        else:
            raise HTTPException(422, "provide url, text or listing")
        return _save(v) if req.save_case else v

    @app.post("/api/deep-check/virustotal")
    def deep_check_virustotal(req: DeepCheckRequest):
        """Manual deep check (UI button): read VirusTotal's existing report for one URL. Never part of /api/analyze,
        never changes the score, never submits the URL to VirusTotal. 4 requests/min (free tier); fails soft."""
        try:
            url = normalize(req.url.strip()[:2048]).url
        except ValueError as e:
            raise HTTPException(422, f"invalid url: {e}") from None
        vt = analyzer.vt
        res = vt.report(url) if vt is not None else {"available": False, "error": "off"}
        if vt is not None and vt.enabled and "retry_after_s" not in res:
            source_status.record("virustotal", res["available"], res.get("error"))
        ar, en = vt_mod.summary(res)
        return {"url": url, "source": "virustotal", **res, "summary_ar": ar, "summary_en": en,
                "note_en": "Shown for reference only: it does not change Baseera's risk score.",
                "note_ar": "للاطلاع فقط، وما يغيّر درجة الخطر في بصيرة"}

    @app.get("/api/screenshots/{sha}.png", include_in_schema=True)
    def screenshot(sha: str):
        """Deep-scan screenshot by SHA-256. Only 64 lowercase hex chars are accepted (no path traversal)."""
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise HTTPException(404, "not found")
        base = settings.screenshot_dir.resolve()
        p = (base / f"{sha}.png").resolve()
        if p.parent != base or not p.is_file():
            raise HTTPException(404, "not found")
        return FileResponse(p, media_type="image/png", headers={"X-Content-Type-Options": "nosniff",
                                                               "Cache-Control": "private, max-age=3600"})

    @app.get("/api/brands")
    def brands():
        reg = analyzer.registry
        fx = set(available_fixtures())
        return [{"id": e.id, "name_ar": e.entity_name_ar, "name_en": e.entity_name_en, "category": e.category,
                 "status": e.status, "has_fixture": e.id in fx} for e in reg.entities]

    @app.post("/api/scan-brand", response_model=ScanBrandResponse)
    def scan_brand(req: ScanBrandRequest):
        reg = analyzer.registry
        ent = reg.by_id.get(req.brand) or reg.match_name(req.brand)
        if not ent:
            raise HTTPException(404, "brand not in registry")
        label = f"{SYNTH_LABEL_AR} / {SYNTH_LABEL_EN}"
        listings = None
        if settings.serpapi_key and not settings.offline:
            try:
                listings = serpapi_listings(f"{ent.entity_name_en} customer service number", settings)
                label = "live (SerpAPI)"
            except Exception as e:  # noqa: BLE001 - fall back to replay data, never fail the request
                label = f"SerpAPI unavailable ({type(e).__name__}); "
        if listings is None:
            prefix = label if label.startswith("SerpAPI unavailable") else ""
            listings, kind = load_fixture(ent.id)
            if kind == "none":
                label = "لا توجد بيانات مسجلة لهذه الجهة / no recorded or example data for this brand"
            elif kind.startswith("recorded"):
                ar, en = recorded_label(kind.split(" ", 1)[1])
                label = f"{ar} / {en}"
            else:
                label = f"{SYNTH_LABEL_AR} / {SYNTH_LABEL_EN}"
            label = prefix + label
        results = []
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=8) as ex:  # live lookups are I/O bound: verify listings in parallel
            analysed = list(ex.map(analyzer.analyze_listing, listings))
        for lst, (v, official) in zip(listings, analysed, strict=True):
            reason_ar = v.explanation_ar.split("\n")[1] if "\n" in v.explanation_ar else v.explanation_ar
            reason_en = v.explanation_en.split("\n")[1] if "\n" in v.explanation_en else v.explanation_en
            if official:
                reason_ar = f"رسمي موثّق (المصدر: سجل الجهات الرسمية، {ent.verified_on})"
                reason_en = f"Verified official (source: registry, {ent.verified_on})"
            results.append(ListingVerdict(listing=lst, verdict=v, official=official, reason_ar=reason_ar, reason_en=reason_en))
        results.sort(key=lambda r: -r.verdict.risk)
        return ScanBrandResponse(brand=req.brand, entity=ent.public(), data_label=label, results=results)

    @app.get("/api/cases", dependencies=analyst)
    def cases(entity: str | None = None, level: str | None = Query(None, pattern="^(low|medium|high)$")):
        return [c.model_dump(exclude={"verdict"}) for c in store.list(entity, level)]

    @app.get("/api/cases/{cid}", dependencies=analyst)
    def case(cid: str):
        c = store.get(cid)
        if not c:
            raise HTTPException(404, "case not found")
        return c

    @app.get("/api/clusters", response_model=list[Cluster], dependencies=analyst)
    def clusters():
        return cluster_cases(store.all())

    def _pack(cid: str) -> dict:
        c = store.get(cid)
        if not c:
            raise HTTPException(404, "case not found")
        cl = next((x for x in cluster_cases(store.all()) if cid in x.case_ids), None)
        return build_pack(c, cl, analyzer.registry, screenshot_dir=settings.screenshot_dir)

    @app.get("/api/cases/{cid}/evidence.json", dependencies=analyst)
    def ev_json(cid: str):
        return JSONResponse(_pack(cid), headers={"Content-Disposition": f'attachment; filename="{cid}-evidence.json"'})

    @app.get("/api/cases/{cid}/evidence.html", response_class=HTMLResponse, dependencies=analyst)
    def ev_html(cid: str):
        return HTMLResponse(render_html(_pack(cid)), headers={"Content-Security-Policy": EVIDENCE_CSP})

    @app.get("/api/cases/{cid}/evidence.zip", dependencies=analyst)
    def ev_zip(cid: str):
        return Response(build_zip(_pack(cid), screenshot_dir=settings.screenshot_dir), media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{cid}-evidence.zip"'})

    @app.get("/api/cases/{cid}/evidence.pdf", dependencies=analyst)
    def ev_pdf(cid: str):
        pdf = render_pdf(_pack(cid))
        if not pdf:
            raise HTTPException(503, "PDF renderer (headless Chrome) not available; use evidence.html and print to PDF")
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{cid}-evidence.pdf"'})

    def _feeds_status() -> dict:
        st = analyzer.feeds
        if not settings.source_feeds:
            return {"status": "off (SOURCE_FEEDS=off)"}
        if st is None:
            return {"status": "no local feed DB yet: run `python -m baseera feeds refresh`"}
        try:
            meta = st.meta()
            return {"status": "on (local SQLite, refreshed by CLI)",
                    **{k: {**meta.get(k, {"count": 0, "status": "never refreshed"}),
                           "label": v["label"], "cadence_h": v["cadence_s"] // 3600}
                       for k, v in feeds_mod.SOURCES.items()}}
        except Exception as e:  # noqa: BLE001
            return {"status": f"error: {type(e).__name__}"}

    def _per_source() -> dict:
        """One uniform row per optional source: enabled?, status (off|ready|ok|degraded|unavailable), last error."""
        live = not settings.offline
        sb = analyzer.sandbox
        sb_status = sb.status() if hasattr(sb, "status") else ("off" if sb is None else "custom")
        enabled = {
            "redirects": live and settings.source_redirects,
            "rdap": live and settings.source_rdap,
            "tls": live and settings.source_tls,
            "whois_ae": live and settings.source_whois_ae,
            "crtsh": live and settings.source_crtsh,
            "feeds": settings.source_feeds,
            "gsb": analyzer.gsb is not None and analyzer.gsb.enabled,
            "urlhaus": analyzer.urlhaus is not None and analyzer.urlhaus.enabled,
            "urlscan": analyzer.urlscan is not None and analyzer.urlscan.enabled,
            "virustotal": analyzer.vt is not None and analyzer.vt.enabled,
            "sandbox": sb is not None and settings.source_sandbox != "off" and live,
        }
        why_off = {"redirects": "SOURCE_REDIRECTS=off", "rdap": "SOURCE_RDAP=off", "tls": "SOURCE_TLS=off",
                   "whois_ae": "SOURCE_WHOIS_AE=off", "crtsh": "SOURCE_CRTSH=off", "feeds": "SOURCE_FEEDS=off",
                   "gsb": "no GSB_API_KEY or SOURCE_GSB=off", "sandbox": "SOURCE_SANDBOX=off"}
        for k, c in (("urlhaus", analyzer.urlhaus), ("urlscan", analyzer.urlscan), ("virustotal", analyzer.vt)):
            why_off[k] = (c.why_off() if c is not None else None) or "off"
        out = {}
        for name in source_status.SOURCES:
            rt = source_status.get(name)
            if not enabled[name]:
                st, detail = "off", "offline mode (BASEERA_MODE=offline)" if not live and name != "feeds" else why_off[name]
            elif name == "feeds" and analyzer.feeds is None:
                st, detail = "unavailable", "no local feed DB: run `python -m baseera feeds refresh`"
            elif name == "sandbox" and sb_status.startswith("unavailable"):
                st, detail = "unavailable", sb_status
            else:
                st = {"ok": "ok", "failed": "degraded"}.get(rt["last"], "ready")
                detail = "fails soft: verdicts mark it available=false" if st == "degraded" else "on"
            out[name] = {"enabled": enabled[name], "status": st, "detail": detail, "calls_ok": rt["ok"],
                         "calls_failed": rt["failed"], "last_ok": rt["last_ok"], "last_error": rt["last_error"],
                         "last_error_at": rt["last_error_at"]}
        return out

    def _search_maps_data() -> str:
        if settings.serpapi_key and not settings.offline:
            return "live (SerpAPI)"
        rec = sorted(p.stem for p in RECORDED.glob("*.json")) if RECORDED.exists() else []
        return (f"replay: recorded fixtures for {', '.join(rec)}; synthetic for the rest" if rec
                else "replay: SYNTHETIC fixtures (written by the team, not recorded)")

    @app.get("/api/health")
    def health():
        t = time.time()
        per = _per_source()
        return {"status": "ok" if not any(v["status"] == "degraded" for v in per.values()) else "degraded",
                "version": __version__, "mode": settings.mode,
                "data_mode": "replay" if settings.offline else "live",
                "data_mode_note": ("offline: no network lookups; Search/Maps results are replayed fixtures"
                                   if settings.offline else "live lookups on, each source fails soft (4s timeout)"),
                "search_maps_data": _search_maps_data(),
                "per_source": per,
                "sources": {"registry": {"entities": len(analyzer.registry.entities),
                                         "verified": sum(e.status == "verified" for e in analyzer.registry.entities)},
                            "rdap": "off (offline)" if settings.offline or not settings.source_rdap else "on",
                            "tls": "off (offline)" if settings.offline or not settings.source_tls else "on",
                            "redirects": "off (offline)" if settings.offline or not settings.source_redirects else "on",
                            "blocklist_feed": f"{len(analyzer.feed)} entries (synthetic demo feed)",
                            "feeds": _feeds_status(),
                            "crtsh": "off (offline)" if settings.offline else ("on (domain-age fallback, 6s, 2 retries)"
                                                                             if settings.source_crtsh else "off"),
                            "whois_ae": "off (offline)" if settings.offline else (
                                "on (.ae only, fail soft; port 43 may be blocked)" if settings.source_whois_ae else "off"),
                            "gsb": analyzer.gsb.status() if analyzer.gsb is not None
                            else {"status": "off", **gsb_mod.notice()},
                            "serpapi": "on" if settings.serpapi_key and not settings.offline else
                            "off (replay: recorded fixtures if present, else synthetic)",
                            "urlhaus": analyzer.urlhaus.status() if analyzer.urlhaus is not None else "off",
                            "urlscan": (analyzer.urlscan.status() if analyzer.urlscan is not None else "off")
                            + " (read-only search of existing scans, informational)",
                            "virustotal": (analyzer.vt.status() if analyzer.vt is not None else "off")
                            + f" (manual deep check only, {settings.vt_per_minute}/min)",
                            "pdf_renderer": "chrome" if chrome_binary() else "unavailable",
                            "sandbox": analyzer.sandbox.status() if hasattr(analyzer.sandbox, "status") else
                            ("off" if analyzer.sandbox is None else "custom")},
                "cases": store.count(), "latency_ms": round((time.time() - t) * 1000, 1)}

    @app.get("/api/registry")
    def registry():
        return [e.public() for e in analyzer.registry.entities]

    fe = ROOT / "frontend"
    app.mount("/static", StaticFiles(directory=fe), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(fe / "index.html")

    return app



