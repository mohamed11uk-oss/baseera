"""Opt-in deep scan: open a suspect page in headless Chrome (Playwright) and capture evidence.

Safety model (CLAUDE.md hard rules 3 + 4):
- Fresh browser context per scan, downloads refused, service workers blocked, WebSockets never connected, popups closed,
  dialogs dismissed. No clicks, no typing, no form submission (submit() is disabled AND every non-GET request is
  aborted at the network layer, so nothing can be posted).
- EVERY request the page makes (document, redirect hop, iframe, script, image...) goes through `page.route`: the host is
  SSRF-checked (baseera.normalize.ssrf_check) and the body is fetched by our own guarded fetcher (2 MB cap after
  decompression, wall-clock deadline), then handed to the browser. Chrome never opens a socket itself.
- Page content is UNTRUSTED DATA. We only run fixed regex/keyword checks over it; nothing in it is ever interpreted as
  an instruction, and the raw text is not stored in the verdict (only title, field list and hashes).
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import socket
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlsplit

from .normalize import MAX_BODY_BYTES, FetchedResponse, FetchRefused, SSRFBlocked, normalize, safe_fetch, ssrf_check
from .schemas import Signal

NAV_TIMEOUT_MS = 10_000
TEXT_LIMIT = 6000
MAX_REQUESTS = 150
MAX_HOPS = 5
MAX_TOTAL_BYTES = 10 * 1024 * 1024
SCREENSHOT_MAX_H = 4000
VIEWPORT = {"width": 1280, "height": 900}
SENSITIVE_KINDS = ("otp", "card", "emirates_id", "password")
STRONG_KINDS = {"otp", "card", "emirates_id"}
KIND_AR = {"otp": "رمز التحقق (OTP)", "card": "بيانات البطاقة (Card)", "emirates_id": "رقم الهوية الإماراتية (Emirates ID)",
           "password": "كلمة المرور (Password)", "phone": "رقم الهاتف (Phone)"}

# Field classification: regexes over name/id/placeholder/label/aria-label/autocomplete (lower-cased). Order matters.
_FIELD_RULES = [
    ("emirates_id", re.compile(r"emirates.?id|\beid\b|e.?id.?(no|num)|national.?id|id.?number|784[-\s]?(x|\d)|"
                               r"الهوية|رقم الهوية|بطاقة الهوية")),
    ("card", re.compile(r"cc-(number|csc|exp)|card.?(no|num)|cardnumber|credit|debit|\bcvv2?\b|\bcvc\b|\bcsc\b|"
                        r"expir|exp.?(date|month|year)|\bmm\s*/\s*yy\b|\bpin\b|\batm\b|رقم البطاقة|البطاقة|الرمز السري|"
                        r"تاريخ الانتهاء")),
    ("otp", re.compile(r"one-time-code|\botp\b|one.?time|verification.?code|verify.?code|sms.?code|auth.?code|"
                       r"passcode|security.?code|رمز التحقق|كود التحقق|رمز التفعيل|الرمز المرسل|رمز مؤقت")),
    ("password", re.compile(r"current-password|new-password|password|passwd|\bpwd\b|كلمة المرور|كلمة السر")),
    ("phone", re.compile(r"\btel\b|phone|mobile|msisdn|هاتف|جوال|موبايل|الهاتف")),
]

_EXTRACT_JS = """(limit) => {
  const vis = (e) => { try { const s = getComputedStyle(e), r = e.getBoundingClientRect();
    return s.display !== 'none' && s.visibility !== 'hidden' && (r.width > 0 || r.height > 0); } catch (x) { return false; } };
  const skip = new Set(['hidden', 'submit', 'button', 'image', 'reset', 'checkbox', 'radio', 'file']);
  const inputs = Array.from(document.querySelectorAll('input,select,textarea')).slice(0, 200)
    .filter((e) => !skip.has((e.getAttribute('type') || '').toLowerCase()))
    .map((e) => ({ name: String(e.getAttribute('name') || e.id || '').slice(0, 80),
      type: String(e.getAttribute('type') || e.tagName).toLowerCase().slice(0, 30),
      placeholder: String(e.getAttribute('placeholder') || '').slice(0, 120),
      autocomplete: String(e.getAttribute('autocomplete') || '').slice(0, 60),
      label: String((e.labels && e.labels[0] && e.labels[0].innerText) || e.getAttribute('aria-label') || '').slice(0, 120),
      maxlength: Number(e.getAttribute('maxlength') || 0), visible: vis(e) }));
  const forms = Array.from(document.querySelectorAll('form')).slice(0, 50).map((f) => {
    try { return new URL(f.getAttribute('action') || '', document.baseURI).href; } catch (x) { return ''; } });
  const body = document.body ? (document.body.innerText || '') : '';
  return { title: String(document.title || '').slice(0, 300), text: body.slice(0, limit), inputs, forms,
           height: Math.max(document.documentElement ? document.documentElement.scrollHeight : 0, 1) };
}"""

# Runs before any page script: neutralise programmatic submission and popups (defence in depth: POSTs are also aborted).
_INIT_JS = """(() => { const no = function () {};
  try { HTMLFormElement.prototype.submit = no; HTMLFormElement.prototype.requestSubmit = no; } catch (e) {}
  try { window.addEventListener('submit', (e) => e.preventDefault(), true); } catch (e) {}
  try { window.open = () => null; } catch (e) {}
})();"""


@dataclass
class SandboxResult:
    url: str
    available: bool = True
    error: str | None = None
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    title: str = ""
    text: str = ""  # UNTRUSTED, truncated to TEXT_LIMIT. Kept in memory for checks; never stored in the verdict.
    inputs: list[dict] = field(default_factory=list)
    sensitive_kinds: list[str] = field(default_factory=list)
    form_actions: list[str] = field(default_factory=list)
    form_domains: list[str] = field(default_factory=list)
    blocked_requests: list[dict] = field(default_factory=list)
    requests: int = 0
    screenshot_sha256: str | None = None
    screenshot_phash: str | None = None
    screenshot_path: str | None = None
    elapsed_ms: int = 0

    def public(self) -> dict:
        """What may be stored / shown: no page text (untrusted, possibly personal data)."""
        d = asdict(self)
        d.pop("text")
        d.pop("screenshot_path")
        d["text_chars"] = len(self.text)
        d["blocked_requests"] = self.blocked_requests[:20]
        return d


# ------------------------------------------------------------------ pure helpers (unit-testable without Chrome)
def classify_field(f: dict) -> str | None:
    t = (f.get("type") or "").lower()
    ac = (f.get("autocomplete") or "").lower()
    if t == "password" or ac in ("current-password", "new-password"):
        return "password"
    if ac == "one-time-code":
        return "otp"
    if ac.startswith("cc-"):
        return "card"
    hay = " ".join(str(f.get(k) or "") for k in ("name", "placeholder", "label", "autocomplete")).lower()
    hay = re.sub(r"[_\-]+", " ", hay) + " " + hay  # card_number and card-number both match
    for kind, rx in _FIELD_RULES:
        if rx.search(hay):
            return kind
    if t == "tel" or ac.startswith("tel"):
        return "phone"
    return None


def dhash(png: bytes, size: int = 8) -> str:
    """64-bit difference hash (hex) of the top viewport of a screenshot. Same kit => same/near hash."""
    from PIL import Image

    img = Image.open(io.BytesIO(png))
    img = img.crop((0, 0, img.width, min(img.height, VIEWPORT["height"])))
    px = list(img.convert("L").resize((size + 1, size), Image.Resampling.LANCZOS).tobytes())
    bits = 0
    for row in range(size):
        for col in range(size):
            bits = (bits << 1) | int(px[row * (size + 1) + col] > px[row * (size + 1) + col + 1])
    return f"{bits:0{size * size // 4}x}"


def hamming(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def chrome_binary() -> str | None:
    return shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")


def _domain(u: str) -> str | None:
    try:
        return normalize(u).registrable_domain if urlsplit(u).scheme in ("http", "https") else None
    except ValueError:
        return None


# ------------------------------------------------------------------ the browser run
Fetcher = Callable[..., FetchedResponse]


def scan(url: str, *, out_dir: Path, fetcher: Fetcher | None = None, resolver=socket.getaddrinfo,
         nav_timeout_ms: int = NAV_TIMEOUT_MS, fetch_timeout_s: float = 4.0, chrome: str | None = None) -> SandboxResult:
    """Open `url` in a throw-away headless Chrome context and capture evidence. Never raises.

    fetcher(url, method=, headers=, resolver=, timeout=, deadline_s=) -> FetchedResponse; defaults to safe_fetch.
    Tests inject a fetcher that serves local HTML strings, so no network is touched.
    """
    t0 = time.monotonic()
    res = SandboxResult(url=url)
    try:
        ssrf_check(urlsplit(url).hostname or "", resolver=resolver)
    except SSRFBlocked as e:
        res.available, res.error = False, f"SSRF guard refused the URL: {e}"
        return res
    exe = chrome or chrome_binary()
    if not exe:
        res.available, res.error = False, "headless Chrome not installed"
        return res
    try:
        from playwright.sync_api import Error as PWError
        from playwright.sync_api import sync_playwright
    except ImportError:
        res.available, res.error = False, "playwright not installed"
        return res
    fetch = fetcher or safe_fetch
    budget = {"bytes": 0}
    checked: dict[str, str | None] = {}  # host -> refusal reason (per scan cache)

    def refuse(req_url: str, why: str):
        res.blocked_requests.append({"url": req_url[:300], "reason": why[:200]})

    def guarded(u: str) -> None:
        """Raise FetchRefused unless u may be fetched (scheme, budgets, SSRF)."""
        scheme = urlsplit(u).scheme
        if scheme not in ("http", "https"):
            raise FetchRefused(f"scheme {scheme} not allowed")
        if res.requests > MAX_REQUESTS or budget["bytes"] > MAX_TOTAL_BYTES:
            raise FetchRefused("request budget exhausted")
        if (time.monotonic() - t0) * 1000 > nav_timeout_ms + 3000:
            raise FetchRefused("scan time budget exhausted")
        host = urlsplit(u).hostname or ""
        if host not in checked:
            try:
                ssrf_check(host, resolver=resolver)
                checked[host] = None
            except SSRFBlocked as e:
                checked[host] = str(e)
        if checked[host]:
            raise FetchRefused(f"SSRF guard: {checked[host]}")

    def fetch_following(u: str, method: str, hdrs: dict, record: bool = False) -> tuple[str, FetchedResponse]:
        """Fetch with redirects followed HERE (Chrome does not follow a fulfilled 3xx); every hop is re-checked."""
        if u in prefetched:
            return prefetched.pop(u)
        cur = u
        for _ in range(MAX_HOPS + 1):
            guarded(cur)
            r = fetch(cur, method=method, headers=hdrs, resolver=resolver, timeout=fetch_timeout_s,
                      deadline_s=min(8.0, nav_timeout_ms / 1000))
            budget["bytes"] += len(r.body)
            loc = r.headers.get("location")
            if r.status not in (301, 302, 303, 307, 308) or not loc:
                return cur, r
            nxt = urljoin(cur, loc)
            if record:
                res.redirect_chain.append(nxt)
            cur, method = nxt, ("GET" if r.status == 303 else method)
        raise FetchRefused(f"more than {MAX_HOPS} redirects")

    def handle(route):
        req = route.request
        u = req.url
        res.requests += 1
        try:
            scheme = urlsplit(u).scheme
            if scheme in ("data", "blob", "about"):
                return route.continue_()
            if req.method not in ("GET", "HEAD"):
                refuse(u, f"{req.method} refused (no form submission / no data sent)")
                return route.abort("blockedbyclient")
            hdrs = {k: v for k, v in req.headers.items() if k.lower() in ("user-agent", "accept", "accept-language", "referer")}
            _, r = fetch_following(u, req.method, hdrs)
            hdrs_out = {k: v for k, v in r.headers.items()
                        if k.lower() not in ("set-cookie", "location", "content-security-policy-report-only")}
            return route.fulfill(status=r.status, headers=hdrs_out, body=r.body)
        except FetchRefused as e:
            refuse(u, str(e))
        except Exception as e:  # noqa: BLE001 - one bad resource must not kill the scan
            refuse(u, f"fetch error {type(e).__name__}")
        try:
            route.abort("blockedbyclient")
        except Exception:  # noqa: BLE001
            pass

    # Resolve the document's redirect chain first so the page opens at its real (final) URL.
    prefetched: dict[str, tuple[str, FetchedResponse]] = {}
    res.redirect_chain = [url]
    try:
        final, r0 = fetch_following(url, "GET", {}, record=True)
        prefetched[final] = (final, r0)
        nav_url = final
    except FetchRefused as e:
        res.available, res.error = False, f"page not fetched: {e}"
        res.blocked_requests.append({"url": res.redirect_chain[-1][:300], "reason": str(e)[:200]})
        res.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return res
    except Exception as e:  # noqa: BLE001
        res.available, res.error = False, f"page not fetched ({type(e).__name__})"
        res.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return res

    browser = None
    try:
        with sync_playwright() as pw:
            args = ["--disable-background-networking", "--dns-prefetch-disable", "--no-first-run", "--disable-sync",
                    "--disable-extensions", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--mute-audio"]
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                args.append("--no-sandbox")  # Chrome refuses to start as root otherwise; run as non-root in production
            browser = pw.chromium.launch(executable_path=exe, headless=True, args=args, timeout=15_000)
            ctx = browser.new_context(accept_downloads=False, service_workers="block", viewport=VIEWPORT,
                                      java_script_enabled=True, locale="ar-AE")
            ctx.add_init_script(_INIT_JS)
            ctx.route("**/*", handle)
            if hasattr(ctx, "route_web_socket"):
                ctx.route_web_socket("**/*", lambda ws: ws.close())  # never connect to the real server
            ctx.on("page", lambda p: p.on("dialog", lambda d: d.dismiss()))
            page = ctx.new_page()
            page.on("popup", lambda p: p.close())
            page.set_default_timeout(nav_timeout_ms)
            try:
                page.goto(nav_url, timeout=nav_timeout_ms, wait_until="load")
            except PWError as e:  # timeout or aborted: capture whatever rendered
                res.error = f"navigation: {str(e).splitlines()[0][:160]}"
            page.wait_for_timeout(400)
            res.final_url = page.url
            if page.url.startswith("chrome-error:"):
                raise RuntimeError(res.error or "browser error page")
            data = {"title": "", "text": "", "inputs": [], "forms": [], "height": VIEWPORT["height"]}
            for fr in page.frames[:10]:
                try:
                    d = fr.evaluate(_EXTRACT_JS, TEXT_LIMIT)
                except PWError:
                    continue
                if fr == page.main_frame:
                    data["title"], data["height"] = d["title"], d["height"]
                data["text"] = (data["text"] + "\n" + d["text"]).strip()[:TEXT_LIMIT]
                data["inputs"] += d["inputs"]
                data["forms"] += d["forms"]
            res.title, res.text = data["title"], data["text"]
            seen = set()
            for f in data["inputs"][:200]:
                key = (f["name"], f["type"], f["placeholder"], f["autocomplete"])
                if key in seen:
                    continue
                seen.add(key)
                f["kind"] = classify_field(f)
                res.inputs.append(f)
            res.sensitive_kinds = [k for k in SENSITIVE_KINDS if any(f["kind"] == k for f in res.inputs)]
            res.form_actions = list(dict.fromkeys(a for a in data["forms"] if a))[:20]
            res.form_domains = sorted({d for d in map(_domain, res.form_actions) if d})
            h = max(1, min(int(data["height"] or VIEWPORT["height"]), SCREENSHOT_MAX_H))
            png = page.screenshot(full_page=True, clip={"x": 0, "y": 0, "width": VIEWPORT["width"], "height": h},
                                  timeout=8000, animations="disabled")
            res.screenshot_sha256 = hashlib.sha256(png).hexdigest()
            res.screenshot_phash = dhash(png)
            out_dir.mkdir(parents=True, exist_ok=True)
            p = out_dir / f"{res.screenshot_sha256}.png"
            p.write_bytes(png)
            res.screenshot_path = str(p)
            browser.close()
            browser = None
    except Exception as e:  # noqa: BLE001 - a failing sandbox never fails /api/analyze
        res.available = bool(res.screenshot_sha256)
        res.error = f"sandbox error: {type(e).__name__}: {str(e).splitlines()[0][:160] if str(e) else ''}"
        if browser is not None:
            try:
                browser.close()
            except Exception:  # noqa: BLE001
                pass
    res.elapsed_ms = int((time.monotonic() - t0) * 1000)
    return res


# ------------------------------------------------------------------ signals (fixed keyword checks only)
def _norm_text(s: str) -> str:
    return " " + re.sub(r"[^\w&؀-ۿ]+", " ", s.lower()) + " "


def brand_mentions(title: str, text: str, registry) -> tuple[object, str, str] | None:
    """(entity, term, where) for the longest registry name/keyword found in the page. Short keywords (<3 chars) are
    ignored and 3-char ones only count in the title, to avoid matching ordinary words."""
    t_title, t_text = _norm_text(title), _norm_text(text)
    best = None
    for e in registry.entities:
        for k in dict.fromkeys([e.entity_name_en.lower(), e.entity_name_ar, *e.keywords]):
            kk = _norm_text(k).strip()
            if len(kk) < 3:
                continue
            for where, hay in (("title", t_title), ("text", t_text)):
                if where == "text" and len(kk) < 4:
                    continue
                if f" {kk} " in hay and (best is None or len(kk) > len(best[1])):
                    best = (e, kk, where)
    return best


def sandbox_signals(res: SandboxResult, host: str, registry, official) -> list[Signal]:
    if not res.available:
        return [Signal(id="sandbox", source="sandbox", score=0, available=False, evidence=f"Deep scan not run: {res.error}")]
    sigs: list[Signal] = []
    kinds = res.sensitive_kinds
    if kinds:
        fields = [f["name"] or f["placeholder"] or f["type"] for f in res.inputs if f["kind"] in kinds][:8]
        post = f"; forms post to {', '.join(res.form_domains)}" if res.form_domains else ""
        sigs.append(Signal(
            id="sensitive_form", source="sandbox", score=1.0 if STRONG_KINDS & set(kinds) else 0.5,
            data={"host": host, "kinds": kinds, "kinds_ar": "، ".join(KIND_AR[k] for k in kinds), "fields": fields,
                  "form_domains": res.form_domains},
            evidence=f"Page at {host} asks for {', '.join(kinds)} (fields: {', '.join(fields)}){post}"))
    m = brand_mentions(res.title, res.text, registry)
    if m and official is None:
        ent, term, where = m
        sigs.append(Signal(
            id="brand_in_page", source="sandbox", score=1.0,
            data={"entity_id": ent.id, "term": term, "where": where, "host": host},
            evidence=f"Page {where} names {ent.entity_name_en} ('{term}') but {host} is not one of its official domains "
                     f"({', '.join(ent.official_domains)})"))
    return sigs


class Sandbox:
    """Default runner bound to settings. Offline mode => unavailable (deep scan needs the network)."""

    def __init__(self, settings):
        self.settings = settings

    @property
    def out_dir(self) -> Path:
        return self.settings.screenshot_dir

    def status(self) -> str:
        if self.settings.source_sandbox == "off":
            return "off (SOURCE_SANDBOX=off)"
        if self.settings.offline:
            return "off (offline)"
        if not chrome_binary():
            return "unavailable (no Chrome)"
        return "on for every URL" if self.settings.source_sandbox == "on" else "on request (deep: true)"

    def __call__(self, url: str) -> SandboxResult:
        if self.settings.offline:
            return SandboxResult(url=url, available=False, error="offline mode (BASEERA_MODE=offline)")
        return scan(url, out_dir=self.out_dir, fetch_timeout_s=self.settings.timeout_s)


__all__ = ["MAX_BODY_BYTES", "Sandbox", "SandboxResult", "brand_mentions", "classify_field", "dhash", "hamming", "sandbox_signals",
           "scan"]
