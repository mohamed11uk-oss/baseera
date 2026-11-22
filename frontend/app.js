"use strict";
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let LANG = "ar";
const T = {
  en: { title: "Baseera", tagline: "Fake link & listing detector", tab_analyze: "Check link / message", tab_scan: "Search & Maps results",
    tab_dash: "Analyst dashboard", tab_health: "Health & registry", paste: "Paste a link, an SMS/WhatsApp message, or a brand name:",
    check: "Check", deep: "Deep scan (isolated browser)", try: "Try:", listing_form: "Check a Maps/Search listing manually (name + phone + website)", sponsored: "Sponsored ad",
    check_listing: "Check listing", report: "Report fraud — Aman service (Abu Dhabi Police)", call: "Call", sms: "SMS", emergency: "Emergency",
    aman_src: "Source: adpolice.gov.ae (verified 2026-11-19)", choose: "Choose an entity to check Search & Maps results for:", scan: "Scan results",
    all_entities: "All entities", all_levels: "All levels", refresh: "Refresh", campaigns: "Detected campaigns", cases: "Cases",
    registry: "Official Entity Registry", proto: "ScamShield AI hackathon prototype. Results are automated and need confirmation; anything labelled synthetic is demo data." },
};
const AR = {};
document.querySelectorAll("[data-i18n]").forEach((el) => (AR[el.dataset.i18n] = el.textContent));
T.ar = AR;
const L = { low: { ar: "منخفض", en: "LOW" }, medium: { ar: "متوسط", en: "MEDIUM" }, high: { ar: "عالٍ", en: "HIGH" } };
const tr = (k) => T[LANG][k] || k;

function setLang(l) {
  LANG = l;
  document.documentElement.lang = l; document.documentElement.dir = l === "ar" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((el) => (el.textContent = tr(el.dataset.i18n)));
  $("#lang").textContent = l === "ar" ? "English" : "العربية";
}
$("#lang").onclick = () => setLang(LANG === "ar" ? "en" : "ar");

document.querySelectorAll(".tab").forEach((b) => (b.onclick = () => showTab(b.dataset.tab)));
function showTab(id) {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === id));
  document.querySelectorAll(".panel").forEach((x) => x.classList.toggle("active", x.id === id));
  if (id === "dash") loadDash();
  if (id === "health") loadHealth();
  location.hash = id;
}

async function api(path, body, method) {
  const opts = body ? { method: method || "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : { method: method || "GET" };
  const r = await fetch("/api" + path, { ...opts, credentials: "same-origin" });
  if (!r.ok) { const e = new Error((await r.text()) || r.status); e.status = r.status; throw e; }
  return r.json();
}
// Analyst session (only enforced when the server has ANALYST_TOKEN set; the token lives in an HttpOnly cookie).
let ANALYST = { required: false, authenticated: true };
async function loadSession() { try { ANALYST = await api("/analyst/session"); } catch (e) { /* keep default */ } }

function gauge(v) {
  return `<div class="gauge lvl-${v.level}" style="--v:${v.risk}"><div>${v.risk}<small>${L[v.level][LANG]}</small></div></div>`;
}
function signalTable(sigs) {
  const rows = sigs.map((s) => `<tr><td class="ltr">${esc(s.id)}</td><td>${esc(s.source)}</td><td>${s.available ? esc(s.contribution) : '<span class="pill na">n/a</span>'}</td><td class="ltr">${esc(s.evidence)}</td></tr>`).join("");
  return `<details><summary>${LANG === "ar" ? "تفاصيل الإشارات والمصادر (Signals)" : "Signal breakdown & sources"} (${sigs.length})</summary>
  <table><tr><th>Signal</th><th>${LANG === "ar" ? "المصدر" : "Source"}</th><th>${LANG === "ar" ? "المساهمة" : "Contribution"}</th><th>${LANG === "ar" ? "الدليل" : "Evidence"}</th></tr>${rows}</table></details>`;
}
// Google Safe Browsing terms: attribution + "not guaranteed" disclaimer wherever a GSB result is displayed.
function gsbNotice(d) {
  if (!d) return "";
  return `<div class="gsb-notice"><b>${esc(LANG === "ar" ? d.attribution_ar : d.attribution_en)}</b>
    (<a class="ltr" target="_blank" rel="noopener noreferrer" href="${esc(d.advisory_url)}">advisory</a>) —
    ${esc(LANG === "ar" ? d.disclaimer_ar : d.disclaimer_en)}</div>`;
}
function renderVerdict(v) {
  const g = (v.signals || []).find((s) => s.source === "gsb");
  const ent = v.matched_entity;
  const entLine = ent ? `<div class="mut">${ent.relation === "official" ? "✔ " : "⚠ "}${esc(LANG === "ar" ? ent.entity_name_ar : ent.entity_name_en)} — <span class="ltr">${esc((ent.official_domains || []).join(", "))}</span></div>` : "";
  const subs = (v.sub_verdicts || []).map((s) => `<li><span class="pill ${s.level}">${s.risk}</span> <span class="ltr">${esc(s.input)}</span></li>`).join("");
  const chain = (v.normalized && v.normalized.redirect_chain && v.normalized.redirect_chain.length > 1) ? `<div class="mut ltr">Redirects: ${v.normalized.redirect_chain.map(esc).join(" → ")}</div>` : "";
  const caseLink = v.case_id && ANALYST.authenticated ? `<div class="row"><span class="mut">${LANG === "ar" ? "حُفظت كحالة" : "Saved as case"} <b>${esc(v.case_id)}</b>${v.campaign_id ? " · " + (LANG === "ar" ? "ضمن الحملة " : "campaign ") + esc(v.campaign_id) : ""}</span>
     <a href="/api/cases/${encodeURIComponent(v.case_id)}/evidence.html" target="_blank">${LANG === "ar" ? "ملف الأدلة" : "Evidence pack"}</a></div>` : "";
  return `<div class="card"><div class="verdict">${gauge(v)}<div>
     ${entLine}<div class="expl">${esc(LANG === "ar" ? v.explanation_ar : v.explanation_en)}</div>
     ${LANG === "ar" ? `<div class="en">${esc(v.explanation_en)}</div>` : ""}${chain}
     ${subs ? `<ul>${subs}</ul>` : ""}${deepBlock(v)}${vtBlock(v)}${caseLink}
     <div class="mut">mode: ${esc(v.mode)} · ${esc(v.analyzed_at)} UTC</div>${signalTable(v.signals)}${g ? gsbNotice(g.data) : ""}</div></div></div>`;
}

// Deep scan: screenshot + captured form fields. Page content is untrusted: everything goes through esc().
function deepBlock(v) {
  const sb = v.normalized && v.normalized.sandbox;
  if (!sb) return "";
  if (!sb.available) return `<div class="mut">${LANG === "ar" ? "الفحص المعمّق غير متاح" : "Deep scan not available"}: <span class="ltr">${esc(sb.error)}</span></div>`;
  const kinds = (sb.sensitive_kinds || []).join(", ");
  const img = /^\/api\/screenshots\/[0-9a-f]{64}\.png$/.test(v.screenshot_url || "")
    ? `<a href="${esc(v.screenshot_url)}" target="_blank" rel="noopener"><img class="shot" alt="screenshot" loading="lazy" src="${esc(v.screenshot_url)}"></a>` : "";
  return `<div class="deep"><b>${LANG === "ar" ? "فحص معمّق (Deep scan)" : "Deep scan"}</b>
    <div class="mut">${LANG === "ar" ? "لقطة من متصفح معزول، ما تم إدخال أو إرسال أي بيانات" : "Isolated browser snapshot; nothing was typed or submitted"}</div>
    <div class="mut ltr">title: ${esc(sb.title)} · fields: ${esc(kinds || "—")}${(sb.form_domains || []).length ? " · posts to: " + esc(sb.form_domains.join(", ")) : ""} · blocked requests: ${(sb.blocked_requests || []).length}</div>
    ${img}<div class="mut ltr">SHA-256 ${esc(sb.screenshot_sha256 || "—")} · dHash ${esc(sb.screenshot_phash || "—")}</div></div>`;
}

// VirusTotal: manual deep check only (separate endpoint, 4 req/min, never changes the score). Shown only when enabled.
let VT_ON = false;
api("/health").then((h) => { VT_ON = !!(h.per_source && h.per_source.virustotal && h.per_source.virustotal.enabled); }).catch(() => {});
function vtBlock(v) {
  const url = v.kind === "url" && v.normalized && v.normalized.url;
  if (!VT_ON || !url) return "";
  return `<div class="deep vt"><button type="button" class="vt-btn" data-url="${esc(url)}">${LANG === "ar" ? "فحص إضافي في VirusTotal (Deep check)" : "Deep check on VirusTotal"}</button>
    <span class="mut">${LANG === "ar" ? "يقرأ تقرير VirusTotal الموجود فقط، وما يغيّر درجة الخطر" : "Reads the existing VirusTotal report only; does not change the score"}</span><div class="vt-out"></div></div>`;
}
async function vtCheck(btn) {
  const out = btn.parentElement.querySelector(".vt-out");
  btn.disabled = true;
  out.textContent = LANG === "ar" ? "جاري الفحص…" : "Checking…";
  try {
    const r = await api("/deep-check/virustotal", { url: btn.dataset.url });
    const link = r.permalink && /^https:\/\/www\.virustotal\.com\/gui\/url\/[0-9a-f]{64}$/.test(r.permalink)
      ? ` <a class="ltr" target="_blank" rel="noopener noreferrer" href="${esc(r.permalink)}">VirusTotal</a>` : "";
    out.innerHTML = `<div>${esc(LANG === "ar" ? r.summary_ar : r.summary_en)}${link}</div>
      ${r.last_analysis_date ? `<div class="mut ltr">last analysis: ${esc(r.last_analysis_date)}${r.cached ? " (cached)" : ""}</div>` : ""}`;
  } catch (e) { out.textContent = e.message; }
  setTimeout(() => { btn.disabled = false; }, 15000);  // 4 req/min budget: no rapid re-clicks
}
$("#result").addEventListener("click", (e) => { const b = e.target.closest(".vt-btn"); if (b) vtCheck(b); });

async function run(body) {
  $("#result").innerHTML = `<div class="card">${LANG === "ar" ? "جاري الفحص…" : "Checking…"}</div>`;
  try { $("#result").innerHTML = renderVerdict(await api("/analyze", body)); }
  catch (e) { $("#result").innerHTML = `<div class="card">${esc(e.message)}</div>`; }
}
$("#go").onclick = () => {
  const q = $("#q").value.trim();
  if (!q) return;
  const looksUrl = !/\s/.test(q) && /[.\/]/.test(q);
  run(looksUrl ? { url: q, deep: $("#deep").checked } : { text: q });
};
$("#go_l").onclick = () => run({ listing: { source: "manual", title: $("#l_title").value || "?", phone: $("#l_phone").value || null,
  displayed_url: $("#l_site").value || null, is_ad: $("#l_ad").checked } });
document.querySelectorAll("[data-ex]").forEach((a) => (a.onclick = (e) => { e.preventDefault(); $("#q").value = a.dataset.ex; $("#go").click(); }));

// ---------------------------------------------------------------- brand scan

// Badge colour for the scan-brand data label. Order matters: the synthetic label says "NOT recorded from Google",
// so "synthetic" must be tested before "recorded" (otherwise synthetic data shows the brown "recorded" badge).
function dataLabelClass(label) {
  if (/synthetic/i.test(label)) return "syn";
  if (/no recorded/i.test(label)) return "na";
  if (/recorded/i.test(label)) return "rec";
  if (/live/i.test(label)) return "off";
  return "syn";
}

async function loadBrands() {
  const bs = await api("/brands");
  $("#brand").innerHTML = bs.map((b) => `<option value="${esc(b.id)}">${esc(b.name_ar)} — ${esc(b.name_en)}${b.has_fixture ? " ★" : ""}</option>`).join("");
  $("#brand").value = "enbd";
  $("#f_entity").innerHTML = `<option value="">${tr("all_entities")}</option>` + bs.map((b) => `<option value="${esc(b.id)}">${esc(b.name_ar)}</option>`).join("");
}
$("#scan_go").onclick = async () => {
  $("#scan_out").innerHTML = `<div class="card">…</div>`;
  try {
    const r = await api("/scan-brand", { brand: $("#brand").value });
    const rows = r.results.map((x) => {
      const l = x.listing, v = x.verdict;
      const cls = x.official ? "off" : "hl-" + v.level;
      return `<tr class="${cls}"><td>${l.source === "maps" ? "🗺️ Maps" : "🔎 Search"}${l.is_ad ? ' <span class="pill high">Ad</span>' : ""}</td>
        <td>${esc(l.title)}</td><td class="ltr">${esc(l.displayed_url || "—")}</td><td class="ltr">${esc(l.phone || "—")}</td>
        <td>${x.official ? '<span class="pill off">✔ رسمي موثّق</span>' : `<span class="pill ${v.level}">${v.risk} ${L[v.level][LANG]}</span>`}</td>
        <td>${esc(LANG === "ar" ? x.reason_ar : x.reason_en)}</td></tr>`;
    }).join("");
    const ent = r.entity;
    $("#scan_out").innerHTML = `<div class="card"><div class="row"><b>${esc(ent.entity_name_ar)}</b><span class="pill ${dataLabelClass(r.data_label)}">${esc(r.data_label)}</span></div>
      <div class="mut">${LANG === "ar" ? "النطاقات الرسمية" : "Official domains"}: <span class="ltr">${esc(ent.official_domains.join(", "))}</span> · ${LANG === "ar" ? "الأرقام الرسمية" : "Official phones"}: <span class="ltr">${esc(ent.official_phones.map((p) => p.number).join(", ") || "—")}</span> · ${esc(ent.status)}</div>
      ${r.results.length ? `<table><tr><th>${LANG === "ar" ? "المصدر" : "Source"}</th><th>${LANG === "ar" ? "الاسم الظاهر" : "Title"}</th><th>${LANG === "ar" ? "الموقع" : "Website"}</th><th>${LANG === "ar" ? "الرقم" : "Phone"}</th><th>${LANG === "ar" ? "الحكم" : "Verdict"}</th><th>${LANG === "ar" ? "السبب" : "Reason"}</th></tr>${rows}</table>` : `<p>${LANG === "ar" ? "لا توجد بيانات لهذه الجهة. أضف مفتاح SerpAPI للفحص الحي أو استخدم الفحص اليدوي." : "No data for this brand. Add a SerpAPI key for live mode or use the manual listing check."}</p>`}</div>`;
  } catch (e) { $("#scan_out").innerHTML = `<div class="card">${esc(e.message)}</div>`; }
};

// ---------------------------------------------------------------- dashboard
function graphSVG(cl, cases) {
  const W = 520, H = 220, cx = W / 2, cy = H / 2;
  const keys = cl.shared.slice(0, 6);
  const nodes = cl.case_ids.map((id, i) => { const a = (2 * Math.PI * i) / cl.case_ids.length; return { id, x: cx + 180 * Math.cos(a), y: cy + 80 * Math.sin(a) }; });
  const knodes = keys.map((k, i) => ({ k, x: cx - 120 + (240 * i) / Math.max(1, keys.length - 1 || 1), y: cy }));
  let s = `<svg class="graph" viewBox="0 0 ${W} ${H}">`;
  nodes.forEach((n) => { const c = cases[n.id] || {}; const ks = new Set([...(c._keys || [])]);
    knodes.forEach((k) => { if (ks.has(k.k)) s += `<line x1="${n.x}" y1="${n.y}" x2="${k.x}" y2="${k.y}" stroke="#9bb" />`; }); });
  knodes.forEach((k) => (s += `<rect x="${k.x - 6}" y="${k.y - 6}" width="12" height="12" fill="#2b7a8f"><title>${esc(k.k)}</title></rect><text x="${k.x}" y="${k.y + 20}" font-size="8" text-anchor="middle" direction="ltr">${esc(k.k.split(":")[0])}</text>`));
  nodes.forEach((n) => { const c = cases[n.id] || {}; const col = c.level === "high" ? "#d93025" : c.level === "medium" ? "#e8a400" : "#1e8e3e";
    s += `<circle cx="${n.x}" cy="${n.y}" r="9" fill="${col}"><title>${esc(c.registrable_domain || n.id)}</title></circle><text x="${n.x}" y="${n.y - 13}" font-size="9" text-anchor="middle" direction="ltr">${esc(c.registrable_domain || n.id)}</text>`; });
  return s + "</svg>";
}
function keysFor(c) {
  const i = c.infra || {}, out = [];
  (i.phones || []).forEach((p) => out.push("phone:" + p.replace(/\D/g, "").replace(/^971/, "").replace(/^0/, "")));
  (i.ips || []).forEach((p) => out.push("ip:" + p));
  if (i.nameservers) out.push("ns:" + [...i.nameservers].sort().join(","));
  if (i.registrar) out.push("registrar:" + i.registrar.toLowerCase());
  if (c.entity_id) out.push("target:" + c.entity_id);
  return out;
}
async function loadDash() {
  try { await loadDashInner(); $("#analyst_login").classList.add("hidden"); }
  catch (e) {
    if (e.status !== 401) throw e;
    ["#kpis", "#clusters", "#cases"].forEach((s) => ($(s).innerHTML = ""));
    $("#analyst_login").classList.remove("hidden");
  }
}
$("#analyst_go").onclick = async () => {
  try { await api("/analyst/session", { token: $("#analyst_token").value }); $("#analyst_token").value = ""; await loadSession(); loadDash(); }
  catch (e) { $("#analyst_msg").textContent = LANG === "ar" ? "الرمز غير صحيح" : "Wrong token"; }
};
// Case links: event delegation (no inline handlers, so the strict Content-Security-Policy can forbid inline script).
document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-case]");
  if (!el) return;
  e.preventDefault();
  openCase(el.dataset.case);
});
async function loadDashInner() {
  const ent = $("#f_entity").value, lvl = $("#f_level").value;
  const qs = new URLSearchParams(); if (ent) qs.set("entity", ent); if (lvl) qs.set("level", lvl);
  const [cases, clusters] = await Promise.all([api("/cases?" + qs), api("/clusters")]);
  const byId = Object.fromEntries(cases.map((c) => [c.id, { ...c, _keys: keysFor(c) }]));
  const allCases = await api("/cases");
  const allById = Object.fromEntries(allCases.map((c) => [c.id, { ...c, _keys: keysFor(c) }]));
  const shown = clusters.filter((cl) => cl.case_ids.some((id) => byId[id]));
  const highs = cases.filter((c) => c.level === "high").length;
  $("#kpis").innerHTML = [[cases.length, LANG === "ar" ? "حالة" : "cases"], [highs, LANG === "ar" ? "عالية الخطورة" : "high risk"],
    [shown.length, LANG === "ar" ? "حملة" : "campaigns"], [new Set(cases.map((c) => c.entity_id).filter(Boolean)).size, LANG === "ar" ? "جهة مستهدفة" : "targeted entities"]]
    .map(([n, t]) => `<div class="kpi"><b>${n}</b>${t}</div>`).join("");
  $("#clusters").innerHTML = shown.map((cl) => {
    const days = {}; cl.case_ids.forEach((id) => { const d = (allById[id] || {}).created_at?.slice(0, 10); if (d) days[d] = (days[d] || 0) + 1; });
    const tl = Object.keys(days).sort().map((d) => `<span title="${esc(d)}" style="height:${12 * days[d] + 8}px"></span>`).join("");
    return `<div class="cl"><div class="row"><b>${esc(cl.id)}</b>${cl.synthetic ? '<span class="pill syn">بيانات تجريبية · synthetic</span>' : ""}
      <span class="pill high">max ${cl.max_risk}</span><span>${cl.case_ids.length} ${LANG === "ar" ? "نطاقات" : "domains"}</span>
      <span class="mut">${LANG === "ar" ? "الجهة المستهدفة" : "Target"}: ${esc(cl.entity_ids.join(", "))} · ${esc(cl.first_seen.slice(0, 10))} → ${esc(cl.last_seen.slice(0, 10))}</span></div>
      <div class="mut ltr">shared: ${esc(cl.shared.join(" | "))}</div>${graphSVG(cl, allById)}
      <div class="row"><span class="mut">${LANG === "ar" ? "الخط الزمني" : "Timeline"}</span><div class="timeline">${tl}</div></div>
      <div class="row">${cl.case_ids.map((id) => `<button data-case="${esc(id)}">${esc((allById[id] || {}).registrable_domain || id)}</button>`).join("")}</div></div>`;
  }).join("") || `<p class="mut">—</p>`;
  $("#cases").innerHTML = `<table><tr><th>ID</th><th>${LANG === "ar" ? "المُدخل" : "Input"}</th><th>${LANG === "ar" ? "الخطر" : "Risk"}</th><th>${LANG === "ar" ? "الجهة" : "Entity"}</th><th>${LANG === "ar" ? "الحملة" : "Campaign"}</th><th>${LANG === "ar" ? "ملف الأدلة" : "Evidence"}</th></tr>` +
    cases.map((c) => `<tr class="hl-${esc(c.level)}"><td><a href="#" data-case="${esc(c.id)}">${esc(c.id)}</a>${c.synthetic ? ' <span class="pill syn">synthetic</span>' : ""}</td>
     <td class="ltr">${esc(String(c.input ?? "").slice(0, 80))}</td><td><span class="pill ${esc(c.level)}">${c.risk}</span></td><td>${esc(c.entity_id || "—")}</td><td>${esc(c.cluster_id || "—")}</td>
     <td><a target="_blank" href="/api/cases/${encodeURIComponent(c.id)}/evidence.html">HTML</a> · <a href="/api/cases/${encodeURIComponent(c.id)}/evidence.pdf">PDF</a> · <a href="/api/cases/${encodeURIComponent(c.id)}/evidence.json">JSON</a> · <a href="/api/cases/${encodeURIComponent(c.id)}/evidence.zip">ZIP</a></td></tr>`).join("") + "</table>";
}
const openCase = async (id) => {
  const c = await api("/cases/" + encodeURIComponent(id));
  $("#modal_content").innerHTML = `<h3>${esc(c.id)} ${c.cluster_id ? "· " + esc(c.cluster_id) : ""}</h3>${renderVerdict({ ...c.verdict, case_id: c.id, campaign_id: c.cluster_id })}
    <pre class="ltr mut">${esc(JSON.stringify(c.infra, null, 1))}</pre>`;
  $("#modal").classList.remove("hidden");
};
$("#close").onclick = () => $("#modal").classList.add("hidden");
$("#refresh").onclick = loadDash; $("#f_entity").onchange = loadDash; $("#f_level").onchange = loadDash;

// ---------------------------------------------------------------- health
async function loadHealth() {
  const h = await api("/health");
  const per = Object.entries(h.per_source || {}).map(([k, v]) => `<tr><td class="ltr">${esc(k)}</td><td><span class="pill ${v.status === "ok" || v.status === "ready" ? "off" : v.status === "degraded" ? "high" : "na"}">${esc(v.status)}</span></td>
    <td class="ltr">${esc(v.detail)}</td><td class="ltr">${esc(v.calls_ok)} / ${esc(v.calls_failed)}</td><td class="ltr">${esc(v.last_error || "—")}</td></tr>`).join("");
  $("#health_out").innerHTML = `<b>status: ${esc(h.status)}</b> · mode: <b>${esc(h.mode)}</b> · data: <b>${esc(h.data_mode)}</b> (${esc(h.data_mode_note)}) · cases: ${esc(h.cases)}
    <div class="mut">Search/Maps: ${esc(h.search_maps_data)}</div>
    <table><tr><th>source</th><th>status</th><th>detail</th><th>ok / failed</th><th>last error</th></tr>${per}</table>
    <details><summary>raw</summary><table>${Object.entries(h.sources).map(([k, v]) => `<tr><td>${esc(k)}</td><td class="ltr">${esc(typeof v === "object" ? JSON.stringify(k === "gsb" ? { status: v.status, usage: v.usage } : v) : v)}</td></tr>`).join("")}</table></details>${h.sources.gsb && h.sources.gsb.status && h.sources.gsb.status.startsWith("on") ? gsbNotice(h.sources.gsb) : ""}`;
  const reg = await api("/registry");
  $("#registry_out").innerHTML = `<table><tr><th>${LANG === "ar" ? "الجهة" : "Entity"}</th><th>${LANG === "ar" ? "النطاقات" : "Domains"}</th><th>${LANG === "ar" ? "الأرقام" : "Phones"}</th><th>${LANG === "ar" ? "الحالة" : "Status"}</th><th>${LANG === "ar" ? "المصدر" : "Source"}</th></tr>` +
    reg.map((e) => `<tr><td>${esc(e.entity_name_ar)}<br><span class="mut">${esc(e.entity_name_en)}</span></td><td class="ltr">${esc(e.official_domains.join(", "))}</td>
    <td class="ltr">${esc(e.official_phones.map((p) => p.number + " (" + p.label + ")").join(", ") || "—")}</td>
    <td>${e.status === "verified" ? '<span class="pill off">verified</span>' : '<span class="pill med medium">domain only · unverified phones</span>'} <span class="mut">${esc(e.verified_on)}</span></td>
    <td class="ltr"><a target="_blank" rel="noopener noreferrer" href="${esc(e.source_url)}">${esc(e.source_url.replace(/^https?:\/\//, "").slice(0, 40))}</a></td></tr>`).join("") + "</table>";
}

loadSession();
loadBrands();
const h = location.hash.slice(1);
if (["analyze", "scan", "dash", "health"].includes(h)) showTab(h);
