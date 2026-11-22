"use strict";
// Sends ONLY the current tab URL to the configured Baseera server (save_case=false). No other data, no remote code.
const $ = (s) => document.querySelector(s);
const DEF = "http://127.0.0.1:8000";
const LBL = { low: ["منخفض", "LOW"], medium: ["متوسط", "MEDIUM"], high: ["عالٍ", "HIGH"] };
const EN = { t_title: "Baseera", t_wait: "Checking…", t_report: "Report to Aman (Abu Dhabi Police)", t_call: "Call", t_sms: "SMS",
  t_settings: "Settings", t_api: "Baseera server (API) URL", save: "Save" };
const AR = {};
Object.keys(EN).forEach((k) => (AR[k] = $("#" + k).textContent));
let lang = "ar", last = null;

function setLang(l) {
  lang = l;
  document.documentElement.dir = l === "ar" ? "rtl" : "ltr";
  Object.keys(EN).forEach((k) => ($("#" + k).textContent = (l === "ar" ? AR : EN)[k]));
  $("#lang").textContent = l === "ar" ? "EN" : "ع";
  if (last) render(last);
}
function render(v) {
  last = v;
  const out = $("#out");
  out.textContent = "";
  const g = document.createElement("div");
  g.className = "gauge " + v.level;
  g.textContent = `${v.risk} · ${LBL[v.level][lang === "ar" ? 0 : 1]}`;
  const e = document.createElement("div");
  e.className = "expl";
  e.textContent = lang === "ar" ? v.explanation_ar : v.explanation_en; // textContent: never render server text as HTML
  out.append(g, e);
}
function fail(msg) {
  $("#out").textContent = msg;
}
async function getApi() {
  const s = await chrome.storage.local.get("api");
  return (s.api || DEF).replace(/\/+$/, "");
}
async function run() {
  const api = await getApi();
  $("#api").value = api;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !/^https?:/.test(tab.url || "")) return fail(lang === "ar" ? "هذه الصفحة لا يمكن فحصها." : "This page cannot be checked.");
  $("#url").textContent = tab.url;
  try {
    const r = await fetch(api + "/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url, save_case: false }) });
    if (!r.ok) throw new Error("HTTP " + r.status);
    render(await r.json());
  } catch (err) {
    fail((lang === "ar" ? "تعذر الاتصال بخادم بصيرة: " : "Cannot reach the Baseera server: ") + api + " (" + err.message + ")");
  }
}
$("#lang").onclick = () => setLang(lang === "ar" ? "en" : "ar");
$("#save").onclick = async () => {
  const v = $("#api").value.trim() || DEF;
  try {
    const origin = new URL(v).origin;
    await chrome.permissions.request({ origins: [origin + "/*"] });
    await chrome.storage.local.set({ api: v });
    run();
  } catch (_) { fail("Invalid URL"); }
};
run();
