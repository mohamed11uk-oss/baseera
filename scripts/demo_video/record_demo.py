import asyncio, sys, time, json, os, shutil
sys.path.insert(0, "/workspace/rec")
from screencast import Recorder
from playwright.async_api import async_playwright

BASE = os.getenv("BASE_URL", "http://127.0.0.1:8001")
OUT = sys.argv[1] if len(sys.argv) > 1 else "/workspace/rec/out"
OVERLAY = open("/workspace/rec/overlay.js").read()
log = []

class Clock:
    def __init__(self, abs_start, lead=0.4):
        self.T0 = time.time() + lead - abs_start
    async def at(self, t, what=""):
        d = self.T0 + t - time.time()
        if d > 0: await asyncio.sleep(d)
        else: log.append(f"LATE {-d:.2f}s at {t} {what}")
        log.append(f"{t:7.2f} {what}")
    def wall(self, t): return self.T0 + t

async def newpage(b, w=1152, h=648):
    ctx = await b.new_context(viewport={"width": w, "height": h}, device_scale_factor=1920/w, bypass_csp=True, locale="ar-AE")
    await ctx.add_init_script(OVERLAY)
    p = await ctx.new_page(); p.set_default_timeout(30000)
    return ctx, p

async def click(p, sel, move=0.7, js=True):
    loc = p.locator(sel).first
    await loc.evaluate("e=>e.scrollIntoViewIfNeeded ? e.scrollIntoViewIfNeeded() : e.scrollIntoView({block:'center'})")
    bb = await loc.bounding_box()
    x, y = bb["x"] + bb["width"] / 2, bb["y"] + bb["height"] / 2
    await p.evaluate(f"__move({x},{y})"); await asyncio.sleep(move)
    await p.evaluate(f"__ripple({x},{y})"); await asyncio.sleep(0.15)
    if js: await loc.evaluate("e=>e.click()")
    else: await loc.click()

async def move_to(p, sel):
    bb = await p.locator(sel).first.bounding_box()
    await p.evaluate(f"__move({bb['x']+bb['width']/2},{bb['y']+bb['height']/2})")

async def scroll_to(p, sel, offset=70):
    await p.evaluate(f"""(()=>{{const e=document.querySelector({json.dumps(sel)}); if(!e) return; const y=e.getBoundingClientRect().top+scrollY-{offset}; window.scrollTo({{top:Math.max(0,y),behavior:'smooth'}})}})()""")

async def hl(p, sel, ms=2500, pad=6, n=None, text=None):
    """highlight elements matching sel (optionally first n, or those containing text)"""
    return await p.evaluate("""([sel,ms,pad,n,text])=>{let els=[...document.querySelectorAll(sel)];
      if(text) els=els.filter(e=>e.textContent.includes(text)); if(n) els=els.slice(0,n);
      els.forEach(e=>__hl(e,ms,pad)); return els.length}""", [sel, ms, pad, n, text])

async def seg_slides(b, start, dur, steps, name):
    ctx, p = await newpage(b, 1280, 720)
    await p.goto("file:///workspace/rec/slides.html"); await p.wait_for_timeout(800)
    r = Recorder(p, f"{OUT}/{name}_frames"); await r.start()
    c = Clock(start, lead=0.6)
    for t, js in steps:
        await c.at(t, f"{name}: {js}"); await p.evaluate(js)
    await c.at(start + dur + 0.3, f"{name} end")
    await r.stop(); r.render(f"{OUT}/{name}.mp4", start_wall=c.wall(start), duration=dur)
    await ctx.close()

async def seg_app(b, start, end):
    ctx, p = await newpage(b)
    await p.goto(BASE + "/#analyze"); await p.wait_for_selector("#brand option", state="attached"); await p.wait_for_timeout(800)
    r = Recorder(p, f"{OUT}/app_frames"); await r.start()
    c = Clock(start, lead=0.6); at = c.at
    await at(start, "app start"); await p.evaluate("__move(900,330)")
    # ---- s2: link / message check
    await at(31.2, "cursor to fines"); await move_to(p, "a[data-ex*='adpolice-fines-pay']")
    await at(33.2, "click fines"); await click(p, "a[data-ex*='adpolice-fines-pay']", move=0.3)
    await p.wait_for_selector("#result .gauge")
    await at(33.9, "scroll result"); await scroll_to(p, "#result", 64)
    await at(34.8, "hl gauge"); await hl(p, "#result .gauge", 2000, 8)
    await at(36.6, "hl expl"); await hl(p, "#result .expl", 4800, 8)
    await at(41.6, "hl case/campaign"); await hl(p, "#result .verdict .row", 2600, 6, n=1)
    case_id = await p.evaluate("(document.querySelector('#result .row b')||{}).textContent")
    camp = await p.evaluate("(()=>{const m=document.querySelector('#result .verdict .row');return m&&(m.textContent.match(/CMP-[A-Z0-9]+/)||[''])[0]})()")
    log.append(f"case {case_id} campaign {camp}")
    await at(44.0, "scroll top"); await p.evaluate("window.scrollTo({top:0,behavior:'smooth'})"); await asyncio.sleep(0.5)
    await move_to(p, "a[data-ex*='adpolice.gov.ae']")
    await at(45.2, "click gov"); await click(p, "a[data-ex*='adpolice.gov.ae']", move=0.2)
    await p.wait_for_function("document.querySelector('#result .gauge small') && document.querySelector('#result .gauge small').textContent.includes('منخفض')")
    await at(45.9, "scroll"); await scroll_to(p, "#result", 64)
    await at(47.2, "hl gauge low"); await hl(p, "#result .gauge", 1800, 8)
    await at(48.0, "hl official expl"); await hl(p, "#result .expl", 3000, 8)
    await at(50.4, "scroll top"); await p.evaluate("window.scrollTo({top:0,behavior:'smooth'})"); await asyncio.sleep(0.4)
    await move_to(p, "a[data-ex^='عاجل']")
    await at(51.4, "click sms"); await click(p, "a[data-ex^='عاجل']", move=0.2)
    await p.wait_for_function("document.querySelectorAll('#result li').length > 0")
    await at(52.0, "scroll"); await scroll_to(p, "#result", 64)
    await at(52.8, "hl sms expl"); await hl(p, "#result .expl", 5400, 8)
    await at(58.3, "hl gauge high"); await hl(p, "#result .gauge", 1800, 8)
    sms_case = await p.evaluate("(document.querySelector('#result .row b')||{}).textContent")
    log.append(f"sms case {sms_case}")
    # ---- s3: search & maps
    await at(61.4, "to scan tab"); await p.evaluate("window.scrollTo({top:0,behavior:'smooth'})")
    await click(p, "button[data-tab='scan']", move=0.6)
    await at(65.8, "hl select"); await move_to(p, "#brand"); await hl(p, "#brand", 2400, 6)
    await at(70.2, "click scan"); await click(p, "#scan_go", move=0.5)
    await p.wait_for_selector("#scan_out table")
    await at(71.2, "scroll scan"); await scroll_to(p, "#scan_out", 64)
    await at(72.1, "hl green"); await hl(p, "#scan_out tr.off", 2000, 2)
    await at(73.9, "hl ad"); await hl(p, "#scan_out tr", 2000, 2, text="Ad")
    await at(75.4, "hl maps hijack"); await hl(p, "#scan_out tr.hl-medium", 2200, 2)
    await at(77.9, "hl synthetic"); await hl(p, "#scan_out .card > .row .pill", 3200, 6)
    await at(82.6, "hover rows"); await move_to(p, "#scan_out tr.hl-high")
    await at(85.0, "hover off"); await move_to(p, "#scan_out tr.off")
    # ---- s4: analyst dashboard
    await at(87.6, "to dash"); await p.evaluate("window.scrollTo({top:0,behavior:'smooth'})"); await asyncio.sleep(0.4)
    await click(p, "button[data-tab='dash']", move=0.5)
    for k in range(10):
        try:
            await p.wait_for_selector(".cl svg", timeout=1500); break
        except Exception:
            log.append("dash retry"); await p.evaluate("document.getElementById('refresh').click()")
    await at(89.2, "hl kpis"); await hl(p, "#kpis", 2200, 6)
    cl_sel = ".cl"
    idx = await p.evaluate(f"[...document.querySelectorAll('.cl')].findIndex(e=>e.textContent.includes({json.dumps(camp or 'CMP')}))")
    log.append(f"cluster idx {idx}")
    await p.evaluate(f"document.querySelectorAll('.cl')[{max(idx,0)}].id='__target'")
    await at(91.4, "scroll campaign"); await scroll_to(p, "#__target", 70)
    await at(92.4, "hl campaign hdr"); await hl(p, "#__target > .row", 2200, 6, n=1)
    await at(94.6, "hl graph"); await hl(p, "#__target svg", 4000, 4)
    await at(96.8, "hl shared"); await hl(p, "#__target > .mut.ltr", 2200, 4)
    await at(99.0, "hl timeline"); await hl(p, "#__target .timeline", 1700, 8)
    await move_to(p, "#__target .timeline")
    await at(100.7, "open evidence"); await p.goto(f"{BASE}/api/cases/{case_id}/evidence.html"); await p.wait_for_timeout(300)
    await at(101.6, "hl evid title"); await hl(p, "h1", 1800, 6)
    await at(102.9, "scroll sha"); await p.evaluate("window.scrollTo({top:document.body.scrollHeight,behavior:'smooth'})")
    await at(103.9, "hl sha"); await hl(p, "ul", 3800, 6, n=None)
    await at(108.0, "scroll campaign sec"); await p.evaluate("(()=>{const h=[...document.querySelectorAll('h2,h3')].find(e=>e.textContent.includes('Campaign'));if(h)window.scrollTo({top:h.getBoundingClientRect().top+scrollY-80,behavior:'smooth'})})()")
    await at(109.0, "hl campaign sec"); await p.evaluate("(()=>{const h=[...document.querySelectorAll('h2,h3')].find(e=>e.textContent.includes('Campaign'));if(h){__hl(h,2600,6);if(h.nextElementSibling)__hl(h.nextElementSibling,2600,6)}})()")
    # ---- s5: health & registry
    await at(112.2, "to health"); await p.goto(BASE + "/#health"); await p.wait_for_selector("#registry_out table")
    await at(113.3, "hl health"); await hl(p, "#health_out > b", 2000, 6)
    await at(114.5, "scroll registry"); await scroll_to(p, "#health h3", 64)
    await at(115.5, "hl sources"); await hl(p, "#registry_out tr td:last-child", 2400, 2, n=7)
    await at(117.4, "scroll limits"); await p.evaluate("(()=>{const e=document.querySelectorAll('#registry_out .pill.med')[0]; if(e) window.scrollTo({top:e.getBoundingClientRect().top+scrollY-120,behavior:'smooth'})})()")
    await at(118.0, "hl limits"); await hl(p, "#registry_out .pill.med", 1600, 4, n=5)
    await at(119.3, "click English"); await click(p, "#lang", move=0.4)
    await at(120.6, "hl tabs en"); await hl(p, "nav", 2200, 4)
    await at(end + 0.3, "app end")
    await r.stop(); r.render(f"{OUT}/app.mp4", start_wall=c.wall(start), duration=end - start)
    await ctx.close()

async def main():
    if os.path.exists(OUT): shutil.rmtree(OUT)
    os.makedirs(OUT)
    async with async_playwright() as pw:
        b = await pw.chromium.launch(executable_path="/usr/bin/google-chrome", headless=True, args=["--no-sandbox", "--hide-scrollbars"])
        await seg_slides(b, 0.0, 30.5, [(0.15, "show('s0')"), (3.9, "show('s1')"), (6.3, "on('b1')"), (8.9, "on('b2')"),
              (11.4, "on('c1')"), (13.2, "on('c2')"), (15.8, "show('s2')"), (18.5, "on('n1')"), (23.6, "on('n2')"), (26.0, "show('s3')")], "s1")
        await seg_app(b, 30.5, 123.0)
        await seg_slides(b, 123.0, 11.64, [(123.05, "show('s4')")], "end")
        await b.close()
    open(f"{OUT}/log.txt", "w").write("\n".join(log))
    print("\n".join(l for l in log if l.startswith("LATE") or "case" in l or "idx" in l))

asyncio.run(main())
