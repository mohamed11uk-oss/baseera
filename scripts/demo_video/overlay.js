(() => {
  if (window.__ov) return; window.__ov = true;
  const css = `#__cur{position:fixed;left:0;top:0;width:26px;height:26px;z-index:2147483647;pointer-events:none;transition:transform .7s cubic-bezier(.4,0,.2,1);transform:translate(640px,500px)}
  #__cur svg{filter:drop-shadow(0 2px 3px #0007)}
  .__rip{position:absolute;width:44px;height:44px;margin:-22px 0 0 -22px;border-radius:50%;border:3px solid #f59e0b;z-index:2147483646;pointer-events:none;animation:__r .6s ease-out forwards}
  @keyframes __r{from{transform:scale(.3);opacity:1}to{transform:scale(1.6);opacity:0}}
  .__hl{position:absolute;z-index:2147483645;pointer-events:none;border:4px solid #f59e0b;border-radius:12px;box-shadow:0 0 0 4000px #0000,0 0 18px #f59e0baa;opacity:0;transition:opacity .35s}
  .__hl.on{opacity:1}
  html{scroll-behavior:smooth}`;
  const add = () => {
    const st = document.createElement("style"); st.textContent = css; document.head.appendChild(st);
    const c = document.createElement("div"); c.id = "__cur";
    c.innerHTML = '<svg width="26" height="26" viewBox="0 0 24 24"><path d="M3 2l7 19 2.6-7.4L20 11z" fill="#fff" stroke="#111" stroke-width="1.5" stroke-linejoin="round"/></svg>';
    document.body.appendChild(c);
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", add); else add();
  window.__move = (x, y) => { const c = document.getElementById("__cur"); if (c) c.style.transform = `translate(${x - 3}px,${y - 2}px)`; };
  window.__ripple = (x, y) => { const r = document.createElement("div"); r.className = "__rip"; r.style.left = (x + scrollX) + "px"; r.style.top = (y + scrollY) + "px"; document.body.appendChild(r); setTimeout(() => r.remove(), 700); };
  window.__hl = (el, ms, pad) => {
    if (typeof el === "string") el = document.querySelector(el);
    if (!el) return false; pad = pad ?? 6;
    const b = el.getBoundingClientRect(); const d = document.createElement("div"); d.className = "__hl";
    Object.assign(d.style, { left: (b.left + scrollX - pad) + "px", top: (b.top + scrollY - pad) + "px", width: (b.width + 2 * pad) + "px", height: (b.height + 2 * pad) + "px" });
    document.body.appendChild(d); requestAnimationFrame(() => d.classList.add("on"));
    setTimeout(() => { d.classList.remove("on"); setTimeout(() => d.remove(), 400); }, ms || 2500); return true;
  };
  window.__clearhl = () => document.querySelectorAll(".__hl").forEach((d) => d.remove());
})();
