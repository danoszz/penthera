/**
 * The Pro page's three behaviours (site/pro.mjs). Nothing is stored or sent.
 *
 *   1. The calculator and the waitlist: the sliders show the reader's own
 *      numbers, and on submit everything goes into the body of a mailto link
 *      that the reader's mail app sends. The CSP blocks form submission, so
 *      this script makes the button work; without it, the plain mailto link
 *      under the form still does.
 *
 *   2. The horizontal page: see below.
 *
 *   3. The header: a dithered ASCII field with a swirl, in brushed steel and
 *      Penthera blue. A setup/draw sketch on a canvas, no library. The swirl's
 *      centre follows the pointer; a click or tap sends a ripple through it; a
 *      slow chrome sheen crosses it. Characters come from a density ramp and
 *      colours from a posterised steel ramp with blue streaks, both through a
 *      4x4 Bayer matrix for the 90s dither. The field goes quiet behind the
 *      heading, so the text needs no box. It runs at 30 fps, stops
 *      when off screen or in a hidden tab, and with reduced motion draws one
 *      still frame.
 */
(() => {
  // 1. The calculator and the waitlist email
  const form = document.querySelector(".pro-form");
  if (form) {
    const MAIL = "daan@penthera.org";
    const money = (n) => `$${Math.round(n).toLocaleString("en-US")}`;
    const val = (name) => Number(form.elements[name]?.value || 0);
    const update = () => {
      for (const input of form.querySelectorAll('input[type="range"]')) {
        const out = form.querySelector(`output[for="${input.id}"]`);
        if (out) out.textContent = out.dataset.unit === "$" ? money(input.value) : `${input.value} ${out.dataset.unit}`;
      }
      const cost = form.querySelector("[data-cost]");
      const fte = form.querySelector("[data-fte]");
      if (cost) cost.textContent = money(val("hours") * val("rate"));
      if (fte) fte.textContent = (val("hours") / 160).toFixed(2);
    };
    form.addEventListener("input", update);
    update();
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const data = new FormData(form);
      const wants = data.getAll("want");
      const note = String(data.get("note") || "").trim();
      const body = [
        `I am: ${data.get("role") || ""}`,
        `I'd want: ${wants.length ? wants.join("; ") : ""}`,
        `Security now: ${val("hours")} hours a month at ${money(val("rate"))} an hour (${money(val("hours") * val("rate"))} a month)`,
        `Budget a month: ${val("budget") ? money(val("budget")) : "$0 (the free tool is enough)"}`,
        `Anything else: ${note}`,
        "",
      ].join("\n");
      location.href = `mailto:${MAIL}?subject=${encodeURIComponent("Penthera Pro waitlist")}&body=${encodeURIComponent(body)}`;
    });
  }

  // 2. The horizontal page. The row of panels is pinned (position: sticky)
  //    and slides left as the page scrolls down, so wheel, touch, keyboard
  //    and the scroll bar all work as usual. A sideways trackpad swipe scrolls
  //    the page too. Tabbing to a control or following #join scrolls to its
  //    panel. Without this script the panels stack vertically.
  const outer = document.querySelector(".pro-h[data-h]");
  if (outer && window.CSS?.supports?.("position", "sticky")) {
    const sticky = outer.querySelector(".pro-sticky");
    const track = outer.querySelector(".pro-track");
    const bar = outer.querySelector(".pro-progress span");
    const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
    let travel = 0;
    outer.classList.add("is-h");
    const layout = () => {
      travel = Math.max(0, track.scrollWidth - sticky.clientWidth);
      outer.style.height = `${travel + sticky.clientHeight}px`;
      move();
    };
    const move = () => {
      const x = Math.min(travel, Math.max(0, window.scrollY - outer.offsetTop));
      track.style.transform = `translate3d(${-x}px, 0, 0)`;
      sticky.scrollLeft = 0; // focus can scroll a clipped box; keep the transform in charge
      if (bar) bar.style.transform = `scaleX(${travel ? x / travel : 0})`;
      // At the end of the row the full bar would read as a rule above the footer: it fades out.
      if (bar) bar.parentElement.toggleAttribute("data-done", travel > 0 && x >= travel - 1);
    };
    const panelY = (el) => outer.offsetTop + Math.min(travel, el.closest(".pro-panel")?.offsetLeft ?? 0);
    window.addEventListener("scroll", move, { passive: true });
    window.addEventListener("resize", layout);
    window.addEventListener("wheel", (e) => {
      if (Math.abs(e.deltaX) > Math.abs(e.deltaY) && outer.contains(e.target)) window.scrollBy(0, e.deltaX);
    }, { passive: true });
    outer.addEventListener("focusin", (e) => {
      const panel = e.target.closest(".pro-panel");
      if (!panel) return;
      const x = Math.min(travel, Math.max(0, window.scrollY - outer.offsetTop));
      const inView = panel.offsetLeft >= x - 1 && panel.offsetLeft + panel.offsetWidth <= x + sticky.clientWidth + 1;
      if (!inView) window.scrollTo({ top: panelY(panel), behavior: "auto" });
    });
    document.addEventListener("click", (e) => {
      const a = e.target.closest('a[href^="#"]');
      const target = a && document.getElementById(a.getAttribute("href").slice(1));
      if (!target || !outer.contains(target)) return;
      e.preventDefault();
      window.scrollTo({ top: panelY(target), behavior: reduceMotion ? "auto" : "smooth" });
      history.replaceState(null, "", a.getAttribute("href"));
    });
    layout();
    if (location.hash) {
      const target = document.getElementById(location.hash.slice(1));
      if (target && outer.contains(target)) window.scrollTo(0, panelY(target));
    }
    if (document.fonts) document.fonts.ready.then(layout);
  }

  // 3. The header sketch
  const canvas = document.querySelector(".pro-canvas");
  if (!canvas || !canvas.getContext) return;
  const hero = canvas.parentElement;
  const ctx = canvas.getContext("2d");
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const RAMP = " .:-=+*#%@";
  // Brushed steel, dark to chrome, then Penthera blue, deep to bright.
  const STEEL = ["#3a404b", "#59616e", "#7f8896", "#a9b1bd", "#d3d9e0", "#f4f6f8"];
  const BLUE = ["#0000b8", "#0000ed", "#3d3dff", "#8a8aff"];
  const PALETTE = [...STEEL, ...BLUE];
  const BAYER = [0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5].map((n) => (n + 0.5) / 16 - 0.5);
  const FONT_PX = 14;

  let W = 0, H = 0, cw = 8.4, ch = FONT_PX, cols = 0, rows = 0, dpr = 1;
  const pointer = { x: 0.68, y: 0.42, tx: 0.68, ty: 0.42, inside: false };
  const ripples = [];
  let quiet = null; // the heading's box, in 0..1 of the band, padded
  let t0 = performance.now();
  let last = 0, running = false, visible = true, raf = 0;

  function setup() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = hero.clientWidth;
    H = hero.clientHeight;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.font = `${FONT_PX}px "Departure Mono", ui-monospace, monospace`;
    ctx.textBaseline = "top";
    cw = ctx.measureText("M").width || 8.4;
    ch = FONT_PX + 2;
    cols = Math.ceil(W / cw);
    rows = Math.ceil(H / ch);
    const text = hero.querySelector(".pro-hero-text");
    const hr = hero.getBoundingClientRect();
    const box = [...text.children].map((el) => el.getBoundingClientRect()).reduce((a, r) => (r.width ? {
      l: Math.min(a.l, r.left), t: Math.min(a.t, r.top), r: Math.max(a.r, r.left + r.width), b: Math.max(a.b, r.bottom),
    } : a), { l: Infinity, t: Infinity, r: -Infinity, b: -Infinity });
    quiet = Number.isFinite(box.l)
      ? { l: (box.l - hr.left - 24) / W, t: (box.t - hr.top - 20) / H, r: (box.r - hr.left + 24) / W, b: (box.b - hr.top + 20) / H }
      : null;
  }

  /** 1 outside the heading's box, falling to 0.12 inside it, with soft edges. */
  function calm(nx, ny) {
    if (!quiet) return 1;
    const dx = Math.max(quiet.l - nx, 0, nx - quiet.r) * W;
    const dy = Math.max(quiet.t - ny, 0, ny - quiet.b) * H;
    const d = Math.hypot(dx, dy);
    return 0.12 + 0.88 * Math.min(1, d / 48);
  }

  function field(nx, ny, t) {
    const aspect = W / H;
    const dx = (nx - pointer.x) * aspect, dy = ny - pointer.y;
    const r = Math.hypot(dx, dy);
    const a = Math.atan2(dy, dx);
    const swirl = Math.sin(10 * r - t * 1.4 + 3 * Math.sin(a * 3 + t * 0.5 + r * 4));
    const plasma = Math.sin(nx * 7 + t * 0.9) * Math.cos(ny * 5 - t * 0.6);
    let v = 0.58 + 0.36 * swirl + 0.16 * plasma;
    for (const p of ripples) {
      const age = t - p.t;
      const d = Math.hypot((nx - p.x) * aspect, ny - p.y) - age * 0.55;
      v += 0.7 * Math.exp(-d * d * 90) * Math.exp(-age * 1.1);
    }
    // A chrome sheen sweeping across every few seconds.
    const sweep = ((t * 0.12) % 1.6) - 0.3;
    const sheen = Math.exp(-((nx * 0.8 + ny * 0.5 - sweep) ** 2) * 60);
    // Fade into the band below, and go quiet behind the heading.
    v *= Math.min(1, (1 - ny) * 4) * calm(nx, ny);
    const band = (a / (2 * Math.PI) + 0.5 + r * 0.9 - t * 0.08) % 1;
    return { v: v + sheen * 0.25 * calm(nx, ny), sheen, blue: (band < 0 ? band + 1 : band) < 0.3 };
  }

  function draw(now) {
    const t = (now - t0) / 1000;
    // Ease the swirl towards the pointer, or let it wander on its own.
    if (!pointer.inside) {
      pointer.tx = 0.62 + 0.22 * Math.sin(t * 0.21);
      pointer.ty = 0.45 + 0.18 * Math.sin(t * 0.33 + 1);
    }
    pointer.x += (pointer.tx - pointer.x) * 0.06;
    pointer.y += (pointer.ty - pointer.y) * 0.06;
    while (ripples.length && t - ripples[0].t > 4) ripples.shift();

    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, W, H);
    const buckets = PALETTE.map(() => []);
    for (let j = 0; j < rows; j++) {
      const ny = (j + 0.5) / rows;
      for (let i = 0; i < cols; i++) {
        const b = BAYER[(j & 3) * 4 + (i & 3)];
        const { v, sheen, blue } = field((i + 0.5) / cols, ny, t);
        const lit = Math.max(0, Math.min(1, v + b * 0.22));
        const level = Math.round(lit * (RAMP.length - 1));
        if (level === 0) continue;
        // Steel by brightness, lifted by the sheen; blue in the swirl's blue arm.
        const tone = Math.max(0, Math.min(0.999, lit * 1.05 + sheen * 0.6 + b * 0.15));
        const c = blue ? STEEL.length + Math.floor(tone * BLUE.length) : Math.floor(tone * STEEL.length);
        buckets[c].push(i, j, level);
      }
    }
    for (let c = 0; c < PALETTE.length; c++) {
      const list = buckets[c];
      if (!list.length) continue;
      ctx.fillStyle = PALETTE[c];
      for (let k = 0; k < list.length; k += 3) ctx.fillText(RAMP[list[k + 2]], list[k] * cw, list[k + 1] * ch);
    }
  }

  function loop(now) {
    raf = requestAnimationFrame(loop);
    if (now - last < 33) return; // 30 fps is plenty for a dither
    last = now;
    draw(now);
  }
  const start = () => { if (!running && visible && !reduce) { running = true; raf = requestAnimationFrame(loop); } };
  const stop = () => { running = false; cancelAnimationFrame(raf); };

  function locate(e) {
    const r = hero.getBoundingClientRect();
    return { x: (e.clientX - r.left) / r.width, y: (e.clientY - r.top) / r.height };
  }
  hero.addEventListener("pointermove", (e) => { const p = locate(e); pointer.tx = p.x; pointer.ty = p.y; pointer.inside = true; });
  hero.addEventListener("pointerleave", () => { pointer.inside = false; });
  hero.addEventListener("pointerdown", (e) => {
    const p = locate(e);
    ripples.push({ x: p.x, y: p.y, t: (performance.now() - t0) / 1000 });
    if (reduce) draw(performance.now());
  });

  new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; visible ? start() : stop(); }).observe(hero);
  document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));
  let resizeT;
  window.addEventListener("resize", () => { clearTimeout(resizeT); resizeT = setTimeout(() => { setup(); draw(performance.now()); }, 120); });

  const begin = () => {
    setup();
    hero.classList.add("is-live");
    if (reduce) { t0 = performance.now() - 8000; draw(performance.now()); } else start();
  };
  (document.fonts ? document.fonts.load(`${FONT_PX}px "Departure Mono"`).catch(() => {}) : Promise.resolve()).then(begin);
})();
