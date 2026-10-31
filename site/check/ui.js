/**
 * The page's script: the live check, the copy buttons and the hero loop.
 * Everything the visitor adds is rendered with textContent, never as HTML.
 */
import { COPY } from "./copy.js";
import { liveField } from "./field.js";
import { cardRows, failedChecks, handoffTitle, reportMarkdown, rowTag } from "./card.js";

const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

// ── Counting, without cookies ───────────────────────────────────────────────

// Vercel Web Analytics custom events, so we can see how many checks run and
// how many lead to an install. An event is a name and at most which button;
// never the URL or host checked, the score, or anything typed or pasted. Web
// Analytics sets no cookies (docs/privacy.md). The stub queues events until
// the analytics script loads; counting never breaks the page.
window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };
function count(name, data) {
  try { window.va("event", data ? { name, data } : { name }); } catch { /* counting is never worth an error */ }
}

// ── Copy buttons ────────────────────────────────────────────────────────────

function copyButtons() {
  for (const btn of document.querySelectorAll("[data-copy], [data-copy-from]")) {
    // A .cmd carries its own text and states; a prompt's button copies the <pre> beside it.
    const root = btn.closest("[data-copy-root]");
    const source = btn.dataset.copy != null ? btn.querySelector("code") || btn : $("[data-copy-text]", root);
    const status = $("[data-copy-status]", btn);
    // A button with an icon swaps only its label's text.
    const labelEl = $("[data-copy-label]", btn) || btn;
    const label = labelEl.textContent;
    let timer;
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(btn.dataset.copy ?? source.textContent);
      } catch {
        // No clipboard permission: select the text so the visitor can copy it.
        getSelection().selectAllChildren(source);
        return;
      }
      btn.dataset.state = "copied";
      if (btn.dataset.track) count("copy", { what: btn.dataset.track });
      if (status) status.textContent = `, ${COPY.copied.toLowerCase()}`;
      else labelEl.textContent = COPY.copied;
      clearTimeout(timer);
      timer = setTimeout(() => {
        delete btn.dataset.state;
        if (status) status.textContent = ", copy to clipboard";
        else labelEl.textContent = label;
      }, 1600);
    });
  }
}

// ── Hero loop: plays only when motion is welcome, and only on screen ────────

function heroLoop() {
  const v = $("[data-loop]");
  if (!v) return;
  const still = matchMedia("(prefers-reduced-motion: reduce)");
  let onScreen = true;
  const apply = () => {
    if (still.matches) { v.pause(); v.controls = true; return; }
    v.controls = false;
    // Off screen it waits, so the decoder does not run for nobody.
    if (!onScreen) { v.pause(); return; }
    v.play().catch(() => { v.controls = true; });
  };
  new IntersectionObserver(([e]) => { onScreen = e.isIntersecting; apply(); }).observe(v);
  still.addEventListener("change", apply);
  apply();
}

// ── The live check ──────────────────────────────────────────────────────────

// POST /api/check (api/check.mjs) and render its report: the score as a
// 10 × 10 grid of pixels, the categories, every check with its evidence, fix
// and verify command, and a prompt for your coding agent built from the
// checks you pick. The report stays in this tab; nothing is stored.

const API = "/api/check";
const REPO_URL = "https://github.com/danoszz/penthera";

async function callCheck(body) {
  const failed = { message: "The check could not run.", hint: "Try again, or run npx penthera on your own machine." };
  let res;
  try { res = await fetch(API, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...body, consent: true }) }); } catch { throw failed; }
  let data;
  try { data = await res.json(); } catch { data = null; }
  if (!res.ok || !data) throw (data?.error || failed);
  return data;
}

function pixels(score) {
  const grid = el("div", "meter");
  grid.setAttribute("role", "img");
  grid.setAttribute("aria-label", `${score} out of 100`);
  for (let i = 0; i < 100; i++) grid.append(el("i", i < score ? "on" : null));
  return grid;
}

function findingItem(c) {
  const li = el("li", `finding sev-${c.severity}${c.passed ? " ok" : ""}`);
  const d = el("details");
  const s = el("summary");
  s.append(el("span", "finding-mark", c.passed ? "ok" : c.severity), el("span", "finding-title", c.title));
  d.append(s);
  const body = el("div", "finding-body");
  if (c.evidence) { const p = el("p", "finding-ev"); textWithCode(p, `Evidence: ${c.evidence}`); body.append(p); }
  if (!c.passed && c.fix) body.append(el("p", "finding-fix", c.fix));
  if (!c.passed && c.verify) body.append(el("pre", "finding-verify", c.verify));
  if (body.childNodes.length) d.append(body);
  li.append(d);
  return li;
}

function promptFor(report, picked) {
  const lines = [
    `Improve the security of ${report.url}.`,
    "",
    `Current Penthera quick check: ${report.score}/100 (${report.scope})`,
    "",
    "Fix these in priority order:",
    "",
  ];
  picked.forEach((c, i) => {
    lines.push(`${i + 1}. ${c.title} (${c.severity})`);
    if (c.evidence) lines.push(`Evidence: ${c.evidence}`);
    lines.push(`Fix: ${c.fix}`);
    if (c.verify) lines.push(`Verify: \`${c.verify}\``);
    lines.push("");
  });
  lines.push(
    "Requirements:",
    "- Inspect the codebase and the hosting config (vercel.json, netlify.toml, nginx, middleware, CDN settings) before changing files.",
    "- Change only what each fix needs and keep the site working.",
    "- After deploying, run each verify command and check the result.",
    `- Then run \`npx penthera ${report.url}\` for the full scan and \`npx penthera --repo .\` for the code.`,
  );
  return lines.join("\n");
}

function promptDialog(report) {
  const failed = failedChecks(report);
  const dlg = el("dialog", "prompt-dialog");
  const form = el("form");
  form.method = "dialog";
  form.append(el("h3", null, "What should the prompt cover?"));
  const tally = el("p", "prompt-count");
  const presets = el("div", "prompt-presets");
  const list = el("ul", "prompt-list");
  const boxes = failed.map((c) => {
    const li = el("li");
    const label = el("label");
    const box = el("input");
    box.type = "checkbox";
    box.checked = c.severity === "high" || c.severity === "medium";
    label.append(box, el("span", "prompt-t", c.title), el("span", "prompt-s", `${CATEGORY[c.category] || c.category} · ${c.severity}`));
    li.append(label);
    list.append(li);
    return [box, c];
  });
  const copy = el("button", "btn", "");
  copy.type = "button";
  copy.dataset.variant = "default";
  const sync = () => {
    const n = boxes.filter(([b]) => b.checked).length;
    tally.textContent = `${failed.length} findings · ${n} selected`;
    copy.textContent = `Copy prompt (${n})`;
    copy.disabled = n === 0;
  };
  for (const [label, pick] of [["Recommended", (c) => c.severity === "high" || c.severity === "medium"], ["All", () => true], ["None", () => false]]) {
    const b = el("button", "btn btn-sm btn-white", label);
    b.type = "button";
    b.addEventListener("click", () => { for (const [box, c] of boxes) box.checked = pick(c); sync(); });
    presets.append(b);
  }
  list.addEventListener("change", sync);
  // Enter on a checkbox would submit the form, and Cancel is its only submit button.
  list.addEventListener("keydown", (e) => { if (e.key === "Enter") e.preventDefault(); });
  const cancel = el("button", "btn btn-white", "Cancel");
  cancel.value = "cancel";
  copy.addEventListener("click", async () => {
    const text = promptFor(report, boxes.filter(([b]) => b.checked).map(([, c]) => c));
    try { await navigator.clipboard.writeText(text); copy.textContent = "Copied. Paste it into your agent."; count("copy", { what: "fix-prompt" }); } catch { copy.textContent = "Copy failed"; }
    setTimeout(() => dlg.close(), 1600);
  });
  const actions = el("div", "prompt-actions");
  actions.append(cancel, copy);
  form.append(tally, presets, list, actions);
  dlg.append(form);
  dlg.addEventListener("close", () => dlg.remove());
  sync();
  return dlg;
}

const CATEGORY = {};

// ── The result, where the example was ──────────────────────────────────────

// The report replaces the poster in the same grid: the hand-off on the left
// (Prompt to fix, the full scan, the code scan), your result card on the
// right, where the example card stood. The full report folds out below.

const svg = (cls, box, d) => {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("viewBox", box);
  s.setAttribute("aria-hidden", "true");
  if (cls) s.setAttribute("class", cls);
  const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
  p.setAttribute("d", d);
  s.append(p);
  return s;
};

function starLink() {
  const a = el("a", "ghost");
  a.href = REPO_URL;
  a.append(svg(null, "0 0 9 9", "M4 0h1v2h1v1h3v1H8v1H7v1h1v3H7V8H6V7H3v1H2v1H1V6h1V5H1V4H0V3h3V2h1z"), document.createTextNode("Star on GitHub"));
  a.addEventListener("click", () => count("link", { to: "github-star-result" }));
  return a;
}

// A command to copy; onCopy counts which one, by a fixed label.
function copyCmd(cmd, cls, onCopy) {
  const b = el("button", `cmd${cls ? ` ${cls}` : ""}`);
  b.type = "button";
  const act = el("span", "cmd-act", "Copy");
  b.append(el("span", "cmd-prompt", "$"), el("code", null, cmd), act);
  b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(cmd); act.textContent = "Copied"; onCopy(); } catch { getSelection().selectAllChildren(b.querySelector("code")); }
  });
  return b;
}

function step(n, title, note, actions, cls) {
  const li = el("li", cls);
  const num = el("span", "handoff-n", n);
  num.setAttribute("aria-hidden", "true");
  const t = el("span", "handoff-t", title);
  t.append(el("small", null, note));
  const a = el("span", "handoff-a");
  a.append(...actions);
  li.append(num, t, a);
  return li;
}

// The next steps, the same for every result: a clean one gets them too. On
// a phone, where npx can't run, one step: star it and finish on a laptop.
function handoff(url, fixes, openPrompt) {
  const ol = el("ol", "handoff");
  let n = 1;
  if (fixes) {
    const b = el("button", "btn glow", `Prompt to fix (${fixes})`);
    b.type = "button";
    b.dataset.variant = "default";
    b.addEventListener("click", openPrompt);
    ol.append(step(String(n++), "Copy the prompt into Claude Code, Cursor or Codex", "Evidence, fix and a verify command for each finding.", [b], "hide-m"));
  }
  ol.append(step(String(n++), "Run the full scan on your own machine", "Exposed files, debug pages, API specs. Never from penthera.org.",
    [copyCmd(`npx penthera ${url}`, "steel", () => count("copy", { what: "full-scan" }))], "hide-m"));
  ol.append(step(String(n++), "Scan the code behind it", "Secrets and API routes in your code. It runs offline.",
    [copyCmd("npx penthera --repo .", null, () => count("copy", { what: "repo-result" })), starLink()], "hide-m"));
  ol.append(step("→", "The full scan and your code run on your laptop", "Star it now, find it there later.", [starLink()], "only-m"));
  return ol;
}

function kicker(host, state) {
  const k = el("div", "report-kick");
  const back = el("button", "report-back", "Back");
  back.type = "button";
  back.setAttribute("aria-label", "Back to the start");
  back.addEventListener("click", () => leaveFixMode());
  const what = el("p");
  what.append(document.createTextNode(host), el("span", null, ` · ${state} · passive`));
  k.append(back, what);
  return k;
}

function cardShell(host, rescan) {
  const card = el("section", "card");
  card.setAttribute("aria-label", "Your result");
  const top = el("div", "card-top");
  top.append(el("span", "card-host", host));
  if (rescan) {
    const again = el("button", "btn btn-white btn-sm", "Check again");
    again.type = "button";
    again.addEventListener("click", rescan);
    top.append(again);
  }
  card.append(top);
  return card;
}

function resultCard(report, rescan, openPrompt) {
  const card = cardShell(new URL(report.url).host, rescan);
  const fixes = failedChecks(report).length;
  const score = el("div", "card-score");
  const n = el("p", "score-n", String(report.score));
  n.append(el("span", null, "/100"));
  score.append(pixels(report.score), n);
  const rows = el("ul", "card-rows");
  for (const c of cardRows(report)) {
    const li = el("li", c.passed ? "ok" : null);
    li.append(el("span", "card-tag", rowTag(c)), document.createTextNode(c.title));
    rows.append(li);
  }
  card.append(el("p", "card-verdict", report.verdict), score, rows);
  if (fixes) {
    const b = el("button", "card-prompt", `Prompt to fix (${fixes})`);
    b.type = "button";
    b.addEventListener("click", openPrompt);
    card.append(b);
  } else {
    card.append(el("p", "card-clean", "The full scan on your own machine goes further."));
  }
  const more = el("div", "card-more");
  const a = el("a", null, `All ${report.checks.length} checks, with evidence`);
  a.href = "#report-detail";
  more.append(a, el("span", null, "nothing stored"));
  card.append(more);
  return card;
}

// The last thing in a report: something to do with it. The fix prompt, the
// report as a file, and the full scan. A phone can't run npx, so it gets the
// file and the star.
function reportNext(report) {
  const fixes = failedChecks(report);
  const box = el("section", "report-next");
  box.setAttribute("aria-label", "What to do next");
  box.append(el("h3", null, fixes.length ? "Fix it now, or go deeper." : "Keep it, or go deeper."));
  const acts = el("div", "report-next-acts");
  if (fixes.length) {
    const b = el("button", "btn glow", `Copy fix prompt (${fixes.length})`);
    b.type = "button";
    b.dataset.variant = "default";
    b.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(promptFor(report, fixes)); b.textContent = "Copied. Paste it into your agent."; count("copy", { what: "fix-prompt-end" }); } catch { b.textContent = "Copy failed"; }
    });
    acts.append(b);
  }
  const dl = el("button", `btn${fixes.length ? " btn-white" : ""}`, "Download report");
  dl.type = "button";
  if (!fixes.length) dl.dataset.variant = "default";
  dl.addEventListener("click", () => {
    const a = el("a");
    a.href = URL.createObjectURL(new Blob([reportMarkdown(report)], { type: "text/markdown" }));
    a.download = `penthera-${new URL(report.url).hostname.replace(/[^a-z0-9.-]/gi, "")}.md`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    count("link", { to: "download-report" });
  });
  acts.append(dl, copyCmd(`npx penthera ${report.url}`, "report-next-scan", () => count("copy", { what: "full-scan-end" })), starLink());
  box.append(acts, el("p", "report-next-note", "The report stays in this tab. The file is made here, and nothing is stored."));
  return box;
}

// Every check with its evidence, fix and verify command, below the fold.
function reportDetail(report) {
  const wrap = el("div", "report-detail");
  wrap.id = "report-detail";
  wrap.append(el("h3", null, "Every check, with evidence"));
  const cats = el("ul", "report-cats");
  for (const c of report.categories) {
    const li = el("li", c.passed === c.total ? "ok" : null);
    li.append(el("span", null, c.label), el("span", "cat-n", `${c.passed} / ${c.total} passed`));
    cats.append(li);
  }
  wrap.append(cats);
  const failed = failedChecks(report);
  if (failed.length) {
    const list = el("ol", "report-list");
    failed.forEach((c) => list.append(findingItem(c)));
    wrap.append(list);
  }
  const passed = report.checks.filter((c) => c.passed);
  if (passed.length) {
    const fold = el("details", "report-passed");
    fold.append(el("summary", null, `${passed.length} checks passed`));
    const okList = el("ol", "report-list");
    passed.forEach((c) => okList.append(findingItem(c)));
    fold.append(okList);
    wrap.append(fold);
  }
  wrap.append(el("p", "report-scope", report.scope), reportNext(report));
  return wrap;
}

// One layout for every state: the left column and a card in the example's place.
function layout(box, left, card, below) {
  const grid = el("div", "report-grid");
  const col = el("div", "report-left");
  col.append(...left);
  grid.append(col, card);
  box.replaceChildren(grid, ...(below ? [below] : []));
  box.hidden = false;
}

function title(text) {
  const h = el("h2", "handoff-title", text);
  h.tabIndex = -1;
  return h;
}

function renderReport(box, report, rescan) {
  for (const c of report.categories) CATEGORY[c.id] = c.label;
  const openPrompt = () => { const d = promptDialog(report); document.body.append(d); d.showModal(); };
  const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const h = title(handoffTitle(report));
  layout(box, [kicker(new URL(report.url).host, `checked ${time}`), h, handoff(report.url, failedChecks(report).length, openPrompt)],
    resultCard(report, rescan, openPrompt), reportDetail(report));
  h.focus({ preventScroll: true });
}

function renderBusy(box, host) {
  const card = cardShell(host);
  card.append(el("p", "card-verdict", "Checking"), el("p", "report-busy", "The page, its headers, its scripts and DNS…"));
  layout(box, [kicker(host, "checking"), title(`Checking ${host}.`)], card);
}

function renderError(box, host, url, e, rescan) {
  const card = cardShell(host, rescan);
  card.append(el("p", "card-verdict", "No report"), el("p", "report-error", `${e.message} ${e.hint || ""}`));
  const h = title("No report this time.");
  layout(box, [kicker(host, "not checked"), h, handoff(url, 0)], card);
  h.focus({ preventScroll: true });
}

// ── Consent before every first check of a site ─────────────────────────────

// A heavy-blur modal with the terms in plain words, then slide to scan. The
// slider is a real range input, so it works with a keyboard and a screen
// reader; it only counts when it reaches the end.
const consented = new Set();

function askConsent(host) {
  if (consented.has(host)) return Promise.resolve(true);
  return new Promise((resolve) => {
    const dlg = el("dialog", "consent");
    const form = el("form");
    form.method = "dialog";
    form.append(el("p", "consent-eyebrow", "Before you check"), el("h3", null, host));
    const ul = el("ul", "consent-list");
    for (const t of [
      "Only check a site you own, or one you have written permission to test.",
      "This check is passive: it loads what one browser visit loads. It sends no attacks and guesses no paths.",
      "It is research-backed and educational. A good score is not a guarantee and not a penetration test.",
      "Zero abuse: checks of sites that aren't yours are not welcome here, and patterns of abuse are blocked.",
      "Nothing about you or the site is stored. Deeper testing runs only on your own machine, under your responsibility.",
    ]) ul.append(el("li", null, t));
    const terms = el("p", "consent-terms");
    terms.append(document.createTextNode("By sliding you confirm this is your site or you are authorized to test it, and you accept the "));
    const a = el("a", null, "terms");
    a.href = "/terms";
    a.target = "_blank";
    terms.append(a, document.createTextNode("."));
    const slide = el("div", "slide");
    const range = el("input");
    range.type = "range";
    range.min = "0";
    range.max = "100";
    range.value = "0";
    range.step = "5";
    range.setAttribute("aria-label", `Slide to scan ${host}`);
    const label = el("span", "slide-label", "slide to scan");
    label.setAttribute("aria-hidden", "true");
    slide.append(label, range);
    const keys = el("p", "consent-keys", "With a keyboard, press End on the slider.");
    const cancel = el("button", "btn consent-cancel", "Not my site");
    cancel.type = "button";
    cancel.addEventListener("click", () => finish(false));
    form.append(ul, terms, slide, keys, cancel);
    dlg.append(form);
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      if (ok) consented.add(host);
      dlg.close();
      dlg.remove();
      resolve(ok);
    };
    const paint = () => slide.style.setProperty("--p", `${range.value}%`);
    range.addEventListener("input", paint);
    const release = () => {
      if (Number(range.value) >= 97) { range.value = "100"; paint(); setTimeout(() => finish(true), 160); return; }
      slide.classList.add("back");
      range.value = "0";
      paint();
      setTimeout(() => slide.classList.remove("back"), 260);
    };
    // A pointer that lets go short of the end slides back; the keyboard
    // (arrows, End) moves it in steps and counts once it reaches the end.
    let dragging = false;
    range.addEventListener("pointerdown", () => { dragging = true; });
    range.addEventListener("change", () => {
      if (dragging) { dragging = false; release(); return; }
      if (Number(range.value) >= 100) finish(true);
    });
    dlg.addEventListener("cancel", () => finish(false));
    // Enter must not answer this: a held key from the address box would skip it.
    form.addEventListener("submit", (e) => e.preventDefault());
    document.body.append(dlg);
    dlg.showModal();
    range.focus();
  });
}

// ── Fix mode ────────────────────────────────────────────────────────────────

// Once a check starts, the poster steps aside and the report takes its
// place. Entering adds a history entry, so the browser's back button leaves
// fix mode too; so does Back above the result.
let leaveFixMode = () => {};

// Say so before the consent dialog: an address the check can never reach, and
// what to run instead. The API enforces the same limits.
function notCheckable(text) {
  let u;
  try { u = new URL(/^https?:\/\//i.test(text) ? text : `https://${text}`); } catch { u = null; }
  if (!u || /\s/.test(text) || !(u.hostname.includes(".") || u.hostname === "localhost" || u.hostname.startsWith("["))) return ["That doesn't look like a web address. Try your-site.com."];
  const h = u.hostname.replace(/^\[|\]$/g, "");
  const local = h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h === "::1" || /^(127|10|0)\./.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h);
  if (!local && (!u.port || u.port === "80" || u.port === "443")) return null;
  const cmd = el("code", null, `npx penthera ${local ? u.href.replace(/^https:/, /^https:/i.test(text) ? "https:" : "http:").replace(/\/$/, "") : u.href.replace(/\/$/, "")}`);
  return [local ? "This check is for public sites. For your local app, run " : "This check only reads the standard web ports. On your own machine, run ", cmd];
}

function setupScan() {
  const form = $("[data-scan]");
  const box = $("[data-report]");
  const hero = $(".hero");
  if (!form || !box || !hero) return;
  const input = form.querySelector("input");
  const button = form.querySelector("button[type=submit]");
  const note = el("p", "scan-stop");
  note.setAttribute("role", "status");
  note.hidden = true;
  form.querySelector(".scan-row").after(note);

  const enter = () => {
    if (hero.dataset.mode !== "fix") history.pushState({ penthera: "fix" }, "", "#check");
    hero.dataset.mode = "fix";
    scrollTo({ top: 0, behavior: "instant" });
  };
  const exit = () => {
    delete hero.dataset.mode;
    box.hidden = true;
    box.replaceChildren();
    scrollTo({ top: 0, behavior: "instant" });
    input.focus({ preventScroll: true });
  };
  leaveFixMode = () => (history.state?.penthera === "fix" ? history.back() : exit());
  addEventListener("popstate", () => { if (hero.dataset.mode === "fix") exit(); });

  const run = async () => {
    const url = input.value.trim();
    if (!url) { input.focus(); return; }
    let host;
    try { host = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`).host; } catch { host = url; }
    const stop = notCheckable(url);
    note.replaceChildren(...(stop ? stop : []));
    note.hidden = !stop;
    if (stop) { input.focus(); return; }
    if (!(await askConsent(host))) { input.focus(); return; }
    button.disabled = true;
    enter();
    renderBusy(box, host);
    try {
      renderReport(box, await callCheck({ url }), run);
      count("check", { result: "report" });
    } catch (e) {
      count("check", { result: "error" });
      renderError(box, host, /^https?:\/\//i.test(url) ? url : `https://${url}`, e, run);
    } finally {
      button.disabled = false;
    }
  };
  form.addEventListener("submit", (e) => { e.preventDefault(); run(); });
}

function textWithCode(parent, text) {
  // Findings mark code with backticks; show it as <code>, as text.
  String(text).split(/(`[^`]+`)/).forEach((part) => {
    if (/^`[^`]+`$/.test(part)) parent.append(el("code", null, part.slice(1, -1)));
    else if (part) parent.append(document.createTextNode(part));
  });
}


// ── The bar wears the palette of the band beneath it ────────────────────────

function barPalette() {
  const bar = $(".bar");
  const bands = [...document.querySelectorAll(".band")];
  if (!bar || !bands.length) return;
  const under = new Set();
  const sync = () => {
    const band = bands.find((b) => under.has(b));
    if (!band) delete bar.dataset.over;
    else bar.dataset.over = band.classList.contains("band-blue") ? "blue" : band.classList.contains("band-grey") ? "grey" : "invert";
  };
  // A strip half the bar's height at the top of the viewport; rebuilt when
  // the viewport changes size, since rootMargin is fixed per observer.
  let io;
  const observe = () => {
    io?.disconnect();
    under.clear();
    io = new IntersectionObserver((entries) => {
      for (const e of entries) e.isIntersecting ? under.add(e.target) : under.delete(e.target);
      sync();
    }, { rootMargin: `0px 0px -${Math.max(0, innerHeight - bar.offsetHeight / 2)}px 0px` });
    for (const b of bands) io.observe(b);
  };
  let t;
  addEventListener("resize", () => { clearTimeout(t); t = setTimeout(observe, 150); });
  observe();
}

// ── The ticker rests off screen ─────────────────────────────────────────

function tickerRest() {
  const ticker = $(".ticker");
  if (!ticker) return;
  new IntersectionObserver(([e]) => {
    if (e.isIntersecting) delete ticker.dataset.rest;
    else ticker.dataset.rest = "";
  }).observe(ticker);
}

// ── The dock opens once the hero has gone ───────────────────────────────

// The dock itself never moves. It opens for the star and the download once the
// hero has gone, and closes when the hero comes back. Without script it stays open.
function dockOpen() {
  const rail = $(".rail[data-hero]");
  const hero = $(".hero");
  if (!rail || !hero) return;
  new IntersectionObserver(([e]) => {
    if (e.isIntersecting) rail.dataset.hero = "here";
    else rail.dataset.hero = "gone";
    // The first call only sets the state: a page opened mid-scroll doesn't animate.
    requestAnimationFrame(() => { rail.dataset.ready = ""; });
  }, { rootMargin: "-8% 0px 0px 0px" }).observe(hero);
}

// ── The bottom veil stays off the hero text and the footer ──────────────

function veilClear() {
  const veil = $(".veil");
  // The first screen, whatever is in it, and the footer.
  const targets = [$(".hero"), $(".foot")].filter(Boolean);
  if (!veil || !targets.length) return;
  const inZone = new Set();
  let io;
  const observe = () => {
    io?.disconnect();
    inZone.clear();
    const h = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--veil-h")) || 224;
    // Watch only the strip the veil covers: the bottom --veil-h of the viewport.
    io = new IntersectionObserver((entries) => {
      for (const e of entries) e.isIntersecting ? inZone.add(e.target) : inZone.delete(e.target);
      if (inZone.size) veil.dataset.off = "";
      else delete veil.dataset.off;
    }, { rootMargin: `-${Math.max(0, innerHeight - h)}px 0px 0px 0px` });
    for (const t of targets) io.observe(t);
  };
  let t;
  addEventListener("resize", () => { clearTimeout(t); t = setTimeout(observe, 150); });
  observe();
}

// ── One light for the metal plates ──────────────────────────────────────

// The plates' sheen is a light above the page. With a mouse, the pointer
// carries it: every plate gets the pointer's position in its own
// coordinates, so they all catch the same light. Off with reduced motion.
//
// Cost (2026-10-29): every write restyles and repaints a plate, so a frame
// reads every rect first and then writes, never interleaved (a read after a
// write forces a style pass per plate), and writes only to the plates the
// light can reach, plus once to a plate it just left. The sheen is a 400 px
// circle that is clear at 72%, so past REACH the plate shows none of it.
const REACH = 300;
function metalLight() {
  const fine = matchMedia("(hover: hover) and (pointer: fine)");
  const still = matchMedia("(prefers-reduced-motion: reduce)");
  if (!fine.matches || still.matches) return;
  const plates = [...document.querySelectorAll(".pillars li, .bench-stats li, .road li, .ways > li, .prompt-card, .btn-prompt, .pb-card")];
  const lit = new Map();   // plate → the "lx,ly" it was last given, while the light reaches it
  const placed = new Set(); // plates that have had the pointer's light at least once
  let x = 0, y = 0, queued = false;
  const paint = () => {
    queued = false;
    const rects = plates.map((el) => el.getBoundingClientRect());
    for (let i = 0; i < plates.length; i++) {
      const el = plates[i], r = rects[i];
      if (r.bottom < -200 || r.top > innerHeight + 200) continue;
      // Distance from the pointer to the plate's nearest edge.
      const dx = Math.max(r.left - x, 0, x - r.right), dy = Math.max(r.top - y, 0, y - r.bottom);
      const near = dx * dx + dy * dy < REACH * REACH;
      // Each plate gets the pointer's light once, which clears the resting
      // light; after that, only plates in reach or just out of it.
      if (!near && placed.has(el) && !lit.has(el)) continue;
      const v = `${Math.round(x - r.left)},${Math.round(y - r.top)}`;
      if (lit.get(el) === v) continue;
      el.style.setProperty("--lx", `${Math.round(x - r.left)}px`);
      el.style.setProperty("--ly", `${Math.round(y - r.top)}px`);
      placed.add(el);
      if (near) lit.set(el, v); else lit.delete(el);
    }
  };
  let seen = false;
  const queue = () => { if (seen && !queued) { queued = true; requestAnimationFrame(paint); } };
  addEventListener("pointermove", (e) => { x = e.clientX; y = e.clientY; seen = true; queue(); }, { passive: true });
  // Scrolling moves the plates under a still pointer.
  addEventListener("scroll", queue, { passive: true });
  document.documentElement.addEventListener("pointerleave", () => {
    for (const el of plates) { el.style.removeProperty("--lx"); el.style.removeProperty("--ly"); }
    lit.clear();
    placed.clear();
  });
}

copyButtons();
// Links marked data-track: counted by where on the page they are.
for (const a of document.querySelectorAll("a[data-track]")) a.addEventListener("click", () => count("link", { to: a.dataset.track }));
metalLight();
heroLoop();
tickerRest();
dockOpen();

// A landing page's form opens here with the address filled in. It stops at the
// button: a link should never start a check on someone's behalf.
(function prefill() {
  const site = new URLSearchParams(location.search).get("check");
  const form = $("[data-scan]");
  if (!site || !form) return;
  form.querySelector("input").value = site;
  form.querySelector("button").focus();
})();
veilClear();
liveField($(".hero .field"));
barPalette();
setupScan();
