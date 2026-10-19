// penthera ui: hash router, keyboard shortcuts, the menu bar and window chrome.
import { h, clear, announce } from "./dom.js";
import { api } from "./api.js";
import { typeInto } from "./typer.js";
import { patternDefs } from "./charts.js";
import { SCREENS, ERR } from "./copy.js";
import * as overview from "./views/overview.js";
import * as findings from "./views/findings.js";
import * as run from "./views/run.js";
import * as history from "./views/history.js";
import * as deps from "./views/deps.js";
import * as ai from "./views/ai.js";
import * as evidence from "./views/evidence.js";
import * as settings from "./views/settings.js";

const VIEWS = { overview, findings, run, history, deps, ai, evidence, settings };
const ORDER = Object.keys(VIEWS);
const THEME_KEY = "penthera-ui-theme";

const main = document.getElementById("main");
const ctx = { api, meta: null, go, params: new URLSearchParams(), theme: { get: getTheme, set: setTheme } };
let cleanup = null;
let renderSeq = 0;

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [name, query = ""] = raw.split("?");
  const alias = name === "agent" ? "run" : name;
  return { name: VIEWS[alias] ? alias : "overview", params: new URLSearchParams(query) };
}

export function go(name, params = {}) {
  const q = new URLSearchParams(params).toString();
  const next = `#/${name}${q ? `?${q}` : ""}`;
  if (location.hash === next) render();
  else location.hash = next;
}

// ── Theme: one system, [data-theme] on <html>. theme.js set it before paint. ──
function getTheme() { return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark"; }
function setTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  try { localStorage.setItem(THEME_KEY, t); } catch { /* storage off: the choice lasts this page only */ }
  paintThemeButton();
  announce(`${t === "light" ? "Light" : "Dark"} theme`);
}
function paintThemeButton() {
  const b = document.getElementById("theme-btn");
  const t = getTheme();
  b.textContent = t === "light" ? "◑ light" : "◐ dark";
  b.setAttribute("aria-label", `Theme: ${t}. Switch to ${t === "light" ? "dark" : "light"}`);
}
document.getElementById("theme-btn").addEventListener("click", () => setTheme(getTheme() === "light" ? "dark" : "light"));
paintThemeButton();

function clock() {
  const d = new Date();
  document.getElementById("mb-clock").textContent = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}
clock();
setInterval(clock, 15_000);

async function render() {
  const seq = ++renderSeq;
  const { name, params } = parseHash();
  ctx.params = params;
  for (const a of document.querySelectorAll(".menubar nav a")) {
    if (a.dataset.view === name) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  const title = SCREENS[name].title;
  document.title = `${title} :: penthera ui`;
  document.getElementById("win-title").textContent = `penthera :: ${title.toLowerCase()}`;
  document.querySelector("#prompt .path").textContent = `~/${name}`;
  typeInto(document.getElementById("prompt-cmd"), `penthera ui --view ${name}`);

  if (cleanup) { try { cleanup(); } catch { /* view already gone */ } cleanup = null; }
  clear(main);
  const root = h("div"); // no enter animation: screens switch from the keyboard (1-8)
  main.append(root);
  try {
    const c = await VIEWS[name].render(root, ctx);
    if (seq !== renderSeq) { c?.(); return; }
    cleanup = c || null;
  } catch (e) {
    if (seq !== renderSeq) return;
    clear(root).append(
      h("h1", {}, title),
      h("p", { class: "error", role: "alert" }, e.message),
      e.status === 401 ? h("p", { class: "muted" }, ERR.session) : null,
    );
  }
  announce(`${title} screen`);
}

function chrome(meta) {
  // Only real elements go into the bar: a null child would render as the text "null".
  const chips = [
    meta.demo ? h("span", { class: "chip inv", title: "Fake data seeded by --demo" }, "DEMO DATA") : null,
    h("span", { class: meta.settings.offline ? "chip on" : "chip" }, meta.settings.offline ? "offline" : "online"),
  ].filter(Boolean);
  clear(document.getElementById("mb-chips")).append(...chips);
  document.getElementById("status-bind").textContent = `v${meta.version} :: bound to ${location.host} :: no network :: no telemetry`;
}

function isTyping(e) {
  const t = e.target;
  return t instanceof HTMLElement && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
}

document.addEventListener("keydown", (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey || isTyping(e)) return;
  const n = Number(e.key);
  if (Number.isInteger(n) && n >= 1 && n <= ORDER.length) {
    e.preventDefault();
    go(ORDER[n - 1]);
    main.focus({ preventScroll: true });
  }
});

window.addEventListener("hashchange", render);

(async function boot() {
  document.body.append(patternDefs());
  try {
    ctx.meta = await api.get("/api/meta");
    chrome(ctx.meta);
  } catch (e) {
    clear(main).append(
      h("h1", {}, "Not signed in"),
      h("p", { class: "error", role: "alert" }, e.message),
      h("p", { class: "muted" }, "Run penthera ui and open the one-time link it prints. The link works once."),
    );
    return;
  }
  ctx.refreshMeta = async () => { ctx.meta = await api.get("/api/meta"); chrome(ctx.meta); };
  render();
})();
