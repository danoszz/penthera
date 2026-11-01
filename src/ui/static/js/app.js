// penthera ui: a menu bar over three tiled windows. Projects on the left, the
// selected project (five tabs) or run in the centre, the inspector on the
// right. Runs start from the New scan dialog; every action is also in a menu.
import { h, clear, announce, metalLight } from "./dom.js";
import { api, signIn } from "./api.js";
import { patternDefs, riskLevel } from "./charts.js";
import { state, set, on, TABS, countsInView, currentProject } from "./state.js";
import { renderMenubar, closeMenus } from "./menubar.js";
import { renderLeft } from "./left.js";
import { renderCenter, refreshList, moveFinding, answerPending } from "./center.js";
import { renderRight } from "./right.js";
import { newScan, about } from "./dialog.js";
import { setup } from "./onboarding.js";
import { ERR } from "./copy.js";

const THEME_KEY = "penthera-ui-theme";
const UX_KEY = "penthera-ui-mode";
const PANELS_KEY = "penthera-ui-panels";
const app = document.getElementById("app");
const menubar = document.getElementById("menubar");
const left = document.getElementById("left");
const center = document.getElementById("center");
const right = document.getElementById("right");
const scrim = document.getElementById("scrim");

// ── Theme: one system, [data-theme] on <html>; theme.js set it before paint ──
const theme = {
  get: () => (document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark"),
  set(t) {
    document.documentElement.setAttribute("data-theme", t);
    try { localStorage.setItem(THEME_KEY, t); } catch { /* storage off: this page only */ }
    announce(`${t === "light" ? "Light" : "Dark"} theme`);
  },
};

// ── Side windows: [ and ] toggle; drawers below 1180px / 760px ──
const narrowRight = () => window.matchMedia("(max-width: 1180px)").matches;
const narrowLeft = () => window.matchMedia("(max-width: 760px)").matches;
function savedPanels() {
  try { return JSON.parse(localStorage.getItem(PANELS_KEY) || "null"); } catch { return null; }
}
const panels = { left: true, right: true, ...(savedPanels() || {}) };
function applyPanels() {
  app.classList.toggle("no-left", !panels.left);
  app.classList.toggle("no-right", !panels.right);
  scrim.hidden = !((panels.right && narrowRight()) || (panels.left && narrowLeft()));
  if (!narrowRight()) {
    try { localStorage.setItem(PANELS_KEY, JSON.stringify(panels)); } catch { /* per-viewer convenience only */ }
  }
  if (state.meta) renderMenubar(menubar, ctx);
}
function toggleLeft() { panels.left = !panels.left; applyPanels(); }
function toggleRight() { panels.right = !panels.right; applyPanels(); }
scrim.addEventListener("click", () => {
  if (narrowLeft()) panels.left = false;
  if (narrowRight()) panels.right = false;
  applyPanels();
});

// ── Context the renderers share ──
const ctx = {
  theme,
  panels,
  toggleLeft,
  toggleRight,
  refresh,
  setTheme(t) { theme.set(t); renderMenubar(menubar, ctx); if (state.right === "settings") renderRight(right, ctx); },
  newScan(kind, project) { closeMenus(); newScan(ctx, { kind, project }); },
  about() { about(); },
  setup() { closeMenus(); setup(ctx); },
  setUx(ux) {
    try { localStorage.setItem(UX_KEY, ux); } catch { /* this page only */ }
    api.post("/api/settings", { ux }).catch(() => { /* kept for this page */ });
    set({ ux, tab: "findings", filter: null });
    announce(`${ux === "simple" ? "Simple" : "Advanced"} mode`);
  },
  /** Setup closed: keep what was chosen, Simple if nothing was. */
  finishSetup(ux) { ctx.setUx(ux || "simple"); },
  /** Leave check and fix: back to the run's project, or to all projects. */
  back() {
    const key = currentProject();
    set({ sel: key ? { kind: "project", key } : { kind: "all", key: null } });
  },
  openTab(tab, project) {
    const patch = { tab };
    if (project) patch.sel = { kind: "project", key: project };
    else if (state.sel.kind !== "all" && state.sel.kind !== "project") patch.sel = { kind: "all", key: null };
    set(patch);
  },
  openFinding(f) {
    set({ finding: { id: f.id, project: f.project }, right: "finding" });
    if (!panels.right) { panels.right = true; applyPanels(); }
    for (const b of document.querySelectorAll("#findings-list .row")) {
      b.setAttribute("aria-current", String(b.dataset.id === f.id && b.dataset.project === f.project));
    }
  },
};

async function refresh() {
  const [overview, findings, runs] = await Promise.all([api.get("/api/overview"), api.get("/api/findings"), api.get("/api/runs")]);
  const live = runs.live.find((r) => r.status === "running" && r.pending);
  set({ overview, findings: findings.findings, giants: findings.giants || [], runs, ...(live && !state.pending ? { pending: { index: live.pending.index, total: live.pending.total } } : {}) });
}

// ── Redraw on state changes, one window at a time ──
on((patch) => {
  const keys = Object.keys(patch);
  if (keys.includes("query") && keys.length === 1) { refreshList(ctx); return; }
  if (keys.some((k) => ["overview", "runs", "sel", "meta", "right", "tab", "pending", "ux"].includes(k))) renderMenubar(menubar, ctx);
  if (keys.some((k) => ["overview", "runs", "sel", "meta"].includes(k))) renderLeft(left, ctx);
  if (keys.some((k) => ["overview", "sel"].includes(k))) app.dataset.risk = String(riskLevel(countsInView()));
  // Check and fix: a run takes the whole desktop, with Back at its top left.
  if (keys.includes("sel")) app.toggleAttribute("data-fix", state.sel.kind === "run" || state.sel.kind === "past");
  if (keys.some((k) => ["overview", "findings", "sel", "tab", "filter", "source", "ux"].includes(k))) {
    // A live transcript is rebuilt only when the selection changes, never on a data refresh.
    if (!(state.sel.kind === "run" && !keys.includes("sel"))) renderCenter(center, ctx);
    if (keys.includes("sel") && narrowLeft() && panels.left) { panels.left = false; applyPanels(); }
  }
  if (keys.some((k) => ["sel", "right", "finding", "ux"].includes(k)) || (keys.includes("overview") && state.right === "none")) {
    if (state.right !== "none" && !panels.right) { panels.right = true; applyPanels(); }
    renderRight(right, ctx);
  }
});

// ── Keyboard ──
function isTyping(e) {
  const t = e.target;
  return t instanceof HTMLElement && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
}
document.addEventListener("pointerdown", (e) => { if (!menubar.contains(e.target)) closeMenus(); });
document.addEventListener("keydown", (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  if (document.querySelector("dialog[open]")) return; // the dialog owns the keyboard
  if (e.key === "Escape") {
    if (closeMenus()) return;
    const q = document.getElementById("q");
    if (document.activeElement === q && q.value) { q.value = ""; set({ query: "" }); return; }
    if (state.right !== "none") { set({ right: "none", finding: null }); return; }
    if (app.hasAttribute("data-fix")) { ctx.back(); return; }
    if ((narrowRight() && panels.right) || (narrowLeft() && panels.left)) scrim.click();
    return;
  }
  if (isTyping(e) || menubar.contains(e.target)) return;
  if (answerPending(e.key)) { e.preventDefault(); return; }
  const tab = state.ux === "advanced" && TABS.find((t) => t.key === e.key);
  if (tab) { e.preventDefault(); ctx.openTab(tab.id); return; }
  if (e.key === "n") { e.preventDefault(); ctx.newScan(); return; }
  if (e.key === "/") {
    e.preventDefault();
    if (state.tab !== "findings" || !(state.sel.kind === "all" || state.sel.kind === "project")) ctx.openTab("findings");
    document.getElementById("q")?.focus();
    return;
  }
  if (e.key === "j" || e.key === "k") { e.preventDefault(); moveFinding(e.key === "j" ? 1 : -1, ctx); return; }
  if (e.key === "[") { e.preventDefault(); toggleLeft(); return; }
  if (e.key === "]") { e.preventDefault(); toggleRight(); }
});

if (narrowLeft()) panels.left = false;
if (narrowRight()) panels.right = false;
applyPanels();

let savedUx = null;
try { savedUx = localStorage.getItem(UX_KEY); } catch { /* storage off */ }
state.ux = savedUx === "advanced" ? "advanced" : "simple";

(async function boot() {
  document.body.append(patternDefs());
  metalLight();
  try {
    // A click that reached a stopped server has no one to tell. Say it once, for good.
    addEventListener("unhandledrejection", (e) => {
      if (e.reason?.status !== 0) return;
      e.preventDefault();
      if (!document.querySelector(".server-stopped")) document.body.append(h("p", { class: "err server-stopped", role: "alert" }, ERR.stopped));
    });
    await signIn();
    state.meta = await api.get("/api/meta");
    // Every restart is a new port, so the browser's copy is gone: the data folder remembers.
    const known = state.meta.settings?.ux || savedUx;
    state.ux = known === "advanced" ? "advanced" : "simple";
    renderMenubar(menubar, ctx);
    renderRight(right, ctx);
    await refresh();
    document.title = `Penthera${state.meta.demo ? " :: demo" : ""}`;
    // First visit for this data folder, unless the wizard has just been through it.
    if (!known && !state.overview?.projects?.length) ctx.setup();
  } catch (e) {
    clear(center).append(h("div", { class: "col" },
      h("h1", {}, "Not signed in"),
      h("p", { class: "bad", role: "alert" }, e.message),
      h("p", { class: "muted" }, e.status === 401 ? ERR.session : "Run penthera ui and open the one-time link it prints. The link works once."),
    ));
  }
})();
