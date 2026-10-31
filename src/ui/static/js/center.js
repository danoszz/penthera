// The centre window: the document you are looking at. A project (or all of
// them) is a header and five tabs :: Findings, Dependencies, AI tooling,
// History, Proof. A run is a transcript of tool output with inline Apply /
// Skip / Stop. Runs start from the New scan dialog, not from here.
import { h, clear, empty, sevBadge, diffBlock, announce } from "./dom.js";
import { api } from "./api.js";
import { state, set, projectOf, TABS, simple } from "./state.js";
import { createTyper } from "./typer.js";
import { stackedBar, sparkline, matrix, halftone, meter } from "./charts.js";
import { ago, duration, shortProject, plural, SEVERITIES } from "./format.js";
import { START, EMPTY, SEV_WORD, AI, FIX_MODE, verdict } from "./copy.js";
import { openWindow } from "./dialog.js";
import { depsTab, aiTab, historyTab, proofTab } from "./panels.js";

const SEV_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

// ── Stream state that outlives a redraw: the live run's typer and SSE ──
let typer = null;
let es = null;
let pending = null;
let visible = [];

export function stopStream() {
  closeApproval();
  es?.close();
  es = null;
  typer?.stop();
  typer = null;
}

export function renderCenter(el, ctx) {
  const { toggleLeft, toggleRight } = ctx;
  const search = h("input", { type: "search", id: "q", placeholder: "Search  /", "aria-label": "Search findings", value: state.query });
  search.addEventListener("input", () => { set({ query: search.value }); });
  const title = state.sel.kind === "all" ? "All projects"
    : state.sel.kind === "project" ? shortProject(state.sel.key)
      : state.sel.kind === "run" ? `Run :: ${state.sel.run?.kind || ""}` : "Fix loop run";
  const doc = state.sel.kind === "all" || state.sel.kind === "project";
  // Check and fix (a run) has no side windows to toggle: Back leads out instead.
  const toolbar = h("div", { class: "win-bar" },
    doc ? h("button", { type: "button", class: "icon", "aria-label": "Show or hide the projects window ([)", title: "Projects  [", onclick: toggleLeft }, "☰") : null,
    h("span", { class: "title" }, title),
    h("span", { class: "grow" }),
    doc && state.tab === "findings" ? search : null,
    doc ? h("button", { type: "button", class: "icon", "aria-label": "Show or hide the inspector (])", title: "Inspector  ]", onclick: toggleRight }, "◫") : null,
  );
  const stream = h("div", { class: "stream pane-body", id: "stream" });
  const col = h("div", { class: "col" });
  stream.append(col);
  clear(el).append(toolbar, stream);

  if (!doc) col.append(h("div", { class: "fix-top" },
    h("button", { type: "button", class: "back", "aria-label": FIX_MODE.backLabel, title: `${FIX_MODE.backLabel}  Esc`, onclick: ctx.back }, FIX_MODE.back),
    h("span", { class: "fix-mode" }, FIX_MODE.label)));
  if (state.sel.kind === "run") return runView(col, ctx);
  stopStream();
  if (state.sel.kind === "past") return pastRunView(col, ctx);
  return projectView(col, ctx);
}

/** Re-render only the findings list (search typing must not rebuild the toolbar). */
export function refreshList(ctx) {
  const list = document.getElementById("findings-list");
  if (list) fillFindings(list, ctx);
}

// ── Project (or all projects) ──────────────────────────────────────────

function projectView(col, ctx) {
  const o = state.overview;
  if (!o) return;
  const all = state.sel.kind === "all";
  const key = state.sel.key;
  const p = all ? null : projectOf(key);

  if (!o.projects.length && all) return startView(col, ctx);
  if (!all && !p) return notScannedView(col, key, ctx);

  const counts = all ? o.mix : p.counts;
  const open = all ? o.open : p.open;
  const fixed = all ? o.fixed : p.fixed;
  const trend = all ? combinedTrend(o.projects) : p.trend.map((t) => t.total);
  const easy = simple();
  const when = ago(all ? o.lastScans[0]?.ts : p.lastScan);
  // The report: the verdict as the headline, the score as a 10 × 10 meter,
  // and one blue action. The project and its counts sit around them.
  const mine = sorted(state.findings.filter((f) => !f.suppressed && !f.other && (all || f.project === key)));
  const v = verdict({ counts, open, top: mine[0], scanned: true, when });
  const scores = all ? o.projects.map((x) => x.score).filter(Number.isFinite) : [p.score].filter(Number.isFinite);
  const score = scores.length ? Math.min(...scores) : null;
  const fix = easy && v.top && v.level !== "clear";
  col.append(h("section", { class: ["report", "verdict", "plate", `v-${v.level}`], "aria-label": "Verdict" },
    h("div", { class: "report-main" },
      h("p", { class: "report-host" },
        h("span", { class: `grade grade-${all ? "x" : p.grade}`, title: all || p.score == null ? "" : `score ${p.score}/100` }, all ? "∑" : p.grade),
        h("span", { title: key || "" }, all ? "All projects" : shortProject(key)),
        h("span", {}, easy
          ? (all ? `${plural(o.projects.length, "project")} · last checked ${when}` : `last checked ${when}`)
          : (all ? `${plural(o.projects.length, "project")} · newest scan ${when}` : `${p.mode || "scan"} · last scan ${when} · ${plural(p.trend.length, "scan")}`))),
      h("h1", { class: "verdict-text" }, v.text),
      h("p", { class: "counts" }, h("b", {}, String(open)), easy ? " to fix · " : " open · ", h("b", {}, String(fixed)), " fixed"),
      v.top ? h("div", { class: "actions start" },
        fix ? h("button", { type: "button", class: "btn primary", onclick: () => ctx.newScan("loop", all ? null : key) }, "Fix problems for me…") : null,
        h("button", { type: "button", class: ["btn", fix ? "ink" : "primary", "first"], onclick: () => { state.focusPanel = true; ctx.openFinding(v.top); } }, easy ? "Show me the first one ▸" : `Open: ${v.top.title}`)) : null),
    h("div", { class: "report-score" },
      score == null ? null : h("div", { class: "score" }, meter(score),
        h("p", { class: "score-n" }, String(score), h("span", {}, all && scores.length > 1 ? `/100, lowest of ${scores.length}` : "/100"))),
      easy ? null : stackedBar(counts, { width: 24 }),
      easy ? null : sparkline(trend, { label: "open findings per scan" })),
  ));

  if (easy) {
    const list = h("ul", { class: "rows simple", id: "findings-list", "aria-label": "Problems to fix" });
    col.append(h("section", { class: "section" }, h("h2", {}, h("span", {}, "To fix"), h("span", { id: "findings-count" })), list));
    fillFindings(list, ctx);
    // What was fixed since the check before, folded into one line.
    const done = o.columns.fixed.filter((r) => all || r.project === key);
    if (done.length) {
      col.append(h("details", { class: "passed" }, h("summary", {}, `${plural(done.length, "problem")} fixed since the check before`),
        h("ul", { class: "mini" }, done.map((r) => h("li", {}, h("span", { class: `sw sev-${r.severity}`, "aria-hidden": "true" }), h("span", { class: "grow muted" }, `✓ ${r.title}`))))));
    }
    col.append(h("p", { class: "muted prose more" }, "Looking for dependencies, AI tooling, history or evidence for an auditor? Switch to Advanced in the Penthera menu."));
    return;
  }

  col.append(tabStrip(ctx));
  const panel = h("div", { class: "tab-panel", role: "tabpanel", id: `tab-${state.tab}`, "aria-labelledby": `tabbtn-${state.tab}` });
  col.append(panel);
  if (state.tab === "deps") return depsTab(panel);
  if (state.tab === "ai") return aiTab(panel);
  if (state.tab === "history") return historyTab(panel, all ? null : key);
  if (state.tab === "proof") return proofTab(panel, all ? null : key);

  // Since the last scan.
  const since = h("div");
  panel.append(since);
  if (!all && p.trend.length > 1) {
    api.get(`/api/history?project=${encodeURIComponent(key)}`).then((hst) => {
      if (state.sel.key !== key) return;
      since.append(h("section", { class: "section" },
        h("h2", {}, h("span", {}, "Since the last scan"), h("span", {}, `${hst.new.length} new · ${hst.fixed.length} fixed`)),
        h("div", { class: "cols2" },
          miniList(hst.new, "Nothing new."),
          miniList(hst.fixed, "Nothing fixed since the last scan.", true),
        )));
    }).catch(() => {});
  } else if (all && (o.columns.newest.length || o.columns.fixed.length)) {
    since.append(h("section", { class: "section" },
      h("h2", {}, h("span", {}, "Since the last scan"), h("span", {}, `${o.columns.newest.length} new · ${o.columns.fixed.length} fixed`)),
      h("div", { class: "cols2" }, miniList(o.columns.newest, "Nothing new."), miniList(o.columns.fixed, "Nothing fixed.", true))));
  }

  const pool = state.findings.filter((f) => !f.suppressed && !f.other && (all || f.project === key));
  panel.append(h("section", { class: "section" },
    h("h2", {}, h("span", {}, "Triage :: severity × how sure"), h("span", {}, state.filter ? h("button", { type: "button", class: "linkish", onclick: () => set({ filter: null }) }, "clear filter ×") : "pick a cell to filter")),
    matrix(pool, state.filter, (cell) => set({ filter: cell }))));

  const cov = state.giants.filter((g) => all || g.project === key);
  if (cov.length) panel.append(giantsCoverage(cov, all));

  const list = h("ul", { class: "rows", id: "findings-list", "aria-label": "Findings" });
  const sources = sourcesIn(state.findings.filter((f) => !f.suppressed && (all || f.project === key)));
  panel.append(h("section", { class: "section" },
    h("h2", {}, h("span", {}, "Findings"), h("span", { id: "findings-count" })),
    sources.length > 1 ? sourceFilter(sources) : null,
    list));
  fillFindings(list, ctx);
}

/** Who reported a row: "penthera" and every other tool that agreed (--giants). */
const sourcesOf = (f) => (f.foundBy?.length ? f.foundBy : [f.other ? f.source : "penthera"]);

function sourcesIn(rows) {
  const seen = new Set(rows.flatMap(sourcesOf));
  return [...seen].sort((a, b) => (a === "penthera" ? -1 : b === "penthera" ? 1 : a.localeCompare(b)));
}

/** Source filter chips: Penthera, or one of the tools --giants ran. */
function sourceFilter(sources) {
  return h("div", { class: "chips source-filter", role: "group", "aria-label": "Filter by source" },
    h("span", { class: "muted" }, "Source "),
    ...[null, ...sources].map((src) => h("button", {
      type: "button", class: ["linkish", state.source === src ? "b" : null], "aria-pressed": String(state.source === src),
      onclick: () => set({ source: src }),
    }, src == null ? "all" : src === "penthera" ? "Penthera" : src)));
}

/** "Coverage by area" from the latest --giants scan of each project in view. */
function giantsCoverage(cov, all) {
  return h("section", { class: "section" },
    h("h2", {}, h("span", {}, "Coverage by area"), h("span", {}, "other tools (--giants)")),
    ...cov.map((g) => h("table", { class: "giants-cov" },
      all ? h("caption", {}, shortProject(g.project)) : null,
      h("tbody", {}, ...g.areas.map((a) => h("tr", {},
        h("th", { scope: "row" }, a.label),
        h("td", {}, a.status),
        h("td", { class: "muted" }, a.tools.length ? a.tools.map((t) => (t.status === "ran" ? `${t.id}${t.version ? ` ${t.version}` : ""} (${t.findings})` : `${t.id}: ${t.status}`)).join(", ") : "no tool for this area")))))));
}

const sorted = (rows) => [...rows].sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.title.localeCompare(b.title));

/** Folder tabs: the selected one joins the page below it. Arrow keys move between them. */
function tabStrip(ctx) {
  const strip = h("div", { class: "tabs", role: "tablist", "aria-label": "Project views" });
  const btns = TABS.map((t, i) => {
    const b = h("button", {
      type: "button", role: "tab", class: "tab", id: `tabbtn-${t.id}`, "aria-selected": String(state.tab === t.id),
      "aria-controls": `tab-${t.id}`, tabindex: state.tab === t.id ? "0" : "-1", title: `${t.label}  ${t.key}`, onclick: () => ctx.openTab(t.id),
    }, t.label);
    b.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      e.preventDefault();
      const n = TABS[(i + (e.key === "ArrowRight" ? 1 : -1) + TABS.length) % TABS.length];
      ctx.openTab(n.id);
      queueMicrotask(() => document.getElementById(`tabbtn-${n.id}`)?.focus());
    });
    return b;
  });
  strip.append(...btns, h("span", { class: "tab-rest" }));
  return strip;
}

function fillFindings(list, ctx) {
  const all = state.sel.kind === "all";
  const q = state.query.trim().toLowerCase();
  const easy = simple();
  const fl = easy ? null : state.filter;
  const rows = sorted(state.findings
    .filter((f) => !f.suppressed && (all || f.project === state.sel.key))
    .filter((f) => !fl || (!f.other && f.severity === fl.severity && (f.confidence || "likely") === fl.confidence))
    .filter((f) => easy || !state.source || sourcesOf(f).includes(state.source))
    .filter((f) => !q || `${f.title} ${f.category} ${f.location} ${f.project}`.toLowerCase().includes(q)));
  visible = rows;
  clear(list);
  let group = null;
  for (const f of rows) {
    const fixFirst = f.severity === "critical" || f.severity === "high";
    const g = fixFirst ? "Fix first" : easy ? "When you have time" : "Then";
    if (g !== group) {
      group = g;
      const n = rows.filter((x) => (x.severity === "critical" || x.severity === "high") === fixFirst).length;
      list.append(h("li", { class: "group-h" }, `${g} :: ${n}`));
    }
    const cur = state.finding && state.finding.id === f.id && state.finding.project === f.project;
    list.append(h("li", {}, h("button", {
      type: "button", class: ["row", fixFirst ? "b" : null], "aria-current": String(Boolean(cur)), dataset: { id: f.id, project: f.project },
      onclick: () => ctx.openFinding(f),
    },
    easy ? h("span", { class: `sev sev-${f.severity}` }, SEV_WORD[f.severity] || f.severity) : sevBadge(f.severity),
    h("span", { class: "t" }, f.title),
    h("span", { class: "tag" }, easy ? (all ? shortProject(f.project) : "▸") : all ? shortProject(f.project) : f.category || ""),
    !easy && f.location ? h("span", { class: "where" }, f.location) : null)));
  }
  if (!rows.length) list.append(h("li", {}, empty(state.findings.length && q ? `${EMPTY.filtered}` : EMPTY.findings)));
  const count = document.getElementById("findings-count");
  if (count) count.textContent = q || fl || (!easy && state.source) ? `${rows.length} match` : easy ? plural(rows.length, "problem") : plural(rows.length, "open finding");
}

/** j / k: move the selection and open the finding in the right panel. */
export function moveFinding(step, ctx) {
  if (!visible.length) return;
  const i = visible.findIndex((f) => state.finding && f.id === state.finding.id && f.project === state.finding.project);
  const next = visible[Math.max(0, Math.min(visible.length - 1, i < 0 ? 0 : i + step))];
  ctx.openFinding(next);
  const btn = document.querySelector(`#findings-list .row[data-id="${next.id}"]`);
  btn?.focus({ preventScroll: false });
}

function miniList(rows, none, fixed = false) {
  return rows.length
    ? h("ul", { class: "mini" }, rows.slice(0, 8).map((r) => h("li", {}, h("span", { class: `sw sev-${r.severity}`, "aria-hidden": "true" }), h("span", { class: ["grow", fixed ? "muted" : null] }, fixed ? `✓ ${r.title}` : r.title))))
    : h("p", { class: "empty" }, none);
}

function combinedTrend(projects) {
  const len = Math.max(0, ...projects.map((p) => p.trend.length));
  const out = [];
  for (let i = 0; i < len; i++) out.push(projects.reduce((n, p) => n + ((p.trend[p.trend.length - len + i] || p.trend[0])?.total || 0), 0));
  return out;
}

function startView(col, ctx) {
  const easy = simple();
  const steps = easy ? [] : START.steps;
  col.append(h("div", { class: "start" },
    h("span", { class: "logotype xl", role: "img", "aria-label": "Penthera" }),
    halftone({ risk: 1, seed: "penthera" }),
    h("h1", {}, START.title),
    h("p", { class: "prose" }, easy ? START.introSimple : START.intro),
    h("div", { class: "actions start" },
      h("button", { type: "button", class: "btn primary", onclick: () => ctx.setup() }, "Set up my project…"),
      h("button", { type: "button", class: "btn", onclick: () => ctx.newScan("scan") }, easy ? "Check my app…" : "New scan…")),
    steps.length ? h("div", { class: "steps" }, steps.map((st, i) => h("div", { class: "step" },
      h("span", { class: "n" }, `${i + 1}.`),
      h("h3", {}, st.title),
      h("button", { type: "button", class: "btn", onclick: () => ctx.newScan(st.kind) }, `${st.title}…`),
      h("p", {}, st.body)))) : null,
    h("p", { class: "muted gate prose" }, START.gate),
    h("p", { class: "muted" }, `${START.demo} `, h("code", {}, "penthera ui --demo"), "."),
  ));
}

function notScannedView(col, key, ctx) {
  col.append(h("div", { class: "start" },
    h("h1", {}, shortProject(key)),
    h("p", { class: "muted" }, key),
    h("p", {}, "Not scanned yet. Start with a scan of this folder; it reads only what is inside it."),
    h("div", { class: "actions start" }, h("button", { type: "button", class: "btn primary", onclick: () => ctx.newScan("scan", key) }, "New scan…")),
  ));
}

// ── A live run, as a transcript ─────────────────────────────────────────

function runView(col, ctx) {
  const run = state.sel.run;
  if (!run) return;
  const status = h("span", { class: "chip" }, run.status);
  const stop = h("button", { type: "button", class: "btn small", disabled: run.status !== "running" }, "Stop");
  const lines = h("div", { class: ["transcript", "gutter", run.status === "running" ? null : "done"], role: "log", "aria-live": "off", "aria-label": "Run output" });
  const tail = h("div");
  const easy = simple();
  // Simple mode: one sentence on what is happening, the raw output folded away.
  const said = h("p", { class: "verdict-text", "aria-live": "polite" }, run.kind === "loop" ? "Looking for problems it can fix…" : "Checking your app… this takes a minute or two.");
  const saidSub = h("p", { class: "verdict-sub muted" }, "You can leave this page; it keeps going.");
  const tally = { verified: 0, failed: 0 };
  col.append(
    h("div", { class: "run-head" },
      h("h1", {}, easy ? ({ scan: "Checking your app", loop: "Fixing problems", deps: "Checking dependencies", agents: "Checking AI tooling" })[run.kind] || run.kind
        : `${({ scan: "Scan", deps: "Dependency check", agents: "AI tooling audit", loop: "Fix loop" })[run.kind] || run.kind}`),
      h("span", { class: "muted" }, `${shortProject(run.repo || run.url)}${run.url && run.repo ? ` + ${run.url}` : ""} · ${ago(run.startedAt)}`),
      aiTag(run.ai),
      h("span", { class: "grow" }), easy ? null : status, stop),
    // Node.append() would print a null as the text "null", so leave it out.
    ...(easy ? [h("section", { class: "report verdict plate" }, h("div", { class: "report-main" }, said, saidSub))] : []),
    tail,
    easy ? h("details", { class: "more" }, h("summary", {}, "Show what it is doing"), lines) : lines,
  );
  const setStatus = (st) => {
    status.textContent = st;
    status.className = `chip ${st === "running" ? "on" : st === "awaiting you" ? "blue" : st === "error" ? "inv" : ""}`;
    stop.disabled = !(st === "running" || st === "awaiting you");
  };
  setStatus(run.status === "running" ? "running" : run.status);
  stop.addEventListener("click", async () => {
    stop.disabled = true;
    try { await api.post(`/api/runs/${run.id}/stop`); } catch (e) { typer?.push(`error: ${e.message}`, "bad"); }
  });

  stopStream();
  typer = createTyper(lines);
  pending = null;
  const scroll = () => { const st = document.getElementById("stream"); if (st) st.scrollTop = st.scrollHeight; };
  const onEvent = (ev) => {
    const d = ev.data;
    switch (ev.type) {
      case "log": {
        const t = d.text.replace(/^\n/, "");
        const cls = /^penthera /.test(t) ? "cmd" : /verified and committed|done:|^(scan|deps|agents) done/.test(t) ? "ok"
          : /failed verification|^error|not applied/.test(t) ? "bad" : /^\s*iteration \d+/.test(t) ? "hl" : /^\s{3,}/.test(t) || /\.\.\.$/.test(t) ? "dim" : null;
        typer.push(cls === "dim" || cls === "bad" ? t.trim() : t, cls);
        break;
      }
      case "approval": {
        pending = d;
        set({ pending: { index: d.index, total: d.total } });
        typer.flush();
        clear(tail).append(waitingNote(run, d, typer));
        said.textContent = `Fix ${d.index} of ${d.total} is waiting for you to approve it.`;
        setStatus("awaiting you");
        scroll();
        // Replayed approvals are followed at once by their decision: open the window only if this one is still waiting.
        setTimeout(() => { if (pending === d) openApproval(run, d, typer); }, 60);
        break;
      }
      case "decision": {
        pending = null;
        set({ pending: null });
        closeApproval();
        clear(tail);
        setStatus("running");
        said.textContent = d.answer === "y" ? "Applying the fix and checking it worked…" : "Moving on…";
        break;
      }
      case "fix": {
        if (d.status === "verified") tally.verified++;
        else if (d.status === "failed") tally.failed++;
        saidSub.textContent = `${plural(tally.verified, "fix", "fixes")} applied and checked so far${tally.failed ? `, ${tally.failed} undone because it did not work` : ""}.`;
        break;
      }
      case "status": {
        if (d.status === "running") break;
        if (state.pending) set({ pending: null });
        closeApproval();
        lines.classList.add("done");
        setStatus(d.status);
        clear(tail);
        const sum = d.summary;
        if (d.status === "error") said.textContent = "Something went wrong. Open “Show what it is doing” for the reason.";
        else if (d.status === "stopped") said.textContent = "Stopped. Everything applied so far was checked; nothing was published.";
        else if (sum?.totals) {
          const t = sum.totals;
          said.textContent = t.verified || t.failed || t.declined ? `Done. ${plural(t.verified, "fix", "fixes")} applied and checked${t.failed ? `, ${t.failed} undone` : ""}${t.declined ? `, ${t.declined} skipped` : ""}.` : "Nothing here can be fixed automatically.";
        } else if (sum?.counts) {
          // A check: say what it found, not "up to date".
          const serious = (sum.counts.critical || 0) + (sum.counts.high || 0);
          said.textContent = sum.total
            ? `Done. ${plural(sum.total, "problem")} found${serious ? `, ${serious} serious` : ""}.`
            : "Done. Penthera found no problems.";
        } else said.textContent = "Done.";
        saidSub.textContent = run.kind === "loop" && d.status !== "error"
          ? (sum?.totals?.verified ? `The fix is on a separate branch on this computer${sum.branch ? `, ${sum.branch}, and your project is on it now` : ""}. Merge it when you are happy with it. Nothing was published. Problems with no automatic fix stay on your list.`
            : "Open a problem on your list and copy its prompt for your coding agent.") : "";
        if (easy) col.querySelector(".run-head h1").textContent = "Finished";
        if (sum?.totals) {
          const t = sum.totals;
          typer.push(`done: ${sum.stopReason} after ${plural(t.iterations, "round")} (${duration(sum.durationMs)})`, "ok");
          typer.push(`${t.verified} verified and committed :: ${t.failed} failed and reverted :: ${t.declined} skipped${sum.branch ? ` :: branch ${sum.branch}` : ""}`, t.failed ? "bad" : "ok");
        }
        if (sum?.ai) tail.append(aiSummaryBlock(sum.ai));
        tail.append(h("div", { class: "actions" },
          run.repo || run.url ? h("button", { type: "button", class: "btn primary", onclick: () => ctx.refresh().then(() => set({ sel: { kind: "project", key: run.repo || run.url } })) }, easy ? "See my project ▸" : "Open the project ▸") : null));
        ctx.refresh();
        announce(`Run ${d.status}`);
        break;
      }
      default: break;
    }
  };
  // fetch-based stream (api.js): it carries the session header, EventSource cannot.
  es = api.stream(`/api/runs/${run.id}/stream`, (type, data) => {
    if (type === "end") { es?.close(); es = null; return; }
    if (type === "error") { typer?.push("error: the run's event stream closed. Reload to reconnect.", "bad"); return; }
    if (!["log", "approval", "decision", "fix", "status"].includes(type)) return;
    try { onEvent(JSON.parse(data)); } catch { /* malformed event */ }
  });
}

/** Hex SHA-256 of the diff text as shown; the server only applies the diff whose hash matches. */
async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── The approval: a floating window, pinstriped because it waits on you ──

let approval = null;   // { win, decide } while the window is open
let decideFn = null;   // answers the waiting diff, window open or not

function closeApproval() {
  approval?.win.close();
  approval = null;
  decideFn = null;
}

function decider(run, d, ty) {
  let busy = false;
  const p = d.plan;
  const shownDiff = String(p.diff || "");
  const fn = async (answer) => {
    if (busy) return;
    // A cut diff is never applied by accident: Apply needs the box in the window ticked first.
    if (answer === "approve" && p.truncated && !fn.acknowledged) { openApproval(run, d, ty); return; }
    busy = true;
    approval?.el?.querySelectorAll("button").forEach((b) => { b.disabled = true; });
    try {
      const body = { approvalId: d.approvalId, answer };
      if (answer === "approve") {
        body.diffSha256 = await sha256Hex(shownDiff);
        if (p.truncated) body.acknowledgeTruncated = fn.acknowledged === true;
      }
      await api.post(`/api/runs/${run.id}/decision`, body);
    } catch (e) {
      ty.push(`error: ${e.message}`, "bad");
      approval?.el?.querySelectorAll("button").forEach((b) => { b.disabled = false; });
      if (approval?.apply && p.truncated && !fn.acknowledged) approval.apply.disabled = true;
      busy = false;
    }
  };
  fn.acknowledged = false;
  return fn;
}

/** Inline in the transcript: what is waiting, and a way back to the window. */
function waitingNote(run, d, ty) {
  decideFn = decider(run, d, ty);
  return h("div", { class: "wait-note plate" },
    h("span", { class: "lamp live", "aria-hidden": "true" }),
    h("span", { class: "grow" }, `Fix ${d.index} of ${d.total} is waiting for you: ${d.plan.title}`),
    h("button", { type: "button", class: "btn primary", onclick: () => openApproval(run, d, ty) }, "Review the change…"));
}

function openApproval(run, d, ty) {
  if (approval) return;
  const p = d.plan;
  const easy = simple();
  const decide = decideFn || (decideFn = decider(run, d, ty));
  const files = p.files.length;
  const shownDiff = String(p.diff || "");
  const diff = diffBlock(shownDiff);
  const ack = p.truncated ? h("input", { type: "checkbox", id: "ap-ack", checked: decide.acknowledged || null }) : null;
  const body = h("div", { class: "approval" },
    h("h3", { id: "ap-h" }, easy ? `Penthera wants to change ${plural(files, "file")} to fix this:` : p.title),
    h("ul", { class: "mini" }, p.findings.map((f) => h("li", {}, easy ? h("span", { class: `sev sev-${f.severity}` }, SEV_WORD[f.severity]) : sevBadge(f.severity), h("span", { class: "grow t1" }, f.title)))),
    h("p", { id: "ap-d", class: easy ? "prose" : "muted" }, easy
      ? `${p.title}. It changes ${p.files.join(", ")} on a separate branch, scans for the problem again, and undoes the change if it is still there. Nothing is published. Try your app afterwards.`
      : `${p.recipe}${p.framework ? ` (${p.framework})` : ""} · ${p.files.join(", ")} · ${d.memory ? `memory: ${d.memory.verified} verified, ${d.memory.failed} failed` : "no history for this recipe yet"}`),
    easy && !p.truncated ? h("details", { class: "more" }, h("summary", {}, "Show the exact change"), diff) : diff,
    p.truncated ? h("p", { class: "bad", role: "note" }, easy
      ? "[!] This change is too long to show in full here. Ask a developer to look at the rest in the project before you apply it."
      : `[!] Diff cut: showing the first ${shownDiff.length.toLocaleString()} of ${Number(p.fullLength).toLocaleString()} characters. Review the rest in the repo before applying.`) : null,
    p.truncated ? h("label", { class: "check", for: "ap-ack" }, ack, h("span", { class: "prose" }, " I have not seen the whole change and want to apply it anyway")) : null,
    p.ownerActions?.length ? h("div", { class: "prose" }, h("b", {}, "After this, check:"), h("ul", { class: "mini" }, p.ownerActions.map((a) => h("li", {}, a)))) : null,
    p.redacted ? h("p", { class: "muted" }, "Secret values are masked here; the real patch uses them.") : null,
  );
  const apply = h("button", { type: "button", class: "btn primary", disabled: Boolean(ack && !ack.checked), onclick: () => decide("approve") }, easy ? "Apply this fix" : "Apply", h("kbd", {}, "y"));
  ack?.addEventListener("change", () => { decide.acknowledged = ack.checked; apply.disabled = !ack.checked; });
  body.append(h("div", { class: "actions" },
    h("button", { type: "button", class: "btn", onclick: () => decide("stop") }, easy ? "Stop fixing" : "Stop", h("kbd", {}, "q")),
    h("span", { class: "grow" }),
    h("button", { type: "button", class: "btn", onclick: () => decide("skip") }, easy ? "Skip this one" : "Skip", h("kbd", {}, "n")),
    apply));
  const win = openWindow({ title: `Fix ${d.index} of ${d.total}`, label: `Fix ${d.index} of ${d.total} waiting for you`, body, wide: true, striped: true });
  win.el.setAttribute("aria-describedby", "ap-d");
  win.el.addEventListener("keydown", (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey || e.target instanceof HTMLInputElement) return;
    const a = { y: "approve", n: "skip", q: "stop" }[e.key];
    if (a) { e.preventDefault(); decide(a); }
  });
  win.el.addEventListener("close", () => { approval = null; }, { once: true });
  approval = { win, el: win.el, apply };
  announce(`Fix ${d.index} of ${d.total} is waiting for you: ${p.title}`);
  (ack && !ack.checked ? ack : apply).focus();
}

/** y / n / q while a diff waits and its window is closed. */
export function answerPending(key) {
  if (!pending || !decideFn) return false;
  const a = { y: "approve", n: "skip", q: "stop" }[key];
  if (!a) return false;
  decideFn(a);
  return true;
}

// ── A past loop run, rebuilt from its loopRun ───────────────────────────

function pastRunView(col, ctx) {
  const l = state.sel.past;
  if (!l) return;
  col.append(
    h("div", { class: "run-head" }, h("h1", {}, "Fix loop"), h("span", { class: "muted" }, `${shortProject(l.target.repo)} · ${ago(l.startedAt)} · ${duration(l.durationMs)}`)),
    h("div", { class: "transcript" },
      h("div", { class: "ln cmd" }, `penthera agent --loop --repo ${l.target.repo}${l.target.url ? ` --url ${l.target.url}` : ""}`),
      l.iterations.flatMap((it) => [
        h("div", { class: "ln hl" }, `iteration ${it.n}`),
        it.findings ? h("div", { class: "ln dim" }, `scan: ${it.findings.total} findings (${it.findings.suppressed} suppressed), ${it.findings.fixable} fixable`) : null,
        ...it.fixes.map((f) => h("div", { class: `ln ${f.status === "verified" ? "ok" : f.status === "failed" ? "bad" : "dim"}` },
          `${f.status === "verified" ? "OK " : f.status === "failed" ? "!! " : "-- "}${f.title} :: ${f.decision}${f.commit ? ` :: ${f.commit.slice(0, 10)}` : ""}`)),
      ]),
      h("div", { class: "ln ok" }, `done: ${l.stopReason} :: ${l.totals.verified} verified, ${l.totals.failed} failed, ${l.totals.declined + l.totals.skipped} skipped`),
      h("div", { class: "ln" }, `branch ${l.branch} :: nothing was pushed`),
    ),
    h("div", { class: "actions" }, h("button", { type: "button", class: "btn", onclick: () => set({ sel: { kind: "project", key: l.target.repo } }) }, "Open the project ▸")),
  );
}

/** "AI · local" or "AI · ollama.com" on a run: opens to say which model ran where. */
function aiTag(ai) {
  if (!ai) return null;
  const cloud = ai.route === "ollama-cloud";
  return h("details", { class: "ai-tag" },
    h("summary", { class: ["chip", cloud ? "blue" : null] }, AI.tag(cloud)),
    h("span", { class: "muted prose" }, AI.tagDetail(ai.model, cloud)));
}

/** After an AI run: the counts, and the unverified proposals folded away. */
function aiSummaryBlock(s) {
  return h("section", { class: "ai-summary" },
    h("p", { class: "prose" }, AI.done(s)),
    s.findings.length
      ? h("details", { class: "more" },
        h("summary", {}, AI.unverified(s.unverified)),
        h("p", { class: "muted prose" }, AI.unverifiedNote),
        h("ul", { class: "mini" }, s.findings.map((f) => h("li", {},
          h("span", { class: "grow" }, f.title),
          h("span", { class: "muted" }, `${f.file}:${f.line} · ${f.class}`)))))
      : null);
}
