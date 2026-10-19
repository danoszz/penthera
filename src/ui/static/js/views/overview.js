import { h, put, panel, empty, subwin, whatNext, fig } from "../dom.js";
import { severityBars, stackedBar, sparkline, trendChart, columns, wordmark } from "../charts.js";
import { ago, duration, shortProject, SEVERITIES, plural } from "../format.js";
import { SCREENS, START, NEXT, TAGLINE } from "../copy.js";

/** Merge per-project trends into one series by scan index from the end. */
function combinedTrend(projects) {
  const len = Math.max(0, ...projects.map((p) => p.trend.length));
  const out = [];
  for (let i = 0; i < len; i++) {
    let total = 0;
    let severe = 0;
    let ts = null;
    for (const p of projects) {
      const t = p.trend[p.trend.length - len + i] || p.trend[0];
      if (!t) continue;
      total += t.total;
      severe += (t.critical || 0) + (t.high || 0);
      if (!ts || t.ts > ts) ts = t.ts;
    }
    out.push({ ts, total, severe });
  }
  return out;
}

function about(meta, o) {
  const facts = o.projects.length
    ? [["projects", String(o.projects.length)], ["open", String(o.open)], ["fixed", String(o.fixed)], ["network", "none"]]
    : [["projects", "0"], ["network", "none"], ["telemetry", "none"]];
  return subwin("About penthera", { class: "about" },
    h("div", { class: "subwin-body" },
      wordmark(),
      h("p", { class: "sr" }, "Penthera"),
      h("div", { class: "tagline" }, TAGLINE),
      h("div", { class: "facts" },
        h("span", {}, `v${meta.version}`),
        facts.map(([k, v]) => h("span", {}, `${k} `, h("b", {}, v))),
        h("span", {}, meta.demo ? "demo data" : "reports from this machine"),
      ),
    ));
}

function startHere(meta, go) {
  const folder = meta.projects?.[0] || "";
  return h("section", { class: "steps", "aria-labelledby": "start-h" },
    h("div", {},
      h("h1", { id: "start-h" }, START.welcome),
      h("p", { class: "lede" }, START.intro),
      h("p", { class: "muted" }, START.gate),
    ),
    START.steps.map((st, i) => h("div", { class: "step" },
      h("h3", {}, h("span", { class: "n" }, `Step ${i + 1}`), st.title),
      h("p", { class: "muted" }, st.body),
      h("button", { type: "button", class: i === 0 ? "btn primary" : "btn", onclick: () => go("run", { kind: st.kind, repo: folder }) }, `${st.action} ▸`),
    )),
    h("p", { class: "muted" }, `${START.demo} `, h("code", {}, "penthera ui --demo"), "."),
  );
}

export async function render(root, { api, go, meta }) {
  const o = await api.get("/api/overview");
  put(root, about(meta, o));

  if (!o.projects.length) {
    put(root, startHere(meta, go));
    return;
  }

  const total = SEVERITIES.reduce((n, s) => n + o.mix[s], 0);
  const severe = o.mix.critical + o.mix.high;
  put(root, 
    h("h1", {}, SCREENS.overview.title),
    h("p", { class: "lede" }, SCREENS.overview.lede),
    h("div", { class: "strip" },
      cell("Open findings", String(o.open), `${severe} critical or high`),
      cell("Fixed", String(o.fixed), "gone in a later scan, or verified by the loop", "ok"),
      cell("Median time to fix", o.timeToFix.medianDays == null ? "-" : String(o.timeToFix.medianDays), plural(o.timeToFix.samples, "fix measured", "fixes measured"), null, o.timeToFix.medianDays == null ? null : "days"),
      cell("Hosts contacted", String(o.egress.hosts.length), `${o.egress.blocked.length} blocked by offline mode`),
    ),
  );

  const c = o.columns;
  const rowsOf = (list, none) => (list.length
    ? h("ul", { class: "rows" }, list.slice(0, 8).map((r) => h("li", {},
      h("span", { class: "code" }, `${r.severity.slice(0, 1).toUpperCase()}+`),
      h("button", { type: "button", class: ["row-btn", "t", r.severity === "critical" || r.severity === "high" ? "b" : null], onclick: () => go("findings", { project: r.project, id: r.id }) },
        r.title, h("span", { class: "where" }, ` · ${shortProject(r.project)}`)))))
    : empty(none));
  put(root, panel("This week", { class: "week", meta: new Date().toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" }) },
    h("div", { class: "cols" },
      h("div", {}, h("h3", {}, `Fix first · ${c.fixFirst.length}`), rowsOf(c.fixFirst, "Nothing critical or high. Good.")),
      h("div", {}, h("h3", {}, `New since the last scan · ${c.newest.length}`), rowsOf(c.newest, "Nothing new since the last scan.")),
      h("div", {}, h("h3", {}, `Fixed since the last scan · ${c.fixed.length}`), rowsOf(c.fixed, "Nothing fixed since the last scan yet.")),
    )));

  const grid = h("div", { class: "grid" });
  put(root, grid);

  const rows = o.projects.map((p) => h("tr", {},
    h("td", {}, h("span", { class: `grade grade-${p.grade}`, title: `score ${p.score}/100` }, p.grade)),
    h("td", {},
      h("button", { class: "row-btn trunc", type: "button", title: p.key, onclick: () => go("findings", { project: p.key }) }, shortProject(p.key)),
      h("span", { class: "faint" }, p.mode || "")),
    h("td", { class: "hide-narrow" }, stackedBar(p.counts, { width: 14 })),
    h("td", {}, sparkline(p.trend.map((t) => t.total), { label: `open findings, ${shortProject(p.key)}` })),
    h("td", { class: "num t1" }, String(p.open)),
    h("td", { class: "num ok" }, String(p.fixed)),
    h("td", { class: "num muted hide-narrow" }, h("button", { type: "button", class: "row-btn", onclick: () => go("history", { project: p.key }) }, ago(p.lastScan))),
  ));
  put(grid, panel("Posture per project", { class: "span-12", meta: plural(o.projects.length, "project") },
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ...["Grade", "Project", "Severity", "Trend", "Open", "Fixed", "Last scan"].map((t, i) => h("th", { class: [i === 4 || i === 5 || i === 6 ? "num" : null, i === 2 || i === 6 ? "hide-narrow" : null] }, t)))),
      h("tbody", {}, rows),
    )),
    fig("fig 1 :: grade = 100 − 30/critical − 15/high − 5/medium − 1/low; any critical is an F", `${o.projects.length} projects`),
  ));

  put(grid, panel("Severity mix", { class: "span-5", meta: `${total} findings` },
    stackedBar(o.mix, { width: 34 }),
    severityBars(o.mix, { width: 18 }),
    fig("fig 2 :: latest report per project", `${total} findings`),
  ));

  put(grid, panel("Findings over time", { class: "span-7", meta: "by scan" },
    trendChart(combinedTrend(o.projects)),
    h("div", { class: "legend" },
      h("span", {}, h("span", { class: "sw" }), "open (critical to low)"),
      h("span", {}, h("span", { class: "sw sw-severe" }), "critical + high"),
    ),
    fig("fig 3 :: summed across projects, by scan", "from reports + memory"),
  ));

  put(grid, panel("Time to fix", { class: "span-4", meta: o.timeToFix.medianDays == null ? "no data" : `median ${o.timeToFix.medianDays}d` },
    columns(o.timeToFix.buckets, { label: "Fixes by time to fix" }),
    fig("fig 4 :: first seen to gone", `${o.timeToFix.samples} fixes`),
  ));

  put(grid, panel("Hosts contacted", { class: "span-4", meta: `${o.egress.hosts.length} hosts` },
    o.egress.hosts.length
      ? h("ul", { class: "list" }, o.egress.hosts.map((x) => h("li", {},
        h("span", { class: x.thirdParty ? "t1" : "ok" }, x.thirdParty ? "3P" : "OK"),
        h("span", { class: "grow trunc t1", title: x.host }, x.host),
        h("span", { class: "num muted" }, String(x.requests)),
      )))
      : empty("No requests recorded."),
    o.egress.blocked.length ? h("div", {},
      h("p", { class: "label" }, "Blocked (offline)"),
      h("ul", { class: "list" }, o.egress.blocked.map((x) => h("li", {}, h("span", { class: "muted" }, "--"), h("span", { class: "grow trunc" }, x.host), h("span", { class: "num muted" }, String(x.requests))))),
    ) : null,
    fig("fig 5 :: latest scan per project", "3P = third party"),
  ));

  put(grid, panel("Last scans", { class: "span-4", meta: `${o.lastScans.length} newest` },
    h("ul", { class: "list" }, o.lastScans.map((sc) => h("li", {},
      h("span", { class: "muted" }, ago(sc.ts).padStart(7)),
      h("span", { class: "grow trunc t1", title: sc.target }, shortProject(sc.target)),
      worst(sc.counts),
      h("span", { class: "num muted hide-narrow" }, duration(sc.durationMs)),
    ))),
  ));

  if (o.loops.length) {
    put(grid, panel("Agent loop runs", { class: "span-12", meta: plural(o.loops.length, "run") },
      h("ul", { class: "list" }, o.loops.map((l) => h("li", {},
        h("span", { class: "muted" }, ago(l.startedAt)),
        h("span", { class: "grow t1" }, `${shortProject(l.target.repo)} :: ${l.findings.initial ?? "?"} → ${l.findings.final ?? "?"} findings`),
        h("span", { class: "ok" }, `${l.totals.verified} verified`),
        l.totals.failed ? h("span", { class: "bad" }, `${l.totals.failed} reverted`) : null,
        h("span", { class: "muted hide-narrow" }, l.branch || ""),
      ))),
    ));
  }

  put(root, whatNext(NEXT.overview, go));
}

function worst(c) {
  const sev = SEVERITIES.find((k) => c[k] > 0);
  return sev ? h("span", { class: `sev sev-${sev}` }, `${c[sev]} ${sev}`) : h("span", { class: "ok" }, "clean");
}

function cell(label, value, sub, cls, unit) {
  return h("div", { class: "cell" }, h("span", { class: "label" }, label), h("div", { class: ["big", cls] }, value, unit ? h("span", { class: "unit" }, unit) : null), h("div", { class: "sub" }, sub));
}
