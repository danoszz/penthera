/**
 * Pure summaries for the dashboard: report JSON (and memory views) in, small
 * plain objects out. Shared by the real data source and the --demo one, so
 * the demo exercises the same code paths as a real project.
 *
 * Report content is untrusted data (finding titles come from scanned sites
 * and repos). Nothing here interprets it; the frontend only ever renders it
 * as text.
 */
import { findingId } from "../../../lib/memory/views.js";
import { gradeFindings } from "../../../lib/agents/index.js";
import { buildReportModel, CONFIDENCE_LABELS } from "../../report/model.js";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEV_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
const DAY = 86_400_000;

export const HIDDEN_CONTENT_RULES = new Set([
  "bidi-controls", "curl-pipe-interpreter", "curl-pipe-shell", "html-comment-instructions",
  "js-eval-remote", "powershell-iex", "py-exec-remote", "scanner-directed",
  "shell-command-substitution", "shell-eval", "shell-process-substitution", "unicode-tags",
  "variation-selectors", "whitespace-horizontal", "whitespace-vertical", "zero-width",
  "embedded-binary", "unknown-binary", "symlink-escape", "file-too-large",
]);

const str = (x, max = 2000) => (typeof x === "string" ? x.slice(0, max) : x == null ? null : String(x).slice(0, max));
const time = (x) => { const t = Date.parse(x); return Number.isNaN(t) ? null : t; };

export function counts(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings || []) if (c[f?.severity] != null) c[f.severity]++;
  return c;
}

export const actionable = (c) => c.critical + c.high + c.medium + c.low;

export function median(xs) {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

/** What kind of Penthera output a parsed JSON file is, or null. */
export function classify(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
  if (obj.loopRun && typeof obj.loopRun === "object") return "loop";
  if (obj.mode === "deps" && obj.deps) return "deps";
  if (obj.mode === "agents" && obj.agents) return "agents";
  if (Array.isArray(obj.changes) && Array.isArray(obj.specs) && obj.npm) return "install";
  if (Array.isArray(obj.findings) && obj.target) return "scan";
  return null;
}

export function projectKey(target) {
  const t = str(target, 500) || "unknown";
  try {
    const u = new URL(t);
    if (u.protocol === "http:" || u.protocol === "https:") return u.origin;
  } catch { /* a path */ }
  return t;
}

/** One finding as a table row. */
export function findingRow(f, report) {
  const loc = f.file ? (Number.isInteger(f.line) ? `${f.file}:${f.line}` : f.file) : f.url;
  return {
    id: `${findingId(f)}`,
    project: projectKey(report.target),
    severity: SEV_RANK[f.severity] != null ? f.severity : "info",
    title: str(f.title, 300) || "(untitled)",
    category: str(f.category, 80),
    source: str(f.source, 80),
    confidence: str(f.confidence, 40),
    location: str(loc, 500),
    seen: report.timestamp || null,
  };
}

/** Latest scan report per project, plus the full series per project (oldest first). */
export function groupScans(scans) {
  const byProject = new Map();
  for (const r of scans) {
    const k = projectKey(r.data.target);
    if (!byProject.has(k)) byProject.set(k, []);
    byProject.get(k).push(r);
  }
  for (const list of byProject.values()) list.sort((a, b) => (time(a.data.timestamp) ?? a.mtime) - (time(b.data.timestamp) ?? b.mtime));
  return byProject;
}

/** Findings that disappeared between consecutive reports, with how long they lived. */
export function fixedBetween(series) {
  const firstSeen = new Map();
  const fixed = new Map();
  for (const r of series) {
    const ts = time(r.data.timestamp) ?? r.mtime;
    const ids = new Set((r.data.findings || []).filter((f) => f.severity !== "info").map(findingId));
    for (const id of ids) {
      if (!firstSeen.has(id)) firstSeen.set(id, ts);
      fixed.delete(id); // came back: open again
    }
    for (const [id, seen] of firstSeen) if (!ids.has(id) && !fixed.has(id)) fixed.set(id, ts - seen);
  }
  return [...fixed.values()];
}

export function postureGrade(c) {
  const list = [];
  for (const s of SEVERITIES) for (let i = 0; i < c[s]; i++) list.push({ severity: s });
  return gradeFindings(list);
}

/**
 * The overview: posture per project, severity mix, trend, open vs fixed,
 * time to fix, egress hosts, last scans.
 * @param {{ scans: object[], memory: object[] }} input  scans: [{ file, mtime, data }]
 */
export function buildOverview({ scans = [], memory = [], runs = [] }) {
  const groups = groupScans(scans);
  const projects = [];
  const mix = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const ttf = [];
  let open = 0;
  let fixed = 0;

  for (const [key, series] of groups) {
    const latest = series[series.length - 1];
    const c = counts(latest.data.findings);
    for (const s of SEVERITIES) mix[s] += c[s];
    const gone = fixedBetween(series);
    ttf.push(...gone);
    open += actionable(c);
    fixed += gone.length;
    const mem = memory.find((m) => matchesProject(m.label, key));
    const trend = series.length > 1 || !mem?.trend?.length
      ? series.slice(-12).map((r) => ({ ts: r.data.timestamp, ...counts(r.data.findings) }))
      : mem.trend;
    projects.push({
      key,
      mode: str(latest.data.mode, 20) || (latest.data.modes || []).join("+") || null,
      lastScan: latest.data.timestamp || null,
      counts: c,
      open: actionable(c),
      fixed: gone.length,
      ...postureGrade(c),
      trend: trend.map((t) => ({ ts: t.ts, total: actionable(t), critical: t.critical, high: t.high })),
      memory: mem ? { events: mem.events, chain: mem.chain, medianTimeToFixDays: mem.medianTimeToFixDays } : null,
    });
  }
  projects.sort((a, b) => b.counts.critical - a.counts.critical || b.counts.high - a.counts.high || a.key.localeCompare(b.key));

  for (const m of memory) {
    if (m.medianTimeToFixMs != null) ttf.push(m.medianTimeToFixMs);
    fixed = Math.max(fixed, m.verifiedFixes || 0);
  }

  const egress = new Map();
  const blocked = new Map();
  for (const [, series] of groups) {
    const e = series[series.length - 1].data.egress;
    for (const h of e?.hosts || []) bumpHost(egress, h, e.thirdPartyHosts);
    for (const h of e?.blocked || []) blocked.set(h.host, (blocked.get(h.host) || 0) + (h.requests || 0));
  }

  const last = [...scans]
    .sort((a, b) => (time(b.data.timestamp) ?? b.mtime) - (time(a.data.timestamp) ?? a.mtime))
    .slice(0, 8)
    .map((r) => ({
      target: projectKey(r.data.target), mode: str(r.data.mode, 20), ts: r.data.timestamp || null,
      durationMs: Number.isFinite(r.data.duration) ? r.data.duration : null, counts: counts(r.data.findings), file: r.name,
    }));

  // "This week" columns: fix first, new since the previous scan, fixed since the previous scan.
  const fixFirst = [];
  const newest = [];
  const fixedLately = [];
  for (const [key] of groups) {
    const hst = buildScanHistory(scans, key);
    if (!hst) continue;
    const latest = groups.get(key)[groups.get(key).length - 1];
    for (const f of latest.data.findings || []) if (f.severity === "critical" || f.severity === "high") fixFirst.push(findingRow(f, latest.data));
    if (hst.scans.length > 1) { newest.push(...hst.new); fixedLately.push(...hst.fixed); }
  }
  const bySev = (xs) => xs.sort((x, y) => SEV_RANK[x.severity] - SEV_RANK[y.severity] || x.title.localeCompare(y.title));
  const columns = { fixFirst: bySev(fixFirst), newest: bySev(newest), fixed: bySev(fixedLately) };

  const ttfDays = ttf.map((ms) => ms / DAY);
  return {
    columns,
    projects,
    mix,
    open,
    fixed,
    timeToFix: {
      medianDays: ttfDays.length ? Math.round(median(ttfDays) * 10) / 10 : null,
      buckets: bucketDays(ttfDays),
      samples: ttfDays.length,
    },
    egress: {
      hosts: [...egress.values()].sort((a, b) => b.requests - a.requests).slice(0, 12),
      blocked: [...blocked].map(([host, requests]) => ({ host, requests })).sort((a, b) => b.requests - a.requests).slice(0, 8),
    },
    lastScans: last,
    loops: runs.slice(0, 5).map(loopSummary),
  };
}

function bumpHost(map, h, thirdParty = []) {
  const host = str(h.host, 255);
  if (!host) return;
  const cur = map.get(host) || { host, requests: 0, thirdParty: (thirdParty || []).some((t) => t.host === host) };
  cur.requests += Number.isFinite(h.requests) ? h.requests : 0;
  map.set(host, cur);
}

function bucketDays(days) {
  const b = [
    { label: "< 1d", n: 0 }, { label: "1-7d", n: 0 }, { label: "7-30d", n: 0 }, { label: "> 30d", n: 0 },
  ];
  for (const d of days) b[d < 1 ? 0 : d < 7 ? 1 : d < 30 ? 2 : 3].n++;
  return b;
}

function matchesProject(label, key) {
  if (typeof label !== "string") return false;
  return label === key || label.startsWith(`${key} (`);
}

export function loopSummary(run) {
  const l = run.loopRun || run;
  return {
    id: str(l.id, 64),
    startedAt: l.startedAt || null,
    durationMs: Number.isFinite(l.durationMs) ? l.durationMs : null,
    target: { repo: str(l.target?.repo, 500), url: str(l.target?.url, 500) },
    branch: str(l.branch?.fix, 200),
    stopReason: str(l.stopReason, 60),
    findings: { initial: l.findings?.initial ?? null, final: l.findings?.final ?? null },
    totals: {
      iterations: l.totals?.iterations ?? 0, verified: l.totals?.verified ?? 0, failed: l.totals?.failed ?? 0,
      declined: l.totals?.declined ?? 0, skipped: l.totals?.skipped ?? 0,
    },
    iterations: (l.iterations || []).slice(0, 50).map((it) => ({
      n: it.n,
      durationMs: it.durationMs ?? null,
      findings: it.findings || null,
      fixes: (it.fixes || []).slice(0, 50).map((f) => ({
        title: str(f.title, 200), recipe: str(f.recipe, 80), decision: str(f.decision, 20), status: str(f.status, 20),
        commit: str(f.commit, 64), files: (f.files || []).slice(0, 20).map((x) => str(x, 300)),
      })),
    })),
  };
}

/** Rows for the findings table: every finding of the latest report per project. */
export function buildFindings(scans) {
  const rows = [];
  for (const [, series] of groupScans(scans)) {
    const latest = series[series.length - 1];
    for (const f of latest.data.findings || []) rows.push(findingRow(f, latest.data));
    for (const f of latest.data.suppressed || []) rows.push({ ...findingRow(f, latest.data), suppressed: true });
  }
  return rows.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.project.localeCompare(b.project) || a.title.localeCompare(b.title));
}

/** The finding and the report it came from, by row id + project. */
export function locateFinding(scans, id, project) {
  for (const [key, series] of groupScans(scans)) {
    if (project && key !== project) continue;
    const latest = series[series.length - 1];
    const all = [...(latest.data.findings || []), ...(latest.data.suppressed || [])];
    const f = all.find((x) => findingId(x) === id);
    if (f) return { finding: f, report: latest };
  }
  return null;
}

/** The evidence part of a finding, every field as text. */
export function findingDetail(f) {
  const pick = (k) => (f[k] == null ? null : typeof f[k] === "string" ? f[k].slice(0, 8000) : JSON.stringify(f[k], null, 2).slice(0, 8000));
  return {
    title: str(f.title, 300),
    severity: f.severity,
    category: str(f.category, 80),
    source: str(f.source, 80),
    confidence: str(f.confidence, 40),
    description: pick("description"),
    evidence: pick("evidence") || pick("detail") || pick("proof"),
    request: pick("request"),
    response: pick("response"),
    remediation: pick("remediation") || pick("fix") || pick("recommendation"),
    location: f.file ? (Number.isInteger(f.line) ? `${f.file}:${f.line}` : f.file) : str(f.url, 500),
    owasp: Array.isArray(f.owasp) ? f.owasp.slice(0, 10).map((x) => str(x, 40)) : [],
    suppression: f.suppression ? { reason: str(f.suppression.reason, 300), source: str(f.suppression.source, 40) } : null,
  };
}

export function buildDeps({ deps = [], installs = [] }) {
  const latest = deps[deps.length - 1]?.data || null;
  const d = latest?.deps;
  return {
    latest: latest ? {
      target: str(latest.target, 500),
      ts: latest.timestamp || null,
      lockfile: str(d.lockfile, 300),
      ecosystem: str(d.ecosystem, 20) || "npm",
      network: str(d.network, 80),
      total: d.total ?? 0,
      scanned: d.scanned ?? 0,
      direct: (d.direct || []).length,
      capabilityCounts: d.capabilityCounts || {},
      typosquats: (d.typosquats || []).slice(0, 20).map((t) => ({ name: str(t.name, 214), similarTo: str(t.similarTo || t.target || t.popular, 214) })),
      counts: counts(latest.findings),
      findings: (latest.findings || []).slice(0, 60).map((f) => ({ severity: f.severity, title: str(f.title, 300), location: str(f.url || f.file, 300) })),
      diff: d.diff ? {
        base: str(d.diff.base, 200),
        added: (d.diff.added || []).slice(0, 100).map((a) => ({ name: str(a.name, 214), version: str(a.version, 64), capabilities: a.capabilities || [], installScripts: Object.keys(a.installScripts || {}) })),
        upgraded: (d.diff.upgraded || []).slice(0, 100).map((u) => ({ name: str(u.name, 214), from: str(u.from, 64), to: str(u.to, 64), gained: u.gained || [], lost: u.lost || [] })),
        removed: (d.diff.removed || []).slice(0, 100).map((r) => ({ name: str(r.name, 214), version: str(r.version, 64) })),
      } : null,
    } : null,
    history: deps.slice(-12).map((r) => ({ ts: r.data.timestamp, total: r.data.deps?.total ?? 0, findings: actionable(counts(r.data.findings)) })),
    installs: installs.slice(-20).reverse().map((r) => ({
      file: r.name,
      ts: r.data.timestamp || new Date(r.mtime).toISOString(),
      specs: (r.data.specs || []).slice(0, 20).map((s) => str(s, 214)),
      clean: Boolean(r.data.clean),
      action: str(r.data.action, 40),
      changes: (r.data.changes || []).slice(0, 50).map((c) => ({
        name: str(c.name, 214), version: str(c.version, 64), flags: c.flags || [], deny: c.deny || [], approval: c.approval || [], allowedBy: c.allowedBy ? true : false,
      })),
    })),
  };
}

export function buildAi(agents = []) {
  const latest = agents[agents.length - 1]?.data || null;
  if (!latest) return { latest: null, history: [] };
  const a = latest.agents;
  const findings = latest.findings || [];
  const rule = (f) => String(f.templateId || "").replace(/^agents\//, "");
  return {
    latest: {
      target: str(latest.target, 500),
      ts: latest.timestamp || null,
      grade: str(a.grade, 1),
      score: a.score ?? null,
      home: Boolean(a.home),
      inventory: a.inventory || {},
      lock: a.lock || null,
      counts: counts(findings),
      hidden: findings.filter((f) => HIDDEN_CONTENT_RULES.has(rule(f))).slice(0, 50).map((f) => ({ severity: f.severity, rule: rule(f), title: str(f.title, 300), location: str(f.url, 300), description: str(f.description, 1000) })),
      findings: findings.filter((f) => !HIDDEN_CONTENT_RULES.has(rule(f))).slice(0, 80).map((f) => ({ severity: f.severity, rule: rule(f), title: str(f.title, 300), location: str(f.url, 300) })),
    },
    history: agents.slice(-12).map((r) => ({ ts: r.data.timestamp, grade: str(r.data.agents?.grade, 1), score: r.data.agents?.score ?? null })),
  };
}

/** A memory project's stats from its verified events (views + history). */
export function memoryStats({ id, label, chain, views, history }) {
  return {
    id: id.slice(0, 16),
    label: str(label, 500) || id.slice(0, 16),
    chain: chain.ok ? "ok" : "broken",
    brokenAt: chain.ok ? null : chain.brokenAt,
    events: chain.count,
    scans: views?.scans ?? 0,
    medianTimeToFixDays: views?.medianTimeToFixDays ?? null,
    medianTimeToFixMs: views?.medianTimeToFixDays == null ? null : views.medianTimeToFixDays * DAY,
    verifiedFixes: (views?.recipeSuccess || []).reduce((n, r) => n + r.verified, 0),
    failedFixes: (views?.recipeSuccess || []).reduce((n, r) => n + r.failed, 0),
    suppressions: (views?.suppressions || []).length,
    recipes: (views?.recipeSuccess || []).slice(0, 20).map((r) => ({ framework: r.framework, recipe: r.recipe, verified: r.verified, failed: r.failed, rate: r.rate })),
    trend: history?.trend || [],
  };
}

/**
 * "Understand one finding": the report model's plain-language fields for a
 * single finding (plain severity, what the confidence label means, OWASP
 * mapping, the recipe that would fix it, the action-plan fix text).
 */
export function explainFinding(f, report) {
  const m = buildReportModel({ target: report?.target, timestamp: report?.timestamp, findings: [f] });
  const x = m.findings[0];
  const conf = CONFIDENCE_LABELS.find((c) => c.label === x.confidence);
  return {
    plainSeverity: x.plainSeverity,
    confidence: x.confidence,
    confidenceMeaning: conf ? conf.meaning : null,
    owasp: x.owasp,
    recipe: x.recipe,
    fixText: x.fixText,
  };
}

const scanMeta = (r, i) => ({
  i, ts: r.data.timestamp || new Date(r.mtime).toISOString(), file: r.name,
  counts: counts(r.data.findings), open: actionable(counts(r.data.findings)),
});

/**
 * "Compare over time": every scan of one project, and what changed between
 * two of them (default: the previous scan and the latest).
 */
export function buildScanHistory(scans, project, a = null, b = null) {
  const series = groupScans(scans).get(project);
  if (!series) return null;
  const list = series.map(scanMeta);
  const bi = Number.isInteger(b) && b >= 0 && b < series.length ? b : series.length - 1;
  const ai = Number.isInteger(a) && a >= 0 && a < series.length ? a : Math.max(0, bi - 1);
  const rows = (r) => new Map((r.data.findings || []).filter((f) => f.severity !== "info").map((f) => [findingId(f), findingRow(f, r.data)]));
  const A = rows(series[ai]);
  const B = rows(series[bi]);
  const sort = (xs) => xs.sort((x, y) => SEV_RANK[x.severity] - SEV_RANK[y.severity] || x.title.localeCompare(y.title));
  // Finding lifetimes across every scan of the project: first seen, last seen, open or fixed.
  const life = new Map();
  series.forEach((r, i) => {
    for (const f of (r.data.findings || []).filter((x) => x.severity !== "info")) {
      const id = findingId(f);
      if (!life.has(id)) life.set(id, { ...findingRow(f, r.data), from: i, to: i });
      life.get(id).to = i;
    }
  });
  const last = series.length - 1;
  const lifetimes = sort([...life.values()].map((x) => ({ ...x, open: x.to === last })))
    .sort((x, y) => Number(y.open) - Number(x.open) || SEV_RANK[x.severity] - SEV_RANK[y.severity] || x.from - y.from)
    .slice(0, 40);
  return {
    project,
    scans: list,
    lifetimes,
    a: list[ai],
    b: list[bi],
    new: sort([...B].filter(([id]) => !A.has(id)).map(([, r]) => r)),
    fixed: sort([...A].filter(([id]) => !B.has(id)).map(([, r]) => r)),
    still: sort([...B].filter(([id]) => A.has(id)).map(([, r]) => r)),
  };
}

/** The latest scan report for a project, or null. */
export function latestScan(scans, project) {
  const series = groupScans(scans).get(project);
  return series ? series[series.length - 1] : null;
}

/** A filesystem-safe slug for a project key. */
export function slug(key) {
  return String(key).replace(/^https?:\/\//, "").replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase().slice(-48) || "project";
}
