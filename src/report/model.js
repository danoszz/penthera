/**
 * The report model: one plain-data view of a scan result that the audience
 * reports (developer, owner, auditor) and user templates (--report-template)
 * render from. Everything here is strings, numbers, booleans, arrays and plain
 * objects, so a template can only print data, never reach code.
 */
import { referencesFor } from "../../lib/references.js";
import { resolveWstgTags } from "../../lib/owasp-wstg.js";
import { buildComplianceCoverage } from "../../lib/compliance/index.js";
import { buildActionPlan } from "../../lib/remediation/index.js";
import { confidenceFor } from "../../lib/provenance.js";
import { RECIPES } from "../../lib/fix/index.js";
import { OWASP_NAMES } from "../../lib/agents/owasp.js";
import { findingId } from "../../lib/memory/views.js";
import { buildTimeline, formatDuration } from "./timeline.js";
import { problemCounts } from "./counts.js";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export const CONFIDENCE_LABELS = [
  { label: "confirmed", meaning: "The pattern matched exactly: a header is absent, a certificate has expired, a key in the file has a provider's format. A rule match, not a verdict that it can be exploited." },
  { label: "likely", meaning: "A strong signal with a small chance of a false positive." },
  { label: "potential", meaning: "A heuristic or timing signal. It needs a second source before anyone acts on it." },
  { label: "needs-human-review", meaning: "A scanner cannot judge exploitability here (access control, IDOR). A person has to look." },
];

// OWASP Top 10 (2021) category per finding category. Categories without a
// clean match (email DNS, fuzzing noise, machine audit) are left unmapped.
export const OWASP_TOP10 = {
  "A01:2021": "Broken Access Control",
  "A02:2021": "Cryptographic Failures",
  "A03:2021": "Injection",
  "A05:2021": "Security Misconfiguration",
  "A06:2021": "Vulnerable and Outdated Components",
  "A07:2021": "Identification and Authentication Failures",
  "A10:2021": "Server-Side Request Forgery",
};
const CATEGORY_TOP10 = {
  "auth-bypass": "A01:2021", "open-redirect": "A01:2021", permissions: "A01:2021",
  tls: "A02:2021", transport: "A02:2021",
  sqli: "A03:2021", xss: "A03:2021", ssti: "A03:2021", cmdi: "A03:2021", injection: "A03:2021",
  headers: "A05:2021", cors: "A05:2021", "cors-misconfiguration": "A05:2021", cookie: "A05:2021",
  config: "A05:2021", exposure: "A05:2021", "info-leak": "A05:2021", disclosure: "A05:2021",
  "method-confusion": "A05:2021", "content-type-confusion": "A05:2021",
  cve: "A06:2021", "js-vulnerability": "A06:2021", "dependency-risk": "A06:2021",
  auth: "A07:2021", secrets: "A07:2021", "rate-limiting": "A07:2021",
  ssrf: "A10:2021",
};

// Test and fixture folders and files, where a "secret" is often a made-up sample.
const TEST_PATH = /(^|\/)(tests?|__tests__|spec|e2e|fixtures|__fixtures__|__mocks__|testdata)\/|\.(test|spec)\.[a-z0-9]+$/i;
const PLAIN = { critical: "serious", high: "serious", medium: "moderate", low: "minor", info: "note" };

function isHttp(u) {
  return typeof u === "string" && /^https?:\/\//i.test(u);
}

function locationOf(f) {
  if (isHttp(f.url)) return { file: null, line: null, url: f.url, location: f.url };
  const file = f.file || f.url || null;
  const line = Number.isInteger(f.line) && f.line > 0 ? f.line : null;
  return { file, line, url: null, location: file ? (line ? `${file}:${line}` : file) : null };
}

function recipeFor(f) {
  for (const r of RECIPES) {
    try {
      if (r.matches(f)) return r.id;
    } catch {
      // a recipe that cannot judge this finding does not claim it
    }
  }
  return null;
}

const keyOf = (f) => `${f.category || ""}|${f.title || ""}|${f.url || ""}`;

/** Map each finding key to a fix plan (from result.fixPlans, e.g. an agent loop). */
function plansByFinding(plans) {
  const map = new Map();
  for (const p of Array.isArray(plans) ? plans : []) {
    for (const f of p?.findings || []) map.set(keyOf(f), p);
  }
  return map;
}

/** Build the report model for a scan result. */
export function buildReportModel(result, { version = "0.0.0" } = {}) {
  const raw = [...(result?.findings || [])].sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));
  const actionPlan = result?.actionPlan || buildActionPlan(raw);
  const plans = plansByFinding(result?.fixPlans);
  const timeline = buildTimeline(result);
  const loopRecipe = new Map((timeline?.entries || []).filter((e) => e.recipe).map((e) => [e.fid, e.recipe]));

  const findings = raw.map((f, i) => {
    const loc = locationOf(f);
    const plan = plans.get(keyOf(f));
    const action = actionPlan.find((a) => a.findings.some((x) => x.title === f.title && (x.url || null) === (f.url || null)));
    const top10 = CATEGORY_TOP10[f.category] || null;
    return {
      n: i + 1,
      fid: f.fid || findingId(f),
      title: String(f.title || "Untitled finding"),
      severity: f.severity || "info",
      plainSeverity: PLAIN[f.severity] || "note",
      category: f.category || null,
      confidence: confidenceFor(f),
      source: f.source || null,
      method: f.method || f.source || null,
      collectedAt: f.collected_at || result?.timestamp || null,
      description: f.description || null,
      ...loc,
      recipe: plan?.recipe || loopRecipe.get(f.fid) || recipeFor(f),
      diff: plan?.diff || null,
      fixText: action?.fix || null,
      sources: referencesFor(f).map((r) => ({ cite: r.cite, url: r.url })),
      owasp: [
        ...(top10 ? [`${top10} ${OWASP_TOP10[top10]}`] : []),
        ...(Array.isArray(f.owasp) ? f.owasp.map((id) => OWASP_NAMES[id] || id) : []),
      ],
      wstg: resolveWstgTags(f),
    };
  });

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) if (counts[f.severity] != null) counts[f.severity]++;

  const suppressed = (result?.suppressed || []).map((f) => ({
    fid: f.fid || findingId(f),
    title: String(f.title || ""),
    severity: f.severity || "info",
    reason: f.suppression?.reason || "",
    actor: f.suppression?.actor || "unknown",
    by: f.suppression?.source === "repo-file" ? "repo file (penthera.suppress.json)" : "local memory",
    expires: f.suppression?.expires || null,
  }));

  const inconclusive = (result?.errors || []).map((e) => ({
    probe: e.probe || "", url: e.url || "", message: e.message || "", count: e.count || 1,
  }));

  const e = result?.egress || null;
  const egress = e ? {
    mode: e.offline ? "offline (scan target only)" : "online",
    userAgent: e.userAgent || "",
    thirdPartyHosts: (e.thirdPartyHosts || []).map((h) => ({ host: h.host, requests: h.requests })),
    blocked: (e.blocked || []).map((h) => ({ host: h.host, requests: h.requests })),
  } : null;

  const actions = actionPlan.map((a, i) => ({
    n: i + 1, id: a.id, action: a.action, why: a.why, fix: a.fix, effort: a.effort,
    severity: a.severity, ownerAction: Boolean(a.ownerAction), findingCount: a.findings.length,
  }));
  const ownerActions = actions.filter((a) => a.ownerAction);
  for (const p of Array.isArray(result?.fixPlans) ? result.fixPlans : []) {
    for (const text of p?.ownerActions || []) {
      if (typeof text === "string") ownerActions.push({ n: ownerActions.length + 1, id: p.recipe, action: text, why: "", fix: "", effort: "", severity: "", ownerAction: true, findingCount: (p.findings || []).length });
    }
  }

  const coverage = result?.compliance?.framework === "nis2" ? result.compliance : buildComplianceCoverage(result || {}, "nis2");
  const nis2 = coverage.measures.map((m) => ({ id: m.id, title: m.title, status: m.status, findings: m.findings || 0, note: m.note || "" }));

  const owaspMap = new Map();
  for (const f of findings) {
    for (const o of f.owasp) {
      if (!owaspMap.has(o)) owaspMap.set(o, []);
      owaspMap.get(o).push(f.fid || `#${f.n}`);
    }
  }
  const owasp = [...owaspMap].sort(([a], [b]) => a.localeCompare(b)).map(([id, ids]) => ({ id, count: ids.length, findings: ids.join(", ") }));

  const trend = (result?.memory?.history?.trend || []).map((t) => ({
    date: String(t.ts).slice(0, 10), serious: t.critical + t.high, critical: t.critical, high: t.high,
    medium: t.medium, low: t.low, total: t.total, suppressed: t.suppressed,
  }));

  return {
    tool: { name: "penthera", version },
    target: result?.target || "unknown",
    timestamp: result?.timestamp || null,
    duration: result?.duration ? formatDuration(result.duration) : null,
    modes: (result?.modes || (result?.mode ? [result.mode] : [])).join(", "),
    profile: result?.profile || null,
    offline: Boolean(e?.offline),
    probes: [...(result?.executedProbes || [])].sort(),
    summary: {
      ...counts,
      // Problems: act on plus check first, the number every surface shows.
      problems: problemCounts(findings).problems,
      serious: counts.critical + counts.high,
      seriousInTests: findings.filter((f) => (f.severity === "critical" || f.severity === "high") && TEST_PATH.test(f.file || "")).length,
      total: findings.length,
      suppressed: suppressed.length,
      inconclusive: new Set(inconclusive.map((x) => x.probe)).size,
      target: result?.target || "unknown",
      timestamp: result?.timestamp || null,
    },
    findings,
    suppressed,
    inconclusive,
    egress,
    actions,
    topActions: actions.slice(0, 3),
    ownerActions,
    nis2,
    owasp,
    trend,
    timeline: timeline ? {
      source: timeline.source,
      verified: timeline.verifiedCount,
      failed: timeline.failedCount,
      open: timeline.openCount,
      medianTimeToFix: formatDuration(timeline.medianTimeToFixMs),
      entries: timeline.entries.map((x) => ({ ...x, timeToFix: formatDuration(x.timeToFixMs) })),
    } : null,
  };
}
