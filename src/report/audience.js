/**
 * Audience reports (--audience developer | owner | auditor), rendered from the
 * report model. The default report (src/report/markdown.js) is unchanged.
 *
 *   developer  findings with file:line, fix recipe or diff, how to fix, sources
 *   owner      plain-language summary, top three things to do, owner actions, trend
 *   agent      the agent brief (src/report/brief.js): verdict, act on, check first,
 *              likely noise, not checked, next
 *   auditor    scope and method, confidence and provenance, egress, inconclusive
 *              probes, suppressions (who and why), loop timeline, NIS2 and OWASP
 */
import { buildReportModel, CONFIDENCE_LABELS } from "./model.js";
import { mdInline } from "./md-escape.js";
import { footerLines } from "./footer.js";
import { buildBrief, formatBrief } from "./brief.js";
import { exitCodeOf, exitNote } from "./exit.js";

export const AUDIENCES = ["developer", "owner", "auditor", "agent"];

const METHODOLOGY_URL = "https://github.com/danoszz/penthera/blob/main/docs/METHODOLOGY.md";
const EVIDENCE_URL = "https://github.com/danoszz/penthera/blob/main/docs/evidence.md";
const SEV_TAG = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "INFO" };
const NIS2_STATUS = {
  "tested-clean": "Tested, no gaps found",
  "tested-findings": "Tested, gaps found",
  "not-run": "Not run this scan",
  evidence: "Evidence only",
  planned: "Planned",
  "out-of-scope": "Out of scope",
};

/** Inline text: one line, no table breaks, no raw HTML. */
const md = mdInline;
/** Penthera's own remediation text (lib/remediation): may hold code spans, so only fold lines. */
function prose(s) {
  return String(s ?? "").replace(/\r?\n|\r/g, " ");
}
/** A code span that its content cannot close. */
function code(s) {
  return `\`${String(s ?? "").replace(/[`\r\n]/g, " ")}\``;
}
function when(iso) {
  return iso ? `${String(iso).replace("T", " ").slice(0, 19)} UTC` : "-";
}
function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}
function sources(list) {
  return list.map((r) => `[${md(r.cite)}](${r.url})`).join(" · ");
}

function header(L, title, m) {
  L.push(`# ${title}`, "");
  L.push(`> ${md(m.target)} · scanned ${when(m.timestamp)} · Penthera v${m.tool.version}`, "");
}

function footer(L, m) {
  L.push("---", "", "*Authorized security testing only. See the Penthera README for ethical use guidelines.*", "");
  L.push(...footerLines(m));
}

function timelineSection(L, t, { heading = "## Fix timeline" } = {}) {
  if (!t) return;
  L.push(heading, "");
  L.push(`Source: ${t.source}. ${t.verified} verified · ${t.failed} failed · ${t.open} open · median time to fix ${t.medianTimeToFix}.`, "");
  L.push("| Finding | Found | Fixed | Verified | Time to fix |");
  L.push("|---------|-------|-------|----------|-------------|");
  for (const e of t.entries) {
    const name = e.title ? `${md(e.title)} (${code(e.fid)})` : code(e.fid);
    const fixed = e.fixed ? `${md(e.fixed)}${e.recipe ? ` (${code(e.recipe)})` : ""}` : "-";
    const verified = e.verified ? md(e.verified) : e.failed ? `**failed** ${md(e.failed)}` : "-";
    L.push(`| ${name} | ${md(e.found || "-")} | ${fixed} | ${verified} | ${e.timeToFix} |`);
  }
  L.push("");
}

function inconclusiveSection(L, m) {
  if (!m.inconclusive.length) return;
  L.push("## Inconclusive probes", "");
  L.push(`${plural(m.summary.inconclusive, "probe")} could not complete. Their silence is not a clean result.`, "");
  L.push("| Probe | URL | Error | Count |");
  L.push("|-------|-----|-------|-------|");
  for (const e of m.inconclusive) L.push(`| ${md(e.probe)} | ${code(e.url)} | ${md(e.message)} | ${e.count} |`);
  L.push("");
}

export function formatDeveloperReport(m) {
  const L = [];
  header(L, "Security findings for developers", m);
  const s = m.summary;
  L.push(`${plural(s.total, "finding")}: ${s.critical} critical · ${s.high} high · ${s.medium} medium · ${s.low} low · ${s.info} info.`);
  if (s.suppressed) L.push(`${s.suppressed} suppressed (listed at the end).`);
  if (m.exitNote) L.push("", md(m.exitNote));
  L.push("");
  if (m.findings.some((f) => f.recipe && !f.diff)) {
    L.push(`Findings with a recipe can be fixed locally: ${code("penthera fix --plan")} shows the diff, ${code("penthera fix --apply <id>")} applies it.`, "");
  }
  for (const f of m.findings) {
    L.push(`### ${f.n}. [${SEV_TAG[f.severity] || "INFO"}] ${md(f.title)}`, "");
    if (f.location) L.push(`- **Where:** ${f.url ? md(f.location) : code(f.location)}`);
    L.push(`- **Confidence:** ${f.confidence}${f.source ? ` (${md(f.source)})` : ""}${f.fid ? ` · id ${code(f.fid)}` : ""}`);
    if (f.recipe) L.push(`- **Fix recipe:** ${code(f.recipe)}`);
    if (f.fixText) L.push(`- **How to fix:** ${prose(f.fixText)}`);
    if (f.sources.length) L.push(`- **Sources:** ${sources(f.sources)}`);
    if (f.description) L.push("", md(f.description));
    if (f.diff) {
      const fence = "`".repeat(Math.max(3, ...[...String(f.diff).matchAll(/`+/g)].map((x) => x[0].length + 1)));
      L.push("", `${fence}diff`, String(f.diff).replace(/\n$/, ""), fence);
    }
    L.push("");
  }
  inconclusiveSection(L, m);
  timelineSection(L, m.timeline);
  if (m.suppressed.length) {
    L.push("## Suppressed", "");
    for (const x of m.suppressed) L.push(`- ${md(x.title)} (${code(x.fid)}): ${md(x.reason)} (${md(x.actor)}, ${x.by})`);
    L.push("");
  }
  footer(L, m);
  return L.join("\n");
}

export function formatOwnerReport(m) {
  const L = [];
  header(L, "Security summary", m);
  const s = m.summary;
  L.push("## In short", "");
  if (s.total === 0 && m.exitCode) {
    L.push(`Penthera checked ${md(m.target)}. ${md(m.exitNote)}`);
  } else if (s.total === 0) {
    L.push(`Penthera checked ${md(m.target)} and found no problems in the areas it tested.`);
  } else {
    const parts = [];
    if (s.serious) parts.push(`**${plural(s.serious, "serious problem")}** to fix this week`);
    if (s.medium) parts.push(`${s.medium} moderate`);
    if (s.low) parts.push(`${s.low} minor`);
    if (s.info) parts.push(`${plural(s.info, "note")}`);
    L.push(`Penthera checked ${md(m.target)} and found ${parts.join(", ")}.`);
    if (s.serious) L.push("Look at the serious ones first: if they are real, an attacker could use them.");
    else if (!m.exitCode) L.push("Nothing here needs an emergency response.");
    if (m.exitNote) L.push(md(m.exitNote));
    if (s.seriousInTests) L.push(`${s.seriousInTests === s.serious ? (s.serious === 1 ? "It is" : "All of them are") : `${s.seriousInTests} of them ${s.seriousInTests === 1 ? "is" : "are"}`} in test or fixture files. If those values are made up, set them aside in penthera.suppress.json with a reason.`);
  }
  if (s.inconclusive) L.push(`${plural(s.inconclusive, "check")} could not finish, so those areas are untested, not clean.`);
  if (s.suppressed) L.push(`${plural(s.suppressed, "known issue")} ${s.suppressed === 1 ? "was" : "were"} set aside on purpose by someone on the team (the auditor report lists who and why).`);
  L.push("");

  if (m.topActions.length) {
    L.push("## What to do first", "");
    m.topActions.forEach((a, i) => {
      L.push(`${i + 1}. **${prose(a.action)}** (${a.effort}${a.ownerAction ? ", needs you" : ", a developer can do this"}). ${prose(a.why)}`);
    });
    L.push("");
  }

  if (m.ownerActions.length) {
    L.push("## Things only you can do", "");
    L.push("A tool or a developer cannot do these for you: they need account access, a provider dashboard or a DNS change.", "");
    for (const a of m.ownerActions) L.push(`- **${prose(a.action)}**${a.fix ? `: ${prose(a.fix)}` : ""}`);
    L.push("");
  }

  if (m.trend.length > 1) {
    const first = m.trend[0];
    const last = m.trend[m.trend.length - 1];
    const dir = last.serious < first.serious ? "down" : last.serious > first.serious ? "up" : "flat";
    L.push("## Trend", "");
    L.push(`Serious problems went from ${first.serious} to ${last.serious} over the last ${m.trend.length} scans (${dir}).`, "");
    L.push("| Scan | Serious | Moderate | Minor | Total |");
    L.push("|------|---------|----------|-------|-------|");
    for (const t of m.trend) L.push(`| ${t.date} | ${t.serious} | ${t.medium} | ${t.low} | ${t.total} |`);
    L.push("");
  }

  if (m.timeline) {
    const t = m.timeline;
    L.push("## Fixes", "");
    L.push(`${t.verified} ${t.verified === 1 ? "fix" : "fixes"} verified by a re-scan, ${t.failed} failed, ${t.open} still open. Typical time to fix: ${t.medianTimeToFix}.`, "");
  }
  footer(L, m);
  return L.join("\n");
}

export function formatAuditorReport(m) {
  const L = [];
  header(L, "Security evidence report", m);
  L.push("> Automated technical evidence. It is not an audit opinion, a compliance determination or a certification.", "");
  if (m.exitNote) L.push(`**${md(m.exitNote)}**`, "");

  L.push("## 1. Scope and method", "");
  L.push("| | |", "|---|---|");
  L.push(`| **Target** | ${code(m.target)} |`);
  L.push(`| **Scan time** | ${when(m.timestamp)} |`);
  if (m.duration) L.push(`| **Duration** | ${m.duration} |`);
  L.push(`| **Modes** | ${md(m.modes || "-")} |`);
  if (m.profile) L.push(`| **Profile** | ${md(m.profile)} |`);
  L.push(`| **Network** | ${m.egress ? md(m.egress.mode) : "not recorded"} |`);
  L.push(`| **Tool** | Penthera v${m.tool.version} |`);
  L.push("");
  if (m.probes.length) L.push(`Probes that ran: ${m.probes.map(code).join(", ")}.`, "");
  L.push(`Method, threat model and limits: [docs/METHODOLOGY.md](${METHODOLOGY_URL}). A probe that is not listed did not run, and an area it covers is untested.`, "");

  L.push("## 2. Confidence and provenance", "");
  L.push("Every finding carries a confidence label that says how sure the scanner is that the issue is real, separate from its severity.", "");
  L.push("| Label | Meaning | This scan |");
  L.push("|-------|---------|-----------|");
  for (const c of CONFIDENCE_LABELS) {
    L.push(`| ${code(c.label)} | ${c.meaning} | ${m.findings.filter((f) => f.confidence === c.label).length} |`);
  }
  L.push("");
  if (m.findings.length) {
    L.push("| # | Id | Finding | Severity | Confidence | Source / method | Collected | Location |");
    L.push("|---|----|---------|----------|------------|-----------------|-----------|----------|");
    for (const f of m.findings) {
      L.push(`| ${f.n} | ${f.fid ? code(f.fid) : "-"} | ${md(f.title)} | ${f.severity} | ${f.confidence} | ${md(f.source || "-")} / ${md(f.method || "-")} | ${when(f.collectedAt)} | ${f.location ? code(f.location) : "-"} |`);
    }
  } else {
    L.push("No findings in the tested areas.");
  }
  L.push("");

  L.push("## 3. Network egress", "");
  if (m.egress) {
    L.push(`- **Mode:** ${md(m.egress.mode)}`);
    L.push(`- **User-Agent:** ${code(m.egress.userAgent)}`);
    L.push(`- **Third-party hosts contacted:** ${m.egress.thirdPartyHosts.length ? m.egress.thirdPartyHosts.map((h) => `${code(h.host)} (${h.requests})`).join(", ") : "none"}`);
    if (m.egress.blocked.length) L.push(`- **Blocked by --offline:** ${m.egress.blocked.map((h) => `${code(h.host)} (${h.requests})`).join(", ")}`);
  } else {
    L.push("No egress record (a repo-only or machine scan makes no network requests to the target).");
  }
  L.push("");
  inconclusiveSection(L, m);

  L.push("## 4. Suppressions", "");
  if (m.suppressed.length) {
    L.push("These findings were hidden from the results by a person's decision. Each needs a reason; review them.", "");
    L.push("| Id | Finding | Severity | Who | Why | Recorded in | Expires |");
    L.push("|----|---------|----------|-----|-----|-------------|---------|");
    for (const x of m.suppressed) {
      L.push(`| ${code(x.fid)} | ${md(x.title)} | ${x.severity} | ${md(x.actor)} | ${md(x.reason)} | ${x.by} | ${x.expires ? md(x.expires) : "never"} |`);
    }
  } else {
    L.push("None. No finding was hidden from this report.");
  }
  L.push("");

  timelineSection(L, m.timeline, { heading: "## 5. Fix timeline" });

  L.push(`## ${m.timeline ? 6 : 5}. NIS2 Article 21(2) mapping`, "");
  L.push("Technical evidence toward each measure, based on the probes that ran. Organisational measures need human process.", "");
  L.push("| Art. 21(2) | Measure | This scan | Findings |");
  L.push("|-----------|---------|-----------|----------|");
  for (const x of m.nis2) L.push(`| (${x.id}) | ${md(x.title)} | ${NIS2_STATUS[x.status] || x.status} | ${x.findings || "-"} |`);
  L.push("");

  L.push(`## ${m.timeline ? 7 : 6}. OWASP mapping`, "");
  if (m.owasp.length) {
    L.push("| OWASP category | Findings | Ids |");
    L.push("|----------------|----------|-----|");
    for (const o of m.owasp) L.push(`| ${md(o.id)} | ${o.count} | ${md(o.findings)} |`);
  } else {
    L.push("No finding maps to an OWASP Top 10 category.");
  }
  L.push("");
  const wstg = [...new Set(m.findings.flatMap((f) => f.wstg))].sort();
  if (wstg.length) L.push(`OWASP WSTG test areas with findings: ${wstg.map(code).join(", ")}.`, "");

  L.push("## Verifying this report", "");
  L.push(`If this report came in an evidence bundle, check that nothing in it changed since it was produced: ${code("penthera evidence verify <dir> --allowed-signers <file>")}. See [docs/evidence.md](${EVIDENCE_URL}).`, "");
  footer(L, m);
  return L.join("\n");
}

const FORMATTERS = { developer: formatDeveloperReport, owner: formatOwnerReport, auditor: formatAuditorReport };

/** Render the report for one audience. Throws on an unknown audience. */
export function formatAudienceReport(result, audience, { version, footer = true } = {}) {
  if (audience === "agent") return formatBrief(result.brief || buildBrief(result), { footer });
  const fmt = FORMATTERS[audience];
  if (!fmt) throw new Error(`Unknown --audience "${audience}". Use one of: ${AUDIENCES.join(", ")}.`);
  return fmt({ ...buildReportModel(result, { version }), footer, exitCode: exitCodeOf(result), exitNote: exitNote(result) });
}
