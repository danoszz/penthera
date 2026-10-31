/**
 * The agent brief (docs/research/spec-agent-brief.md): one short, fixed-shape
 * summary an AI assistant can pass on as it is. Rules fill every section:
 *
 *   Verdict       Fix now | Review | Nothing to fix | Nothing to assess, with the counts behind it
 *   Act on        findings that need a change, grouped by place and fix
 *   Check first   heuristic, low or dependency-capability findings
 *   Likely noise  findings demoted by a deterministic reason, one line per group
 *   Not checked   what the scan did not read (always shown)
 *   Next          exact commands, at most three
 *
 * No model is involved: a finding's bucket comes from fields the engines set
 * (severity, confidence, localOnly, path, source). Every finding lands in
 * exactly one bucket or group count.
 */
import { cleanText } from "../mcp/results.js";
import { mdInline } from "./md-escape.js";
import { footerLines } from "./footer.js";
import { exitCodeOf, exitReason, isSevere } from "./exit.js";

export const BRIEF_SCHEMA = "penthera.brief/1";
// Exit 0 is not "safe to publish". Penthera tests these from outside; a pass shows
// only that no rule matched, with or without a session cookie.
export const NOT_PROVEN_NOTE = "This run does not prove login, access rules or payments are right.";

export const VERDICTS = { fix: "Fix now", review: "Review", clean: "Nothing to fix", none: "Nothing to assess" };

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const MAX_ITEMS = 8;
const MAX_EXAMPLES = 3;
const MAX_NEXT = 3;

// Generated or build output: nobody edits these files, so a hit in them is noise.
const GENERATED = /(?:^|\/)(?:\.next[^/]*|dist|build|out|\.turbo|\.svelte-kit|\.nuxt|\.output|__pycache__|coverage)\//;
const FIXTURE = /(?:^|\/)(?:fixtures?|__fixtures__|testdata|__mocks__)\//;
// An info finding that says something was not found or not run belongs under Not checked.
const GAP = /^no\b|not (?:found|run|read|checked|supported)|did not|skipped|unreachable/i;
const URL_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

const NOISE_REASONS = {
  "local-only": "in files git ignores, never committed",
  generated: "in generated build output",
  fixture: "in test fixtures",
};

const SKIP_LABELS = {
  "skipped-folder": "in folders the scan skips (virtualenvs, caches, folders git ignores)",
  "type-not-read": "of a file type the scan does not read",
  "too-large": "over the size limit",
  "no-api-surface": "not analysed because no API routes were found",
  "language-not-supported": "in a language route analysis does not support",
};

const text = (s, max = 300) => cleanText(String(s ?? ""), max);

function pathOf(f) {
  const u = f.file || f.url;
  return u && !URL_RE.test(String(u)) ? String(u) : null;
}

function whereOf(f) {
  const p = pathOf(f);
  if (p) return Number.isInteger(f.line) && f.line > 0 ? `${p}:${f.line}` : p;
  return f.url ? String(f.url) : null;
}

/** Which bucket a finding goes in, and for noise, why. First match wins. */
export function bucketOf(f, { skillTarget = false } = {}) {
  const p = pathOf(f) || "";
  if (f.localOnly) return { bucket: "noise", reason: "local-only" };
  // A skill ships its dist/ and build/, so in a named skill those are real code.
  if (!skillTarget && GENERATED.test(p)) return { bucket: "noise", reason: "generated" };
  if (FIXTURE.test(p)) return { bucket: "noise", reason: "fixture" };
  if (f.severity === "info") return { bucket: "info" };
  if (["potential", "needs-human-review"].includes(f.confidence)) return { bucket: "check" };
  if (f.severity === "low") return { bucket: "check" };
  if (f.category === "dependency-risk") return { bucket: "check" };
  return { bucket: "act" };
}

/** A title with its own path taken out, so one rule across many files reads as one line. */
function genericTitle(f) {
  const p = pathOf(f);
  let t = String(f.title || "Finding");
  if (p && t.includes(p)) t = t.replace(p, "").replace(/\s+(?:in|at|from)\s*$/i, "").trim();
  return t;
}

function firstSentence(s, max = 220) {
  const t = String(s ?? "").replace(/\s+/g, " ").trim();
  const m = /^(.+?[.!?])(?:\s|$)/.exec(t);
  return text(m ? m[1] : t, max);
}

/** Group findings: same place and same fix, or same rule and same generic title. */
function groupFindings(list, keyOf) {
  const groups = new Map();
  for (const f of list) {
    const k = keyOf(f);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(f);
  }
  return [...groups.values()].sort((a, b) =>
    (SEV_ORDER[a[0].severity] ?? 9) - (SEV_ORDER[b[0].severity] ?? 9) || b.length - a.length);
}

const ruleOf = (f) => String(f.rule || f.templateId || f.category || "unknown");

function item(group) {
  const f = group[0];
  const paths = [...new Set(group.map(whereOf).filter(Boolean))];
  const titles = [...new Set(group.map((g) => text(g.title, 200)))];
  const sameWhere = paths.length === 1;
  return {
    title: text(sameWhere && titles.length > 1 ? `${paths[0]}: ${titles.length} findings` : group.length > 1 ? genericTitle(f) : f.title, 300),
    severity: f.severity,
    confidence: f.confidence || "likely",
    count: group.length,
    where: paths.slice(0, MAX_EXAMPLES).map((p) => text(p, 300)),
    more: Math.max(0, paths.length - MAX_EXAMPLES),
    why: sameWhere && titles.length > 1 ? titles.join("; ") : firstSentence(f.description),
    fix: fixOf(group),
    rules: [...new Set(group.map(ruleOf))].map((r) => text(r, 120)),
  };
}

/** Merge rule groups that all sit in one file and share a category. */
function regroupByFile(groups) {
  const merged = new Map();
  for (const g of groups) {
    const paths = new Set(g.map(pathOf));
    const k = paths.size === 1 && pathOf(g[0]) ? `file|${pathOf(g[0])}|${g[0].category}` : `rule|${ruleOf(g[0])}|${genericTitle(g[0])}`;
    merged.set(k, [...(merged.get(k) || []), ...g]);
  }
  return [...merged.values()].sort((a, b) =>
    (SEV_ORDER[a[0].severity] ?? 9) - (SEV_ORDER[b[0].severity] ?? 9) || b.length - a.length);
}

function fixOf(group) {
  const r = group.find((g) => g.remediation)?.remediation;
  return r ? firstSentence(r, 300) : null;
}

function noiseGroup(group, reason) {
  const f = group[0];
  const paths = [...new Set(group.map(whereOf).filter(Boolean))];
  const titles = [...new Set(group.map(genericTitle))];
  const label = titles.length === 1 ? titles[0] : `${f.category || "other"} findings (${titles.slice(0, MAX_EXAMPLES).join(", ")}${titles.length > MAX_EXAMPLES ? ", …" : ""})`;
  return {
    reason,
    label: text(label, 200),
    text: NOISE_REASONS[reason],
    count: group.length,
    severe: group.filter(isSevere).length,
    where: paths.slice(0, MAX_EXAMPLES).map((p) => text(p, 300)),
    more: Math.max(0, paths.length - MAX_EXAMPLES),
    rules: [...new Set(group.map(ruleOf))].map((r) => text(r, 120)),
  };
}

function coverageLines(coverage) {
  if (!coverage) return [];
  const out = [];
  for (const fam of coverage.families || []) {
    if (!fam.ran) {
      const why = Object.entries(fam.skipped || {}).map(([k, n]) => `${n} files ${SKIP_LABELS[k] || k.replace(/-/g, " ")}`).join("; ");
      out.push(`${fam.label} did not run${why ? `: ${why}` : ""}.`);
      continue;
    }
    for (const [k, n] of Object.entries(fam.skipped || {})) {
      if (n > 0) out.push(`${fam.label}: ${n} files ${SKIP_LABELS[k] || k.replace(/-/g, " ")} were not read.`);
    }
  }
  if (coverage.truncated) out.push(`The file count stopped at ${coverage.files}; files past that were not counted.`);
  return out;
}

/** A command a finding's own text tells the user to run (`penthera agents --pin`). */
function commandIn(f) {
  const m = /`(penthera [^`]{1,120})`/.exec(`${f.description || ""} ${f.remediation || ""}`);
  return m ? m[1] : null;
}

/**
 * Build the brief from one or more Penthera results (a repo, deps and agents
 * scan merge into one brief).
 * @param {object|object[]} results
 * @param {{ reports?: string[], notRunCommand?: (n: object) => string }} [opts]
 *   reports: paths of the full reports, for Next; notRunCommand: how to name a
 *   scan that did not run (the MCP server names its tool instead of the CLI)
 */
export function buildBrief(results, { reports = [], notRunCommand = (n) => String(n.command).replace("<path>", ".") } = {}) {
  const list = (Array.isArray(results) ? results : [results]).filter(Boolean);
  const findings = list.flatMap((r) => r.findings || []);
  const modes = [...new Set(list.flatMap((r) => r.modes || (r.mode ? [r.mode] : [])))];
  const targets = [...new Set(list.map((r) => r.target).filter(Boolean))];

  const by = { act: [], check: [], noise: [], info: [] };
  const noiseReason = new Map();
  for (const r of list) for (const f of r.findings || []) {
    const b = bucketOf(f, { skillTarget: !!r.agents?.skillTarget });
    by[b.bucket].push(f);
    if (b.reason) noiseReason.set(f, b.reason);
  }

  // One line per file and kind of problem (two advisories for one pin, three
  // sinks in one route file); without a file, one line per rule.
  const act = regroupByFile(groupFindings(by.act, (f) => `${ruleOf(f)}|${genericTitle(f)}`)).map(item);
  const check = groupFindings(by.check, (f) => `${f.category}|${ruleOf(f)}|${genericTitle(f)}`).map(item);
  const noise = groupFindings(by.noise, (f) => `${noiseReason.get(f)}|${f.category}`)
    .map((g) => noiseGroup(g, noiseReason.get(g[0])));

  const notChecked = [];
  for (const r of list) notChecked.push(...coverageLines(r.coverage), ...(r.agents?.notChecked || []).map((l) => text(l, 300)), ...(r.notChecked || []).map((l) => text(l, 300)));
  const next = [];
  for (const f of by.info) {
    const cmd = commandIn(f);
    if (cmd) next.push({ command: text(cmd, 200), why: text(f.title, 200) });
    else if (GAP.test(f.title || "")) notChecked.push(`${text(f.title, 200)}${f.description ? `: ${firstSentence(f.description)}` : ""}`);
  }
  // Scans that were not part of this run, unless another result in the brief covers them.
  for (const r of list) {
    for (const n of r.coverage?.notRun || []) {
      if (!modes.includes(n.id)) next.push({ command: text(notRunCommand(n), 200), why: `${text(n.label, 100)} was not part of this run` });
    }
  }
  if (!notChecked.length) notChecked.push("The scan reported nothing it skipped. No finding is still not proof of safety: Penthera reports what its rules match.");

  const actHigh = act.some((i) => i.severity === "critical" || i.severity === "high");
  if (!actHigh && modes.some((m) => m === "repo" || m === "url")) notChecked.unshift(NOT_PROVEN_NOTE);
  // A null grade means the agents audit read nothing: no finding there is no result.
  const nothingRead = list.length > 0 && !findings.length && list.every((r) => r.agents?.grade === null);
  // The verdict never reads as clean on a run that fails: it and the exit code agree.
  const exitCode = Math.max(0, ...list.map(exitCodeOf));
  const verdict = actHigh ? VERDICTS.fix : act.length || check.length || exitCode ? VERDICTS.review : nothingRead ? VERDICTS.none : VERDICTS.clean;

  return {
    schema: BRIEF_SCHEMA,
    verdict,
    exit_code: exitCode,
    exit_reason: exitCode === 2 || !actHigh ? exitReason(list) : null,
    target: text(targets.join(", "), 500),
    scanned: modes,
    counts: {
      act: by.act.length,
      check: by.check.length,
      noise: by.noise.length,
      info: by.info.length,
      total: findings.length,
    },
    act_on: act,
    check_first: check,
    likely_noise: noise,
    not_checked: [...new Set(notChecked)],
    next: dedupeNext(next).slice(0, MAX_NEXT),
    reports: reports.map((p) => text(p, 300)),
  };
}

function dedupeNext(list) {
  const seen = new Set();
  return list.filter((n) => (seen.has(n.command) ? false : seen.add(n.command)));
}

const MODE_NAMES = { url: "live URL", repo: "repo", deps: "dependencies", agents: "agent config" };
const md = mdInline;
const code = (s) => `\`${String(s ?? "").replace(/[`\r\n]/g, " ")}\``;

function whereText(i) {
  if (!i.where.length) return "";
  return `${i.where.map(code).join(", ")}${i.more ? ` and ${i.more} more` : ""}`;
}

/**
 * The brief as Markdown, about 40 lines at most. The product footer only goes
 * on a report file (--audience agent); stdout and MCP results leave it off.
 */
export function formatBrief(b, { footer = false } = {}) {
  const L = [];
  const c = b.counts;
  const parts = [`${c.act} to act on`, `${c.check} to check first`, `${c.noise} likely noise`];
  if (c.info) parts.push(`${c.info} info in the full report`);
  const scanned = b.scanned.length ? ` Scanned: ${b.scanned.map((m) => MODE_NAMES[m] || m).join(", ")}.` : "";
  L.push(`**Penthera: ${b.verdict}.** ${parts.join(", ")}.${scanned}`, "");
  if (b.exit_reason) L.push(md(b.exit_reason), "");

  if (b.act_on.length) {
    L.push("### Act on", "");
    b.act_on.slice(0, MAX_ITEMS).forEach((i, n) => {
      const where = whereText(i);
      const count = i.count > 1 && i.where.length > 1 ? ` (${i.count} findings)` : "";
      const tail = [i.why && md(i.why), i.fix && `Fix: ${md(i.fix)}`, i.rules.map(code).join(", ")].filter(Boolean).join(" ");
      L.push(`${n + 1}. **${md(i.title)}**${count} [${i.severity}]${where ? ` in ${where}` : ""}. ${tail}`);
    });
    if (b.act_on.length > MAX_ITEMS) L.push(`${b.act_on.length - MAX_ITEMS} more in the full report.`);
    L.push("");
  }
  if (b.check_first.length) {
    L.push("### Check first", "");
    for (const i of b.check_first.slice(0, MAX_ITEMS)) {
      const where = whereText(i);
      L.push(`- **${md(i.title)}**${i.count > 1 ? ` (${i.count})` : ""} [${i.severity}, ${i.confidence}]${where ? ` in ${where}` : ""}.${i.why ? ` ${md(i.why)}` : ""}`);
    }
    if (b.check_first.length > MAX_ITEMS) L.push(`- ${b.check_first.length - MAX_ITEMS} more in the full report.`);
    L.push("");
  }
  if (b.likely_noise.length) {
    L.push("### Likely noise", "");
    for (const g of b.likely_noise.slice(0, MAX_ITEMS)) {
      const where = whereText(g);
      const severe = g.severe ? ` (${g.severe} critical or high)` : "";
      L.push(`- ${g.count} × ${md(g.label)}${severe}, ${g.text}${where ? `: ${where}` : ""}.`);
    }
    L.push("");
  }
  L.push("### Not checked", "");
  for (const s of b.not_checked.slice(0, MAX_ITEMS)) L.push(`- ${md(s)}`);
  L.push("");
  if (b.next.length || b.reports.length) {
    L.push("### Next", "");
    for (const n of b.next) L.push(`- ${code(n.command)}: ${md(n.why)}`);
    if (b.reports.length) L.push(`- Full report${b.reports.length > 1 ? "s" : ""}: ${b.reports.map(code).join(", ")}`);
    L.push("");
  }
  if (footer) L.push("---", "", ...footerLines({ footer }));
  return L.join("\n");
}
