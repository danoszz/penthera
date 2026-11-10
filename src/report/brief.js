/**
 * The agent brief (docs/research/spec-agent-brief.md): one short, fixed-shape
 * summary an AI assistant can pass on as it is. Rules fill every section:
 *
 *   Verdict       Fix now | Review | Nothing to fix now | Nothing to fix | Nothing to assess | Site not read | N suppressed, with the counts behind it; `verdict_id` names it without string matching;
 *                 then the one thing to do first (`first`), when there is anything to act on or check
 *   Act on        findings that need a change, grouped by place and fix
 *   Check first   heuristic, low or dependency-capability findings
 *   Likely noise  findings demoted by a deterministic reason, one line per group
 *   Not checked   what the scan did not read (always shown)
 *   Next          exact commands, at most three
 *
 * No model is involved: a finding's bucket comes from fields the engines set
 * (severity, confidence, localOnly, path, source). Every finding lands in
 * exactly one bucket or group count. The "why it matters" line and the first
 * step come from a fixed table in plain words (src/report/plain.js), keyed on
 * the rule; they explain a finding and never move it.
 */
import { cleanText } from "../mcp/results.js";
import { scrubDeep } from "../../lib/scrub.js";
import { mdInline } from "./md-escape.js";
import { footerLines } from "./footer.js";
import { exitCodeOf, exitReason, isSevere } from "./exit.js";
import { hintCommand } from "../utils/invocation.js";
import { notRead, readNothing, siteUnread, SITE_NOT_READ } from "./unread.js";
import { unreachableText } from "./reach.js";
import { bucketOf, pathOf, plural, problemsText } from "./counts.js";
import { exploitabilityFor, matchLabel } from "../../lib/provenance.js";
import { plainWords } from "./plain.js";

export { bucketOf };

export const BRIEF_SCHEMA = "penthera.brief/1";
// Exit 0 is not "safe to publish". Penthera tests these from outside; a pass shows
// only that no rule matched, with or without a session cookie.
export const NOT_PROVEN_NOTE = "This run does not prove login, access rules or payments are right.";

// check: only things to check first (a header read from code, which the host
// may still add) and nothing to act on: not a problem yet, and not clean either.
export const VERDICTS = { fix: "Fix now", review: "Review", check: "Nothing to fix now", clean: "Nothing to fix", none: "Nothing to assess", unread: "Site not read" };

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const MAX_ITEMS = 8;
const MAX_EXAMPLES = 3;
const MAX_NEXT = 3;

// An info finding that says something was not found or not run belongs under Not checked.
const GAP = /^no\b|not (?:found|run|read|checked|supported)|did not|skipped|unreachable/i;

const NOISE_REASONS = {
  "local-only": "in files git ignores, never committed",
  generated: "in generated build output",
  fixture: "in test fixtures",
  "test-file": "in test files",
  vendored: "in vendored or minified third-party files",
  example: "in examples, demos or samples",
};

const SKIP_LABELS = {
  "skipped-folder": "in folders the scan skips (virtualenvs, caches, folders git ignores)",
  "type-not-read": "of a file type the scan does not read",
  "too-large": "over the size limit",
  "sink-file-cap": "past the eval and exec check's 5,000-file limit",
  "no-api-surface": "not analysed because no API routes were found",
  "language-not-supported": "in a language route analysis does not support",
  "settings-file-cap": "past the settings check's 5,000-file limit",
  refused: "refused (a link out of the project, a device or a FIFO)",
  unreadable: "that could not be read",
};

const text = (s, max = 300) => cleanText(String(s ?? ""), max);

function whereOf(f) {
  const p = pathOf(f);
  if (p) return Number.isInteger(f.line) && f.line > 0 ? `${p}:${f.line}` : p;
  return f.url ? String(f.url) : null;
}

/** A title with its own path taken out, so one rule across many files reads as one line. */
function genericTitle(f) {
  const p = pathOf(f);
  let t = String(f.title || "Finding");
  if (p && t.includes(p)) {
    t = t.replace(p, "").trimEnd();
    const tail = /\s(?:in|at|from)$/i.exec(t); // a dangling "in", "at" or "from", found without a regex that rescans the run
    if (tail) t = t.slice(0, tail.index);
    t = t.trim();
  }
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

/** "critical 1, high 2" for a group of mixed severity, so its count does not read as all critical. */
function severityMix(group) {
  const counts = {};
  for (const g of group) counts[g.severity] = (counts[g.severity] || 0) + 1;
  const names = Object.keys(counts).sort((a, b) => (SEV_ORDER[a] ?? 9) - (SEV_ORDER[b] ?? 9));
  return names.length > 1 ? names.map((n) => `${n} ${counts[n]}`).join(", ") : null;
}

export const SUPPRESS_COMMAND = 'penthera memory suppress <fid> --reason "<why>"';
const SUPPRESS_WHY = "It sets the finding aside on this machine; add the fid and reason to penthera.suppress.json to share that with your team. Both apply to scans with --memory, and the report lists what they hide. The fid is next to each finding in the JSON and Markdown reports";

function item(group) {
  const f = group[0];
  const plain = plainWords(f);
  const paths = [...new Set(group.map(whereOf).filter(Boolean))];
  const titles = [...new Set(group.map((g) => text(g.title, 200)))];
  const sameWhere = paths.length === 1;
  return {
    title: text(sameWhere && titles.length > 1 ? `${paths[0]}: ${titles.length} findings` : group.length > 1 ? genericTitle(f) : f.title, 300),
    severity: f.severity,
    mix: severityMix(group),
    confidence: f.confidence || "likely",
    exploitability: f.exploitability || exploitabilityFor(f),
    count: group.length,
    where: paths.slice(0, MAX_EXAMPLES).map((p) => text(p, 300)),
    more: Math.max(0, paths.length - MAX_EXAMPLES),
    why: sameWhere && titles.length > 1 ? titles.join("; ") : firstSentence(f.description),
    fix: fixOf(group),
    // Added in 2.5.0: what could happen, in words a non-security reader follows, and the first step.
    why_it_matters: plain ? plain.why : null,
    first_step: plain ? plain.act : null,
    rules: [...new Set(group.map(ruleOf))].map((r) => text(r, 120)),
  };
}

/**
 * The one thing to do first: the top Act on item (the most severe, then the
 * largest group), else the top Check first item. Null when there is neither.
 */
function firstOf(act, check) {
  const i = act[0] || check[0];
  if (!i) return null;
  const where = i.where[0] || null;
  const action = i.first_step || i.fix || (act[0] ? `Fix ${i.title}${where ? ` in ${where}` : ""}.` : `Check ${i.title}${where ? ` in ${where}` : ""}.`);
  return { title: i.title, where, action: text(action, 300), why_it_matters: i.why_it_matters, from: act[0] ? "act_on" : "check_first" };
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

const rootOutputRead = (dirs) => `The secret scan ran only its fixed-shape rules (key prefixes, private keys) in ${dirs.map((d) => `${d}/`).join(", ")} at the repo root (env files and shell scripts there got every rule), and none in such a folder git ignores. Below the root, folders with these names get every rule.`;

const filesText = (n) => `${n} file${n === 1 ? "" : "s"}`;

function coverageLines(coverage) {
  if (!coverage) return [];
  const out = [];
  for (const fam of coverage.families || []) {
    if (!fam.ran) {
      const why = Object.entries(fam.skipped || {}).map(([k, n]) => `${filesText(n)} ${SKIP_LABELS[k] || k.replace(/-/g, " ")}`).join("; ");
      out.push(`${fam.label} did not run${why ? `: ${why}` : ""}.`);
      continue;
    }
    for (const [k, count] of Object.entries(fam.skipped || {})) {
      // A file that is not a route but was read by the settings check was read.
      const n = k === "not-a-route" ? count - (fam.notRouteReadBySettings || 0) : count;
      if (n > 0) out.push(`${fam.label}: ${filesText(n)} ${SKIP_LABELS[k] || k.replace(/-/g, " ")} ${n === 1 ? "was" : "were"} not read.`);
    }
  }
  if (coverage.rootOutputDirs?.length) out.push(rootOutputRead(coverage.rootOutputDirs));
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
 *   reports: paths of the full reports, for Next; fixes: what `penthera fix`
 *   could do ({ count, command }); limits: what this kind of scan
 *   never checks, for Not checked; moreNext: extra Next items; notRunCommand: how to name a
 *   scan that did not run (the MCP server names its tool instead of the CLI)
 */
export function buildBrief(results, { reports = [], fixes = null, limits = [], moreNext = [], notRunCommand = (n) => String(n.command).replace("<path>", ".") } = {}) {
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

  const notChecked = [...limits];
  for (const r of list) for (const t of r.giants?.tools || []) if (t.status !== "ran") notChecked.push(`${t.id}: ${t.status}`);
  for (const r of list) notChecked.push(...coverageLines(r.coverage), ...(r.agents?.notChecked || []).map((l) => text(l, 300)), ...(r.notChecked || []).map((l) => text(l, 300)));
  const next = [];
  if (fixes) {
    const problems = by.act.length + by.check.length;
    // How many a recipe matches; `penthera fix --plan` says how many fixes it plans for them.
    const lead = fixes.count ? `A fix recipe matches ${fixes.count} of the ${plural(problems, "problem")}. ` : "Plans a fix for each problem it can. ";
    next.push({ command: text(fixes.command, 200), why: `${lead}It shows each diff and changes nothing until you approve one` });
  }
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
  next.push(...moreNext);
  // How to set aside a problem you checked: by its fid (in the JSON and the
  // Markdown report), with a reason. Only where the findings carry one.
  const setAside = (act.length || check.length) && findings.some((f) => typeof f.fid === "string")
    ? { command: SUPPRESS_COMMAND, why: SUPPRESS_WHY }
    : null;
  for (const r of list) if (r.challenge) notChecked.unshift(`${SITE_NOT_READ} ${siteUnread(r).text}`);
  if (!notChecked.length) notChecked.push("The scan reported nothing it skipped. No finding is still not proof of safety: Penthera reports what its rules match.");

  const actHigh = act.some((i) => i.severity === "critical" || i.severity === "high");
  if (!actHigh && modes.some((m) => m === "repo" || m === "url")) notChecked.unshift(NOT_PROVEN_NOTE);
  const nothingRead = list.length > 0 && findings.every((f) => f.severity === "info") && list.every(readNothing);
  // A 403 with no firewall's name on it may still be a firewall's page, so it can't read as clean.
  const forbidden = list.filter((r) => r.httpStatus === 403 && !r.challenge);
  const partly = list.some((r) => notRead(r)?.partly);
  for (const r of forbidden) notChecked.unshift(`${r.target} answered HTTP 403, which may be a firewall's page, so a clean result may say nothing about the site.`);
  // The verdict never reads as clean on a run that fails: it and the exit code agree.
  const exitCode = Math.max(0, ...list.map(exitCodeOf));
  // A firewall answered instead of the site, so nothing here describes it. The exit code doesn't move.
  const unread = list.some(siteUnread);
  // A target that was down or answered with a server error says nothing about the site either.
  const unreachable = list.flatMap((r) => (r.siteUnread ? [r.siteUnread] : r.mode === "url" && r.reachable === false ? [r] : []));
  for (const r of unreachable) notChecked.unshift(`${unreachableText(r, r.target)} The site was not checked.`);
  // A suppressed finding still exists, so an empty list here is not a clean one.
  const hidden = list.flatMap((r) => r.suppressed || []);
  const hiddenSevere = hidden.filter(isSevere).length;
  const hiddenText = `${hidden.length} suppressed${hiddenSevere ? ` (${hiddenSevere} critical or high)` : ""}`;
  // First in the list, because the brief prints only the first few.
  if (hidden.length) notChecked.unshift(`${hiddenText}: not counted here. Review them with \`penthera memory show --repo .\` and penthera.suppress.json.`);
  const quiet = hidden.length ? hiddenText : VERDICTS.clean;
  // Only things to check first, on a run that passes: "Nothing to fix now". Anything to act
  // on, a failing exit code, a 403 or a partly read site still reads as Review.
  // Suppressed findings keep their own verdict ("N suppressed"): they may hide something serious.
  const onlyCheck = !act.length && check.length && !exitCode && !forbidden.length && !partly && !hidden.length;
  const verdict = actHigh ? VERDICTS.fix : unread ? VERDICTS.unread : onlyCheck ? VERDICTS.check : act.length || check.length || exitCode || forbidden.length || partly ? VERDICTS.review : nothingRead ? VERDICTS.none : quiet;

  return {
    schema: BRIEF_SCHEMA,
    verdict,
    // Added in 2.4.0: a stable name for the verdict (fix, review, check, clean, none, unread, suppressed).
    verdict_id: Object.keys(VERDICTS).find((k) => VERDICTS[k] === verdict) || "suppressed",
    exit_code: exitCode,
    exit_reason: exitCode === 2 || !actHigh ? exitReason(list) : null,
    target: text(targets.join(", "), 500),
    scanned: unread ? modes.filter((m) => m !== "url") : modes,
    counts: {
      // Problems: act on plus check first, the number every surface shows (src/report/counts.js).
      problems: by.act.length + by.check.length,
      act: by.act.length,
      check: by.check.length,
      noise: by.noise.length,
      suppressed: hidden.length,
      info: by.info.length,
      total: findings.length,
    },
    // Added in 2.5.0: the single most important step, from the top Act on (or Check first) item.
    first: firstOf(act, check),
    act_on: act,
    check_first: check,
    likely_noise: noise,
    not_checked: [...new Set(notChecked)],
    next: dedupeNext(next).slice(0, MAX_NEXT),
    // Added in 2.4.1: how to suppress a problem you checked, by fid with a reason.
    ...(setAside ? { set_aside: setAside } : {}),
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
export function formatBrief(raw, { footer = false } = {}) {
  const b = scrubDeep(raw); // the brief's own fields are scrubbed; this covers a brief read back from a file
  const L = [];
  const c = b.counts;
  const parts = [problemsText({ problems: c.problems ?? c.act + c.check, act: c.act, check: c.check }), `${c.noise} likely noise`];
  if (c.info) parts.push(`${c.info} info in the full report`);
  const scanned = b.scanned.length ? ` Scanned: ${b.scanned.map((m) => MODE_NAMES[m] || m).join(", ")}.` : "";
  L.push(`**Penthera: ${b.verdict}.** ${parts.join(", ")}.${scanned}`, "");
  if (b.exit_reason) L.push(md(b.exit_reason), "");
  if (b.first) L.push(`**Do this first**${b.first.where ? ` (${code(b.first.where)})` : ""}: ${md(b.first.action)}${b.first.why_it_matters ? ` Why it matters: ${md(b.first.why_it_matters)}` : ""}`, "");

  if (b.act_on.length) {
    L.push("### Act on", "");
    b.act_on.slice(0, MAX_ITEMS).forEach((i, n) => {
      const where = whereText(i);
      const count = i.count > 1 && i.where.length > 1 ? ` (${i.count} findings)` : "";
      const fix = i.fix || i.first_step;
      const tail = [i.why_it_matters ? `Why it matters: ${md(i.why_it_matters)}` : i.why && md(i.why), fix && `Fix: ${md(fix)}`, i.rules.map(code).join(", ")].filter(Boolean).join(" ");
      L.push(`${n + 1}. **${md(i.title)}**${count} [${i.mix || i.severity}]${where ? ` in ${where}` : ""}. ${tail}`);
    });
    if (b.act_on.length > MAX_ITEMS) L.push(`${b.act_on.length - MAX_ITEMS} more in the full report.`);
    L.push("");
  }
  if (b.check_first.length) {
    L.push("### Check first", "");
    for (const i of b.check_first.slice(0, MAX_ITEMS)) {
      const where = whereText(i);
      const why = i.why_it_matters ? `Why it matters: ${i.why_it_matters}` : i.why;
      L.push(`- **${md(i.title)}**${i.count > 1 ? ` (${i.count})` : ""} [${i.mix || i.severity}, ${matchLabel(i.confidence)}]${where ? ` in ${where}` : ""}.${why ? ` ${md(why)}` : ""}`);
    }
    if (b.check_first.length > MAX_ITEMS) L.push(`- ${b.check_first.length - MAX_ITEMS} more in the full report.`);
    L.push("");
  }
  // Plain, like the brief's other in-text commands: the same words however Penthera was started.
  if (b.set_aside) L.push(`Checked one and it is not a problem? ${code(b.set_aside.command)}. ${md(b.set_aside.why)}.`, "");
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
    for (const n of b.next) L.push(`- ${code(hintCommand(n.command))}: ${md(hintCommand(n.why))}`);
    if (b.reports.length) L.push(`- Full report${b.reports.length > 1 ? "s" : ""}: ${b.reports.map(code).join(", ")}`);
    L.push("");
  }
  if (footer) L.push("---", "", ...footerLines({ footer }));
  return L.join("\n");
}