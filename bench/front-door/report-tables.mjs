#!/usr/bin/env node
/**
 * E20-R2 report: the one step that joins the claims and the audit, so numbers reach the
 * report by code and neither can appear without the other. Prints no site. It groups
 * nothing itself, so the floor on small groups stays the analysis's job.
 *
 *   node bench/front-door/report-tables.mjs --run <run folder> --analysis <analysis.json> --score <score.json> --out <final-report.md>
 *       --pass2 <pass 1 raw> --e20 <tranco raw> <yc raw> --industries <csv> --e20-excluded <file>
 *
 * Runs where the whole run, the key and the private inputs are. It proves the chain from the
 * raw file, runs the analysis and the score again from their inputs, and compares every field.
 * The self-hashes aren't keyed, so nothing is taken from them alone. Exits 3 and writes nothing
 * on any refusal, and there is no unchecked way to write a report. Amendment 3: the headline
 * stands above the claims, and when the audit is not estimable, every real-page view says so.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";
import { analysisOf } from "./analyze-r.mjs";
import { selfHashed, selfHashHolds } from "./record-checks.mjs";
import { studyState } from "./replicate.mjs";
import { LABEL_STRATA, MIN_AUDIT_FRAME, overWithheldLimit, scoreRun, STATE_FIELDS, stateProblem, SUPPRESSED, verifyDraw } from "./validation-sample.mjs";

export const NOT_VALIDATED = "; candidate-page not validated on this run";
export const SCOPE_LINE = "Audit figures describe non-withheld records, not the run as a whole.";
export const NOT_THE_RESULT = "These figures are for the frame, and are not the audit's result.";
const PROVENANCE = Object.freeze(["manifestSha256", "rawSha256", "drawProofSha256", "frameSha256", "sheetSha256", "keySha256"]);
const DIGEST = /^[0-9a-f]{64}$/;
const hash = (b) => createHash("sha256").update(b).digest("hex");

// Every top-level key of analysis.json is printed or listed here with a reason. A new key needs one or the other.
export const PRINTED_KEYS = Object.freeze(["level", "claims", "traits", "traitsByCohort", "refusals", "privacyDeviation", "primaryRefusal", "bounds", "standardized", "standardizedR", "secondaryCohorts", "challengeByEdge", "skipsByCohort", "textWithheld", "cspControlsScripts", "dnsGradedOnlyReading", "dnsBeside", "dnsCoverage", "industries", "replicationAsE20", "provenance", "selfSha256"]);
export const NOT_PRINTED = Object.freeze({
  experiment: "names the study, which the title does",
  resamples: "fixed in the code and printed in provenance as an option",
  auditFrame: "must equal the score's frame, which the audit's detail prints",
});
// The fields below the top level, which those lists can't see. Every open cell of a share table holds exactly these five.
export const SHARE_FIELDS = Object.freeze(["passed", "judged", "share", "ci95", "interval"]);
export const GROUP_FIELDS = Object.freeze({ trait: ["sites", "shares"], industry: ["sites", "median", "shares"], suppressed: ["sites", "suppressed"], edge: ["n", "share", "ci95", "interval"], refusals: ["n", "all", "allCi95", "signatureBacked", "registered", "registeredCi95", "interval"] });
export const PART_TWO = "Secondary figures. Their intervals are naive row-level, with no clustering, and they corroborate nothing. The two DNS tables keep the claims' cluster bootstrap and level.";
export const UNDER_20 = "under 20";

const refuse = (why) => { throw new Error(`Refused: ${why}.`); };

/** What is wrong with the nested rows of an analysis: a field missing, an unlisted field, a figure under the floor, or an interval that doesn't fit its counts. */
export function nestedProblems(a) {
  const out = [];
  const exact = (at, row, fields) => {
    const names = row !== null && typeof row === "object" ? Object.keys(row) : [];
    for (const f of fields) if (!names.includes(f)) out.push(`${at} has no ${f}`);
    for (const f of names) if (!fields.includes(f)) out.push(`${at} has the unlisted field ${f}`);
  };
  const group = (at, g, fields) => {
    if (g.suppressed) return exact(at, g, GROUP_FIELDS.suppressed);
    exact(at, g, fields);
    for (const [check, s] of Object.entries(g.shares ?? {})) {
      if (s?.suppressed) { exact(`${at}.${check}`, s, ["suppressed"]); continue; }
      exact(`${at}.${check}`, s, SHARE_FIELDS);
      if (s?.interval !== "naive row-level") out.push(`${at}.${check} doesn't say its interval is naive row-level`);
      if (!(s?.judged >= 20) || !Array.isArray(s?.ci95) || s?.ci95.length !== 2 || typeof s?.share !== "number") out.push(`${at}.${check} has a figure that doesn't fit its counts`);
    }
  };
  for (const [name, g] of Object.entries(a.traits ?? {})) group(`traits.${name}`, g, GROUP_FIELDS.trait);
  for (const [cohort, table] of Object.entries(a.traitsByCohort ?? {})) for (const [name, g] of Object.entries(table)) group(`traitsByCohort.${cohort}.${name}`, g, GROUP_FIELDS.trait);
  const { suppressedGroups: _hidden, ...industries } = a.industries ?? {};
  for (const [name, g] of Object.entries(industries)) group(`industries.${name}`, g, GROUP_FIELDS.industry);
  for (const [edge, g] of Object.entries(a.challengeByEdge ?? {})) exact(`challengeByEdge.${edge}`, g, GROUP_FIELDS.edge);
  exact("refusals", a.refusals, GROUP_FIELDS.refusals);
  if (a.refusals?.interval !== "naive row-level") out.push("refusals doesn't say its interval is naive row-level");
  return out;
}

/** The headline a frame's own counts give, by the exact test. */
const headlineOf = (frame) => (Object.values(frame.strata).some((g) => overWithheldLimit(g.withheld, g.eligible)) ? "not estimable" : "stands, on its frame");

/** Why this score can't be reported, from what it says of itself. A hand edit has to agree with the counts. */
function scoreProblem(s) {
  const p = s.provenance;
  for (const name of PROVENANCE) if (!DIGEST.test(p?.[name] ?? "")) return `the score has no ${name}`;
  for (const role of ["human", "model"]) for (const name of ["labelsSha256", "manifestSha256"]) if (!DIGEST.test(p?.[role]?.[name] ?? "")) return `the score has no ${name} for the ${role} labels`;
  for (const name of STATE_FIELDS) if (!p?.state?.[name] || !p.runState?.[name]) return `the score has no ${name}`;
  const frame = s.frame;
  if (!frame?.strata || !frame.labels) return "the score has no frame";
  if (hash(`${JSON.stringify(frame, null, 2)}\n`) !== p.frameSha256) return "the score's frame is not the one its hash names";
  for (const [name, g] of Object.entries(frame.strata)) {
    if (g.frame !== g.eligible - g.withheld || g.withheld < 0 || g.overLimit !== overWithheldLimit(g.withheld, g.eligible)) return `the frame's ${name} row doesn't add up`;
  }
  const headline = headlineOf(frame);
  if (s.headline !== headline || frame.headline !== headline || frame.notEstimable !== (headline === "not estimable")) return "the score's headline doesn't match its frame";
  for (const [label, strata] of Object.entries(LABEL_STRATA)) {
    const size = strata.reduce((n, name) => n + frame.strata[name].frame, 0);
    if (frame.labels[label]?.frame !== size || frame.labels[label].figures !== (size >= MIN_AUDIT_FRAME)) return `the frame's ${label} label doesn't add up`;
    for (const block of [s.metrics?.[label], s.worstCase?.[label]]) {
      if (!block) return `the score has no ${label} figures`;
      if (size < MIN_AUDIT_FRAME && block.suppressed !== SUPPRESSED) return `${label} has figures under 20 in frame`;
      if (block.suppressed && Object.entries(block).some(([k, v]) => k !== "frame" && k !== "suppressed" && v !== null)) return `suppressed ${label} carries a number`;
    }
  }
  const total = Object.values(frame.labels).reduce((n, l) => n + l.frame, 0);
  if (total < MIN_AUDIT_FRAME && (s.kappa !== null || s.humanVsAgent?.kappa !== null)) return "kappa has a figure under 20 in frame";
  return null;
}

/** Throws unless the two files name one run, one state, and agree with themselves. */
export function joined(analysis, score) {
  if (!selfHashHolds(analysis)) refuse("analysis.json was changed after it was written");
  if (!selfHashHolds(score)) refuse("score.json was changed after it was written");
  const problem = scoreProblem(score);
  if (problem) refuse(problem);
  const a = analysis.provenance, s = score.provenance;
  if (!DIGEST.test(a?.manifestSha256 ?? "") || a.manifestSha256 !== s.manifestSha256) refuse("the analysis and the score are of different runs: manifestSha256 differs");
  if (!DIGEST.test(a.rawSha256 ?? "") || a.rawSha256 !== s.rawSha256) refuse("the analysis didn't read the raw file the draw left: rawSha256 differs");
  for (const name of STATE_FIELDS) if (a.state?.[name] !== s.state[name]) refuse(`the analysis and the score ran under different states: ${name} differs`);
  // The analysis builds the frame from the raw file on its own, so a frame edited in one file shows.
  if (JSON.stringify(analysis.auditFrame) !== JSON.stringify(score.frame)) refuse("the analysis and the score hold different audit frames");
}

/**
 * Against the whole run: the chain from the raw file, this checkout against the manifest, and
 * the score and the analysis worked out again from their inputs, compared field for field.
 */
export function checkAgainstRun(dir, analysis, score, inputs, { state = studyState(), preregText } = {}) {
  const bound = verifyDraw(dir);
  if (bound.problem) refuse(bound.problem);
  for (const name of PROVENANCE) if (score.provenance[name] !== bound[name]) refuse(`this score doesn't match the run: ${name} differs`);
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  const departs = stateProblem(manifest, state);
  if (departs) refuse(departs);
  if (hash(readFileSync(join(dir, "aggregate.json"))) !== manifest.aggregateSha256) refuse("the aggregate file is not the run's");
  const again = scoreRun(dir, { state });
  if (again.problem) refuse(again.problem);
  const figures = ({ selfSha256: _self, scoredAt: _at, ...rest }) => JSON.stringify(rest);
  if (figures(score) !== figures(again)) refuse("this score's figures don't follow from its inputs");
  const said = [];
  const redone = analysisOf(["--pass1", join(dir, "raw.jsonl"), ...inputs], { fail: (m) => said.push(m), state, preregText });
  if (!redone) refuse(said.join(" ").replace(/^Refused: |\.$/g, ""));
  if (JSON.stringify(selfHashed(redone)) !== JSON.stringify(analysis)) refuse("this analysis doesn't follow from its inputs");
}

const pct = (v) => (typeof v === "number" ? (v * 100).toFixed(1) : "n/a");
const ci = (c) => (Array.isArray(c) && typeof c[0] === "number" ? `${pct(c[0])} to ${pct(c[1])}` : "n/a");
const num = (v) => (typeof v === "number" ? v.toFixed(3) : "n/a");

/** The report's text, in the registered order. It checks nothing and writes nothing: only `main` writes, after every check. */
export function assemble(a, s, { runtimeNow = null } = {}) {
  const out = [];
  const table = (head, rows) => out.push(`| ${head.join(" | ")} |`, `|${head.map(() => "---").join("|")}|`, ...rows.map((r) => `| ${r.join(" | ")} |`), "");
  const title = (t) => out.push(`## ${t}`, "");
  const notEstimable = s.frame.notEstimable;
  const view = (v) => (v ? `${pct(v.diff)} (${ci(v.ci)}), orgs ${v.orgsA}/${v.orgsB}, ${v.direction}` : "");
  const real = (cell) => (notEstimable ? `${cell}${NOT_VALIDATED}` : cell);
  const realView = (v) => (v ? real(view(v)) : "");
  const p = s.provenance;

  out.push("# E20-R2 results", "");
  title("Provenance");
  table(["Input", "SHA-256"], [["Commit", p.commit ?? "n/a"], ["Manifest", p.manifestSha256], ["Raw, after the draw", p.rawSha256], ["Draw proof", p.drawProofSha256], ["Audit frame", p.frameSha256], ["Sheet", p.sheetSha256], ["Key", p.keySha256], ["Human labels", p.human.labelsSha256], ["Human label manifest", p.human.manifestSha256], ["Model labels", p.model.labelsSha256], ["Model label manifest", p.model.manifestSha256], ["Score", s.selfSha256], ["Analysis", a.selfSha256], ["Classifier", p.state.classifierSha256], ["Protocol now", p.state.protocolSha256], ["Protocol of the run", p.runState.protocolSha256], ["Code", p.state.codeSha256], ["Public Suffix List", p.state.pslSha256], ["Lockfile", p.state.lockfileSha256], ["Amendment", p.state.amendmentSha256], ["Study page", p.state.studyPageSha256], ["Node version", p.state.node], ["Node binary of the run, not compared", p.runRuntimeSha256], ["Node binary now, not compared", runtimeNow ?? "n/a"], ["Aggregate file, with MX and NS counts", p.aggregateSha256 ?? "n/a"], ...Object.entries(a.provenance.inputs ?? {}), ...Object.entries(a.provenance.options ?? {}).map(([name, value]) => [`Option: ${name}`, value])]);

  const over = Object.entries(s.frame.strata).filter(([, g]) => g.overLimit).map(([name, g]) => `${name} ${g.withheld} of ${g.eligible}`);
  out.push(notEstimable ? `**Headline audit: not estimable.** Over 2.0% withheld: ${over.join("; ")}. It changes no claim's decision.` : "**Headline audit: stands, on its frame.**", "");
  out.push(SCOPE_LINE, "");

  title("Primary refusal endpoint");
  table(["Graded", "Signature-backed", "95% interval", "All refusals", "95% interval", "Original rules", "95% interval", "Interval of the last two"], [[a.primaryRefusal?.n ?? "n/a", pct(a.primaryRefusal?.share), ci(a.primaryRefusal?.ci), pct(a.refusals?.all), ci(a.refusals?.allCi95), pct(a.refusals?.registered), ci(a.refusals?.registeredCi95), a.refusals?.interval ?? "n/a"]]);

  title(`Claims C1 to C11, on ${(a.level * 100).toFixed(2)}% intervals`);
  table(["Claim", "Comparison", "Check", "Predicted", "Served", "Real page", "Decision"], a.claims.filter((c) => c.S).map((c) => [c.id, c.label, `\`${c.check}\``, c.predicted, view(c.S), realView(c.R), c.decision]));

  title("CSP controls scripts");
  table(["Claim", "Comparison", "Served", "Real page", "Decision"], (a.cspControlsScripts ?? []).map((c) => [c.id, c.label, view(c.S), realView(c.R), c.decision]));

  title("Standardized figures");
  const standard = (d) => (d ? `${pct(d.diff)} (${ci(d.ci)})` : "");
  table(["Claim", "Served", "Real page"], Object.keys(a.standardized ?? {}).map((id) => [id, standard(a.standardized[id]), a.standardizedR?.[id] ? real(standard(a.standardizedR[id])) : ""]));

  title("The E20-matched reading");
  table(["Claim", "Comparison", "Served", "Real page", "Decision"], (a.replicationAsE20 ?? []).map((c) => [c.id, c.label, view(c.S), realView(c.R), c.decision]));

  title("C12 to C15, descriptive");
  table(["Claim", "What", "n", "Value", "Interval or lower bound"], a.claims.filter((c) => !c.S).map((c) => [c.id, c.label, c.n ?? "n/a", typeof c.diff === "number" ? pct(c.diff) : num(c.kappa), c.ci ? ci(c.ci) : `${num(c.lower)} (threshold ${c.threshold})`]));

  title("Worst-case bounds of the claims");
  table(["Claim", "Low", "High", "Coverage A", "Coverage B"], Object.entries(a.bounds ?? {}).map(([id, b]) => [id, pct(b.low), pct(b.high), pct(b.coverageA), pct(b.coverageB)]));
  title("Sites skipped, per list and reason");
  const reasons = [...new Set(Object.values(a.skipsByCohort ?? {}).flatMap((c) => Object.keys(c)))].sort();
  table(["List", ...reasons], Object.entries(a.skipsByCohort ?? {}).map(([c, r]) => [c, ...reasons.map((k) => r[k] ?? 0)]));
  title("DNS coverage");
  table(["List", "Read", "Domain exists", "No such domain", "Unknown"], Object.entries(a.dnsCoverage ?? {}).map(([c, d]) => [c, d.read, d.exists, d.nxdomain, d.unknown]));

  const w = a.textWithheld;
  title("Text withheld");
  out.push(`${w.records} of ${w.of} records with evidence, ${pct(w.share)}%. Findings by kind: ${JSON.stringify(w.kinds)}. Fires are counts, never verdicts.`, "");
  for (const [name, group] of [["List", w.byCohort], ["Audit stratum", w.byStratum], ["Label", w.byLabel], ["HTTP status", w.byStatus], ["Edge", w.byEdge]]) {
    table([name, "Withheld", "Of", "Share"], Object.entries(group ?? {}).map(([k, v]) => [k, v.records, v.of, `${pct(v.of ? v.records / v.of : 0)}%`]));
  }

  title("The audit's detail");
  out.push(`Withheld overall: ${s.frame.withheld} of ${s.frame.eligible}, ${pct(s.frame.share)}%. ${s.rows} rows, ${s.unsure} unsure.`, "");
  table(["Stratum", "Eligible", "Withheld", "Share", "Over 2.0%", "Frame", "Drawn", "Target", "Shortfall"], Object.entries(s.frame.strata).map(([k, g]) => [k, g.eligible, g.withheld, `${pct(g.share)}%`, g.overLimit ? "yes" : "no", g.frame, g.drawn, g.target, g.shortfall]));
  title(notEstimable ? "Frame figures, not the audit's result" : "Audit figures, on the frame");
  const cell = (block, text) => block.suppressed ?? text;
  table(["Label", "Frame", "Precision", "95% interval", "Worst case", "Recall", "95% interval", "Worst case"], Object.entries(s.metrics).map(([l, m]) => {
    const c = s.worstCase[l];
    return [l, s.frame.labels[l].frame, cell(m, pct(m.precision)), cell(m, ci(m.precisionCi)), cell(c, pct(c.precision)), cell(m, pct(m.recall)), cell(m, ci(m.recallCi)), cell(c, pct(c.recall))];
  }));
  if (notEstimable) out.push(NOT_THE_RESULT, "");
  const kappa = s.kappaSuppressed ?? `${num(s.kappa)}, with unsure as disagreement ${num(s.kappaUnsureAsDisagreement)}`;
  const model = s.humanVsAgent.kappaSuppressed ?? `kappa ${num(s.humanVsAgent.kappa)}, ${s.humanVsAgent.disagreements} disagreements`;
  out.push(`${notEstimable ? "Frame only, not the audit's result: kappa" : "Kappa"} ${kappa}. Kappa has no worst-case bound. Human against the model, ${s.humanVsAgent.bothAnswered} rows: ${model}.`, "");

  if (a.privacyDeviation) { title("Privacy deviation"); out.push(`A person reviewed and recorded a false fire. Note hash \`${a.privacyDeviation.noteSha256}\`.`, ""); }

  // Part 2. Every row and field the analysis holds, read off the data so none can be left out.
  out.push("# Part 2", "", PART_TWO, "");
  const cellOf = (v) => (Array.isArray(v) ? v.map(cellOf).join(" to ") : typeof v === "number" ? (Number.isInteger(v) ? v : v.toFixed(3)) : v === null || v === undefined ? "n/a" : typeof v === "object" ? JSON.stringify(v) : v);
  const fields = (rows) => {
    const keys = [...new Set(rows.flatMap((r) => Object.keys(r)))];
    table(keys, rows.map((r) => keys.map((k) => cellOf(r[k]))));
  };
  // One row per check, with its counts, share, interval and the interval's label. A suppressed group or cell shows no figure.
  const shareRows = (head, group, extraHead = [], extra = () => []) => {
    const hidden = Array(5).fill(UNDER_20);
    table([head, "Sites", ...extraHead, "Check", "Passed", "Judged", "Share, %", "95% interval, %", "Interval"], Object.entries(group).flatMap(([name, g]) => (g.suppressed
      ? [[name, UNDER_20, ...extraHead.map(() => UNDER_20), "all", ...hidden]]
      : Object.entries(g.shares).map(([check, s]) => [name, g.sites, ...extra(g), check, ...(s.suppressed ? hidden : [s.passed, s.judged, pct(s.share), ci(s.ci95), s.interval])]))));
  };
  title("Secondary cohorts");
  fields(a.secondaryCohorts ?? []);
  title("Checks by site trait");
  shareRows("Trait", a.traits ?? {});
  for (const [cohort, group] of Object.entries(a.traitsByCohort ?? {})) { out.push(`List: ${cohort}`, ""); shareRows("Trait", group); }
  title("Checks by industry");
  const { suppressedGroups = 0, ...industries } = a.industries ?? {};
  out.push(`Groups under 20, not shown: ${suppressedGroups}.`, "");
  shareRows("Industry", industries, ["Median score"], (g) => [cellOf(g.median)]);
  title("Challenge share by edge");
  fields(Object.entries(a.challengeByEdge ?? {}).map(([edge, g]) => ({ edge, ...g })));
  title("DNS beside the decision");
  for (const [name, list] of Object.entries(a.dnsBeside ?? {})) {
    out.push(`Measure: ${name === "rejectOnly" ? "p=reject" : name}`, "");
    table(["Claim", "Comparison", "Check", "Served", "Decision"], list.map((c) => [c.id, c.label, `\`${c.check}\``, view(c.S), c.decision]));
  }
  title("Graded-only DNS reading");
  out.push("Decides nothing.", "");
  table(["Claim", "Comparison", "Check", "Served", "Real page", "Decision"], (a.dnsGradedOnlyReading ?? []).map((c) => [c.id, c.label, `\`${c.check}\``, view(c.S), realView(c.R), c.decision]));
  return out.join("\n");
}

export function main(args, { log = console.log, fail = console.error, ...deps } = {}) {
  const at = (flag, offset = 1) => (args.includes(flag) ? args[args.indexOf(flag) + offset] : undefined);
  const [analysisFile, scoreFile, outFile, run] = [at("--analysis"), at("--score"), at("--out"), at("--run")];
  if (!analysisFile || !scoreFile || !outFile) { fail("Usage: report-tables.mjs --run <run folder> --analysis <analysis.json> --score <score.json> --out <final-report.md> --pass2 <raw> --e20 <tranco raw> <yc raw> --industries <csv> --e20-excluded <file>"); return 2; }
  try {
    if (!run) refuse("the report needs --run, because nothing unchecked may become the final report");
    const inputs = ["--pass2", at("--pass2"), "--e20", at("--e20"), at("--e20", 2), "--industries", at("--industries"), "--e20-excluded", at("--e20-excluded")];
    if (inputs.some((v) => !v)) refuse("the report needs every registered input, to run the analysis again");
    for (const file of [analysisFile, scoreFile]) if (!existsSync(file)) refuse(`there is no ${file}`);
    const analysis = JSON.parse(readFileSync(analysisFile, "utf8")), score = JSON.parse(readFileSync(scoreFile, "utf8"));
    joined(analysis, score);
    checkAgainstRun(run, analysis, score, inputs, deps);
    const text = `${assemble(analysis, score, { runtimeNow: (deps.state ?? studyState()).runtimeSha256 })}\n`;
    writeFileSync(`${outFile}.tmp`, text, { mode: 0o600 });
    renameSync(`${outFile}.tmp`, outFile);
    log(JSON.stringify({ report: outFile, notEstimable: score.frame.notEstimable }));
    return 0;
  } catch (e) {
    fail(e.message.startsWith("Refused") ? e.message : `Refused: ${e.message}.`);
    return 3;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.slice(2));
