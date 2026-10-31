#!/usr/bin/env node
/**
 * E20-R2 final report: the one step that joins the claims and the audit, so numbers reach
 * the report by code and neither can appear without the other. It takes a run folder that
 * holds the analysis, the score and the draw, and refuses unless every hash chains from the
 * run's manifest to both. It prints no site.
 *
 *   node bench/front-door/final-report.mjs <run folder>
 *
 * Writes final-report.md there. Amendment 3: the audit's headline stands beside the claims.
 * When it is not estimable, the frame's figures are marked as not the audit's result, and
 * every real-page view of an HTTP claim says `candidate-page` wasn't validated on this run.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { selfHashHolds } from "./record-checks.mjs";
import { stateOf, verifyDraw } from "./validation-sample.mjs";

export const NOT_VALIDATED = "`candidate-page` wasn't validated on this run";
export const NOT_THE_RESULT = "These figures are for the frame, and are not the audit's result.";

const hash = (b) => createHash("sha256").update(b).digest("hex");
const pct = (v) => (typeof v === "number" ? (v * 100).toFixed(1) : "n/a");
const ci = (c) => (Array.isArray(c) && typeof c[0] === "number" ? `${pct(c[0])} to ${pct(c[1])}` : "n/a");

/** Throws unless the analysis and the score both chain to this run, its draw and this code. */
function checked(dir) {
  const refuse = (why) => { throw new Error(`Refused: ${why}.`); };
  const bound = verifyDraw(dir);
  if (bound.problem) refuse(bound.problem);
  const load = (name) => {
    if (!existsSync(join(dir, name))) refuse(`there is no ${name}`);
    const value = JSON.parse(readFileSync(join(dir, name), "utf8"));
    if (!selfHashHolds(value)) refuse(`${name} was changed after it was written`);
    return value;
  };
  const analysis = load("analysis.json"), score = load("score.json");
  if (analysis.provenance?.manifestSha256 !== bound.manifestSha256 || analysis.provenance.rawSha256 !== bound.rawSha256) refuse("this analysis is not of this run's drawn raw file");
  for (const name of ["manifestSha256", "rawSha256", "drawProofSha256", "frameSha256", "sheetSha256", "keySha256"]) if (score.provenance?.[name] !== bound[name]) refuse(`this score doesn't match the run: ${name}`);
  if (JSON.stringify(score.frame) !== JSON.stringify(JSON.parse(readFileSync(join(dir, "audit-frame.json"), "utf8")))) refuse("this score's frame is not the run's");
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  const runState = JSON.stringify(stateOf(manifest));
  if (JSON.stringify(stateOf(analysis.provenance.state)) !== runState) refuse("this analysis ran under other code or another protocol");
  if (JSON.stringify(stateOf(score.provenance.state)) !== runState) refuse("this score ran under other code or another protocol");
  if (JSON.stringify(stateOf()) !== runState) refuse("this checkout is not the one the run used");
  return { analysis, score, bound };
}

/** The report, as text. Claims and audit can't be read apart: the headline opens it and sits on the claims table. */
export function assembleReport(dir) {
  const { analysis: a, score: s, bound } = checked(dir);
  const notEstimable = s.frame.notEstimable === true;
  const out = [];
  const table = (head, rows) => out.push(`| ${head.join(" | ")} |`, `|${head.map(() => "---").join("|")}|`, ...rows.map((r) => `| ${r.join(" | ")} |`), "");
  const title = (t) => out.push(`## ${t}`, "");
  const headline = `**Audit headline: ${s.frame.headline}.** ${pct(s.frame.share)}% of audit-eligible records withheld, worst stratum ${pct(Math.max(...Object.values(s.frame.strata).map((g) => g.share)))}%.`;
  const realPage = (cell) => (notEstimable ? `${cell} ${NOT_VALIDATED}` : cell);
  const view = (v) => (v ? `${pct(v.diff)} (${ci(v.ci)}), orgs ${v.orgsA}/${v.orgsB}, ${v.direction}` : "");

  out.push("# E20-R2 results", "", headline, "");
  title("Primary refusal endpoint");
  table(["Graded", "Signature-backed", "95% interval", "All refusals", "Original rules"], [[a.primaryRefusal?.n ?? "n/a", pct(a.primaryRefusal?.share), ci(a.primaryRefusal?.ci), pct(a.refusals?.all), pct(a.refusals?.registered)]]);
  title(`Claims C1 to C11, on ${(a.level * 100).toFixed(2)}% intervals`);
  out.push(headline, "");
  table(["Claim", "Comparison", "Check", "Predicted", "Served", "Real page", "Decision"], a.claims.filter((c) => c.S).map((c) => [c.id, c.label, `\`${c.check}\``, c.predicted, view(c.S), c.R ? realPage(view(c.R)) : "", c.decision]));
  title("CSP that controls scripts");
  table(["Claim", "Served", "Real page", "Decision"], (a.cspControlsScripts ?? []).map((c) => [c.id, view(c.S), c.R ? realPage(view(c.R)) : "", c.decision]));
  title("Real-page differences, standardized to the edge mix");
  table(["Claim", "Difference", "95% interval", "Strata dropped"], Object.entries(a.standardizedR ?? {}).map(([id, d]) => [id, realPage(pct(d.diff)), ci(d.ci), (d.dropped ?? []).join(" ") || "none"]));
  title("C12 to C15, descriptive");
  table(["Claim", "What", "n", "Value", "Interval or lower bound"], a.claims.filter((c) => !c.S).map((c) => [c.id, c.label, c.n ?? "n/a", c.diff !== undefined && c.diff !== null ? pct(c.diff) : c.kappa?.toFixed(3) ?? "n/a", c.ci ? ci(c.ci) : `${c.lower?.toFixed(3) ?? "n/a"} (threshold ${c.threshold ?? "n/a"})`]));
  title("Worst-case bounds of the claims");
  table(["Claim", "Low", "High", "Coverage A", "Coverage B"], Object.entries(a.bounds ?? {}).map(([id, b]) => [id, pct(b.low), pct(b.high), pct(b.coverageA), pct(b.coverageB)]));
  title("Sites skipped, per list and reason");
  const reasons = [...new Set(Object.values(a.skipsByCohort ?? {}).flatMap((c) => Object.keys(c)))].sort();
  table(["List", ...reasons], Object.entries(a.skipsByCohort ?? {}).map(([c, r]) => [c, ...reasons.map((k) => r[k] ?? 0)]));
  title("Withheld text");
  out.push(`${a.textWithheld?.records ?? 0} of ${a.textWithheld?.of ?? 0} records, ${pct(a.textWithheld?.share)}%. Fires are counts, never verdicts.`, "");
  for (const [name, group] of Object.entries({ Cohort: a.textWithheld?.byCohort, Stratum: a.textWithheld?.byStratum, Label: a.textWithheld?.byLabel, Status: a.textWithheld?.byStatus, Edge: a.textWithheld?.byEdge })) table([name, "Withheld", "Of", "Share"], Object.entries(group ?? {}).map(([k, g]) => [k, g.records, g.of, pct(g.share)]));
  table(["Kind", "Findings"], Object.entries(a.textWithheld?.kinds ?? {}));
  title("Single-human audit with model comparison");
  out.push(headline, "", `Covers ${s.frame.scope}. ${s.rows} rows, ${s.unsure} unsure.`, "");
  table(["Stratum", "Eligible", "Withheld", "Share", "Frame", "Drawn", "Target"], Object.entries(s.frame.strata).map(([k, g]) => [k, g.eligible, g.withheld, pct(g.share), g.frame, g.drawn, g.target]));
  if (notEstimable) out.push(`**${NOT_THE_RESULT}**`, "");
  const figure = (m, fn) => (m.suppressed ? `no figure: ${m.suppressed}` : fn(m));
  table(["Label", "Precision", "95% interval", "Recall", "95% interval", "Worst-case precision", "Worst-case recall"], Object.entries(s.metrics).map(([l, m]) => [l, figure(m, (x) => pct(x.precision)), figure(m, (x) => ci(x.precisionCi)), figure(m, (x) => pct(x.recall)), figure(m, (x) => ci(x.recallCi)), figure(s.worstCase[l], (x) => pct(x.precision)), figure(s.worstCase[l], (x) => pct(x.recall))]));
  out.push(`Kappa against the human, ${s.kappa?.toFixed(3) ?? "n/a"}, with unsure as disagreement ${s.kappaUnsureAsDisagreement?.toFixed(3) ?? "n/a"}. Its worst case: ${s.kappaWorstCase}. Human against model, ${s.humanVsAgent.bothAnswered} rows: kappa ${s.humanVsAgent.kappa?.toFixed(3) ?? "n/a"}, ${s.humanVsAgent.disagreements} disagreements.`, "");
  if (a.privacyDeviation) { title("Privacy deviation"); out.push(`A person reviewed and recorded a false fire. Note hash \`${a.privacyDeviation.noteSha256}\`.`, ""); }
  title("Provenance");
  table(["Input", "SHA-256"], [["Manifest", bound.manifestSha256], ["Raw, after the draw", bound.rawSha256], ["Draw proof", bound.drawProofSha256], ["Audit frame", bound.frameSha256], ["Sheet", bound.sheetSha256], ["Key", bound.keySha256], ["Human labels", s.provenance.human.labelsSha256], ["Model labels", s.provenance.agent.labelsSha256], ["Analysis", a.selfSha256], ["Score", s.selfSha256], ["Code", a.provenance.state.codeSha256], ["Protocol", a.provenance.state.protocolSha256]]);
  return { text: out.join("\n"), notEstimable };
}

export function main([dir], { log = console.log, fail = console.error } = {}) {
  if (!dir) { fail("Usage: final-report.mjs <run folder>"); return 2; }
  try {
    const { text, notEstimable } = assembleReport(dir);
    writeFileSync(join(dir, "final-report.md"), `${text}\n`, { mode: 0o600 });
    log(JSON.stringify({ report: "final-report.md", sha256: hash(`${text}\n`), notEstimable }));
    return 0;
  } catch (e) {
    fail(e.message);
    return 3;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.slice(2));
