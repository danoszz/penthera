#!/usr/bin/env node
/**
 * Penthera Bench v1: inter-rater agreement and adjudication (E1 § 6.2, § 8.4).
 *
 *   node bench/real-world/kappa.js --corpus bench/real-world/pilot/corpus.json --set calibration
 *
 * Computes Cohen's kappa between labellers A and B, level 1 ("correct") and
 * level 2 ("actionable"), overall and per category, with 95% intervals.
 * For the calibration set it writes calibration-gate.json: passed when level-1
 * kappa is at least 0.70 overall and no category is below 0.50. For any set it
 * writes disagreements-<set>.jsonl for adjudication; the agreed outcome goes
 * into adjudications.jsonl as { id, correct, actionable, by, reason }.
 */
import { join, resolve } from "node:path";
import { CATEGORIES, cacheDir, isMain, parseArgs, readJsonl, readManifest, studyDir, writeJson, writeJsonl } from "./lib.js";
import { cohenKappa } from "./stats.js";

export const GATE = { overall: 0.7, perCategory: 0.5 };

/** Last label per unit for one labeller (a later answer replaces an earlier one). */
export function latest(labels) {
  const m = new Map();
  for (const l of labels) m.set(l.id, l);
  return m;
}

const level2 = (l) => (l.correct === "yes" ? l.actionable || "cannot" : "no");

/** Kappa report for the units of `set` that both labellers answered. */
export function agreement(units, labelsA, labelsB, set, round = null) {
  const A = latest(labelsA);
  const B = latest(labelsB);
  units = units.filter((u) => u.set === set && (round == null || (u.round || 1) === round));
  const both = units.filter((u) => A.has(u.id) && B.has(u.id));
  const k = (sel, f) => cohenKappa(sel.map((u) => [f(A.get(u.id)), f(B.get(u.id))]));
  const report = {
    set,
    round,
    units: units.length,
    labelledByBoth: both.length,
    level1: k(both, (l) => l.correct),
    level2: k(both, level2),
    perCategory: {},
  };
  for (const c of CATEGORIES) {
    const sel = both.filter((u) => u.category === c);
    report.perCategory[c] = { n: sel.length, level1: k(sel, (l) => l.correct), level2: k(sel, level2) };
  }
  report.disagreements = both
    .filter((u) => A.get(u.id).correct !== B.get(u.id).correct || level2(A.get(u.id)) !== level2(B.get(u.id)))
    .map((u) => ({ id: u.id, category: u.category, A: { correct: A.get(u.id).correct, actionable: A.get(u.id).actionable, note: A.get(u.id).note }, B: { correct: B.get(u.id).correct, actionable: B.get(u.id).actionable, note: B.get(u.id).note } }));
  return report;
}

/** The calibration gate of § 6.2. A kappa that cannot be computed passes only with perfect agreement. */
export function gate(report) {
  const ok = (kp, min) => (kp.kappa == null ? kp.n === 0 || kp.agreement === 1 : kp.kappa >= min);
  const overall = report.labelledByBoth > 0 && report.labelledByBoth === report.units && ok(report.level1, GATE.overall);
  const failing = CATEGORIES.filter((c) => report.perCategory[c].n > 0 && !ok(report.perCategory[c].level1, GATE.perCategory));
  return { passed: overall && failing.length === 0, overallKappa: report.level1.kappa, failingCategories: failing, complete: report.labelledByBoth === report.units };
}

/**
 * Final labels for scoring: agreed labels, or the adjudicated outcome where
 * the labellers disagree. Returns { labels: Map(id → {correct, actionable}), unresolved, missing }.
 */
export function finalLabels(units, labelsA, labelsB, adjudications, set = "analysis") {
  const A = latest(labelsA);
  const B = latest(labelsB);
  const adj = latest(adjudications);
  const labels = new Map();
  let unresolved = 0;
  let missing = 0;
  for (const u of units.filter((x) => x.set === set)) {
    const a = A.get(u.id);
    const b = B.get(u.id);
    if (!a || !b) { missing++; continue; }
    if (a.correct === b.correct && level2(a) === level2(b)) labels.set(u.id, { correct: a.correct, actionable: level2(a) });
    else if (adj.has(u.id)) labels.set(u.id, { correct: adj.get(u.id).correct, actionable: adj.get(u.id).correct === "yes" ? adj.get(u.id).actionable || "cannot" : "no" });
    else unresolved++;
  }
  return { labels, unresolved, missing };
}

async function main() {
  const args = parseArgs(process.argv.slice(2), ["allow-file"]);
  if (!args.corpus) {
    console.error("usage: node bench/real-world/kappa.js --corpus <manifest.json> [--set calibration|analysis] [--round <n>] [--labels-dir <dir>] [--cache <dir>]");
    process.exit(2);
  }
  const cache = cacheDir(args.cache);
  const manifest = readManifest(resolve(args.corpus), { allowFile: !!args["allow-file"] });
  const out = studyDir(cache, manifest.set);
  const labelsDir = args["labels-dir"] ? resolve(args["labels-dir"]) : out;
  const set = args.set || "calibration";
  const units = readJsonl(join(out, "units-key.jsonl"));
  // Calibration: the latest round unless --round says otherwise.
  const round = set === "calibration" ? Number(args.round || Math.max(1, ...units.filter((u) => u.set === "calibration").map((u) => u.round || 1))) : null;
  const report = agreement(units, readJsonl(join(labelsDir, "labels-A.jsonl")), readJsonl(join(labelsDir, "labels-B.jsonl")), set, round);
  writeJsonl(join(labelsDir, `disagreements-${set}.jsonl`), report.disagreements);
  const fmt = (k) => (k.kappa == null ? "n/a" : `${k.kappa.toFixed(3)} [${k.lo.toFixed(3)}, ${k.hi.toFixed(3)}]`);
  console.log(`${set}${round ? ` round ${round}` : ""}: ${report.labelledByBoth}/${report.units} units labelled by both`);
  console.log(`  level 1 kappa ${fmt(report.level1)}, agreement ${report.level1.agreement == null ? "n/a" : report.level1.agreement.toFixed(3)}`);
  console.log(`  level 2 kappa ${fmt(report.level2)}`);
  for (const c of CATEGORIES) console.log(`  ${c.padEnd(13)} n=${String(report.perCategory[c].n).padStart(3)}  level 1 ${fmt(report.perCategory[c].level1)}`);
  console.log(`  ${report.disagreements.length} disagreements written to disagreements-${set}.jsonl`);
  if (set === "calibration") {
    const g = gate(report);
    writeJson(join(labelsDir, "calibration-gate.json"), { ...g, round, at: new Date().toISOString(), report: { ...report, disagreements: undefined } });
    console.log(g.passed ? "Calibration gate PASSED: analysis labelling may start." : `Calibration gate not passed${g.complete ? "" : " (labelling incomplete)"}${g.failingCategories.length ? `; below 0.50: ${g.failingCategories.join(", ")}` : ""}.`);
  }
}

if (isMain(import.meta.url)) main().catch((e) => { console.error(e.message); process.exit(1); });
