#!/usr/bin/env node
/**
 * Penthera Bench v1: score the labelled sample and write RESULTS.md (E1 § 7, § 8).
 *
 *   node bench/real-world/score.js --corpus bench/real-world/pilot/corpus.json
 *
 * Precision per category with Wilson intervals; overall precision as the
 * category-stratified estimate weighted by each category's share of all
 * flagged units, with a Wilson interval at the Kish effective sample size;
 * recall from the labelled sample of unflagged units; a cluster bootstrap over
 * projects; hypotheses H1 to H3 with Holm-adjusted p-values. Only aggregate
 * numbers are written: no file paths, code, or secret values from the corpus.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { BENCH_DIR, CATEGORIES, REPO_ROOT, STRATA, cacheDir, included, isMain, parseArgs, projectId, readJson, readJsonl, readManifest, sha256, studyDir } from "./lib.js";
import { wilson, newcombeDiff, kishN, clusterBootstrap, percentile, holm } from "./stats.js";
import { agreement, finalLabels } from "./kappa.js";

const H1_THRESHOLD = 0.7;

function normCdf(x) {
  // Abramowitz and Stegun 7.1.26 (|error| < 1.5e-7).
  const t = 1 / (1 + 0.3275911 * Math.abs(x) / Math.SQRT2);
  const y = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-(x * x) / 2);
  return x >= 0 ? (1 + y) / 2 : (1 - y) / 2;
}

/**
 * Precision and recall estimates from labelled units and population counts.
 * @param {object[]} rows labelled analysis units: { project, category, flagged, confidence, stratum, correct: bool, actionable: bool }
 * @param {Record<string, {flagged: object, unflagged: object}>} pop per-project counts
 * @param {string[]} projects the (possibly resampled) project list, with multiplicity
 */
export function estimate(rows, pop, projects, { level = "correct" } = {}) {
  const byProject = new Map();
  for (const r of rows) {
    if (!byProject.has(r.project)) byProject.set(r.project, []);
    byProject.get(r.project).push(r);
  }
  const cat = Object.fromEntries(CATEGORIES.map((c) => [c, { N: 0, U: 0, x: 0, n: 0, fx: 0, fn: 0 }]));
  for (const id of projects) {
    const p = pop[id];
    if (!p) continue;
    for (const c of CATEGORIES) { cat[c].N += p.flagged[c] || 0; cat[c].U += p.unflagged[c] || 0; }
    for (const r of byProject.get(id) || []) {
      const s = cat[r.category];
      if (!s) continue;
      const yes = level === "correct" ? r.correct : r.actionable;
      if (r.flagged) { s.n++; if (yes) s.x++; } else { s.fn++; if (r.correct) s.fx++; }
    }
  }
  const withData = CATEGORIES.filter((c) => cat[c].n > 0 && cat[c].N > 0);
  const W = withData.reduce((a, c) => a + cat[c].N, 0);
  let p = null;
  let weights = [];
  if (W > 0) {
    p = withData.reduce((a, c) => a + (cat[c].N / W) * (cat[c].x / cat[c].n), 0);
    weights = withData.flatMap((c) => new Array(cat[c].n).fill(cat[c].N / W / cat[c].n));
  }
  // Recall: TP scaled to all flagged units, FN from the unflagged sample (§ 7).
  let tp = 0;
  let fnHat = 0;
  for (const c of CATEGORIES) {
    const s = cat[c];
    if (s.n === 0 || s.fn === 0) continue;
    tp += (s.x / s.n) * s.N;
    fnHat += (s.fx / s.fn) * s.U;
  }
  const recall = tp + fnHat > 0 ? tp / (tp + fnHat) : null;
  return { precision: p, nEff: weights.length ? kishN(weights) : 0, recall, cat, tp, fnHat };
}

const f3 = (x) => (x == null || Number.isNaN(x) ? "n/a" : x.toFixed(3));
const ci = (lo, hi) => (lo == null ? "n/a" : `[${f3(lo)}, ${f3(hi)}]`);
const fp = (p) => (p == null ? "n/a" : p < 0.001 ? "< 0.001" : p.toFixed(3));

/** Score a study. Returns { md, results }. */
export function score({ manifest, cache, labelsDir, reps = 10000, seed = 20261020, synthetic = false, now = new Date(), outPath = resolve(BENCH_DIR, "RESULTS.md") }) {
  const out = studyDir(cache, manifest.set);
  labelsDir = labelsDir || out;
  const population = readJson(join(out, "population.json"), null);
  if (!population) throw new Error(`No study in ${out}. Run units.js first.`);
  const units = readJsonl(join(out, "units-key.jsonl"));
  const labelsA = readJsonl(join(labelsDir, "labels-A.jsonl"));
  const labelsB = readJsonl(join(labelsDir, "labels-B.jsonl"));
  const adjudications = readJsonl(join(labelsDir, "adjudications.jsonl"));
  const { labels, unresolved, missing } = finalLabels(units, labelsA, labelsB, adjudications, "analysis");
  const rows = units.filter((u) => u.set === "analysis" && labels.has(u.id)).map((u) => {
    const l = labels.get(u.id);
    // Primary analysis: "cannot tell" counts as no (§ 2).
    return { ...u, label: l, correct: l.correct === "yes", actionable: l.actionable === "yes" };
  });
  const pop = population.projects;
  const projects = Object.keys(pop);

  const main = estimate(rows, pop, projects);
  const main2 = estimate(rows, pop, projects, { level: "actionable" });
  const wPrimary = wilson(main.precision * main.nEff, main.nEff);
  const flaggedRows = rows.filter((r) => r.flagged);
  const pooled = wilson(flaggedRows.filter((r) => r.correct).length, flaggedRows.length);
  const pooled2 = wilson(flaggedRows.filter((r) => r.actionable).length, flaggedRows.length);
  const sens = flaggedRows.filter((r) => r.label.correct !== "cannot");
  const pooledSens = wilson(sens.filter((r) => r.correct).length, sens.length);

  // Cluster bootstrap over projects (§ 8.3, § 7).
  const boots = projects.length > 1 && rows.length ? clusterBootstrap(projects, (s) => estimate(rows, pop, s), { reps, seed }) : [];
  const bp = boots.map((b) => b.precision);
  const br = boots.map((b) => b.recall);
  const bd = boots.map((b) => (b.precision != null && b.recall != null ? b.precision - b.recall : null)).filter((x) => x != null);
  const bootP = { lo: percentile(bp, 0.025), hi: percentile(bp, 0.975) };
  const bootR = { lo: percentile(br, 0.025), hi: percentile(br, 0.975) };
  const bootD = { lo: percentile(bd, 0.025), hi: percentile(bd, 0.975) };
  const useBoot = bootP.lo != null && wPrimary.lo != null && (Math.abs(bootP.lo - wPrimary.lo) > 0.02 || Math.abs(bootP.hi - wPrimary.hi) > 0.02);
  const h1ci = useBoot ? bootP : wPrimary;
  const varBoot = bp.length > 1 ? bp.reduce((a, x) => a + (x - main.precision) ** 2, 0) / (bp.length - 1) : null;
  const deff = varBoot != null && main.precision > 0 && main.precision < 1 && main.nEff > 0 ? varBoot / ((main.precision * (1 - main.precision)) / main.nEff) : null;

  // Hypotheses.
  const p1 = main.precision != null && main.nEff > 0 ? 1 - normCdf((main.precision - H1_THRESHOLD) / Math.sqrt((H1_THRESHOLD * (1 - H1_THRESHOLD)) / main.nEff)) : null;
  const byConf = (c) => flaggedRows.filter((r) => r.confidence === c);
  const conf = byConf("confirmed");
  const pot = byConf("potential");
  const h2 = newcombeDiff(conf.filter((r) => r.correct).length, conf.length, pot.filter((r) => r.correct).length, pot.length);
  let p2 = null;
  if (conf.length && pot.length) {
    const x1 = conf.filter((r) => r.correct).length;
    const x2 = pot.filter((r) => r.correct).length;
    const pp = (x1 + x2) / (conf.length + pot.length);
    const se = Math.sqrt(pp * (1 - pp) * (1 / conf.length + 1 / pot.length));
    p2 = se > 0 ? 1 - normCdf((x1 / conf.length - x2 / pot.length) / se) : null;
  }
  const p3 = bd.length ? bd.filter((d) => d <= 0).length / bd.length : null;
  const adj = holm([p1, p2, p3]);
  const hyp = [
    { id: "H1", text: "Overall precision (correct) above 0.70", estimate: main.precision, ci: h1ci, supported: h1ci.lo != null ? h1ci.lo > H1_THRESHOLD : null, p: p1, pAdj: adj[0], note: useBoot ? "cluster bootstrap interval (differs from Wilson by > 0.02)" : "Wilson interval at Kish effective n" },
    { id: "H2", text: "confirmed more precise than potential", estimate: h2.d, ci: { lo: h2.lo, hi: h2.hi }, supported: h2.lo != null ? h2.lo > 0 : null, p: p2, pAdj: adj[1], note: "Newcombe method 10" },
    { id: "H3", text: "Recall lower than precision", estimate: main.precision != null && main.recall != null ? main.precision - main.recall : null, ci: bootD, supported: bootD.lo != null ? bootD.lo > 0 : null, p: p3, pAdj: adj[2], note: "paired cluster bootstrap" },
  ];

  const kappa = agreement(units, labelsA, labelsB, "analysis");
  const metas = included(manifest).map((p) => readJson(join(cache, "scans", manifest.set, projectId(p.url), "meta.json"), null)).filter(Boolean);
  const scanner = metas[0]?.scanner || {};
  const netRefusals = metas.reduce((a, m) => a + (m.networkRefusals || 0), 0);
  const isPilot = manifest.set === "pilot";
  const hashOf = (p) => (existsSync(p) ? sha256(readFileSync(p)).slice(0, 16) : "none");

  const L = [];
  L.push("# Penthera Bench v1: real-world results");
  L.push("");
  if (isPilot) L.push("> **Pilot, not part of the pre-registered sample.** These projects were chosen to test the pipeline and are excluded from the E1 frame. Nothing here is a measurement of Penthera's accuracy.", "");
  if (synthetic) L.push("> **Pipeline check with synthetic labels.** The labels below were generated by a script, not by people, to exercise κ and scoring end to end. Every precision, recall and κ figure in this file is meaningless as a measurement.", "");
  L.push(`Generated by \`node bench/real-world/score.js\` on ${now.toISOString().slice(0, 10)}. Do not edit by hand. Method: [E1 pre-registration](${relative(dirname(outPath), resolve(REPO_ROOT, "docs/research/prereg/E1-real-world-accuracy.md")).split("\\").join("/")}).`, "");
  L.push("## Provenance", "");
  L.push(`- Corpus set: \`${manifest.set}\`, ${included(manifest).length} projects, manifest sha256 \`${sha256(JSON.stringify(manifest)).slice(0, 16)}\``);
  L.push(`- Scanner: penthera ${scanner.version || "?"}${scanner.frozen ? ` from npm (${scanner.integrity})` : " (development build, not the frozen release)"}; Node ${metas[0]?.node || process.version}`);
  L.push(`- Sampling seed: \`${String(population.seed).slice(0, 16)}\`; bootstrap: ${boots.length} resamples, seed ${seed}`);
  L.push(`- Label files: A \`${hashOf(join(labelsDir, "labels-A.jsonl"))}\`, B \`${hashOf(join(labelsDir, "labels-B.jsonl"))}\`, adjudications \`${hashOf(join(labelsDir, "adjudications.jsonl"))}\``);
  L.push(`- Network connections refused during scans: **${netRefusals}**`);
  L.push("");
  L.push("## Scans", "");
  L.push("| Stratum | Projects | repo ok | deps ok / no input | agents ok | Flagged units | Other findings |", "|---|---:|---:|---:|---:|---:|---:|");
  for (const s of STRATA) {
    const ms = metas.filter((m) => m.stratum === s);
    if (!ms.length) continue;
    const ids = ms.map((m) => m.id);
    const fl = ids.reduce((a, id) => a + CATEGORIES.reduce((b, c) => b + (pop[id]?.flagged[c] || 0), 0), 0);
    const ot = ids.reduce((a, id) => a + (pop[id]?.other || 0), 0);
    L.push(`| ${s} | ${ms.length} | ${ms.filter((m) => m.scans.repo?.ok).length} | ${ms.filter((m) => m.scans.deps?.ok).length} / ${ms.filter((m) => m.scans.deps?.noInput).length} | ${ms.filter((m) => m.scans.agents?.ok).length} | ${fl} | ${ot} |`);
  }
  L.push("", "\"Other findings\" are non-info findings that map to no E1 category; they are counted, not labelled.", "");
  L.push("## Units", "");
  L.push("| Category | Flagged (population) | Unflagged candidates | Flagged labelled | Unflagged labelled | Skipped, package too large |", "|---|---:|---:|---:|---:|---:|");
  for (const c of CATEGORIES) {
    const s = main.cat[c];
    L.push(`| ${c} | ${s.N} | ${s.U} | ${s.n} | ${s.fn} | ${population.skippedUnreadable?.[c] ?? 0} |`);
  }
  L.push("", `Analysis units: ${units.filter((u) => u.set === "analysis").length}; labelled by both and resolved: ${rows.length}; disagreements without adjudication: ${unresolved}; not labelled by both: ${missing}.`, "");
  L.push("## Precision", "");
  L.push("| | Estimate | 95% CI | n |", "|---|---:|---|---:|");
  L.push(`| **Overall, correct (primary, stratified)** | **${f3(main.precision)}** | ${ci(wPrimary.lo, wPrimary.hi)} | ${main.nEff.toFixed(1)} (Kish) |`);
  L.push(`| Overall, correct, cluster bootstrap | | ${ci(bootP.lo, bootP.hi)} | ${projects.length} projects |`);
  L.push(`| Overall, correct, unweighted pooled | ${f3(pooled.p)} | ${ci(pooled.lo, pooled.hi)} | ${pooled.n} |`);
  L.push(`| Overall, correct, "cannot tell" dropped | ${f3(pooledSens.p)} | ${ci(pooledSens.lo, pooledSens.hi)} | ${pooledSens.n} |`);
  L.push(`| Overall, actionable (level 2, stratified) | ${f3(main2.precision)} | ${ci(wilson(main2.precision * main2.nEff, main2.nEff).lo, wilson(main2.precision * main2.nEff, main2.nEff).hi)} | ${main2.nEff.toFixed(1)} |`);
  L.push(`| Overall, actionable, unweighted pooled | ${f3(pooled2.p)} | ${ci(pooled2.lo, pooled2.hi)} | ${pooled2.n} |`);
  for (const c of CATEGORIES) {
    const w = wilson(main.cat[c].x, main.cat[c].n);
    L.push(`| ${c} | ${f3(w.p)} | ${ci(w.lo, w.hi)} | ${w.n} |`);
  }
  L.push("", `Estimated design effect (bootstrap variance over binomial variance): ${f3(deff)}.`, "");
  L.push("### By confidence label", "", "| Confidence | Precision | 95% CI | n |", "|---|---:|---|---:|");
  for (const c of ["confirmed", "likely", "potential", "needs-human-review"]) {
    const r = byConf(c);
    const w = wilson(r.filter((x) => x.correct).length, r.length);
    L.push(`| ${c} | ${f3(w.p)} | ${ci(w.lo, w.hi)} | ${w.n} |`);
  }
  L.push("", "### By stratum", "", "| Stratum | Precision | 95% CI | n |", "|---|---:|---|---:|");
  for (const s of STRATA) {
    const r = flaggedRows.filter((x) => x.stratum === s);
    if (!r.length) continue;
    const w = wilson(r.filter((x) => x.correct).length, r.length);
    L.push(`| ${s} | ${f3(w.p)} | ${ci(w.lo, w.hi)} | ${w.n} |`);
  }
  L.push("", "## Recall", "");
  L.push("Recall is estimated from a blind, labelled sample of units Penthera did not flag (E1 § 7). It covers only the categories Penthera claims, and it is an upper bound: issues the labellers also missed are not counted.", "");
  L.push("| | Estimate | 95% CI | Issues in unflagged sample |", "|---|---:|---|---:|");
  L.push(`| **Overall** | **${f3(main.recall)}** | ${ci(bootR.lo, bootR.hi)} (cluster bootstrap) | ${CATEGORIES.reduce((a, c) => a + main.cat[c].fx, 0)} / ${CATEGORIES.reduce((a, c) => a + main.cat[c].fn, 0)} |`);
  for (const c of CATEGORIES) {
    const s = main.cat[c];
    const tp = s.n ? (s.x / s.n) * s.N : null;
    const fnh = s.fn ? (s.fx / s.fn) * s.U : null;
    const r = tp != null && fnh != null && tp + fnh > 0 ? tp / (tp + fnh) : null;
    const piw = wilson(s.fx, s.fn);
    L.push(`| ${c} | ${f3(r)} | miss rate ${ci(piw.lo, piw.hi)} | ${s.fx} / ${s.fn} |`);
  }
  L.push("", "Seeded issues (secondary recall estimate, § 6.5): not run in this version of the tooling.", "");
  L.push("## Hypotheses", "", "| | Hypothesis | Estimate | 95% CI | p (one-sided) | p (Holm) | Supported | Interval |", "|---|---|---:|---|---:|---:|---|---|");
  for (const h of hyp) L.push(`| ${h.id} | ${h.text} | ${f3(h.estimate)} | ${ci(h.ci.lo, h.ci.hi)} | ${fp(h.p)} | ${fp(h.pAdj)} | ${h.supported == null ? "n/a" : h.supported ? "yes" : "no"} | ${h.note} |`);
  L.push("", "## Agreement (analysis set)", "");
  const fk = (k) => (k.kappa == null ? "n/a" : `${f3(k.kappa)} ${ci(k.lo, k.hi)}`);
  L.push(`Cohen's κ, level 1: ${fk(kappa.level1)}, raw agreement ${f3(kappa.level1.agreement)}; level 2: ${fk(kappa.level2)}; ${kappa.labelledByBoth} units labelled by both.`, "");
  L.push("| Category | n | κ level 1 |", "|---|---:|---|");
  for (const c of CATEGORIES) L.push(`| ${c} | ${kappa.perCategory[c].n} | ${fk(kappa.perCategory[c].level1)} |`);
  L.push("", "## Limits", "");
  L.push("- Static analysis of each project at one pinned commit, with the frozen scanner; no URL scanning, so black-box findings are out of scope.");
  L.push("- FastAPI projects have no route or code-pattern units: Penthera's route discovery reads JavaScript and TypeScript only.");
  L.push("- Dependency recall covers packages of at most 200 KB of source whose tarball or wheel could be read.");
  L.push("- Recall is an upper bound (labellers miss issues too) and covers only the categories listed.");
  L.push("");
  const results = { main, main2, wPrimary, pooled, bootP, bootR, bootD, hyp, kappa: { level1: kappa.level1, level2: kappa.level2 }, deff, unresolved, missing };
  return { md: L.join("\n"), results };
}

async function main() {
  const args = parseArgs(process.argv.slice(2), ["allow-file", "synthetic"]);
  if (!args.corpus) {
    console.error("usage: node bench/real-world/score.js --corpus <manifest.json> [--out RESULTS.md] [--labels-dir <dir>] [--reps 10000] [--synthetic] [--cache <dir>]");
    process.exit(2);
  }
  const cache = cacheDir(args.cache);
  const manifestPath = resolve(args.corpus);
  const manifest = readManifest(manifestPath, { allowFile: !!args["allow-file"] });
  const outPath = resolve(args.out || join(dirname(manifestPath), "RESULTS.md"));
  const { md } = score({ manifest, cache, labelsDir: args["labels-dir"] ? resolve(args["labels-dir"]) : null, reps: Number(args.reps || 10000), synthetic: !!args.synthetic, outPath });
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, md);
  console.log(`Wrote ${relative(process.cwd(), outPath)}`);
}

if (isMain(import.meta.url)) main().catch((e) => { console.error(e.message); process.exit(1); });
