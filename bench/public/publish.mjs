#!/usr/bin/env node
/**
 * E11b publishing step: one numbers file for the README and penthera.org,
 * built only from the result files, so no number is typed by hand.
 *
 *   node bench/public/publish.mjs --split test --before <dir>   # the real thing
 *   node bench/public/publish.mjs --split dev                    # a SAMPLE, for layout only
 *
 * Reads $PENTHERA_BENCH_CACHE/public/results/{bench}.{split}.json (Penthera
 * now), competitors-{bench}.{split}.json (the free tools), and, with
 * --before, the same files from the 1.9.0 run. Writes bench/public/published.json
 * and bench/public/PUBLISHED.md. Anything but the test split is marked sample.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { RESULTS, ROOT, wilson } from "./common.mjs";

const argv = process.argv.slice(2);
const opt = (k) => (argv.includes(k) ? argv[argv.indexOf(k) + 1] : null);
const split = opt("--split") || "dev";
const beforeDir = opt("--before");
const sample = split !== "test";
const read = (dir, name) => { const p = join(dir, name); return existsSync(p) ? JSON.parse(readFileSync(p, "utf-8")) : null; };

// Paid tools: none publishes results on these benchmarks (searched 2026-10-24).
const PAID = ["GitGuardian", "Socket", "Snyk", "Phylum", "Semgrep Pro"];

const rate = ([k, n]) => (n ? k / n : null);
const ci = ([k, n]) => { if (!n) return null; const w = wilson(k, n); return [w.lo, w.hi]; };
const f1 = (p, r) => (p && r ? (2 * p * r) / (p + r) : 0);
const median = (xs) => { const s = [...xs].sort((a, b) => a - b); const m = s.length >> 1; return s.length ? (s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2) : null; };
const mean = (xs) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);

// A rank means something only against a field: with fewer than this many
// other tools measured, the tables show scores and no rank (E11b § 7).
export const MIN_FIELD = 5;

/** Rank rows by `score` (higher is better) and summarise the other tools. */
function rank(rows, score) {
  const ranked = rows.filter((r) => r.score != null && !r.excluded).sort((a, b) => b.score - a.score);
  const others = ranked.filter((r) => r.kind === "tool");
  const ranks = others.length >= MIN_FIELD;
  if (ranks) ranked.forEach((r, i) => { r.rank = i + 1; });
  const summary = {};
  for (const k of Object.keys(score)) {
    const xs = others.map((r) => r[k]).filter((x) => x != null);
    summary[k] = { mean: mean(xs), median: median(xs) };
  }
  return { rows, of: ranked.length, ranked: ranks, field: others.length, others: summary };
}

// ── Secrets (CredData) ────────────────────────────────────────────────────

function secretsRow(name, version, kind, prec, rec, extra = {}) {
  const P = [prec.correct, prec.units], R = [rec.found, rec.n];
  const p = rate(P), r = rate(R);
  return { tool: name, version, kind, precision: P, precisionCI: ci(P), recall: R, recallCI: ci(R), f1: f1(p, r), p, r, score: f1(p, r), ...extra };
}

function secrets(now, before, tools) {
  const rows = [];
  if (now) rows.push(secretsRow("Penthera", now.env?.penthera?.slice(0, 7) || "now", "penthera", now.runs.asReported.prec.all, now.runs.asReported.rec.primary));
  if (before) rows.push(secretsRow("Penthera 1.9.0", "1.9.0", "penthera-before", before.runs.asReported.prec.all, before.runs.asReported.rec.primary, { excluded: true }));
  for (const [name, t] of Object.entries(tools?.tools || {})) {
    if (t.error || t.variantOf || !t.prec) continue;
    rows.push(secretsRow(name, t.version, "tool", t.prec.all, t.rec.primary, t.caveat ? { caveat: t.caveat, excluded: /trained on this dataset/.test(t.caveat) } : {}));
  }
  const out = rank(rows, { p: 1, r: 1, f1: 1 });
  return { title: "Leaked secrets (Samsung CredData)", measure: "F1 of strict precision and in-scope recall, as the CLI reports", n: now?.runs?.asReported?.rec?.primary?.n, ...out, skipped: tools?.skipped || {} };
}

// ── Malware (DataDog) ─────────────────────────────────────────────────────

function gdRate(t) {
  if (!t) return null;
  const k = (t.labels?.suspicious || 0) + (t.labels?.high_risk || 0);
  return [k, t.n];
}

// Ranked by Youden's J: the share of malicious packages caught minus the share
// of benign ones flagged (registered in E11b § 7 before the test half was read).
function youden(d, b) {
  const r = d && rate(d), fa = b && rate(b);
  return { r, fa, j: r != null && fa != null ? r - fa : null, score: r != null && fa != null ? r - fa : null };
}

function malware(now, before, tools, eco) {
  const groups = eco === "npm"
    ? { detect: "malicious npm malicious_intent, payload", all: "malicious npm malicious_intent", benign: "benign npm" }
    : { detect: "malicious pypi malicious_intent", all: "malicious pypi malicious_intent", benign: "benign pypi" };
  const pen = (res, name, version, kind, extra = {}) => {
    const d = res.table[groups.detect]?.["code-medium"], a = res.table[groups.all]?.["code-medium"], b = res.table[groups.benign]?.["code-medium"];
    return { tool: name, version, kind, detect: d, detectCI: d && ci(d), all: a, benign: b, benignCI: b && ci(b), ...youden(d, b), ...extra };
  };
  const rows = [];
  if (now) rows.push(pen(now, "Penthera", now.env?.penthera?.slice(0, 7) || "now", "penthera"));
  if (before) rows.push(pen(before, "Penthera 1.9.0", "1.9.0", "penthera-before", { excluded: true }));
  const g = tools?.guarddog;
  if (g) {
    const d = gdRate(g[groups.detect]) || (eco === "npm" ? null : gdRate(g[groups.all]));
    const b = gdRate(g[groups.benign]);
    rows.push({ tool: "GuardDog", version: tools.pins?.guarddog?.version, kind: "tool", detect: d, detectCI: d && ci(d), all: gdRate(g[groups.all]), benign: b, benignCI: b && ci(b), ...youden(d, b), caveat: "found most samples in this dataset, so its detection rate is inflated by construction" });
  }
  const out = rank(rows, { r: 1, fa: 1, j: 1 });
  return { title: `Malicious ${eco === "npm" ? "npm" : "PyPI"} packages (DataDog)`, measure: eco === "npm" ? "caught (packages with a payload) minus false alarms (benign packages): Youden's J" : "caught minus false alarms on benign packages: Youden's J", ...out };
}

// ── Library bugs (SecBench.js) ────────────────────────────────────────────

function library(now, before, tools) {
  const row = (name, version, kind, per, extra = {}) => {
    const c = per["command-injection"]?.strict || [0, 0], e = per["code-injection"]?.strict || [0, 0];
    const pooled = [c[0] + e[0], c[1] + e[1]];
    return { tool: name, version, kind, command: c, code: e, pooled, pooledCI: ci(pooled), score: rate(pooled), r: rate(pooled), ...extra };
  };
  const rows = [];
  if (now) rows.push(row("Penthera", now.env?.penthera?.slice(0, 7) || "now", "penthera", now.per));
  if (before) rows.push(row("Penthera 1.9.0", "1.9.0", "penthera-before", before.per, { excluded: true }));
  for (const [name, t] of Object.entries(tools?.tools || {})) if (!t.error && t.per) rows.push(row(name, t.version, "tool", t.per));
  const out = rank(rows, { r: 1 });
  return { title: "Injection bugs in JavaScript libraries (SecBench.js)", measure: "share of command and code injection bugs found in the right file", ...out };
}

// ── Build ─────────────────────────────────────────────────────────────────

const now = Object.fromEntries(["creddata", "malware", "secbench"].map((b) => [b, read(RESULTS, `${b}.${split}.json`)]));
const was = Object.fromEntries(["creddata", "malware", "secbench"].map((b) => [b, beforeDir ? read(beforeDir, `${b}.${split}.json`) : null]));
const comp = Object.fromEntries(["creddata", "malware", "secbench"].map((b) => [b, read(RESULTS, `competitors-${b}.${split}.json`)]));

// Results published elsewhere: other datasets, other versions, so context
// only, never a row in our tables.
const CONTEXT = {
  secrets: [{ title: "A comparative study of software secrets reporting by secret detection tools (2023): nine tools on SecretBench, ggshield included", url: "https://arxiv.org/abs/2307.00714" }],
  npm: [{ title: "How effective are npm malicious package detectors? (2026): eleven detectors on their own benchmark", url: "https://arxiv.org/abs/2603.27549" }],
  pypi: [{ title: "Cutting the Gordian knot: detecting malicious PyPI packages (USENIX Security 2026): GuardDog, Bandit4Mal and OSSGadget on PyPI", url: "https://arxiv.org/abs/2601.16463" }],
  library: [{ title: "Study of JavaScript static analysis tools for vulnerability detection in Node.js packages (2023): nine tools incl. CodeQL, NodeJsScan, ODGen", url: "https://www.researchgate.net/publication/367088656" }],
};

const published = {
  split, sample, date: new Date().toISOString().slice(0, 10),
  note: sample ? "SAMPLE: practice (dev) half, for layout only. Not a result." : "Sealed test half, scored once (E11b § 10).",
  paidTools: { names: PAID, note: "None publishes results on these benchmarks; we cannot measure them (cost and licence terms)." },
  benchmarks: {
    secrets: secrets(now.creddata, was.creddata, comp.creddata),
    npm: malware(now.malware, was.malware, comp.malware, "npm"),
    pypi: malware(now.malware, was.malware, comp.malware, "pypi"),
    library: library(now.secbench, was.secbench, comp.secbench),
  },
};
for (const [k, b] of Object.entries(published.benchmarks)) b.context = CONTEXT[k] || [];

// ── Markdown (README source) ─────────────────────────────────────────────

const pct = (x) => (x == null ? "n/a" : x.toFixed(2));
const kn = (a) => (a ? `${a[0]}/${a[1]}` : "n/a");
const civ = (c) => (c ? ` [${c[0].toFixed(2)}, ${c[1].toFixed(2)}]` : "");
const name = (r) => (r.kind === "penthera" ? `**${r.tool}**` : r.tool) + (r.version ? ` ${r.version}` : "");
const L = [];
if (sample) L.push("> **SAMPLE.** Practice (dev) half, for layout only. Not a result.", "");
const S = published.benchmarks.secrets;
L.push(`### ${S.title}`, "", "| Rank | Tool | Precision | Recall | F1 |", "|---:|---|---|---|---|");
for (const r of [...S.rows].sort((a, b) => (!!a.excluded - !!b.excluded) || ((b.score ?? -1) - (a.score ?? -1)))) L.push(`| ${r.rank ?? "–"} | ${name(r)}${r.caveat ? " ¹" : ""} | ${pct(r.p)}${civ(r.precisionCI)} | ${pct(r.r)}${civ(r.recallCI)} | ${pct(r.f1)} |`);
L.push(`| | Free tools, mean / median | ${pct(S.others.p.mean)} / ${pct(S.others.p.median)} | ${pct(S.others.r.mean)} / ${pct(S.others.r.median)} | ${pct(S.others.f1.mean)} / ${pct(S.others.f1.median)} |`, "");
for (const key of ["npm", "pypi"]) {
  const M = published.benchmarks[key];
  L.push(`### ${M.title}`, "", "| Rank | Tool | Caught | False alarms on benign packages | Caught minus false alarms |", "|---:|---|---|---|---|");
  for (const r of [...M.rows].sort((a, b) => (!!a.excluded - !!b.excluded) || ((b.score ?? -1) - (a.score ?? -1)))) L.push(`| ${r.rank ?? "–"} | ${name(r)}${r.caveat ? " ²" : ""} | ${pct(r.r)}${civ(r.detectCI)} (${kn(r.detect)}) | ${pct(r.fa)}${civ(r.benignCI)} (${kn(r.benign)}) | ${pct(r.j)} |`);
  L.push("");
}
const B = published.benchmarks.library;
L.push(`### ${B.title}`, "", "| Rank | Tool | Command injection | Code injection | Both |", "|---:|---|---|---|---|");
for (const r of [...B.rows].sort((a, b) => (!!a.excluded - !!b.excluded) || ((b.score ?? -1) - (a.score ?? -1)))) L.push(`| ${r.rank ?? "–"} | ${name(r)} | ${kn(r.command)} | ${kn(r.code)} | ${pct(r.r)}${civ(r.pooledCI)} |`);
L.push("", `A rank is shown only where at least ${MIN_FIELD} other free tools were measured; otherwise "–".`,
  "", `Paid tools (${PAID.join(", ")}) publish no results on these benchmarks, so they are not in the tables.`, "",
  "Published elsewhere, on other datasets (context, not comparable):", "",
  ...Object.values(published.benchmarks).flatMap((b) => b.context.map((c) => `- [${c.title}](${c.url})`)), "",
  "¹ Not ranked: trained on this dataset by its authors. ² Found most samples in this dataset, so its rate is inflated by construction.");

// Only the test split's numbers go in the repo; a sample stays in the cache.
const outDir = sample ? RESULTS : join(ROOT, "bench", "public");
writeFileSync(join(outDir, sample ? "published.sample.json" : "published.json"), JSON.stringify(published, null, 2) + "\n");
writeFileSync(join(outDir, sample ? "PUBLISHED.sample.md" : "PUBLISHED.md"), L.join("\n") + "\n");
// --readme <file>: write the tables between the README's markers. A sample
// only goes into a copy (--readme pointing outside the repo), never README.md.
const readme = opt("--readme");
if (readme) {
  if (sample && readme === join(ROOT, "README.md")) throw new Error("refusing to write sample numbers into README.md");
  const START = "<!-- public-benchmarks:start -->", END = "<!-- public-benchmarks:end -->";
  const text = readFileSync(readme, "utf-8");
  const a = text.indexOf(START), b = text.indexOf(END);
  if (a < 0 || b < a) throw new Error(`${readme}: no ${START} ... ${END} markers`);
  writeFileSync(readme, text.slice(0, a + START.length) + "\n" + L.join("\n").replace(/^### /gm, "#### ") + "\n" + text.slice(b));
}
console.log(L.join("\n"));
