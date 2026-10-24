#!/usr/bin/env node
/**
 * E11b pass 1 (workstream A2): simulate the proposed file coverage on the
 * CredData dev split, from the cached dev scan (rule hits on every file), before
 * any change to lib/. Dev only: refuses any other split.
 *
 *   PENTHERA_E11_SPLIT=dev node bench/public/sim-a2.mjs [--sheet out.md]
 *
 * Policy under review:
 *   - read today's types, plus .pem .key .p8 .ppk .php .cs .properties .conf .xml .tfstate;
 *   - also read any file whose first non-blank line is a PEM private-key header;
 *   - in .txt and .md, keep only the high-precision rules (provider prefixes,
 *     private keys, service-account JSON), never the assignment guesses.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CACHE, RESULTS, SEED, shuffled } from "./common.mjs";
import { loadMeta, scoreHits, family, PRIMARY } from "./creddata.mjs";
import { inSplit, currentSplit } from "./split.mjs";

if (currentSplit() !== "dev") throw new Error("sim-a2 runs on the dev split only (PENTHERA_E11_SPLIT=dev)");
const DIR = join(CACHE, "creddata");
const argv = process.argv.slice(2);
const sheetPath = argv.includes("--sheet") ? argv[argv.indexOf("--sheet") + 1] : null;

const ADD = new Set([".pem", ".key", ".p8", ".ppk", ".php", ".cs", ".properties", ".conf", ".xml", ".tfstate"]);
const DOCS = new Set([".txt", ".md"]);
const GUESSES = new Set(["Hardcoded password", "Generic API key assignment", "JWT secret assignment", "Hardcoded session secret"]);
const extOf = (f) => { const b = f.split("/").pop(); return b.includes(".") ? b.slice(b.lastIndexOf(".")) : "(none)"; };
const KEY_HEAD = /^\s*-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const startsWithKey = (f) => { try { return KEY_HEAD.test(readFileSync(join(DIR, f), "utf-8").slice(0, 4096)); } catch { return false; } };

const raw = JSON.parse(readFileSync(join(RESULTS, "creddata.dev.raw.json"), "utf-8"));
const keep = inSplit("creddata");
const rows = loadMeta().filter((r) => keep(r.file)).map((r) => ({ ...r, ext: extOf(r.file), read: true }));

const why = new Map();
function policy(h) {
  if (h.read) return "today";
  const e = extOf(h.file);
  if (ADD.has(e)) return `type ${e}`;
  if (DOCS.has(e)) return GUESSES.has(h.rule) ? null : `docs ${e}, high-precision rule`;
  if (startsWithKey(h.file)) return "content: key header";
  return null;
}
const before = raw.hits.filter((h) => h.read);
const after = raw.hits.filter((h) => { const w = policy(h); if (w) why.set(`${h.file}:${h.line}`, w); return !!w; });

const A = scoreHits(rows, before), B = scoreHits(rows, after);
const fmt = (o, d = "labelled") => `${(o.correct / o[d]).toFixed(2)} (${o.correct}/${o[d]})`;
const rfmt = (o) => `${(o.found / o.n).toFixed(2)} (${o.found}/${o.n})`;

// Units new under the policy, and in-scope true rows still missed.
const key = (h) => `${h.file}:${h.line}`;
const had = new Set(before.map(key));
const units = new Map();
for (const h of after) if (!had.has(key(h))) (units.get(key(h)) || units.set(key(h), { file: h.file, line: h.line, rules: new Set() }).get(key(h))).rules.add(h.rule);
const label = (u) => { const m = rows.filter((r) => r.file === u.file && u.line >= r.ls && u.line <= r.le); return m.some((r) => r.gt === "T") ? "T" : m.length ? m[0].gt : "unlabelled"; };
const newUnits = [...units.values()].map((u) => ({ ...u, gt: label(u), why: why.get(key(u)) }));
const hitLines = new Map();
for (const h of after) (hitLines.get(h.file) || hitLines.set(h.file, new Set()).get(h.file)).add(h.line);
const missed = rows.filter((r) => r.gt === "T" && PRIMARY.includes(family(r.cats)) && ![...Array(r.le - r.ls + 1).keys()].some((i) => hitLines.get(r.file)?.has(r.ls + i)));

const summary = {
  precisionLabelled: [fmt(A.prec.all), fmt(B.prec.all)],
  precisionStrict: [fmt(A.prec.all, "units"), fmt(B.prec.all, "units")],
  recallRow: [rfmt(A.rec.primary), rfmt(B.rec.primary)],
  recallFileMatched: [rfmt(A.rec["file:matched"]), rfmt(B.rec["file:matched"])],
  families: Object.fromEntries(PRIMARY.map((f) => [f, [rfmt(A.rec[`family:${f}`]), rfmt(B.rec[`family:${f}`])]])),
  newUnits: newUnits.length, newByLabel: newUnits.reduce((o, u) => ((o[u.gt] = (o[u.gt] || 0) + 1), o), {}),
  newByWhy: newUnits.reduce((o, u) => ((o[u.why] = (o[u.why] || 0) + 1), o), {}),
  missed: missed.length,
  missedByExt: Object.entries(missed.reduce((o, r) => ((o[r.ext] = (o[r.ext] || 0) + 1), o), {})).sort((a, b) => b[1] - a[1]).slice(0, 12),
  missedByFamily: missed.reduce((o, r) => ((o[family(r.cats)] = (o[family(r.cats)] || 0) + 1), o), {}),
};
console.log(JSON.stringify(summary, null, 2));

if (sheetPath) {
  const pickNew = shuffled(newUnits.sort((a, b) => key(a).localeCompare(key(b))), SEED).list.slice(0, 10);
  const pickBad = shuffled(newUnits.filter((u) => u.gt !== "T").sort((a, b) => key(a).localeCompare(key(b))), SEED + 2).list.slice(0, 5);
  const pickMiss = shuffled(missed.sort((a, b) => a.id.localeCompare(b.id)), SEED + 1).list.slice(0, 10);
  const ctx = (file, ls, le) => {
    let lines; try { lines = readFileSync(join(DIR, file), "utf-8").split("\n"); } catch { return "(unreadable)"; }
    const a = Math.max(1, ls - 2), b = Math.min(lines.length, Math.min(le, ls + 3) + 2);
    return lines.slice(a - 1, b).map((t, i) => `${String(a + i).padStart(5)}${a + i >= ls && a + i <= le ? " >" : "  "} ${t.slice(0, 160)}`).join("\n");
  };
  const out = [];
  out.push(JSON.stringify(summary, null, 2), "", "## NEW", "");
  pickNew.forEach((u, i) => out.push(`### N${i + 1} ${u.file}:${u.line} [${u.gt}] ${[...u.rules].join(", ")} (${u.why})`, "```", ctx(u.file, u.line, u.line), "```", ""));
  out.push("## NEW, NOT TRUE", "");
  pickBad.forEach((u, i) => out.push(`### W${i + 1} ${u.file}:${u.line} [${u.gt}] ${[...u.rules].join(", ")} (${u.why})`, "```", ctx(u.file, u.line, u.line), "```", ""));
  out.push("## MISSED", "");
  pickMiss.forEach((r, i) => out.push(`### M${i + 1} ${r.file}:${r.ls}-${r.le} ${family(r.cats)} [${r.cats.join(":")}] ext ${r.ext}`, "```", ctx(r.file, r.ls, r.le), "```", ""));
  writeFileSync(sheetPath, out.join("\n"));
}
