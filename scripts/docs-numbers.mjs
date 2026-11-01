#!/usr/bin/env node
import { loadPopular } from "../lib/deps/typosquat.js";
// Prints the counts quoted in the README's "By the numbers" block, so they can
// be refreshed from the source instead of edited by hand. Offline, read-only.
//
//   node scripts/docs-numbers.mjs            # counts from the code and docs
//   node scripts/docs-numbers.mjs --tests    # also runs the test suite (a minute or two) to count tests

import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { BUILT_IN_TEMPLATES } from "../lib/templates.js";
import { CAPABILITIES } from "../lib/deps/capabilities.js";
import { RULE_OWASP } from "../lib/agents/owasp.js";

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");

const secretsSrc = read("lib/whitebox/secrets.js");
const patternsBlock = secretsSrc.slice(secretsSrc.indexOf("const SECRET_PATTERNS = ["));
// Inline patterns in secrets.js plus the ones it pulls from the core rule pack.
const corePack = JSON.parse(read("lib/rules/core/secrets.json"));
const secretPatterns = (patternsBlock.slice(0, patternsBlock.indexOf("\n];")).match(/\bname: "/g) || []).length
  + (Array.isArray(corePack) ? corePack : corePack.rules || []).length;

const recipes = readdirSync(new URL("../lib/fix/recipes", import.meta.url)).filter((f) => f.endsWith(".js")).length;
const references = (read("docs/references.bib").match(/^@/gm) || []).length;
const popular = loadPopular("npm").names.length;
const popularPypi = loadPopular("pypi").names.length;

const total = read("bench/RESULTS.md").match(/\| \*\*Total\*\* \|[^\n]*/)?.[0] ?? "";
const [tp, fp, fn, precision, recall] = total.replace(/\*/g, "").split("|").map((s) => s.trim()).filter(Boolean).slice(1);

/** The counts, for the site's build (site/build.mjs) as well as the printout below. */
export const COUNTS = {
  urlTemplates: BUILT_IN_TEMPLATES.length,
  secretPatterns,
  capabilities: Object.keys(CAPABILITIES).length,
  agentRules: Object.keys(RULE_OWASP).length,
  recipes,
  references,
  popularNpm: popular,
  popularPypi,
};

/**
 * Every readable rule in this release, the figure the README and the site quote.
 * The `core` pack holds rules already counted above, so only the other packs add to it.
 * @param {{name: string, count: number}[]} packs activePacks() from lib/rules
 */
export function totalRules(packs) {
  const packed = packs.filter((p) => p.name !== "core").reduce((n, p) => n + p.count, 0);
  return COUNTS.urlTemplates + COUNTS.secretPatterns + COUNTS.capabilities + COUNTS.agentRules + COUNTS.recipes + packed;
}

const rows = [
  ["URL scan templates (built in)", BUILT_IN_TEMPLATES.length],
  ["Secret and AI-key patterns", secretPatterns],
  ["Dependency capabilities", Object.keys(CAPABILITIES).length],
  ["AI-tooling audit rules", Object.keys(RULE_OWASP).length],
  ["Fix recipes", recipes],
  ["Popular npm names for typosquat checks", popular],
  ["Popular PyPI names for typosquat checks", popularPypi],
  ["Cited references (docs/references.bib)", references],
  ["Benchmark TP / FP / FN", `${tp} / ${fp} / ${fn}`],
  ["Benchmark precision / recall", `${precision} / ${recall}`],
];

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain && process.argv.includes("--tests")) {
  const vitest = new URL("../node_modules/.bin/vitest", import.meta.url).pathname;
  const dir = mkdtempSync(join(tmpdir(), "penthera-numbers-"));
  const file = join(dir, "vitest.json");
  try {
    execFileSync(vitest, ["run", "--reporter=json", `--outputFile=${file}`], { stdio: "ignore" });
  } catch {
    // a failing test still writes its counts
  }
  const r = JSON.parse(readFileSync(file, "utf8"));
  rmSync(dir, { recursive: true, force: true });
  rows.push(["Tests (total / passed / skipped)", `${r.numTotalTests} / ${r.numPassedTests} / ${r.numPendingTests}`]);
}

if (isMain) for (const [label, value] of rows) console.log(`${label.padEnd(42)} ${value}`);
