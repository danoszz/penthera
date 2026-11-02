/**
 * The runtime-strings set (bench/runtime-strings/strings.json): real version
 * strings, labelled by hand, run through the real engine and the bundled packs.
 *
 * Each entry names one product and says what a correct engine reports for it:
 * the kind of evidence (exact, distro, branch, present, or none at all), one
 * verdict per bundled advisory for that product, and whether the line is end
 * of life. An entry the engine gets wrong today carries a `deviation`: the
 * label stays the truth, the test pins what the engine does now, and the entry
 * counts as a miss in the per-category table. Fixing the engine then fails
 * this test until the deviation is removed, so every fix is visible here.
 *
 * Labels are relative to the bundled packs (advisories and end-of-life dates
 * as of the pack's date), not to the day the test runs.
 */
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { rulesOf } from "../lib/rules/index.js";
import { PRODUCTS } from "../lib/advisories/products.js";
import { evidenceFromResponse, evidenceFromRepo } from "../lib/advisories/evidence.js";
import { matchRuntimeAdvisories, verdictFor } from "../lib/advisories/index.js";

const SET = JSON.parse(readFileSync(new URL("../bench/runtime-strings/strings.json", import.meta.url), "utf-8"));
const ADVISORIES = rulesOf("runtime-advisory");

// The engine's verdicts in the set's words.
const WORD = { affected: "affected", unsupported: "end-of-life-no-fix", check: "check-on-server", patched: "has-fix", none: "none" };
const VERDICTS = new Set(Object.values(WORD));
const KINDS = new Set(["exact", "distro", "branch", "present", "none"]);
const EOLS = new Set(["none", "end-of-life", "end-of-life-distro"]);

/** Evidence for one entry's input, through the same functions a scan uses. */
function evidenceOf(input) {
  if (input.headers) return evidenceFromResponse({ headers: input.headers, cookieNames: input.cookies || [] });
  const dir = mkdtempSync(join(tmpdir(), "penthera-strings-"));
  try {
    if (input.image) writeFileSync(join(dir, "Dockerfile"), `FROM ${input.image}\n`);
    else writeFileSync(join(dir, input.file), input.content);
    return evidenceFromRepo(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** What the engine says about `product` for this input, in the set's terms. */
function engineSays(entry) {
  const all = evidenceOf(entry.input);
  const ev = all.filter((e) => e.product === entry.product);
  const findings = matchRuntimeAdvisories(ev).filter((f) => f.title.startsWith(PRODUCTS[entry.product].name));
  if (!ev.length) return { kind: "none", verdicts: {}, eol: "none", findings };
  // Several headers naming the same version are one group in the engine too.
  const kinds = [...new Set(ev.map((e) => e.kind))];
  const versions = [...new Set(ev.map((e) => e.version?.raw ?? null))];
  if (kinds.length > 1 || versions.length > 1) throw new Error(`${entry.id}: more than one ${entry.product} version in one entry`);
  const eolFinding = findings.find((f) => f.rule === `${entry.product}-eol`);
  const eol = !eolFinding ? "none" : ev[0].kind === "distro" ? "end-of-life-distro" : "end-of-life";
  const verdicts = {};
  for (const adv of ADVISORIES.filter((a) => a.product === entry.product)) {
    const v = WORD[verdictFor(adv, ev[0], eolFinding ? {} : null).verdict];
    if (v !== "none") verdicts[adv.id] = v;
  }
  return { kind: kinds[0], verdicts, eol, findings };
}

/** The findings a report shows for these verdicts, per the table in lib/advisories/index.js. */
function expectedFindings(verdicts, eol) {
  const out = [];
  const byV = (w) => Object.entries(verdicts).filter(([, v]) => v === w).map(([id]) => id).sort();
  for (const id of byV("affected")) out.push(`affected:${id}`);
  for (const id of byV("end-of-life-no-fix")) out.push(`end-of-life-no-fix:${id}`);
  if (byV("check-on-server").length) out.push(`check-on-server:${byV("check-on-server").join(",")}`);
  if (eol !== "none") out.push(eol);
  if (!out.length && byV("has-fix").length) out.push("has-fix");
  return out.sort();
}

function shownFindings(findings) {
  return findings.flatMap((f) => {
    // A distribution build's end-of-life finding needs human review; an upstream
    // one is likely, or potential from a banner with no distribution token (#114).
    // An upstream one also lists the advisories its line will never get a fix for.
    if (f.rule?.endsWith("-eol")) {
      if (f.confidence === "needs-human-review") return "end-of-life-distro";
      return ["end-of-life", ...(f.advisories || []).map((id) => `end-of-life-no-fix:${id}`)];
    }
    if (f.severity === "info") return "has-fix";
    if (f.confidence === "needs-human-review") return `check-on-server:${f.rule.split(",").sort().join(",")}`;
    return `${/end-of-life line/.test(f.title) ? "end-of-life-no-fix" : "affected"}:${f.rule}`;
  }).sort();
}

const label = (e) => ({ kind: e.kind, verdicts: e.verdicts, eol: e.eol });
const said = (s) => ({ kind: s.kind, verdicts: s.verdicts, eol: s.eol });
const tally = new Map();

describe("runtime-strings set", () => {
  it("is well formed: unique ids, known products, kinds, verdicts and advisories, a source for each", () => {
    expect(SET.entries.length).toBeGreaterThanOrEqual(150);
    const seen = new Set();
    for (const e of SET.entries) {
      expect(seen.has(e.id), e.id).toBe(false);
      seen.add(e.id);
      expect(Object.keys(PRODUCTS), e.id).toContain(e.product);
      expect(SET.categories, e.id).toHaveProperty(e.category);
      expect(KINDS.has(e.kind), e.id).toBe(true);
      expect(EOLS.has(e.eol), e.id).toBe(true);
      expect(e.source, e.id).toMatch(/^https:\/\//);
      expect(e.note, e.id).toBeTruthy();
      expect(Object.keys(e.input).filter((k) => ["headers", "image", "file"].includes(k)), e.id).toHaveLength(1);
      for (const [id, v] of Object.entries(e.verdicts)) {
        expect(ADVISORIES.find((a) => a.id === id && a.product === e.product), `${e.id}: ${id}`).toBeTruthy();
        expect(VERDICTS.has(v) && v !== "none", `${e.id}: ${v}`).toBe(true);
      }
      if (e.deviation) expect(SET.deviations, e.id).toHaveProperty(e.deviation.id);
    }
    for (const p of Object.keys(PRODUCTS)) expect(SET.entries.filter((e) => e.product === p).length, p).toBeGreaterThanOrEqual(10);
  });

  it("strings.json is what bench/runtime-strings/label.mjs drafts from rows.mjs", () => {
    const r = spawnSync(process.execPath, [fileURLToPath(new URL("../bench/runtime-strings/label.mjs", import.meta.url)), "--check"], { encoding: "utf-8" });
    // On failure, label.mjs's message says why (a stale file, or a deviation the engine no longer shows).
    expect(r.status, r.stderr.split("\n").find((l) => /Error|stale/.test(l)) || r.stderr).toBe(0);
  });

  for (const e of SET.entries) {
    it(`${e.category} / ${e.id}`, () => {
      const s = engineSays(e);
      // The report must show what the verdicts imply, whatever they are.
      expect(shownFindings(s.findings)).toEqual(expectedFindings(s.verdicts, s.eol));
      const ok = JSON.stringify(said(s)) === JSON.stringify(label(e));
      // What the report shows (verdicts and end of life), whatever the evidence kind.
      const shown = JSON.stringify([s.verdicts, s.eol]) === JSON.stringify([e.verdicts, e.eol]);
      const t = tally.get(e.category) || { pass: 0, shown: 0, total: 0, deviations: [] };
      t.total++;
      if (ok) t.pass++;
      if (shown) t.shown++;
      if (!ok) t.deviations.push(`${e.id}${shown ? " (kind only)" : ""}`);
      tally.set(e.category, t);
      if (e.deviation) {
        // Still wrong in the known way; when a fix lands, update the entry.
        expect(ok, `${e.id} now matches its label: remove deviation ${e.deviation.id}`).toBe(false);
        expect(said(s)).toEqual({ kind: e.deviation.engine.kind ?? e.kind, verdicts: e.deviation.engine.verdicts ?? e.verdicts, eol: e.deviation.engine.eol ?? e.eol });
      } else {
        expect(said(s)).toEqual(label(e));
      }
    });
  }

  it("the promises hold on every labelled string the engine reads as intended", () => {
    for (const e of SET.entries.filter((x) => !x.deviation)) {
      const v = Object.values(e.verdicts);
      // A distribution build is never "affected" and never "end of life, no fix".
      if (e.kind === "distro") expect(v.filter((x) => x === "affected" || x === "end-of-life-no-fix"), e.id).toEqual([]);
      // A hidden or partial version is never "has the fix".
      if (e.kind === "present" || e.kind === "branch") expect(v, e.id).not.toContain("has-fix");
      // A lookalike or a string with no version evidence gives nothing.
      if (e.kind === "none") expect(v.length + (e.eol === "none" ? 0 : 1), e.id).toBe(0);
    }
  });

  it("an exact version from a banner with no distribution token is never more than potential (#114)", () => {
    const ADV = new Map(ADVISORIES.map((a) => [a.id, a]));
    let banners = 0, pins = 0;
    for (const e of SET.entries) {
      const s = engineSays(e);
      if (s.kind !== "exact") continue;
      // "affected" and "end of life" findings; "end of life, no fix" is always potential.
      const claims = s.findings.filter((f) => f.confidence !== "needs-human-review" && (f.rule?.endsWith("-eol") || / is affected by /.test(f.title)));
      if (!claims.length) continue;
      if (e.input.headers && PRODUCTS[e.product].backports) {
        banners++;
        for (const f of claims) {
          expect(f.confidence, `${e.id}: ${f.title}`).toBe("potential");
          expect(f.description, e.id).toMatch(/your distribution may have patched this under the same version number/);
        }
      } else if (!e.input.headers) {
        pins++;
        // An official image or a version file is an upstream build: likely, unless the advisory has a condition.
        for (const f of claims) expect(f.confidence, `${e.id}: ${f.title}`).toBe(ADV.get(f.rule)?.condition ? "potential" : "likely");
      }
    }
    expect(banners).toBeGreaterThan(20);
    expect(pins).toBeGreaterThan(10);
  });

  afterAll(() => {
    const rows = [...tally].sort(([a], [b]) => a.localeCompare(b));
    const total = rows.reduce((n, [, t]) => n + t.total, 0);
    const pass = rows.reduce((n, [, t]) => n + t.pass, 0);
    const shown = rows.reduce((n, [, t]) => n + t.shown, 0);
    const pct = (p, n) => `${((100 * p) / n).toFixed(1)}%`.padStart(6);
    const line = (c, p, s, n) => `  ${c.padEnd(18)} ${`${p}/${n}`.padStart(7)} ${pct(p, n)}   ${`${s}/${n}`.padStart(7)} ${pct(s, n)}`;
    console.log([
      "runtime-strings, per category: label matched exactly (kind, verdicts, end of life) | report matched (verdicts, end of life)",
      ...rows.map(([c, t]) => `${line(c, t.pass, t.shown, t.total)}${t.deviations.length ? `   misses: ${t.deviations.join(", ")}` : ""}`),
      line("total", pass, shown, total),
    ].join("\n"));
  });
});
