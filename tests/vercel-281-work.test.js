/**
 * Vercel Security Review on PR 281, the work findings: each crafted input must
 * cost linear time (checked by the ratio across a doubling, which survives a
 * slow CI runner), and a library file past its work budget is incomplete (exit
 * 2), never a pass.
 * 1. nested destructured parameters with defaults were re-split per level
 * 5. parameterTaint kept slicing right-hand sides after the budget ran out
 * 6. an unclosed regex class `/[` was rescanned to the line end per slash
 * 7. nested exported object literals were re-split, uncharged
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/scan-repo.js";
import { lexJs } from "../lib/whitebox/js-lex.js";

const HEAD = 'const { exec } = require("child_process");\n';
const libRepo = (code) => {
  const d = mkdtempSync(join(tmpdir(), "penthera-281w-"));
  writeFileSync(join(d, "package.json"), JSON.stringify({ name: "l", version: "1.0.0", main: "index.js" }));
  writeFileSync(join(d, "index.js"), HEAD + code);
  return d;
};
const ms = async (fn) => { const s = performance.now(); const r = await fn(); return [performance.now() - s, r]; };
/** Time at n and 4n; linear work grows about 4x, quadratic about 16x. */
async function linear(gen, n) {
  await scanRepo(libRepo(gen(64))); // warm up
  const [a] = await ms(() => scanRepo(libRepo(gen(n))));
  const [b, r] = await ms(() => scanRepo(libRepo(gen(4 * n))));
  expect(b / Math.max(a, 20), `n=${n}: ${Math.round(a)} ms, 4n: ${Math.round(b)} ms`).toBeLessThan(9);
  // The budget alone can keep a quadratic path under the ratio, only slow: the fixed code is ~0.1 s here.
  expect(b, `4n took ${Math.round(b)} ms`).toBeLessThan(5000);
  return r;
}

describe("work stays linear on crafted library files", () => {
  it("1: nested destructured parameters with defaults", async () => {
    await linear((n) => `module.exports = function f(${"{a: ".repeat(n)}cmd = [1, (2), {x: 3}]${" } = {}".repeat(n)}) { exec(cmd); };\n`, 4000);
  }, 60_000);

  it("1: a parameter nested past the split depth still counts as a parameter", async () => {
    const r = await scanRepo(libRepo(`module.exports = function f(${"{a: ".repeat(200)}cmd = "x"${"}".repeat(200)}) { exec(cmd); };\n`));
    expect(r.findings.some((f) => /command-injection/.test(f.title) && f.severity !== "info")).toBe(true);
  });

  it("5: nested assignments stop at the budget and make the file incomplete", async () => {
    const r = await linear((n) => `module.exports = function f(cmd) {\n${Array.from({ length: n }, (_, i) => `v${i} = (() => { `).join("")}exec(cmd);${" })();".repeat(n)}\n};\n`, 3000);
    expect(r.incomplete?.length).toBeGreaterThan(0);
  }, 60_000);

  it("7: nested exported object literals are charged to the budget", async () => {
    await linear((n) => `module.exports = function f(cmd) { ${"return { a: (() => { ".repeat(n)}exec(cmd);${" })() };".repeat(n)} };\n`, 1500);
  }, 60_000);
});

describe("6: an unclosed regex class is not rescanned per slash", () => {
  const t = (n) => { const s = performance.now(); lexJs("( /[a ".repeat(n), null, { stringLineSeps: true }); return performance.now() - s; };
  it("stays linear", () => {
    t(1000);
    const a = t(20_000), b = t(80_000);
    expect(b / Math.max(a, 5)).toBeLessThan(9);
    expect(b).toBeLessThan(2000);
  });
  it("a valid literal after a failed class is still a regex", () => {
    expect(lexJs('( /[a ( /x"y/ ; z').code).toBe("( /[a ( /   / ; z");
  });
});
