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
import { findSinks } from "../lib/whitebox/code-sinks.js";
import { firstShellPipe } from "../lib/agents/hidden-content.js";

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

describe("3: exported functions nested in default parameters", () => {
  it("are charged to the budget: linear, and incomplete past it", async () => {
    const r = await linear((n) => `${Array.from({ length: n }, (_, i) => `exports.f${i} = function (a${i} = `).join("")}1${") { exec(a0); }".repeat(n)};\n`, 2000);
    expect(r.incomplete?.length).toBeGreaterThan(0);
  }, 60_000);
});

describe("9: nested object literals in server code are split once", () => {
  const t = (n) => {
    const src = 'const cp = require("child_process");\n' + Array.from({ length: n }, (_, i) => `v${i} = { k${i}: cp.exec, a: `).join("") + "1" + " }".repeat(n) + ";\n";
    const s = performance.now(); findSinks(src); return performance.now() - s;
  };
  it("stays linear", () => {
    t(500);
    const a = t(2000), b = t(8000);
    expect(b / Math.max(a, 5)).toBeLessThan(9);
    expect(b).toBeLessThan(3000);
  });
  it("still binds a shell function held in an object, next to nested ones", () => {
    expect(findSinks('const cp = require("child_process");\nconst tools = { run: cp.exec, nested: { x: 1 } };\ntools.run(req.body.cmd);\n').map((f) => f.pattern)).toEqual(["command-injection"]);
    expect(findSinks('const cp = require("child_process");\nconst opts = { ...{ shell: true } };\ncp.spawn(req.body.cmd, [], opts);\n').map((f) => f.pattern)).toEqual(["command-injection"]);
  });
});

describe("6: pipes only the prose pass marks are read with the prose reading", () => {
  const unit = "a\\'b'c|";
  const t = (n) => { const s = performance.now(); firstShellPipe(unit.repeat(n)); return performance.now() - s; };
  it("stays linear on escaped and intra-word apostrophes", () => {
    t(500);
    const a = t(4000), b = t(16000);
    expect(b / Math.max(a, 5)).toBeLessThan(9);
    expect(b).toBeLessThan(2000);
  });
  it("prose and shell pipes are still found", () => {
    for (const s of ["don't worry | sh", "echo it's | sh", "a'b | /usr/bin/env bash"]) expect(firstShellPipe(s), s).not.toBe(-1);
  });
});

// Vercel review of 8b7af83 (row 15): a helper with thousands of parameters, called
// with thousands of copies of an exported parameter, scanned every parameter per argument.
describe("15: helper arguments map to parameters by position", () => {
  // Spread copies: each one named every later parameter (quadratic before).
  const gen = (n) => `function helper(${Array.from({ length: n }, (_, i) => `p${i}`).join(", ")}) { exec(p${n - 1}); }\nexports.run = function (...cmd) { helper(${Array(n).fill("...cmd").join(", ")}); };\n`;
  it("stays linear and still finds the sink", async () => {
    const r = await linear(gen, 1500);
    expect(r.findings.some((f) => /command-injection/.test(f.title) && f.severity !== "info") || r.incomplete?.length > 0).toBe(true);
  }, 60_000);
  it("position, rest and spread still map; a safe slot stays clean", async () => {
    const found = async (code) => (await scanRepo(libRepo(code))).findings.some((f) => /command-injection/.test(f.title) && f.severity !== "info");
    expect(await found(`function helper(a, b, c) { exec(c); }\nexports.run = function (cmd) { helper(1, 2, cmd); };\n`)).toBe(true);
    expect(await found(`function helper(a, ...rest) { exec(rest[1]); }\nexports.run = function (cmd) { helper(1, 2, cmd); };\n`)).toBe(true);
    expect(await found(`function helper(a, b, c) { exec(c); }\nexports.run = function (...cmd) { helper(...cmd); };\n`)).toBe(true);
    expect(await found(`function helper(a, b) { exec(b); }\nexports.run = function (cmd) { helper(cmd, "ls"); };\n`)).toBe(false);
  });
});
