/**
 * Taint without silent caps (checklist row 1, PR 281): a value, a list, an
 * index, a pushed value, a helper's arguments or a chain of assignments padded
 * past a length or round cap dropped the taint, and the sink passed with exit
 * 0. App mode (taintedNames) is now one linear pass with no caps. Library mode
 * (parameterTaint) reads brackets by their pairs and values to their end, runs
 * to a fixed point, and past the file's work budget or the hop bound says
 * `incomplete`, so the run exits 2.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { findSinks, taintedNames } from "../lib/whitebox/code-sinks.js";
import { parameterTaint } from "../lib/whitebox/library.js";

const CP = 'const cp = require("child_process");\n';
const list = (n) => Array.from({ length: n }, (_, i) => "a" + i).join(", ");
const chain = (n, last) => Array.from({ length: n }, (_, i) => `v${i} = v${i + 1};`).join("\n").replace(`v${n};`, `${last};`);
const app = (s) => findSinks(CP + s).filter((h) => h.pattern === "command-injection");
const lib = (s) => {
  const incomplete = [];
  const hits = findSinks(CP + s, { library: true, onIncomplete: (m) => incomplete.push(m) }).filter((h) => h.pattern === "command-injection");
  return { hits: hits.length, incomplete: incomplete.length > 0 };
};
const hasMain = (f) => spawnSync("git", ["cat-file", "-e", `origin/main:${f}`]).status === 0;
/** A module from origin/main, its relative imports pointed at this checkout. */
async function fromMain(file) {
  const d = mkdtempSync(join(tmpdir(), "penthera-main-"));
  const dir = resolve(file, "..");
  const src = spawnSync("git", ["show", `origin/main:${file}`], { encoding: "utf-8" }).stdout
    .replace(/from "(\.{1,2}\/[^"]+)"/g, (_, f) => `from ${JSON.stringify(resolve(dir, f))}`);
  writeFileSync(join(d, "m.mjs"), src);
  return import(join(d, "m.mjs"));
}

describe("app mode: request data is followed with no length or round cap", () => {
  const H = (v) => `\napp.post("/x", (req, res) => { cp.exec(${v}); });\n`;
  it("padded value, padded destructure, padded `= req` list, padded typed parameter, a 50-deep chain written bottom-up", () => {
    const cases = {
      value: `const c = "${"x".repeat(5000)}" + req.body.c;` + H("c"),
      destructure: `const { ${list(400)}, c } = req.body;` + H("c"),
      "= req list": `const { ${list(400)}, body } = req;` + H("body.c"),
      typed: `app.post("/x", ({ ${list(400)}, body }: Request, res) => { cp.exec(body.c); });\n`,
      "chain of 50": chain(50, "req.body.c") + H("v0"),
      "chained in one statement": `a = b = c = d = "${"x".repeat(400)}" + req.body.c;` + H("a"),
    };
    for (const [k, src] of Object.entries(cases)) expect(app(src).map((h) => h.confidence), k).toEqual(["likely"]);
    // Untainted stays untainted.
    expect(app(`const c = "ls";` + H("c"))).toEqual([]);
    expect(app(chain(50, '"ls"') + H("v0"))).toEqual([]);
  });

  // Several 4 MiB inputs in one test, each under its own limit below: the whole test gets
  // room for all of them (vitest's 20 s default bound it first on CI's slower Node 22 runner).
  it("at the 4 MiB cap: chains, statements and lists of every kind stay fast", () => {
    const lib = resolve("lib/whitebox/code-sinks.js");
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", `
      const { taintedNames } = await import(${JSON.stringify(lib)});
      const N = 4 * 1024 * 1024;
      const cases = {
        "a=a= in one statement": "a=".repeat(N / 2) + "req.body;",
        "decls": "a = b;\\n".repeat(N / 7),
        "brace lists": "const {a} = b;\\n".repeat(N / 15),
        "one long statement": "x = " + "y + ".repeat(N / 4) + "req.body;",
        "reverse chain": Array.from({ length: 300000 }, (_, i) => "v" + i + " = v" + (i + 1) + ";").join("\\n") + "\\nv300000 = req.body;",
        "open braces": "const {".repeat(N / 7),
      };
      const out = {};
      for (const [k, t] of Object.entries(cases)) { const s = performance.now(); const n = taintedNames(t).size; out[k] = { ms: performance.now() - s, n }; }
      console.log(JSON.stringify(out));`], { encoding: "utf-8", timeout: 120_000, maxBuffer: 1 << 24 });
    expect(r.status, r.stderr || "timed out").toBe(0);
    const out = JSON.parse(r.stdout);
    for (const [k, c] of Object.entries(out)) expect(c.ms, k).toBeLessThan(6000);
    expect(out["reverse chain"].n).toBe(300001);
  }, 120_000);

  it.skipIf(!hasMain("lib/whitebox/code-sinks.js"))("differential against main: every name main's taintedNames finds is found (3,000 seeded programs)", async () => {
    const main = await fromMain("lib/whitebox/code-sinks.js");
    let seed = 0x7a17;
    const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
    const parts = ["const ", "let ", "a", "b", "c", " = ", "=", "==", "=>", "req.body", "req.query.x", "request.params", "; ", "\n", "{", "}", ", ", ": ", "(", ")", "+ ", '"s"', "body", "Request", "...", "x."];
    let found = 0;
    for (let n = 0; n < 3000; n++) {
      let t = "";
      for (let k = 1 + rnd(14); k > 0; k--) t += parts[rnd(parts.length)];
      const was = main.taintedNames(t), now = taintedNames(t);
      for (const name of was) { found++; expect(now.has(name), `${JSON.stringify(t)}: ${name}`).toBe(true); }
    }
    expect(found).toBeGreaterThan(50);
  });
});

describe("library mode: no silent caps; past the budget the file is incomplete", () => {
  const P = "x".repeat(2500);
  it("padded value, destructure, for-of, iterate, index, push, helper arguments, and a 9-deep chain bottom-up are found", () => {
    const cases = {
      value: `exports.run = (cmd) => { const c = "${P}" + cmd; cp.exec(c); };`,
      destructure: `exports.run = (o) => { const { ${list(200)}, cmd } = o; cp.exec(cmd); };`,
      "for-of": `exports.run = (l) => { for (const { ${list(200)}, cmd } of l) cp.exec(cmd); };`,
      iterate: `exports.run = (l) => { each(${"l".padEnd(250, " ")}, (cmd) => cp.exec(cmd)); };`,
      index: `exports.run = (cmd) => { const t = {}; t[${'"k"+'.repeat(30)}"k"] = cmd; cp.exec(t); };`,
      push: `exports.run = (cmd) => { const a = []; a.push(${"0, ".repeat(800)}cmd); cp.exec(a.join(" ")); };`,
      "helper arguments": `function h(x) { cp.exec(x); }\nexports.run = (cmd) => h(${"0 + ".repeat(600)}cmd);`,
      "chain of 9": `exports.run = (cmd) => { ${chain(9, "cmd")} cp.exec(v0); };`,
    };
    for (const [k, src] of Object.entries(cases)) expect(lib(src), k).toEqual({ hits: 1, incomplete: false });
    expect(lib(`exports.run = (cmd) => { const c = "ls"; cp.exec(c); };`)).toEqual({ hits: 0, incomplete: false });
  });

  it("work past the file's budget (a long chain in one statement) and more than 200 helper hops: incomplete, never a silent pass", () => {
    const deep = lib(`exports.run = (cmd) => { ${"a=".repeat(20000)}cmd; cp.exec(a); };`);
    expect(deep.incomplete || deep.hits === 1).toBe(true);
    const helpers = Array.from({ length: 210 }, (_, i) => `function h${i}(x) { cp.exec(x); }`).join("\n");
    const calls = Array.from({ length: 210 }, (_, i) => `h${i}(cmd);`).join(" ");
    expect(lib(`${helpers}\nexports.run = (cmd) => { ${calls} };`).incomplete).toBe(true);
    // The parameterTaint result says so itself when its budget runs out.
    let left = 50;
    const t = parameterTaint("a = b; b = c; c = d; d = cmd;".repeat(5), ["cmd"], null, (n) => (left -= n) > 0);
    expect(t.incomplete).toBe(true);
  });

  // Several 4 MiB inputs in one test, each under its own limit below: the whole test gets
  // room for all of them (vitest's 20 s default bound it first on CI's slower Node 22 runner).
  it("at the 4 MiB cap: library mode stays within the run's time", () => {
    const sinks = resolve("lib/whitebox/code-sinks.js");
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", `
      const { findSinks } = await import(${JSON.stringify(sinks)});
      const CP = 'const cp = require("child_process");\\n';
      const N = 4 * 1024 * 1024;
      const cases = {
        "assignments": "exports.run = (cmd) => {\\n" + "a = b;\\n".repeat(N / 7) + "cp.exec(cmd); };",
        "one statement": "exports.run = (cmd) => { " + "a=".repeat(N / 2) + "cmd; cp.exec(a); };",
        "pushes": "exports.run = (cmd) => {\\n" + "a.push(b);\\n".repeat(N / 11) + "cp.exec(cmd); };",
        "for-of": "exports.run = (cmd) => {\\n" + "for (const {a} of b) c;\\n".repeat(N / 25) + "cp.exec(cmd); };",
        "blank lines": "exports.run = (cmd) => { const c = cmd" + "\\n".repeat(N - 200) + "; cp.exec(c); };",
      };
      const out = {};
      for (const [k, t] of Object.entries(cases)) { const s = performance.now(); findSinks(CP + t, { library: true, onIncomplete: () => {} }); out[k] = performance.now() - s; }
      console.log(JSON.stringify(out));`], { encoding: "utf-8", timeout: 180_000, maxBuffer: 1 << 24 });
    expect(r.status, r.stderr || "timed out").toBe(0);
    for (const [k, ms] of Object.entries(JSON.parse(r.stdout))) expect(ms, k).toBeLessThan(10_000);
  }, 120_000);

  it.skipIf(!hasMain("lib/whitebox/library.js"))("differential against main: every name main's parameterTaint finds is found (3,000 seeded bodies)", async () => {
    const main = await fromMain("lib/whitebox/library.js");
    let seed = 0x11b;
    const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
    const parts = ["const ", "a", "b", "p", " = ", "=", "+=", "; ", "\n", "{", "}", "[", "]", ", ", "(", ")", "for (", " of ", ".push(", "each(", "=> ", "x.", "...", "t[k]",
      "a = p;", "b = a;", "c = b + 1;", "const { d, e } = p;", "for (const f of p) ", "g.push(p);", "each(p, (h) => h);", "t[k] = p;"];
    let found = 0;
    for (let n = 0; n < 3000; n++) {
      let t = "";
      for (let k = 1 + rnd(14); k > 0; k--) t += parts[rnd(parts.length)];
      const was = main.parameterTaint(t, ["p"]), now = parameterTaint(t, ["p"]);
      for (const name of was) { if (name !== "p") found++; expect(now.has(name), `${JSON.stringify(t)}: ${name}`).toBe(true); }
    }
    expect(found).toBeGreaterThan(50); // names beyond the parameter itself
  });
});

// Function detection in library mode: a return type was read only 400 characters, parameters only 20,000,
// and an arrow with a return type was skipped, so the function's parameters were never followed.
describe("library mode: functions are found whatever the length of their types and parameters", () => {
  const T = "Promise<{ " + Array.from({ length: 60 }, (_, i) => `f${i}: string`).join("; ") + " }>";
  it("a long return type, a typed arrow, long parameters, a function type as the return type", () => {
    const cases = {
      "function, long return type": `export function run(cmd: string): ${T} { cp.exec(cmd); }`,
      "method, long return type": `export class K { run(cmd: string): ${T} { cp.exec(cmd); } }`,
      "typed arrow": "export const run = (cmd: string): void => { cp.exec(cmd); };",
      "typed arrow, long type": `export const run = (cmd: string): ${T} => { cp.exec(cmd); };`,
      "typed arrow, expression body": "export const run = (cmd: string): void => cp.exec(cmd);",
      "long parameters": `export function run(${Array.from({ length: 3000 }, (_, i) => `a${i}: string`).join(", ")}, cmd: string) { cp.exec(cmd); }`,
      "function type as return type": "export function run(cmd: string): () => void { cp.exec(cmd); return () => {}; }",
      "type literal then union": "export function run(cmd: string): { a: 1 } | null { cp.exec(cmd); return null; }",
    };
    for (const [k, src] of Object.entries(cases)) expect(lib(src), k).toEqual({ hits: 1, incomplete: false });
  });

  it("return types that cost more than the file's budget: the file is incomplete, never a silent pass", () => {
    const seg = "(a): " + "<".repeat(20000);
    const r = lib("export function q(c) { cp.exec(c); }\n" + seg.repeat(100));
    expect(r.incomplete).toBe(true);
  });

  // Several 4 MiB inputs in one test, each under its own limit below: the whole test gets
  // room for all of them (vitest's 20 s default bound it first on CI's slower Node 22 runner).
  it("at the 4 MiB cap: typed arrows, nested arrows, ternaries and `():` runs stay fast", () => {
    const sinks = resolve("lib/whitebox/code-sinks.js");
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", `
      const { findSinks } = await import(${JSON.stringify(sinks)});
      const CP = 'const cp = require("child_process");\\nexport function q(c) { cp.exec(c); }\\n';
      const N = 4 * 1024 * 1024;
      const cases = { "():": "():".repeat(N / 3), "nested arrows": "a => ".repeat(N / 5) + "1", "typed arrows": "(a): T => ".repeat(N / 10) + "1",
        "ternaries": "x = " + "f(a) ? g(b) : ".repeat(N / 14) + "1;", "long return type": "export function r(c): " + "A|".repeat(N / 2) + "B { cp.exec(c); }" };
      const out = {};
      for (const [k, t] of Object.entries(cases)) { const s = performance.now(); findSinks(CP + t, { library: true, onIncomplete: () => {} }); out[k] = performance.now() - s; }
      console.log(JSON.stringify(out));`], { encoding: "utf-8", timeout: 180_000, maxBuffer: 1 << 24 });
    expect(r.status, r.stderr || "timed out").toBe(0);
    for (const [k, ms] of Object.entries(JSON.parse(r.stdout))) expect(ms, k).toBeLessThan(10_000);
  }, 120_000);

  it.skipIf(!hasMain("lib/whitebox/library.js"))("differential against main: every function main's functionRanges finds is found (3,000 seeded texts)", async () => {
    const main = await fromMain("lib/whitebox/library.js");
    const { functionRanges } = await import("../lib/whitebox/library.js");
    let seed = 0xf00d;
    const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
    const parts = ["function ", "f", "(", ")", "a", ": ", "T", "<", ">", "{", "}", " => ", "=", ";", ",", "async ", "\n", " ", "x ", "?", "|", "run", "() => void"];
    let found = 0;
    for (let n = 0; n < 3000; n++) {
      let t = "";
      for (let k = 1 + rnd(16); k > 0; k--) t += parts[rnd(parts.length)];
      const now = new Set(functionRanges(t).map((f) => `${f.bodyStart}:${f.bodyEnd}`));
      for (const f of main.functionRanges(t)) { found++; expect(now.has(`${f.bodyStart}:${f.bodyEnd}`), `${JSON.stringify(t)} ${f.bodyStart}`).toBe(true); }
    }
    expect(found).toBeGreaterThan(100);
  });
});
