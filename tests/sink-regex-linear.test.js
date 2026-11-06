/**
 * The code-sink scan stays linear on long strings, long names, long lines and
 * long blank space, now that minified files are scanned and the read cap is
 * 4 MiB (Reviewer fourth pass and Red Team v2, 2.3.2). Each check runs in a
 * child with a time limit, so a regression fails instead of hanging the suite.
 *
 * Why the lint did not catch it: regexp/no-super-linear-* reads regex literals
 * and `new RegExp("…")` with a constant string. The sink patterns are built at
 * run time (`req(mod)`, `rx(String.raw`…${…}`)`), which the rule cannot see.
 * The last test runs the rule's own analyser (scslre) over every pattern the
 * scan builds.
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const LIB = resolve("lib/whitebox/code-sinks.js");
const run = (body, timeout = 120_000) => {
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", `
    const { findSinks } = await import(${JSON.stringify(LIB)});
    const SINK = '\\nconst cp = require("child_process");\\napp.post("/x", (req, res) => { cp.exec(req.body.c); });\\n';
    const time = (src) => { const s = performance.now(); const hits = findSinks(src).length; return { ms: performance.now() - s, hits }; };
    ${body}`], { encoding: "utf-8", timeout, maxBuffer: 1 << 24 });
  expect(r.status, r.stderr || "timed out").toBe(0);
  return JSON.parse(r.stdout);
};

// Inputs of about n characters that each drove a sink regex quadratic.
const CASES = String.raw`
  const CASES = {
    "long string literal": (n) => 'var s="' + "x".repeat(n) + '";',
    "long name": (n) => "x".repeat(n),
    "a. run": (n) => "a.".repeat(n / 2),
    "req.body.a run": (n) => "req.body.a ".repeat(n / 11),
    "import a, { without }": (n) => "import a, {".repeat(n / 11),
    "blank space after require()": (n) => 'x = require("child_process")' + " ".repeat(n) + "y",
    "import a and blank space": (n) => "import a" + " ".repeat(n) + "y",
    "x = and blank space": (n) => "x =" + " ".repeat(n) + "y",
    "wrapped require and blank space": (n) => "x(" + " ".repeat(n / 3) + 'require("child_process")' + " ".repeat(n / 3) + ")" + " ".repeat(n / 3) + "y",
    "x( run": (n) => "x(".repeat(n / 2),
  };`;

describe("code-sink regexes are linear (2.3.2)", () => {
  it("256 KiB and 1 MiB of each crafted input: fast, and about 4x from n to 4n, not 16x", () => {
    const out = run(`${CASES}
      const out = [];
      for (const [k, f] of Object.entries(CASES)) {
        const small = time(f(256 * 1024) + SINK), big = time(f(1024 * 1024) + SINK);
        out.push({ k, small: small.ms, big: big.ms, hits: big.hits });
      }
      console.log(JSON.stringify(out));`);
    for (const c of out) {
      expect(c.hits, c.k).toBe(1);
      expect(c.small, c.k).toBeLessThan(1500);
      expect(c.big, c.k).toBeLessThan(Math.max(10 * c.small, 400));
    }
  });

  it("at the 4 MiB read cap: each crafted input takes under 5 s", () => {
    const out = run(`${CASES}
      const out = [];
      for (const [k, f] of Object.entries(CASES)) out.push({ k, ...time(f(4 * 1024 * 1024 - 256) + SINK) });
      console.log(JSON.stringify(out));`, 180_000);
    for (const c of out) {
      expect(c.hits, c.k).toBe(1);
      expect(c.ms, c.k).toBeLessThan(5000);
    }
  });

  it("minified: one 4 MiB line, a long string and the exec on the same line, is scanned and the sink found", () => {
    const out = run(`
      const line = 'var s="' + "x".repeat(4 * 1024 * 1024 - 300) + '"; const cp = require("child_process"); app.post("/x", (req, res) => { cp.exec(req.body.c); });';
      const at256 = 'var s="' + "x".repeat(256 * 1024) + '"; const { exec } = await import("child_process"); const cp = require("child_process"); app.post("/x", (req, res) => { cp.exec(req.body.c); });';
      console.log(JSON.stringify([time(line), time(at256)]));`, 180_000);
    for (const c of out) {
      expect(c.hits).toBe(1);
      expect(c.ms).toBeLessThan(5000);
    }
  });

  it("the lint rule's analyser (scslre) finds no super-linear pattern among those the scan builds at run time", () => {
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", `
      import { createRequire } from "node:module";
      const fromPlugin = createRequire(createRequire(${JSON.stringify(resolve("package.json"))}).resolve("eslint-plugin-regexp"));
      const { analyse } = fromPlugin("scslre");
      const { RegExpParser } = fromPlugin("@eslint-community/regexpp");
      const built = new Map();
      const Native = globalThis.RegExp;
      globalThis.RegExp = new Proxy(Native, { construct(t, a) { const re = new t(...a); built.set(re.source + "/" + re.flags, re); return re; } });
      const { findSinks } = await import(${JSON.stringify(LIB)});
      // Every binding form, so every pattern (bindings rounds, shelljs, execa, cross-spawn) is built.
      findSinks('import a, { b } from "child_process"; import * as sh from "shelljs"; import ex from "execa"; import xs from "cross-spawn";'
        + ' const cp = require("child_process"); const { exec: run } = cp; const q = cp.exec; const t = { r: cp.exec };'
        + ' const p = promisify(require("child_process").exec); const s2 = require("shelljs"); const e2 = s2.exec;'
        + ' app.post("/x", (req, res) => { cp.exec(req.body.c); run(req.body.c); sh.exec(req.body.c); ex(req.body.c, { shell: true }); });');
      const parser = new RegExpParser();
      const bad = [];
      for (const re of built.values()) {
        const ast = parser.parseLiteral("/" + re.source + "/" + re.flags.replace(/[yd]/g, ""));
        for (const rep of analyse(ast, { maxReports: 1 }).reports) bad.push(rep.type + ": " + re.source.slice(0, 120));
      }
      console.log(JSON.stringify({ n: built.size, bad }));`], { encoding: "utf-8", timeout: 60_000 });
    expect(r.status, r.stderr).toBe(0);
    const { n, bad } = JSON.parse(r.stdout);
    expect(n).toBeGreaterThan(25);
    expect(bad).toEqual([]);
  });
});
