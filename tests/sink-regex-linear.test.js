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

  // Several 4 MiB inputs in one test, each under its own limit below: the whole test gets
  // room for all of them (vitest's 20 s default bound it first on CI's slower Node 22 runner).
  it("at the 4 MiB read cap: each crafted input takes under 5 s", () => {
    const out = run(`${CASES}
      const out = [];
      for (const [k, f] of Object.entries(CASES)) out.push({ k, ...time(f(4 * 1024 * 1024 - 256) + SINK) });
      console.log(JSON.stringify(out));`, 180_000);
    for (const c of out) {
      expect(c.hits, c.k).toBe(1);
      expect(c.ms, c.k).toBeLessThan(5000);
    }
  }, 120_000);

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
        // A sticky pattern is tried at one place only: analysed as anchored there.
        const source = re.flags.includes("y") ? "^(?:" + re.source + ")" : re.source;
        const ast = parser.parseLiteral("/" + source + "/" + re.flags.replace(/[yd]/g, ""));
        for (const rep of analyse(ast, { maxReports: 1 }).reports) bad.push(rep.type + ": " + re.source.slice(0, 120));
      }
      console.log(JSON.stringify({ n: built.size, bad }));`], { encoding: "utf-8", timeout: 60_000 });
    expect(r.status, r.stderr).toBe(0);
    const { n, bad } = JSON.parse(r.stdout);
    expect(n).toBeGreaterThan(25);
    expect(bad).toEqual([]);
  });
});

// Vercel U: the import-length cap dropped a padded shell binding. Brace lists are read whole now.
describe("brace lists are read whole: a padded binding is still bound (Vercel U, checklist row 1)", () => {
  const pad = (n, f) => Array.from({ length: n }, (_, i) => f(i)).join(", ");
  const H = '\napp.post("/x", (req, res) => { runTask(req.body.c); });\n';
  const forms = (n) => ({
    named: `import { ${pad(n, (i) => `spawn as s${i}`)}, exec as runTask } from "child_process";` + H,
    combined: `import cp, { ${pad(n, (i) => `spawn as s${i}`)}, exec as runTask } from "child_process";` + H,
    "destructured require": `const { ${pad(n, (i) => `spawn: s${i}`)}, exec: runTask } = require("child_process");` + H,
    "destructured object": `const cp = require("child_process");\nconst { ${pad(n, (i) => `spawn: s${i}`)}, exec: runTask } = cp;` + H,
    "object of tools": `const cp = require("child_process");\nconst tools = { ${pad(n, (i) => `k${i}: 1`)}, runTask: cp.exec };\napp.post("/x", (req, res) => { tools.runTask(req.body.c); });\n`,
    "option object": `const cp = require("child_process");\nconst o = { ${pad(n, (i) => `k${i}: 1`)}, shell: true };\napp.post("/x", (req, res) => { cp.spawn(req.body.c, [], o); });\n`,
  });

  it("padded past the old caps (2,000 and 400 characters), each form still finds the sink", async () => {
    const { findSinks } = await import(LIB);
    for (const n of [0, 400, 20000]) for (const [k, src] of Object.entries(forms(n))) expect(findSinks(src).length, `${k}, ${n} padding entries`).toBe(1);
  });

  // Several 4 MiB inputs in one test, each under its own limit below: the whole test gets
  // room for all of them (vitest's 20 s default bound it first on CI's slower Node 22 runner).
  it("at the 4 MiB cap: one huge list, and a file of many small lists and lone braces, take under 5 s", () => {
    const out = run(`
      const pad = (n, f) => Array.from({ length: n }, (_, i) => f(i)).join(", ");
      const big = 'import { ' + pad(230000, (i) => "spawn as s" + i) + ', exec as runTask } from "child_process";\\napp.post("/x", (req, res) => { runTask(req.body.c); });\\n';
      const many = "const { a } = b;\\n".repeat(240000) + SINK;
      const open = "{".repeat(4 * 1024 * 1024 - 256) + SINK;
      const close = "} =      ".repeat(400000) + SINK;
      console.log(JSON.stringify({ big: time(big), many: time(many), open: time(open), close: time(close), kib: big.length >> 10 }));`, 180_000);
    expect(out.kib).toBeGreaterThan(3000);
    for (const k of ["big", "many", "close"]) { expect(out[k].hits, k).toBe(1); expect(out[k].ms, k).toBeLessThan(5000); }
    expect(out.open.ms).toBeLessThan(5000);
  }, 120_000);

  it.skipIf(spawnSync("git", ["cat-file", "-e", "origin/main:lib/whitebox/code-sinks.js"]).status !== 0)(
    "differential against main: every sink main finds in a corpus of binding forms is found now", async () => {
      const { mkdtempSync, writeFileSync } = await import("node:fs");
      const { tmpdir } = await import("node:os");
      const { join } = await import("node:path");
      const d = mkdtempSync(join(tmpdir(), "penthera-sinks-main-"));
      const src = spawnSync("git", ["show", "origin/main:lib/whitebox/code-sinks.js"], { encoding: "utf-8" }).stdout
        .replace(/from "(\.{1,2}\/[^"]+)"/g, (_, f) => `from ${JSON.stringify(resolve("lib/whitebox", f))}`);
      writeFileSync(join(d, "main-sinks.mjs"), src);
      const main = await import(join(d, "main-sinks.mjs"));
      const { findSinks } = await import(LIB);
      const T = 'app.post("/x", (req, res) => { CALL(req.body.c); });';
      const corpus = [
        ['import { exec } from "child_process";', "exec"], ['import { exec as run } from "node:child_process";', "run"],
        ['import cp, { execSync as run } from "child_process";', "run"], ['import cp from "child_process";', "cp.exec"],
        ['import * as cp from "child_process";', "cp.exec"], ['const { exec: run } = require("child_process");', "run"],
        ['const cp = require("child_process"); const { exec: run } = cp;', "run"], ['const cp = require("child_process");', "cp.execSync"],
        ['const cp = require("child_process"); const t = { run: cp.exec };', "t.run"], ['const t = { run: require("child_process").exec };', "t.run"],
        ['const run = require("util").promisify(require("child_process").exec);', "run"], ['const cp = __importStar(require("child_process"));', "cp.exec"],
        ['const sh = require("shelljs");', "sh.exec"], ['import { exec } from "shelljs";', "exec"],
        ['const { exec } = require("child_process");', "exec"], ['const cp = require("child_process"); const run = cp.exec;', "run"],
      ];
      let mainHits = 0;
      for (const [bind, call] of corpus) {
        const text = bind + "\n" + T.replace("CALL", call) + "\n";
        const was = main.findSinks(text).length;
        mainHits += was;
        expect(findSinks(text).length, text).toBeGreaterThanOrEqual(was);
      }
      expect(mainHits).toBeGreaterThan(10);
    });
});
