/**
 * Library mode (ADR 0001, decision 3) and the sink shapes and lexer fix that
 * came with it (E11b D1 and D2). Every fixture here is written for this test;
 * none is taken from a benchmark. Fixture repos go to a temp dir at runtime
 * and nothing in them is executed.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { lexJs, maskStrings, stripComments } from "../lib/whitebox/js-lex.js";
import { findSinks, scanCodeSinks } from "../lib/whitebox/code-sinks.js";
import { detectLibrary, exportedFunctions, namedFunctions, paramNames, parameterTaint } from "../lib/whitebox/library.js";
import { scanRepo } from "../src/scan-repo.js";

// Split so Penthera's own scans do not read the fixtures as real sinks.
const EVAL = ["ev", "al"].join("");
const EXEC = ["ex", "ec"].join("");
const CP = ["child", "_process"].join("");
const FN = ["Func", "tion"].join("");

const lib = (src) => findSinks(src, { library: true }).filter((h) => h.pattern === "command-injection");
const app = (src) => findSinks(src).filter((h) => h.pattern === "command-injection");

describe("lexer", () => {
  it("keeps a regex literal with a quote from swallowing the code after it", () => {
    const src = `const re = /[\\s\\w:'",]*/g;\nconst x = ${EVAL}(input);\n`;
    const { code, plain, expr } = lexJs(src);
    for (const s of [code, plain, expr]) expect(s).toHaveLength(src.length);
    expect(code).toContain(`${EVAL}(input)`);
    expect(findSinks(src)).toMatchObject([{ pattern: "eval", line: 2 }]);
  });

  it("tells division from a regex literal", () => {
    const src = "const a = b / c / d;\nconst e = (f) / 2;\nif (/x'y/.test(s)) run(t)\nreturn /'/.source + q\n";
    const code = maskStrings(src);
    expect(code.split("\n")[0]).toBe("const a = b / c / d;");
    expect(code.split("\n")[2]).toBe("if (/   /.test(s)) run(t)");
    expect(code.split("\n")[3]).toBe("return / /.source + q");
  });

  it("masks strings and templates in code, keeps `${...}` in expr, blanks comments everywhere", () => {
    const src = "const s = `a ${b + \"}\"} c` + 'd' // note\n";
    const { code, plain, expr } = lexJs(src);
    expect(code).toBe("const s = `" + " ".repeat(14) + "` + ' '        \n");
    expect(expr).toBe("const s = `    b + \" \"   ` + ' '        \n");
    expect(plain).toBe("const s = `a ${b + \"}\"} c` + 'd'        \n");
    expect(stripComments(src)).toBe(plain);
  });
});

describe("sink shapes (both modes)", () => {
  it("finds exec under any binding of the module", () => {
    const cases = [
      `const ${CP}_1 = require("${CP}");\n${CP}_1.${EXEC}("ls " + req.query.dir)`,
      `const proc = require('node:${CP}')\nproc.${EXEC}Sync(\`ls \${req.body.dir}\`)`,
      `const { ${EXEC}: run } = require('${CP}')\nrun('ls ' + req.params.d)`,
      `import { ${EXEC} as sh } from '${CP}'\nsh('ls ' + req.query.d)`,
      `import * as k from '${CP}'\nk.${EXEC}('ls ' + req.query.d)`,
      `const util = require('util'); const c = require('${CP}')\nconst run = util.promisify(c.${EXEC})\nrun('ls ' + req.query.d)`,
      `var _cp = _interopRequireDefault(require("${CP}"));\n(0, _cp.${EXEC})("ls " + req.query.d)`,
      `const s = require('shelljs')\ns.${EXEC}('ls ' + req.query.d)`,
      `const { spawn } = require('${CP}')\nspawn('ls ' + req.query.d, [], { shell: true })`,
      `const { spawn } = require('${CP}')\nconst OPTS = { shell: true }\nspawn('ls ' + req.query.d, [], OPTS)`,
      `const { ${EXEC}File } = require('${CP}')\n${EXEC}File('/bin/sh', ['-c', 'ls ' + req.query.d])`,
      `const execa = require('execa')\nexeca('ls ' + req.query.d, { shell: true })`,
    ];
    for (const src of cases) expect(app(src), src).toMatchObject([{ confidence: "likely", tainted: true }]);
  });

  it("leaves spawn and execFile without a shell alone", () => {
    expect(app(`const { spawn } = require('${CP}')\nspawn('ls', [req.query.d])`)).toEqual([]);
    expect(app(`const { spawn } = require('${CP}')\nspawn('ls', [req.query.d], { shell: false })`)).toEqual([]);
    expect(app(`const { ${EXEC}File } = require('${CP}')\n${EXEC}File('git', ['log', req.query.ref])`)).toEqual([]);
  });

  it("finds indirect eval and a dynamic body in new Function", () => {
    expect(findSinks(`const run = (src) => (0, ${EVAL})(src)\n`)).toMatchObject([{ pattern: "eval", call: "eval" }]);
    expect(findSinks(`globalThis.${EVAL}(code)\n`)).toMatchObject([{ pattern: "eval" }]);
    expect(findSinks(`const f = new ${FN}("a", "b", body)\n`)).toMatchObject([{ pattern: "eval", call: "new Function", confidence: "potential" }]);
    expect(findSinks(`const g = new ${FN}("return this")()\nconst h = new ${FN}("a", "return a + 1")\n`)).toEqual([]);
  });
});

describe("long lines", () => {
  const ordinary = Array.from({ length: 300 }, (_, i) => `const v${i} = load(${i});`).join("\n");
  it("reads a file with one long generated line among ordinary code", () => {
    const src = `const table = [${"1,".repeat(3000)}1];\n${ordinary}\nconst out = ${EVAL}("[" + text + "]");\n`;
    expect(findSinks(src)).toMatchObject([{ pattern: "eval", line: 302 }]);
  });
  it("still skips a file that is mostly long lines (minified)", () => {
    const src = `${"var a=b(c);".repeat(2000)}${EVAL}(x);\n${"var d=e(f);".repeat(2000)}\n`;
    expect(findSinks(src)).toEqual([]);
  });
});

describe("library mode: exported parameters as sources", () => {
  const shapes = {
    "module.exports = function": `const { ${EXEC} } = require('${CP}')\nmodule.exports = function (name, cb) { ${EXEC}('pkill ' + name, cb) }\n`,
    "exports.x = named function": `const c = require('${CP}')\nfunction size(dir) { return c.${EXEC}Sync('du -s ' + dir) }\nexports.size = size\n`,
    "object of methods": `const c = require('${CP}')\nmodule.exports = { open(file) { c.${EXEC}('xdg-open "' + file + '"') }, other: 1 }\n`,
    "options-object property": `const c = require('${CP}')\nmodule.exports = (opts) => c.${EXEC}(opts.bin + ' --version')\n`,
    "prototype alias": `const c = require('${CP}')\nfunction Tool() {}\nconst P = Tool.prototype\nP.run = function (target) { c.${EXEC}('tool ' + target) }\nmodule.exports = Tool\n`,
    "class method and constructor": `import { ${EXEC} } from '${CP}'\nexport class Box { constructor(dir) { ${EXEC}('mkdir ' + dir) } }\n`,
    "IIFE return": `const c = require('${CP}')\nconst api = (() => { function up(dir) { c.${EXEC}('cp -r ' + dir + ' /tmp') } return { up } })()\nmodule.exports = api\n`,
    "conditional arrow property": `const c = require('${CP}')\nmodule.exports = { kill: win ? (pid) => c.${EXEC}('taskkill ' + pid) : (pid) => c.${EXEC}('kill ' + pid) }\n`,
    "factory return": `const c = require('${CP}')\nmodule.exports = function make() { return { go(ref) { c.${EXEC}('git checkout ' + ref) } } }\n`,
    "ESM export const": `import { ${EXEC}Sync } from 'node:${CP}'\nexport const df = (path) => ${EXEC}Sync(\`df -k \${path}\`)\n`,
    "callback inside": `const c = require('${CP}')\nmodule.exports = function (files) { files.forEach((f) => c.${EXEC}('rm ' + f)) }\n`,
    "iteration helper": `const c = require('${CP}')\nexports.all = function (files, done) { each(files, function (file, next) { const cmd = 'gzip ' +\n  file.path\n  c.${EXEC}(cmd, next) }, done) }\n`,
    "members copied onto exports in a loop": `const c = require('${CP}')\nvar api = { add: function (pkg) { c.${EXEC}Sync('npm i ' + pkg) } }\nfor (var k in api) {\n  exports[k] = api[k]\n}\n`,
    "Object.assign of a named object": `const c = require('${CP}')\nconst api = { rm(dir) { c.${EXEC}('rm -r ' + dir) } }\nObject.assign(module.exports, api)\n`,
    "pushed into an argument list": `const c = require('${CP}')\nmodule.exports = function (msg) { const args = ['say']; args.push(JSON.stringify(msg)); c.${EXEC}(args.join(' ')) }\n`,
  };
  for (const [name, src] of Object.entries(shapes)) {
    it(`reports ${name}`, () => {
      const hits = lib(src);
      expect(hits.length, src).toBeGreaterThan(0);
      expect(hits[0]).toMatchObject({ confidence: "potential", tainted: false, library: { kind: "parameter" } });
      expect(app(src)).toEqual([]);
    });
  }

  it("marks a function that only runs its argument", () => {
    const hits = lib(`const c = require('${CP}')\nexports.run = function (command, cb) { return c.${EXEC}(command, cb) }\n`);
    expect(hits).toMatchObject([{ library: { kind: "runs-argument", function: "exports.run" } }]);
  });

  it("stays quiet where no exported parameter reaches the command", () => {
    const quiet = {
      "helper not exported": `const c = require('${CP}')\nfunction helper(x) { c.${EXEC}('rm ' + x) }\nmodule.exports = function () { helper('a') }\n`,
      "parameter only in the options": `const c = require('${CP}')\nmodule.exports = function (cwd) { return c.${EXEC}Sync('git status', { cwd }) }\n`,
      "constant command": `const c = require('${CP}')\nmodule.exports = function (cb) { c.${EXEC}('uname -a', cb) }\n`,
      "IIFE parameters are not a caller's": `const c = require('${CP}')\nmodule.exports = (function (root) { return { info() { c.${EXEC}('ls ' + root) } } })(__dirname)\n`,
      "spawn with an argument array": `const { spawn } = require('${CP}')\nmodule.exports = (file) => spawn('convert', [file, 'out.png'])\n`,
      "a field set from a constant": `const c = require('${CP}')\nclass T { constructor(p) { this.p = p; this.bin = 'tool' } info() { c.${EXEC}(this.bin + ' --version') } }\nmodule.exports = T\n`,
      "parameter name inside a string": `const c = require('${CP}')\nmodule.exports = function (name) { c.${EXEC}('echo name') }\n`,
    };
    for (const [name, src] of Object.entries(quiet)) expect(lib(src), name).toEqual([]);
  });

  it("reads parameter lists with defaults, types and destructuring", () => {
    expect(paramNames("a, b = () => {}, { c, d: e, f = 1 }, [g, ...h], ...rest")).toEqual(["a", "b", "c", "e", "f", "g", "h", "rest"]);
    expect(paramNames("cmd: string, opts?: Map<string, number>, private readonly cb: () => void")).toEqual(["cmd", "opts", "cb"]);
  });

  it("follows a parameter through assignments that span lines", () => {
    const body = lexJs("{ var x = 'a' +\n  opts.y +\n  'b'\n var z = x }").expr;
    expect([...parameterTaint(body, ["opts"])].sort()).toEqual(["opts", "x", "z"]);
  });

  it("lists what a file exports", () => {
    const { code } = lexJs("function a(x) {}\nfunction b(y) {}\nconst c = (z) => z\nmodule.exports = { a, c }\n");
    expect(exportedFunctions(code).map((f) => f.name).sort()).toEqual(["a", "c"]);
  });
});

describe("library mode: one helper call", () => {
  const found = {
    "function declaration": `const { ${EXEC}Sync } = require('${CP}')\nfunction probe(tool) { return ${EXEC}Sync('which ' + tool) }\nmodule.exports = function has(name) { return probe(name) }\n`,
    "arrow bound to a const": `const { ${EXEC} } = require('${CP}')\nconst list = (url) => new Promise((ok) => ${EXEC}(\`tool ls \${url}\`, ok))\nconst get = (url) => list(url).then(String)\nmodule.exports = { get }\n`,
    "function expression in a var list": `var c = require('${CP}'), n = 1, run = function (opts, cb) { c.${EXEC}('tool ' + opts.flag, cb) }\nmodule.exports = { go: function (o, cb) { run({ flag: o.flag }, cb) } }\n`,
    "second argument": `const c = require('${CP}')\nfunction tag(dir, name) { c.${EXEC}Sync('git tag ' + name, { cwd: dir }) }\nexports.tag = (name) => tag(process.cwd(), name)\n`,
    "spread into a rest parameter": `const c = require('${CP}')\nfunction sh(...parts) { return c.${EXEC}Sync(parts.join(' ')) }\nexports.git = (...args) => sh('git', ...args)\n`,
    "a value derived from the parameter": `const c = require('${CP}')\nfunction kill(pid) { c.${EXEC}('kill -9 ' + pid) }\nexports.stop = function (port) { const pid = lookup(port); kill(pid) }\n`,
  };
  for (const [name, src] of Object.entries(found)) {
    it(`follows ${name}`, () => {
      const hits = lib(src);
      expect(hits.length, src).toBe(1);
      expect(hits[0]).toMatchObject({ confidence: "potential", tainted: false, library: { kind: "parameter" } });
      expect(hits[0].library.via).toBeTruthy();
      expect(app(src)).toEqual([]);
    });
  }

  it("marks a helper that runs the exported parameter unchanged", () => {
    const hits = lib(`const c = require('${CP}')\nfunction sh(cmd) { return c.${EXEC}Sync(cmd) }\nexports.run = function (command) { return sh(command) }\n`);
    expect(hits).toMatchObject([{ library: { kind: "runs-argument", function: "exports.run", via: "sh" } }]);
  });

  it("stops after one hop and at untainted arguments", () => {
    const quiet = {
      "two hops": `const c = require('${CP}')\nfunction inner(x) { c.${EXEC}('tool ' + x) }\nfunction mid(y) { inner(y) }\nmodule.exports = function (z) { mid(z) }\n`,
      "tainted value at another position": `const c = require('${CP}')\nfunction run(cmd, cb) { c.${EXEC}('tool ' + cmd, cb) }\nmodule.exports = function (done) { run('--version', done) }\n`,
      "a name bound twice": `const c = require('${CP}')\nfunction run(x) { c.${EXEC}('tool ' + x) }\nfunction run(x) { return x }\nmodule.exports = (v) => run(v)\n`,
      "a method of another object": `const c = require('${CP}')\nconst h = { run(x) { c.${EXEC}('tool ' + x) } }\nmodule.exports = (v) => other.run(v)\n`,
      "a helper called from a function that is not exported": `const c = require('${CP}')\nfunction run(x) { c.${EXEC}('tool ' + x) }\nfunction local(v) { run(v) }\nmodule.exports = () => local('a')\n`,
    };
    for (const [name, src] of Object.entries(quiet)) expect(lib(src), name).toEqual([]);
  });

  it("names the helper in the finding", () => {
    const [f] = findSinks(`const c = require('${CP}')\nfunction probe(t) { c.${EXEC}Sync('which ' + t) }\nexports.has = (n) => probe(n)\n`, { library: true });
    expect(f.library).toEqual({ function: "exports.has", kind: "parameter", via: "probe" });
  });

  it("lists the functions a file calls by name", () => {
    const { code } = lexJs("function a(x) {}\nconst b = (y) => y\nvar n = 1, c = function (z) {}\nconst o = { d(w) {} }\nlet e = async (v) => v\n");
    expect([...namedFunctions(code).keys()].sort()).toEqual(["a", "b", "c", "e"]);
  });
});

describe("library mode: values kept on this", () => {
  const found = {
    "class field set in the constructor": `const c = require('${CP}')\nclass Disk { constructor(dev) { this.dev = dev } usage() { return c.${EXEC}Sync('df ' + this.dev) } }\nmodule.exports = Disk\n`,
    "prototype method and constructor function": `var c = require('${CP}')\nfunction Img(file, opts) { this.file = file; this.opts = opts || {} }\nImg.prototype.info = function () { c.${EXEC}('identify "' + this.file + '"') }\nmodule.exports = Img\n`,
    "prototype object and a method that builds the command": `var c = require('${CP}')\nfunction Doc(path) { this.path = path }\nDoc.prototype = {\n  command: function () { return 'pdfinfo "' + this.path + '"' },\n  pages: function (cb) { var cmd = this.command(); c.${EXEC}(cmd, cb) },\n}\nmodule.exports = Doc\n`,
    "a setter and self = this": `const c = require('${CP}')\nclass Job { setTarget(t) { this.target = t } run() { const self = this; setTimeout(function () { c.${EXEC}('ping ' + self.target) }) } }\nexport default Job\n`,
    "an options field": `const c = require('${CP}')\nexport class Tool { constructor(options) { this.options = options } version() { return c.${EXEC}Sync(\`\${this.options.bin} --version\`) } }\n`,
    "an instance returned by an exported factory": `var c = require('${CP}')\nvar Stat = function (dir) { this.dir = dir }\nStat.prototype.size = function () { return c.${EXEC}Sync('du -s ' + this.dir) }\nmodule.exports = function (dir) { return new Stat(dir) }\n`,
  };
  for (const [name, src] of Object.entries(found)) {
    it(`follows ${name}`, () => {
      const hits = lib(src);
      expect(hits.length, src).toBe(1);
      expect(hits[0]).toMatchObject({ confidence: "potential", tainted: false, library: { kind: "parameter" } });
      expect(app(src)).toEqual([]);
    });
  }

  it("keeps fields to their own class", () => {
    const quiet = {
      "another class": `const c = require('${CP}')\nclass A { constructor(p) { this.p = p } }\nclass B { constructor() { this.p = 'x' } run() { c.${EXEC}('tool ' + this.p) } }\nmodule.exports = { A, B }\n`,
      "a class that is not exported": `const c = require('${CP}')\nclass T { constructor(p) { this.p = p } run() { c.${EXEC}('tool ' + this.p) } }\nmodule.exports = () => 1\n`,
      "a field set from another field": `const c = require('${CP}')\nclass T { constructor(p) { this.p = p; this.q = 'x' } a() { this.r = this.q } b() { c.${EXEC}('tool ' + this.r) } }\nmodule.exports = T\n`,
    };
    for (const [name, src] of Object.entries(quiet)) expect(lib(src), name).toEqual([]);
  });

  it("finds the class of each exported function", () => {
    const { code } = lexJs("function K(a) { this.a = a }\nK.prototype.m = function () {}\nconst P = K.prototype\nP.n = function () {}\nclass C { x() {} }\nmodule.exports = { K, C }\n");
    expect(Object.fromEntries(exportedFunctions(code).map((f) => [f.name, f.cls]))).toEqual({ K: "K", "K.prototype.m": "K", "P.n": "K", x: "C" });
  });
});

describe("library mode: when it turns on and what it reads", () => {
  let root;
  const repo = (name, files) => {
    const dir = join(root, name);
    for (const [path, body] of Object.entries(files)) {
      mkdirSync(join(dir, dirname(path)), { recursive: true });
      writeFileSync(join(dir, path), typeof body === "string" ? body : JSON.stringify(body));
    }
    return dir;
  };
  const SINK = `const c = require('${CP}')\nmodule.exports = (dir) => c.${EXEC}('ls ' + dir)\n`;
  beforeAll(() => { root = mkdtempSync(join(tmpdir(), "penthera-library-")); });
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it("decides from package.json", () => {
    expect(detectLibrary(repo("pub", { "package.json": { name: "p", main: "lib/index.js" } }))).toMatchObject({ enabled: true });
    expect(detectLibrary(repo("default-main", { "package.json": { name: "p" }, "index.js": "" }))).toMatchObject({ enabled: true });
    expect(detectLibrary(repo("private", { "package.json": { name: "p", main: "x.js", private: true } }))).toMatchObject({ enabled: false, reason: "package.json is private" });
    expect(detectLibrary(repo("app", { "package.json": { name: "p", main: "server.js", dependencies: { express: "^5" } } }))).toMatchObject({ enabled: false, reason: "depends on the app framework express" });
    expect(detectLibrary(repo("no-entry", { "package.json": { name: "p" } }))).toMatchObject({ enabled: false });
    expect(detectLibrary(repo("none", { "a.js": "" }))).toMatchObject({ enabled: false, reason: "no package.json" });
    expect(detectLibrary(join(root, "app"), true)).toMatchObject({ enabled: true, reason: "--library" });
    expect(detectLibrary(join(root, "pub"), false)).toMatchObject({ enabled: false, reason: "--no-library" });
    expect(detectLibrary(repo("dist", { "package.json": { name: "p", exports: { ".": { require: "./dist/index.cjs" } } } })).readDirs).toEqual(["dist"]);
  });

  it("reads dist/ only when package.json points there, and skips tooling folders", () => {
    const pointed = repo("pointed", { "package.json": { name: "p", main: "dist/index.js" }, "dist/index.js": SINK, "tools/release.js": SINK, "examples/demo.js": SINK });
    const files = scanCodeSinks(pointed, { library: detectLibrary(pointed) }).map((f) => f.file);
    expect(files).toEqual(["dist/index.js"]);
    const notPointed = repo("not-pointed", { "package.json": { name: "p", main: "index.js" }, "index.js": "", "dist/index.js": SINK });
    expect(scanCodeSinks(notPointed, { library: detectLibrary(notPointed) })).toEqual([]);
  });

  it("is reported in the repo scan, with potential confidence and a lower severity", async () => {
    const dir = repo("scan", { "package.json": { name: "p", main: "index.js" }, "index.js": SINK, "run.js": `const c = require('${CP}')\nexports.run = (cmd) => c.${EXEC}(cmd)\n` });
    const r = await scanRepo(dir, {});
    expect(r.library).toMatchObject({ enabled: true });
    expect(r.executedProbes).toContain("library-mode");
    const byFile = Object.fromEntries(r.findings.filter((f) => f.category === "code-pattern").map((f) => [f.file, f]));
    expect(byFile["index.js"]).toMatchObject({ pattern: "command-injection", confidence: "potential", severity: "high", library: "parameter" });
    expect(byFile["run.js"]).toMatchObject({ severity: "medium", library: "runs-argument" });
    expect(byFile["run.js"].description).toMatch(/callers must not pass untrusted input/);
    const off = await scanRepo(dir, { library: false });
    expect(off.findings.filter((f) => f.category === "code-pattern")).toEqual([]);
  });
});
