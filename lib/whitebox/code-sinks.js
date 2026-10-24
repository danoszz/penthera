/**
 * Code-execution sinks in server code, with a taint-lite check for request
 * data reaching them.
 *
 * The route-scoped risky-pattern check (lib/attack-surface.js) only reads
 * files it recognizes as route handlers, so a sink in a helper module (DVNA's
 * core/appHandler.js) or behind an Express `routes/` folder that is not a
 * Next.js API root (Juice Shop) is never read. This pass reads every server
 * code file instead.
 *
 * Sinks:
 *   eval              eval(x), (0, eval)(x), globalThis.eval(x), and
 *                     new Function(...) with any non-literal argument (the
 *                     body is the last one); vm.runIn*Context /
 *                     vm.compileFunction / new vm.Script (node:vm is not a
 *                     security boundary)
 *   command-injection a shell command whose text contains request data:
 *                     child_process exec / execSync under any binding
 *                     (`cp.exec`, `child_process_1.exec`, `{ exec: run }`,
 *                     `promisify(exec)`, `(0, _child_process.exec)`),
 *                     shelljs exec, and spawn / execFile / execa with a
 *                     `shell` option or a `sh -c` command
 *
 * Taint-lite: request data (`req.body`, `req.query`, `req.params`,
 * `req.headers`, `req.cookies`, `req.file(s)`, also `request.` and
 * `ctx.request.`, and those fields destructured from `req` or from a
 * parameter typed `Request`) and every variable assigned from an expression
 * that uses it, function calls included, within one file. No call graph, no
 * scopes, no sanitizers: "likely" means "derived from the request", not
 * "exploitable".
 *
 * Library mode (lib/whitebox/library.js): the parameters of exported
 * functions are sources too, followed inside the function that receives them
 * and one helper call further (a named function in the same file).
 *
 * Confidence:
 *   likely     request data appears in the sink's arguments
 *   potential  eval or new Function with a non-literal argument of unknown
 *              origin (stored data, a helper's parameter); worth a look,
 *              often safe. In library mode: a shell command built from an
 *              exported function's parameter
 * Not reported: a vm call whose arguments are untainted (running a fixed
 * script in a context is how vm is meant to be used) and an exec whose
 * command is untainted (CLIs and build tools build shell commands from their
 * own constants all the time; eval of a non-constant is rare and worth a look).
 */
import { readdirSync, lstatSync, existsSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { lexJs, stripComments, maskStrings, matchBracket, splitTopLevel } from "./js-lex.js";
import { librarySources, LIBRARY_SKIP } from "./library.js";

const CODE_EXT = /\.(?:js|ts|mjs|cjs|jsx|tsx)$/;
// Not server code an attacker can reach: dependencies, build output, tests,
// browser assets, build tooling.
const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage", "vendor",
  "test", "tests", "__tests__", "spec", "e2e", "cypress", "fixtures", "__mocks__",
  "public", "static", "assets", "scripts",
]);
// Next.js App Router route files are read by the route-scoped check already.
const ROUTE_FILE = /(?:^|\/)api\/(?:.*\/)?route\.[cm]?[jt]s$/;
const SKIP_FILES = /\.(?:spec|test)\.[cm]?[jt]sx?$|\.min\.js$|^(?:gruntfile|gulpfile)\.[cm]?js$|\.config\.[cm]?[jt]s$/i;
const MAX_BYTES = 512 * 1024;
// Lines this long that hold most of a file mean minified or bundled code, not
// a source file. One long line (a generated parser table, an inlined data
// blob) in an otherwise ordinary file does not.
const MAX_LINE = 5000;
const minified = (source) => {
  let long = 0;
  for (const l of source.split("\n")) if (l.length > MAX_LINE) long += l.length;
  return long > source.length / 2;
};
const MAX_FILES = 5000;

const SOURCE = /\b(?:req|request|ctx\.request)\.(?:body|query|params|headers|cookies|files?)\b/;
const REQUEST_FIELDS = new Set(["body", "query", "params", "headers", "cookies", "file", "files"]);

// eval: `args` says which arguments make the call dynamic.
const EVAL_SINKS = [
  { call: "eval", re: /(?<![\w.$])eval\s*\(|\(\s*0\s*,\s*eval\s*\)\s*\(|\b(?:globalThis|global|window|self)\.eval\s*\(/g, args: "first" },
  { call: "new Function", re: /\bnew\s+Function\s*\(/g, args: "all" },
  { call: "vm", re: /\bvm\.(?:runInContext|runInNewContext|runInThisContext|compileFunction)\s*\(|\bnew\s+vm\.Script\s*\(/g, args: null },
];

const SEVERITY = { eval: "high", "command-injection": "critical" };
// Library findings need a caller to pass untrusted input: one step below an app finding.
const LIBRARY_SEVERITY = { parameter: "high", "runs-argument": "medium" };

function walk(dir, files, root, allow) {
  if (files.length >= MAX_FILES || !existsSync(dir) || (dir !== root && existsSync(join(dir, ".git")))) return files;
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry) && !(dir === root && allow.includes(entry))) continue;
    const full = join(dir, entry);
    const st = lstatSync(full);
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) walk(full, files, root, allow);
    else if (st.isFile() && CODE_EXT.test(entry) && !SKIP_FILES.test(entry) && st.size <= MAX_BYTES) files.push(full);
    if (files.length >= MAX_FILES) break;
  }
  return files;
}

export { stripComments, maskStrings };

// One string literal without interpolation, or a number: nothing dynamic.
const LITERAL_ARG = /^\s*(?:'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`[^`$]*`|\d+(?:\.\d+)?)\s*$/;

const escapeRe = (s) => s.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
const alt = (names) => [...names].map(escapeRe).join("|");

/** Variables that hold request data, followed through assignments in this file. */
export function taintedNames(src) {
  const names = new Set();
  const isTainted = (expr) => SOURCE.test(expr) || [...names].some((n) => new RegExp(`(?<![\\w$.])${escapeRe(n)}\\b`).test(expr));
  const decl = /(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=(?![=>])\s*([^;\n]{1,300})/g;
  const destructure = /\b(?:const|let|var)\s*\{([^}]{1,300})\}\s*=\s*([^;\n]{1,300})/g;
  const fieldsOf = (list) => {
    for (const part of list.split(",")) {
      const field = part.split(/[:=]/)[0].trim();
      if (REQUEST_FIELDS.has(field)) names.add(part.split("=")[0].split(":").pop().trim());
    }
  };
  // `({ body, query }: Request, res) =>` and `const { body } = req`
  for (const m of src.matchAll(/\(\s*\{([^}]{1,300})\}\s*:\s*(?:express\.)?Request\b/g)) fieldsOf(m[1]);
  for (const m of src.matchAll(/\b(?:const|let|var)\s*\{([^}]{1,300})\}\s*=\s*(?:req|request|ctx\.request)\s*[;\n]/g)) fieldsOf(m[1]);
  for (let round = 0; round < 6; round++) {
    const size = names.size;
    for (const m of src.matchAll(decl)) if (!names.has(m[1]) && isTainted(m[2])) names.add(m[1]);
    for (const m of src.matchAll(destructure)) {
      if (!isTainted(m[2])) continue;
      for (const part of m[1].split(",")) {
        const name = part.split("=")[0].split(":").pop().trim().replace(/^\.\.\./, "");
        if (/^[A-Za-z_$][\w$]*$/.test(name)) names.add(name);
      }
    }
    if (names.size === size) break;
  }
  return names;
}

const SHELL_FNS = new Set(["exec", "execSync"]);
const SPAWN_FNS = new Set(["spawn", "spawnSync", "execFile", "execFileSync"]);
const CP_MOD = String.raw`['"\x60](?:node:)?child_process['"\x60]|['"\x60]mz/child_process['"\x60]`;
const SHELLJS_MOD = String.raw`['"\x60]shelljs['"\x60]`;
const EXECA_MOD = String.raw`['"\x60]execa['"\x60]`;
const XSPAWN_MOD = String.raw`['"\x60]cross-spawn['"\x60]`;
// require('m'), possibly wrapped by a module-interop helper: __importStar(require('m')).
const req = (mod) => String.raw`(?:[\w$.]+\(\s*)?require\(\s*(?:${mod})\s*\)\s*\)?`;
// Compiled patterns, shared across files (matchAll copies a regex, so reuse is safe).
const RX = new Map();
const rx = (pattern) => {
  let re = RX.get(pattern);
  if (!re) {
    if (RX.size > 500) RX.clear();
    re = new RegExp(pattern, "g");
    RX.set(pattern, re);
  }
  return re;
};

/**
 * How this file binds the functions that run shell commands: module objects
 * (`const cp = require('child_process')`), functions (`const { exec: run } =
 * ...`, `const run = promisify(cp.exec)`), shelljs and execa.
 */
export function commandBindings(src, code) {
  const live = (i) => code[i] === src[i];
  const b = { cpObj: new Set(), shellFn: new Set(), spawnFn: new Set(), shellObj: new Set() };
  const each = (re, fn) => { for (const m of src.matchAll(re)) if (live(m.index)) fn(m); };
  const bindDestructured = (list, mod) => {
    for (const part of list.split(",")) {
      const [orig, local = orig] = part.split(/\s*(?::|\bas\b)\s*/).map((x) => x.trim());
      if (!/^[\w$]+$/.test(local || "")) continue;
      if (mod === "cp" && SHELL_FNS.has(orig)) b.shellFn.add(local);
      if (mod === "cp" && SPAWN_FNS.has(orig)) b.spawnFn.add(local);
      if (mod === "shelljs" && orig === "exec") b.shellFn.add(local);
      if (mod === "execa" && /^execa(?:Sync)?$/.test(orig)) b.spawnFn.add(local);
    }
  };
  for (const [mod, re] of [["cp", CP_MOD], ["shelljs", SHELLJS_MOD], ["execa", EXECA_MOD], ["xspawn", XSPAWN_MOD]]) {
    const objects = mod === "cp" ? b.cpObj : mod === "shelljs" ? b.shellObj : b.spawnFn;
    each(rx(String.raw`(?<![\w$.])([\w$]+)\s*=\s*${req(re)}\s*(?=[;,\n)]|$)`), (m) => objects.add(m[1]));
    each(rx(String.raw`\bimport\s+\*\s+as\s+([\w$]+)\s+from\s+(?:${re})`), (m) => objects.add(m[1]));
    each(rx(String.raw`\bimport\s+([\w$]+)\s*(?:,\s*\{([^}]*)\})?\s+from\s+(?:${re})`), (m) => { objects.add(m[1]); if (m[2]) bindDestructured(m[2], mod); });
    each(rx(String.raw`\bimport\s+([\w$]+)\s*=\s*require\(\s*(?:${re})\s*\)`), (m) => objects.add(m[1]));
    each(rx(String.raw`\bimport\s*\{([^}]*)\}\s*from\s+(?:${re})`), (m) => bindDestructured(m[1], mod));
    each(rx(String.raw`\{([^{}]{0,400})\}\s*=\s*${req(re)}`), (m) => bindDestructured(m[1], mod));
  }
  // execa and cross-spawn export a spawn-like default; shelljs and child_process do not.
  // Destructuring from a bound module object, and members taken off it.
  const size = () => b.cpObj.size + b.shellFn.size + b.spawnFn.size + b.shellObj.size;
  for (let round = 0, before = -1; round < 3 && size() !== before; round++) {
    before = size();
    const objs = [...b.cpObj];
    const shells = [...b.shellObj];
    if (objs.length) {
      each(rx(String.raw`\{([^{}]{0,400})\}\s*=\s*(?:${alt(objs)})\s*[;\n]`), (m) => bindDestructured(m[1], "cp"));
      each(rx(String.raw`(?<![\w$.])([\w$]+)\s*=\s*(?:${alt(objs)})(?:\.default)?\.([\w$]+)\b`), (m) => {
        if (SHELL_FNS.has(m[2])) b.shellFn.add(m[1]); else if (SPAWN_FNS.has(m[2])) b.spawnFn.add(m[1]);
      });
    }
    each(rx(String.raw`(?<![\w$.])([\w$]+)\s*=\s*${req(CP_MOD)}\.([\w$]+)\b`), (m) => {
      if (SHELL_FNS.has(m[2])) b.shellFn.add(m[1]); else if (SPAWN_FNS.has(m[2])) b.spawnFn.add(m[1]);
    });
    if (shells.length) each(rx(String.raw`(?<![\w$.])([\w$]+)\s*=\s*(?:${alt(shells)})\.exec\b`), (m) => b.shellFn.add(m[1]));
    // const run = promisify(exec) / util.promisify(cp.exec) / promisify(require('child_process').exec)
    const fnRef = [
      b.shellFn.size ? `(?:${alt(b.shellFn)})` : null,
      objs.length ? String.raw`(?:${alt(objs)})(?:\.default)?\.(?:exec|execSync)` : null,
      String.raw`${req(CP_MOD)}\.(?:exec|execSync)`,
    ].filter(Boolean).join("|");
    each(rx(String.raw`(?<![\w$.])([\w$]+)\s*=\s*[\w$.]+\(\s*(?:${fnRef})\s*[,)]`), (m) => b.shellFn.add(m[1]));
  }
  return b;
}

// A `shell` option that turns the shell on: anything but false, null, undefined, 0 or "".
const SHELL_ON = /\bshell\s*:(?!\s*(?:false|null|undefined|0)\b|\s*''|\s*""|\s*[,}])/;

/** A spawn-style call runs a shell:a `shell` option that is not false, or `sh -c <command>`. */
function spawnRunsShell(args, optionObjects) {
  const opt = args.find((a, i) => i > 0 && (/^\s*\{/.test(a) || optionObjects.has(a.trim())));
  if (opt && (SHELL_ON.test(opt) || optionObjects.get(opt.trim()) === true)) return "option";
  if (/^\s*['"`](?:\/(?:usr\/)?bin\/)?(?:ba|da|z|k)?sh['"`]\s*$|^\s*['"`]cmd(?:\.exe)?['"`]\s*$/i.test(args[0] || "") && /^\s*\[\s*['"`][-/]c['"`]/i.test(args[1] || "")) return "sh-c";
  return null;
}

/** Command sinks in this file: { re, call, kind: "shell" | "spawn" }. */
function commandSinks(src, code) {
  if (!/child_process|shelljs|execa|cross-spawn/.test(src)) return [];
  const b = commandBindings(src, code);
  const cpObjs = alt(new Set(["child_process", "childProcess", "cp", ...b.cpObj]));
  const shellNames = alt(new Set([...SHELL_FNS, ...b.shellFn]));
  const out = [
    { call: "exec", kind: "shell", re: rx(String.raw`(?<![\w.$])(?:${shellNames})\s*\(|\b(?:${cpObjs})(?:\.default)?\.(?:exec|execSync)\s*\(|\(\s*0\s*,\s*(?:${cpObjs})(?:\.default)?\.(?:exec|execSync)\s*\)\s*\(|${req(CP_MOD)}\.(?:exec|execSync)\s*\(`) },
  ];
  if (b.shellObj.size) out.push({ call: "shelljs exec", kind: "shell", re: rx(String.raw`\b(?:${alt(b.shellObj)})\.exec\s*\(|${req(SHELLJS_MOD)}\.exec\s*\(`) });
  const spawnNames = alt(new Set([...SPAWN_FNS, ...b.spawnFn]));
  out.push({ call: "spawn with a shell", kind: "spawn", re: rx(String.raw`(?<![\w.$])(?:${spawnNames})\s*\(|\b(?:${cpObjs})(?:\.default)?\.(?:spawn|spawnSync|execFile|execFileSync)\s*\(|\(\s*0\s*,\s*(?:${cpObjs})(?:\.default)?\.(?:spawn|spawnSync|execFile|execFileSync)\s*\)\s*\(`) });
  return out;
}

/** `const opts = { shell: true }`: option objects declared in this file, by name. */
function shellOptionObjects(src) {
  const out = new Map();
  for (const m of src.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*\{([^{}]{0,400})\}/g)) {
    out.set(m[1], SHELL_ON.test(m[2]));
  }
  return out;
}

/** The arguments of the call whose "(" is at `open`, split at top-level commas (bounded). */
function callArgs(code, src, open) {
  const close = matchBracket(code, open, 2000);
  const end = close === -1 ? Math.min(src.length, open + 300) : close;
  return splitTopLevel(code.slice(open + 1, end), src.slice(open + 1, end));
}

/**
 * Find code-execution sinks in one file's source.
 * @param {string} source
 * @param {{ library?: boolean }} [opts] - library: also treat exported functions' parameters as sources
 * @returns {{ pattern, call, line, confidence, tainted, library? }[]}
 */
export function findSinks(source, opts = {}) {
  if (minified(source)) return [];
  const { code, plain: src, expr } = lexJs(source);
  const names = taintedNames(src);
  const taints = (text) => SOURCE.test(text) || [...names].some((n) => new RegExp(`(?<![\\w$.])${escapeRe(n)}\\b`).test(text));
  const live = (m) => code[m.index] === src[m.index];
  const lineOf = (i) => src.slice(0, i).split("\n").length;
  const hits = [];

  for (const sink of EVAL_SINKS) {
    for (const m of src.matchAll(sink.re)) {
      if (!live(m)) continue;
      const open = m.index + m[0].length - 1;
      const args = callArgs(code, src, open);
      const all = args.join(",");
      const tainted = taints(all);
      const dynamic = sink.args === "all" ? args.some((a) => !LITERAL_ARG.test(a)) : sink.args === "first" ? !LITERAL_ARG.test(args[0] ?? "") : false;
      if (!tainted && !dynamic) continue;
      hits.push({ pattern: "eval", call: sink.call, line: lineOf(m.index), tainted, confidence: tainted ? "likely" : "potential" });
    }
  }

  const sinks = commandSinks(src, code);
  if (!sinks.length) return hits;
  const optionObjects = shellOptionObjects(src);
  let lib = null;
  const libraryFns = () => (lib ||= librarySources(code, expr));
  const seen = new Set();
  for (const sink of sinks) {
    for (const m of src.matchAll(sink.re)) {
      if (!live(m) || seen.has(m.index)) continue;
      const open = m.index + m[0].length - 1;
      if (code[open] !== "(") continue;
      const args = callArgs(code, src, open);
      // The command text with string contents blanked (`${...}` kept), for the parameter check.
      const exprArgs = callArgs(code, expr, open);
      let command = exprArgs.slice(0, 1);
      if (sink.kind === "spawn") {
        const how = spawnRunsShell(args, optionObjects);
        if (!how) continue;
        command = how === "sh-c" ? exprArgs.slice(1, 2) : exprArgs.slice(0, 2);
      }
      seen.add(m.index);
      const line = lineOf(m.index);
      if (taints(args.join(","))) {
        hits.push({ pattern: "command-injection", call: sink.call, line, tainted: true, confidence: "likely" });
        continue;
      }
      if (!opts.library) continue;
      const text = command.join(",");
      for (const fn of libraryFns()) {
        if (m.index <= fn.bodyStart - 1 || m.index > fn.bodyEnd) continue;
        if (!fn.uses(text)) continue;
        const bare = /^\s*([\w$]+)(?:\s*\.\s*[\w$]+)*\s*$/.exec(command[0] || "");
        const runsArgument = Boolean(bare && fn.params.has(bare[1]));
        hits.push({
          pattern: "command-injection", call: sink.call, line, tainted: false, confidence: "potential",
          library: { function: fn.name, kind: runsArgument ? "runs-argument" : "parameter", ...(fn.via ? { via: fn.via } : {}) },
        });
        break;
      }
    }
  }
  return hits;
}

const describeHit = (h) => `${h.call} on line ${h.line}${h.tainted ? " (from the request)" : h.library ? ` (from a parameter of \`${h.library.function}\`${h.library.via ? `, through \`${h.library.via}\`` : ""})` : ""}`;

/**
 * Scan a repository's server code for code-execution sinks.
 * @param {string} repoPath
 * @param {{ library?: { enabled: boolean, readDirs?: string[] } }} [opts]
 * @returns {object[]} findings, one per file and sink kind
 */
export function scanCodeSinks(repoPath, opts = {}) {
  const library = opts.library?.enabled ? opts.library : null;
  const findings = [];
  for (const file of walk(repoPath, [], repoPath, library?.readDirs || [])) {
    let source;
    try { source = readFileSync(file, "utf-8"); } catch { continue; }
    const rel = relative(repoPath, file).split(sep).join("/");
    if (ROUTE_FILE.test(rel)) continue;
    const byPattern = new Map();
    for (const hit of findSinks(source, { library: Boolean(library) && !LIBRARY_SKIP.test(rel) })) {
      const list = byPattern.get(hit.pattern) || [];
      list.push(hit);
      byPattern.set(hit.pattern, list);
    }
    for (const [pattern, hits] of byPattern) {
      const top = hits.find((h) => h.tainted) || hits.find((h) => h.library?.kind === "parameter") || hits[0];
      const lines = hits.map(describeHit).slice(0, 5).join(", ");
      const finding = {
        severity: top.library ? LIBRARY_SEVERITY[top.library.kind] : SEVERITY[pattern],
        title: `${pattern} in ${rel}`,
        description: top.tainted
          ? `Data derived from the request reaches a code-execution sink in \`${rel}\`: ${lines}.`
          : top.library?.kind === "parameter"
            ? `A parameter of the exported function \`${top.library.function}\` reaches a shell command in \`${rel}\`: ${lines}. Whoever calls this library decides what that parameter holds.`
            : top.library
              ? `The exported function \`${top.library.function}\` runs its argument as a shell command in \`${rel}\`: ${lines}. That may be its job, but callers must not pass untrusted input to it.`
              : `A code-execution sink in \`${rel}\` takes a value Penthera cannot trace to a constant: ${lines}. Check where it comes from.`,
        remediation: pattern === "eval"
          ? "Do not evaluate data as code. Parse it (JSON.parse, a math parser) instead; node:vm is not a sandbox."
          : top.library
            ? "Pass the parameter as an argument to execFile or spawn, with an argument array and no shell. If the function must take a command line, say in its documentation that callers must never pass untrusted input."
            : "Use execFile or spawn with an argument array and no shell, and validate the input against an allowlist.",
        url: rel,
        file: rel,
        line: top.line,
        pattern,
        category: "code-pattern",
        source: "static-analysis",
        confidence: top.confidence,
      };
      if (top.library) finding.library = top.library.kind;
      findings.push(finding);
    }
  }
  return findings;
}
