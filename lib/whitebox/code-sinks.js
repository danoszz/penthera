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
import { readdirSync, lstatSync, statSync, realpathSync, existsSync, readSync, closeSync } from "node:fs";
import { readRepoFile, openRepoFile } from "../fs-safe.js";
import { join, relative, resolve, sep } from "node:path";
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
// Files up to this size are analysed in one piece. A larger one is analysed in
// pieces of this size, streamed and lexed with the state carried (findSinksStream), so it is
// scanned, not skipped; one over READ_MAX_BYTES is not read and the run is incomplete.
const MAX_BYTES = 512 * 1024;
const READ_MAX_BYTES = 64 * 1024 * 1024;
const OVERLAP_LINES = 200;
// Lines this long that hold most of a file mean minified or bundled code, not
// a source file. One long line (a generated parser table, an inlined data
// blob) in an otherwise ordinary file does not.
const MAX_LINE = 5000;
/**
 * Minified or bundled? Measured on the lexed text with comments blanked
 * (lexJs `plain`), so one long comment line can't make a file with an eval in
 * it read as minified and skip the whole file (Fact-checker, 2.3.2).
 */
const minified = (plain) => {
  let long = 0;
  let total = 0;
  for (const l of plain.split("\n")) {
    const t = l.trim().length;
    total += t;
    if (t > MAX_LINE) long += t;
  }
  return total > 0 && long > total / 2;
};
const MAX_FILES = 5000;
export const SINK_MAX_FILES = MAX_FILES;

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

// Next.js build output under another name (`.next-dev`, `.next-3002`, set by distDir).
const NEXT_BUILD = /^\.next(?:$|[-_.])/;

/** Is this folder one the sink walk does not enter? `ignoredDirs` holds the absolute paths git ignores. */
export function isSinkSkipDir(name, full, ignoredDirs) {
  return SKIP_DIRS.has(name) || NEXT_BUILD.test(name) || Boolean(ignoredDirs?.has(full));
}

/** Does the sink walk read a file of this name and size? "examined", "too-large" or null. */
export function sinkFileStatus(name, size) {
  if (!CODE_EXT.test(name) || SKIP_FILES.test(name)) return null;
  return size > READ_MAX_BYTES ? "too-large" : "examined";
}

// Files past MAX_FILES are counted in `over`, not read, so the scan can say so (R2).
// Sorted, as the Coverage walk is, so both agree on which files were past the cap.
function walk(dir, files, root, allow, ignoredDirs, over = { n: 0 }, unread = [], seen = new Set()) {
  if (!existsSync(dir) || (dir !== root && existsSync(join(dir, ".git")))) return files;
  let realRoot = root;
  try { realRoot = realpathSync(root); } catch { /* keep as given */ }
  try { seen.add(realpathSync(dir)); } catch { /* keep going */ }
  let entries;
  try { entries = readdirSync(dir).sort(); } catch (e) { unread.push({ path: dir, reason: `the folder could not be listed (${e.code || e.message})` }); return files; }
  for (const entry of entries) {
    const full = join(dir, entry);
    if (isSinkSkipDir(entry, full, ignoredDirs) && !(dir === root && allow.includes(entry))) continue;
    let st;
    try { st = lstatSync(full); } catch { continue; } // gone since the listing
    if (st.isSymbolicLink()) {
      // A link that stays in the project is read (a file) or walked once (a
      // folder); one that leaves it or leads nowhere is named, never silent.
      let target = null;
      try { target = realpathSync(full); } catch { /* broken */ }
      const inside = target && (target === realRoot || target.startsWith(realRoot + sep));
      let tst = null;
      if (target) { try { tst = statSync(full); } catch { /* raced */ } }
      if (tst?.isDirectory()) {
        if (!inside) unread.push({ path: full, reason: "it is a linked folder outside the project" });
        else if (!seen.has(target)) walk(full, files, root, allow, ignoredDirs, over, unread, seen);
      } else if (sinkFileStatus(entry, 0)) {
        if (!target) unread.push({ path: full, reason: "it is a link to nothing" });
        else if (!inside) unread.push({ path: full, reason: "it resolves outside the project folder" });
        else if (files.length < MAX_FILES) files.push(full);
        else over.n++;
      }
      continue;
    }
    if (st.isDirectory()) walk(full, files, root, allow, ignoredDirs, over, unread, seen);
    else if (!st.isFile()) {
      // A FIFO or a device with a code file's name: never read, never silent.
      if (sinkFileStatus(entry, 0)) unread.push({ path: full, reason: "it is not a regular file (a FIFO, a socket or a device)" });
    } else {
      const status = sinkFileStatus(entry, st.size);
      if (status === "too-large") unread.push({ path: full, reason: `it is over the ${READ_MAX_BYTES / 1024 / 1024} MiB limit` });
      else if (status === "examined") {
        if (files.length < MAX_FILES) files.push(full);
        else over.n++;
      }
    }
  }
  return files;
}

export { stripComments, maskStrings };

// One string literal without interpolation, or a number: nothing dynamic.
const LITERAL_ARG = /^\s*(?:'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`[^`$]*`|\d+(?:\.\d+)?)\s*$/;

const escapeRe = (s) => s.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
const alt = (names) => [...names].map(escapeRe).join("|");

/** Variables that hold request data, followed through assignments in this file. */
export function taintedNames(src, seed = null) {
  // seed: names found tainted earlier in the same file (findSinksStream), so a
  // value taken from the request in one piece is still tainted in the next.
  const names = new Set(seed || []);
  const isTainted = (expr) => SOURCE.test(expr) || [...names].some((n) => new RegExp(`(?<![\\w$.])${escapeRe(n)}\\b`).test(expr));
  // The name starts at an identifier boundary: without the lookbehind every
  // position inside a long run of letters rescanned the run (quadratic: about
  // 160 s on one 600 KB line).
  const decl = /(?:\b(?:const|let|var)\s+)?(?<![\w$])([A-Za-z_$][\w$]*)\s*=(?![=>])\s*([^;\n]{1,300})/g;
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
export function commandBindings(src, code, seed = null) {
  const live = (i) => code[i] === src[i];
  // seed: bindings found earlier in the same file (findSinksStream), so an alias
  // or a promisify in this piece resolves against a module bound in another.
  const b = {
    cpObj: new Set(seed?.cpObj), shellFn: new Set(seed?.shellFn), spawnFn: new Set(seed?.spawnFn), shellObj: new Set(seed?.shellObj),
  };
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
function commandSinks(src, code, seed = null) {
  const seeded = seed && (seed.cpObj.size + seed.shellFn.size + seed.spawnFn.size + seed.shellObj.size) > 0;
  if (!seeded && !/child_process|shelljs|execa|cross-spawn/.test(src)) return [];
  const b = commandBindings(src, code, seed);
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
/**
 * A large file's text in pieces of about MAX_BYTES that end at a line break,
 * read from `fd` and decoded as UTF-8 across piece edges. A line longer than a
 * piece is cut at a space, so no word or two-character token is split. Memory:
 * one read buffer and at most two pieces of text.
 */
function* textPieces(fd, size) {
  const decoder = new TextDecoder("utf-8");
  const buf = Buffer.alloc(MAX_BYTES);
  let carry = "";
  for (let pos = 0; pos < size;) {
    const n = readSync(fd, buf, 0, Math.min(MAX_BYTES, size - pos), pos);
    if (n <= 0) break;
    pos += n;
    const text = carry + decoder.decode(buf.subarray(0, n), { stream: pos < size });
    let cut = text.lastIndexOf("\n") + 1;
    if (cut === 0 && text.length >= MAX_BYTES) cut = text.lastIndexOf(" ", MAX_BYTES) + 1 || MAX_BYTES;
    // No line break yet: nothing is skipped, the text is carried into the next read.
    if (cut === 0) { carry = text; continue; }
    yield text.slice(0, cut);
    carry = text.slice(cut);
  }
  carry += decoder.decode();
  if (carry) yield carry;
}

const countNl = (t) => { let c = 0; for (let k = t.indexOf("\n"); k !== -1; k = t.indexOf("\n", k + 1)) c++; return c; };
const TAIL_MAX = 64 * 1024; // the overlap carried into the next piece: OVERLAP_LINES lines, at most this many characters
// Whole-file context carried across pieces: names bound to child_process,
// shelljs, execa or cross-spawn, and names holding request data. Past this many,
// the file is not checked in pieces (it is named, and the run is incomplete),
// so no binding is ever dropped to make room for decoys.
const CARRY_MAX = 5000;

/** The text from the start of the last OVERLAP_LINES lines of `text` (at most TAIL_MAX characters) to its end. */
function tailStart(text) {
  let at = text.length;
  for (let lines = 0; at > 0 && lines < OVERLAP_LINES; lines++) {
    const start = text.lastIndexOf("\n", at - 2) + 1;
    if (start >= at || text.length - start > TAIL_MAX) break;
    at = start;
  }
  return at;
}

/** A file whose whole-file context is too large to carry: named by the caller, never checked in part. */
export class SinkContextError extends Error {}

const bindingCount = (b) => b.cpObj.size + b.shellFn.size + b.spawnFn.size + b.shellObj.size;

/**
 * findSinks for a file too large to hold: streamed from `fd`, with memory
 * bounded by the piece size, whatever the file's size. The lexer state
 * (template nesting, open comments and strings, the regex rule's last word)
 * is carried from one piece into the next, so each piece is lexed as the whole
 * file would be. Whole-file context is gathered first, in up to three streaming
 * passes until nothing new turns up: the command bindings (imports, requires,
 * destructuring over several lines, aliases, promisify) and the names holding
 * request data, each piece read with the previous piece's last OVERLAP_LINES
 * lines in front, the last line included whether or not it ends in a line
 * break. The check pass then reads each piece the same way with that context
 * seeded, so a call bound or tainted in another piece is still found. Hits are
 * mapped to the file's lines and deduplicated. Throws SinkContextError when
 * the context outgrows CARRY_MAX.
 */
export function findSinksStream(fd, size, opts = {}) {
  const pieces = function* () {
    let state = null;
    let tail = { code: "", plain: "", expr: "" };
    let lineBase = 0;
    for (const piece of textPieces(fd, size)) {
      const lexed = lexJs(piece, state);
      state = lexed.state;
      const first = lineBase - countNl(tail.code);
      yield { part: { code: tail.code + lexed.code, plain: tail.plain + lexed.plain, expr: tail.expr + lexed.expr }, first, plain: lexed.plain };
      lineBase += countNl(piece);
      const at = tailStart(lexed.code);
      tail = { code: lexed.code.slice(at), plain: lexed.plain.slice(at), expr: lexed.expr.slice(at) };
    }
  };

  // minified() over the whole file first: lexing only, nothing else is run on it.
  {
    let long = 0, total = 0, cur = 0;
    for (const { plain } of pieces()) {
      const lines = plain.split("\n");
      for (let k = 0; k < lines.length; k++) {
        cur += lines[k].trim().length;
        if (k < lines.length - 1) { total += cur; if (cur > MAX_LINE) long += cur; cur = 0; }
      }
    }
    total += cur;
    if (cur > MAX_LINE) long += cur;
    // Minified, as findSinks decides for a small file: no findings, and the
    // coverage ledger says the check did not apply (onMinified), never silent.
    if (total > 0 && long > total / 2) { opts.onMinified?.(); return []; }
  }

  // Context passes, until nothing new turns up (at most three).
  let bindings = { cpObj: new Set(), shellFn: new Set(), spawnFn: new Set(), shellObj: new Set() };
  let tainted = new Set();
  const COMMAND_MODULE = /child_process|shelljs|execa|cross-spawn/;
  for (let pass = 0; pass < 3; pass++) {
    const before = bindingCount(bindings) + tainted.size;
    for (const { part } of pieces()) {
      // Bindings only where a command module is named or one is already bound, as commandSinks does.
      if (bindingCount(bindings) || COMMAND_MODULE.test(part.plain)) bindings = commandBindings(part.plain, part.code, bindings);
      tainted = taintedNames(part.plain, tainted);
      if (bindingCount(bindings) > CARRY_MAX || tainted.size > CARRY_MAX) throw new SinkContextError(`it binds more than ${CARRY_MAX} command or request names, too many to carry across pieces`);
    }
    if (bindingCount(bindings) + tainted.size === before) break;
  }

  // The check pass, with the whole file's context seeded.
  const out = new Map();
  for (const { part, first } of pieces()) {
    for (const h of sinksIn(part, { ...opts, bindings, tainted })) {
      const line = first + h.line;
      const key = `${h.pattern}|${h.call}|${line}`;
      const had = out.get(key);
      if (!had || (h.tainted && !had.tainted)) out.set(key, { ...h, line });
    }
  }
  return [...out.values()].sort((a, b) => a.line - b.line);
}

export function findSinks(source, opts = {}) {
  const lexed = lexJs(source);
  // Minified code gets no findings; onMinified lets the coverage ledger say so.
  if (minified(lexed.plain)) { opts.onMinified?.(); return []; }
  return sinksIn(lexed, opts);
}

/** The sinks in lexed JavaScript (lexJs output, or a line-aligned slice of it). */
function sinksIn({ code, plain: src, expr }, opts = {}) {
  const names = taintedNames(src, opts.tainted);
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

  const sinks = commandSinks(src, code, opts.bindings);
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
 * @param {{ library?: { enabled: boolean, readDirs?: string[] }, ignored?: { dirs: Set<string> } | null, refused?: object[] }} [opts]
 *   `ignored` is gitIgnored(repoPath): folders git ignores are build output or local, so they are skipped.
 *   `minified`: the repo-relative path of each minified file (no findings) is
 *   pushed there, for the coverage ledger.
 *   `refused`: each code file that could not be read is pushed there as
 *   `{ path, reason, message }`, so the caller can name it and mark the run incomplete.
 * @returns {object[]} findings, one per file and sink kind
 */
export function scanCodeSinks(repoPath, opts = {}) {
  const library = opts.library?.enabled ? opts.library : null;
  const ignoredDirs = opts.ignored?.dirs ? new Set([...opts.ignored.dirs].map((d) => resolve(d))) : null;
  const findings = [];
  const over = { n: 0 };
  const unread = [];
  const refuse = (path, reason) => opts.refused?.push({ path, reason, message: `${relative(resolve(repoPath), path).split(sep).join("/")} was not read: ${reason}` });
  const files = walk(resolve(repoPath), [], resolve(repoPath), library?.readDirs || [], ignoredDirs, over, unread);
  for (const u of unread) refuse(u.path, u.reason);
  for (const file of files) {
    const rel = relative(resolve(repoPath), file).split(sep).join("/");
    if (ROUTE_FILE.test(rel)) continue;
    const sinkOpts = { library: Boolean(library) && !LIBRARY_SKIP.test(rel), onMinified: () => opts.minified?.push(rel) };
    let hits;
    // A read error is never silent: the file is named and the run is incomplete.
    // A file over MAX_BYTES is streamed, so memory stays bounded whatever its size.
    try {
      let size = 0;
      try { size = statSync(file).size; } catch { /* the open below says why */ }
      if (size <= MAX_BYTES) hits = findSinks(readRepoFile(file, { maxBytes: MAX_BYTES * 2, root: resolve(repoPath) }), sinkOpts);
      else {
        const { fd, size: n } = openRepoFile(file, { maxBytes: READ_MAX_BYTES, root: resolve(repoPath) });
        try { hits = findSinksStream(fd, n, sinkOpts); } finally { closeSync(fd); }
      }
    } catch (e) {
      if (e.code !== "ENOENT") refuse(file, e.reason || e.code || e.message);
      continue;
    }
    const byPattern = new Map();
    for (const hit of hits) {
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
  if (over.n) {
    findings.push({
      severity: "info",
      title: `Code-execution check stopped at ${MAX_FILES} files`,
      description: `The eval and exec check reads at most ${MAX_FILES} code files. ${over.n} more were not read; Coverage lists them as past the limit.`,
      remediation: "Scan the folders that hold server code on their own (penthera --repo <folder>).",
      category: "code-pattern",
      source: "static-analysis",
    });
  }
  return findings;
}
