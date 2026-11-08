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
import { readdirSync, lstatSync, statSync, realpathSync, existsSync } from "node:fs";
import { readRepoFile } from "../fs-safe.js";
import { join, relative, resolve, sep } from "node:path";
import { lexJs, stripComments, maskStrings, matchBracket, splitTopLevel, bracketPairs } from "./js-lex.js";
import { librarySources, LIBRARY_SKIP } from "./library.js";
import { lineIndex, mentions } from "../linear-text.js";

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
// A server file is read and analysed whole, up to READ_MAX_BYTES; a larger one
// is not read, and the run is incomplete (exit 2). Whole reads leave no piece
// edges for context to fall through (Vercel Security Review K, 2.3.2).
// Measured, worst content (a file of eval(x) lines, of a = req.body lines, one
// whitespace line), hits kept compact: 12 MiB peaks at 455 MB, 14 MiB at 508 MB,
// 16 MiB at 589 MB; the budget is 512 MB. Time sets the cap lower: a crafted
// file costs about 0.11 s per MiB per kind of content on Node 22 (linear:
// 1.5, 3, 6 and 12 MiB measured), and 12 MiB of three kinds overran a 20 s CI
// test on the slower Node 22 runner. At 4 MiB the worst case takes a few
// seconds there. Before 2.3.2, files over 512 KB were skipped.
const READ_MAX_BYTES = 4 * 1024 * 1024;
// The lines a finding names (describeHit, slice(0, 5)).
const FIRST_HITS = 5;
// Lines this long that hold most of a file mean minified or bundled code, not
// a source file. One long line (a generated parser table, an inlined data
// blob) in an otherwise ordinary file does not.
const MAX_LINE = 5000;
/**
 * Minified or bundled? Measured on the lexed text with comments blanked
 * (lexJs `plain`), so one long comment line can't make a file with an eval in
 * it read as minified and skip the whole file (Fact-checker, 2.3.2).
 */
// JavaScript's whitespace (what \s matches), by code point.
const isWhite = (c) => c === 32 || (c >= 9 && c <= 13) || c === 0xa0 || c === 0x1680 || (c >= 0x2000 && c <= 0x200a)
  || c === 0x2028 || c === 0x2029 || c === 0x202f || c === 0x205f || c === 0x3000 || c === 0xfeff;

/** How many characters of `l` are not whitespace. A loop: l.match(/\s/g) built one string per space (892 MB peak on a 16 MiB line). */
function solidLength(l) {
  let n = 0;
  for (let k = 0; k < l.length; k++) if (!isWhite(l.charCodeAt(k))) n++;
  return n;
}

const minified = (plain) => {
  let long = 0;
  let total = 0;
  // CR, CRLF, U+2028 and U+2029 end a line too: a file with only those was one
  // long "line" and read as minified.
  for (const l of plain.split(/\r\n|[\n\r\u2028\u2029]/)) {
    // A line is long by the characters in it that are not whitespace, and its
    // weight in `long` is that count; `total` keeps every character of the
    // trimmed line. So spaces padded inside a line can only make a file look
    // less minified, never more (a padded line with an eval read as minified,
    // Fact-checker 2.3.2).
    const solid = solidLength(l);
    total += l.trim().length;
    if (solid > MAX_LINE) long += solid;
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

const PLAIN_NAME = /^[A-Za-z_$][\w$]*$/;

const SOURCE_G = new RegExp(SOURCE.source, "g");
const IDENT_G = /(?<![\w$.])[A-Za-z_$][\w$]*/g; // as linear-text's mentions() reads names
// A declaration (`a = …`, `const a = …`) up to its value. The name starts at an
// identifier boundary: without the lookbehind every position inside a long run
// of letters rescanned the run (quadratic: about 160 s on one 600 KB line).
const DECL = /(?:\b(?:const|let|var)\s+)?(?<![\w$])([A-Za-z_$][\w$]*)\s*=(?![=>])\s*/g;
const isStatementEnd = (c) => c === ";" || c === "\n";

/**
 * Variables that hold request data, followed through assignments in this file.
 *
 * One linear pass, no caps (Vercel, checklist row 1): a value was read only
 * 300 characters deep, a destructured list only 300, and taint followed only
 * 6 rounds, so padding a value or a list, or a chain of 7 assignments written
 * bottom-up, dropped the taint without a word. Now each value is the rest of
 * its statement (to ";" or a line end), read as a region: the text up to the
 * next value in the same statement, plus that value (so `a = b = req.body`
 * costs each character once). A region is tainted when it holds request data
 * or a tainted name; it taints the names assigned from it, and the region
 * before it in the statement. Taint spreads by a breadth-first walk, as far
 * as it goes.
 * @param {string} src  the text (comments blanked, strings kept)
 * @param {string} [code]  the same text with strings masked, for brace matching
 */
export function taintedNames(src, code = lexJs(src).code) {
  const names = new Set();
  const lists = braceLists(src, code);
  const fieldsOf = (list) => {
    for (const part of list.split(",")) {
      const field = part.split(/[:=]/)[0].trim();
      const name = part.split("=")[0].split(":").pop().trim();
      if (REQUEST_FIELDS.has(field) && PLAIN_NAME.test(name)) names.add(name);
    }
  };
  // `({ body, query }: Request, res) =>` and `const { body } = req`
  for (const m of src.matchAll(/\(\s*\{/g)) {
    const l = lists.get(m.index + m[0].length - 1);
    if (l && matchAt(String.raw`\s*:\s*(?:express\.)?Request\b`, src, l.after)) fieldsOf(lists.list(l));
  }
  // Values: where each starts, and the names assigned from it.
  const values = [];
  for (const m of src.matchAll(/\b(?:const|let|var)\s*\{/g)) {
    const l = lists.get(m.index + m[0].length - 1);
    if (!l) continue;
    if (matchAt(String.raw`\s*=\s*(?:req|request|ctx\.request)\s*[;\n]`, src, l.after)) fieldsOf(lists.list(l));
    const eq = matchAt(String.raw`\s*=\s*`, src, l.after);
    if (!eq) continue;
    const targets = [];
    for (const part of lists.top(l).split(",")) {
      const name = part.split("=")[0].split(":").pop().trim().replace(/^\.\.\./, "");
      if (PLAIN_NAME.test(name)) targets.push(name);
    }
    values.push({ v: l.after + eq[0].length, targets });
  }
  for (const m of src.matchAll(DECL)) values.push({ v: m.index + m[0].length, targets: [m[1]] });
  // A value is at least one character before its statement ends.
  const live = values.filter((x) => x.v < src.length && !isStatementEnd(src[x.v])).sort((x, y) => x.v - y.v);
  // Merge values that start at the same place, then find each one's statement end, in one forward sweep.
  const regions = [];
  for (const x of live) {
    const last = regions[regions.length - 1];
    if (last && last.v === x.v) last.targets.push(...x.targets);
    else regions.push({ v: x.v, targets: [...x.targets], end: 0, tainted: false, prev: -1 });
  }
  let e = 0;
  for (const r of regions) {
    if (e < r.v) { e = r.v; while (e < src.length && !isStatementEnd(src[e])) e++; }
    r.end = e;
  }
  // A region runs to the next value in its statement, or the statement's end.
  for (let i = 0; i < regions.length; i++) {
    const n = regions[i + 1];
    if (n && n.v < regions[i].end) { n.prev = i; regions[i].stop = n.v; } else regions[i].stop = regions[i].end;
  }
  // Which region a position falls in, for positions in increasing order (a sweep).
  const sweep = () => {
    let k = 0;
    return (p) => {
      while (k < regions.length && regions[k].stop <= p) k++;
      return k < regions.length && regions[k].v <= p ? k : -1;
    };
  };
  const byName = new Map();
  const queue = [];
  const taint = (i) => { if (i !== -1 && !regions[i].tainted) { regions[i].tainted = true; queue.push(i); } };
  const regionOfIdent = sweep();
  for (const m of src.matchAll(IDENT_G)) {
    const i = regionOfIdent(m.index);
    if (i === -1) continue;
    let list = byName.get(m[0]);
    if (!list) byName.set(m[0], (list = []));
    if (list[list.length - 1] !== i) list.push(i);
  }
  const regionOfSource = sweep();
  for (const m of src.matchAll(SOURCE_G)) taint(regionOfSource(m.index));
  const doneNames = new Set();
  const taintName = (name) => {
    names.add(name);
    if (doneNames.has(name)) return;
    doneNames.add(name);
    for (const i of byName.get(name) || []) taint(i);
  };
  for (const name of [...names]) taintName(name);
  for (let k = 0; k < queue.length; k++) {
    const r = regions[queue[k]];
    for (const t of r.targets) taintName(t);
    taint(r.prev);
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
// The helper's name starts at a name boundary: without the lookbehind, every
// position inside a long run of name characters (a long string literal or
// name) restarted it and rescanned the run, quadratic (hours at 4 MiB,
// Reviewer and Red Team, 2.3.2).
// The wrapper's ")" is `(?:\s*\))?`, not `\s*\)?`: two runs of \s* next to each
// other (here and in a pattern that follows with \s*) traded a long run of
// blank space between them, quadratic.
const req = (mod) => String.raw`(?:(?<![\w$.])[\w$.]+\(\s*)?require\s*\(\s*(?:${mod})\s*\)(?:\s*\))?`;
// The member step after require(...): `.exec`, `?.exec`, `["exec"]` or `?.["exec"]`.
const MEMBER = (names) => String.raw`(?:\s*\??\.\s*(?:${names})\b|\s*(?:\?\.\s*)?\[\s*['"\x60](?:${names})['"\x60]\s*\])`;
// require("child_process").exec as a whole value.
const REQUIRED_EXEC = new RegExp(String.raw`^${req(CP_MOD)}${MEMBER("exec|execSync")}$`);
/**
 * `name` is `obj.method` or `obj.default.method` with obj in `objs` and method
 * in `methods`. whole: the name is exactly that; otherwise it may also end in
 * it (`x.cp.exec`, as \bcp\.exec matched). Split on dots, no pattern.
 */
function memberOf(name, objs, methods, whole = false) {
  if (!objs.size) return false;
  const parts = name.split(".");
  if (parts.length < 2 || !methods.has(parts.pop())) return false;
  if (parts.length >= 2 && parts.at(-1) === "default" && objs.has(parts.at(-2)) && (!whole || parts.length === 2)) return true;
  return objs.has(parts.at(-1)) && (!whole || parts.length === 1);
}
// Compiled patterns, shared across files (matchAll copies a regex, so reuse is safe).
const RX = new Map();
const rx = (pattern, flags = "g") => {
  const key = flags + "/" + pattern;
  let re = RX.get(key);
  if (!re) {
    if (RX.size > 500) RX.clear();
    re = new RegExp(pattern, flags);
    RX.set(key, re);
  }
  return re;
};
/** Does `pattern` match `src` exactly at `at`? (sticky; the match, or null) */
const matchAt = (pattern, src, at) => { const re = rx(pattern, "y"); re.lastIndex = at; return re.exec(src); };

/**
 * The brace lists of a file, `{ … }`, read whole with their matching "}"
 * (bracketPairs over the lexed code, so a brace in a string or comment is
 * not one). No length cap: a `{0,N}` bound dropped a padded
 * `import { …, exec as runTask } from "child_process"` without a word, and a
 * cap must never drop silently (Vercel U, checklist row 1). Linear: one pass
 * for the pairs, and each list is sliced once.
 */
// One map per file, shared by every caller, so the budget below is the file's.
let braceCache = null;
function braceLists(src, code) {
  if (braceCache && braceCache.src === src && braceCache.code === code) return braceCache.at;
  const closeOf = bracketPairs(code);
  const at = new Map();
  // Offsets only: a list's text and its top-level text are built on first use
  // and charged to the file's work budget; past it they are empty and
  // `at.over` makes the run incomplete (Vercel, PR 281).
  for (let i = code.indexOf("{"); i !== -1; i = code.indexOf("{", i + 1)) {
    const close = closeOf(i);
    if (close !== -1 && code[close] === "}") at.set(i, { open: i, close, after: close + 1 });
  }
  const limit = 8 * code.length + (1 << 20);
  let work = 0;
  at.over = false;
  const spend = (n) => { work += n; if (work > limit) at.over = true; return !at.over; };
  // The list's text, whole.
  at.list = (l) => (l.text ??= spend(l.close - l.open) ? src.slice(l.open + 1, l.close) : "");
  // The list with each nested `{...}` collapsed to `{}`: every character is in one
  // list's top text, so splitting nested object literals is linear.
  at.top = (l) => {
    if (l.top !== undefined) return l.top;
    let out = "", seg = l.open + 1;
    for (let i = code.indexOf("{", l.open + 1); i !== -1 && i < l.close; i = code.indexOf("{", i + 1)) {
      const j = closeOf(i);
      if (j === -1 || j > l.close) break;
      out += src.slice(seg, i) + "{}";
      seg = j + 1;
      i = j;
    }
    out += src.slice(seg, l.close);
    return (l.top = spend(out.length + 1) ? out : "");
  };
  braceCache = { src, code, at };
  return at;
}

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
      const [orig, local = orig] = part.split(/:|\bas\b/).map((x) => x.trim());
      if (!/^[\w$]+$/.test(local || "")) continue;
      if (mod === "cp" && SHELL_FNS.has(orig)) b.shellFn.add(local);
      if (mod === "cp" && SPAWN_FNS.has(orig)) b.spawnFn.add(local);
      if (mod === "shelljs" && orig === "exec") b.shellFn.add(local);
      if (mod === "execa" && /^execa(?:Sync)?$/.test(orig)) b.spawnFn.add(local);
    }
  };
  const lists = braceLists(src, code);
  // The brace list whose "{" ends the match m, or null.
  const listEnding = (m) => lists.get(m.index + m[0].length - 1) || null;
  for (const [mod, re] of [["cp", CP_MOD], ["shelljs", SHELLJS_MOD], ["execa", EXECA_MOD], ["xspawn", XSPAWN_MOD]]) {
    const objects = mod === "cp" ? b.cpObj : mod === "shelljs" ? b.shellObj : b.spawnFn;
    each(rx(String.raw`(?<![\w$.])([\w$]+)\s*=\s*${req(re)}\s*(?=[;,\n)]|$)`), (m) => objects.add(m[1]));
    each(rx(String.raw`\bimport\s+\*\s+as\s+([\w$]+)\s+from\s+(?:${re})`), (m) => objects.add(m[1]));
    each(rx(String.raw`\bimport\s+([\w$]+)\s+from\s*(?:${re})`), (m) => objects.add(m[1]));
    // import cp, { exec as run } from "child_process": the list read whole.
    each(rx(String.raw`\bimport\s+([\w$]+)\s*,\s*\{`), (m) => {
      const l = listEnding(m);
      if (l && matchAt(String.raw`\s*from\s*(?:${re})`, src, l.after)) { objects.add(m[1]); bindDestructured(lists.list(l), mod); }
    });
    each(rx(String.raw`\bimport\s+([\w$]+)\s*=\s*require\s*\(\s*(?:${re})\s*\)`), (m) => objects.add(m[1]));
    each(rx(String.raw`\bimport\s*\{`), (m) => {
      const l = listEnding(m);
      if (l && matchAt(String.raw`\s*from\s*(?:${re})`, src, l.after)) bindDestructured(lists.list(l), mod);
    });
    // const { exec: run } = require("child_process")
    for (const l of lists.values()) if (live(l.open) && matchAt(String.raw`\s*=\s*${req(re)}`, src, l.after)) bindDestructured(lists.list(l), mod);
  }
  // execa and cross-spawn export a spawn-like default; shelljs and child_process do not.
  // Destructuring from a bound module object, and members taken off it.
  const size = () => b.cpObj.size + b.shellFn.size + b.spawnFn.size + b.shellObj.size;
  for (let round = 0, before = -1; round < 3 && size() !== before; round++) {
    before = size();
    // Names bound so far are looked up in a Set after one fixed pattern: a
    // pattern with the names spelled out as an alternation tried every name at
    // every position (Vercel Security Review, 2.3.2).
    const objs = new Set(b.cpObj);
    const shells = new Set(b.shellObj);
    if (objs.size) {
      for (const l of lists.values()) {
        const m = live(l.open) && matchAt(String.raw`\s*=\s*([\w$]+)\s*[;\n]`, src, l.after);
        if (m && objs.has(m[1])) bindDestructured(lists.list(l), "cp");
      }
      each(rx(String.raw`(?<![\w$.])([\w$]+)\s*=\s*([\w$]+)(?:\.default)?\.([\w$]+)\b`), (m) => {
        if (!objs.has(m[2])) return;
        if (SHELL_FNS.has(m[3])) b.shellFn.add(m[1]); else if (SPAWN_FNS.has(m[3])) b.spawnFn.add(m[1]);
      });
    }
    each(rx(String.raw`(?<![\w$.])([\w$]+)\s*=\s*${req(CP_MOD)}(?:\s*\??\.\s*([\w$]+)\b|\s*(?:\?\.\s*)?\[\s*['"\x60]([\w$]+)['"\x60]\s*\])`), (m) => {
      const fn = m[2] ?? m[3];
      if (SHELL_FNS.has(fn)) b.shellFn.add(m[1]); else if (SPAWN_FNS.has(fn)) b.spawnFn.add(m[1]);
    });
    if (shells.size) each(rx(String.raw`(?<![\w$.])([\w$]+)\s*=\s*([\w$]+)\.exec\b`), (m) => { if (shells.has(m[2])) b.shellFn.add(m[1]); });
    // const run = promisify(exec) / util.promisify(cp.exec) / promisify(require('child_process').exec)
    // A reference to a shell function: a bound name, `cp.exec` /
    // `cp.default.exec` on a bound module object, or require("child_process").exec.
    const fnRef = (v) => b.shellFn.has(v) || REQUIRED_EXEC.test(v) || memberOf(v, objs, SHELL_FNS, true);
    // const run = promisify(exec) / util.promisify(cp.exec) / promisify(require('child_process').exec)
    // The wrapper may be a name (promisify, util.promisify) or a required module's
    // member: require("util").promisify(require("child_process").exec).
    each(rx(String.raw`(?<![\w$.])([\w$]+)\s*=\s*(?:[\w$.]+|require\s*\(\s*['"][\w./:@-]+['"]\s*\)(?:\.[\w$]+)+)\(\s*(${req(CP_MOD)}${MEMBER("exec|execSync")}|[\w$.]+)\s*[,)]`), (m) => { if (fnRef(m[2])) b.shellFn.add(m[1]); });
    // An object holding a shell function: const tools = { run: require("child_process").exec }
    // binds `tools.run` (and { exec } shorthand binds `tools.exec`). One check
    // per property, no pattern built for it.
    each(rx(String.raw`(?<![\w$.])([\w$]+)\s*=\s*\{`), (m) => {
      const l = listEnding(m);
      if (!l) return;
      for (const part of lists.top(l).split(",")) {
        const colon = part.indexOf(":");
        const key = (colon === -1 ? part : part.slice(0, colon)).trim();
        const value = colon === -1 ? key : part.slice(colon + 1).trim();
        if (!/^[\w$]+$/.test(key)) continue;
        if (fnRef(value)) b.shellFn.add(`${m[1]}.${key}`);
      }
    });
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

/**
 * Command sinks in this file: { re, call, kind: "shell" | "spawn", accept }.
 * Each pattern is fixed: a call by a name (`run(`, `tools.run(`, `cp.exec(`)
 * is matched as any dotted name before "(" (the "(" itself is not taken, so a
 * `(0, cp.exec)(` right after it is still seen), and `accept` looks the name
 * up in this file's bindings. The names spelled out as an alternation tried
 * every name at every position (Vercel Security Review, 2.3.2).
 */
const SHELL_METHODS = new Set(["exec", "execSync"]);
const SPAWN_METHODS = new Set(["spawn", "spawnSync", "execFile", "execFileSync"]);
const SHELLJS_METHODS = new Set(["exec"]);
const CALLED = String.raw`(?<![\w.$])([\w$][\w$.]*)\s*(?=\()`;
function commandSinks(src, code) {
  if (!/child_process|shelljs|execa|cross-spawn/.test(src)) return [];
  const b = commandBindings(src, code);
  const cpObjs = new Set(["child_process", "childProcess", "cp", ...b.cpObj]);
  const shellNames = new Set([...SHELL_FNS, ...b.shellFn]);
  const spawnNames = new Set([...SPAWN_FNS, ...b.spawnFn]);
  // m[1]: the object in `(0, obj.method)(`; m[2]: a called name. Neither: a
  // fixed form (require(...).exec(, a wrapped require), always a sink.
  const accept = (names, methods) => (m) =>
    m[1] !== undefined ? cpObjs.has(m[1]) : m[2] !== undefined ? names.has(m[2]) || memberOf(m[2], cpObjs, methods) : true;
  const out = [
    { call: "exec", kind: "shell", accept: accept(shellNames, SHELL_METHODS), re: rx(String.raw`(?<![\w.$])[\w$.]+\(\s*${req(CP_MOD)}${MEMBER("exec|execSync")}\s*\)\s*\(|${req(CP_MOD)}${MEMBER("exec|execSync")}\s*(?:\?\.\s*)?\(|\(\s*0\s*,\s*([\w$]+)(?:\.default)?\.(?:exec|execSync)\s*\)\s*\(|${CALLED}`) },
  ];
  if (b.shellObj.size) {
    const shellObjs = new Set(b.shellObj);
    out.push({ call: "shelljs exec", kind: "shell", accept: (m) => m[1] === undefined || memberOf(m[1], shellObjs, SHELLJS_METHODS), re: rx(String.raw`${req(SHELLJS_MOD)}${MEMBER("exec")}\s*(?:\?\.\s*)?\(|${CALLED}`) });
  }
  out.push({ call: "spawn with a shell", kind: "spawn", accept: accept(spawnNames, SPAWN_METHODS), re: rx(String.raw`\(\s*0\s*,\s*([\w$]+)(?:\.default)?\.(?:spawn|spawnSync|execFile|execFileSync)\s*\)\s*\(|${CALLED}`) });
  return out;
}

/** `const opts = { shell: true }`: option objects declared in this file, by name. */
function shellOptionObjects(src, code) {
  const out = new Map();
  const lists = braceLists(src, code);
  for (const m of src.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*\{/g)) {
    const l = lists.get(m.index + m[0].length - 1);
    // Top-level properties only (linear); a spread object literal `...{ shell: true }` is read whole.
    if (l) { const t = lists.top(l); out.set(m[1], SHELL_ON.test(t) || (t.includes("...{}") && SHELL_ON.test(lists.list(l)))); }
  }
  return out;
}

/**
 * The arguments of the call whose "(" is at `open`, split at top-level commas
 * (bounded). `pairOf` is bracketPairs(code): looking for the ")" anew for each
 * call read up to 2,000 characters per call (a file of unclosed `eval(x`
 * lines read 2,000 characters a line).
 */
function callArgs(code, src, open, pairOf = (o, limit) => matchBracket(code, o, limit)) {
  const close = pairOf(open, 2000);
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
  const lexed = lexJs(source);
  // Minified code is still scanned: a "minified" skip hid `exec(req.body.code)`
  // in a small file with one long string literal (Red Team E23, 2.3.2). The read
  // cap bounds the cost. onMinified only lets the coverage ledger note it.
  if (minified(lexed.plain)) opts.onMinified?.();
  return sinksIn(lexed, opts);
}

/** The sinks in lexed JavaScript (lexJs output, or a line-aligned slice of it). */
function sinksIn({ code, plain: src, expr }, opts = {}) {
  const names = taintedNames(src, code);
  const taints = (text) => SOURCE.test(text) || mentions(text, names);
  const live = (m) => code[m.index] === src[m.index];
  // Line starts once, then a binary search per hit: re-splitting the text for
  // each hit was quadratic in the hits (28,000 evals in 492 KB took 4.6 s).
  const lineOf = lineIndex(src);
  let pairs = null;
  const pairOf = (o, limit) => (pairs ||= bracketPairs(code))(o, limit);
  const hits = [];
  // compact (scanCodeSinks): one finding per file and pattern is all it reports,
  // so per pattern keep the first FIRST_HITS hits (the lines the finding lists)
  // and the first hit of each kind that decides it (tainted, a library
  // parameter): the same finding, without one object per call (a 16 MiB file of
  // eval(x) lines held 2 million and peaked at 759 MB). Never only "the first N".
  const perPattern = opts.compact ? new Map() : null;
  const keep = (h) => {
    if (!perPattern) { hits.push(h); return; }
    const st = perPattern.get(h.pattern) || { n: 0, tainted: false, parameter: false };
    perPattern.set(h.pattern, st);
    const decides = (h.tainted && !st.tainted) || (h.library?.kind === "parameter" && !st.parameter);
    if (st.n < FIRST_HITS || decides) hits.push(h);
    st.n++;
    if (h.tainted) st.tainted = true;
    if (h.library?.kind === "parameter") st.parameter = true;
  };

  for (const sink of EVAL_SINKS) {
    for (const m of src.matchAll(sink.re)) {
      if (!live(m)) continue;
      const open = m.index + m[0].length - 1;
      const args = callArgs(code, src, open, pairOf);
      const all = args.join(",");
      const tainted = taints(all);
      const dynamic = sink.args === "all" ? args.some((a) => !LITERAL_ARG.test(a)) : sink.args === "first" ? !LITERAL_ARG.test(args[0] ?? "") : false;
      if (!tainted && !dynamic) continue;
      keep({ pattern: "eval", call: sink.call, line: lineOf(m.index), tainted, confidence: tainted ? "likely" : "potential" });
    }
  }

  let lib = null;
  // Every return goes through here: a spent brace budget or library budget makes
  // the run incomplete, also for a file with only eval or vm sinks and no shell
  // module, whose taint analysis was cut short (checklist row 19, Vercel, PR 281).
  const finish = () => {
    if (braceLists(src, code).over) opts.onIncomplete?.("object and destructuring lists took more than the file's work budget to read, so the rest was not checked");
    if (lib?.incomplete) opts.onIncomplete?.(`library mode read ${LIBRARY_FACTOR} times the file's length of function bodies and stopped (nested exported functions), so the rest was not checked`);
    return hits;
  };
  const sinks = commandSinks(src, code);
  if (!sinks.length) return finish();
  const optionObjects = shellOptionObjects(src, code);
  const libraryFns = () => (lib ||= withContaining(librarySources(code, expr, LIBRARY_BUDGET(code.length))));
  const seen = new Set();
  for (const sink of sinks) {
    for (const m of src.matchAll(sink.re)) {
      if (!sink.accept(m) || !live(m) || seen.has(m.index)) continue;
      // A called name stops before its "(" (see commandSinks).
      const open = m.index + m[0].length - (src[m.index + m[0].length - 1] === "(" ? 1 : 0);
      if (code[open] !== "(") continue;
      const args = callArgs(code, src, open, pairOf);
      // The command text with string contents blanked (`${...}` kept), for the parameter check.
      const exprArgs = callArgs(code, expr, open, pairOf);
      let command = exprArgs.slice(0, 1);
      if (sink.kind === "spawn") {
        const how = spawnRunsShell(args, optionObjects);
        if (!how) continue;
        command = how === "sh-c" ? exprArgs.slice(1, 2) : exprArgs.slice(0, 2);
      }
      seen.add(m.index);
      const line = lineOf(m.index);
      if (taints(args.join(","))) {
        keep({ pattern: "command-injection", call: sink.call, line, tainted: true, confidence: "likely" });
        continue;
      }
      if (!opts.library) continue;
      const text = command.join(",");
      for (const fn of libraryFns().containing(m.index)) {
        if (!fn.uses(text)) continue;
        const bare = /^\s*([\w$]+)(?:\s*\.\s*[\w$]+)*\s*$/.exec(command[0] || "");
        const runsArgument = Boolean(bare && fn.params.has(bare[1]));
        keep({
          pattern: "command-injection", call: sink.call, line, tainted: false, confidence: "potential",
          library: { function: fn.name, kind: runsArgument ? "runs-argument" : "parameter", ...(fn.via ? { via: fn.via } : {}) },
        });
        break;
      }
    }
  }
  return finish();
}

// Library mode reads each exported function's body (and a helper's); nested
// ones read the same text again per level. A file may make it read at most
// this many times its own length, plus a floor for small files.
const LIBRARY_FACTOR = 16;
const LIBRARY_BUDGET = (len) => LIBRARY_FACTOR * len + 4 * 1024 * 1024;

/**
 * `fns` with `containing(i)`: the ones whose body holds index i, in list
 * order. Function bodies nest, so the bodies sorted by start form a forest;
 * the ones holding i are ancestors of the last body that starts at or before
 * i. Checking every function for every sink was functions x sinks.
 */
function withContaining(fns) {
  const order = fns.map((f, i) => ({ f, i })).sort((a, b) => a.f.bodyStart - b.f.bodyStart || b.f.bodyEnd - a.f.bodyEnd || a.i - b.i);
  const parent = [];
  const stack = [];
  for (let k = 0; k < order.length; k++) {
    while (stack.length && order[stack.at(-1)].f.bodyEnd < order[k].f.bodyStart) stack.pop();
    parent.push(stack.length ? stack.at(-1) : -1);
    stack.push(k);
  }
  fns.containing = (i) => {
    let lo = 0, hi = order.length - 1, k = -1;
    while (lo <= hi) { const mid = (lo + hi) >> 1; if (order[mid].f.bodyStart <= i) { k = mid; lo = mid + 1; } else hi = mid - 1; }
    const out = [];
    for (; k !== -1; k = parent[k]) if (order[k].f.bodyEnd >= i) out.push(order[k]);
    return out.sort((a, b) => a.i - b.i).map((x) => x.f);
  };
  return fns;
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
    const sinkOpts = {
      library: Boolean(library) && !LIBRARY_SKIP.test(rel),
      onMinified: () => opts.minified?.push(rel),
      // Read, but not checked to the end: named, and the run is incomplete.
      onIncomplete: (reason) => opts.refused?.push({ path: file, reason, message: `${rel} was not fully checked: ${reason}`, partial: true }),
    };
    let hits;
    // A read error, or a file over READ_MAX_BYTES, is never silent: the file is
    // named and the run is incomplete.
    try {
      hits = findSinks(readRepoFile(file, { maxBytes: READ_MAX_BYTES, root: resolve(repoPath) }), { ...sinkOpts, compact: true });
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
