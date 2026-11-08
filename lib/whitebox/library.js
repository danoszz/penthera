/**
 * Library mode for the code-sink scan (ADR 0001, decision 3).
 *
 * In an app, untrusted data arrives in a request. In a library, it arrives as
 * an argument: whoever calls an exported function decides what its parameters
 * hold. Library mode treats the parameters of exported functions as sources
 * and reports a flow from one into a shell command, inside the same function
 * (closures and callbacks in it included), at `potential` confidence. A
 * function whose whole job is to run its argument is reported too, with the
 * note that callers must not pass untrusted input.
 *
 * Exported means reachable from the package's public surface in this file:
 *   module.exports = fn | { a, b: fn, c() {} } | class {...} | (function () { return {...} })()
 *   exports.x = fn, module.exports.x = fn, Object.assign(exports, {...})
 *   X.prototype.m = fn, var P = X.prototype; P.m = fn, X.prototype = { m: fn },
 *   X.m = fn and this.m = fn inside X, for an exported X
 *   class methods (the constructor included) of an exported class
 *   object properties of an exported object, `cond ? arrow : other` included
 *   ESM: export function, export const, export default, export { a, b as c }
 *   objects and functions returned by an exported function (factories)
 *
 * The analysis is lexical, on masked source (lib/whitebox/js-lex.js): no
 * parse tree, no call graph, no type information. One helper step is
 * followed: a parameter passed to a named function in the same file makes
 * that function's parameter a source inside it (librarySources). The
 * helper's own calls are not followed. A field set from a parameter on
 * `this` is followed into the other methods of its class (followFields).
 */
import { existsSync } from "node:fs";
import { asName, mentions } from "../linear-text.js";
import { join } from "node:path";
import { matchBracket, splitTopLevel, bracketPairs } from "./js-lex.js";
import { readRepoFile, isRefused } from "../fs-safe.js";

// A dependency on one of these means the package is an app that serves
// requests (or renders pages), not a library: request taint applies instead.
const APP_FRAMEWORKS = new Set([
  "express", "koa", "fastify", "@hapi/hapi", "hapi", "restify", "hono", "polka",
  "next", "nuxt", "@nestjs/core", "sails", "loopback", "@loopback/core",
  "@remix-run/node", "@remix-run/serve", "@sveltejs/kit", "astro", "@adonisjs/core",
  "meteor-node-stubs", "electron", "strapi", "@strapi/strapi", "@feathersjs/feathers",
  "react-scripts", "vite",
]);

/** Paths that a package.json `main`, `module`, `exports` or `bin` names. */
function entryPaths(pkg) {
  const out = [];
  const add = (v) => {
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) v.forEach(add);
    else if (v && typeof v === "object") Object.values(v).forEach(add);
  };
  add(pkg.main); add(pkg.module); add(pkg.exports); add(pkg.bin);
  return out;
}

/**
 * Decide whether to scan a repository as a library.
 * @param {string} repoPath
 * @param {boolean|undefined} force - true (--library), false (--no-library), undefined (decide from package.json)
 * @returns {{ enabled: boolean, reason: string, readDirs: string[] }}
 *   readDirs: build-output folders (dist/, build/) that package.json points into, read in library mode
 */
export function detectLibrary(repoPath, force) {
  let pkg = null;
  let refused = null;
  const pj = join(repoPath, "package.json");
  if (existsSync(pj)) {
    // A package.json linked to /dev/zero or made a FIFO would hang the read.
    try { pkg = JSON.parse(readRepoFile(pj, { root: repoPath, label: "package.json", maxBytes: 5 * 1024 * 1024 })); } catch (e) { pkg = null; if (isRefused(e)) refused = e; }
  }
  const readDirs = [];
  if (pkg && typeof pkg === "object") {
    for (const p of entryPaths(pkg)) {
      const top = p.replace(/^\.\//, "").split("/")[0];
      if ((top === "dist" || top === "build") && !readDirs.includes(top)) readDirs.push(top);
    }
  }
  if (force === true) return { enabled: true, reason: "--library", readDirs };
  if (force === false) return { enabled: false, reason: "--no-library", readDirs: [] };
  if (refused) return { enabled: false, reason: `${refused.message}; use --library to scan it as one`, readDirs: [], refused };
  if (!pkg || typeof pkg !== "object") return { enabled: false, reason: "no package.json", readDirs: [] };
  if (pkg.private === true) return { enabled: false, reason: "package.json is private", readDirs: [] };
  // Without `main`, Node and npm load index.js: a named package with one is publishable.
  const defaultMain = typeof pkg.name === "string" && ["index.js", "index.cjs", "index.mjs"].some((f) => existsSync(join(repoPath, f)));
  if (!entryPaths(pkg).length && !defaultMain) return { enabled: false, reason: "package.json has no main, exports or bin, and there is no index.js", readDirs: [] };
  const framework = Object.keys(pkg.dependencies || {}).find((d) => APP_FRAMEWORKS.has(d));
  if (framework) return { enabled: false, reason: `depends on the app framework ${framework}`, readDirs: [] };
  return { enabled: true, reason: `package.json is publishable (${entryPaths(pkg).length ? "main, exports or bin" : "index.js"}, not private, no app framework)`, readDirs };
}

// Folders that hold tooling, examples or docs, not the library's code.
export const LIBRARY_SKIP = /(?:^|\/)(?:tools?|tooling|examples?|demos?|docs?|benchmarks?|bench|release|\.github|types)\//;

const KEYWORDS = new Set([
  "if", "for", "while", "switch", "catch", "function", "with", "return", "typeof", "else",
  "do", "try", "new", "delete", "void", "await", "yield", "in", "of", "instanceof", "case",
  "throw", "super", "import", "export", "class", "extends", "var", "let", "const",
]);

/**
 * Split at top-level commas. With `types`, angle brackets count inside a
 * TypeScript type (after a top-level ":"), so `Map<a, b>` stays whole and the
 * `>` of a default `cb = () => {}` does not.
 */
function splitTop(text, types = false) {
  const pieces = [];
  let depth = 0, angle = 0, inType = false, from = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (types && !depth && !angle && c === ":") inType = true;
    else if (types && !depth && !angle && c === "=" && text[i + 1] !== ">") inType = false;
    else if (inType && c === "<") angle++;
    else if (inType && c === ">" && text[i - 1] !== "=" && angle > 0) angle--;
    if (c === "," && depth === 0 && angle === 0) { pieces.push(text.slice(from, i)); from = i + 1; inType = false; }
  }
  pieces.push(text.slice(from));
  return pieces;
}

/** Parameter names in a parameter list (defaults, types, destructuring, rest). */
export function paramNames(text) {
  const names = [];
  for (let p of splitTop(text, true)) {
    p = p.trim().replace(/^(?:(?:public|private|protected|readonly|override)\s+)+/, "").replace(/^\.\.\./, "");
    if (!p) continue;
    if (p[0] === "{" || p[0] === "[") {
      const close = matchBracket(p, 0);
      const inner = close === -1 ? p.slice(1) : p.slice(1, close);
      names.push(...destructuredNames(inner));
      continue;
    }
    const m = /^([A-Za-z_$][\w$]*)/.exec(p);
    if (m && m[1] !== "this") names.push(m[1]);
  }
  return names;
}

// Patterns nested deeper than this are not split further: every name in what
// is left counts as bound (a superset, so taint is never lost), and each level
// reads the text once, so a deeply nested pattern costs at most this many passes.
const MAX_PATTERN_DEPTH = 16;

/** Local names bound by the inside of a `{...}` or `[...]` pattern. */
function destructuredNames(inner, depth = 0) {
  if (depth >= MAX_PATTERN_DEPTH) return inner.match(/[A-Za-z_$][\w$]*/g) || [];
  const out = [];
  for (let p of splitTop(inner)) {
    p = p.trim().replace(/^\.\.\./, "");
    if (!p) continue;
    // `key: local`, `key: { nested }`, `local = default`
    const colon = topLevelIndex(p, ":");
    let target = colon === -1 ? p : p.slice(colon + 1).trim();
    const eq = topLevelIndex(target, "=");
    if (eq !== -1) target = target.slice(0, eq).trim();
    if (target[0] === "{" || target[0] === "[") {
      const close = matchBracket(target, 0);
      out.push(...destructuredNames(close === -1 ? target.slice(1) : target.slice(1, close), depth + 1));
    } else if (/^[A-Za-z_$][\w$]*$/.test(target)) out.push(target);
  }
  return out;
}

function topLevelIndex(s, ch) {
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) depth--;
    else if (c === ch && depth === 0 && !(ch === "=" && (s[i + 1] === ">" || s[i + 1] === "="))) return i;
  }
  return -1;
}

/** Skip whitespace backwards from `i` (inclusive); returns the index of the last non-space char, or -1. */
function backSkip(code, i) {
  while (i >= 0 && /\s/.test(code[i])) i--;
  return i;
}

/** The identifier ending at index `end` (inclusive), or "". */
function wordBefore(code, end) {
  let s = end;
  while (s >= 0 && /[\w$#]/.test(code[s])) s--;
  return code.slice(s + 1, end + 1);
}

// A generic parameter list can nest (`<T extends Array<string>>`), hold
// parentheses (`<T extends (x: string) => void>`) and be long. It is skipped
// by a counter: "<" and ">" by depth, "=>" is not a ">", brackets by their pairs.
const GENERIC_MAX = 4000;
/** Index just past the ">" that closes the "<" at `i`; -1 if not a generic list, -2 if longer than GENERIC_MAX. */
function skipGenerics(code, i, pairOf, spend = () => true) {
  let depth = 0;
  for (let j = i; j < code.length; j++) {
    if (j - i > GENERIC_MAX || !spend()) return -2;
    const c = code[j];
    if (c === "<") depth++;
    else if (c === ">" && code[j - 1] !== "=") { if (--depth === 0) return j + 1; }
    else if (c === "(" || c === "[" || c === "{") { const k = pairOf(j); if (k === -1) return -1; j = k; }
    else if (c === ";" || c === ")" || c === "]" || c === "}") return -1;
  }
  return -1;
}
/** Index of the "<" that opens the generic list closed by the ">" at `end` (not part of "=>"); -1 if none, -2 if longer than GENERIC_MAX or out of budget. */
function genericStart(code, end, spend = () => true) {
  let depth = 0;
  for (let j = end; j >= 0; j--) {
    if (end - j > GENERIC_MAX || !spend()) return -2;
    const c = code[j];
    if (c === ">" && code[j - 1] !== "=") depth++;
    else if (c === "<") { if (--depth === 0) return j; }
    else if (c === ";" || c === "{" || c === "}") return -1;
  }
  return -1;
}

/** The member expression (a.b.c, a.b[...]) ending at `end` (inclusive) and where it starts. */
function lhsBefore(code, end) {
  let s = end;
  while (s >= 0) {
    const c = code[s];
    if (/[\w$.]/.test(c)) { s--; continue; }
    if (c === "]") {
      let depth = 0; let k = s;
      for (; k >= 0; k--) { if (code[k] === "]") depth++; else if (code[k] === "[" && --depth === 0) break; }
      if (k < 0) break;
      s = k - 1; continue;
    }
    break;
  }
  return { text: code.slice(s + 1, end + 1).replace(/\s+/g, ""), start: s + 1 };
}

/**
 * Every function-like construct in masked code, with its parameters and body range.
 * @returns {{ start: number, paramsText: string, bodyStart: number, bodyEnd: number, name: string, kind: string }[]}
 */
export function functionRanges(code) {
  const pairOf = bracketPairs(code);
  const fns = [];
  const seen = new Set();
  // Return types are read with no length cap (a 400-character stop dropped a
  // function with a long type, and its parameters were never followed:
  // checklist row 1). The reading is bounded by a work budget for the file;
  // past it the result says `incomplete` and the run exits 2.
  let work = 0;
  const budget = 8 * code.length + (1 << 20);
  const spend = () => ++work <= budget;
  const returnType = (i, arrow = false) => { const r = skipReturnType(code, i, pairOf, spend, arrow); if (r === -1) fns.incomplete = true; return r; };
  // A return annotation the reader can't resolve keeps the function (checklist
  // row 19: keep the candidate, never drop it): the body is the next top-level
  // "{" before a ";", past a type literal right before it, within GENERIC_MAX
  // and the budget. No body (an overload, a `declare` line) still ends at ";".
  const bodyAfter = (close, b) => {
    if (code[b] === "{" || b === -1) return b;
    let k = close + 1;
    while (k < code.length && /\s/.test(code[k])) k++;
    if (code[k] !== ":") return b;
    // From the annotation's start, not from where the reader stopped: the first
    // body candidate is never skipped (checklist row 18).
    for (let j = k + 1; j < code.length && j - close <= GENERIC_MAX; j++) {
      if (!spend()) { fns.incomplete = true; return -1; }
      const c = code[j];
      if (c === ";") return b;
      if (c === "(" || c === "[") { const q = pairOf(j); if (q === -1) return b; j = q; continue; }
      if (c === "{") {
        const q = pairOf(j);
        if (q === -1) return b;
        let n = q + 1;
        while (n < code.length && /\s/.test(code[n])) n++;
        if (code[n] === "{") { j = n - 1; continue; } // `: { a: T } { body }`: the literal was the type
        return j;
      }
    }
    return b;
  };
  // "(" of each ")", and each arrow function's expression end, both from one pass.
  const openOf = new Int32Array(code.length).fill(-1);
  for (let i = code.indexOf("("); i !== -1; i = code.indexOf("(", i + 1)) { const c = pairOf(i); if (c !== -1) openOf[c] = i; }
  const exprEndOf = exprEnds(code, pairOf);
  // `(a: T): R =>`: arrows with a return type, found forward from their ")".
  const typedArrows = new Map();
  for (const m of code.matchAll(/\)(?=\s*:)/g)) {
    if (openOf[m.index] === -1) continue;
    const r = returnType(m.index + 1, true);
    if (r !== -1 && code[r] === "=" && code[r + 1] === ">") typedArrows.set(r, openOf[m.index]);
  }
  // function name? (params) { body }
  for (const m of code.matchAll(/\bfunction\b\s*(?:\*\s*)?(?:([\w$]+)\s*)?(?=[<(])/g)) {
    let open = m.index + m[0].length;
    if (code[open] === "<") {
      const g = skipGenerics(code, open, pairOf, spend);
      // A generic list too long to skip after `function name` is not dropped silently.
      if (g === -2) { fns.incomplete = true; continue; }
      if (g === -1) continue;
      open = g;
      while (open < code.length && /\s/.test(code[open])) open++;
      if (code[open] !== "(") continue;
    }
    const close = pairOf(open);
    if (close === -1) continue;
    const b = bodyAfter(close, returnType(close + 1));
    if (code[b] !== "{") continue;
    const end = pairOf(b);
    if (end === -1) continue;
    seen.add(b);
    fns.push({ start: m.index, paramsText: code.slice(open + 1, close), bodyStart: b, bodyEnd: end, name: m[1] || "", kind: "function" });
  }
  // (params) => body, x => body
  for (const m of code.matchAll(/=>/g)) {
    const arrow = m.index;
    let p = backSkip(code, arrow - 1);
    let start; let paramsText;
    // `c ? (a) : (cmd) => run(cmd)` reads as a typed arrow `(a): (cmd) =>` too, so
    // both readings are kept: the plain one from the ")" before "=>" never drops
    // the arrow's own parameters (a rewrite runs next to the old reading).
    const plain = p >= 0 && code[p] === ")" ? openOf[p] : -1;
    const readings = [];
    if (typedArrows.has(arrow)) readings.push(typedArrows.get(arrow));
    if (plain >= 0 && !readings.includes(plain)) readings.push(plain);
    if (readings.length > 1) {
      let b2 = arrow + 2;
      while (b2 < code.length && /\s/.test(code[b2])) b2++;
      const end2 = code[b2] === "{" ? pairOf(b2) : exprEndOf(b2);
      if (end2 !== -1) fns.push({ start: plain, paramsText: code.slice(plain + 1, p), bodyStart: b2, bodyEnd: end2, name: "", kind: "arrow" });
    }
    if (typedArrows.has(arrow)) {
      start = typedArrows.get(arrow); paramsText = code.slice(start + 1, pairOf(start));
    } else if (p >= 0 && code[p] === ")") {
      // The matching "(", from the pairs (a walk back per arrow re-read nested lists).
      const k = openOf[p];
      if (k < 0) continue;
      start = k; paramsText = code.slice(k + 1, p);
    } else if (p >= 0 && /[\w$]/.test(code[p])) {
      const w = wordBefore(code, p);
      start = p - w.length + 1; paramsText = w;
    } else {
      // Other shapes (a typed arrow is found above, from its ")"): skip.
      continue;
    }
    const before = backSkip(code, start - 1);
    if (wordBefore(code, before) === "async") start = before - 4;
    let b = arrow + 2;
    while (b < code.length && /\s/.test(code[b])) b++;
    if (code[b] === "{") {
      const end = pairOf(b);
      if (end === -1) continue;
      fns.push({ start, paramsText, bodyStart: b, bodyEnd: end, name: "", kind: "arrow" });
    } else {
      fns.push({ start, paramsText, bodyStart: b, bodyEnd: exprEndOf(b), name: "", kind: "arrow" });
    }
  }
  // Methods in classes and object literals: name(params) { body }
  // Horizontal whitespace only after the separator: masked comments leave long
  // runs of spaces and line breaks, and `\s*` there backtracks badly.
  for (const m of code.matchAll(/(^|[{,;}\n])([ \t]*)((?:(?:async|static|get|set|public|private|protected|override|readonly)[ \t]+)*)(?:\*[ \t]*)?(#?[A-Za-z_$][\w$]*)[ \t]*(?=[<(])/g)) {
    const name = m[4];
    if (KEYWORDS.has(name)) continue;
    let open = m.index + m[0].length;
    if (code[open] === "<") {
      const g = skipGenerics(code, open, pairOf, spend);
      if (g === -2) { fns.incomplete = true; continue; } // too long to read: never dropped silently
      if (g < 0) continue; // a comparison, not a generic method
      open = g;
      while (open < code.length && (code[open] === " " || code[open] === "\t")) open++;
      if (code[open] !== "(") continue;
    }
    const close = pairOf(open);
    if (close === -1) continue;
    const b = bodyAfter(close, returnType(close + 1));
    if (code[b] !== "{" || seen.has(b)) continue;
    const end = pairOf(b);
    if (end === -1) continue;
    const start = m.index + m[1].length + m[2].length;
    fns.push({ start, paramsText: code.slice(open + 1, close), bodyStart: b, bodyEnd: end, name, kind: "method" });
  }
  return fns;
}

/**
 * After a parameter list: skip whitespace and a TypeScript return type, up to
 * the body's "{", or (`arrow`) the "=" of an arrow's "=>". Stops at a top-level ";",
 * "=", ",", "?", ":" or "}", or a closing bracket of an outer group. No length
 * cap; `spend()` counts the characters read, and -1 means the file's budget
 * ran out (the caller marks the file incomplete).
 */
// Words after which a "{" opens a type literal, not a body.
const TYPE_WORDS = new Set(["extends", "keyof", "typeof", "readonly", "is", "asserts", "infer", "new", "unique"]);

function skipReturnType(code, i, pairOf, spend, arrow = false) {
  while (i < code.length && /\s/.test(code[i])) i++;
  if (code[i] !== ":") return i;
  let depth = 0;
  // A conditional type, `T extends U ? X : Y`: a top-level `extends` opens one,
  // and its "?" and ":" are part of the type, not the end of it.
  let conds = 0; let asks = 0;
  for (let j = i + 1; j < code.length; j++) {
    if (!spend()) return -1;
    const c = code[j];
    if (depth === 0 && c === "e" && code.startsWith("extends", j) && !/[\w$]/.test(code[j - 1]) && !/[\w$]/.test(code[j + 7] || "")) { conds++; j += 6; continue; }
    if (depth === 0 && c === "?" && conds > asks) { asks++; continue; }
    if (depth === 0 && c === ":" && asks > 0) { asks--; conds--; continue; }
    // A top-level "=>" ends an arrow's return type; after `function f()` or a method it is a function type: `(): () => void {`.
    if (c === "=" && code[j + 1] === ">") { if (depth === 0 && arrow) return j; j++; continue; }
    if (c === "<" || c === "(" || c === "[") depth++;
    else if (c === ">" || c === ")" || c === "]") { if (--depth < 0) return j; }
    else if (c === "{" && depth === 0) {
      // From the annotation's own syntax: after a complete type (a name, ">", "]",
      // ")" or a literal) a "{" is the body, never a type literal, whatever
      // follows it (`): string { … } [1, 2];`, Vercel, PR 281). A type literal
      // comes after ":", "|", "&", "?", ",", "<", "(" or a type keyword.
      let q = j - 1;
      while (q > i && /\s/.test(code[q])) { if (!spend()) return -1; q--; }
      const pc = code[q];
      if (q > i && (/[\w$"'\x60\])]/.test(pc) || (pc === ">" && code[q - 1] !== "="))) {
        if (!/[\w$]/.test(pc) || !TYPE_WORDS.has(wordBefore(code, q))) return j;
      }
      // A type literal `{ ... }` is followed by more type, the body or an arrow; the body is the "{" not followed by a type.
      const close = pairOf(j);
      if (close === -1) return j;
      let k = close + 1;
      while (k < code.length && /\s/.test(code[k])) { if (!spend()) return -1; k++; }
      if (code[k] === "{" || (code[k] === "=" && code[k + 1] === ">")) { j = k - 1; continue; }
      if ("|&[".includes(code[k] || " ")) { j = k - 1; continue; } // more type after the literal
      if (code[k] === ":" && asks > 0) { j = k - 1; continue; } // `A extends B ? { x: 1 } : C`: the conditional goes on
      return j;
    } else if (depth === 0 && (c === ";" || c === "=" || c === "," || c === "?" || c === ":" || c === "}")) return j;
  }
  return code.length;
}

/**
 * End of each arrow function's expression body, as a lookup: the first
 * top-level `,` `;`, closing bracket, or line break that the next line does
 * not continue. One backward pass (a bracket
 * group is skipped by its pair): a forward scan per arrow re-read nested
 * arrows' bodies, quadratic on `a => b => c => …`.
 */
function exprEnds(code, pairOf) {
  const n = code.length;
  const end = new Int32Array(n + 1);
  end[n] = n;
  let nextSolid = n; // the first character after k that is not a space, tab or CR
  for (let k = n - 1; k >= 0; k--) {
    const c = code[k];
    if (c === ")" || c === "]" || c === "}" || c === "," || c === ";") end[k] = k;
    else if (c === "(" || c === "[" || c === "{") { const close = pairOf(k); end[k] = close === -1 ? n : end[close + 1]; }
    // A line break ends it unless the next line goes on with an operator.
    else if (c === "\n") end[k] = /[.?:+\-*/%&|,)]/.test(code[nextSolid] || "") ? end[k + 1] : k;
    else end[k] = end[k + 1];
    if (c !== " " && c !== "\t" && c !== "\r") nextSolid = k;
  }
  return (i) => (i >= n ? n : end[i]);
}


/** Innermost open bracket enclosing each index (an Int32Array; -1 at top level). */
function enclosingBrackets(code) {
  const encl = new Int32Array(code.length);
  const stack = [];
  for (let i = 0; i < code.length; i++) {
    encl[i] = stack.length ? stack[stack.length - 1] : -1;
    const c = code[i];
    if (c === "(" || c === "[" || c === "{") stack.push(i);
    else if (c === ")" || c === "]" || c === "}") stack.pop();
  }
  return encl;
}

const EXPORT_LHS = /^(?:module\.exports|exports)(?:\.[\w$]+|\[[^\]]*\])?$|^module\.exports\.[\w$]+$/;

/**
 * The functions in a file that a caller of the package can reach, with their
 * parameter names.
 * @param {string} code - masked source (lexJs(...).code)
 * @returns {{ start, bodyStart, bodyEnd, params: string[], name: string }[]}
 */
export function exportedFunctions(code, fns = functionRanges(code), spend = () => true) {
  const encl = enclosingBrackets(code);
  const pairOf = bracketPairs(code);
  const exportNames = new Set();
  const exportedObjects = new Set(); // index of "{" of exported object literals and class bodies
  const protoAlias = new Map(); // P -> X for `var P = X.prototype`

  for (const m of code.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*([\w$]+)\.prototype\s*[;\n,]/g)) protoAlias.set(m[1], m[2]);

  // What the file exports by name.
  const addObjectNames = (open) => {
    const close = pairOf(open);
    if (close === -1 || !spend(close - open)) return; // nested literals are re-read: charged to the budget
    // Depth-1 entries `a`, `b: c`, `...d` (methods are handled as members).
    for (const p of splitTop(code.slice(open + 1, close))) {
      const t = p.trim();
      const mm = /^([\w$]+)$/.exec(t) || /^[\w$'"]+\s*:\s*([\w$]+)$/.exec(t) || /^\.\.\.([\w$]+)$/.exec(t);
      if (mm) exportNames.add(mm[1]);
    }
  };
  for (const m of code.matchAll(/(?<![\w$.])(module\.exports(?:\.[\w$]+)?|exports\.[\w$]+)\s*=(?![=>])\s*/g)) {
    let k = m.index + m[0].length;
    // module.exports = exports = X
    const chain = /^(?:module\.exports|exports)(?:\.[\w$]+)?\s*=(?![=>])\s*/.exec(code.slice(k, k + 80));
    if (chain) k += chain[0].length;
    const rest = code.slice(k, k + 200);
    const id = /^([\w$]+)\s*(?:[;\n,)}]|$)/.exec(rest);
    if (id) exportNames.add(id[1]);
    if (code[k] === "{") { exportedObjects.add(k); addObjectNames(k); }
    const cls = /^class\b[^{;]{0,300}\{/.exec(rest);
    if (cls) exportedObjects.add(k + cls[0].length - 1);
    const newId = /^new\s+([\w$]+)\s*\(/.exec(rest);
    if (newId) exportNames.add(newId[1]);
  }
  for (const m of code.matchAll(/\bexport\s+(?:default\s+)?(?:async\s+)?(?:function\s*(?:\*\s*)?|(?:class|const|let|var)\s+)([\w$]+)/g)) exportNames.add(m[1]);
  for (const m of code.matchAll(/\bexport\s+default\s+([\w$]+)\s*[;\n]/g)) exportNames.add(m[1]);
  for (const m of code.matchAll(/\bexport\s*\{([^}]*)\}/g)) {
    for (const part of m[1].split(",")) { const local = asName(part, "first"); if (/^[\w$]+$/.test(local)) exportNames.add(local); }
  }
  for (const m of code.matchAll(/\bexport\s+default\s*\{/g)) { const k = m.index + m[0].length - 1; exportedObjects.add(k); addObjectNames(k); }
  for (const m of code.matchAll(/\bexport\s+(?:default\s+)?class\b[^{;]{0,300}\{/g)) exportedObjects.add(m.index + m[0].length - 1);
  // Object.assign(module.exports, { ... }) / Object.assign(exports, { ... })
  for (const m of code.matchAll(/\bObject\.assign\(\s*(?:module\.)?exports\s*,\s*\{/g)) { const k = m.index + m[0].length - 1; exportedObjects.add(k); addObjectNames(k); }
  // Object.assign(module.exports, api) and `for (k in api) exports[k] = api[k]`: every member of api.
  for (const m of code.matchAll(/\bObject\.assign\(\s*(?:module\.)?exports\s*,\s*([\w$]+)\s*\)/g)) exportNames.add(m[1]);
  for (const m of code.matchAll(/\bfor\s*\(\s*(?:(?:var|let|const)\s+)?([\w$]+)\s+in\s+([\w$]+)\s*\)\s*(?:\{\s*)?(?:module\.)?exports\[\s*\1\s*\]\s*=\s*\2\[\s*\1\s*\]/g)) exportNames.add(m[2]);

  // The "(", "[" or "{" of each closing bracket, for walking back over groups.
  const openOfClose = new Int32Array(code.length).fill(-1);
  for (let i = 0; i < code.length; i++) {
    const c = code[i];
    if (c === "(" || c === "[" || c === "{") { const k = pairOf(i); if (k !== -1) openOfClose[k] = i; }
  }
  // `x = cond ? (a) => … : (b) => …`: from a branch's "?" or ":" back across the
  // ternary (nested ones included) to the "=" or `return` it belongs to, or to
  // the group or list it sits in. Each step is charged to the work budget.
  const ternaryBase = (p0) => {
    let need = code[p0] === ":" ? 1 : 0;
    for (let j = p0 - 1; j >= 0; j--) {
      if (!spend(1)) return p0;
      const c = code[j];
      if (c === ")" || c === "]" || c === "}") { const o = openOfClose[j]; if (o === -1) return p0; j = o; continue; }
      if (c === "?" && code[j + 1] !== "." && code[j + 1] !== "?" && code[j - 1] !== "?") { if (need) need--; continue; }
      if (c === ":") { need++; continue; }
      if (c === "n" && wordBefore(code, j) === "return") return need ? p0 : j;
      // `=>`, `==`, `===`, `!=`, `<=`, `>=` belong to the branches or the condition: only an assignment "=" ends it.
      if (c === "=" && (code[j + 1] === ">" || code[j + 1] === "=" || "=!<>".includes(code[j - 1] || ""))) continue;
      if (c === "=" || c === "(" || c === "[" || c === "{" || c === "," || c === ";") return need ? p0 : j;
    }
    return p0;
  };

  // How each function is bound, read from the text before it.
  const info = fns.map((f) => {
    let s = f.start;
    let p = backSkip(code, s - 1);
    if (wordBefore(code, p) === "async") p = backSkip(code, p - 5);
    // `<T>(x) =>`: the generic list before an arrow's parameters.
    if (p >= 1 && code[p] === ">" && code[p - 1] !== "=") {
      const lt = genericStart(code, p, () => spend(1));
      if (lt === -2) fns.incomplete = true; // too long to read: the file says so
      else if (lt !== -1) p = backSkip(code, lt - 1);
    }
    // A ternary branch: `export const run = flag ? (a) : (cmd) => …`.
    // From ":", only when a "?" was found before it (an object key's ":" comes back unchanged).
    if (code[p] === "?" || code[p] === ":") p = ternaryBase(p);
    // `export default function`, `export function`, `export const x = () =>`
    let lhs = "";
    let assigned = false;
    let returned = false;
    let exportKw = false;
    if (p >= 1 && code[p] === "=" && code[p - 1] !== "=" && code[p - 1] !== "!" && code[p - 1] !== ">" && code[p - 1] !== "<") {
      const q = backSkip(code, p - 1);
      const l = lhsBefore(code, q);
      lhs = l.text; assigned = true;
      const pre = code.slice(Math.max(0, l.start - 40), l.start);
      if (/\bexport\s+(?:const|let|var)\s*$/.test(pre)) exportKw = true;
      // module.exports = exports = function
      const pp = backSkip(code, l.start - 1);
      if (pp >= 0 && code[pp] === "=") { const l2 = lhsBefore(code, backSkip(code, pp - 1)); if (EXPORT_LHS.test(l2.text)) lhs = l2.text; }
    } else if (wordBefore(code, p) === "return") returned = true;
    else if (wordBefore(code, p) === "default" || wordBefore(code, p) === "export") exportKw = true;
    // `export function name` / `export default async function`
    const pre = code.slice(Math.max(0, s - 40), s);
    if (/\bexport\s+(?:default\s+)?(?:async\s+)?$/.test(pre)) exportKw = true;
    // An IIFE, `(function () { ... })()` or `(() => { ... })()`, whose result
    // goes to exports or to a variable: what it returns is the module's API.
    let iife = false;
    let iifeLhs = "";
    if (code[p] === "(") {
      const close = pairOf(p);
      if (close !== -1) {
        const after = code.slice(close + 1, close + 4).replace(/\s/g, "");
        const before = backSkip(code, p - 1);
        if (after.startsWith("(") && before >= 0 && code[before] === "=" && code[before - 1] !== "=") {
          iife = true;
          iifeLhs = lhsBefore(code, backSkip(code, before - 1)).text;
        }
      }
    }
    // `module.exports = function () {...}()` (unparenthesized IIFE)
    if (assigned && /^\s*\(/.test(code.slice(f.bodyEnd + 1, f.bodyEnd + 4)) && f.kind === "function") { iife = true; iifeLhs = lhs; }
    const iifeExported = iife && EXPORT_LHS.test(iifeLhs);
    const varName = assigned && /^[\w$]+$/.test(lhs) ? lhs : iife && /^[\w$]+$/.test(iifeLhs) ? iifeLhs : "";
    // `key: function () {}` in an object literal: the key names it.
    const key = code[p] === ":" ? wordBefore(code, backSkip(code, p - 1)) : "";
    return { f, lhs, assigned, returned, exportKw, iife, iifeExported, owner: encl[f.start], name: varName || f.name || key, names: [f.name, varName].filter(Boolean) };
  });

  // Which object literals and class bodies are which, by the "{" index.
  const classBodies = new Map(); // "{" index -> class name
  for (const m of code.matchAll(/\bclass\s+([\w$]+)?[^{;]{0,300}\{/g)) classBodies.set(m.index + m[0].length - 1, m[1] || "");
  const objectVar = new Map(); // "{" index -> variable name for `const x = {`
  for (const m of code.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*(?::[^=;\n]{0,200})?=\s*\{/g)) objectVar.set(m.index + m[0].length - 1, m[1]);
  for (const m of code.matchAll(/(?<![\w$.])([\w$]+)\s*=\s*\{/g)) if (!objectVar.has(m.index + m[0].length - 1)) objectVar.set(m.index + m[0].length - 1, m[1]);
  const protoObjects = new Map(); // "{" index -> X for `X.prototype = {`
  for (const m of code.matchAll(/(?<![\w$.])([\w$]+)\.prototype\s*=\s*\{/g)) protoObjects.set(m.index + m[0].length - 1, m[1]);
  for (const m of code.matchAll(/\bclass\s+([\w$]+)[^{;]{0,300}\{/g)) objectVar.set(m.index + m[0].length - 1, m[1]);

  const exported = new Set();
  const addedAt = new Map(); // x -> order it was exported in
  // Function bodies nest: sorted by start they form a forest, and the bodies
  // around a position are ancestors of the last body that starts before it.
  // Checking every exported function per position was positions x functions.
  const order = info.slice().sort((a, b) => a.f.bodyStart - b.f.bodyStart || b.f.bodyEnd - a.f.bodyEnd);
  const up = [];
  const stack = [];
  for (let k = 0; k < order.length; k++) {
    while (stack.length && order[stack.at(-1)].f.bodyEnd <= order[k].f.bodyStart) stack.pop();
    up.push(stack.length ? stack.at(-1) : -1);
    stack.push(k);
  }
  // The exported bodies strictly around `pos`, innermost first. Each step is
  // charged to the work budget (deep nesting); past it, none.
  const around = (pos, fn) => {
    let lo = 0, hi = order.length - 1, k = -1;
    while (lo <= hi) { const mid = (lo + hi) >> 1; if (order[mid].f.bodyStart < pos) { k = mid; lo = mid + 1; } else hi = mid - 1; }
    for (; k !== -1; k = up[k]) {
      if (!spend(1)) return;
      const x = order[k];
      if (x.f.bodyEnd > pos && exported.has(x) && fn(x) === false) return;
    }
  };
  // The first one exported (as the Set kept them), as the loop over the Set returned.
  const insideExported = (pos) => {
    let best = null;
    around(pos, (x) => { if (!best || addedAt.get(x) < addedAt.get(best)) best = x; });
    return best;
  };
  // `return new Name(` and an IIFE's `return Name;`, found once for the file.
  const returnsNew = [...code.matchAll(/\breturn\s+new\s+([\w$]+)\s*\(/g)];
  const returnsName = [...code.matchAll(/\breturn\s+([\w$]+)\s*[;\n}]/g)];

  for (let round = 0; round < 6; round++) {
    const before = exported.size;
    // Objects returned from exported functions are exported (factories, IIFEs).
    for (const m of code.matchAll(/\breturn\s*\{/g)) {
      const k = m.index + m[0].length - 1;
      if (insideExported(k)) { if (!exportedObjects.has(k)) { exportedObjects.add(k); addObjectNames(k); } }
    }
    // An instance an exported function returns: `return new Name(...)` exports Name's methods.
    for (const m of returnsNew) {
      if (exportNames.has(m[1])) continue;
      let yes = false;
      around(m.index, () => { yes = true; return false; });
      if (yes) exportNames.add(m[1]);
    }
    // `return Name;` in an exported IIFE exports Name (the whole match inside its body).
    for (const m of returnsName) {
      if (exportNames.has(m[1])) continue;
      let yes = false;
      around(m.index, (x) => { if (x.iife && m.index + m[0].length <= x.f.bodyEnd) { yes = true; return false; } });
      if (yes) exportNames.add(m[1]);
    }
    for (const [k, name] of objectVar) if (exportNames.has(name)) exportedObjects.add(k);
    for (const [k, name] of protoObjects) if (exportNames.has(name)) exportedObjects.add(k);
    for (const [k, name] of classBodies) if (name && exportNames.has(name)) exportedObjects.add(k);

    for (const x of info) {
      if (exported.has(x)) continue;
      const { lhs } = x;
      let yes = false;
      if (x.exportKw || x.iifeExported) yes = true;
      else if (x.assigned && EXPORT_LHS.test(lhs)) yes = true;
      else if (x.names.some((nm) => exportNames.has(nm))) yes = true;
      else if (x.assigned) {
        const parts = lhs.split(".");
        // X.prototype.m, P.m (P = X.prototype), X.m, this.m inside an exported X
        if (parts.length >= 3 && parts[1] === "prototype" && exportNames.has(parts[0])) yes = true;
        else if (parts.length === 2 && protoAlias.has(parts[0]) && exportNames.has(protoAlias.get(parts[0]))) yes = true;
        else if (parts.length === 2 && parts[0] !== "this" && exportNames.has(parts[0])) yes = true;
        else if (parts.length === 2 && parts[0] === "this") { const outer = insideExported(x.f.start); if (outer && outer.f.kind !== "arrow") yes = true; }
      }
      if (!yes && x.returned && insideExported(x.f.start)) yes = true;
      // A direct member of an exported object literal or class body.
      // `a: cond ? (x) => ... : ...` has the object as its owner too.
      if (!yes && x.owner !== -1 && exportedObjects.has(x.owner)) yes = true;
      if (yes) { exported.add(x); addedAt.set(x, addedAt.size); }
    }
    if (exported.size === before) break;
  }
  // Which class or object each function belongs to, for values kept on `this`:
  // a class body, `X.prototype = {...}`, `X.prototype.m =`, `P.m =` (P = X.prototype),
  // `this.m =` inside X, the constructor X itself, or an exported object literal.
  const classOf = (x, depth = 0) => {
    if (x.owner !== -1 && classBodies.has(x.owner)) return classBodies.get(x.owner) || `#${x.owner}`;
    if (x.owner !== -1 && protoObjects.has(x.owner)) return protoObjects.get(x.owner);
    if (x.assigned) {
      const parts = x.lhs.split(".");
      if (parts.length >= 3 && parts[1] === "prototype") return parts[0];
      if (parts.length === 2 && protoAlias.has(parts[0])) return protoAlias.get(parts[0]);
      if (parts.length === 2 && parts[0] === "this") { const outer = insideExported(x.f.start); return outer && depth < 3 ? classOf(outer, depth + 1) : ""; }
    }
    if (x.owner !== -1 && exportedObjects.has(x.owner) && x.f.kind !== "arrow") return `#${x.owner}`;
    return x.f.kind === "function" && !x.iife ? x.names.find((n) => !EXPORT_LHS.test(n)) || "" : "";
  };
  // Parameter lists can overlap (functions nested in defaults), so each one is
  // charged to the file's budget before it is split; past it, no more are
  // split and the caller's result says incomplete (Vercel, PR 281).
  let paramsOver = false;
  const paramsOf = (x) => {
    if (x.iife || paramsOver) return [];
    if (!spend(x.f.paramsText.length)) { paramsOver = true; return []; }
    return paramNames(x.f.paramsText);
  };
  return [...exported].map((x) => ({ start: x.f.start, bodyStart: x.f.bodyStart, bodyEnd: x.f.bodyEnd, params: paramsOf(x), name: x.name || x.lhs || "(anonymous)", cls: classOf(x) }));
}

/**
 * A test for "this text uses one of these names" (not as a property name
 * after a dot), for the names as they are now. One pass over the text's
 * identifiers with a Set lookup: an alternation of the names tried each name
 * at each position (Vercel Security Review, 2.3.2).
 */
export function usesNames(names) {
  if (!names.size) return () => false;
  const set = new Set(names);
  return (text) => mentions(text, set);
}

// `obj.member` at an identifier boundary, then an optional "(".
const MEMBER = /(?<![\w$.])([A-Za-z_$][\w$]*)\.([\w$]+)(?![\w$])(\s*\()?/g;
/**
 * A test for `who.field` (a field in `fields`) or `who.getter(` (a getter in
 * `getters`), with `who` one of the names for `this`. Same as the alternation
 * of all three it replaces, in one pass with Set lookups.
 */
function memberRef(who, fields, getters = new Set()) {
  return {
    test(text) {
      const re = new RegExp(MEMBER);
      for (let m = re.exec(text); m; m = re.exec(text)) {
        if (who.has(m[1]) && (fields.has(m[2]) || (m[3] !== undefined && getters.has(m[2])))) return true;
      }
      return false;
    },
  };
}

/**
 * End of the expression that starts at `i` in masked code: a top-level `;` or
 * `,`, a bracket that closes an outer one, or a line break that is not inside
 * a continued expression (the line ends with an operator or the next one
 * starts with one). `stmtEnds(code)` gives a lookup i -> end for the whole
 * text, built in one backward pass (a bracket group is skipped by its pair).
 * It replaces a forward scan per call that stopped at 2,000 characters, so a
 * value padded past that was cut and its taint lost without a word (Vercel,
 * checklist row 1); a scan per call without the stop was quadratic.
 */
function stmtEnds(code) {
  const n = code.length;
  const closeOf = bracketPairs(code);
  const isWs = (c) => /\s/.test(c);
  const prevSolid = new Int32Array(n + 1); // the last non-space index before k, or -1
  for (let k = 0, last = -1; k <= n; k++) { prevSolid[k] = last; if (k < n && !isWs(code[k])) last = k; }
  const nextSolid = new Int32Array(n + 1); // the first non-space index at or after k
  nextSolid[n] = n;
  for (let k = n - 1; k >= 0; k--) nextSolid[k] = isWs(code[k]) ? nextSolid[k + 1] : k;
  const end = new Int32Array(n + 1);
  end[n] = n;
  for (let k = n - 1; k >= 0; k--) {
    const c = code[k];
    if (c === ")" || c === "]" || c === "}" || c === ";" || c === ",") end[k] = k;
    else if (c === "(" || c === "[" || c === "{") { const close = closeOf(k); end[k] = close === -1 ? n : end[close + 1]; }
    else if (c === "\n") {
      const continued = /[+\-*/%&|^?:=,<>(.!~]/.test(code[prevSolid[k]] || "") || /^[.+\-*/%&|^?:]/.test(code[nextSolid[k + 1]] || "");
      end[k] = continued ? end[k + 1] : k;
    } else end[k] = end[k + 1];
  }
  return (i) => (i >= n ? n : end[i]);
}

/**
 * Names in a function body that carry a parameter's value: the parameters,
 * then every variable assigned, destructured, pushed or iterated from one,
 * and the parameters of callbacks passed to a method of one or to an
 * iteration helper together with one.
 * @param {string} body - the body's expression text (lexJs(...).expr: comments and string contents blanked, `${...}` kept)
 * @param {string[]} params
 * @param {RegExp|null} [extra] - other expressions that carry a parameter's value (`this.x` for a field set from one)
 */
export function parameterTaint(body, params, extra = null, spend = () => true) {
  const names = new Set(params);
  if (!names.size && !extra) return names;
  // No length caps (Vercel, checklist row 1): an index, a destructured list, a
  // for-of binding, an iterated collection or a pushed value padded past a cap
  // dropped its taint silently. Brackets are read by their pairs, values to
  // their expression's end (stmtEnds). The rounds run to a fixed point; the
  // work counts against the file's budget, and past it the result says
  // `incomplete`, so the run exits 2 instead of passing.
  const closeOf = bracketPairs(body);
  const ends = stmtEnds(body);
  let over = false;
  const read = (n) => { if (!spend(n)) over = true; return !over; };
  // An index `[…]` holds no "[": nested ones were not read before either, and it keeps the scan linear.
  const assign = /(?<![\w$.])([A-Za-z_$][\w$]*)((?:\.[\w$]+|\[[^\]\n[]*\])*)\s*(?:\+|\|\||\?\?|&&)?=(?![=>])/g;
  const destructureOpen = /\b(?:const|let|var)\s*[{[]/g;
  const push = /(?<![\w$.])([A-Za-z_$][\w$]*)\.(?:push|unshift|splice|concat)\(/g;
  const forOpen = /\bfor\s*\(\s*(?:(?:const|let|var)\b\s*)?/g;
  const OF = /\s+(?:of|in)\s+/y;
  const EQ = /\s*=(?![=>])/y;
  const IDENT_AT = /[\w$]+/y;
  const at = (re, i) => { re.lastIndex = i; const m = re.exec(body); return m ? m[0].length : -1; };
  // `const { a, b } = …` and `const [a, b] = …`: [binding, where the value starts].
  const destructures = [];
  for (const m of body.matchAll(destructureOpen)) {
    const open = m.index + m[0].length - 1;
    const close = closeOf(open);
    if (close === -1) continue;
    const eq = at(EQ, close + 1);
    if (eq !== -1) destructures.push([body.slice(open, close + 1), close + 1 + eq]);
  }
  // `for (const x of xs)`: [binding, iterable].
  const forOfs = [];
  for (const m of body.matchAll(forOpen)) {
    const paren = body.indexOf("(", m.index);
    const parenClose = closeOf(paren);
    let i = m.index + m[0].length;
    let binding;
    if (body[i] === "{" || body[i] === "[") {
      const close = closeOf(i);
      if (close === -1) continue;
      binding = body.slice(i, close + 1);
      i = close + 1;
    } else {
      const len = at(IDENT_AT, i);
      if (len === -1) continue;
      binding = body.slice(i, i + len);
      i += len;
    }
    const of = at(OF, i);
    if (of === -1) continue;
    const from = i + of;
    forOfs.push([binding, body.slice(from, parenClose === -1 ? ends(from) : parenClose)]);
  }
  const callback = /(?<![\w$.])([A-Za-z_$][\w$]*)(?:\.[\w$]+|\[[^\]\n]{1,80}\])*\s*\.\s*[\w$]+\s*\(\s*(?:async\s*)?(?:function\s*(?:[\w$]+\s*)?\(([^)]*)\)|\(([^)]*)\)\s*=>|([\w$]+)\s*=>)/g;
  // Iteration helpers called with the collection first: async.eachSeries(files, function (file, next) {...}), _.map(list, (x) => ...).
  const iterate = /(?<![\w$])(?:[\w$]+\.)?(?:each\w*|forEach\w*|map(?:Series|Limit|Values)?|filter\w*|reduce|some|every)\s*\(\s*([^,;()\s][^,;()]*),\s*(?:async\s*)?(?:function\s*(?:[\w$]+\s*)?\(([^)]*)\)|\(([^)]*)\)\s*=>|([\w$]+)\s*=>)/g;
  // Past the budget nothing more is read: every loop below stops at `over`.
  const rhs = (from) => { const to = ends(from); return read(to - from) ? body.slice(from, to) : ""; };
  for (;;) {
    if (!read(body.length)) break;
    const size = names.size;
    const usesName = usesNames(names);
    const uses = extra ? (t) => usesName(t) || extra.test(t) : usesName;
    // `this.x = param` is not followed: it would taint every `this.` read in the body.
    for (const m of body.matchAll(assign)) { if (over) break; if (!names.has(m[1]) && m[1] !== "this" && !KEYWORDS.has(m[1]) && uses(rhs(m.index + m[0].length))) names.add(m[1]); }
    for (const [binding, from] of destructures) { if (over) break; if (uses(rhs(from))) for (const n of destructuredOf(binding)) names.add(n); }
    for (const m of body.matchAll(push)) {
      if (over) break;
      if (names.has(m[1])) continue;
      const open = m.index + m[0].length - 1;
      const close = closeOf(open);
      const to = close === -1 ? ends(open + 1) : close;
      if (!read(to - open)) break;
      if (uses(body.slice(open + 1, to))) names.add(m[1]);
    }
    for (const [binding, iterable] of forOfs) { if (over || !read(iterable.length)) break; if (uses(iterable)) for (const n of destructuredOf(binding)) names.add(n); }
    for (const m of body.matchAll(callback)) { if (over) break; if (names.has(m[1])) for (const n of paramNames(m[2] ?? m[3] ?? m[4] ?? "")) names.add(n); }
    for (const m of body.matchAll(iterate)) { if (over || !read(m[1].length)) break; if (uses(m[1].trim())) for (const n of paramNames(m[2] ?? m[3] ?? m[4] ?? "")) names.add(n); }
    if (names.size === size || over) break;
  }
  return over ? Object.assign(names, { incomplete: true }) : names;
}

function destructuredOf(pattern) {
  const p = pattern.trim();
  if (p[0] === "{" || p[0] === "[") return paramNames(p);
  return /^[\w$]+$/.test(p) ? [p] : [];
}

/**
 * Functions in a file that are called by a plain name: `function name(...)`
 * declarations and `const|let|var name = function / arrow`. A name bound twice
 * (shadowing, redefinition) is left out: which one a call reaches is unclear.
 * @param {string} code - masked source
 * @returns {Map<string, { start, paramsText, bodyStart, bodyEnd }>}
 */
export function namedFunctions(code, fns = functionRanges(code)) {
  const out = new Map();
  const twice = new Set();
  const add = (name, f) => {
    if (!name || KEYWORDS.has(name)) return;
    if (out.has(name) && out.get(name) !== f) twice.add(name);
    else out.set(name, f);
  };
  for (const f of fns) {
    if (f.kind === "method") continue;
    if (f.kind === "function" && f.name) add(f.name, f);
    let p = backSkip(code, f.start - 1);
    if (f.kind === "function" && wordBefore(code, p) === "async") p = backSkip(code, p - 5);
    if (p < 1 || code[p] !== "=" || "=!<>+-*/%&|^?".includes(code[p - 1])) continue;
    const q = backSkip(code, p - 1);
    const w = wordBefore(code, q);
    if (!/^[A-Za-z_$][\w$]*$/.test(w)) continue;
    const before = backSkip(code, q - w.length);
    // `const name =`, or a later declarator in `var a = 1, name = ...`
    if (/^(?:const|let|var)$/.test(wordBefore(code, before)) || code[before] === ",") add(w, f);
  }
  for (const n of twice) out.delete(n);
  return out;
}

const THIS_ALIAS = /\b(?:const|let|var)\s+([\w$]+)\s*=\s*this\s*[;,\n]/g;
const thisNames = (body) => new Set(["this", ...[...body.matchAll(THIS_ALIAS)].map((m) => m[1])]);
const FIELD_SET = /(?<![\w$.])([A-Za-z_$][\w$]*)\.([\w$]+)\s*(?:\|\||\?\?|&&)?=(?![=>])/g;

/**
 * Values kept on `this`. Within one class (or prototype, or exported object),
 * a field assigned from a parameter (`this.path = path` in the constructor or
 * in a setter) is a source in every method of that class, and so is a call to
 * a method of the class that returns a value built from such a field
 * (`this.command()`). `const self = this` and Babel's `_this` are read as
 * `this`. One level: a field set from another field is not followed.
 */
function followFields(exported, spend = () => true) {
  const byClass = new Map();
  for (const fn of exported) {
    if (!fn.cls) continue;
    if (!byClass.has(fn.cls)) byClass.set(fn.cls, []);
    byClass.get(fn.cls).push(fn);
  }
  for (const group of byClass.values()) {
    const fields = new Set();
    for (const fn of group) {
      if (!spend(fn.body.length)) return;
      if (!fn.names.size || !/\bthis\b/.test(fn.body)) continue;
      fn.who = thisNames(fn.body);
      for (const m of fn.body.matchAll(FIELD_SET)) {
        if (!fn.who.has(m[1])) continue;
        const from = m.index + m[0].length;
        const to = (fn.ends ||= stmtEnds(fn.body))(from);
        if (!spend(to - from)) return;
        if (fn.uses(fn.body.slice(from, to))) fields.add(m[2]);
      }
    }
    if (!fields.size) continue;
    // Methods that return a value built from a field.
    const getters = new Set();
    for (const fn of group) {
      if (!spend(fn.body.length)) return;
      fn.who ||= thisNames(fn.body);
      const re = memberRef(fn.who, fields);
      if (!re.test(fn.body)) continue;
      const uses = usesNames(parameterTaint(fn.body, [...fn.params], re, spend));
      for (const m of fn.body.matchAll(/\breturn\b/g)) {
        const from = m.index + m[0].length;
        const to = (fn.ends ||= stmtEnds(fn.body))(from);
        if (!spend(to - from)) return;
        const r = fn.body.slice(from, to);
        if (uses(r) || re.test(r)) { getters.add(fn.name.split(".").pop()); break; }
      }
    }
    const getterSet = new Set([...getters].filter((g) => /^[\w$]+$/.test(g)));
    for (const fn of group) {
      if (!spend(fn.body.length)) return;
      const re = memberRef(fn.who, fields, getterSet);
      if (!re.test(fn.body)) continue;
      const taint = parameterTaint(fn.body, [...fn.params], re, spend);
      const usesName = usesNames(taint);
      fn.uses = (t) => usesName(t) || re.test(t);
      fn.names = taint.size ? taint : new Set(["this"]);
    }
  }
}

// One hop at most, and a bound on the work per file.
const MAX_HOPS = 200;

/**
 * Where the parameters of exported functions can reach, as ranges of code
 * whose sinks should be checked:
 *
 *   - each exported function, with its parameters as sources;
 *   - one helper step: a named function in the same file (not exported, or
 *     exported too, it makes no difference) that an exported function calls
 *     with a tainted argument. The helper's parameter at that position is a
 *     source inside the helper. The helper's own calls are not followed
 *     (one hop, no call graph).
 *
 * @param {string} code - masked source (lexJs(...).code)
 * @param {string} expr - lexJs(...).expr of the same source
 * @param {number} [budget] - characters of function bodies to read at most; past it the array has `incomplete: true`
 * @returns {{ name, bodyStart, bodyEnd, params: Set<string>, uses: (t: string) => boolean, via?: string }[]}
 */
export function librarySources(code, expr, budget = Infinity) {
  // Every step reads one function body; nested exported functions read the
  // same text again for each level (quadratic in the depth: 4,000 levels in
  // 160 KB took 6.7 s). `spend` counts the characters read; past the budget
  // the rest is not checked and the result says so (`incomplete`), so the
  // file makes the run incomplete instead of a pass.
  let work = 0;
  let cut = false; // a bound reached that is not the budget (the hop count): the rest was not read
  const spend = (n) => (work += n) <= budget;
  const done = (out) => (work > budget || cut || fns.incomplete ? Object.assign(out, { incomplete: true }) : out);
  const fns = functionRanges(code);
  if (fns.incomplete) cut = true; // return types not all read: said, never a silent pass
  const exported = [];
  for (const fn of exportedFunctions(code, fns, spend)) {
    const body = expr.slice(fn.bodyStart, fn.bodyEnd + 1);
    if (!spend(body.length)) break;
    const taint = parameterTaint(body, fn.params, null, spend);
    exported.push({ name: fn.name, cls: fn.cls, body, bodyStart: fn.bodyStart, bodyEnd: fn.bodyEnd, params: new Set(fn.params), uses: usesNames(taint), names: taint });
  }
  followFields(exported, spend);
  const out = exported.map(({ names, body, cls, who, ends, ...x }) => x);
  const named = namedFunctions(code, fns);
  if (!named.size) return done(out);
  // Any call by a plain name, then a lookup: an alternation of the names tried
  // each at each position.
  const callRe = /(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(/g;
  const hops = new Map(); // helper body start -> hop entry
  const closeOf = bracketPairs(code);
  const helperParams = new Map(); // helper body start -> { pieces, restAt, namesOf }
  for (const fn of exported) {
    if (!fn.names.size) continue;
    if (!spend(fn.bodyEnd + 1 - fn.bodyStart)) break;
    const body = code.slice(fn.bodyStart, fn.bodyEnd + 1);
    for (const m of body.matchAll(callRe)) {
      if (!named.has(m[1])) continue;
      // Past the hop bound the rest is not followed: said, never a silent pass (checklist row 1).
      if (hops.size >= MAX_HOPS) { cut = true; break; }
      const at = fn.bodyStart + m.index;
      // `function name(` is a definition, not a call.
      if (wordBefore(code, backSkip(code, at - 1)) === "function") continue;
      const helper = named.get(m[1]);
      if (helper.bodyStart === fn.bodyStart) continue;
      const open = at + m[0].length - 1;
      const close = closeOf(open); // the call's arguments, read whole (a 2,000-character bound dropped padded ones)
      if (close === -1) continue;
      if (!spend(close - open)) break;
      const args = splitTopLevel(code.slice(open + 1, close), expr.slice(open + 1, close));
      // Every step is charged before it runs: the call's arguments (above), the
      // helper's parameter list here, and each argument's scan below (Vercel, PR 281).
      // Each helper's parameter list is split once and its names kept for every call.
      let hp = helperParams.get(helper.bodyStart);
      if (!hp) {
        if (!spend(helper.paramsText.length + 1)) { cut = true; break; }
        const ps = splitTop(helper.paramsText, true).map((p) => p.trim());
        hp = { pieces: ps, restAt: ps.findIndex((p) => p.startsWith("...")), namesOf: new Map() };
        helperParams.set(helper.bodyStart, hp);
      }
      const { pieces, restAt, namesOf } = hp;
      // Each argument maps to its parameter by position (or to the rest
      // parameter past its index); spread arguments cover a range from the
      // first one, added once. Each parameter's names are read once and
      // charged to the budget: no scan of every parameter per argument
      // (Vercel, PR 281: quadratic with thousands of each).
      const seedSet = new Set();
      const bareArgs = new Map(); // helper parameter -> the exported parameter passed unchanged
      const names = (k) => {
        if (!namesOf.has(k)) { if (!spend(pieces[k].length + 1)) { cut = true; return null; } namesOf.set(k, paramNames(pieces[k])); }
        return namesOf.get(k);
      };
      let spreadFrom = -1;
      for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (!spend(a.length + 1)) { cut = true; break; }
        const spread = /^\s*\.\.\./.test(a);
        if (!fn.uses(spread ? a.replace(/^\s*\.\.\./, "") : a)) continue;
        if (spread) { if (spreadFrom === -1) spreadFrom = i; continue; }
        const k = restAt !== -1 && i >= restAt ? restAt : i;
        if (k >= pieces.length) continue;
        const ns = names(k);
        if (!ns) break;
        for (const n of ns) seedSet.add(n);
        const bare = /^\s*([\w$]+)\s*$/.exec(a);
        if (bare && fn.params.has(bare[1]) && ns.length === 1 && k !== restAt) bareArgs.set(ns[0], bare[1]);
      }
      // A spread fills every parameter from its position on.
      if (spreadFrom !== -1) {
        for (let k = spreadFrom; k < pieces.length; k++) { const ns = names(k); if (!ns) break; for (const n of ns) seedSet.add(n); }
        if (restAt !== -1 && restAt < spreadFrom) { const ns = names(restAt); if (ns) for (const n of ns) seedSet.add(n); }
      }
      const seeds = [...seedSet];
      if (!seeds.length) continue;
      const prev = hops.get(helper.bodyStart);
      if (prev) { for (const s of seeds) prev.seeds.add(s); continue; }
      hops.set(helper.bodyStart, { name: fn.name, via: m[1], bodyStart: helper.bodyStart, bodyEnd: helper.bodyEnd, seeds: new Set(seeds), bareArgs });
    }
  }
  for (const h of hops.values()) {
    if (!spend(h.bodyEnd + 1 - h.bodyStart)) break;
    const taint = parameterTaint(expr.slice(h.bodyStart, h.bodyEnd + 1), [...h.seeds], null, spend);
    // "Runs its argument" through a helper: the exported parameter goes to the helper unchanged.
    out.push({ name: h.name, via: h.via, bodyStart: h.bodyStart, bodyEnd: h.bodyEnd, params: new Set(h.bareArgs.keys()), uses: usesNames(taint) });
  }
  return done(out);
}
