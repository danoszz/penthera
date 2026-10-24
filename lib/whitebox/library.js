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
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { matchBracket, splitTopLevel } from "./js-lex.js";

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
  const pj = join(repoPath, "package.json");
  if (existsSync(pj)) {
    try { pkg = JSON.parse(readFileSync(pj, "utf-8")); } catch { pkg = null; }
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

/** Local names bound by the inside of a `{...}` or `[...]` pattern. */
function destructuredNames(inner) {
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
      out.push(...destructuredNames(close === -1 ? target.slice(1) : target.slice(1, close)));
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
  const fns = [];
  const seen = new Set();
  // function name? (params) { body }
  for (const m of code.matchAll(/\bfunction\b\s*\*?\s*([\w$]*)\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    const close = matchBracket(code, open, 20000);
    if (close === -1) continue;
    const b = skipReturnType(code, close + 1);
    if (code[b] !== "{") continue;
    const end = matchBracket(code, b);
    if (end === -1) continue;
    seen.add(b);
    fns.push({ start: m.index, paramsText: code.slice(open + 1, close), bodyStart: b, bodyEnd: end, name: m[1] || "", kind: "function" });
  }
  // (params) => body, x => body
  for (const m of code.matchAll(/=>/g)) {
    const arrow = m.index;
    let p = backSkip(code, arrow - 1);
    let start; let paramsText;
    if (p >= 0 && code[p] === ")") {
      // Walk back to the matching "(".
      let depth = 0; let k = p;
      for (; k >= 0; k--) { if (code[k] === ")") depth++; else if (code[k] === "(" && --depth === 0) break; }
      if (k < 0) continue;
      start = k; paramsText = code.slice(k + 1, p);
    } else if (p >= 0 && /[\w$]/.test(code[p])) {
      const w = wordBefore(code, p);
      start = p - w.length + 1; paramsText = w;
    } else {
      // `(a): Type =>` (TypeScript return type) and other shapes: skip.
      continue;
    }
    const before = backSkip(code, start - 1);
    if (wordBefore(code, before) === "async") start = before - 4;
    let b = arrow + 2;
    while (b < code.length && /\s/.test(code[b])) b++;
    if (code[b] === "{") {
      const end = matchBracket(code, b);
      if (end === -1) continue;
      fns.push({ start, paramsText, bodyStart: b, bodyEnd: end, name: "", kind: "arrow" });
    } else {
      fns.push({ start, paramsText, bodyStart: b, bodyEnd: exprEnd(code, b), name: "", kind: "arrow" });
    }
  }
  // Methods in classes and object literals: name(params) { body }
  // Horizontal whitespace only after the separator: masked comments leave long
  // runs of spaces and line breaks, and `\s*` there backtracks badly.
  for (const m of code.matchAll(/(^|[{,;}\n])([ \t]*)((?:(?:async|static|get|set|public|private|protected|override|readonly)[ \t]+)*)\*?[ \t]*(#?[A-Za-z_$][\w$]*)[ \t]*(?:<[^>()\n]*>[ \t]*)?\(/g)) {
    const name = m[4];
    if (KEYWORDS.has(name)) continue;
    const open = m.index + m[0].length - 1;
    const close = matchBracket(code, open, 20000);
    if (close === -1) continue;
    const b = skipReturnType(code, close + 1);
    if (code[b] !== "{" || seen.has(b)) continue;
    const end = matchBracket(code, b);
    if (end === -1) continue;
    const start = m.index + m[1].length + m[2].length;
    fns.push({ start, paramsText: code.slice(open + 1, close), bodyStart: b, bodyEnd: end, name, kind: "method" });
  }
  return fns;
}

/** After a parameter list: skip whitespace and a TypeScript return type, up to the body's "{". */
function skipReturnType(code, i) {
  while (i < code.length && /\s/.test(code[i])) i++;
  if (code[i] !== ":") return i;
  // `: Promise<string> {` or `: { a: string } {`: take the last "{" before a line end that opens the body.
  let j = i + 1;
  let depth = 0;
  for (; j < code.length && j < i + 400; j++) {
    const c = code[j];
    if (c === "<" || c === "(" || c === "[") depth++;
    else if (c === ">" || c === ")" || c === "]") depth--;
    else if (c === "{" && depth === 0) {
      // A type literal `{ ... }` is followed by more type or the body; the body is the "{" not followed by a type.
      const close = matchBracket(code, j, 2000);
      let k = close + 1;
      while (k < code.length && /\s/.test(code[k])) k++;
      if (close !== -1 && code[k] === "{") { j = k - 1; continue; }
      return j;
    } else if (c === ";" || c === "=") return j;
  }
  return j;
}

/** End of an arrow function's expression body: the first top-level `,` `;` or closing bracket. */
function exprEnd(code, i) {
  let depth = 0;
  for (; i < code.length; i++) {
    const c = code[i];
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") { if (depth === 0) return i; depth--; }
    else if ((c === "," || c === ";") && depth === 0) return i;
    else if (c === "\n" && depth === 0) {
      let k = i + 1;
      while (k < code.length && /[ \t\r]/.test(code[k])) k++;
      if (!/[.?:+\-*/%&|,)]/.test(code[k] || "")) return i;
    }
  }
  return i;
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
export function exportedFunctions(code, fns = functionRanges(code)) {
  const encl = enclosingBrackets(code);
  const exportNames = new Set();
  const exportedObjects = new Set(); // index of "{" of exported object literals and class bodies
  const protoAlias = new Map(); // P -> X for `var P = X.prototype`

  for (const m of code.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*([\w$]+)\.prototype\s*[;\n,]/g)) protoAlias.set(m[1], m[2]);

  // What the file exports by name.
  const addObjectNames = (open) => {
    const close = matchBracket(code, open);
    if (close === -1) return;
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
  for (const m of code.matchAll(/\bexport\s+(?:default\s+)?(?:async\s+)?(?:function\s*\*?|class|const|let|var)\s*([\w$]+)/g)) exportNames.add(m[1]);
  for (const m of code.matchAll(/\bexport\s+default\s+([\w$]+)\s*[;\n]/g)) exportNames.add(m[1]);
  for (const m of code.matchAll(/\bexport\s*\{([^}]*)\}/g)) {
    for (const part of m[1].split(",")) { const local = part.trim().split(/\s+as\s+/)[0].trim(); if (/^[\w$]+$/.test(local)) exportNames.add(local); }
  }
  for (const m of code.matchAll(/\bexport\s+default\s*\{/g)) { const k = m.index + m[0].length - 1; exportedObjects.add(k); addObjectNames(k); }
  for (const m of code.matchAll(/\bexport\s+(?:default\s+)?class\b[^{;]{0,300}\{/g)) exportedObjects.add(m.index + m[0].length - 1);
  // Object.assign(module.exports, { ... }) / Object.assign(exports, { ... })
  for (const m of code.matchAll(/\bObject\.assign\(\s*(?:module\.)?exports\s*,\s*\{/g)) { const k = m.index + m[0].length - 1; exportedObjects.add(k); addObjectNames(k); }
  // Object.assign(module.exports, api) and `for (k in api) exports[k] = api[k]`: every member of api.
  for (const m of code.matchAll(/\bObject\.assign\(\s*(?:module\.)?exports\s*,\s*([\w$]+)\s*\)/g)) exportNames.add(m[1]);
  for (const m of code.matchAll(/\bfor\s*\(\s*(?:var|let|const)?\s*([\w$]+)\s+in\s+([\w$]+)\s*\)\s*\{?\s*(?:module\.)?exports\[\s*\1\s*\]\s*=\s*\2\[\s*\1\s*\]/g)) exportNames.add(m[2]);

  // How each function is bound, read from the text before it.
  const info = fns.map((f) => {
    let s = f.start;
    let p = backSkip(code, s - 1);
    if (wordBefore(code, p) === "async") p = backSkip(code, p - 5);
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
      const close = matchBracket(code, p);
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
  const insideExported = (pos) => {
    for (const x of exported) if (pos > x.f.bodyStart && pos < x.f.bodyEnd) return x;
    return null;
  };

  for (let round = 0; round < 6; round++) {
    const before = exported.size;
    // Objects returned from exported functions are exported (factories, IIFEs).
    for (const m of code.matchAll(/\breturn\s*\{/g)) {
      const k = m.index + m[0].length - 1;
      if (insideExported(k)) { if (!exportedObjects.has(k)) { exportedObjects.add(k); addObjectNames(k); } }
    }
    for (const x of exported) {
      const body = code.slice(x.f.bodyStart, x.f.bodyEnd);
      // An instance an exported function returns: `return new Name(...)` exports Name's methods.
      for (const m of body.matchAll(/\breturn\s+new\s+([\w$]+)\s*\(/g)) exportNames.add(m[1]);
      if (!x.iife) continue;
      // `return Name;` at the IIFE's top level exports Name.
      for (const m of body.matchAll(/\breturn\s+([\w$]+)\s*[;\n}]/g)) exportNames.add(m[1]);
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
      if (yes) exported.add(x);
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
  return [...exported].map((x) => ({ start: x.f.start, bodyStart: x.f.bodyStart, bodyEnd: x.f.bodyEnd, params: x.iife ? [] : paramNames(x.f.paramsText), name: x.name || x.lhs || "(anonymous)", cls: classOf(x) }));
}

const escapeRe = (s) => s.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");

/** A test for "this text uses one of these names" (not as a property name after a dot). */
export function usesNames(names) {
  if (!names.size) return () => false;
  const re = new RegExp(`(?<![\\w$.])(?:${[...names].map(escapeRe).join("|")})(?![\\w$])`);
  return (text) => re.test(text);
}

/**
 * End of the expression that starts at `i` in masked code: a top-level `;` or
 * `,`, a bracket that closes an outer one, or a line break that is not inside
 * a continued expression (the line ends with an operator or the next one
 * starts with one).
 */
function stmtEnd(code, i, limit = 2000) {
  let depth = 0;
  const stop = Math.min(code.length, i + limit);
  for (let k = i; k < stop; k++) {
    const c = code[k];
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") { if (depth === 0) return k; depth--; }
    else if ((c === ";" || c === ",") && depth === 0) return k;
    else if (c === "\n" && depth === 0) {
      const prev = backSkip(code, k - 1);
      let next = k + 1;
      while (next < code.length && /\s/.test(code[next])) next++;
      const continued = /[+\-*/%&|^?:=,<>(.!~]/.test(code[prev] || "") || /^[.+\-*/%&|^?:]/.test(code[next] || "");
      if (!continued) return k;
    }
  }
  return stop;
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
export function parameterTaint(body, params, extra = null) {
  const names = new Set(params);
  if (!names.size && !extra) return names;
  const assign = /(?<![\w$.])([A-Za-z_$][\w$]*)((?:\.[\w$]+|\[[^\]\n]{1,80}\])*)\s*(?:\+|\|\||\?\?|&&)?=(?![=>])/g;
  const destructure = /\b(?:const|let|var)\s*([{[][^=;]{1,300}[}\]])\s*=(?![=>])/g;
  const push = /(?<![\w$.])([A-Za-z_$][\w$]*)\.(?:push|unshift|splice|concat)\(/g;
  const forOf = /\bfor\s*\(\s*(?:const|let|var)?\s*([\w$]+|[{[][^=;]{1,200}[}\]])\s+(?:of|in)\s+([^;\n)]{1,200})\)/g;
  const callback = /(?<![\w$.])([A-Za-z_$][\w$]*)(?:\.[\w$]+|\[[^\]\n]{1,80}\])*\s*\.\s*[\w$]+\s*\(\s*(?:async\s*)?(?:function\s*[\w$]*\s*\(([^)]*)\)|\(([^)]*)\)\s*=>|([\w$]+)\s*=>)/g;
  // Iteration helpers called with the collection first: async.eachSeries(files, function (file, next) {...}), _.map(list, (x) => ...).
  const iterate = /(?<![\w$])(?:[\w$]+\.)?(?:each\w*|forEach\w*|map(?:Series|Limit|Values)?|filter\w*|reduce|some|every)\s*\(\s*([^,;()]{1,200}?)\s*,\s*(?:async\s*)?(?:function\s*[\w$]*\s*\(([^)]*)\)|\(([^)]*)\)\s*=>|([\w$]+)\s*=>)/g;
  const rhs = (m) => { const from = m.index + m[0].length; return body.slice(from, stmtEnd(body, from)); };
  for (let round = 0; round < 6; round++) {
    const size = names.size;
    const usesName = usesNames(names);
    const uses = extra ? (t) => usesName(t) || extra.test(t) : usesName;
    // `this.x = param` is not followed: it would taint every `this.` read in the body.
    for (const m of body.matchAll(assign)) if (!names.has(m[1]) && m[1] !== "this" && !KEYWORDS.has(m[1]) && uses(rhs(m))) names.add(m[1]);
    for (const m of body.matchAll(destructure)) if (uses(rhs(m))) for (const n of destructuredOf(m[1])) names.add(n);
    for (const m of body.matchAll(push)) {
      if (names.has(m[1])) continue;
      const open = m.index + m[0].length - 1;
      const close = matchBracket(body, open, 2000);
      if (uses(body.slice(open + 1, close === -1 ? open + 300 : close))) names.add(m[1]);
    }
    for (const m of body.matchAll(forOf)) if (uses(m[2])) for (const n of destructuredOf(m[1])) names.add(n);
    for (const m of body.matchAll(callback)) if (names.has(m[1])) for (const n of paramNames(m[2] ?? m[3] ?? m[4] ?? "")) names.add(n);
    for (const m of body.matchAll(iterate)) if (uses(m[1])) for (const n of paramNames(m[2] ?? m[3] ?? m[4] ?? "")) names.add(n);
    if (names.size === size) break;
  }
  return names;
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
const thisNames = (body) => ["this", ...[...body.matchAll(THIS_ALIAS)].map((m) => m[1])].map(escapeRe).join("|");

/**
 * Values kept on `this`. Within one class (or prototype, or exported object),
 * a field assigned from a parameter (`this.path = path` in the constructor or
 * in a setter) is a source in every method of that class, and so is a call to
 * a method of the class that returns a value built from such a field
 * (`this.command()`). `const self = this` and Babel's `_this` are read as
 * `this`. One level: a field set from another field is not followed.
 */
function followFields(exported) {
  const byClass = new Map();
  for (const fn of exported) {
    if (!fn.cls) continue;
    if (!byClass.has(fn.cls)) byClass.set(fn.cls, []);
    byClass.get(fn.cls).push(fn);
  }
  for (const group of byClass.values()) {
    const fields = new Set();
    for (const fn of group) {
      if (!fn.names.size || !/\bthis\b/.test(fn.body)) continue;
      fn.who = thisNames(fn.body);
      const set = new RegExp(`(?<![\\w$.])(?:${fn.who})\\.([\\w$]+)\\s*(?:\\|\\||\\?\\?|&&)?=(?![=>])`, "g");
      for (const m of fn.body.matchAll(set)) {
        const from = m.index + m[0].length;
        if (fn.uses(fn.body.slice(from, stmtEnd(fn.body, from)))) fields.add(m[1]);
      }
    }
    if (!fields.size) continue;
    const fieldAlt = [...fields].map(escapeRe).join("|");
    // Methods that return a value built from a field.
    const getters = new Set();
    for (const fn of group) {
      fn.who ||= thisNames(fn.body);
      const re = new RegExp(`(?<![\\w$.])(?:${fn.who})\\.(?:${fieldAlt})(?![\\w$])`);
      if (!re.test(fn.body)) continue;
      const uses = usesNames(parameterTaint(fn.body, [...fn.params], re));
      for (const m of fn.body.matchAll(/\breturn\b/g)) {
        const from = m.index + m[0].length;
        const r = fn.body.slice(from, stmtEnd(fn.body, from));
        if (uses(r) || re.test(r)) { getters.add(fn.name.split(".").pop()); break; }
      }
    }
    const getterAlt = [...getters].filter((g) => /^[\w$]+$/.test(g)).map(escapeRe).join("|");
    for (const fn of group) {
      const re = new RegExp(`(?<![\\w$.])(?:${fn.who})\\.(?:(?:${fieldAlt})(?![\\w$])${getterAlt ? `|(?:${getterAlt})\\s*\\(` : ""})`);
      if (!re.test(fn.body)) continue;
      const taint = parameterTaint(fn.body, [...fn.params], re);
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
 * @returns {{ name, bodyStart, bodyEnd, params: Set<string>, uses: (t: string) => boolean, via?: string }[]}
 */
export function librarySources(code, expr) {
  const fns = functionRanges(code);
  const exported = exportedFunctions(code, fns).map((fn) => {
    const body = expr.slice(fn.bodyStart, fn.bodyEnd + 1);
    const taint = parameterTaint(body, fn.params);
    return { name: fn.name, cls: fn.cls, body, bodyStart: fn.bodyStart, bodyEnd: fn.bodyEnd, params: new Set(fn.params), uses: usesNames(taint), names: taint };
  });
  followFields(exported);
  const out = exported.map(({ names, body, cls, who, ...x }) => x);
  const named = namedFunctions(code, fns);
  if (!named.size) return out;
  const callRe = new RegExp(`(?<![\\w$.])(${[...named.keys()].map(escapeRe).join("|")})\\s*\\(`, "g");
  const hops = new Map(); // helper body start -> hop entry
  for (const fn of exported) {
    if (!fn.names.size) continue;
    const body = code.slice(fn.bodyStart, fn.bodyEnd + 1);
    for (const m of body.matchAll(callRe)) {
      if (hops.size >= MAX_HOPS) break;
      const at = fn.bodyStart + m.index;
      // `function name(` is a definition, not a call.
      if (wordBefore(code, backSkip(code, at - 1)) === "function") continue;
      const helper = named.get(m[1]);
      if (helper.bodyStart === fn.bodyStart) continue;
      const open = at + m[0].length - 1;
      const close = matchBracket(code, open, 2000);
      if (close === -1) continue;
      const args = splitTopLevel(code.slice(open + 1, close), expr.slice(open + 1, close));
      const pieces = splitTop(helper.paramsText, true).map((p) => p.trim());
      const seeds = [];
      const bareArgs = new Map(); // helper parameter -> the exported parameter passed unchanged
      args.forEach((a, i) => {
        const spread = /^\s*\.\.\./.test(a);
        if (!fn.uses(spread ? a.replace(/^\s*\.\.\./, "") : a)) return;
        for (let k = 0; k < pieces.length; k++) {
          const rest = pieces[k].startsWith("...");
          if (k === i || (spread && k > i) || (rest && k <= i)) {
            const ns = paramNames(pieces[k]);
            seeds.push(...ns);
            const bare = /^\s*([\w$]+)\s*$/.exec(a);
            if (bare && fn.params.has(bare[1]) && ns.length === 1 && !rest) bareArgs.set(ns[0], bare[1]);
          }
        }
      });
      if (!seeds.length) continue;
      const prev = hops.get(helper.bodyStart);
      if (prev) { for (const s of seeds) prev.seeds.add(s); continue; }
      hops.set(helper.bodyStart, { name: fn.name, via: m[1], bodyStart: helper.bodyStart, bodyEnd: helper.bodyEnd, seeds: new Set(seeds), bareArgs });
    }
  }
  for (const h of hops.values()) {
    const taint = parameterTaint(expr.slice(h.bodyStart, h.bodyEnd + 1), [...h.seeds]);
    // "Runs its argument" through a helper: the exported parameter goes to the helper unchanged.
    out.push({ name: h.name, via: h.via, bodyStart: h.bodyStart, bodyEnd: h.bodyEnd, params: new Set(h.bareArgs.keys()), uses: usesNames(taint) });
  }
  return out;
}
