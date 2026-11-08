/**
 * Shared helpers for fix recipes: framework detection, file discovery, and the
 * small, anchor-based text edits recipes are built from. No AST: every edit
 * keys off a line the recipe can recognise exactly, and gives up otherwise.
 */
import { existsSync, readdirSync, lstatSync, statSync, realpathSync } from "node:fs";
import { readRepoFile } from "../fs-safe.js";
import { isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import { detectFramework as detectSourceFramework } from "../whitebox/frameworks.js";
import { createPatch } from "./diff.js";

const SKIP = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage", "vendor", "reports", ".security-results",
  // Generated output: nobody edits it, and it must not push real code past the cap.
  "out", ".turbo", ".output", ".svelte-kit", ".nuxt", ".vercel", ".netlify", "storybook-static",
]);
// Next.js build output under another name (`.next-dev`, set by distDir).
const NEXT_BUILD = /^\.next(?:$|[-_.])/;
const CODE_EXT = /\.(js|ts|mjs|cjs|jsx|tsx)$/;
// The sink check reads up to 5,000 code files; this walk reads as many.
const MAX_FILES = 5000;

export const ENTRY_CANDIDATES = [
  "server.js", "server.ts", "server.mjs", "app.js", "app.ts", "app.mjs",
  "index.js", "index.ts", "index.mjs", "main.js", "main.ts",
  "src/server.js", "src/server.ts", "src/app.js", "src/app.ts",
  "src/index.js", "src/index.ts", "src/main.js", "src/main.ts",
];

export function readText(repoPath, rel) {
  try {
    return readRepoFile(join(repoPath, rel), { root: repoPath, maxBytes: 5 * 1024 * 1024 });
  } catch {
    return null;
  }
}

export function readPackageJson(repoPath) {
  const text = readText(repoPath, "package.json");
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export function hasDep(repoPath, name) {
  const pkg = readPackageJson(repoPath);
  return Boolean(pkg && (pkg.dependencies?.[name] || pkg.devDependencies?.[name]));
}

/**
 * The web framework a repo uses: "next" | "hono" | "fastify" | "express" | null.
 * package.json decides; source imports (via the white-box route scanner's
 * detector) are the fallback for repos without one.
 */
export function detectFramework(repoPath) {
  for (const fw of ["next", "hono", "fastify", "express"]) if (hasDep(repoPath, fw)) return fw;
  if (["next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs"].some((f) => existsSync(join(repoPath, f)))) return "next";
  for (const rel of ENTRY_CANDIDATES) {
    const source = readText(repoPath, rel);
    if (!source) continue;
    const fw = detectSourceFramework(source);
    if (fw !== "node") return fw;
  }
  return null;
}

/**
 * Repo-relative paths (with `/`) of JS/TS source files, in sorted order, at
 * most MAX_FILES. It skips dependencies and generated output (SKIP,
 * NEXT_BUILD) and folders git ignores (`ignoredDirs`, absolute paths), so a
 * generated or ignored folder never pushes real code past the cap. Tests and
 * public/ are read: findings there are likely noise, and the headers fix reads
 * the origins client code calls. A link is not walked
 * past the project: a linked file goes in the list (the read then follows it
 * only inside the project, readRepoFile), a linked folder inside it is walked
 * once, and one outside it or a link to nothing is named in `unread`.
 * `over` counts the code files past the cap and `firstOver` names the first.
 *
 * @param {string} repoPath
 * @param {{ ignoredDirs?: Set<string> | null }} [opts]
 * @returns {{ files: string[], over: number, firstOver: string | null, unread: { file: string, reason: string }[] }}
 */
export function listCodeFiles(repoPath, { ignoredDirs = null } = {}) {
  const files = [];
  const unread = [];
  let over = 0;
  let firstOver = null;
  const rel = (full) => relative(repoPath, full).split(sep).join("/");
  let realRoot = resolve(repoPath);
  try { realRoot = realpathSync(repoPath); } catch { /* keep as given */ }
  const seen = new Set([realRoot]);
  const isCode = (name) => CODE_EXT.test(name) && !/\.(test|spec)\.|\.d\.ts$|\.min\.js$/.test(name);
  const add = (full) => {
    if (files.length < MAX_FILES) files.push(rel(full));
    else if (over++ === 0) firstOver = rel(full);
  };
  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir);
    } catch (e) {
      // A folder that can't be listed hides its files: name it, never skip it in silence.
      if (dir !== repoPath) unread.push({ file: rel(dir), reason: `it is a folder that could not be read (${e.code || e.message})` });
      return;
    }
    for (const entry of entries.sort()) {
      const full = join(dir, entry);
      if (SKIP.has(entry) || NEXT_BUILD.test(entry) || ignoredDirs?.has(full)) continue;
      let st;
      try {
        st = lstatSync(full);
      } catch (e) {
        if (e.code !== "ENOENT") unread.push({ file: rel(full), reason: `it could not be read (${e.code || e.message})` });
        continue;
      }
      if (st.isSymbolicLink()) {
        let target = null;
        try { target = realpathSync(full); } catch { /* a link to nothing */ }
        const inside = target && (target === realRoot || target.startsWith(realRoot + sep));
        let tst = null;
        if (target) { try { tst = statSync(full); } catch { /* gone since */ } }
        if (tst?.isDirectory()) {
          if (!inside) unread.push({ file: rel(full), reason: "it is a linked folder outside the project" });
          else if (!seen.has(target)) { seen.add(target); walk(full); }
        } else if (isCode(entry)) {
          if (!target) unread.push({ file: rel(full), reason: "it is a link to nothing" });
          else add(full); // the read follows it only inside the project, and names it otherwise
        }
        continue;
      }
      if (st.isDirectory()) {
        let real = full;
        try { real = realpathSync(full); } catch { /* keep */ }
        if (seen.has(real)) continue;
        seen.add(real);
        walk(full);
      } else if (isCode(entry)) add(full);
    }
  };
  walk(repoPath);
  return { files, over, firstOver, unread };
}

/**
 * The code files' total size in bytes, from their sizes alone (nothing read),
 * stopping once it passes `stopAt`.
 */
export function codeBytes(repoPath, stopAt = Infinity) {
  let total = 0;
  for (const file of listCodeFiles(repoPath).files) {
    try { total += statSync(join(repoPath, file)).size; } catch { /* gone */ }
    if (total > stopAt) break;
  }
  return total;
}

/** Repo-relative paths of JS/TS source files (listCodeFiles, without the count past the cap). */
export function walkCodeFiles(repoPath) {
  return listCodeFiles(repoPath).files;
}

export const CODE_FILE_CAP = MAX_FILES;

/** A 1-based line number for any offset: one implementation, in lib/linear-text.js. */
export { lineIndex } from "../linear-text.js";

/** First entry-candidate file whose source matches `anchor`. */
export function findEntryFile(repoPath, anchor) {
  const candidates = [...ENTRY_CANDIDATES];
  const main = readPackageJson(repoPath)?.main;
  // package.json is repo data: a "main" that points out of the repo is ignored.
  if (typeof main === "string" && main && !isAbsolute(main) && !/^[a-zA-Z]:/.test(main)) {
    const rel = normalize(main);
    if (rel !== ".." && !rel.startsWith(`..${sep}`) && !rel.startsWith("../")) candidates.unshift(rel.replace(/\\/g, "/"));
  }
  for (const rel of candidates) {
    const source = readText(repoPath, rel);
    if (source && anchor.test(source)) return { file: rel, source };
  }
  return null;
}

export const isTypeScript = (file) => /\.tsx?$/.test(file);

export function moduleStyle(source) {
  // Line by line: one multi-line regex for this rescanned long lines from every `import`.
  for (const line of source.split("\n")) {
    const t = line.trimStart();
    if (/^export\s/.test(t) || /^import\s*['"{*]/.test(t) || (/^import\s/.test(t) && /\bfrom\s*['"]/.test(t))) return "esm";
  }
  if (/\brequire\s*\(/.test(source)) return "cjs";
  return "esm";
}

/** Index of the line after the last top-level import/require statement. */
function importBlockEnd(lines) {
  let end = 0;
  let open = false;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (open) {
      if (/\bfrom\s+['"][^'"]+['"];?\s*$/.test(l)) { open = false; end = i + 1; }
      continue;
    }
    if (/^import\s.*\bfrom\s+['"][^'"]+['"];?\s*$/.test(l) || /^import\s+['"][^'"]+['"];?\s*$/.test(l)) end = i + 1;
    else if (/^import\s+(?:type\s+)?\{[^}]*$/.test(l)) open = true;
    else if (/^(?:const|let|var)(?=\s)[\w{}\s,:]+=\s*require\(\s*['"][^'"]+['"]\s*\)[\w.]*;?\s*$/.test(l)) end = i + 1;
    else if (i === 0 && /^#!/.test(l)) end = 1;
    else if (/^['"]use (strict|client|server)['"];?\s*$/.test(l)) end = Math.max(end, i + 1);
  }
  return end;
}

/** Insert `block` (lines) after the import block, separated by a blank line. */
export function insertAfterImports(source, block) {
  const lines = source.split("\n");
  const at = importBlockEnd(lines);
  const insert = [...block];
  if (at > 0 && lines[at - 1].trim() !== "") insert.unshift("");
  if (lines[at] !== undefined && lines[at].trim() !== "") insert.push("");
  lines.splice(at, 0, ...insert);
  return lines.join("\n");
}

/** Add an import (ESM or CommonJS, matching the file) unless the module is already imported. */
export function addImport(source, { name, module, named = false }) {
  const escaped = module.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  if (new RegExp(`from\\s+['"]${escaped}['"]|require\\(\\s*['"]${escaped}['"]\\s*\\)`).test(source)) return source;
  const line = moduleStyle(source) === "cjs"
    ? `const ${named ? `{ ${name} }` : name} = require("${module}");`
    : `import ${named ? `{ ${name} }` : name} from "${module}";`;
  const lines = source.split("\n");
  const at = importBlockEnd(lines);
  lines.splice(at, 0, line);
  return lines.join("\n");
}

/** Insert lines right after line `index`, matching that line's indentation. */
export function insertAfterLine(source, index, block) {
  const lines = source.split("\n");
  const indent = lines[index].match(/^\s*/)[0];
  lines.splice(index + 1, 0, ...block.map((l) => (l ? indent + l : l)));
  return lines.join("\n");
}

/** Index of the first line matching re, or -1. */
export function findLine(source, re) {
  return source.split("\n").findIndex((l) => re.test(l));
}

/**
 * Split a call's arguments starting at the "(" at `open`, on one line only.
 * Returns { args: [{ text, start, end }], close } with absolute offsets, or
 * null if the call does not close before the end of the line.
 * `budget` ({ left }): characters the caller may still read; each call takes
 * what it reads from it, and past it the result is { over: true }. Calls on
 * one long line each read to the line's end, so a file of unclosed
 * `s.set(` read its line once per call (quadratic).
 * `multiline`: the call may span lines (a newline outside a string, or inside
 * a template literal, no longer ends it). Only for checks that read; an edit
 * keeps to one line.
 */
export function splitCallArgs(text, open, budget = null, { multiline = false } = {}) {
  const args = [];
  let depth = 0;
  let quote = null;
  let argStart = open + 1;
  const stop = budget ? Math.min(text.length, open + Math.max(0, budget.left)) : text.length;
  const take = (i) => { if (budget) budget.left -= i - open + 1; };
  for (let i = open; i < text.length; i++) {
    if (i >= stop) { take(i); return { over: true }; }
    const ch = text[i];
    // multiline (a check that only reads): a call may span lines, as Prettier writes an options object.
    if (ch === "\n" && !quote && !multiline) { take(i); return null; }
    if (quote) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = null;
      else if (ch === "\n" && !(multiline && quote === "`")) { take(i); return null; }
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") quote = ch;
    else if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      depth--;
      if (depth === 0) {
        if (text.slice(argStart, i).trim()) args.push({ text: text.slice(argStart, i).trim(), start: argStart, end: i });
        take(i);
        return { args, close: i };
      }
    } else if (ch === "," && depth === 1) {
      args.push({ text: text.slice(argStart, i).trim(), start: argStart, end: i });
      argStart = i + 1;
    }
  }
  take(text.length - 1);
  return null;
}

/** Add `NAME=value` to .env.example (creating it) unless NAME is already listed. */
export function envExampleChange(repoPath, name, value = "", comment = null) {
  const before = readText(repoPath, ".env.example");
  if (before != null && new RegExp(`^\\s*${name}\\s*=`, "m").test(before)) return null;
  const add = [...(comment ? [`# ${comment}`] : []), `${name}=${value}`].join("\n") + "\n";
  const after = before == null ? add : before + (before.endsWith("\n") || before === "" ? "" : "\n") + add;
  return { file: ".env.example", before, after };
}

/** Turn [{ file, before, after }] into { diff, files }, dropping no-op changes. */
export function toDiff(changes) {
  const parts = [];
  const files = [];
  for (const c of changes.filter(Boolean)) {
    const patch = createPatch(c.file, c.before, c.after);
    if (!patch) continue;
    parts.push(patch);
    files.push(c.file);
  }
  if (parts.length === 0) return null;
  return { diff: parts.join(""), files };
}

/** "sessionSecret" / "api-key" -> "SESSION_SECRET" / "API_KEY". */
export function toEnvName(key) {
  return String(key)
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_|_$/g, "") // runs are one "_" already
    .toUpperCase();
}
