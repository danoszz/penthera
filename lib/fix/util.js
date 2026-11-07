/**
 * Shared helpers for fix recipes: framework detection, file discovery, and the
 * small, anchor-based text edits recipes are built from. No AST: every edit
 * keys off a line the recipe can recognise exactly, and gives up otherwise.
 */
import { existsSync, readdirSync, lstatSync } from "node:fs";
import { readRepoFile } from "../fs-safe.js";
import { isAbsolute, join, normalize, relative, sep } from "node:path";
import { detectFramework as detectSourceFramework } from "../whitebox/frameworks.js";
import { createPatch } from "./diff.js";

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage", "vendor", "reports", ".security-results"]);
const CODE_EXT = /\.(js|ts|mjs|cjs|jsx|tsx)$/;
const MAX_FILES = 2000;
/** A single-line call longer than this is not split (see splitCallArgs). */
const MAX_CALL_LENGTH = 4096;

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
 * Repo-relative paths of JS/TS source files, skipping dependencies and build
 * output, and symbolic links (a link can point out of the repo or loop). At most
 * MAX_FILES, in sorted order; `over` counts the code files past that, and
 * `firstOver` names the first of them. `unread` names folders it could not list.
 *
 * @returns {{ files: string[], over: number, firstOver: string | null, unread: { file: string, reason: string }[] }}
 */
export function listCodeFiles(repoPath) {
  const files = [];
  const unread = [];
  let over = 0;
  let firstOver = null;
  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir);
    } catch (e) {
      // A folder that can't be listed hides its files: name it, never skip it in silence.
      if (dir !== repoPath) unread.push({ file: relative(repoPath, dir), reason: `it is a folder that could not be read (${e.code || e.message})` });
      return;
    }
    for (const entry of entries.sort()) {
      if (SKIP.has(entry)) continue;
      const full = join(dir, entry);
      let st;
      try {
        st = lstatSync(full);
      } catch (e) {
        if (e.code !== "ENOENT") unread.push({ file: relative(repoPath, full), reason: `it could not be read (${e.code || e.message})` });
        continue;
      }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) walk(full);
      else if (CODE_EXT.test(entry) && !/\.(test|spec)\.|\.d\.ts$|\.min\.js$/.test(entry)) {
        if (files.length < MAX_FILES) files.push(relative(repoPath, full));
        else if (over++ === 0) firstOver = relative(repoPath, full);
      }
    }
  };
  walk(repoPath);
  return { files, over, firstOver, unread };
}

/** Repo-relative paths of JS/TS source files (listCodeFiles, without the count past the cap). */
export function walkCodeFiles(repoPath) {
  return listCodeFiles(repoPath).files;
}

export const CODE_FILE_CAP = MAX_FILES;

/**
 * A 1-based line number for any offset in `source`, in O(log n) per call:
 * counting newlines from the start on every hit is quadratic on a large file.
 */
export function lineIndex(source) {
  const starts = [0];
  for (let i = source.indexOf("\n"); i !== -1; i = source.indexOf("\n", i + 1)) starts.push(i + 1);
  return (offset) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

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
  if (/^\s*import\s[^;]*?from\s+['"]|^\s*import\s+['"]|^\s*export\s/m.test(source)) return "esm";
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
    else if (/^(?:const|let|var)\s+[\w{}\s,:]+=\s*require\(\s*['"][^'"]+['"]\s*\)[\w.]*;?\s*$/.test(l)) end = i + 1;
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
 * null if the call does not close before the end of the line or within
 * `maxLength` characters (one long minified line must not make every call on it
 * rescan the rest of the line).
 */
export function splitCallArgs(text, open, maxLength = MAX_CALL_LENGTH) {
  const args = [];
  const stop = Math.min(text.length, open + maxLength);
  let depth = 0;
  let quote = null;
  let argStart = open + 1;
  for (let i = open; i < stop; i++) {
    const ch = text[i];
    if (ch === "\n" && !quote) return null;
    if (quote) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = null;
      else if (ch === "\n") return null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") quote = ch;
    else if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      depth--;
      if (depth === 0) {
        if (text.slice(argStart, i).trim()) args.push({ text: text.slice(argStart, i).trim(), start: argStart, end: i });
        return { args, close: i };
      }
    } else if (ch === "," && depth === 1) {
      args.push({ text: text.slice(argStart, i).trim(), start: argStart, end: i });
      argStart = i + 1;
    }
  }
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
    .replace(/^_+|_+$/g, "")
    .toUpperCase();
}
