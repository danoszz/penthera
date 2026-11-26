/**
 * Framework advisories: the installed version of a web framework, read from
 * the lockfile, against a short table of published vulnerabilities that hit
 * the people Penthera is for (Next.js on Vercel, React Server Components).
 *
 * The runtime check (lib/advisories) reads PHP, nginx, Node and the like from
 * Dockerfiles and banners. Nothing read npm packages: a Next.js app on a
 * version with a known remote code execution or middleware bypass scanned
 * clean. This check reads what is installed, so a range in package.json
 * (`^15.5.0`) is never guessed: the lockfile says 15.5.6 or it says nothing.
 *
 * Lockfiles read: package-lock.json and npm-shrinkwrap.json (v1 to v3),
 * pnpm-lock.yaml (v5 to v9), yarn.lock (classic and berry), bun.lock. With no
 * lockfile, an exact pin in package.json (`"next": "15.5.6"`) counts, a range
 * does not. Every version of a package in the tree is checked, nested ones
 * too. A pre-release or canary build (`15.0.0-canary.12`) is not compared:
 * the advisories name release versions.
 *
 * The table ships with the release (rule 5: no run-time downloads). Each row
 * names its advisory so a reader can check the ranges.
 */
import { existsSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { parse as parseYaml } from "../vendor/yaml/index.js";
import { readRepoFile, isRefused } from "../fs-safe.js";
import { parseLockfile } from "../deps/lockfile.js";
import { parseJson } from "../json-text.js";
import { parseVersion, compareVersions } from "../advisories/versions.js";

export const FRAMEWORK_RULE = "framework-advisory";
// A lockfile over this is refused and the scan is incomplete, as deps does.
export const LOCKFILE_MAX_BYTES = 64 * 1024 * 1024;

/**
 * Affected versions as closed ranges [first, last] of release versions.
 * `needs`: a file that must exist for the bug to be reachable; without it the
 * row reports at `without` severity (the upgrade is still due).
 */
export const FRAMEWORK_ADVISORIES = [
  {
    id: "CVE-2025-55182",
    title: "React Server Components deserialisation lets a request run code on the server",
    packages: {
      next: [["15.0.0", "15.0.4"], ["15.1.0", "15.1.8"], ["15.2.0", "15.2.5"], ["15.3.0", "15.3.5"], ["15.4.0", "15.4.7"], ["15.5.0", "15.5.6"], ["16.0.0", "16.0.6"]],
      "react-server-dom-webpack": [["19.0.0", "19.0.0"], ["19.1.0", "19.1.1"], ["19.2.0", "19.2.0"]],
      "react-server-dom-turbopack": [["19.0.0", "19.0.0"], ["19.1.0", "19.1.1"], ["19.2.0", "19.2.0"]],
      "react-server-dom-parcel": [["19.0.0", "19.0.0"], ["19.1.0", "19.1.1"], ["19.2.0", "19.2.0"]],
    },
    fixed: { next: "15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7 or 16.0.7", "react-server-dom-webpack": "19.0.1, 19.1.2 or 19.2.1", "react-server-dom-turbopack": "19.0.1, 19.1.2 or 19.2.1", "react-server-dom-parcel": "19.0.1, 19.1.2 or 19.2.1" },
    severity: "critical",
    why: "An unauthenticated request to any Server Components or Server Actions endpoint can run code on the server (React advisory of 3 December 2025, also tracked by Next.js as CVE-2025-66478). Every App Router app is reachable.",
    source: "https://nextjs.org/blog/CVE-2025-66478",
  },
  {
    // Checked at the source on 22 Nov 2026 (Mythos E): nextjs.org/blog/security-update-2025-12-11
    // and react.dev's post of 11 December 2025 with its addendum of 26 January 2026.
    id: "CVE-2025-55184",
    title: "React Server Components: one request can hang the server or show Server Function code",
    packages: {
      next: [["13.3.0", "14.2.34"], ["15.0.0", "15.0.6"], ["15.1.0", "15.1.10"], ["15.2.0", "15.2.7"], ["15.3.0", "15.3.7"], ["15.4.0", "15.4.9"], ["15.5.0", "15.5.8"], ["16.0.0", "16.0.9"]],
      "react-server-dom-webpack": [["19.0.0", "19.0.3"], ["19.1.0", "19.1.4"], ["19.2.0", "19.2.3"]],
      "react-server-dom-turbopack": [["19.0.0", "19.0.3"], ["19.1.0", "19.1.4"], ["19.2.0", "19.2.3"]],
      "react-server-dom-parcel": [["19.0.0", "19.0.3"], ["19.1.0", "19.1.4"], ["19.2.0", "19.2.3"]],
    },
    fixed: { next: "14.2.35, 15.0.7, 15.1.11, 15.2.8, 15.3.8, 15.4.10, 15.5.9 or 16.0.10", "react-server-dom-webpack": "19.0.4, 19.1.5 or 19.2.4", "react-server-dom-turbopack": "19.0.4, 19.1.5 or 19.2.4", "react-server-dom-parcel": "19.0.4, 19.1.5 or 19.2.4" },
    severity: "high",
    needs: { files: ["app", "src/app"], without: "low", what: "App Router (`app` folder)" },
    why: "A crafted request to any App Router endpoint can loop forever and stop the server answering (CVE-2025-55184, completed as CVE-2025-67779), and on 15.x and 16.0 it can make a Server Function return the compiled code of others (CVE-2025-55183), with any secret written into that code. The versions that fixed CVE-2025-55182 (15.5.7 and the like) are still affected. The `react-server-dom-*` fixed versions also cover React's follow-up of 26 January 2026 (CVE-2026-23864).",
    source: "https://nextjs.org/blog/security-update-2025-12-11",
  },
  {
    id: "CVE-2025-29927",
    title: "Next.js middleware can be skipped with one request header",
    packages: {
      next: [["11.1.4", "12.3.4"], ["13.0.0", "13.5.8"], ["14.0.0", "14.2.24"], ["15.0.0", "15.2.2"]],
    },
    fixed: { next: "12.3.5, 13.5.9, 14.2.25 or 15.2.3" },
    severity: "high",
    needs: { files: ["middleware.ts", "middleware.js", "middleware.mjs", "src/middleware.ts", "src/middleware.js", "src/middleware.mjs"], without: "low", what: "a middleware file" },
    why: "A request that carries `x-middleware-subrequest` skips the middleware, so a login or paywall check written there never runs (Next.js advisory of 21 March 2025).",
    source: "https://nextjs.org/blog/cve-2025-29927",
  },
];

const WATCHED = new Set(FRAMEWORK_ADVISORIES.flatMap((a) => Object.keys(a.packages)));

/**
 * Line lookups for one lockfile, built in a single pass (Vercel DoS
 * 01M6YHC0DY36SDKCNAKEC8FN6B): searching and recounting from the start for each
 * package was quadratic on a lockfile full of nested copies. Line starts are
 * indexed once (binary search), and the first offset of each quoted string or
 * line-leading key that names a watched package is recorded once.
 */
function lockIndex(text) {
  const starts = [0];
  for (let k = text.indexOf("\n"); k !== -1; k = text.indexOf("\n", k + 1)) starts.push(k + 1);
  const lineAt = (i) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= i) lo = mid; else hi = mid - 1; }
    return lo + 1;
  };
  const watchedIn = (s) => {
    for (const name of WATCHED) if (s === name || s.endsWith(`/${name}`) || s.includes(`${name}@`) || s.includes(`/${name}/`)) return true;
    return false;
  };
  const first = new Map();
  // Quoted strings: `[^"\\\n]` cannot overlap the quotes, so the pass is linear.
  for (const m of text.matchAll(/"([^"\\\n]{1,2048})"/g)) if (!first.has(m[0]) && watchedIn(m[1])) first.set(m[0], m.index);
  // Line-leading YAML keys (pnpm): the text before the first `:` at the line's start, quotes dropped.
  for (let l = 0; l < starts.length; l++) {
    const end = l + 1 < starts.length ? starts[l + 1] - 1 : text.length;
    if (end - starts[l] > 4096) continue;
    let key = text.slice(starts[l], end).trim();
    const colon = key.indexOf(":");
    if (colon !== -1) key = key.slice(0, colon);
    key = key.replace(/^['"]|['"]$/g, "");
    if (key && !first.has(key) && watchedIn(key)) first.set(key, starts[l]);
  }
  return {
    lineAt,
    /** 1-based line of the first `needle` recorded in the index, or null. */
    lineOf: (needle) => (first.has(needle) ? lineAt(first.get(needle)) : null),
  };
}

/** Installed { name, version, line } for the watched packages, from each lockfile format. */
export function installedFromNpm(text) {
  const out = [];
  const ix = lockIndex(text);
  for (const p of parseLockfile(parseJson(text))) {
    if (WATCHED.has(p.name) && p.version) out.push({ name: p.name, version: p.version, line: ix.lineOf(`"${p.path}"`) || ix.lineOf(`"${p.name}"`) });
  }
  return out;
}

// pnpm keys: `/next@15.5.6`, `/next/15.5.6`, `next@15.5.6`, `next@15.5.6(react@19.0.0)`.
const PNPM_KEY = /^\/?((?:@[^/@]+\/)?[^/@()]+)[@/](\d[^()\s]*)/;
// The YAML parser builds a tree, and neither its memory nor its time is bounded by the file's
// size: 6 MiB of "[" took 4.5 GB and aborted the whole scan with no report, a dense 3.5 MiB
// file 2.5 GB, and 256 KB of commas in one flow list 70 s (final review of 2.5.0 and its blind
// review; checklist rows 4, 15 and 27). So a lockfile is read three ways, and any of them
// reports a package:
//   1. every `name@version` or `name/version` of a watched package anywhere in the text, in
//      one pass: no indent, quoting, flow style, comment, anchor or line ending can hide it;
//   2. the package keys, line by line;
//   3. the parser, on a small file only, after the shapes it is slow on are refused.
// What none of them can read (an escaped key, an explicit `? ` key, nesting no lockfile has)
// is refused, so the scan is incomplete and never clean.
export const PNPM_YAML_MAX_BYTES = 64 * 1024;
const PNPM_MAX_DEPTH = 32;
const PNPM_MAX_COMMAS = 200;
const PNPM_LINE_MAX = 4096;

// A watched name with a version right after it. Before the name: the start, a blank, a quote
// or flow punctuation, or the "/" of an old-style key (`/next@15.5.6`); never the "/" of a
// scope, so `@acme/next@15.5.8` is another package. Every repeat is capped: one linear pass.
const PNPM_TOKEN = new RegExp(String.raw`(?<=^|[\s'"{,(\[]|(?<![\w.@-])\/)(${[...WATCHED].map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})[@/](\d[^\s'":(){},\[\]]{0,100})`, "g");

/**
 * One pass over a pnpm lockfile's lines (ended by LF, CRLF or a lone CR): the package keys
 * (`  /next@15.5.6:`, `  'next@15.5.6(react@19.0.0)':`), and whether it says it is a lockfile
 * and has a packages or snapshots section. Returns null for a shape pnpm never writes and the
 * readers cannot vouch for: a flow collection left open at the end of a line or nested deeper
 * than a lockfile's, hundreds of commas on one line, deep "- - -" nesting, an explicit `? `
 * key, or a double-quoted string with an escape in it (`"ne\x78t@15.5.8"`).
 */
function pnpmShape(text) {
  const keys = [];
  let lockfile = false, header = false;
  let depth = 0, commas = 0, markers = 0, lineStart = true, quote = false, escape = false, at = 0;
  for (let i = 0; i <= text.length; i++) {
    const c = i < text.length ? text.charCodeAt(i) : 10;
    if (c === 10 || c === 13) {
      if (depth !== 0 || (quote && escape)) return null;
      if (i > at && i - at <= PNPM_LINE_MAX) {
        const line = text.slice(at, i);
        if (text.charCodeAt(at) === 32) {
          // A package key sits at an indent of two to four blanks and ends its line with ":".
          const key = line.trim();
          if (line.length - line.trimStart().length <= 4 && key.endsWith(":")) keys.push(key.slice(0, -1).replace(/^['"]|['"]$/g, ""));
        } else if (line.startsWith("lockfileVersion:")) lockfile = true;
        else if (line.startsWith("packages:") || line.startsWith("snapshots:")) header = true;
      }
      if (c === 13 && text.charCodeAt(i + 1) === 10) i++;
      at = i + 1; commas = 0; markers = 0; lineStart = true; quote = false; escape = false;
      continue;
    }
    if (c === 91 || c === 123) { if (++depth > PNPM_MAX_DEPTH) return null; } // [ {
    else if (c === 93 || c === 125) { if (depth > 0) depth--; } // ] }
    else if (c === 44) { if (++commas > PNPM_MAX_COMMAS) return null; } // ,
    else if (c === 34) quote = true;
    else if (c === 92) escape = true;
    if (lineStart) {
      const n = text.charCodeAt(i + 1);
      const marker = (c === 45 || c === 63) && (n === 32 || n === 9 || n === 10 || n === 13 || i + 1 === text.length);
      if (marker && c === 63) return null; // "? key": an explicit key
      if (marker) { if (++markers > PNPM_MAX_DEPTH) return null; } // "- - -": one nested list per marker
      else if (c !== 32 && c !== 9) lineStart = false;
    }
  }
  return { keys, lockfile, header };
}

export function installedFromPnpm(text) {
  const out = [];
  // Not the shape of a pnpm lockfile: named, and the scan is incomplete.
  const shape = pnpmShape(text);
  if (!shape) return null;
  let keys = shape.keys;
  if (text.length <= PNPM_YAML_MAX_BYTES) {
    let doc;
    try { doc = parseYaml(text, { maxAliasCount: 100, uniqueKeys: false }); } catch { return null; }
    keys = [...Object.keys(doc?.packages || {}), ...Object.keys(doc?.snapshots || {}), ...keys];
  } else if (!shape.lockfile || !shape.header || !shape.keys.length) {
    // Past the parser's cap nothing else proves the file is a lockfile: it has to say so, and
    // to hold a packages or snapshots section with entries a line reader can see.
    return null;
  }
  const seen = new Set();
  const ix = lockIndex(text);
  for (const key of keys) {
    const m = PNPM_KEY.exec(key);
    if (!m || !WATCHED.has(m[1]) || seen.has(`${m[1]}@${m[2]}`)) continue;
    seen.add(`${m[1]}@${m[2]}`);
    out.push({ name: m[1], version: m[2], line: ix.lineOf(key) });
  }
  for (const m of text.matchAll(PNPM_TOKEN)) {
    if (seen.has(`${m[1]}@${m[2]}`)) continue;
    seen.add(`${m[1]}@${m[2]}`);
    out.push({ name: m[1], version: m[2], line: ix.lineAt(m.index) });
  }
  return out;
}

// yarn classic: `"next@^15.5.0", next@15.5.6:` then `  version "15.5.6"`;
// yarn berry: `"next@npm:^15.5.0, next@npm:15.5.6":` then `  version: 15.5.6`.
export function installedFromYarn(text) {
  const out = [];
  const lines = text.split("\n");
  const seen = new Set();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line || /^\s|^#/.test(line) || !line.trimEnd().endsWith(":")) continue;
    const names = new Set();
    for (const part of line.trimEnd().slice(0, -1).split(",")) {
      const spec = part.trim().replace(/^"|"$/g, "");
      const at = spec.lastIndexOf("@");
      if (at <= 0) continue;
      names.add(spec.slice(0, at));
    }
    const watched = [...names].filter((n) => WATCHED.has(n));
    if (!watched.length) continue;
    for (let j = i + 1; j < lines.length && /^\s/.test(lines[j]); j++) {
      const v = /^\s+version:?\s+"?([^"\s]+)"?/.exec(lines[j]);
      if (!v) continue;
      for (const name of watched) {
        if (seen.has(`${name}@${v[1]}`)) continue;
        seen.add(`${name}@${v[1]}`);
        out.push({ name, version: v[1], line: j + 1 });
      }
      break;
    }
  }
  return out;
}

// bun.lock: `"next": ["next@15.5.6", ...]`, scoped and nested keys included.
const BUN_ENTRY = /\[\s*"((?:@[^/"]+\/)?[^@"/]+)@([^"]+)"/g;
export function installedFromBun(text) {
  const out = [];
  const seen = new Set();
  const ix = lockIndex(text);
  for (const m of text.matchAll(BUN_ENTRY)) {
    if (!WATCHED.has(m[1]) || seen.has(`${m[1]}@${m[2]}`)) continue;
    seen.add(`${m[1]}@${m[2]}`);
    out.push({ name: m[1], version: m[2], line: ix.lineAt(m.index) });
  }
  return out;
}

/** package.json exact pins only: a range says nothing about what is installed. */
export function installedFromPackageJson(text) {
  const out = [];
  let pkg;
  try { pkg = parseJson(text); } catch { return out; }
  const ix = lockIndex(text);
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    for (const [name, spec] of Object.entries(pkg?.[field] || {})) {
      if (WATCHED.has(name) && typeof spec === "string" && /^v?\d+\.\d+\.\d+$/.test(spec.trim())) {
        out.push({ name, version: spec.trim().replace(/^v/, ""), line: ix.lineOf(`"${name}"`) });
      }
    }
  }
  return out;
}

const LOCKFILES = [
  ["package-lock.json", installedFromNpm],
  ["npm-shrinkwrap.json", installedFromNpm],
  ["pnpm-lock.yaml", installedFromPnpm],
  ["yarn.lock", installedFromYarn],
  ["bun.lock", installedFromBun],
];

/** Is `version` a release inside one of `ranges`? Pre-releases and suffixed builds are never compared. */
export function inRanges(version, ranges) {
  const v = parseVersion(version);
  if (!v || v.pre || v.suffix || v.minor === null || v.patch === null) return false;
  return ranges.some(([lo, hi]) => compareVersions(v, lo) >= 0 && compareVersions(v, hi) <= 0);
}

// Never an app's own source, at any depth.
const WALK_SKIP = new Set(["node_modules", ".git"]);
// Tool output at the root only, and only the names no person gives a folder. `dist`, `build`
// and `out` are walked like any other: `build/web` or `apps/out` can be a workspace, and a
// folder name is no proof (blind review; checklist row 25).
const WALK_SKIP_AT_ROOT = new Set([".next", ".turbo", ".vercel"]);
const WALK_MAX_DIRS = 5000;
const WALK_MAX_DEPTH = 6;

/**
 * Does any folder below the root hold one of `files` (`app`, `src/middleware.ts`, ...)? In a
 * monorepo the lockfile sits at the root and the app in `apps/web`, so a look at the root
 * alone called a reachable bug "not reachable here" and lowered it from high to low (final
 * review of 2.5.0; checklist row 25). A lower severity needs proof: when the walk cannot
 * finish (too many folders, too deep, an unreadable folder, a link to a folder, which is not
 * followed), the answer is yes.
 */
function workspaceHas(root, files) {
  const queue = [[root, 0]];
  let seen = 0;
  for (let q = 0; q < queue.length; q++) {
    const [dir, depth] = queue[q];
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return true; }
    for (const e of entries) {
      if (WALK_SKIP.has(e.name) || (depth === 0 && WALK_SKIP_AT_ROOT.has(e.name))) continue;
      const sub = join(dir, e.name);
      if (e.isSymbolicLink()) {
        // A link to a folder (`apps/web -> ../web`) may hold the app: not followed, so not ruled out.
        let st = null;
        try { st = statSync(sub); } catch { /* a broken link holds nothing */ }
        if (st?.isDirectory()) return true;
        continue;
      }
      if (!e.isDirectory()) continue;
      if (files.some((f) => existsSync(join(sub, f)))) return true;
      if (depth + 1 >= WALK_MAX_DEPTH || ++seen > WALK_MAX_DIRS) return true;
      queue.push([sub, depth + 1]);
    }
  }
  return false;
}

/**
 * The advisory findings for a repository.
 * @param {string} repoPath
 * @param {{ refused?: object[] }} [opts] - a lockfile that could not be read is pushed to `refused` (a RefusedFileError)
 */
export function frameworkAdvisoriesForRepo(repoPath, { refused = [] } = {}) {
  const root = resolve(repoPath);
  const findings = [];
  let installed = [];
  let from = null;
  for (const [name, reader] of LOCKFILES) {
    const path = join(root, name);
    if (!existsSync(path)) continue;
    let text;
    try {
      text = readRepoFile(path, { root, label: name, maxBytes: LOCKFILE_MAX_BYTES });
    } catch (e) {
      if (isRefused(e)) { refused.push(e); continue; }
      if (e.code === "ENOENT") continue;
      // Unreadable (EACCES, EIO, ...): named, and the scan is incomplete, never a crash or a silent pass.
      refused.push({ path: path, reason: `it could not be read (${e.code || e.message})` });
      continue;
    }
    let list;
    try { list = reader(text); } catch { list = null; }
    if (list === null) {
      // A lockfile that does not parse is not a clean lockfile: named, and the scan is incomplete.
      refused.push({ path, reason: `it could not be parsed as a ${name} lockfile` });
      continue;
    }
    // One at a time: a lockfile with hundreds of thousands of entries would overflow a spread
    // into push() (Vercel 01M72FB3CQ25K7XSXGRQ3ET4HD) and abort the whole scan.
    for (const p of list) installed.push({ ...p, file: name });
    from ||= name;
  }
  if (!from) {
    const pj = join(root, "package.json");
    if (existsSync(pj)) {
      try {
        installed = installedFromPackageJson(readRepoFile(pj, { root, label: "package.json", maxBytes: 5 * 1024 * 1024 })).map((p) => ({ ...p, file: "package.json" }));
      } catch (e) {
        if (isRefused(e)) refused.push(e); else throw e;
      }
    }
  }
  if (!installed.length) return findings;

  const seen = new Set();
  for (const adv of FRAMEWORK_ADVISORIES) {
    // Lazily: the tree is walked only for a row with an affected package installed.
    let needed = null;
    const isNeeded = () => (needed ??= adv.needs ? adv.needs.files.some((f) => existsSync(join(root, f))) || workspaceHas(root, adv.needs.files) : true);
    for (const p of installed) {
      const ranges = adv.packages[p.name];
      if (!ranges || !inRanges(p.version, ranges)) continue;
      const key = `${adv.id}|${p.name}@${p.version}|${p.file}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const severity = isNeeded() ? adv.severity : adv.needs.without;
      const rel = relative(root, join(root, p.file)).split(sep).join("/");
      findings.push({
        severity,
        title: `${adv.title} (${p.name} ${p.version})`,
        description: `\`${rel}\` installs \`${p.name}@${p.version}\`, a version affected by ${adv.id}. ${adv.why}${isNeeded() ? "" : ` This project has no ${adv.needs.what}, so the bug is not reachable here; the upgrade is still due.`} Fixed in ${p.name} ${adv.fixed[p.name]}.`,
        remediation: `Upgrade \`${p.name}\` to ${adv.fixed[p.name]} (or later) and commit the updated lockfile. Advisory: ${adv.source}`,
        url: rel,
        file: rel,
        ...(p.line ? { line: p.line } : {}),
        templateId: FRAMEWORK_RULE,
        cve: adv.id,
        package: p.name,
        version: p.version,
        category: "cve",
        source: "static-analysis",
        confidence: "confirmed",
      });
    }
  }
  return findings;
}
