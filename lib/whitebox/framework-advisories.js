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
import { existsSync } from "node:fs";
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
export function installedFromPnpm(text) {
  const out = [];
  let doc;
  try { doc = parseYaml(text, { maxAliasCount: 100, uniqueKeys: false }); } catch { return null; }
  const keys = [...Object.keys(doc?.packages || {}), ...Object.keys(doc?.snapshots || {})];
  const seen = new Set();
  const ix = lockIndex(text);
  for (const key of keys) {
    const m = PNPM_KEY.exec(key);
    if (!m || !WATCHED.has(m[1]) || seen.has(`${m[1]}@${m[2]}`)) continue;
    seen.add(`${m[1]}@${m[2]}`);
    out.push({ name: m[1], version: m[2], line: ix.lineOf(key) });
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
    const needed = adv.needs ? adv.needs.files.some((f) => existsSync(join(root, f))) : true;
    for (const p of installed) {
      const ranges = adv.packages[p.name];
      if (!ranges || !inRanges(p.version, ranges)) continue;
      const key = `${adv.id}|${p.name}@${p.version}|${p.file}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const severity = needed ? adv.severity : adv.needs.without;
      const rel = relative(root, join(root, p.file)).split(sep).join("/");
      findings.push({
        severity,
        title: `${adv.title} (${p.name} ${p.version})`,
        description: `\`${rel}\` installs \`${p.name}@${p.version}\`, a version affected by ${adv.id}. ${adv.why}${needed ? "" : ` This project has no ${adv.needs.what}, so the bug is not reachable here; the upgrade is still due.`} Fixed in ${p.name} ${adv.fixed[p.name]}.`,
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
