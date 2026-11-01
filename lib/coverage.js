/**
 * Coverage ledger for a repo scan: what each check family read, and what it
 * did not read and why.
 *
 * A clean report only means something next to a list of what was looked at.
 * The ledger walks the repo once (no file contents are read, only names and
 * sizes) and asks each family's own file filter whether it read the file:
 *
 * - secrets:      lib/whitebox/secrets.js (isSecretScanTarget, isSecretSkipDir,
 *                 isVirtualenv, MAX_SCAN_BYTES) plus the folders git ignores
 * - routes:       route discovery plus the trust-boundary and risky-pattern
 *                 checks over the discovered routes (src/scan-repo.js)
 * - runtime-pins: lib/advisories/evidence.js (isRuntimePinFile)
 * - code-sinks:   lib/whitebox/code-sinks.js (isSinkSkipDir, sinkFileStatus)
 *
 * Source files that no code analysis read are the scan's blind spots. They are
 * listed (capped) so a reader, or a later model pass, knows where rules did not
 * look. Same repo and result in, same ledger out.
 */
import { readdirSync, lstatSync, existsSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { isSecretScanTarget, isSecretSkipDir, isVirtualenv, MAX_SCAN_BYTES } from "./whitebox/secrets.js";
import { isRuntimePinFile, RUNTIME_PIN_SKIP_DIRS } from "./advisories/evidence.js";
import { isSinkSkipDir, sinkFileStatus } from "./whitebox/code-sinks.js";

export const COVERAGE_SCHEMA = "penthera.coverage/1";

// Folders no family reads: dependencies, build output, virtualenvs. Counted, not walked.
const EXCLUDED_DIRS = new Set([
  "node_modules", "dist", "build", ".next", "coverage", "reports", ".security-results", "vendor",
  "venv", ".venv", "site-packages", "__pycache__", ".tox", ".nox",
]);
const MAX_FILES = 50_000;
const MAX_LISTED = 200;
const RUNTIME_PIN_MAX_BYTES = 256 * 1024;

// Source languages, by extension. Route and code-pattern analysis reads JS and TS only.
const LANGUAGES = {
  ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
  ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
  ".py": "Python", ".rb": "Ruby", ".go": "Go", ".java": "Java", ".kt": "Kotlin", ".php": "PHP",
  ".cs": "C#", ".rs": "Rust", ".swift": "Swift", ".scala": "Scala", ".ex": "Elixir", ".exs": "Elixir",
  ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
};
const ROUTE_LANGUAGES = new Set(["JavaScript", "TypeScript"]);
const FRAMEWORK_ROUTE_DIRS = ["routes", "src/routes", "api", "src/api", "server/routes", "src/server/routes"];
const FRAMEWORK_ENTRY_FILES = new Set(["server.js", "server.ts", "index.js", "index.ts", "app.js", "app.ts", "src/index.ts"]);
const FRAMEWORK_SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage", "vendor"]);

export const REASONS = {
  "too-large": "over the size limit",
  "skipped-folder": "in a folder the secret scan skips (a virtualenv, a tool cache or a folder git ignores)",
  "type-not-read": "file type not read",
  "no-api-surface": "no API routes found, so route analysis did not run",
  "outside-route-folders": "not in a route folder or server entry file",
  "not-a-route": "not a route file",
  "language-not-supported": "language not supported by route analysis",
  "sink-skipped-folder": "in a folder the eval and exec check skips (tests, scripts, static assets, build output or a folder git ignores)",
};

const FAMILIES = [
  { id: "secrets", label: "Secret scan" },
  { id: "routes", label: "Route and code-pattern analysis" },
  { id: "runtime-pins", label: "Runtime versions vs advisories" },
  { id: "code-sinks", label: "eval, vm and exec sinks" },
];

/** Families a repo scan does not run; each has its own command. */
const NOT_RUN = [
  { id: "deps", label: "Dependency behaviour", command: "penthera deps <path>" },
  { id: "agents", label: "AI agent config", command: "penthera agents <path>" },
];

function languageOf(name) {
  const dot = name.lastIndexOf(".");
  return dot > 0 ? LANGUAGES[name.slice(dot).toLowerCase()] || null : null;
}

/**
 * Every regular file under root: { rel, name, depth, size, secretSkip }. Same
 * skips as the scanners: no symlinks, no nested repos. secretSkip marks a file
 * in a folder the secret scan does not enter; `ignoredDirs` are the absolute
 * paths of the folders git ignores (gitIgnored().dirs), if known.
 */
function walk(root, ignoredDirs = new Set()) {
  const files = [];
  const excludedDirs = new Set();
  let truncated = false;
  const visit = (dir, depth, secretSkip, sinkSkip) => {
    if (truncated) return;
    if (dir !== root && existsSync(join(dir, ".git"))) return;
    let entries;
    try { entries = readdirSync(dir); } catch { return; }
    for (const name of entries.sort()) {
      if (name === ".git") continue;
      const full = join(dir, name);
      let st;
      try { st = lstatSync(full); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) {
        if (EXCLUDED_DIRS.has(name)) { excludedDirs.add(name); continue; }
        visit(full, depth + 1, secretSkip || isSecretSkipDir(name) || ignoredDirs.has(full) || isVirtualenv(full), sinkSkip || isSinkSkipDir(name, full, ignoredDirs));
      } else if (st.isFile()) {
        if (files.length >= MAX_FILES) { truncated = true; return; }
        files.push({ rel: relative(root, full).split(sep).join("/"), name, depth, size: st.size, secretSkip, sinkSkip });
      }
    }
  };
  visit(root, 0, false, false);
  return { files, excludedDirs: [...excludedDirs].sort(), truncated };
}

/** Repo-relative paths the route analysis read, and whether it ran at all. */
function routeReads(root, result) {
  const surface = result?.attackSurface || [];
  if (!surface.length) return { ran: false, read: new Set(), mode: null };
  if (result.apiRoot) {
    // Next.js: route.js / route.ts under the API root; filePath is relative to apiRoot/../..
    const base = resolve(result.apiRoot, "..", "..");
    const read = new Set(surface.map((r) => relative(root, resolve(base, r.filePath)).split(sep).join("/")));
    return { ran: true, read, mode: "next" };
  }
  // Express / Hono / Fastify: every JS file in the route folders plus the server entry files was read.
  return { ran: true, read: null, mode: "framework" };
}

function frameworkReads(rel) {
  if (FRAMEWORK_ENTRY_FILES.has(rel)) return true;
  if (!/\.(js|ts|mjs|cjs)$/.test(rel)) return false;
  const inDir = FRAMEWORK_ROUTE_DIRS.find((d) => rel.startsWith(d + "/"));
  if (!inDir) return false;
  return !rel.slice(inDir.length + 1).split("/").slice(0, -1).some((d) => FRAMEWORK_SKIP.has(d));
}

/**
 * Per-file coverage: Map of repo-relative path → { language, secrets, routes, runtimePins }.
 * Each family value is "examined", a REASONS key, or null when the family does not apply.
 * `codeSinks` is null when the scan did not run the eval and exec check.
 * @param {string} repoPath
 * @param {object} result - the scanRepo result (attackSurface, apiRoot)
 */
export function fileCoverage(repoPath, result, { ignored = null } = {}) {
  const root = resolve(repoPath);
  const { files, excludedDirs, truncated } = walk(root, new Set([...(ignored?.dirs || [])].map((d) => resolve(d))));
  const routes = routeReads(root, result);
  const sinksRan = (result?.executedProbes || []).includes("code-sinks");
  const map = new Map();
  for (const f of files) {
    const language = languageOf(f.name);
    const secrets = f.secretSkip ? "skipped-folder"
      : isSecretScanTarget(f.rel) ? (f.size > MAX_SCAN_BYTES ? "too-large" : "examined") : "type-not-read";
    const pinFolders = f.rel.split("/").slice(0, -1);
    const runtimePins = isRuntimePinFile(f.name, f.depth) && !pinFolders.some((d) => RUNTIME_PIN_SKIP_DIRS.has(d))
      ? (f.size > RUNTIME_PIN_MAX_BYTES ? "too-large" : "examined")
      : null;
    let routeStatus = null;
    if (language) {
      if (!ROUTE_LANGUAGES.has(language)) routeStatus = "language-not-supported";
      else if (!routes.ran) routeStatus = "no-api-surface";
      else if (routes.mode === "next") routeStatus = routes.read.has(f.rel) ? "examined" : "not-a-route";
      else routeStatus = frameworkReads(f.rel) ? "examined" : "outside-route-folders";
    }
    const sinkStatus = sinksRan ? sinkFileStatus(f.name, f.size) : null;
    const codeSinks = sinkStatus && f.sinkSkip ? "sink-skipped-folder" : sinkStatus;
    map.set(f.rel, { language, size: f.size, secrets, routes: routeStatus, runtimePins, codeSinks });
  }
  return { files: map, excludedDirs, truncated, routesRan: routes.ran, sinksRan };
}

/**
 * The ledger for a repo scan result, as stored in the JSON report.
 * @param {string} repoPath
 * @param {object} result - the scanRepo result
 */
export function buildCoverage(repoPath, result, { ignored = null } = {}) {
  const { files, excludedDirs, truncated, routesRan, sinksRan } = fileCoverage(repoPath, result, { ignored });
  const keyOf = { secrets: "secrets", routes: "routes", "runtime-pins": "runtimePins", "code-sinks": "codeSinks" };
  const ranOf = { routes: routesRan, "code-sinks": sinksRan };
  const families = FAMILIES.map(({ id, label }) => {
    const skipped = {};
    let examined = 0;
    for (const entry of files.values()) {
      const s = entry[keyOf[id]];
      if (s === "examined") examined++;
      else if (s) skipped[s] = (skipped[s] || 0) + 1;
    }
    return { id, label, ran: ranOf[id] ?? true, examined, skipped };
  });

  const languages = new Map();
  const blind = [];
  const blindByReason = {};
  for (const [rel, e] of files) {
    if (!e.language) continue;
    const l = languages.get(e.language) || { language: e.language, files: 0, analysed: 0 };
    l.files++;
    if (e.routes === "examined") l.analysed++;
    else {
      blind.push(rel);
      blindByReason[e.routes] = (blindByReason[e.routes] || 0) + 1;
    }
    languages.set(e.language, l);
  }
  const sourceFiles = [...languages.values()].reduce((n, l) => n + l.files, 0);

  return {
    schema: COVERAGE_SCHEMA,
    files: files.size,
    truncated,
    excludedDirs,
    sourceFiles,
    sourceFilesAnalysed: sourceFiles - blind.length,
    families,
    notRun: NOT_RUN,
    languages: [...languages.values()].sort((a, b) => b.files - a.files || a.language.localeCompare(b.language)),
    blindSpots: { count: blind.length, byReason: blindByReason, paths: blind.slice(0, MAX_LISTED), listed: Math.min(blind.length, MAX_LISTED) },
  };
}

/** One line per family and the blind-spot summary, for the terminal and Markdown. */
export function describeCoverage(cov) {
  const lines = [];
  for (const f of cov.families) {
    if (!f.ran) {
      lines.push({ family: f.label, text: f.id === "routes" ? "did not run (no API routes found)" : "did not run" });
      continue;
    }
    const skipped = Object.entries(f.skipped).map(([r, n]) => `${n} ${REASONS[r] || r}`).join(", ");
    lines.push({ family: f.label, text: `${f.examined} file${f.examined === 1 ? "" : "s"} read${skipped ? `; not read: ${skipped}` : ""}` });
  }
  if (cov.excludedDirs?.includes("reports")) lines.push({ family: "Folder not read", text: "every folder named reports, at any depth (treated as Penthera's own output)" });
  return lines;
}
