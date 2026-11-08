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
 * - supabase:     lib/whitebox/supabase.js: the SQL under supabase/migrations
 *                 and supabase/schemas (listed only when a repo has some)
 *
 * Source files that no code analysis read are the scan's blind spots. They are
 * listed (capped) so a reader, or a later model pass, knows where rules did not
 * look. Same repo and result in, same ledger out.
 */
import { readdirSync, lstatSync, existsSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { isSecretScanTarget, isSecretSkipDir, isRootOutputDir, isVirtualenv, MAX_SCAN_BYTES } from "./whitebox/secrets.js";
import { isRuntimePinFile, RUNTIME_PIN_SKIP_DIRS } from "./advisories/evidence.js";
import { isSinkSkipDir, sinkFileStatus, SINK_MAX_FILES } from "./whitebox/code-sinks.js";
import { MAX_SQL_BYTES } from "./whitebox/supabase.js";

export const COVERAGE_SCHEMA = "penthera.coverage/1";

// Folders no family reads: dependencies, framework output, virtualenvs. Counted, not walked.
const EXCLUDED_DIRS = new Set([
  "node_modules", ".next", ".security-results",
  "venv", ".venv", "site-packages", "__pycache__", ".tox", ".nox",
]);
// Build output, coverage, vendored code and reports (isRootOutputDir): the
// secret scan reads them, every rule below the repo root and only the
// fixed-shape rules at the root, and skips them when git ignores them. The
// other families do not count them, as before.
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
  "sink-file-cap": "past the eval and exec check's 5,000-file limit",
  "sink-skipped-folder": "in a folder the eval and exec check skips (tests, scripts, static assets, build output or a folder git ignores)",
  "not-read": "could not be read (a link, a FIFO, or past a cap)",
  "settings-file-cap": "past the settings check's 5,000-file limit",
  refused: "refused (a link out of the project, a device or a FIFO)",
  unreadable: "could not be read",
};

const FAMILIES = [
  { id: "secrets", label: "Secret scan" },
  { id: "routes", label: "Route and code-pattern analysis" },
  { id: "runtime-pins", label: "Runtime versions vs advisories" },
  { id: "code-sinks", label: "eval, vm and exec sinks" },
  // The fix planner's static checks (lib/fix probeRepoDetailed), run by every repo scan.
  { id: "app-settings", label: "Headers, cookies, CORS and login rate limits" },
  { id: "supabase", label: "Supabase migrations (row-level security)" },
];
const SUPABASE_SQL = /(?:^|\/)supabase\/(?:migrations|schemas)\/.+\.sql$/i;

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
  const rootOutputDirs = new Set();
  let truncated = false;
  const visit = (dir, depth, secretSkip, sinkSkip, outputDir = false) => {
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
        const output = isRootOutputDir(name);
        const skip = secretSkip || isSecretSkipDir(name) || ignoredDirs.has(full) || isVirtualenv(full);
        if (output && depth === 0 && !skip) rootOutputDirs.add(name);
        visit(full, depth + 1, skip, sinkSkip || isSinkSkipDir(name, full, ignoredDirs), outputDir || output);
      } else if (st.isFile()) {
        if (files.length >= MAX_FILES) { truncated = true; return; }
        files.push({ rel: relative(root, full).split(sep).join("/"), name, depth, size: st.size, secretSkip, sinkSkip, outputDir });
      }
    }
  };
  visit(root, 0, false, false);
  return { files, excludedDirs: [...excludedDirs].sort(), rootOutputDirs: [...rootOutputDirs].sort(), truncated };
}

/** Repo-relative paths the route analysis read, and whether it ran at all. */
function routeReads(root, result) {
  const surface = result?.attackSurface || [];
  if (!surface.length) return { ran: false, read: new Set(), mode: null };
  if (result.apiRoot) {
    // Next.js: route.js / route.ts under the API root; filePath is relative to apiRoot/../..
    const base = result.routeFilesFrom || resolve(result.apiRoot, "..", "..");
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
export function fileCoverage(repoPath, result, { ignored = null, settings = result?.settingsCoverage || null } = {}) {
  const root = resolve(repoPath);
  const { files, excludedDirs, rootOutputDirs, truncated } = walk(root, new Set([...(ignored?.dirs || [])].map((d) => resolve(d))));
  const routes = routeReads(root, result);
  const sinksRan = (result?.executedProbes || []).includes("code-sinks");
  const supabaseRan = (result?.executedProbes || []).includes("supabase");
  const supabaseRead = new Set(result?.supabase?.read || []);
  const settingsRead = settings ? new Set(settings.examined) : null;
  const map = new Map();
  let sinkFiles = 0;
  const minifiedSet = new Set(result?.sinkMinified || []);
  for (const f of files) {
    const language = f.outputDir ? null : languageOf(f.name);
    const secrets = f.secretSkip ? "skipped-folder"
      : isSecretScanTarget(f.rel) ? (f.size > MAX_SCAN_BYTES ? "too-large" : "examined") : "type-not-read";
    const pinFolders = f.rel.split("/").slice(0, -1);
    const runtimePins = !f.outputDir && isRuntimePinFile(f.name, f.depth) && !pinFolders.some((d) => RUNTIME_PIN_SKIP_DIRS.has(d))
      ? (f.size > RUNTIME_PIN_MAX_BYTES ? "too-large" : "examined")
      : null;
    let routeStatus = null;
    if (language) {
      if (!ROUTE_LANGUAGES.has(language)) routeStatus = "language-not-supported";
      else if (!routes.ran) routeStatus = "no-api-surface";
      else if (routes.mode === "next") routeStatus = routes.read.has(f.rel) ? "examined" : "not-a-route";
      else routeStatus = frameworkReads(f.rel) ? "examined" : "outside-route-folders";
    }
    const sinkStatus = sinksRan && !f.outputDir ? sinkFileStatus(f.name, f.size) : null;
    let codeSinks = sinkStatus && f.sinkSkip ? "sink-skipped-folder" : sinkStatus;
    if (codeSinks === "examined" && ++sinkFiles > SINK_MAX_FILES) codeSinks = "sink-file-cap";
    // Minified files are checked like any other (Red Team E23); they are only noted.
    const minified = codeSinks === "examined" && minifiedSet.has(f.rel);
    // Examined only if the Supabase check says it read the file; a refused one (a link, a FIFO) is "not-read".
    const supabase = !SUPABASE_SQL.test(f.rel) || f.secretSkip ? null
      : f.size > MAX_SQL_BYTES ? "too-large"
      : !supabaseRan || supabaseRead.has(f.rel) ? "examined" : "not-read";
    const appSettings = settingsRead?.has(f.rel) ? "examined" : null;
    map.set(f.rel, { language, size: f.size, secrets, routes: routeStatus, runtimePins, codeSinks, appSettings, supabase, ...(minified ? { minified: true } : {}) });
  }
  return { files: map, excludedDirs, rootOutputDirs, truncated, routesRan: routes.ran, sinksRan, settingsRan: Boolean(settings), supabaseRan };
}

/**
 * The ledger for a repo scan result, as stored in the JSON report.
 * @param {string} repoPath
 * @param {object} result - the scanRepo result
 */
export function buildCoverage(repoPath, result, { ignored = null, settings = result?.settingsCoverage || null } = {}) {
  const { files, excludedDirs, rootOutputDirs, truncated, routesRan, sinksRan, settingsRan, supabaseRan } = fileCoverage(repoPath, result, { ignored, settings });
  const keyOf = { secrets: "secrets", routes: "routes", "runtime-pins": "runtimePins", "code-sinks": "codeSinks", "app-settings": "appSettings", supabase: "supabase" };
  const ranOf = { routes: routesRan, "code-sinks": sinksRan, "app-settings": settingsRan, supabase: supabaseRan };
  // The Supabase family is listed only in a repo with migrations: elsewhere it has nothing to say.
  const hasSql = [...files.values()].some((e) => e.supabase);
  const families = FAMILIES.filter(({ id }) => (id !== "app-settings" || settingsRan) && (id !== "supabase" || hasSql)).map(({ id, label }) => {
    const skipped = {};
    let examined = 0;
    let minified = 0;
    for (const entry of files.values()) {
      const s = entry[keyOf[id]];
      if (s === "examined") { examined++; if (id === "code-sinks" && entry.minified) minified++; }
      else if (s) skipped[s] = (skipped[s] || 0) + 1;
    }
    if (id === "app-settings") {
      // The walk's own counts: files it refused or never reached are not in the per-file map.
      for (const [k, n] of Object.entries(settings.skipped || {})) if (n) skipped[k] = (skipped[k] || 0) + n;
      if (settings.over) skipped["settings-file-cap"] = settings.over;
    }
    const family = { id, label, ran: ranOf[id] ?? true, examined, skipped, ...(minified ? { minified } : {}) };
    // A file that is not a route was still read by the settings check: say so, so a
    // brief does not list it as unread.
    if (id === "routes" && settingsRan) {
      let n = 0;
      for (const e of files.values()) if (e.routes === "not-a-route" && e.appSettings === "examined") n++;
      if (n) family.notRouteReadBySettings = n;
    }
    return family;
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
    rootOutputDirs,
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
  if (cov.rootOutputDirs?.length) lines.push({ family: "Secret scan", text: `only the fixed-shape rules (key prefixes, private keys) in ${cov.rootOutputDirs.map((d) => d + "/").join(", ")} at the repo root; env files and shell scripts there got every rule` });
  return lines;
}
