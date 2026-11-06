/**
 * Penthera, Repo Scanner (white-box)
 *
 * Analyzes source code for security patterns:
 *   1. Auto-detect API route directory (Next.js App/Pages Router)
 *   2. Discover attack surface from filesystem
 *   3. Classify trust boundaries
 *   4. Detect risky code patterns
 */
import { existsSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { discoverAttackSurface, groupByTrustBoundary, findRiskyRoutes, findRouteFiles, routeRecord } from "../lib/attack-surface.js";
import { scanSecrets } from "../lib/whitebox/secrets.js";
import { gitIgnored } from "../lib/git.js";
import { scanCodeSinks } from "../lib/whitebox/code-sinks.js";
import { scanWorkflows } from "../lib/whitebox/workflows.js";
import { detectLibrary } from "../lib/whitebox/library.js";
import { discoverFrameworkRoutes } from "../lib/whitebox/frameworks.js";
import { runtimeAdvisoriesForRepo } from "../lib/advisories/index.js";
import { buildCoverage } from "../lib/coverage.js";
import { readRepoFile, isRefused } from "../lib/fs-safe.js";

/** Source and config files the route scan reads are capped at 5 MiB. */
const SOURCE_MAX_BYTES = 5 * 1024 * 1024;

/** A file the route scan would have read but refused: a link out, a device, a FIFO, too large. */
function refusedFileFinding(e, repoPath) {
  const name = relative(resolve(repoPath), resolve(repoPath, e.path)).split(sep).join("/") || e.path;
  if (e.partial) {
    return {
      severity: "info",
      title: `File not fully checked: ${name}`,
      description: `\`${name}\` was read, but ${e.reason}. The scan is incomplete and exits 2.`,
      url: name,
      file: name,
      category: "config",
      source: "repo-scan",
    };
  }
  return {
    severity: "info",
    title: `File not read: ${name}`,
    description: `\`${name}\` was not read because ${e.reason}, so what it holds was not checked. The scan is incomplete and exits 2. Make it a regular file inside the project.`,
    url: name,
    file: name,
    category: "config",
    source: "repo-scan",
  };
}

/**
 * A Next.js app folder with a route handler outside app/api, such as
 * app/auth/confirm/route.ts: then the whole app folder is the API root.
 */
function nextAppRoot(repoPath) {
  for (const app of ["app", "src/app"]) {
    const dir = join(repoPath, app);
    const api = join(dir, "api") + sep;
    if (findRouteFiles(dir).some((f) => !f.startsWith(api))) return dir;
  }
  return null;
}

/**
 * A Worker's or Bun's `export default { fetch }` entry: one route that answers every path.
 * The entry is wrangler's `main`, or a usual entry file.
 */
function workerRoutes(repoPath, refused = []) {
  const entries = ["src/index.ts", "src/index.js", "src/worker.ts", "src/worker.js", "index.ts", "index.js"];
  const read = (rel) => {
    try {
      return readRepoFile(join(repoPath, rel), { root: repoPath, label: rel, maxBytes: SOURCE_MAX_BYTES });
    } catch (e) {
      if (isRefused(e)) refused.push(e);
      return null; // absent
    }
  };
  for (const name of ["wrangler.jsonc", "wrangler.json", "wrangler.toml"]) {
    const text = read(name);
    const main = text == null ? null : /["']?main["']?\s*[:=]\s*["']([^"']+)["']/.exec(text)?.[1];
    if (main) entries.unshift(main.replace(/^\.\//, ""));
  }
  for (const entry of entries) {
    const source = read(entry);
    if (source == null) continue;
    if (/export\s+default\s*\{[\s\S]*?\bfetch\s*(?:\(|:|=)/.test(source)) return [{ ...routeRecord("/*", entry, source, ["ALL"]), framework: "fetch" }];
  }
  return [];
}

/** Auto-detect API routes directory (Next.js, Express-style, etc.). */
function findApiRoot(repoPath) {
  const candidates = [
    "app/api",
    "src/app/api",
    "pages/api",
    "src/pages/api",
    "routes",
    "src/routes",
    "server/routes",
    "api",
    "src/api",
    "src/server/routes",
  ];
  for (const candidate of candidates) {
    const full = join(repoPath, candidate);
    if (existsSync(full)) return full;
  }
  return null;
}

/**
 * Run a white-box scan against a local repository.
 *
 * @param {string} repoPath - Path to the repository root
 * @param {object} opts - { apiRoot, onPhase, library }; library: true (--library),
 *   false (--no-library), or undefined to decide from package.json
 * @returns {object} Scan result with findings
 */
export async function scanRepo(repoPath, opts = {}) {
  if (!existsSync(repoPath)) throw new Error(`Path not found: ${repoPath}`);
  const progress = opts.onPhase || (() => {});
  const startTime = Date.now();

  const result = {
    target: repoPath,
    mode: "repo",
    timestamp: new Date().toISOString(),
    duration: 0,
    apiRoot: null,
    attackSurface: [],
    boundaries: {},
    executedProbes: [],
    findings: [],
  };
  // What git ignores here: the secret scan skips ignored folders and marks
  // hits in ignored files as local only, and the ledger says so.
  const ignored = gitIgnored(repoPath);
  // Every return goes through here: the ledger says what was read, including
  // when route analysis found nothing to read.
  // A refused file (a link out, a device, a FIFO, over the size cap) is an info
  // finding and makes the run incomplete, so it exits 2 (src/report/exit.js):
  // a route file too large to read must never pass as clean.
  const named = new Set();
  const noteRefused = (e) => {
    const f = refusedFileFinding(e, repoPath);
    if (named.has(f.file)) return;
    named.add(f.file);
    result.findings.push(f);
    (result.incomplete ||= []).push({ file: f.file, reason: e.reason || e.message });
  };

  const finish = () => {
    result.coverage = buildCoverage(repoPath, result, { ignored });
    delete result.sinkMinified; // in the coverage ledger now
    result.duration = Date.now() - startTime;
    return result;
  };

  // ── Phase 1: Secret scanning (whole repo) ─────────────────────────────
  progress("Scanning for hardcoded secrets...");
  // So is a file the secret scan could not read (a FIFO, a device, over 512 MiB).
  const secretRefused = [];
  result.findings.push(...scanSecrets(repoPath, { ignored, refused: secretRefused }));
  for (const e of secretRefused) noteRefused(e);
  result.executedProbes.push("secret-scanning");

  // ── Phase 1b: Runtime pins (Dockerfile, .tool-versions, ...) vs advisories
  progress("Checking pinned runtime versions against advisories...");
  result.findings.push(...runtimeAdvisoriesForRepo(repoPath));
  result.executedProbes.push("runtime-advisories");

  // ── Phase 1c: Code-execution sinks (all server code, not just routes) ──
  progress("Looking for eval, vm and exec sinks...");
  // Library mode: a publishable package's exported parameters are sources too.
  const library = detectLibrary(repoPath, opts.library);
  result.library = { enabled: library.enabled, reason: library.reason };
  if (library.refused) noteRefused(library.refused);
  // A code file the sink check could not read is named and makes the run incomplete.
  const sinkRefused = [];
  // Minified files are checked too; the coverage ledger notes how many.
  result.sinkMinified = [];
  result.findings.push(...scanCodeSinks(repoPath, { library, ignored, refused: sinkRefused, minified: result.sinkMinified }));
  for (const e of sinkRefused) noteRefused(e);
  result.executedProbes.push("code-sinks");

  // ── Phase 1d: GitHub Actions workflows (.github/workflows) ────────────
  progress("Checking GitHub Actions workflows...");
  result.findings.push(...scanWorkflows(repoPath));
  result.executedProbes.push("ci-workflows");
  if (library.enabled) {
    result.executedProbes.push("library-mode");
    result.findings.push({
      severity: "info",
      title: "Library mode: exported functions' parameters count as untrusted",
      description: `Scanned as a library (${library.reason}). A shell command built from a parameter of an exported function is reported at potential confidence, since the caller decides what it holds.${library.reason === "--library" ? "" : " Use --no-library to scan it as an app."}`,
      category: "config",
      source: "repo-scan",
    });
  }

  // ── Phase 2: Locate API root ───────────────────────────────────────────
  progress("Locating API routes directory...");
  const appRoot = opts.apiRoot ? null : nextAppRoot(repoPath);
  const apiRoot = opts.apiRoot || appRoot || findApiRoot(repoPath);

  if (opts.apiRoot && !existsSync(apiRoot)) {
    result.findings.push({
      severity: "info",
      title: `API root not found: ${apiRoot}`,
      description: "The specified --api-root path does not exist.",
      category: "config",
      source: "repo-scan",
    });
    return finish();
  }

  // Files the route scan would have read but refused: one info finding per file,
  // and the run is incomplete (noteRefused). Never a silent pass.
  const refused = [];
  const reportRefused = () => {
    for (const e of refused.splice(0)) noteRefused(e);
  };

  if (apiRoot) {
    // ── Phase 2: Discover attack surface ───────────────────────────────────
    progress("Discovering attack surface from filesystem...");
    result.apiRoot = apiRoot;
    // A Next.js app folder: URLs come from its folders, and file paths are the repo's.
    if (appRoot) result.routeFilesFrom = repoPath;
    result.attackSurface = appRoot
      ? discoverAttackSurface(apiRoot, { appDir: appRoot, repoRoot: repoPath, refused })
      : discoverAttackSurface(apiRoot, { refused });
    reportRefused();
  }

  // An auto-detected routes/ or api/ folder without route.js/ts is an Express-style
  // app, not a Next.js one: fall back to the framework scan. --api-root is taken as given.
  if (result.attackSurface.length === 0 && !opts.apiRoot) {
    progress("Scanning for Express/Hono/Fastify routes...");
    // How many routes it found, or that it found none, is coverage (lib/coverage.js), not a finding.
    const fwRoutes = discoverFrameworkRoutes(repoPath, { refused });
    const found = fwRoutes.length ? fwRoutes : workerRoutes(repoPath, refused);
    reportRefused();
    if (found.length > 0) {
      result.apiRoot = null;
      result.attackSurface = found;
    } else if (!apiRoot) {
      return finish();
    }
  }

  if (result.attackSurface.length === 0) {
    result.findings.push({
      severity: "info",
      title: "No API routes found",
      description: `No route.js/ts files found under ${apiRoot}`,
      category: "config",
      source: "repo-scan",
    });
    return finish();
  }

  // ── Phase 3: Trust boundary analysis ───────────────────────────────────
  progress("Classifying trust boundaries...");
  result.boundaries = groupByTrustBoundary(result.attackSurface);

  // Flag public routes that call external services without rate limiting
  for (const route of result.boundaries.public || []) {
    if (route.externalCalls.length > 0 && !route.auth.includes("rate-limited")) {
      result.findings.push({
        severity: "medium",
        title: `Public endpoint without rate limiting: ${route.url}`,
        description: `This route's file calls ${route.externalCalls.join(", ")}, so abuse can cost you money.`,
        url: route.url,
        category: "rate-limiting",
        source: "trust-boundary",
      });
    }
  }

  // Flag routes with no auth that probably need it (heuristic: has user inputs)
  for (const route of result.boundaries.public || []) {
    if (route.inputs.length > 3) {
      result.findings.push({
        severity: "low",
        title: `Public route accepts many inputs: ${route.url}`,
        description: `Inputs: ${route.inputs.join(", ")} \u2014 verify auth is intentionally absent`,
        url: route.url,
        category: "auth",
        source: "trust-boundary",
      });
    }
  }

  // Route file paths are relative to the repo for framework routes, and to
  // apiRoot/../.. for Next.js routes; findings carry the repo-relative path.
  const repoRelative = (filePath) => {
    const abs = result.apiRoot ? resolve(result.apiRoot, "..", "..", filePath) : resolve(repoPath, filePath);
    return relative(resolve(repoPath), abs).split(sep).join("/");
  };

  // ── Phase 4: Risky pattern detection ───────────────────────────────────
  progress("Detecting risky code patterns...");
  const risky = findRiskyRoutes(result.attackSurface);

  // These patterns match a whole file, so a file with six routes gets one
  // finding, not six: nothing says which route holds the sink.
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const sevMap = {
    eval: "high",
    innerHTML: "high",
    "command-injection": "critical",
    "error-leak": "low",
    "cors-wildcard": "medium",
    "json-parse-unguarded": "low",
  };
  const perFile = new Map();
  // The sink scan reads these files too, and it can tell what reaches the sink.
  const sinks = new Map(result.findings.filter((f) => f.category === "code-pattern").map((f) => [`${f.file}|${f.pattern}`, f]));
  for (const route of risky) {
    for (const risk of route.securityPatterns.filter((p) => p.startsWith("RISK:"))) {
      const name = risk.replace("RISK:", "");
      const file = repoRelative(route.filePath);
      const key = `${file}|${name}`;
      if (perFile.has(key)) {
        perFile.get(key).routes.add(route.url);
        continue;
      }
      const severity = sevMap[name] || "medium";
      // A sink finding stands in for the route's only if it says as much, or a real bug would lose its severity.
      if (sinks.has(key) && SEVERITIES.indexOf(sinks.get(key).severity) <= SEVERITIES.indexOf(severity)) {
        perFile.set(key, { sink: sinks.get(key), routes: new Set([route.url]) });
        continue;
      }
      const finding = {
        severity,
        title: `${name} in ${route.url}`,
        url: route.url,
        file,
        pattern: name,
        category: "code-pattern",
        source: "static-analysis",
      };
      perFile.set(key, { finding, routes: new Set([route.url]), filePath: route.filePath });
      result.findings.push(finding);
    }
  }
  for (const { finding, sink, routes, filePath } of perFile.values()) {
    const list = `${routes.size} route${routes.size === 1 ? "" : "s"}: ${[...routes].slice(0, 10).join(", ")}`;
    if (sink) sink.description = `${sink.description} This file serves ${list}.`;
    else finding.description = routes.size > 1 ? `Detected in ${filePath}, which serves ${list}. The pattern matches the file, not one route.` : `Detected in ${filePath}`;
  }

  // Check: more public than admin routes is a smell
  const pub = (result.boundaries.public || []).length;
  const adm = (result.boundaries.adminAuth || []).length;
  if (pub > adm && adm > 0) {
    result.findings.push({
      severity: "info",
      title: `More public routes (${pub}) than admin routes (${adm})`,
      description: "Review if all public endpoints should truly be unauthenticated",
      category: "auth",
      source: "trust-boundary",
    });
  }

  // Route analysis and risky-pattern detection ran (this point is only reached
  // when an API surface was found; the no-routes paths return earlier).
  result.executedProbes.push("trust-boundary", "risky-patterns");

  return finish();
}
