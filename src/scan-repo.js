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
import { discoverAttackSurface, groupByTrustBoundary, findRiskyRoutes } from "../lib/attack-surface.js";
import { scanSecrets } from "../lib/whitebox/secrets.js";
import { gitIgnored } from "../lib/git.js";
import { scanCodeSinks } from "../lib/whitebox/code-sinks.js";
import { detectLibrary } from "../lib/whitebox/library.js";
import { discoverFrameworkRoutes } from "../lib/whitebox/frameworks.js";
import { runtimeAdvisoriesForRepo } from "../lib/advisories/index.js";
import { buildCoverage } from "../lib/coverage.js";

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
  const finish = () => {
    result.coverage = buildCoverage(repoPath, result, { ignored });
    result.duration = Date.now() - startTime;
    return result;
  };

  // ── Phase 1: Secret scanning (whole repo) ─────────────────────────────
  progress("Scanning for hardcoded secrets...");
  result.findings.push(...scanSecrets(repoPath, { ignored }));
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
  result.findings.push(...scanCodeSinks(repoPath, { library, ignored }));
  result.executedProbes.push("code-sinks");
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
  const apiRoot = opts.apiRoot || findApiRoot(repoPath);

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

  if (apiRoot) {
    // ── Phase 2: Discover attack surface ───────────────────────────────────
    progress("Discovering attack surface from filesystem...");
    result.apiRoot = apiRoot;
    result.attackSurface = discoverAttackSurface(apiRoot);
  }

  // An auto-detected routes/ or api/ folder without route.js/ts is an Express-style
  // app, not a Next.js one: fall back to the framework scan. --api-root is taken as given.
  if (result.attackSurface.length === 0 && !opts.apiRoot) {
    progress("Scanning for Express/Hono/Fastify routes...");
    const fwRoutes = discoverFrameworkRoutes(repoPath);
    if (fwRoutes.length > 0) {
      result.apiRoot = null;
      result.attackSurface = fwRoutes;
      result.findings.push({
        severity: "info",
        title: `Found ${fwRoutes.length} API routes (Express/Hono/Fastify)`,
        description: "Discovered via route pattern matching, not Next.js app/api.",
        category: "config",
        source: "framework-scan",
      });
    } else if (!apiRoot) {
      result.findings.push({
        severity: "info",
        title: "No API routes directory found",
        description: `Searched Next.js, Express, Hono, and Fastify patterns in ${repoPath}. Use --api-root to specify.`,
        category: "config",
        source: "repo-scan",
      });
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
        description: `Calls ${route.externalCalls.join(", ")} \u2014 abuse/cost vector`,
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

  for (const route of risky) {
    const risks = route.securityPatterns.filter((p) => p.startsWith("RISK:"));
    for (const risk of risks) {
      const name = risk.replace("RISK:", "");
      const sevMap = {
        eval: "high",
        innerHTML: "high",
        "command-injection": "critical",
        "error-leak": "low",
        "cors-wildcard": "medium",
        "json-parse-unguarded": "low",
      };
      result.findings.push({
        severity: sevMap[name] || "medium",
        title: `${name} in ${route.url}`,
        description: `Detected in ${route.filePath}`,
        url: route.url,
        file: repoRelative(route.filePath),
        pattern: name,
        category: "code-pattern",
        source: "static-analysis",
      });
    }
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
