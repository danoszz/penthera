/**
 * Penthera — Repo Scanner (white-box)
 *
 * Analyzes source code for security patterns:
 *   1. Auto-detect API route directory (Next.js App/Pages Router)
 *   2. Discover attack surface from filesystem
 *   3. Classify trust boundaries
 *   4. Detect risky code patterns
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import { discoverAttackSurface, groupByTrustBoundary, findRiskyRoutes } from "../lib/attack-surface.js";
import { scanSecrets } from "../lib/whitebox/secrets.js";
import { discoverFrameworkRoutes } from "../lib/whitebox/frameworks.js";

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
 * @param {object} opts - { apiRoot, onPhase }
 * @returns {object} Scan result with findings
 */
export async function scanRepo(repoPath, opts = {}) {
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
    findings: [],
  };

  // ── Phase 1: Secret scanning (whole repo) ─────────────────────────────
  progress("Scanning for hardcoded secrets...");
  result.findings.push(...scanSecrets(repoPath));

  // ── Phase 2: Locate API root ───────────────────────────────────────────
  progress("Locating API routes directory...");
  const apiRoot = opts.apiRoot || findApiRoot(repoPath);
  let useFrameworkScan = false;

  if (!apiRoot) {
    progress("Scanning for Express/Hono/Fastify routes...");
    const fwRoutes = discoverFrameworkRoutes(repoPath);
    if (fwRoutes.length > 0) {
      result.attackSurface = fwRoutes;
      result.boundaries = groupByTrustBoundary(fwRoutes);
      result.findings.push({
        severity: "info",
        title: `Found ${fwRoutes.length} API routes (Express/Hono/Fastify)`,
        description: "Discovered via route pattern matching — not Next.js app/api.",
        category: "config",
        source: "framework-scan",
      });
      useFrameworkScan = true;
    } else {
      result.findings.push({
        severity: "info",
        title: "No API routes directory found",
        description: `Searched Next.js, Express, Hono, and Fastify patterns in ${repoPath}. Use --api-root to specify.`,
        category: "config",
        source: "repo-scan",
      });
      result.duration = Date.now() - startTime;
      return result;
    }
  } else if (!existsSync(apiRoot)) {
    result.findings.push({
      severity: "info",
      title: `API root not found: ${apiRoot}`,
      description: "The specified --api-root path does not exist.",
      category: "config",
      source: "repo-scan",
    });
    result.duration = Date.now() - startTime;
    return result;
  }

  if (!useFrameworkScan) {
    result.apiRoot = apiRoot;

    // ── Phase 2: Discover attack surface ───────────────────────────────────
    progress("Discovering attack surface from filesystem...");
    result.attackSurface = discoverAttackSurface(apiRoot);

    if (result.attackSurface.length === 0) {
      result.findings.push({
        severity: "info",
        title: "No API routes found",
        description: `No route.js/ts files found under ${apiRoot}`,
        category: "config",
        source: "repo-scan",
      });
      result.duration = Date.now() - startTime;
      return result;
    }

    // ── Phase 3: Trust boundary analysis ───────────────────────────────────
    progress("Classifying trust boundaries...");
    result.boundaries = groupByTrustBoundary(result.attackSurface);
  }

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

  result.duration = Date.now() - startTime;
  return result;
}
