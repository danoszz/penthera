/**
 * Attack Surface Discovery (Portable)
 *
 * Auto-discovers API routes from the filesystem for Next.js App Router projects.
 * Classifies auth patterns, input types, data flows, and security patterns.
 *
 * Set API_ROOT_PATH in pentest.config.js to your app/api directory.
 */
import { readdirSync, lstatSync, existsSync } from "fs";
import { join, relative } from "path";
import { SHELL_EXEC_RE } from "./whitebox/frameworks.js";
import { readRepoFile, isRefused } from "./fs-safe.js";

/** A route file over 5 MiB is not read (and is reported by the caller). */
const ROUTE_MAX_BYTES = 5 * 1024 * 1024;

/** Recursively find all route.js/ts files under a directory */
export function findRouteFiles(dir, files = []) {
  if (!existsSync(dir)) return files;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    // Linked folders are not followed (app/x -> / would walk the disk, a link to
    // its parent loops). A route file that is a link, a FIFO or a device is kept:
    // the read refuses it, so the scan is incomplete rather than silent.
    const st = lstatSync(full);
    if (st.isDirectory()) {
      if (entry !== "node_modules" && !entry.startsWith(".")) findRouteFiles(full, files);
    } else if (entry === "route.js" || entry === "route.ts") {
      files.push(full);
    }
  }
  return files;
}

/**
 * Convert filesystem path to URL path. From a Next.js app folder (appDir), the URL is
 * the folder path itself, without route groups `(name)` or parallel slots `@name`;
 * otherwise it is taken as under /api.
 */
function pathToUrl(filePath, apiRoot, appDir = null) {
  if (appDir) {
    const parts = relative(appDir, filePath).split(/[\\/]/).slice(0, -1).filter((p) => !/^\(.*\)$|^@/.test(p));
    return `/${parts.join("/")}`.replace(/\[\.\.\.([^\]]+)\]/g, ":$1*").replace(/\[([^\]]+)\]/g, ":$1");
  }
  const rel = relative(apiRoot, filePath).replace(/\/route\.(js|ts)$/, "");
  return "/api/" + rel.replace(/\[([^\]]+)\]/g, ":$1");
}

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];

/** Extract exported HTTP methods from source: `export function GET`, `export const GET =`, `export { h as GET }`. */
function extractMethods(source) {
  const named = new Set();
  for (const block of source.matchAll(/export\s*\{([^}]*)\}/g)) {
    for (const part of block[1].split(",")) named.add(part.trim().split(/\s+as\s+/).pop());
  }
  return HTTP_METHODS.filter((m) => new RegExp(`export\\s+(?:async\\s+)?function\\s+${m}\\b|export\\s+(?:const|let|var)\\s+${m}\\s*=`).test(source) || named.has(m));
}

/** Classify the auth mechanism from source code patterns */
function classifyAuth(source) {
  const auth = [];
  // Common auth function names, extend for your framework
  if (/verifyAdmin|isAdmin|requireAdmin|adminAuth/.test(source)) auth.push("admin");
  if (/verifyUser|requireAuth|getSession|getServerSession|verifyIdToken|getAdminAuth/.test(source)) {
    if (!auth.includes("admin")) auth.push("user");
  }
  if (/CRON_SECRET|cronSecret|verifyCron/.test(source)) auth.push("cron");
  if (/throttle|rateLimit|rateLimiter/.test(source)) auth.push("rate-limited");
  if (/NODE_ENV\s*!==\s*["']development["']|NODE_ENV\s*===\s*["']development["']/.test(source)) {
    auth.push("dev-only");
  }
  if (auth.length === 0) auth.push("public");
  return auth;
}

/** Detect user-controlled input fields */
function detectInputs(source) {
  const inputs = [];
  const bodyMatch = source.match(/(?:const|let)\s*\{([^}]+)\}\s*=\s*await\s+(?:req|request)\.json/);
  if (bodyMatch) {
    inputs.push(...bodyMatch[1].split(",").map(s => s.trim().split("=")[0].trim()).filter(Boolean));
  }
  const paramMatches = source.matchAll(/params\.(\w+)/g);
  for (const m of paramMatches) inputs.push(`param:${m[1]}`);
  const queryMatches = source.matchAll(/searchParams\.get\(["'](\w+)["']\)/g);
  for (const m of queryMatches) inputs.push(`query:${m[1]}`);
  return [...new Set(inputs)];
}

/** Detect external services called */
function detectExternalCalls(source) {
  const calls = [];
  if (/replicate\.com|REPLICATE_API_TOKEN/.test(source)) calls.push("replicate");
  if (/stripe\.|STRIPE_/.test(source)) calls.push("stripe");
  if (/GoogleGenAI|GEMINI_API_KEY|gemini|openai|OPENAI_/.test(source)) calls.push("ai-api");
  if (/pinterest\.com|Pinterest/.test(source)) calls.push("pinterest");
  if (/Resend|RESEND_API_KEY|sendgrid|SENDGRID/.test(source)) calls.push("email-service");
  if (/firebaseAdmin|getAdminFirestore|prisma|mongoose/.test(source)) calls.push("database");
  if (/getAdminAuth/.test(source)) calls.push("auth-service");
  return calls;
}

/** Detect security-relevant patterns */
function detectSecurityPatterns(source) {
  const patterns = [];
  if (/escapeHtml|sanitize|DOMPurify/.test(source)) patterns.push("html-escaped");
  if (/timingSafeEqual|safeCompare/.test(source)) patterns.push("timing-safe");
  if (/runTransaction|BEGIN.*COMMIT/.test(source)) patterns.push("transactional");
  if (/isAllowedImageUrl|urlAllowlist/.test(source)) patterns.push("url-allowlist");
  if (/err\.message|error\.message/.test(source)) patterns.push("RISK:error-leak");
  if (/origin\s*\|\|\s*"\*"/.test(source)) patterns.push("RISK:cors-wildcard");
  if (/JSON\.parse/.test(source) && !/\.catch/.test(source)) patterns.push("RISK:json-parse-unguarded");
  if (/eval\s*\(/.test(source)) patterns.push("RISK:eval");
  if (/innerHTML/.test(source)) patterns.push("RISK:innerHTML");
  if (SHELL_EXEC_RE.test(source)) patterns.push("RISK:command-injection");
  return patterns;
}

/** One route's record, as discovery and the framework scan both give it. */
export function routeRecord(url, filePath, source, methods) {
  return {
    url,
    filePath,
    methods,
    auth: classifyAuth(source),
    inputs: detectInputs(source),
    externalCalls: detectExternalCalls(source),
    securityPatterns: detectSecurityPatterns(source),
    hasParams: url.includes(":"),
    sourceLength: source.length,
  };
}

/**
 * Discover the full attack surface from the filesystem.
 * @param {string} apiRoot - Path to app/api directory, or a Next.js app folder
 * @param {{appDir?: string, repoRoot?: string}} [o] - appDir: URLs are read from that app folder
 */
export function discoverAttackSurface(apiRoot, { appDir = null, repoRoot = join(apiRoot, "../.."), refused = [] } = {}) {
  if (!apiRoot || !existsSync(apiRoot)) {
    console.warn(`[PENTEST] API_ROOT_PATH not found: ${apiRoot}, skipping filesystem discovery`);
    return [];
  }
  const routes = [];
  for (const filePath of findRouteFiles(apiRoot)) {
    let source;
    try {
      source = readRepoFile(filePath, { maxBytes: ROUTE_MAX_BYTES });
    } catch (e) {
      if (isRefused(e)) { refused.push(e); continue; } // too large: said by the caller, not read
      throw e;
    }
    routes.push(routeRecord(pathToUrl(filePath, apiRoot, appDir), relative(repoRoot, filePath), source, extractMethods(source)));
  }
  return routes.sort((a, b) => a.url.localeCompare(b.url));
}

/**
 * Group routes by trust boundary.
 */
export function groupByTrustBoundary(routes) {
  return {
    public: routes.filter(r => r.auth.includes("public")),
    userAuth: routes.filter(r => r.auth.includes("user") && !r.auth.includes("admin")),
    adminAuth: routes.filter(r => r.auth.includes("admin")),
    cronAuth: routes.filter(r => r.auth.includes("cron") && !r.auth.includes("admin")),
    mixed: routes.filter(r => r.auth.length > 1 && !r.auth.includes("public")),
  };
}

/**
 * Find routes with security risk patterns.
 */
export function findRiskyRoutes(routes) {
  return routes.filter(r => r.securityPatterns.some(p => p.startsWith("RISK:")));
}
