/**
 * Attack Surface Discovery (Portable)
 *
 * Auto-discovers API routes from the filesystem for Next.js App Router projects.
 * Classifies auth patterns, input types, data flows, and security patterns.
 *
 * Set API_ROOT_PATH in pentest.config.js to your app/api directory.
 */
import { readdirSync, lstatSync, statSync, realpathSync, existsSync } from "fs";
import { asName } from "./linear-text.js";
import { join, relative, sep } from "path";
import { SESSION_CHECK_RE, RISK_RE, riskPatterns } from "./whitebox/frameworks.js";
import { codeMatcher } from "./whitebox/js-lex.js";
import { readRepoFile, isRefused } from "./fs-safe.js";

/** A route file over 5 MiB is not read (and is reported by the caller). */
const ROUTE_MAX_BYTES = 5 * 1024 * 1024;

const isRouteName = (entry) => entry === "route.js" || entry === "route.ts";

/**
 * Recursively find all route.js/ts files under a directory. Every route file
 * there is returned, whatever it is: the reader (readRepoFile with a root)
 * follows a link that stays in the project and refuses a link out or a FIFO,
 * so the scan names it and is incomplete. With `unread`, a broken link and a
 * linked folder that leaves `root` are pushed there; a linked folder inside it
 * is walked once (app/x -> / would walk the disk, a link to its parent loops).
 */
export function findRouteFiles(dir, files = [], { unread = null, root = null, seen = new Set() } = {}) {
  if (!existsSync(dir)) return files;
  let realRoot = null;
  if (root) { try { realRoot = realpathSync(root); } catch { realRoot = root; } }
  const insideRoot = (t) => !realRoot || t === realRoot || t.startsWith(realRoot + sep);
  try { seen.add(realpathSync(dir)); } catch { /* keep going */ }
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = lstatSync(full);
    if (st.isDirectory()) {
      if (entry !== "node_modules" && !entry.startsWith(".")) findRouteFiles(full, files, { unread, root, seen });
    } else if (st.isSymbolicLink()) {
      let target = null;
      try { target = realpathSync(full); } catch { /* broken */ }
      if (!target) { if (isRouteName(entry)) unread?.push(notRead(full, "it is a link to nothing")); continue; }
      let tst;
      try { tst = statSync(full); } catch { continue; }
      if (tst.isDirectory()) {
        if (entry === "node_modules" || entry.startsWith(".")) continue;
        if (!unread) continue; // the old walk: linked folders are not followed
        if (!insideRoot(target)) { unread.push(notRead(full, "it is a linked folder outside the project")); continue; }
        if (seen.has(target)) continue;
        findRouteFiles(full, files, { unread, root, seen });
      } else if (isRouteName(entry)) {
        files.push(full); // the reader follows it inside the project, or refuses it
      }
    } else if (isRouteName(entry)) {
      files.push(full); // a regular file, or a FIFO the reader refuses: named, never silent
    }
  }
  return files;
}

/** A route or server file the walk found but cannot read, in the shape readers refuse with. */
export function notRead(path, reason) {
  return { path, reason, message: `${path} was not read: ${reason}`, code: "EREFUSED" };
}

/**
 * Convert filesystem path to URL path. From a Next.js app folder (appDir), the URL is
 * the folder path itself, without route groups `(name)` or parallel slots `@name`;
 * otherwise it is taken as under /api.
 */
function pathToUrl(filePath, apiRoot, appDir = null) {
  if (appDir) {
    const parts = relative(appDir, filePath).split(/[\\/]/).slice(0, -1).filter((p) => !/^\(.*\)$|^@/.test(p));
    return `/${parts.join("/")}`.replace(/\[\.\.\.([^[\]]+)\]/g, ":$1*").replace(/\[([^[\]]+)\]/g, ":$1");
  }
  const rel = relative(apiRoot, filePath).replace(/\/route\.(js|ts)$/, "");
  return "/api/" + rel.replace(/\[([^[\]]+)\]/g, ":$1");
}

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];

/** Extract exported HTTP methods from source: `export function GET`, `export const GET =`, `export { h as GET }`. */
function extractMethods(source) {
  const named = new Set();
  for (const block of source.matchAll(/export\s*\{([^}]*)\}/g)) {
    for (const part of block[1].split(",")) named.add(asName(part, "last"));
  }
  return HTTP_METHODS.filter((m) => new RegExp(`export\\s+(?:async\\s+)?function\\s+${m}\\b|export\\s+(?:const|let|var)\\s+${m}\\s*=`).test(source) || named.has(m));
}

/** Classify the auth mechanism from source code patterns */
function classifyAuth(source) {
  const auth = [];
  // Common auth function names, extend for your framework
  if (/verifyAdmin|isAdmin|requireAdmin|adminAuth/.test(source)) auth.push("admin");
  if (/verifyUser|requireAuth|getServerSession|verifyIdToken|getAdminAuth/.test(source) || SESSION_CHECK_RE.test(source)) {
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

/**
 * Detect security-relevant patterns. The low-severity hints (error leak, CORS
 * wildcard, unguarded JSON.parse) read the code with comments blanked and strings
 * kept (codeMatcher): a word in a comment is not a hint. The serious sinks
 * (riskPatterns) read the raw text, so no comment trick can hide them.
 */
function detectSecurityPatterns(source) {
  const patterns = [];
  if (/escapeHtml|sanitize|DOMPurify/.test(source)) patterns.push("html-escaped");
  if (/timingSafeEqual|safeCompare/.test(source)) patterns.push("timing-safe");
  if (/runTransaction|BEGIN.*COMMIT/.test(source)) patterns.push("transactional");
  if (/isAllowedImageUrl|urlAllowlist/.test(source)) patterns.push("url-allowlist");
  const code = codeMatcher(source);
  if (code.has(RISK_RE.errorLeak)) patterns.push("RISK:error-leak");
  // Medium: a superset like the serious sinks, so a fake comment can't hide it.
  if (code.has(RISK_RE.corsWildcard) || new RegExp(RISK_RE.corsWildcard.source).test(source)) patterns.push("RISK:cors-wildcard");
  // A `.catch` in a comment guards nothing.
  if (code.has(RISK_RE.jsonParse) && !code.has(RISK_RE.dotCatch)) patterns.push("RISK:json-parse-unguarded");
  patterns.push(...riskPatterns(source, code));
  return patterns;
}

/** One route's record, as discovery and the framework scan both give it. */
export function routeRecord(url, filePath, source, methods) {
  const securityPatterns = detectSecurityPatterns(source);
  return {
    url,
    filePath,
    methods,
    auth: classifyAuth(source),
    inputs: detectInputs(source),
    externalCalls: detectExternalCalls(source),
    securityPatterns,
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
  const unread = [];
  for (const filePath of findRouteFiles(apiRoot, [], { unread, root: repoRoot })) {
    let source;
    try {
      // Inside the project: a link there is followed, a link out or a FIFO refused.
      source = readRepoFile(filePath, { maxBytes: ROUTE_MAX_BYTES, root: repoRoot, label: relative(repoRoot, filePath) || filePath });
    } catch (e) {
      if (isRefused(e)) { refused.push({ ...e, path: filePath, reason: e.reason, message: e.message }); continue; } // said by the caller
      if (e.code === "ENOENT") continue; // gone since the walk
      refused.push(notRead(filePath, e.code || e.message));
      continue;
    }
    routes.push(routeRecord(pathToUrl(filePath, apiRoot, appDir), relative(repoRoot, filePath), source, extractMethods(source)));
  }
  refused.push(...unread);
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
