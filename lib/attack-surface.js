/**
 * Attack Surface Discovery (Portable)
 *
 * Auto-discovers API routes from the filesystem for Next.js App Router projects.
 * Classifies auth patterns, input types, data flows, and security patterns.
 *
 * Set API_ROOT_PATH in pentest.config.js to your app/api directory.
 */
import { readdirSync, readFileSync, statSync, existsSync } from "fs";
import { join, relative } from "path";

/** Recursively find all route.js/ts files under a directory */
function findRouteFiles(dir, files = []) {
  if (!existsSync(dir)) return files;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      findRouteFiles(full, files);
    } else if (entry === "route.js" || entry === "route.ts") {
      files.push(full);
    }
  }
  return files;
}

/** Convert filesystem path to URL path */
function pathToUrl(filePath, apiRoot) {
  const rel = relative(apiRoot, filePath).replace(/\/route\.(js|ts)$/, "");
  return "/api/" + rel.replace(/\[([^\]]+)\]/g, ":$1");
}

/** Extract exported HTTP methods from source */
function extractMethods(source) {
  const methods = [];
  if (/export\s+(async\s+)?function\s+GET/m.test(source)) methods.push("GET");
  if (/export\s+(async\s+)?function\s+POST/m.test(source)) methods.push("POST");
  if (/export\s+(async\s+)?function\s+PUT/m.test(source)) methods.push("PUT");
  if (/export\s+(async\s+)?function\s+DELETE/m.test(source)) methods.push("DELETE");
  if (/export\s+(async\s+)?function\s+PATCH/m.test(source)) methods.push("PATCH");
  if (/export\s+(async\s+)?function\s+OPTIONS/m.test(source)) methods.push("OPTIONS");
  return methods;
}

/** Classify the auth mechanism from source code patterns */
function classifyAuth(source) {
  const auth = [];
  // Common auth function names — extend for your framework
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
  if (/exec\s*\(|spawn\s*\(|execSync/.test(source)) patterns.push("RISK:command-injection");
  return patterns;
}

/**
 * Discover the full attack surface from the filesystem.
 * @param {string} apiRoot - Path to app/api directory
 */
export function discoverAttackSurface(apiRoot) {
  if (!apiRoot || !existsSync(apiRoot)) {
    console.warn(`[PENTEST] API_ROOT_PATH not found: ${apiRoot} — skipping filesystem discovery`);
    return [];
  }
  const routeFiles = findRouteFiles(apiRoot);
  return routeFiles.map((filePath) => {
    const source = readFileSync(filePath, "utf-8");
    const url = pathToUrl(filePath, apiRoot);
    return {
      url,
      filePath: relative(join(apiRoot, "../.."), filePath),
      methods: extractMethods(source),
      auth: classifyAuth(source),
      inputs: detectInputs(source),
      externalCalls: detectExternalCalls(source),
      securityPatterns: detectSecurityPatterns(source),
      hasParams: url.includes(":"),
      sourceLength: source.length,
    };
  }).sort((a, b) => a.url.localeCompare(b.url));
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
