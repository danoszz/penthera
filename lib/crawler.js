/**
 * Runtime Endpoint Discovery (inspired by Katana/httpx)
 *
 * Crawls a live target to discover API endpoints, forms, and links.
 * Compares findings with filesystem-discovered routes to find "shadow" endpoints.
 *
 * Techniques borrowed from:
 *   - Katana (ProjectDiscovery) — recursive crawl with scope control
 *   - httpx — tech fingerprinting from response headers
 *   - ffuf — wordlist-based endpoint brute-forcing
 */

const DEFAULT_TIMEOUT = 8_000;

async function safeFetch(url, opts = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeout || DEFAULT_TIMEOUT);
  try {
    return await fetch(url, { ...opts, signal: controller.signal, redirect: "manual" });
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Discover endpoints by brute-forcing common API paths.
 * Like ffuf but built-in — no external tool needed.
 *
 * @param {string} baseUrl - Target base URL
 * @param {object} opts - { concurrency, wordlist, timeout }
 * @returns {Array<{ path, status, size, tech }>} Discovered endpoints
 */
export async function discoverEndpoints(baseUrl, opts = {}) {
  const concurrency = opts.concurrency || 10;
  const timeout = opts.timeout || DEFAULT_TIMEOUT;

  // Common API paths — inspired by Nikto's 8k+ check database
  // and common Next.js / Node.js patterns
  const wordlist = opts.wordlist || [
    // Health / status
    "/api/health", "/api/status", "/api/ping", "/api/version",
    "/health", "/healthz", "/ready", "/readyz", "/.well-known/health",
    // Auth
    "/api/auth/login", "/api/auth/register", "/api/auth/logout",
    "/api/auth/me", "/api/auth/session", "/api/auth/refresh",
    "/api/auth/forgot-password", "/api/auth/reset-password",
    "/api/auth/verify-email", "/api/auth/callback",
    "/api/login", "/api/register", "/api/signup",
    // User
    "/api/user", "/api/user/profile", "/api/user/settings",
    "/api/users", "/api/me", "/api/account",
    // Admin
    "/api/admin", "/api/admin/users", "/api/admin/settings",
    "/api/admin/logs", "/api/admin/stats", "/api/admin/dashboard",
    // CRUD common
    "/api/posts", "/api/comments", "/api/items", "/api/products",
    "/api/orders", "/api/invoices", "/api/payments",
    "/api/projects", "/api/tasks", "/api/events",
    "/api/messages", "/api/notifications", "/api/uploads",
    // Common utility
    "/api/search", "/api/contact", "/api/feedback", "/api/subscribe",
    "/api/unsubscribe", "/api/webhook", "/api/webhooks",
    "/api/email", "/api/chat", "/api/ai", "/api/generate",
    // Cron / background
    "/api/cron", "/api/cron/cleanup", "/api/cron/digest",
    "/api/cron/sync", "/api/cron/reindex",
    // Stripe / billing
    "/api/stripe/checkout", "/api/stripe/webhook",
    "/api/billing", "/api/subscription", "/api/pricing",
    // Third-party integrations
    "/api/oauth/callback", "/api/oauth/google", "/api/oauth/github",
    "/api/integrations", "/api/connect",
    // Export / import
    "/api/export", "/api/import", "/api/download",
    // GraphQL
    "/graphql", "/api/graphql",
    // Documentation / debug (should be disabled in prod)
    "/docs", "/redoc", "/openapi.json",
    "/api/docs", "/api/swagger", "/api/openapi",
    "/api/debug", "/api/test", "/api/_debug",
    // Sensitive files
    "/.env", "/.env.local", "/.env.production",
    "/.git/HEAD", "/.git/config",
    "/package.json", "/tsconfig.json",
    "/next.config.js", "/next.config.mjs",
    "/firebase.json", "/firestore.rules",
    "/serviceAccountKey.json", "/service-account.json",
    "/robots.txt", "/sitemap.xml",
    "/.well-known/security.txt",
    // Next.js internals
    "/_next/static/chunks/main.js.map",
    "/_next/data/build-id/index.json",
    "/api/__nextjs_original-stack-frame",
    // Common CMS / frameworks
    "/wp-admin", "/wp-login.php", "/administrator",
    "/.htaccess", "/web.config",
  ];

  const discovered = [];

  // Batch requests with concurrency control (like httpx)
  for (let i = 0; i < wordlist.length; i += concurrency) {
    const batch = wordlist.slice(i, i + concurrency);
    const results = await Promise.allSettled(
      batch.map(async (path) => {
        const res = await safeFetch(`${baseUrl}${path}`, { timeout });
        if (!res) return null;
        return {
          path,
          status: res.status,
          size: parseInt(res.headers.get("content-length") || "0", 10),
          contentType: res.headers.get("content-type") || "",
          server: res.headers.get("server") || "",
          poweredBy: res.headers.get("x-powered-by") || "",
          redirectTo: res.headers.get("location") || null,
        };
      }),
    );

    for (const r of results) {
      if (r.status === "fulfilled" && r.value) {
        discovered.push(r.value);
      }
    }
  }

  return discovered;
}

/**
 * Fingerprint the target technology stack.
 * Inspired by httpx / Wappalyzer.
 *
 * @param {string} baseUrl - Target base URL
 * @returns {object} Technology fingerprint
 */
export async function fingerprint(baseUrl) {
  const tech = {
    framework: null,
    server: null,
    cdn: null,
    security: [],
    headers: {},
  };

  // Fetch the homepage
  const res = await safeFetch(baseUrl);
  if (!res) return tech;

  tech.headers = Object.fromEntries(res.headers.entries());

  // Server detection
  const server = res.headers.get("server") || "";
  const poweredBy = res.headers.get("x-powered-by") || "";
  if (server.includes("Vercel")) tech.server = "Vercel";
  else if (server.includes("cloudflare")) { tech.server = "Cloudflare"; tech.cdn = "Cloudflare"; }
  else if (server.includes("nginx")) tech.server = "nginx";
  else if (server.includes("apache")) tech.server = "Apache";
  else if (server) tech.server = server;

  // Framework detection
  if (poweredBy.includes("Next.js")) tech.framework = "Next.js";
  else if (poweredBy.includes("Express")) tech.framework = "Express";
  else if (poweredBy.includes("Nuxt")) tech.framework = "Nuxt";

  // CDN / platform detection from headers
  if (res.headers.has("cf-ray")) tech.cdn = "Cloudflare";
  if (res.headers.has("x-vercel-id")) { tech.server = "Vercel"; tech.cdn = "Vercel Edge"; }
  if (res.headers.has("x-amz-cf-id")) tech.cdn = "AWS CloudFront";

  // Next.js detection from HTML
  try {
    const html = await res.text();
    if (html.includes("/_next/static") || html.includes("__NEXT_DATA__")) {
      tech.framework = "Next.js";
    }
    if (html.includes("__nuxt")) tech.framework = "Nuxt";
    if (html.includes("ng-version")) tech.framework = "Angular";
    if (html.includes("data-reactroot") || html.includes("__react")) tech.framework = "React";
  } catch { /* ignore */ }

  // Security header audit
  const securityHeaders = [
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options",
    "x-xss-protection", "referrer-policy",
    "permissions-policy",
  ];
  for (const h of securityHeaders) {
    if (res.headers.has(h)) tech.security.push(h);
  }

  return tech;
}

/**
 * Auto-calibrate response filtering (inspired by ffuf -ac).
 * Sends baseline requests and identifies the "default" response signature.
 * Returns a filter function that rejects matching responses.
 *
 * @param {string} baseUrl
 * @returns {function} Filter function: (response) => boolean (true = interesting, false = noise)
 */
export async function autoCalibrate(baseUrl) {
  // Send requests to paths that definitely don't exist
  const baselines = [];
  for (const garbage of [
    `/api/${Date.now()}-nonexistent-calibration-a`,
    `/api/${Date.now()}-nonexistent-calibration-b`,
    `/api/${Date.now()}-nonexistent-calibration-c`,
  ]) {
    const res = await safeFetch(`${baseUrl}${garbage}`);
    if (res) {
      const text = await res.text().catch(() => "");
      baselines.push({
        status: res.status,
        size: text.length,
        contentType: res.headers.get("content-type") || "",
      });
    }
  }

  // Find common baseline signature
  if (baselines.length === 0) return () => true; // can't calibrate, accept everything

  const baselineStatus = baselines[0].status;
  const baselineSize = baselines.reduce((sum, b) => sum + b.size, 0) / baselines.length;
  const sizeTolerance = baselineSize * 0.1 + 50; // 10% + 50 bytes tolerance

  return (response) => {
    // If response matches the baseline signature, it's noise
    if (response.status === baselineStatus &&
        Math.abs(response.size - baselineSize) < sizeTolerance) {
      return false; // noise — filter out
    }
    return true; // interesting — keep
  };
}

/**
 * Compare crawled endpoints with filesystem-discovered routes.
 * Returns "shadow" endpoints — routes that exist at runtime but aren't in source.
 */
export function findShadowEndpoints(crawledPaths, filesystemRoutes) {
  const knownPaths = new Set(filesystemRoutes.map(r => r.url));
  return crawledPaths.filter(ep => {
    const normalized = ep.path.replace(/\/$/, "");
    return !knownPaths.has(normalized) && ep.status !== 404;
  });
}
