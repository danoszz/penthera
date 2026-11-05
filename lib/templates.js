/**
 * YAML Template Engine (inspired by Nuclei)
 *
 * Run declarative vulnerability checks defined in YAML files.
 * Compatible with a subset of Nuclei's template format.
 */
import { joinUrl, registrableDomain } from "../src/utils/url.js";
import { request, readBody } from "../src/utils/http.js";
import { checkRegex } from "./rules/regex-guard.js";
import { rulesOf } from "./rules/index.js";

/**
 * Execute a single template check against a target.
 *
 * @param {string} baseUrl - Target URL
 * @param {object} template - Parsed YAML template object
 * @returns {Array<object>} Findings
 */
export async function executeTemplate(baseUrl, template) {
  const findings = [];

  for (const req of template.http || []) {
    const url = joinUrl(baseUrl, req.path.replace("{{BaseURL}}", ""));

    try {
      const { matched, res, body, headerString } = await sendAndMatch(url, req);

      if (matched) {
        // A second request that must also match, for checks one response cannot
        // decide: many hosts answer every path with the same 200.
        if (req.confirm) {
          const proof = await sendAndMatch(joinUrl(baseUrl, req.confirm.path), req.confirm);
          if (!proof.matched || !sameSite(baseUrl, proof.res.url)) continue;
        }
        if (req.mustChangeAnswer && !(await headerChangesAnswer(url, req.headers))) continue;

        // Run extractors
        const extracted = {};
        for (const extractor of req.extractors || []) {
          const result = runExtractor(extractor, { body, headers: headerString });
          if (result) extracted[extractor.name || "extracted"] = result;
        }

        findings.push({
          templateId: template.id,
          name: template.info?.name || template.id,
          severity: template.info?.severity || "info",
          tags: template.info?.tags || [],
          description: template.info?.description || "",
          matchedUrl: url,
          status: res.status,
          extracted,
        });
      }
    } catch {
      // Timeout, network error or egress refusal: recorded by the HTTP client
      // in result.errors, so the miss shows up as inconclusive.
    }
  }

  return findings;
}

/** Send one template request and evaluate its matchers. */
async function sendAndMatch(url, req) {
  const fetchOpts = {
    method: req.method || "GET",
    headers: req.headers || {},
    redirect: req.redirect || "manual",
    timeout: 10_000,
    probe: "templates",
  };
  if (req.body && ["POST", "PUT", "PATCH"].includes(fetchOpts.method)) {
    fetchOpts.body = req.body;
    if (!fetchOpts.headers["Content-Type"]) {
      fetchOpts.headers["Content-Type"] = "application/json";
    }
  }

  const res = await request(url, fetchOpts);
  const body = await readBody(res).catch(() => "");
  const headerString = [...res.headers.entries()]
    .map(([k, v]) => `${k}: ${v}`).join("\n");

  // Run matchers
  const matchResults = (req.matchers || []).map(matcher =>
    runMatcher(matcher, { status: res.status, body, headers: headerString, res }),
  );

  // Evaluate matchers-condition (default: OR for single matcher, AND for multiple)
  const condition = req["matchers-condition"] || (matchResults.length > 1 ? "and" : "or");
  const matched = matchResults.length > 0 && (condition === "and"
    ? matchResults.every(Boolean)
    : matchResults.some(Boolean));

  return { matched, res, body, headerString };
}

/**
 * True when a followed redirect stayed on the target's site: the same host on
 * the same port (or the default ports, so http to https counts), or another host
 * in its registrable domain. On a shared platform such as vercel.app each host
 * is its own site (SHARED_HOST_DOMAINS in src/utils/url.js), as in the egress rule.
 */
export function sameSite(baseUrl, finalUrl) {
  const [from, to] = [new URL(baseUrl), new URL(finalUrl)];
  if (from.hostname === to.hostname) return from.port === to.port;
  return registrableDomain(from.hostname) === registrableDomain(to.hostname);
}

/**
 * True when `headers` steadily turn another answer into a 200. An SPA's
 * catch-all answers the same either way. Call it after a first 200 with the
 * headers; it then sends plain, plain, headers, plain.
 *
 * If no plain request got a 200, the header opened something that stays shut, so
 * a mix of 401, 429 and 503 still counts. If some did and some did not, the
 * route is open and flaky, and it does not count. If all did, the header must
 * change a stable body or the content type: a page with a nonce or a clock
 * differs from itself, so its difference says nothing. That also means a login
 * page with a fresh token that turns into another HTML page is missed.
 */
export async function headerChangesAnswer(url, headers, { timeout = 10_000, probe = "templates" } = {}) {
  const get = async (sent) => {
    const res = await request(url, { headers: sent, redirect: "manual", timeout, probe });
    return { status: res.status, type: res.headers.get("content-type"), body: await readBody(res).catch(() => "") };
  };
  const [first, second] = [await get({}), await get({})];
  const sent = await get(headers);
  if (sent.status !== 200) return false;
  const plain = [first, second, await get({})];
  const open = plain.filter((p) => p.status === 200).length;
  if (open === 0) return true;
  if (open < plain.length || plain.some((p) => p.body === sent.body)) return false;
  return first.type !== sent.type || plain.every((p) => p.body === first.body);
}

/**
 * Run a single matcher against response data.
 */
// Community templates are untrusted input: they arrive as YAML from a directory
// the user points us at, and their regexes run against whole response bodies.
// A catastrophically-backtracking pattern would hang the scanner, so bound both
// the input and the pattern. This is a mitigation, not an immunity proof: real
// guarantees need a non-backtracking engine or a killable worker.
const REGEX_INPUT_CAP = 256 * 1024; // 256 KB is far past any real matcher's needs
// Template regexes pass the same structural ReDoS guard as rule packs
// (checkRegex in lib/rules/regex-guard.js); a refused pattern never runs.
const guardCache = new Map();
function regexAllowed(pattern, flags = "") {
  const key = `${flags}\u0000${pattern}`;
  let ok = guardCache.get(key);
  if (ok === undefined) {
    ok = checkRegex(pattern, flags).ok;
    if (guardCache.size > 1000) guardCache.clear();
    guardCache.set(key, ok);
  }
  return ok;
}

function safeRegexTest(pattern, target, flags = "") {
  if (!regexAllowed(pattern, flags)) return false; // refuse shapes that backtrack
  try {
    const input = target.length > REGEX_INPUT_CAP ? target.slice(0, REGEX_INPUT_CAP) : target;
    return new RegExp(pattern, flags).test(input);
  } catch {
    return false; // invalid pattern in a template must not abort the scan
  }
}

export function runMatcher(matcher, ctx) {
  const part = matcher.part || "body";
  const target = part === "header" ? ctx.headers : ctx.body;

  switch (matcher.type) {
    case "status":
      return (matcher.status || []).includes(ctx.status);

    case "word": {
      const words = matcher.words || [];
      const check = (w) => target.includes(w);
      return matcher.condition === "and"
        ? words.every(check)
        : words.some(check);
    }

    case "regex": {
      const patterns = matcher.regex || [];
      const check = (p) => safeRegexTest(p, target, matcher.flags);
      return matcher.condition === "and"
        ? patterns.every(check)
        : patterns.some(check);
    }

    case "negative-word": {
      const words = matcher.words || [];
      return words.every(w => !target.includes(w));
    }

    case "negative-regex": {
      const patterns = matcher.regex || [];
      return patterns.every(p => !safeRegexTest(p, target));
    }

    default:
      return false;
  }
}

/**
 * Run a single extractor against response data.
 */
export function runExtractor(extractor, ctx) {
  const part = extractor.part || "body";
  const target = part === "header" ? ctx.headers : ctx.body;

  switch (extractor.type) {
    case "regex": {
      for (const pattern of extractor.regex || []) {
        if (!regexAllowed(pattern)) continue;
        const capped = target.length > REGEX_INPUT_CAP ? target.slice(0, REGEX_INPUT_CAP) : target;
        let match;
        try {
          match = capped.match(new RegExp(pattern));
        } catch {
          continue; // invalid pattern in a template must not abort the scan
        }
        if (match) return match[extractor.group || 0];
      }
      return null;
    }

    case "json": {
      try {
        const data = JSON.parse(target);
        for (const path of extractor.json || []) {
          const value = path.split(".").reduce((obj, key) => obj?.[key], data);
          if (value !== undefined) return value;
        }
      } catch { /* not JSON */ }
      return null;
    }

    default:
      return null;
  }
}

/**
 * Built-in security templates (no YAML parser needed).
 * These cover the most common web app vulnerabilities.
 * Inspired by Nuclei's community templates.
 */
export const BUILT_IN_TEMPLATES = [
  // ── Exposed sensitive files ──────────────────────────────────────────
  // .env: lib/rules/core/templates.json.
  ...rulesOf("nuclei-template", { pack: "core" }).map((r) => r.template),
  {
    id: "env-local-exposure",
    info: { name: ".env.local file exposed", severity: "critical", tags: ["exposure", "config"] },
    http: [{
      method: "GET", path: "/.env.local",
      matchers: [
        { type: "status", status: [200] },
        // Must look like a dotenv file, not just any 200 containing "=".
        // SPAs serve index.html for unknown paths, and HTML is full of "=",
        // which made this fire critical on healthy sites.
        // JavaScript has no inline (?m), so the multiline flag goes in `flags`;
        // the regex guard refuses an unbounded {2,}, so the name is capped.
        { type: "regex", regex: ["^[A-Z][A-Z0-9_]{2,127}="], flags: "m" },
        { type: "negative-word", words: ["<html", "<!DOCTYPE", "<script"] },
      ],
      "matchers-condition": "and",
    }],
  },
  {
    id: "git-config-exposure",
    info: { name: "Git config exposed", severity: "high", tags: ["exposure", "git"] },
    http: [{
      method: "GET", path: "/.git/config",
      matchers: [
        { type: "status", status: [200] },
        { type: "word", words: ["[core]", "[remote"], condition: "or" },
      ],
      "matchers-condition": "and",
    }],
  },
  {
    id: "git-head-exposure",
    info: { name: "Git HEAD exposed", severity: "medium", tags: ["exposure", "git"] },
    http: [{
      method: "GET", path: "/.git/HEAD",
      matchers: [
        { type: "status", status: [200] },
        { type: "word", words: ["ref: refs/"] },
      ],
      "matchers-condition": "and",
    }],
  },
  {
    id: "service-account-key-exposure",
    info: { name: "Service account key exposed", severity: "critical", tags: ["exposure", "firebase", "gcp"] },
    http: [{
      method: "GET", path: "/serviceAccountKey.json",
      matchers: [
        { type: "status", status: [200] },
        { type: "word", words: ["private_key", "client_email"], condition: "and" },
      ],
      "matchers-condition": "and",
    }],
  },

  // ── Source map exposure ──────────────────────────────────────────────
  {
    id: "nextjs-sourcemap-exposure",
    info: { name: "Next.js source maps exposed", severity: "medium", tags: ["exposure", "nextjs"],
      description: "Source maps allow attackers to read your original source code" },
    http: [{
      method: "GET", path: "/_next/static/chunks/main.js.map",
      matchers: [
        { type: "status", status: [200] },
        // Test the shape, not the words: an SPA's index.html can say "sources",
        // and a real map's sourcesContent can hold <html> from JSX.
        { type: "regex", regex: ["^\\s*\\{"] },
        { type: "word", words: ['"mappings"', '"sources"'], condition: "or" },
      ],
      "matchers-condition": "and",
    }],
  },

  // ── Firebase specific ───────────────────────────────────────────────
  {
    id: "firebase-database-open-read",
    info: { name: "Firebase Realtime DB open read", severity: "high", tags: ["firebase", "misconfiguration"] },
    http: [{
      method: "GET", path: "/.json",
      matchers: [
        { type: "status", status: [200] },
        // Require an actual JSON body. Without this an SPA's index.html served
        // at /.json counted as an open Firebase database.
        { type: "regex", regex: ["^\\s*[\\{\\[]"] },
        { type: "negative-word", words: ["Permission denied", "error", "<html", "<!DOCTYPE"] },
      ],
      "matchers-condition": "and",
    }],
  },

  // ── Security headers (also checked by lib/blackbox/headers.js) ────────

  // ── Debug / internal endpoints ──────────────────────────────────────
  {
    id: "nextjs-debug-endpoint",
    info: { name: "Next.js debug endpoint accessible", severity: "medium", tags: ["nextjs", "debug"] },
    http: [{
      method: "GET", path: "/api/__nextjs_original-stack-frame",
      matchers: [
        { type: "status", status: [200, 400] },
        { type: "negative-word", words: ["<html", "<HTML", "<!DOCTYPE", "<!doctype"] },
      ],
      "matchers-condition": "and",
      // SPAs answer 200 and many APIs answer 400 on any path, so the home page
      // must show that this is a Next.js app. It may redirect to a locale or login.
      confirm: {
        method: "GET", path: "/", redirect: "follow",
        matchers: [
          { type: "word", words: ["/_next/static/", "__NEXT_DATA__"] },
          { type: "word", words: ["x-powered-by: Next.js"], part: "header" },
        ],
        "matchers-condition": "or",
      },
    }],
  },
  {
    // Prometheus exposition format: "# HELP name text" and "# TYPE name kind"
    // lines. Both are required, so a page that merely mentions "metrics", or
    // an SPA's index.html served at /metrics, does not match.
    id: "prometheus-metrics-exposed",
    info: { name: "Prometheus metrics endpoint exposed", severity: "medium", tags: ["exposure", "observability"],
      description: "/metrics serves Prometheus metrics to anyone. They name internal components, versions, routes and load, and can carry business data. Serve them on an internal port or behind auth." },
    http: [{
      method: "GET", path: "/metrics",
      matchers: [
        { type: "status", status: [200] },
        { type: "regex", regex: ["^# HELP [a-zA-Z_:]"], flags: "m" },
        { type: "regex", regex: ["^# TYPE [a-zA-Z_:][a-zA-Z0-9_:]* (?:counter|gauge|histogram|summary|untyped|gaugehistogram|info|stateset)\\b"], flags: "m" },
        { type: "negative-word", words: ["<html", "<!DOCTYPE"] },
      ],
      "matchers-condition": "and",
    }],
  },
  {
    id: "graphql-introspection",
    info: { name: "GraphQL introspection enabled", severity: "medium", tags: ["graphql", "misconfiguration"] },
    http: [{
      method: "POST", path: "/graphql",
      headers: { "Content-Type": "application/json" },
      body: '{"query":"{ __schema { types { name } } }"}',
      matchers: [
        { type: "status", status: [200] },
        { type: "word", words: ["__schema", "__type"], condition: "or" },
      ],
      "matchers-condition": "and",
    }],
  },
  {
    id: "swagger-ui-exposed",
    info: { name: "Swagger UI exposed", severity: "low", tags: ["exposure", "api-docs"] },
    http: [{
      method: "GET", path: "/api/docs",
      matchers: [
        { type: "status", status: [200] },
        { type: "word", words: ["swagger", "openapi", "api-docs"], condition: "or" },
      ],
      "matchers-condition": "and",
    }],
  },

  // ── CVE checks ────────────��─────────────────────────────────────────
  {
    id: "cve-2025-29927-nextjs-middleware-bypass",
    info: { name: "CVE-2025-29927: Next.js middleware bypass", severity: "critical",
      tags: ["cve", "nextjs", "auth-bypass"],
      description: "x-middleware-subrequest header can bypass Next.js middleware auth checks" },
    http: [{
      method: "GET", path: "/api/admin/users",
      headers: { "x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware" },
      matchers: [{ type: "status", status: [200] }],
      mustChangeAnswer: true,
    }],
  },

  // ── CORS misconfiguration ───────────────────────────────────────────
  {
    id: "cors-wildcard",
    info: { name: "CORS allows wildcard origin", severity: "medium", tags: ["cors", "misconfiguration"] },
    http: [{
      method: "GET", path: "/api/health",
      headers: { Origin: "https://evil-attacker.com" },
      matchers: [
        { type: "word", words: ["https://evil-attacker.com"], part: "header" },
      ],
    }],
  },
  {
    id: "cors-null-origin",
    info: { name: "CORS allows null origin", severity: "high", tags: ["cors", "misconfiguration"] },
    http: [{
      method: "GET", path: "/api/health",
      headers: { Origin: "null" },
      matchers: [
        { type: "regex", regex: ["access-control-allow-origin:\\s*null"], part: "header" },
      ],
    }],
  },

  // (An "open redirect via callback" template lived here but was removed: a
  // declarative word-matcher on the Location header can't tell a real open
  // redirect from a same-site canonicalization redirect that merely preserves
  // the payload in the query string. The code-based OAuth probe covers this
  // path correctly by resolving the redirect's destination origin.)

  // ── Directory listing ───────────────────────────────────────────────
  {
    id: "directory-listing",
    info: { name: "Directory listing enabled", severity: "low", tags: ["exposure", "misconfiguration"] },
    http: [{
      method: "GET", path: "/api/",
      matchers: [
        { type: "status", status: [200] },
        { type: "word", words: ["Index of", "Directory listing", "<pre>"], condition: "or" },
      ],
      "matchers-condition": "and",
    }],
  },

  // ── Error handling ──────────────────────────────────────────────────
  {
    // A request for a path that does not exist, the same kind of request
    // endpoint discovery's calibration sends: no payload. Each pattern is a
    // runtime's stack-frame shape with a file and line number, so an error
    // page that only says "Not Found" does not match.
    id: "error-stack-trace",
    info: { name: "Stack trace in error response", severity: "low", tags: ["info-leak", "error-handling"],
      description: "An error page shows a stack trace: source paths, function names and library versions. Turn off debug error pages in production and log the trace server-side instead." },
    http: ["/api/penthera-not-found", "/penthera-not-found"].map((path) => ({
      method: "GET", path,
      matchers: [{
        type: "regex",
        regex: [
          // Node.js / V8: "at fn (/app/x.js:12:5)" or "at /app/x.js:12:5"
          "\\bat (?:[\\w$.<>\\[\\] ]{1,200} \\()?(?:/|[A-Za-z]:\\\\|file://)[^\\s()<>\"]{1,250}:\\d{1,6}:\\d{1,6}",
          // Python
          "Traceback \\(most recent call last\\):",
          // Java: "at com.example.Foo.bar(Foo.java:42)"
          "\\bat [a-zA-Z_$][\\w$.]{0,250}\\([\\w$]{1,100}\\.java:\\d{1,6}\\)",
          // PHP
          "Stack trace:\\s{0,20}(?:<br\\s?/?>\\s{0,20})?#0 ",
          // .NET: "at Foo.Bar() in C:\\src\\Foo.cs:line 42"
          "\\bat [\\w.`<>]{1,250}\\([^)\\n]{0,250}\\) in [^\\n<]{1,250}:line \\d{1,6}",
        ],
      }],
    })),
  },
];

// ── Directory listings ─────────────────────────────────────────────────
// Autoindex pages (Apache, nginx, lighttpd: "Index of /"; Node serve-index:
// "listing directory /"; Python http.server: "Directory listing for /"; IIS:
// "[To Parent Directory]"). The title must name the listing, so a page that
// merely contains "Index of" in its text does not match.
const LISTING_SIGNATURES = [
  "<title>\\s{0,10}(?:Index of|listing directory|Directory listing for) /",
  "\\[To Parent Directory\\]",
];

// Common upload, file and backup folders. Paths that robots.txt disallows are
// checked as well (see robotsDisallowedPaths).
export const LISTING_PATHS = ["/uploads/", "/files/", "/backup/", "/backups/", "/logs/", "/download/", "/downloads/"];

/** A template that reports a browsable directory listing at `path`. */
export function directoryListingTemplate(path) {
  return {
    id: `directory-listing:${path}`,
    info: { name: "Browsable directory listing", severity: "medium", tags: ["exposure", "misconfiguration"],
      description: `${path} lists its files to anyone, including files nobody links to. Turn off directory indexes (Options -Indexes, autoindex off, no serve-index) or restrict the folder.` },
    http: [{
      method: "GET", path,
      matchers: [
        { type: "status", status: [200] },
        { type: "regex", regex: LISTING_SIGNATURES, flags: "i" },
      ],
      "matchers-condition": "and",
    }],
  };
}

// robots.txt names folders the owner would rather not have crawled, which
// makes them the folders most worth checking. Plain path prefixes only:
// entries with wildcards or query strings are skipped.
const MAX_ROBOTS_PATHS = 20;

/** Folder paths from robots.txt `Disallow:` lines, at most MAX_ROBOTS_PATHS. */
export function robotsDisallowedPaths(robotsTxt) {
  const paths = [];
  for (const line of String(robotsTxt || "").split(/\r?\n/)) {
    const m = /^\s*disallow\s*:\s*(\S+)/i.exec(line);
    if (!m) continue;
    const path = m[1];
    if (!path.startsWith("/") || path === "/" || /[*$?#]/.test(path) || path.length > 200) continue;
    if (!paths.includes(path)) paths.push(path);
    if (paths.length >= MAX_ROBOTS_PATHS) break;
  }
  return paths;
}

async function listingTemplates(baseUrl) {
  let robots = "";
  try {
    const res = await request(joinUrl(baseUrl, "/robots.txt"), { redirect: "manual", timeout: 10_000, probe: "templates" });
    if (res.status === 200 && !/html/i.test(res.headers.get("content-type") || "")) robots = await readBody(res);
  } catch { /* unreachable or refused: recorded by the HTTP client */ }
  const paths = [...LISTING_PATHS];
  for (const p of robotsDisallowedPaths(robots)) {
    const folder = p.endsWith("/") ? p : `${p}/`;
    if (!paths.includes(p) && !paths.includes(folder)) paths.push(p);
  }
  return paths.map(directoryListingTemplate);
}

/**
 * Run all built-in templates against a target.
 * @param {string} baseUrl
 * @returns {Array<object>} All findings
 */
export async function runBuiltInTemplates(baseUrl) {
  const allFindings = [];
  // Built-ins, then templates from other packs (bundled or --rules).
  const packTemplates = rulesOf("nuclei-template", { exceptPack: "core" }).map((r) => r.template);
  for (const template of [...BUILT_IN_TEMPLATES, ...await listingTemplates(baseUrl), ...packTemplates]) {
    const findings = await executeTemplate(baseUrl, template);
    allFindings.push(...findings);
  }
  return allFindings;
}
