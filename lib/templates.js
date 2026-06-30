/**
 * YAML Template Engine (inspired by Nuclei)
 *
 * Run declarative vulnerability checks defined in YAML files.
 * Compatible with a subset of Nuclei's template format.
 */
import { joinUrl } from "../src/utils/url.js";

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
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    try {
      const fetchOpts = {
        method: req.method || "GET",
        headers: req.headers || {},
        signal: controller.signal,
        redirect: "manual",
      };
      if (req.body && ["POST", "PUT", "PATCH"].includes(fetchOpts.method)) {
        fetchOpts.body = req.body;
        if (!fetchOpts.headers["Content-Type"]) {
          fetchOpts.headers["Content-Type"] = "application/json";
        }
      }

      const res = await fetch(url, fetchOpts);
      const body = await res.text().catch(() => "");
      const headerString = [...res.headers.entries()]
        .map(([k, v]) => `${k}: ${v}`).join("\n");

      // Run matchers
      const matchResults = (req.matchers || []).map(matcher =>
        runMatcher(matcher, { status: res.status, body, headers: headerString, res }),
      );

      // Evaluate matchers-condition (default: OR for single matcher, AND for multiple)
      const condition = req["matchers-condition"] || (matchResults.length > 1 ? "and" : "or");
      const matched = condition === "and"
        ? matchResults.every(Boolean)
        : matchResults.some(Boolean);

      if (matched && matchResults.length > 0) {
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
    } catch (err) {
      if (err.name !== "AbortError") {
        // Network error — skip
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  return findings;
}

/**
 * Run a single matcher against response data.
 */
function runMatcher(matcher, ctx) {
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
      const check = (p) => new RegExp(p, matcher.flags || "").test(target);
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
      return patterns.every(p => !new RegExp(p).test(target));
    }

    default:
      return false;
  }
}

/**
 * Run a single extractor against response data.
 */
function runExtractor(extractor, ctx) {
  const part = extractor.part || "body";
  const target = part === "header" ? ctx.headers : ctx.body;

  switch (extractor.type) {
    case "regex": {
      for (const pattern of extractor.regex || []) {
        const match = target.match(new RegExp(pattern));
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
  {
    id: "env-file-exposure",
    info: { name: ".env file exposed", severity: "critical", tags: ["exposure", "config"] },
    http: [{
      method: "GET", path: "/.env",
      matchers: [
        { type: "status", status: [200] },
        { type: "word", words: ["DB_", "API_KEY", "SECRET", "PASSWORD", "FIREBASE_", "STRIPE_"], condition: "or" },
      ],
      "matchers-condition": "and",
    }],
  },
  {
    id: "env-local-exposure",
    info: { name: ".env.local file exposed", severity: "critical", tags: ["exposure", "config"] },
    http: [{
      method: "GET", path: "/.env.local",
      matchers: [
        { type: "status", status: [200] },
        { type: "word", words: ["="], condition: "or" },
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
        { type: "word", words: ["mappings", "sources"], condition: "or" },
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
        { type: "negative-word", words: ["Permission denied", "error"] },
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
      matchers: [{ type: "status", status: [200, 400] }],
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

  // ── Open redirect ───────────────────────────────────────────────────
  {
    id: "open-redirect-callback",
    info: { name: "Open redirect via callback parameter", severity: "medium", tags: ["redirect"] },
    http: [{
      method: "GET", path: "/api/auth/callback?redirect=https://evil.com",
      matchers: [
        { type: "status", status: [301, 302, 303, 307, 308] },
        { type: "word", words: ["evil.com"], part: "header" },
      ],
      "matchers-condition": "and",
    }],
  },

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
];

/**
 * Run all built-in templates against a target.
 * @param {string} baseUrl
 * @returns {Array<object>} All findings
 */
export async function runBuiltInTemplates(baseUrl) {
  const allFindings = [];
  for (const template of BUILT_IN_TEMPLATES) {
    const findings = await executeTemplate(baseUrl, template);
    allFindings.push(...findings);
  }
  return allFindings;
}
