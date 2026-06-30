/**
 * HTTP Parameter Discovery (Arjun-style)
 *
 * Discovers active HTTP parameters via batched differential analysis.
 * Instead of testing 1 parameter per request (slow), we send batches of
 * 50+ parameters and use response differences to detect active ones.
 *
 * Algorithm:
 *   1. Establish baseline response (no params)
 *   2. Send batches of 50 candidate params
 *   3. If response differs from baseline → active params in this batch
 *   4. Binary-search the batch to isolate individual active params
 *
 * Inspired by: Arjun (6.2k stars), ParamSpider
 */

const PARAM_TIMEOUT = 8_000;

async function safeFetch(url, opts = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeout || PARAM_TIMEOUT);
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal, redirect: "manual" });
    const body = await res.text().catch(() => "");
    return { status: res.status, body, size: body.length, ok: true };
  } catch {
    return { status: 0, body: "", size: 0, ok: false };
  } finally {
    clearTimeout(timeout);
  }
}

function simpleHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return hash;
}

function isDifferent(baseline, response, tolerance = 0.05) {
  if (baseline.status !== response.status) return true;
  const sizeDiff = Math.abs(baseline.size - response.size);
  if (sizeDiff > Math.max(50, baseline.size * tolerance)) return true;
  if (simpleHash(baseline.body) !== simpleHash(response.body)) return true;
  return false;
}

// ── Common parameter wordlist ────────────────────────────────────────────
// Curated from SecLists, Arjun defaults, and CommonCrawl analysis.

const COMMON_PARAMS = [
  // Auth / identity
  "id", "user", "username", "email", "password", "token", "key", "api_key",
  "apikey", "auth", "session", "sid", "uid", "user_id", "userId",
  // Pagination / filtering
  "page", "limit", "offset", "sort", "order", "filter", "search", "query",
  "q", "keyword", "per_page", "perPage", "size", "start", "end",
  // Content / data
  "name", "title", "body", "content", "text", "message", "description",
  "comment", "note", "data", "value", "type", "status", "state",
  // URLs / redirects
  "url", "link", "href", "src", "redirect", "redirect_uri", "return",
  "return_to", "next", "callback", "redir", "destination", "go", "target",
  // Files / paths
  "file", "filename", "path", "dir", "folder", "upload", "image", "img",
  "photo", "avatar", "attachment", "document", "doc",
  // Actions
  "action", "cmd", "command", "method", "do", "func", "function",
  "handler", "operation", "task", "step", "mode",
  // Formatting
  "format", "output", "view", "template", "layout", "theme", "lang",
  "language", "locale", "timezone", "tz",
  // Database / technical
  "table", "column", "field", "select", "where", "from", "join",
  "group", "having", "debug", "verbose", "trace", "log", "level",
  // Common API
  "version", "v", "format", "fields", "include", "exclude", "expand",
  "embed", "populate", "with", "scope", "context",
  // Security-relevant
  "admin", "role", "permission", "access", "grant", "deny", "allow",
  "block", "ban", "delete", "remove", "drop", "reset", "confirm",
  // Payment / e-commerce
  "amount", "price", "quantity", "qty", "total", "discount", "coupon",
  "code", "promo", "plan", "subscription", "invoice", "order_id",
  // Misc
  "category", "tag", "label", "ref", "source", "medium", "campaign",
  "from", "to", "date", "timestamp", "created", "updated",
];

// ── Batched parameter discovery ──────────────────────────────────────────

/**
 * Discover active HTTP parameters on an endpoint.
 *
 * @param {string} baseUrl
 * @param {string} path - Endpoint path
 * @param {object} opts - { method, batchSize, extraParams, timeout }
 * @returns {{ params: string[], method: string, path: string }}
 */
export async function discoverParams(baseUrl, path, opts = {}) {
  const method = opts.method || "GET";
  const batchSize = opts.batchSize || 50;
  const wordlist = [...COMMON_PARAMS, ...(opts.extraParams || [])];
  const canary = "pnth3r4_" + Math.random().toString(36).slice(2, 8);

  // 1. Baseline (no params)
  const baselineUrl = `${baseUrl}${path}`;
  const baseline = method === "GET"
    ? await safeFetch(baselineUrl)
    : await safeFetch(baselineUrl, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

  if (!baseline.ok) return { params: [], method, path };

  // Also get a "noise" baseline (with a definitely-fake param)
  const noiseUrl = `${baseUrl}${path}?__pnth_noise__=${canary}`;
  const noise = await safeFetch(noiseUrl);

  // If adding a random param changes the response, the endpoint is too dynamic
  const tooNoisy = isDifferent(baseline, noise, 0.01);

  const activeParams = [];

  // 2. Batch testing
  for (let i = 0; i < wordlist.length; i += batchSize) {
    const batch = wordlist.slice(i, i + batchSize);

    let batchResponse;
    if (method === "GET") {
      const qs = batch.map((p) => `${p}=${canary}`).join("&");
      batchResponse = await safeFetch(`${baseUrl}${path}?${qs}`);
    } else {
      const body = {};
      for (const p of batch) body[p] = canary;
      batchResponse = await safeFetch(`${baseUrl}${path}`, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    }

    if (!batchResponse.ok) continue;

    // If batch response equals baseline, no active params here
    if (!isDifferent(baseline, batchResponse)) continue;

    // If endpoint is noisy, skip individual testing (too many false positives)
    if (tooNoisy) continue;

    // 3. Narrow down: test each param individually
    for (const param of batch) {
      let singleResponse;
      if (method === "GET") {
        singleResponse = await safeFetch(`${baseUrl}${path}?${param}=${canary}`);
      } else {
        singleResponse = await safeFetch(`${baseUrl}${path}`, {
          method,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ [param]: canary }),
        });
      }

      if (singleResponse.ok && isDifferent(baseline, singleResponse)) {
        activeParams.push(param);
      }
    }
  }

  return { params: activeParams, method, path };
}

/**
 * Discover parameters across multiple endpoints.
 *
 * @param {string} baseUrl
 * @param {Array<{ path, status }>} endpoints
 * @param {object} opts - { onPhase, maxEndpoints, extraParams }
 * @returns {{ results: object[], findings: object[] }}
 */
export async function discoverAllParams(baseUrl, endpoints, opts = {}) {
  const progress = opts.onPhase || (() => {});
  const max = opts.maxEndpoints || 5;
  const findings = [];
  const results = [];

  const candidates = endpoints
    .filter((ep) => ep.status !== 404 && ep.status < 500)
    .filter((ep) => ep.path.includes("/api/") || ep.path.includes("?"))
    .slice(0, max);

  if (candidates.length === 0) return { results, findings };

  for (const ep of candidates) {
    progress(`Discovering parameters on ${ep.path}...`);
    const result = await discoverParams(baseUrl, ep.path, {
      extraParams: opts.extraParams,
    });
    results.push(result);

    if (result.params.length > 0) {
      // Flag security-sensitive parameters
      const sensitiveParams = result.params.filter((p) =>
        /admin|role|permission|debug|token|secret|password|key|cmd|exec|file|path|redirect|url/i.test(p),
      );

      if (sensitiveParams.length > 0) {
        findings.push({
          severity: "medium",
          title: `Sensitive parameters found on ${ep.path}`,
          description: `Active params: ${sensitiveParams.join(", ")}`,
          url: `${baseUrl}${ep.path}`,
          category: "parameter-discovery",
          source: "param-discovery",
        });
      }

      if (result.params.length > 0) {
        findings.push({
          severity: "info",
          title: `${result.params.length} active params on ${ep.path}`,
          description: result.params.join(", "),
          url: `${baseUrl}${ep.path}`,
          category: "parameter-discovery",
          source: "param-discovery",
        });
      }
    }
  }

  return { results, findings };
}
