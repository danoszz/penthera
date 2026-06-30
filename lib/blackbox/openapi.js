/**
 * OpenAPI / Swagger discovery and misconfiguration checks.
 */
import { joinUrl } from "../../src/utils/url.js";
import { probeFetch } from "../../src/utils/http.js";

const SPEC_CANDIDATES = [
  "/openapi.json",
  "/swagger.json",
  "/api/openapi.json",
  "/openapi.yaml",
];

const DOC_CANDIDATES = [
  { path: "/docs", name: "FastAPI/Swagger UI" },
  { path: "/redoc", name: "ReDoc API docs" },
  { path: "/swagger", name: "Swagger UI" },
  { path: "/api/docs", name: "API docs" },
];

/**
 * @param {string} baseUrl
 * @returns {Promise<{ spec: object|null, specUrl: string|null, paths: string[], findings: object[] }>}
 */
export async function scanOpenApi(baseUrl, opts = {}) {
  const timeout = opts.timeout || 8_000;
  const findings = [];
  let spec = null;
  let specUrl = null;

  for (const path of SPEC_CANDIDATES) {
    const res = await probeFetch(joinUrl(baseUrl, path), { timeout });
    if (!res || res.status !== 200) continue;
    try {
      spec = JSON.parse(res.body);
      specUrl = joinUrl(baseUrl, path);
      break;
    } catch {
      // not JSON — skip
    }
  }

  for (const doc of DOC_CANDIDATES) {
    const res = await probeFetch(joinUrl(baseUrl, doc.path), { timeout });
    if (!res || res.status !== 200) continue;
    const looksLikeDocs = /swagger|openapi|redoc|rapidoc/i.test(res.body);
    if (!looksLikeDocs && doc.path !== "/docs") continue;

    findings.push({
      severity: "medium",
      title: `${doc.name} exposed`,
      description: `API documentation is publicly accessible at ${doc.path}. Disable in production or protect with authentication.`,
      url: joinUrl(baseUrl, doc.path),
      status: res.status,
      category: "exposure",
      source: "openapi-scan",
    });
  }

  if (specUrl) {
    findings.push({
      severity: "medium",
      title: "OpenAPI specification exposed",
      description: "Machine-readable API spec reveals all routes, parameters, and schemas to attackers.",
      url: specUrl,
      status: 200,
      category: "exposure",
      source: "openapi-scan",
    });
  }

  const paths = spec?.paths ? Object.keys(spec.paths) : [];
  const unprotectedRoutes = [];

  for (const path of paths) {
    const methods = spec.paths[path] || {};
    const hasSecurity = Object.values(methods).some((op) => op?.security?.length > 0);
    const globalSecurity = spec.security?.length > 0;
    if (hasSecurity || globalSecurity) continue;

    for (const [method, op] of Object.entries(methods)) {
      if (!["get", "post", "put", "delete", "patch"].includes(method)) continue;
      unprotectedRoutes.push({ path, method: method.toUpperCase(), summary: op.summary || path });
    }
  }

  for (const route of unprotectedRoutes
    .filter((r) => r.method === "GET")
    .sort((a, b) => sensitivePathScore(a.path) - sensitivePathScore(b.path))) {
    const res = await probeFetch(joinUrl(baseUrl, route.path), { timeout });
    if (!res || res.status >= 400) continue;

    const hasBody = res.body && res.body.length > 2;
    const looksSensitive = /password|secret|token|user_id|email|seat|participant/i.test(res.body);

    if (hasBody) {
      findings.push({
        severity: looksSensitive ? "high" : "medium",
        title: `Unauthenticated endpoint: ${route.method} ${route.path}`,
        description: route.summary
          ? `${route.summary} — responds HTTP ${res.status} without authentication.`
          : `Responds HTTP ${res.status} without authentication.`,
        url: joinUrl(baseUrl, route.path),
        status: res.status,
        category: "auth",
        source: "openapi-scan",
      });
    }
  }

  return {
    spec,
    specUrl,
    paths,
    unprotectedRoutes,
    findings,
  };
}

/**
 * Basic authentication hardening checks for login endpoints.
 */
export async function probeAuthEndpoints(baseUrl, opts = {}) {
  const timeout = opts.timeout || 8_000;
  const findings = [];
  const loginUrl = joinUrl(baseUrl, "/api/login");

  const validAttempt = await probeFetch(loginUrl, {
    timeout,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "penthera-probe-invalid", password: "invalid-password-12345" }),
  });

  if (!validAttempt) return findings;

  if (validAttempt.status === 200) {
    findings.push({
      severity: "critical",
      title: "Login accepts arbitrary credentials",
      description: "POST /api/login returned HTTP 200 for invalid test credentials.",
      url: loginUrl,
      status: 200,
      category: "auth",
      source: "auth-probe",
    });
  }

  // Rate limiting — 8 rapid attempts
  let rateLimited = false;
  for (let i = 0; i < 8; i++) {
    const res = await probeFetch(loginUrl, {
      timeout,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "rate-test", password: `attempt-${i}` }),
    });
    if (res && (res.status === 429 || /rate.?limit/i.test(res.body))) {
      rateLimited = true;
      break;
    }
  }

  if (!rateLimited && validAttempt.status !== 404) {
    findings.push({
      severity: "medium",
      title: "No login rate limiting detected",
      description: "8 rapid login attempts did not trigger HTTP 429 or a rate-limit response.",
      url: loginUrl,
      status: validAttempt.status,
      category: "auth",
      source: "auth-probe",
    });
  }

  // SQL injection smoke test — error-based
  const sqli = await probeFetch(loginUrl, {
    timeout,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "' OR '1'='1", password: "' OR '1'='1" }),
  });

  if (sqli && /sql|syntax error|sqlite|postgres|mysql|ORA-/i.test(sqli.body)) {
    findings.push({
      severity: "critical",
      title: "SQL error leaked on login",
      description: "Login endpoint returned a database error message for SQLi probe payload.",
      url: loginUrl,
      status: sqli.status,
      category: "injection",
      source: "auth-probe",
    });
  }

  return findings;
}

function sensitivePathScore(path) {
  if (/data|json|user|admin|config|secret|env|export/i.test(path)) return 0;
  if (path === "/" || path.includes("{")) return 2;
  return 1;
}
