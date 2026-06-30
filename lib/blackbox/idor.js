/**
 * IDOR / BOLA probes — test object-level authorization on parameterized routes.
 */
import { joinUrl } from "../../src/utils/url.js";
import { probeFetch } from "../../src/utils/http.js";

const ID_PARAM_RE = /\{([^}]+)\}/g;
const ID_LIKE_NAMES = /^(id|uuid|uid|user_?id|account_?id|resource_?id|item_?id|order_?id|seat_?id|project_?id)$/i;
const PROBE_IDS = ["1", "2", "999", "0", "admin"];
const SENSITIVE_BODY_RE = /email|password|role|admin|token|secret|billing|ssn|phone|address|user_id/i;

export function extractIdRoutes(spec, paths = []) {
  const routes = [];
  const seen = new Set();

  const add = (template, method = "GET") => {
    if (!template.includes("{")) return;
    const params = [...template.matchAll(ID_PARAM_RE)].map((m) => m[1]);
    if (!params.some((p) => ID_LIKE_NAMES.test(p) || p.toLowerCase().includes("id"))) return;
    const key = `${method}:${template}`;
    if (seen.has(key)) return;
    seen.add(key);
    routes.push({ template, method, params });
  };

  if (spec?.paths) {
    for (const [path, methods] of Object.entries(spec.paths)) {
      for (const method of Object.keys(methods)) {
        if (["get", "put", "patch", "delete"].includes(method)) add(path, method.toUpperCase());
      }
    }
  }

  for (const path of paths) {
    if (path.includes("{")) add(path, "GET");
  }

  for (const path of paths) {
    const m = path.match(/^(.+\/)([a-zA-Z0-9-]{1,64})$/);
    if (!m) continue;
    const prefix = m[1].replace(/\/$/, "");
    if (!/\/(users|accounts|orders|items|projects|resources|seats|documents)/i.test(prefix)) continue;
    add(`${prefix}/{id}`, "GET");
  }

  return routes.slice(0, 12);
}

function fillTemplate(template, values) {
  let path = template;
  for (const [key, val] of Object.entries(values)) {
    path = path.replace(`{${key}}`, encodeURIComponent(val));
  }
  return path;
}

export async function probeIdorBola(baseUrl, opts = {}) {
  const timeout = opts.timeout || 8_000;
  const authHeaders = opts.authHeaders || {};
  const findings = [];
  const routes = extractIdRoutes(opts.spec, opts.paths || []);

  if (routes.length === 0) return findings;

  for (const route of routes.slice(0, opts.maxRoutes || 8)) {
    const results = [];

    for (const id of PROBE_IDS) {
      const values = {};
      for (const p of route.params) values[p] = id;

      const path = fillTemplate(route.template, values);
      const res = await probeFetch(joinUrl(baseUrl, path), {
        timeout,
        method: route.method,
        headers: authHeaders,
      });

      if (!res || res.status >= 400 || res.body.length < 3) continue;
      results.push({ id, path, status: res.status, body: res.body });
    }

    const sensitive = results.filter((r) => SENSITIVE_BODY_RE.test(r.body));
    if (sensitive.length >= 2) {
      findings.push({
        severity: "high",
        title: `IDOR/BOLA: ${route.method} ${route.template}`,
        description:
          `Multiple object IDs (${sensitive.map((r) => r.id).join(", ")}) returned HTTP 200 with sensitive fields.`,
        url: joinUrl(baseUrl, sensitive[0].path),
        status: 200,
        category: "auth",
        source: "idor-probe",
      });
      continue;
    }

    const adminHit = results.find((r) => /999|admin/.test(r.id) && SENSITIVE_BODY_RE.test(r.body));
    if (adminHit && !Object.keys(authHeaders).length) {
      findings.push({
        severity: "high",
        title: `BOLA: privileged ID accessible on ${route.template}`,
        description: `ID "${adminHit.id}" returned sensitive data without authorization.`,
        url: joinUrl(baseUrl, adminHit.path),
        status: 200,
        category: "auth",
        source: "idor-probe",
      });
    }
  }

  return findings;
}
