/**
 * Adaptive black-box probes for live URL scans.
 * Uses OpenAPI paths and discovered endpoints as the attack surface.
 */
import { SecurityKnowledgeGraph } from "../knowledge-graph.js";
import {
  probeAuthEscalation,
  probeMethodConfusion,
  probeInfoLeakage,
  probeCors,
  probePrototypePollution,
  probeContentTypeConfusion,
  probeTimingAnalysis,
} from "../adaptive-probes.js";
import { normalizeBaseUrl } from "../../src/utils/url.js";

function graphFindingToPenthera(base, finding) {
  return {
    severity: finding.severity,
    title: finding.title,
    description: finding.detail || finding.title,
    url: finding.routeUrl ? `${base}${finding.routeUrl}` : base,
    category: finding.category,
    source: "adaptive-probe",
  };
}

/** Build route objects from OpenAPI paths. */
export function routesFromOpenApi(spec, paths = []) {
  if (!spec?.paths && paths.length === 0) return [];

  const pathMap = spec?.paths || {};
  const entries = paths.length > 0 ? paths : Object.keys(pathMap);

  return entries.map((path) => {
    const ops = pathMap[path] || {};
    const methods = Object.keys(ops)
      .filter((m) => ["get", "post", "put", "patch", "delete", "options"].includes(m))
      .map((m) => m.toUpperCase());
    const security = ops.get?.security || ops.post?.security || spec?.security;
    const auth = security?.length ? ["user"] : ["public"];

    return {
      url: path.startsWith("/") ? path : `/${path}`,
      methods: methods.length ? methods : ["GET"],
      auth,
      inputs: [],
      externalCalls: [],
      securityPatterns: [],
    };
  });
}

/** Build routes from discovered endpoint list. */
export function routesFromEndpoints(endpoints = []) {
  return endpoints
    .filter((ep) => ep.path && ep.status !== 404)
    .slice(0, 25)
    .map((ep) => ({
      url: ep.path.startsWith("/") ? ep.path : `/${ep.path}`,
      methods: ["GET"],
      auth: ["public"],
      inputs: [],
      externalCalls: [],
      securityPatterns: [],
    }));
}

/**
 * Run adaptive probe chains against a live target.
 *
 * @param {string} target
 * @param {object} opts - { spec, paths, endpoints, maxRoutes, onPhase }
 */
export async function runAdaptiveProbes(target, opts = {}) {
  const base = normalizeBaseUrl(target);
  const progress = opts.onPhase || (() => {});
  const graph = new SecurityKnowledgeGraph();

  let routes = routesFromOpenApi(opts.spec, opts.paths);
  if (routes.length === 0) {
    routes = routesFromEndpoints(opts.endpoints);
  }

  const maxRoutes = opts.maxRoutes || 15;
  routes = routes.slice(0, maxRoutes);

  if (routes.length === 0) {
    return [];
  }

  progress(`Running adaptive probes on ${routes.length} routes...`);

  const allFindings = [];
  const probes = [
    probeAuthEscalation,
    probeMethodConfusion,
    probeInfoLeakage,
    probeCors,
    probePrototypePollution,
    probeContentTypeConfusion,
    probeTimingAnalysis,
  ];

  for (const route of routes) {
    graph.addRoute(route);
    for (const probe of probes) {
      try {
        const findings = await probe(base, route, graph);
        allFindings.push(...findings.map((f) => graphFindingToPenthera(base, f)));
      } catch {
        // Skip failing probe on this route
      }
    }
  }

  return allFindings;
}
