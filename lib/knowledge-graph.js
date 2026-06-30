/**
 * Security Knowledge Graph (Portable)
 *
 * Builds a graph of the application's security posture:
 *   Nodes = routes, auth mechanisms, data stores, external services, findings
 *   Edges = trust boundaries, data flows, attack paths
 *
 * Enables chain discovery, impact analysis, coverage tracking, and historical diffs.
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const RESULTS_DIR = join(process.cwd(), ".security-results");
const GRAPH_FILE = join(RESULTS_DIR, "knowledge-graph.json");
const HISTORY_FILE = join(RESULTS_DIR, "findings-history.json");

export class SecurityKnowledgeGraph {
  constructor() {
    this.nodes = new Map();
    this.edges = [];
    this.findings = [];
    this.probeResults = [];
  }

  // ── Node management ─────────────────────────────────────────────────────

  addRoute(route) {
    const id = `route:${route.url}`;
    this.nodes.set(id, { type: "route", data: route, findings: [] });

    for (const auth of route.auth) {
      const authId = `auth:${auth}`;
      if (!this.nodes.has(authId)) {
        this.nodes.set(authId, { type: "auth", data: { mechanism: auth }, findings: [] });
      }
      this.edges.push({ from: id, to: authId, type: "protected-by", label: `requires ${auth}` });
    }

    for (const svc of route.externalCalls) {
      const svcId = `service:${svc}`;
      if (!this.nodes.has(svcId)) {
        this.nodes.set(svcId, { type: "service", data: { name: svc }, findings: [] });
      }
      this.edges.push({ from: id, to: svcId, type: "calls", label: `calls ${svc}` });
    }

    return id;
  }

  // ── Finding management ──────────────────────────────────────────────────

  addFinding({ severity, category, title, detail, routeUrl, chain = [], probeData = {} }) {
    const finding = {
      id: `F-${this.findings.length + 1}`,
      severity,
      category,
      title,
      detail,
      routeUrl,
      chain,
      probeData,
      timestamp: new Date().toISOString(),
    };
    this.findings.push(finding);

    const routeId = `route:${routeUrl}`;
    if (this.nodes.has(routeId)) {
      this.nodes.get(routeId).findings.push(finding.id);
    }
    return finding;
  }

  addProbeResult(result) {
    this.probeResults.push({ ...result, timestamp: new Date().toISOString() });
    return result;
  }

  // ── Chain Discovery ─────────────────────────────────────────────────────

  discoverChains() {
    const chains = [];

    // Pattern 1: Public endpoint + user input + external service
    const publicRoutes = this.getRoutesByAuth("public");
    for (const route of publicRoutes) {
      if (route.data.inputs.length > 0 && route.data.externalCalls.length > 0) {
        chains.push({
          type: "public-input-to-external",
          severity: "medium",
          path: [route.data.url],
          description: `Public endpoint ${route.data.url} accepts input (${route.data.inputs.join(", ")}) → calls ${route.data.externalCalls.join(", ")}`,
        });
      }
    }

    // Pattern 2: Parameterised routes without transaction protection
    const paramRoutes = [...this.nodes.values()].filter(n => n.type === "route" && n.data.hasParams);
    for (const route of paramRoutes) {
      if (!route.data.securityPatterns.includes("transactional")) {
        chains.push({
          type: "potential-idor",
          severity: "medium",
          path: [route.data.url],
          description: `Parameterised route ${route.data.url} — verify ownership check`,
        });
      }
    }

    // Pattern 3: Error leak chain
    const leakyRoutes = [...this.nodes.values()]
      .filter(n => n.type === "route" && n.data.securityPatterns.includes("RISK:error-leak"));
    if (leakyRoutes.length > 0) {
      chains.push({
        type: "error-leak-chain",
        severity: "low",
        path: leakyRoutes.map(r => r.data.url),
        description: `${leakyRoutes.length} routes may leak error details → attacker learns stack → targeted exploitation`,
      });
    }

    // Pattern 4: Rate-limit-free public endpoints
    const unlimitedPublic = publicRoutes.filter(r => !r.data.auth.includes("rate-limited"));
    for (const route of unlimitedPublic) {
      if (route.data.externalCalls.length > 0) {
        chains.push({
          type: "no-rate-limit-abuse",
          severity: "medium",
          path: [route.data.url],
          description: `Public ${route.data.url} has no rate limit, calls ${route.data.externalCalls.join(", ")} — abuse/cost vector`,
        });
      }
    }

    // Pattern 5: Auth confusion on mixed-auth routes
    const mixedAuth = [...this.nodes.values()]
      .filter(n => n.type === "route" && n.data.auth.length > 1 && !n.data.auth.includes("public"));
    for (const route of mixedAuth) {
      chains.push({
        type: "auth-confusion",
        severity: "low",
        path: [route.data.url],
        description: `${route.data.url} accepts multiple auth (${route.data.auth.join(" + ")}) — verify each path`,
      });
    }

    // Pattern 6: Critical chain — auth bypass + IDOR
    const authBypass = this.findings.filter(f => f.category === "auth-bypass");
    const idor = this.findings.filter(f => f.category === "idor");
    if (authBypass.length > 0 && idor.length > 0) {
      chains.push({
        type: "auth-bypass-to-idor",
        severity: "critical",
        path: [...authBypass.map(f => f.routeUrl), ...idor.map(f => f.routeUrl)],
        description: `Auth bypass on ${authBypass[0].routeUrl} + IDOR on ${idor[0].routeUrl} = cross-user access`,
      });
    }

    return chains;
  }

  // ── Queries ─────────────────────────────────────────────────────────────

  getRoutesByAuth(authType) {
    return [...this.nodes.values()].filter(n => n.type === "route" && n.data.auth.includes(authType));
  }

  // ── Persistence ─────────────────────────────────────────────────────────

  save() {
    mkdirSync(RESULTS_DIR, { recursive: true });
    const serializable = {
      timestamp: new Date().toISOString(),
      nodes: Object.fromEntries(this.nodes),
      edges: this.edges,
      findings: this.findings,
      probeResults: this.probeResults,
      chains: this.discoverChains(),
      stats: this.getStats(),
    };
    writeFileSync(GRAPH_FILE, JSON.stringify(serializable, null, 2));

    const history = this.loadHistory();
    history.push({
      timestamp: serializable.timestamp,
      findingCount: this.findings.length,
      chainCount: serializable.chains.length,
      routeCount: [...this.nodes.values()].filter(n => n.type === "route").length,
      findings: this.findings.map(f => ({ id: f.id, severity: f.severity, category: f.category, title: f.title, routeUrl: f.routeUrl })),
    });
    writeFileSync(HISTORY_FILE, JSON.stringify(history.slice(-50), null, 2));
    return serializable;
  }

  loadHistory() {
    try {
      if (existsSync(HISTORY_FILE)) return JSON.parse(readFileSync(HISTORY_FILE, "utf-8"));
    } catch { /* ignore */ }
    return [];
  }

  diffWithLastRun() {
    const history = this.loadHistory();
    if (history.length === 0) return { new: this.findings, fixed: [], recurring: [] };
    const last = history[history.length - 1];
    const lastTitles = new Set(last.findings.map(f => `${f.category}:${f.routeUrl}`));
    const currentTitles = new Set(this.findings.map(f => `${f.category}:${f.routeUrl}`));
    return {
      new: this.findings.filter(f => !lastTitles.has(`${f.category}:${f.routeUrl}`)),
      fixed: last.findings.filter(f => !currentTitles.has(`${f.category}:${f.routeUrl}`)),
      recurring: this.findings.filter(f => lastTitles.has(`${f.category}:${f.routeUrl}`)),
    };
  }

  getStats() {
    const routes = [...this.nodes.values()].filter(n => n.type === "route");
    return {
      totalRoutes: routes.length,
      publicRoutes: routes.filter(r => r.data.auth.includes("public")).length,
      userRoutes: routes.filter(r => r.data.auth.includes("user")).length,
      adminRoutes: routes.filter(r => r.data.auth.includes("admin")).length,
      cronRoutes: routes.filter(r => r.data.auth.includes("cron")).length,
      routesWithParams: routes.filter(r => r.data.hasParams).length,
      routesWithExternalCalls: routes.filter(r => r.data.externalCalls.length > 0).length,
      riskyRoutes: routes.filter(r => r.data.securityPatterns.some(p => p.startsWith("RISK:"))).length,
      totalFindings: this.findings.length,
      criticalFindings: this.findings.filter(f => f.severity === "critical").length,
      highFindings: this.findings.filter(f => f.severity === "high").length,
      mediumFindings: this.findings.filter(f => f.severity === "medium").length,
      lowFindings: this.findings.filter(f => f.severity === "low").length,
    };
  }
}
