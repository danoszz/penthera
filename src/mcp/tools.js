/**
 * The tools `penthera mcp` offers. Each one is read-only: it runs one of
 * Penthera's deterministic engines and returns findings. None writes to the
 * workspace, none runs an active (payload) scan, none spawns a shell.
 *
 * The inputSchema of each tool is also what the server validates arguments
 * against (./validate.js), so the published contract and the check are one
 * object.
 */
import { scanRepo } from "../scan-repo.js";
import { scanUrl } from "../scan-url.js";
import { mergeResults } from "../cli/merge-results.js";
import { resolveScanOptions } from "../cli/profiles.js";
import { normalizeBaseUrl } from "../utils/url.js";
import { buildActionPlan } from "../../lib/remediation/index.js";
import { CATEGORY_REFERENCES, SOURCES } from "../../lib/references.js";
import { RULE_OWASP, OWASP_NAMES } from "../../lib/agents/owasp.js";
import { BUILT_IN_TEMPLATES } from "../../lib/templates.js";
import { runtimeAdvisoriesForRepo, runtimeAdvisoriesForResponse } from "../../lib/advisories/index.js";
import { stampProvenance } from "../../lib/provenance.js";
import { confinePath, checkTarget, ToolInputError } from "./workspace.js";
import { buildResult, callResult, cleanText, DEFAULT_FINDINGS, MAX_FINDINGS } from "./results.js";

// ── Shared argument schemas ───────────────────────────────────────────────

const PATH = {
  type: "string",
  minLength: 1,
  maxLength: 4096,
  // No NUL or other control characters; the path never reaches a shell either way.
  pattern: "^[^\\u0000-\\u001f\\u007f]+$",
  description: "Project folder to scan, relative to the workspace root or absolute inside it. Default: the workspace root.",
};
const MAX = {
  type: "integer",
  minimum: 1,
  maximum: MAX_FINDINGS,
  description: `How many findings to return, most severe first (default ${DEFAULT_FINDINGS}).`,
};

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

// ── Limits each tool states in its result ─────────────────────────────────

const REPO_LIMITS = [
  "Static analysis of the source tree: secrets, code-execution sinks with taint-lite, routes and trust boundaries, runtime version pins. No full data-flow analysis and no execution of the code.",
  "Files over the scanners' size limits and folders like node_modules, dist and .git are skipped.",
];
const URL_LIMITS = [
  "Passive checks only (quick or standard profile): TLS, headers, cookies, CORS, discovery, templates, OpenAPI and auth smoke tests. No injection payloads, no fuzzing, no recon sources: active modes are not available over MCP; run `penthera <url> --deep` yourself for those.",
  "Only what the target serves to an unauthenticated client is seen.",
  "Stays on the target and hosts listed with --allow-host. A redirect may also move within the target's registrable domain. Anything else is refused and named under Not checked. Retire.js uses the vendored snapshot, never a download.",
];
const DEPS_LIMITS = [
  "Reads the lockfile and the installed package tree; never runs install scripts and never contacts the registry (no --online).",
  "Capabilities come from static patterns in package code; a package can still do things its code hides at rest.",
];
const AGENTS_LIMITS = [
  "Project-level agent config only (.mcp.json, .claude/, .cursor/, .vscode/mcp.json, skills, AGENTS.md, CLAUDE.md). The user's home config (--home) is outside the workspace and is not read.",
  "Codex config.toml and Windsurf mcp_config.json are not read yet; the result's Not checked list names any such file it saw.",
  "MCP servers are never started, so tool descriptions (tools/list) and tool-description poisoning are not checked.",
  "No penthera.lock is written; rug-pull detection compares against an existing lock only.",
];
const ADVISORY_LIMITS = [
  "Compares visible product versions with the advisories in Penthera's signed rule packs, offline. A distribution build or hidden version is reported as \"check on server\", never as affected or safe.",
  "No evidence of a product is not evidence that it is absent or patched.",
];

// ── Tool definitions ──────────────────────────────────────────────────────

/**
 * @typedef {object} Ctx
 * @property {() => Promise<string[]>} roots  realpath'd workspace roots
 * @property {string[]} allowHosts
 * @property {boolean} offline
 * @property {string} version
 */

export const TOOLS = [
  {
    name: "scan_repo",
    title: "Scan a repository",
    description: "White-box scan of a local project folder: hardcoded secrets, code-execution sinks, API routes and trust boundaries, runtime versions with known advisories. Offline and read-only. Returns findings with evidence at file:line and confidence labels.",
    inputSchema: { type: "object", properties: { path: PATH, max_findings: MAX }, additionalProperties: false },
    annotations: { title: "Scan a repository", ...READ_ONLY },
    async run(args, ctx) {
      const { real, display } = confinePath(args.path, await ctx.roots());
      const raw = await scanRepo(real, { offline: true });
      const merged = mergeResults([raw]);
      return buildResult({
        tool: "scan_repo", target: display, findings: merged.findings, limits: REPO_LIMITS, maxFindings: args.max_findings,
        extra: { routes: Array.isArray(raw.attackSurface) ? raw.attackSurface.length : 0, coverage: coverageOf(raw.coverage) },
        scan: { mode: "repo", coverage: raw.coverage },
      });
    },
  },
  {
    name: "scan_url",
    title: "Scan a running app (passive)",
    description: "Passive black-box scan of a running web app the user is authorized to test: TLS, security headers, cookies, CORS, exposed files and docs, OpenAPI and auth checks. Sends no attack payloads: profile quick sends no login request, standard sends one POST /api/login with invalid credentials. Only loopback targets, or hosts the user listed with --allow-host when configuring this server, can be scanned, and a redirect off them is refused.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", minLength: 8, maxLength: 2048, pattern: "^https?://[^\\s]+$", description: "http(s) URL of the app, e.g. http://localhost:3000" },
        profile: { type: "string", enum: ["quick", "standard"], description: "quick skips Retire.js and parameter discovery; standard is the full passive scan (default)." },
        max_findings: MAX,
      },
      required: ["url"],
      additionalProperties: false,
    },
    annotations: { title: "Scan a running app (passive)", ...READ_ONLY, openWorldHint: true },
    async run(args, ctx) {
      const target = checkTarget(args.url, ctx.allowHosts);
      const url = normalizeBaseUrl(target.href);
      // Active modes are never reachable here: the profile is quick or standard, and deep/fuzz/adaptive/recon are fixed off.
      const p = resolveScanOptions({ profile: args.profile || "standard" });
      // The scope holds on every request and redirect hop, with or without --offline.
      const raw = await scanUrl(url, {
        timeout: 10000, concurrency: 10, profile: p.profile,
        recon: false, deep: false, fuzz: false, adaptive: false,
        skipRetireJs: p.skipRetireJs, skipParamDiscovery: p.skipParamDiscovery,
        offline: ctx.offline, scoped: true, allowHosts: ctx.offline ? [] : ctx.allowHosts, onPhase: () => {},
      });
      if (!raw.reachable) throw new ToolInputError(`Target unreachable: ${url}. Is the app running?`);
      const merged = mergeResults([raw]);
      const blocked = (raw.egress?.blocked || []).map((b) => cleanText(b.host, 300));
      return buildResult({
        tool: "scan_url", target: url, findings: merged.findings, limits: URL_LIMITS, maxFindings: args.max_findings,
        extra: { profile: p.profile, offline: !!ctx.offline, blocked_hosts: blocked },
        scan: { mode: "url", notChecked: blocked.length ? [`Requests that left the allowed scope were refused: ${blocked.join(", ")}. What they would have returned was not checked.`] : [] },
      });
    },
  },
  {
    name: "check_dependencies",
    title: "Check dependencies",
    description: "What each npm or Python dependency can do (install scripts, shell, network, eval, credential access), known-malicious packages and typosquats, read offline from the lockfile and installed tree. Read-only.",
    inputSchema: {
      type: "object",
      properties: { path: PATH, prod: { type: "boolean", description: "Skip dev dependencies (npm)." }, max_findings: MAX },
      additionalProperties: false,
    },
    annotations: { title: "Check dependencies", ...READ_ONLY },
    async run(args, ctx) {
      const { real, display } = confinePath(args.path, await ctx.roots());
      const { scanDeps } = await import("../../lib/deps/index.js");
      let raw;
      try {
        raw = await scanDeps(real, { prod: !!args.prod });
      } catch (e) {
        throw new ToolInputError(e.message);
      }
      const d = raw.deps || {};
      return buildResult({
        tool: "check_dependencies", target: display, findings: stampProvenance(raw.findings, raw.timestamp), limits: DEPS_LIMITS, maxFindings: args.max_findings,
        extra: { ecosystem: d.ecosystem || null, lockfile: d.lockfile || null, packages: d.total ?? null, scanned: d.scanned ?? null, capabilities: d.capabilityCounts || {} },
        scan: { mode: "deps" },
      });
    },
  },
  {
    name: "audit_ai_tooling",
    title: "Audit AI agent config",
    description: "Audit the project's AI agent setup: skills, MCP servers, hooks, permissions, plugins and rule files, for hidden instructions, curl-pipe-shell, unpinned MCP packages, inline secrets and wildcard permissions. Grades A to F, or gives no grade when it finds no agent config. Offline, deterministic, read-only.",
    inputSchema: { type: "object", properties: { path: PATH, max_findings: MAX }, additionalProperties: false },
    annotations: { title: "Audit AI agent config", ...READ_ONLY },
    async run(args, ctx) {
      const { real, display, named } = confinePath(args.path, await ctx.roots(), { skillFile: true });
      const { scanAgents } = await import("../../lib/agents/index.js");
      const raw = await scanAgents(real, { home: false, pin: false, skillTarget: named });
      const a = raw.agents || {};
      return buildResult({
        tool: "audit_ai_tooling", target: display, findings: stampProvenance(raw.findings, raw.timestamp), limits: AGENTS_LIMITS, maxFindings: args.max_findings,
        extra: { grade: a.grade ?? null, score: a.score ?? null, inventory: a.inventory ? { ...a.inventory, configFiles: (a.inventory.configFiles || []).slice(0, 50).map((f) => cleanText(f, 300)) } : null },
        scan: { mode: "agents", agents: a },
      });
    },
  },
  {
    name: "explain_finding",
    title: "Explain a finding",
    description: "Explain a finding's rule: what it checks, why it matters, how to fix it, effort, whether it is an owner action (rotate a key, change DNS), research references and OWASP MCP/Agentic ids. Pass the `rule` field of a finding (e.g. agents/mcp-unpinned, secrets, headers).",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string", minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9][A-Za-z0-9/_.:-]*$", description: "The finding's `rule`, e.g. agents/mcp-unpinned." } },
      required: ["id"],
      additionalProperties: false,
    },
    annotations: { title: "Explain a finding", ...READ_ONLY },
    async run(args) {
      return explain(args.id);
    },
  },
  {
    name: "runtime_advisories",
    title: "Runtime advisories",
    description: "Is the PHP, nginx, Apache, Node.js, Python or OpenSSL an app runs affected by a published advisory, or past end of life? Give a project path (reads Dockerfiles, compose files and version pins) or the response headers you already have (Server, X-Powered-By). Offline.",
    inputSchema: {
      type: "object",
      properties: {
        path: PATH,
        headers: {
          type: "object",
          description: "Response headers, e.g. {\"server\": \"nginx/1.24.0\", \"x-powered-by\": \"PHP/8.1.2\"}.",
          maxProperties: 50,
          propertyNames: { type: "string", minLength: 1, maxLength: 100, pattern: "^[A-Za-z0-9-]+$" },
          additionalProperties: { type: "string", maxLength: 1000 },
        },
        max_findings: MAX,
      },
      additionalProperties: false,
    },
    annotations: { title: "Runtime advisories", ...READ_ONLY },
    async run(args, ctx) {
      if (args.headers && args.path !== undefined) throw new ToolInputError("Pass either path or headers, not both.");
      if (args.headers) {
        const headers = Object.fromEntries(Object.entries(args.headers).map(([k, v]) => [k.toLowerCase(), v]));
        const cookieNames = String(headers["set-cookie"] || "").split(/,(?=[^;]*=)/).map((c) => c.split("=")[0].trim()).filter(Boolean);
        const findings = runtimeAdvisoriesForResponse({ headers, cookieNames });
        return buildResult({ tool: "runtime_advisories", target: "response headers", findings: stampProvenance(findings, new Date().toISOString()), limits: ADVISORY_LIMITS, maxFindings: args.max_findings });
      }
      const { real, display } = confinePath(args.path, await ctx.roots());
      const findings = runtimeAdvisoriesForRepo(real, {});
      return buildResult({ tool: "runtime_advisories", target: display, findings: stampProvenance(findings, new Date().toISOString()), limits: ADVISORY_LIMITS, maxFindings: args.max_findings });
    },
  },
];

export const TOOL_BY_NAME = new Map(TOOLS.map((t) => [t.name, t]));

/** The tools/list entries (no handlers). */
export function listTools() {
  return TOOLS.map(({ name, title, description, inputSchema, annotations }) => ({ name, title, description, inputSchema, annotations }));
}

// ── Coverage ledger ───────────────────────────────────────────────────────

const NOT_RUN_TOOL = { deps: "check_dependencies", agents: "audit_ai_tooling" };

/** scan_repo's coverage ledger (lib/coverage.js): what was examined, skipped and not run, with MCP tool names. */
function coverageOf(c) {
  if (!c) return null;
  return {
    files: c.files,
    source_files: c.sourceFiles,
    source_files_analysed: c.sourceFilesAnalysed,
    truncated: !!c.truncated,
    checks: (c.families || []).map((f) => ({ id: f.id, label: f.label, ran: f.ran, examined: f.examined, skipped: f.skipped })),
    not_run: (c.notRun || []).map((n) => ({ id: n.id, label: n.label, tool: NOT_RUN_TOOL[n.id] || null })),
    blind_spots: c.blindSpots ? { count: c.blindSpots.count, by_reason: c.blindSpots.byReason, paths: (c.blindSpots.paths || []).slice(0, 20).map((p) => cleanText(typeof p === "string" ? p : p.path, 300)) } : null,
  };
}

// ── explain_finding ───────────────────────────────────────────────────────

function explain(id) {
  if (/^pf-[0-9a-f]+$/.test(id)) {
    throw new ToolInputError("That is a finding id. This server keeps no scan state between calls, so pass the finding's `rule` field instead (for example agents/mcp-unpinned).");
  }
  const agentsRule = id.startsWith("agents/") ? id.slice("agents/".length) : null;
  const template = BUILT_IN_TEMPLATES.find((t) => t.id === id);
  const category = agentsRule !== null ? "agent-config" : CATEGORY_REFERENCES[id] ? id : template ? (template.info?.tags?.[0] || "exposure") : null;
  const known = (agentsRule !== null && Object.hasOwn(RULE_OWASP, agentsRule)) || !!template || category !== null;

  const probe = { severity: "high", category: category || id, templateId: id, title: template?.info?.name || "" };
  const plan = buildActionPlan([probe])[0];
  const refs = (CATEGORY_REFERENCES[probe.category] || []).map((k) => SOURCES[k] ? { key: k, cite: SOURCES[k].cite, title: SOURCES[k].title, url: SOURCES[k].url } : null).filter(Boolean);
  const owasp = agentsRule ? (RULE_OWASP[agentsRule] || []).map((o) => ({ id: o, name: OWASP_NAMES[o] || o })) : [];

  const structured = {
    tool: "explain_finding",
    rule: id,
    known,
    category: probe.category,
    ...(template && { check: { name: template.info?.name, default_severity: template.info?.severity, requests: (template.http || []).map((h) => `${h.method || "GET"} ${h.path}`) } }),
    action: plan.action,
    why: plan.why,
    fix: plan.fix,
    effort: plan.effort,
    owner_action: plan.ownerAction,
    references: refs,
    owasp,
    docs: agentsRule !== null ? "https://github.com/danoszz/penthera/blob/main/docs/commands/agents.md" : "https://github.com/danoszz/penthera/blob/main/docs/METHODOLOGY.md",
    limits: known ? [] : [`"${id}" is not a rule Penthera knows; the guidance below is the generic review advice.`],
  };
  const text = [
    `${id}${known ? "" : " (unknown rule)"}: ${plan.action}.`,
    `Why: ${plan.why}`,
    `Fix: ${plan.fix}`,
    `Effort: ${plan.effort}${plan.ownerAction ? "; an owner action, not a code change a tool should make" : ""}.`,
    ...(owasp.length ? [`OWASP: ${owasp.map((o) => o.name).join(" · ")}`] : []),
  ].join("\n");
  return { structured, text };
}

export { callResult };
