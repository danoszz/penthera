/**
 * A fake Vercel API that holds every request the server makes to Vercel's published contract.
 *
 * The contract is test/fixtures/vercel-openapi.json, a trimmed copy of https://vercel.com/openapi.json
 * (scripts/refresh-openapi.mjs; the date is in the file). For each request it checks:
 *
 *   - that an operation with this method and path exists,
 *   - path parameters are filled, required query parameters are there, every query parameter
 *     is one the operation declares, and its value fits the declared type or enum,
 *   - the Bearer token, and the JSON body against the request schema (ajv: required fields,
 *     enums, types, patterns, additionalProperties). `source` on a check is checked against the
 *     one branch of the schema's oneOf that its `kind` names, because the spec's branches overlap,
 *   - and each answer this fake gives against the response schema, so the fake cannot answer in
 *     a shape Vercel does not promise.
 *
 * The OAuth code exchange is not in the OpenAPI spec; it is checked by hand against Vercel's
 * docs (form-encoded client_id, client_secret, code, redirect_uri).
 *
 * Every mismatch is pushed to `violations` as "<METHOD> <path>: <field>: <problem>", and the
 * request is answered 400, as Vercel would.
 */
import { readFileSync } from "node:fs";
import Ajv from "ajv";

export const SPEC = JSON.parse(readFileSync(new URL("./fixtures/vercel-openapi.json", import.meta.url), "utf8"));
const ajv = new Ajv({ strict: false, allErrors: true, validateFormats: false });
const compiled = new Map();
/** OpenAPI's `nullable` without a `type` is legal there and refused by ajv; it means nothing extra. */
const forAjv = (node) => {
  if (Array.isArray(node)) return node.map(forAjv);
  if (!node || typeof node !== "object") return node;
  const out = Object.fromEntries(Object.entries(node).map(([k, v]) => [k, forAjv(v)]));
  if ("nullable" in out && !("type" in out)) delete out.nullable;
  return out;
};
const compile = (schema) => {
  if (!compiled.has(schema)) compiled.set(schema, ajv.compile(forAjv(schema)));
  return compiled.get(schema);
};

const OPS = Object.entries(SPEC.paths).flatMap(([path, methods]) =>
  Object.entries(methods).map(([method, op]) => {
    const names = [];
    const re = new RegExp(`^${path.replace(/\{([^}]+)\}/g, (_, n) => (names.push(n), "([^/]+)"))}$`);
    return { method: method.toUpperCase(), path, re, names, op };
  }),
);

/** The source branch of the create-check schema that a `kind` names. */
function sourceBranch(schema, kind) {
  const branches = schema?.properties?.source?.oneOf ?? [];
  const marker = { integration: "integrationConfigurationId", webhook: "webhookId", "git-provider": "externalCheckName" }[kind];
  return branches.find((b) => marker && b.properties?.[marker]) ?? null;
}

function fitsParam(value, schema) {
  if (!schema) return true;
  if (Array.isArray(schema.enum)) return schema.enum.map(String).includes(value);
  if (schema.type === "number" || schema.type === "integer") return value !== "" && Number.isFinite(Number(value));
  if (schema.type === "boolean") return value === "true" || value === "false" || value === "1" || value === "0";
  return true;
}

const fmt = (errors, base = "") => (errors ?? []).map((e) => `${base}${e.instancePath || "/"}: ${e.message}${e.params?.allowedValues ? ` (${e.params.allowedValues.join(", ")})` : ""}${e.params?.additionalProperty ? ` (${e.params.additionalProperty})` : ""}`);

/**
 * Checks one request against the contract. Returns { op, params, body, problems }.
 */
export function checkRequest(method, url, init = {}) {
  const problems = [];
  const match = OPS.find((o) => o.method === method && o.re.test(url.pathname));
  if (!match) return { op: null, problems: [`no operation ${method} ${url.pathname} in Vercel's spec`] };
  const params = Object.fromEntries(match.names.map((n, i) => [n, decodeURIComponent(match.re.exec(url.pathname)[i + 1])]));
  const declared = match.op.parameters ?? [];
  for (const p of declared.filter((p) => p.in === "path")) if (!params[p.name]) problems.push(`path parameter ${p.name} is empty`);
  for (const p of declared.filter((p) => p.in === "query" && p.required)) if (!url.searchParams.has(p.name)) problems.push(`query ${p.name} is required`);
  for (const [k, v] of url.searchParams) {
    const p = declared.find((d) => d.in === "query" && d.name === k);
    if (!p) problems.push(`query ${k} is not a parameter of ${match.op.operationId}`);
    else if (!fitsParam(v, p.schema)) problems.push(`query ${k}=${v} does not fit ${JSON.stringify(p.schema.enum ?? p.schema.type)}`);
  }
  const auth = new Headers(init.headers ?? {}).get("authorization") ?? "";
  if (!/^Bearer \S+$/.test(auth)) problems.push("Authorization: Bearer <token> is missing");

  let body;
  const schema = match.op.requestBody;
  if (init.body !== undefined && init.body !== null) {
    if (!schema) problems.push(`${match.op.operationId} takes no body`);
    if (!/^application\/json/.test(new Headers(init.headers ?? {}).get("content-type") ?? "")) problems.push("Content-Type is not application/json");
    try {
      body = JSON.parse(String(init.body));
    } catch {
      problems.push("the body is not JSON");
    }
  } else if (schema?.required?.length) {
    problems.push(`a body with ${schema.required.join(", ")} is required`);
  }
  if (schema && body !== undefined) {
    let whole = schema;
    if (schema.properties?.source?.oneOf && body?.source !== undefined) {
      const branch = sourceBranch(schema, body.source?.kind);
      if (!branch) problems.push(`/source/kind: ${JSON.stringify(body.source?.kind)} names no branch of the source schema`);
      else {
        const v = compile(branch);
        if (!v(body.source)) problems.push(...fmt(v.errors, "/source"));
      }
      const { source: _s, ...rest } = schema.properties;
      whole = { ...schema, properties: rest };
      body = { ...body };
      const { source: _b, ...bodyRest } = body;
      if (!compile(whole)(bodyRest)) problems.push(...fmt(compile(whole).errors));
    } else if (!compile(whole)(body)) {
      problems.push(...fmt(compile(whole).errors));
    }
  }
  return { op: match, params, body: body ?? null, problems };
}

/**
 * The trimmed response schemas keep types and enums but not the fields that tell oneOf branches
 * apart, so a response is checked against any of its branches.
 */
const anyOfAll = (node) =>
  Array.isArray(node) ? node.map(anyOfAll)
    : node && typeof node === "object" ? Object.fromEntries(Object.entries(node).map(([k, v]) => [k === "oneOf" ? "anyOf" : k, anyOfAll(v)]))
      : node;
const responseSchemas = new Map();

/** Checks a fake answer against the operation's (trimmed) response schema. */
export function checkResponse(op, json) {
  if (!op.op.response || json === null || json === undefined) return [];
  if (!responseSchemas.has(op.op)) responseSchemas.set(op.op, anyOfAll(op.op.response));
  const v = compile(responseSchemas.get(op.op));
  return v(json) ? [] : fmt(v.errors, "response ");
}

/**
 * A stateful fake Vercel. `world` holds the projects, deployments and the configuration; checks
 * and runs live here. Options:
 *   autoRuns: Vercel makes a queued run of each project check on each production deployment (true)
 *   token:    the access token the code exchange hands out
 */
export function contractVercel({ world, token, clientId, clientSecret, code, redirectUri, autoRuns = true }) {
  const violations = [];
  const calls = [];
  const checks = {};
  const runs = {};
  let n = 1;

  const projectOf = (deploymentId) => world.deployments[deploymentId]?.projectId ?? world.deployments[deploymentId]?.project?.id;
  const reply = (status, body) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const runsFor = (deploymentId) => {
    runs[deploymentId] ??= [];
    const d = world.deployments[deploymentId];
    if (autoRuns && d?.target === "production") {
      for (const k of checks[projectOf(deploymentId)] ?? []) {
        if (!runs[deploymentId].some((r) => r.checkId === k.id)) runs[deploymentId].push(newRun(deploymentId, k));
      }
    }
    return runs[deploymentId];
  };
  const newRun = (deploymentId, k) => ({
    id: `crun_${n++}`, checkId: k.id, deploymentId, projectId: projectOf(deploymentId), name: k.name,
    ownerId: world.teamId, status: "queued", timeout: k.timeout ?? 300, createdAt: 1, updatedAt: 1, source: k.source,
  });

  const fetch = async (input, init = {}) => {
    try {
      return await serve(input, init);
    } catch (e) {
      violations.push(`the contract check itself failed on ${init.method ?? "GET"} ${String(input)}: ${e.message}`);
      return reply(500, {});
    }
  };
  const serve = async (input, init = {}) => {
    const url = new URL(String(input));
    const method = (init.method ?? "GET").toUpperCase();
    calls.push({ method, url, body: init.body ?? null });
    if (url.origin !== "https://api.vercel.com") {
      violations.push(`${method} ${url.href}: not Vercel's API`);
      return reply(404, {});
    }
    if (url.pathname === "/v2/oauth/access_token") {
      const ct = new Headers(init.headers ?? {}).get("content-type") ?? "";
      const form = new URLSearchParams(String(init.body ?? ""));
      const problems = [];
      if (method !== "POST") problems.push("method is not POST");
      if (!ct.startsWith("application/x-www-form-urlencoded")) problems.push("Content-Type is not form-encoded");
      for (const k of ["client_id", "client_secret", "code", "redirect_uri"]) if (!form.get(k)) problems.push(`${k} is missing`);
      if (problems.length) {
        violations.push(...problems.map((p) => `POST /v2/oauth/access_token: ${p}`));
        return reply(400, { error: { code: "bad_request" } });
      }
      if (form.get("code") !== code || form.get("client_id") !== clientId || form.get("client_secret") !== clientSecret || form.get("redirect_uri") !== redirectUri) {
        return reply(400, { error: { code: "invalid_grant" } });
      }
      return reply(200, { token_type: "Bearer", access_token: token, installation_id: world.configurationId, user_id: world.userId, team_id: world.teamId });
    }

    const { op, params, body, problems } = checkRequest(method, url, init);
    if (problems.length) {
      violations.push(...problems.map((p) => `${method} ${url.pathname}: ${p}`));
      return reply(400, { error: { code: "bad_request", message: problems[0] } });
    }
    if (new Headers(init.headers ?? {}).get("authorization") !== `Bearer ${token}`) return reply(403, { error: { code: "forbidden" } });
    if (world.teamId && url.searchParams.get("teamId") !== world.teamId) return reply(403, { error: { code: "forbidden", message: "teamId is required for a team token" } });

    const answer = (status, json) => {
      if (status < 300) {
        const bad = checkResponse(op, json);
        if (bad.length) violations.push(...bad.map((b) => `${method} ${op.path} (fake answer): ${b}`));
      }
      return reply(status, json);
    };
    const project = (id) => world.projects.find((p) => p.id === id);

    switch (`${method} ${op.path}`) {
      case "GET /v10/projects":
        return answer(200, { projects: world.projects, pagination: { count: world.projects.length, next: null, prev: null } });
      case "GET /v9/projects/{idOrName}":
        return project(params.idOrName) ? answer(200, project(params.idOrName)) : reply(404, { error: { code: "not_found" } });
      case "GET /v13/deployments/{idOrUrl}": {
        const d = world.deployments[params.idOrUrl];
        return d ? answer(200, JSON.parse(JSON.stringify({ id: params.idOrUrl, ...d }))) : reply(404, { error: { code: "not_found" } });
      }
      case "GET /v1/integrations/configuration/{id}":
        return params.id === world.configurationId
          ? answer(200, { id: world.configurationId, integrationId: world.integrationId, slug: "penthera", ownerId: world.teamId, teamId: world.teamId })
          : reply(404, { error: { code: "not_found" } });
      case "GET /v2/projects/{projectIdOrName}/checks":
        return answer(200, { checks: checks[params.projectIdOrName] ?? [] });
      case "POST /v2/projects/{projectIdOrName}/checks": {
        if (body.source?.kind === "git-provider") return reply(400, { error: { code: "not_implemented", message: "Integrations cannot create git-provider checks" } });
        if (body.source?.kind === "integration" && (body.source.integrationConfigurationId !== world.configurationId || (body.source.integrationId && body.source.integrationId !== world.integrationId))) {
          return reply(400, { error: { code: "bad_request", message: "source does not belong to this integration" } });
        }
        const created = {
          id: `chk_${n++}`, ...body, projectId: params.projectIdOrName, ownerId: world.teamId, sourceKind: body.source?.kind ?? "integration",
          isRerequestable: body.isRerequestable ?? false, targets: body.targets ?? ["production"], blocks: body.blocks ?? "deployment-alias",
          timeout: body.timeout ?? 300, createdAt: 1, updatedAt: 1,
        };
        (checks[params.projectIdOrName] ??= []).push(created);
        return answer(200, created);
      }
      case "DELETE /v2/projects/{projectIdOrName}/checks/{checkId}":
        checks[params.projectIdOrName] = (checks[params.projectIdOrName] ?? []).filter((k) => k.id !== params.checkId);
        return reply(204);
      case "GET /v2/deployments/{deploymentId}/check-runs":
        return world.deployments[params.deploymentId] ? answer(200, { runs: runsFor(params.deploymentId) }) : reply(404, { error: { code: "not_found" } });
      case "POST /v2/deployments/{deploymentId}/check-runs": {
        const d = world.deployments[params.deploymentId];
        const k = d && (checks[projectOf(params.deploymentId)] ?? []).find((c) => c.id === body.checkId);
        if (!k) return reply(400, { error: { code: "bad_request", message: "check is not on this deployment's project" } });
        const run = newRun(params.deploymentId, k);
        runsFor(params.deploymentId).push(run);
        return answer(200, run);
      }
      case "PATCH /v2/deployments/{deploymentId}/check-runs/{checkRunId}": {
        const run = (runs[params.deploymentId] ?? []).find((r) => r.id === params.checkRunId);
        if (!run) return reply(404, { error: { code: "not_found" } });
        Object.assign(run, body, { updatedAt: 2 });
        return answer(200, run);
      }
      default:
        violations.push(`${method} ${url.pathname}: in the spec, but this fake does not serve it`);
        return reply(501, {});
    }
  };
  return { fetch, violations, calls, checks, runs };
}
