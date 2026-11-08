#!/usr/bin/env node
/**
 * Refreshes test/fixtures/vercel-openapi.json, the trimmed copy of Vercel's OpenAPI spec that the
 * contract tests check every outgoing request against. Run it by hand, never from a test or at run
 * time (AGENTS.md rule 5):
 *
 *   node integrations/vercel/scripts/refresh-openapi.mjs            # downloads https://vercel.com/openapi.json
 *   node integrations/vercel/scripts/refresh-openapi.mjs spec.json  # or trims a copy you saved
 *
 * It keeps only the operations the server calls (OPERATIONS below), inlines every $ref they use,
 * and records the source and the date. Review the diff before you commit it: a changed schema is
 * a changed Vercel API.
 */
import { readFileSync, writeFileSync } from "node:fs";

const SOURCE = "https://vercel.com/openapi.json";
const OUT = new URL("../test/fixtures/vercel-openapi.json", import.meta.url);

const LINK = ["type", "org", "repo", "repoId", "repoOwnerId", "productionBranch"];

/**
 * Every Vercel REST call in lib/vercel.mjs, as [method, path in the spec, response fields the
 * server reads]. Request schemas are kept whole; a response schema keeps only the fields listed
 * here, and the refresh fails if the spec has one of them nowhere, because then the server reads
 * a field Vercel does not promise.
 */
export const OPERATIONS = [
  ["get", "/v10/projects", ["projects[].id", "projects[].name", ...LINK.map((f) => `projects[].link.${f}`), "pagination.next"]],
  ["get", "/v9/projects/{idOrName}", ["id", "name", ...LINK.map((f) => `link.${f}`)]],
  ["get", "/v13/deployments/{idOrUrl}", ["id", "projectId", "project.id", "target", "url"]],
  ["get", "/v1/integrations/configuration/{id}", ["id", "integrationId"]],
  ["get", "/v2/projects/{projectIdOrName}/checks", ["checks[].id", "checks[].source.kind", "checks[].source.integrationConfigurationId", "checks[].source.externalCheckName"]],
  ["post", "/v2/projects/{projectIdOrName}/checks", ["id"]],
  ["delete", "/v2/projects/{projectIdOrName}/checks/{checkId}", []],
  ["get", "/v2/deployments/{deploymentId}/check-runs", ["runs[].id", "runs[].checkId", "runs[].projectId", "runs[].deploymentId", "runs[].status"]],
  ["post", "/v2/deployments/{deploymentId}/check-runs", ["id", "checkId", "projectId", "deploymentId", "status"]],
  ["patch", "/v2/deployments/{deploymentId}/check-runs/{checkRunId}", []],
];

const BRANCHES = ["oneOf", "anyOf", "allOf"];
const LEAF = ["type", "enum", "format", "nullable", "pattern", "minimum", "maximum"];

/** A tree of the read fields: { projects: { "[]": { id: {}, link: { repoId: {} } } } }. */
function fieldTree(fields) {
  const tree = {};
  for (const f of fields) {
    let node = tree;
    for (const seg of f.split(".")) {
      const [name, arr] = seg.endsWith("[]") ? [seg.slice(0, -2), true] : [seg, false];
      node = node[name] ??= {};
      if (arr) node = node["[]"] ??= {};
    }
  }
  return tree;
}

/** The schema cut down to the fields in `tree`, keeping types, enums and the branches they sit in. */
function prune(schema, tree) {
  if (!schema || typeof schema !== "object") return {};
  const out = Object.fromEntries(LEAF.filter((k) => k in schema).map((k) => [k, schema[k]]));
  for (const b of BRANCHES) if (Array.isArray(schema[b])) out[b] = schema[b].map((s) => prune(s, tree));
  if (tree["[]"] && schema.items) out.items = prune(schema.items, tree["[]"]);
  const props = Object.keys(tree).filter((k) => k !== "[]");
  if (props.length && schema.properties) {
    out.properties = {};
    for (const k of props) if (schema.properties[k]) out.properties[k] = prune(schema.properties[k], tree[k]);
  }
  return out;
}

/** True when some branch of the schema has the field. */
export function hasField(schema, segs) {
  if (!schema || typeof schema !== "object") return false;
  if (!segs.length) return true;
  if (BRANCHES.some((b) => Array.isArray(schema[b]) && schema[b].some((s) => hasField(s, segs)))) return true;
  const [seg, ...rest] = segs;
  if (seg.endsWith("[]")) {
    const arr = schema.properties?.[seg.slice(0, -2)];
    return !!arr && [arr, ...BRANCHES.flatMap((b) => arr[b] ?? [])].some((a) => a.items && hasField(a.items, rest));
  }
  return !!schema.properties?.[seg] && hasField(schema.properties[seg], rest);
}

function resolver(spec) {
  const lookup = (ref) => ref.replace(/^#\//, "").split("/").reduce((o, k) => o?.[k.replace(/~1/g, "/").replace(/~0/g, "~")], spec);
  const inline = (node, stack = []) => {
    if (Array.isArray(node)) return node.map((n) => inline(n, stack));
    if (!node || typeof node !== "object") return node;
    if (typeof node.$ref === "string") {
      // A cycle becomes an open schema rather than an endless copy.
      if (stack.includes(node.$ref) || stack.length > 40) return {};
      return inline(lookup(node.$ref) ?? {}, [...stack, node.$ref]);
    }
    return Object.fromEntries(Object.entries(node).map(([k, v]) => [k, inline(v, stack)]));
  };
  return inline;
}

export function trim(spec, fetchedAt) {
  const inline = resolver(spec);
  const paths = {};
  const missing = [];
  for (const [method, path, reads] of OPERATIONS) {
    const op = spec.paths?.[path]?.[method];
    if (!op) throw new Error(`the spec has no ${method.toUpperCase()} ${path}: Vercel changed its API, check lib/vercel.mjs`);
    const ok = op.responses?.["200"] ?? op.responses?.["201"] ?? op.responses?.["204"];
    const full = inline(ok?.content?.["application/json"]?.schema ?? null);
    for (const f of reads) {
      if (!hasField(full, f.split("."))) missing.push(`${method.toUpperCase()} ${path}: ${f}`);
    }
    paths[path] ??= {};
    paths[path][method] = {
      operationId: op.operationId,
      parameters: inline(op.parameters ?? []),
      requestBody: inline(op.requestBody?.content?.["application/json"]?.schema ?? null),
      reads,
      response: full ? prune(full, fieldTree(reads)) : null,
    };
  }
  if (missing.length) process.stderr.write(`response fields the server reads that the spec does not have:\n  ${missing.join("\n  ")}\n`);
  return { "x-source": SOURCE, "x-fetched": fetchedAt, "x-spec-version": spec.info?.version ?? null, "x-not-in-spec": missing, paths };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const file = process.argv[2];
  const spec = file
    ? JSON.parse(readFileSync(file, "utf8"))
    : await (await fetch(SOURCE, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(60_000) })).json();
  const out = trim(spec, new Date().toISOString().slice(0, 10));
  writeFileSync(OUT, `${JSON.stringify(out, null, 1)}\n`);
  process.stdout.write(`wrote ${OUT.pathname}: ${OPERATIONS.length} operations from ${SOURCE}\n`);
  if (out["x-not-in-spec"].length) process.exitCode = 1;
}
