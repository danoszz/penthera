/**
 * Every field the server sends to Vercel, the values Vercel allows for it, and where that comes
 * from. The fake Vercel (test/vercel-contract.mjs) refuses any field that is not in this table,
 * and any value outside it, with a 400 in Vercel's error shape: { error: { code, message } }.
 *
 * `live` says what a live call has shown:
 *   "refused live <date>"  Vercel refused a value; `refusal` is its answer, word for word.
 *   "worked live <date>"   a live call with this field went through.
 *   "unverified live"      only the docs or the spec say so; no live call has shown it yet.
 * The README table "What Vercel accepts" lists the same rows; a test keeps the two in step.
 *
 * Sources:
 *   spec   test/fixtures/vercel-openapi.json, Vercel's OpenAPI spec trimmed, fetched 7 Nov 2026
 *   create https://vercel.com/docs/rest-api/checks-v2/create-a-check (updated 7 Nov 2026)
 *   update https://vercel.com/docs/rest-api/checks-v2/update-a-check-run (updated 7 Nov 2026)
 *   oauth  https://vercel.com/docs/integrations/create-integration/vercel-api-integrations
 *   gates  https://vercel.com/docs/deployment-checks
 */

const CREATE = "POST /v2/projects/{projectIdOrName}/checks";
const RUN = "POST /v2/deployments/{deploymentId}/check-runs";
const PATCH = "PATCH /v2/deployments/{deploymentId}/check-runs/{checkRunId}";
const EXCHANGE = "POST /v2/oauth/access_token";

const str = (v) => typeof v === "string" && v.length > 0;
const oneOf = (...values) => (v) => values.includes(v);
const TEAM_READS = [
  "GET /v10/projects",
  "GET /v9/projects/{idOrName}",
  "GET /v13/deployments/{idOrUrl}",
  "GET /v1/integrations/configuration/{id}",
  "GET /v2/projects/{projectIdOrName}/checks",
  CREATE,
  "DELETE /v2/projects/{projectIdOrName}/checks/{checkId}",
  "GET /v2/deployments/{deploymentId}/check-runs",
  RUN,
  PATCH,
];

export const ALLOWED = [
  // The code exchange (form-encoded; not in the OpenAPI spec).
  ...["client_id", "client_secret", "code", "redirect_uri"].map((field) => ({
    op: EXCHANGE, in: "form", field, allowed: "required, a non-empty string", ok: str, source: "oauth", live: "worked live 7 Nov",
  })),

  // Every call on a team installation carries teamId ("append the teamId query parameter to each
  // API request"; without it, 403).
  ...TEAM_READS.map((op) => ({
    op, in: "query", field: "teamId", allowed: "the installation's team_... id", ok: (v) => /^team_[A-Za-z0-9]+$/.test(String(v)), source: "oauth, spec",
    live: op === "GET /v10/projects" ? "worked live 7 Nov" : "unverified live",
  })),
  { op: "GET /v10/projects", in: "query", field: "limit", allowed: "a string (the spec types it as one); we send 20", ok: (v) => /^\d{1,3}$/.test(String(v)), source: "spec", live: "worked live 7 Nov" },
  { op: "GET /v10/projects", in: "query", field: "from", allowed: "the continuation token from pagination.next", ok: str, source: "spec", live: "unverified live" },

  // The check (create a check).
  { op: CREATE, in: "body", field: "name", allowed: "required, a string; no length limit is documented", ok: str, source: "spec, create", live: "unverified live" },
  { op: CREATE, in: "body", field: "requires", allowed: "required: build-ready, deployment-url or none", ok: oneOf("build-ready", "deployment-url", "none"), source: "spec, create", live: "unverified live" },
  {
    op: CREATE, in: "body", field: "blocks", allowed: "deployment-alias or none (the spec also lists build-start, deployment-start and deployment-promotion)",
    ok: oneOf("deployment-alias", "none"), source: "spec, create, gates", live: "refused live 7 Nov",
    refusal: { code: "not_implemented", message: "Only deployment-alias and none are currently supported for blocks" },
  },
  {
    op: CREATE, in: "body", field: "targets", allowed: "unique strings: production, preview, all (alone) or a custom environment env_...",
    ok: (v) => Array.isArray(v) && v.length > 0 && new Set(v).size === v.length && v.every((t) => ["production", "preview", "all"].includes(t) || /^env_[A-Za-z0-9]+$/.test(t)) && (!v.includes("all") || v.length === 1),
    source: "spec, create", live: "unverified live",
  },
  { op: CREATE, in: "body", field: "isRerequestable", allowed: "a boolean; git-provider checks cannot be re-requested", ok: (v) => typeof v === "boolean", source: "spec, create", live: "unverified live" },
  { op: CREATE, in: "body", field: "timeout", allowed: "a number of seconds, default 300; no maximum is documented", ok: (v) => Number.isFinite(v) && v > 0, source: "spec, create", live: "unverified live" },
  {
    op: CREATE, in: "source", field: "kind", allowed: "integration, for an integration's token (the spec also has webhook and git-provider)",
    ok: oneOf("integration"), source: "spec, create", live: "refused live 7 Nov",
    // The README records the code; the message of that answer was not kept.
    refusal: { code: "not_implemented", message: "git-provider checks cannot be created by an integration" },
  },
  { op: CREATE, in: "source", field: "integrationId", allowed: "the integration's oac_... id; required in the answer's integration source", ok: (v) => /^oac_[A-Za-z0-9]+$/.test(String(v)), source: "spec, create", live: "unverified live" },
  { op: CREATE, in: "source", field: "integrationConfigurationId", allowed: "this installation's icfg_... id; required in the answer's integration source", ok: (v) => /^icfg_[A-Za-z0-9]+$/.test(String(v)), source: "spec, create", live: "unverified live" },

  // A check run (create a run, when Vercel has not made one).
  { op: RUN, in: "body", field: "checkId", allowed: "required: the id of a check on the deployment's project", ok: str, source: "spec", live: "unverified live" },

  // The result (update a check run). The body has additionalProperties: false.
  { op: PATCH, in: "body", field: "status", allowed: "queued, running or completed", ok: oneOf("queued", "running", "completed"), source: "spec, update", live: "unverified live" },
  { op: PATCH, in: "body", field: "conclusion", allowed: "canceled, skipped, timeout, failed, neutral or succeeded", ok: oneOf("canceled", "skipped", "timeout", "failed", "neutral", "succeeded"), source: "spec, update", live: "unverified live" },
  { op: PATCH, in: "body", field: "conclusionText", allowed: "a string; no length limit is documented", ok: str, source: "spec, update", live: "unverified live" },
  { op: PATCH, in: "body", field: "externalUrl", allowed: "a URI matching ^https?://|^sso:", ok: (v) => typeof v === "string" && /^https?:\/\/|^sso:/.test(v) && URL.canParse(v), source: "spec, update", live: "unverified live" },
];

/** The rows for one operation and place. */
export const allowedFor = (op, place) => ALLOWED.filter((r) => r.op === op && r.in === place);

/** Every field in `values` checked against the table: [{ field, row, problem }]; empty when all fit. */
export function checkFields(op, place, values) {
  const rows = allowedFor(op, place);
  const out = [];
  for (const [field, value] of Object.entries(values ?? {})) {
    if (value === undefined) continue;
    const row = rows.find((r) => r.field === field);
    if (!row) out.push({ field, row: null, problem: `${place} field ${field} is not in the table of what Vercel accepts (test/vercel-allowed.mjs)` });
    else if (!row.ok(value)) out.push({ field, row, problem: `${JSON.stringify(value)} is outside what Vercel accepts: ${row.allowed}` });
  }
  return out;
}

/** A refused value as Vercel answers it: the live answer when one was seen, otherwise a plain 400. */
export function refusalOf(found) {
  const { field, row, problem } = found;
  if (row?.refusal) return { status: 400, error: { ...row.refusal } };
  return { status: 400, error: { code: "bad_request", message: `Invalid request: ${field}: ${problem}` } };
}
