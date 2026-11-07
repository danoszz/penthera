/**
 * The handful of Vercel REST calls the integration makes. Each takes an
 * injected fetch, so tests never reach the network.
 *
 *   POST /v2/oauth/access_token           exchange the install code (no scope)
 *   GET  /v1/integrations/configuration/{id}  this installation's integrationId, for the check's source
 *   GET  /v10/projects                    list granted projects   (project: Read)
 *   GET  /v9/projects/{id}                read one project        (project: Read)
 *   GET  /v2/projects/{id}/checks         list the project's checks
 *   POST /v2/projects/{id}/checks         register our check
 *   DELETE /v2/projects/{id}/checks/{cid} remove our check
 *   GET  /v13/deployments/{id}            which project a deployment belongs to (POST /report)
 *   GET  /v2/deployments/{id}/check-runs  find our check's run for one deployment (POST /report)
 *   POST /v2/deployments/{id}/check-runs  start that run if Vercel has not
 *   PATCH /v2/deployments/{id}/check-runs/{rid}  set its conclusion
 *
 * Which scope the three checks-v2 calls need is not documented (README.md,
 * "Unverified"). Errors carry the HTTP status, Vercel's error code and its error message (at most
 * 200 characters, for the error log, which redacts token shapes), never a header or the rest of
 * the body.
 */
export const API = "https://api.vercel.com";

export class VercelError extends Error {
  constructor(status, code, detail = "") {
    super(`vercel_api_${status}`);
    this.status = status;
    this.code = code;
    /** Vercel's error message, cut to 200 printable characters. Logged only through lib/log.mjs. */
    this.detail = detail;
  }
}

async function fail(res) {
  let code = "unknown";
  let detail = "";
  try {
    const body = await res.json();
    if (typeof body?.error?.code === "string") code = body.error.code.slice(0, 64);
    if (typeof body?.error?.message === "string") detail = body.error.message.replace(/[^\x20-\x7e]/g, " ").slice(0, 200);
  } catch {}
  throw new VercelError(res.status, code, detail);
}

/** Exchanges the one-time install code. Returns { accessToken, configurationId, teamId, userId }. */
export async function exchangeCode({ code, clientId, clientSecret, redirectUri, fetch: f = globalThis.fetch }) {
  const res = await f(`${API}/v2/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: redirectUri }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) await fail(res);
  const json = await res.json();
  if (typeof json?.access_token !== "string" || !json.access_token) throw new VercelError(502, "no_access_token");
  return {
    accessToken: json.access_token,
    configurationId: json.installation_id ?? null,
    teamId: json.team_id ?? null,
    userId: json.user_id ?? null,
  };
}

/** A client bound to one install's token and owner. */
export function vercelClient({ token, teamId, fetch: f = globalThis.fetch }) {
  async function call(method, path, { query = {}, body, signal } = {}) {
    const url = new URL(path, API);
    for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    if (teamId) url.searchParams.set("teamId", teamId);
    const res = await f(url, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal: signal ? AbortSignal.any([AbortSignal.timeout(10_000), signal]) : AbortSignal.timeout(10_000),
    });
    if (!res.ok) await fail(res);
    return res.status === 204 ? null : res.json().catch(() => null);
  }
  const enc = encodeURIComponent;
  return {
    /** One page of granted projects: { projects: [{ id, name, repo, branch }], next }. */
    async listProjects({ from, limit = 20 } = {}) {
      const json = await call("GET", "/v10/projects", { query: { limit, from } });
      const list = Array.isArray(json) ? json : (json?.projects ?? []);
      return { projects: list.map(projectView), next: json?.pagination?.next ?? null };
    },
    /**
     * The id of the integration this installation belongs to (oac_...), from Vercel's record of
     * the installation, or null when Vercel's answer is not about `configurationId`.
     */
    async getIntegrationId(configurationId, { signal } = {}) {
      const json = await call("GET", `/v1/integrations/configuration/${enc(configurationId)}`, { signal });
      if (json?.id !== configurationId) return null;
      return typeof json.integrationId === "string" && /^oac_[A-Za-z0-9]{1,64}$/.test(json.integrationId) ? json.integrationId : null;
    },
    async getProject(id, { signal } = {}) {
      return projectView(await call("GET", `/v9/projects/${enc(id)}`, { signal }));
    },
    async listChecks(projectId, { signal } = {}) {
      const json = await call("GET", `/v2/projects/${enc(projectId)}/checks`, { signal });
      return Array.isArray(json?.checks) ? json.checks : [];
    },
    async createCheck(projectId, body) {
      return call("POST", `/v2/projects/${enc(projectId)}/checks`, { body });
    },
    async deleteCheck(projectId, checkId, { signal } = {}) {
      return call("DELETE", `/v2/projects/${enc(projectId)}/checks/${enc(checkId)}`, { signal });
    },
    /** Only the deployment's id, project, target and host. Everything else is dropped here. */
    async getDeployment(deploymentId, { signal } = {}) {
      const d = await call("GET", `/v13/deployments/${enc(deploymentId)}`, { signal });
      // Vercel answers one of three views (OpenAPI, GET /v13/deployments/{idOrUrl}): the owner's view
      // has `projectId`; the reduced public view has only `project.id`. Both are Vercel's own data.
      const projectId = typeof d?.projectId === "string" ? d.projectId : typeof d?.project?.id === "string" ? d.project.id : "";
      return {
        id: typeof d?.id === "string" ? d.id : typeof d?.uid === "string" ? d.uid : "",
        projectId,
        target: typeof d?.target === "string" ? d.target : null,
        // The deployment's own host, as Vercel names it: what a scan of this deployment must have read.
        url: typeof d?.url === "string" ? d.url.toLowerCase().replace(/^https:\/\//, "").replace(/\/$/, "") : "",
      };
    },
    async listCheckRuns(deploymentId, { signal } = {}) {
      const json = await call("GET", `/v2/deployments/${enc(deploymentId)}/check-runs`, { signal });
      return Array.isArray(json?.runs) ? json.runs : [];
    },
    async createCheckRun(deploymentId, checkId, { signal } = {}) {
      return call("POST", `/v2/deployments/${enc(deploymentId)}/check-runs`, { body: { checkId }, signal });
    },
    async updateCheckRun(deploymentId, runId, body, { signal } = {}) {
      return call("PATCH", `/v2/deployments/${enc(deploymentId)}/check-runs/${enc(runId)}`, { body, signal });
    },
  };
}

/** Only the project fields the pages and the relay use. Everything else is dropped here. */
export function projectView(p) {
  const link = p?.link;
  const github = link?.type === "github" && link.org && link.repo;
  const repoId = github && (typeof link.repoId === "number" || typeof link.repoId === "string") ? String(link.repoId) : null;
  const ownerId = github && (typeof link.repoOwnerId === "number" || typeof link.repoOwnerId === "string") ? String(link.repoOwnerId) : null;
  return {
    id: String(p?.id ?? ""),
    name: String(p?.name ?? ""),
    repo: github ? `${link.org}/${link.repo}` : null,
    repoId: repoId && /^\d{1,20}$/.test(repoId) ? repoId : null,
    repoOwnerId: ownerId && /^\d{1,20}$/.test(ownerId) ? ownerId : null,
    branch: github ? String(link.productionBranch || "main") : null,
  };
}
