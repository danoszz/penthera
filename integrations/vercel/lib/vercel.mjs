/**
 * The handful of Vercel REST calls the integration makes. Each takes an
 * injected fetch, so tests never reach the network.
 *
 *   POST /v2/oauth/access_token           exchange the install code (no scope)
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
 * "Unverified"). Errors carry the HTTP status and Vercel's error code only,
 * never a body or a header.
 */
export const API = "https://api.vercel.com";

export class VercelError extends Error {
  constructor(status, code) {
    super(`vercel_api_${status}`);
    this.status = status;
    this.code = code;
  }
}

async function fail(res) {
  let code = "unknown";
  try {
    const body = await res.json();
    if (typeof body?.error?.code === "string") code = body.error.code.slice(0, 64);
  } catch {}
  throw new VercelError(res.status, code);
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
    /** Only the deployment's id, project and target. Everything else is dropped here. */
    async getDeployment(deploymentId, { signal } = {}) {
      const d = await call("GET", `/v13/deployments/${enc(deploymentId)}`, { signal });
      return {
        id: typeof d?.id === "string" ? d.id : typeof d?.uid === "string" ? d.uid : "",
        projectId: typeof d?.projectId === "string" ? d.projectId : "",
        target: typeof d?.target === "string" ? d.target : null,
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
