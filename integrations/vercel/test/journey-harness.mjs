/**
 * The offline world the install journey runs in, shared by test/e2e-journey.test.js,
 * test/e2e-listing.test.js and scripts/local-journey.mjs:
 *
 *   - the real server (createApp) with an in-memory store,
 *   - a fake Vercel held to Vercel's spec and to test/vercel-allowed.mjs (test/vercel-contract.mjs),
 *   - a fake GitHub OIDC issuer: a local RSA key whose JWKS is served at GitHub's JWKS URL, and
 *     oidc() to sign a token like the one a workflow run gets.
 *
 * Nothing here reaches the network: every fetch is answered by the fakes or recorded in `outside`.
 */
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { createApp } from "../lib/app.mjs";
import { GITHUB_ISSUER, GITHUB_JWKS_URL } from "../lib/oidc.mjs";
import { memoryStore } from "../lib/store.mjs";
import { contractVercel } from "./vercel-contract.mjs";

export const BASE = "https://vercel.penthera.example.test";
export const CLIENT_ID = "oac_testclient";
export const CLIENT_SECRET = `cs_${randomBytes(18).toString("hex")}`;
export const ACCESS_TOKEN = `at_${randomBytes(18).toString("hex")}`;
export const CODE = randomBytes(12).toString("hex");
export const CFG = "icfg_JourneyConfig1";
export const TEAM = "team_JourneyTeam1";
export const NEXT = "https://vercel.com/integrations/penthera/new/done?configurationId=icfg_JourneyConfig1";
export const T0 = Date.UTC(2026, 10, 7, 12, 0, 0);

export const github = generateKeyPairSync("rsa", { modulusLength: 2048 });
export const KID = "journey-kid";
export const JWKS = { keys: [{ ...github.publicKey.export({ format: "jwk" }), kid: KID, use: "sig", alg: "RS256" }] };
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString("base64url");
export function oidc(deploymentId, t = T0, { base = BASE, runId = "123456" } = {}) {
  const s = Math.floor(t / 1000);
  const h = b64({ alg: "RS256", typ: "JWT", kid: KID });
  const p = b64({
    iss: GITHUB_ISSUER, aud: `${base}/report/${deploymentId}`, repository: "daan/gaia-web", repository_id: "9001",
    repository_owner: "daan", repository_owner_id: "42", event_name: "repository_dispatch", ref: "refs/heads/main",
    workflow_ref: "daan/gaia-web/.github/workflows/penthera-vercel.yml@refs/heads/main", run_id: runId, iat: s - 5, nbf: s - 5, exp: s + 295,
  });
  return `${h}.${p}.${sign("RSA-SHA256", Buffer.from(`${h}.${p}`), github.privateKey).toString("base64url")}`;
}

/** Daan's Vercel team: one GitHub project, one GitLab one, a production and a preview deployment. */
export const world = () => ({
  configurationId: CFG, teamId: TEAM, userId: "user_daan", integrationId: "oac_PentheraIntegration",
  projects: [
    { id: "prj_gaiaweb", name: "gaia-web", link: { type: "github", org: "daan", repo: "gaia-web", repoId: 9001, repoOwnerId: 42, productionBranch: "main" } },
    { id: "prj_notes", name: "notes", link: { type: "gitlab", projectNamespace: "daan", projectName: "notes", projectId: "77", productionBranch: "main" } },
  ],
  deployments: {
    dpl_prod1: { projectId: "prj_gaiaweb", target: "production", url: "gaia-web-abc.vercel.app" },
    dpl_preview1: { projectId: "prj_gaiaweb", target: null, url: "gaia-web-git-x.vercel.app" },
  },
});

export function harness({ autoRuns = true, publicView = false, base = BASE, now = () => T0 } = {}) {
  const w = world();
  // Vercel's reduced public view of a deployment: `project: { id, name }` and no `projectId`.
  if (publicView) for (const d of Object.values(w.deployments)) Object.assign(d, { project: { id: d.projectId, name: "gaia-web" }, projectId: undefined });
  const vercel = contractVercel({ world: w, token: ACCESS_TOKEN, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, code: CODE, redirectUri: `${base}/install`, autoRuns });
  const outside = [];
  const fetch = async (input, init) => {
    const href = String(input);
    if (href === GITHUB_JWKS_URL) return new Response(JSON.stringify(JWKS), { status: 200 });
    if (new URL(href).origin !== "https://api.vercel.com") outside.push(href);
    return vercel.fetch(input, init);
  };
  const env = {
    INTEGRATION_CLIENT_ID: CLIENT_ID, INTEGRATION_CLIENT_SECRET: CLIENT_SECRET, PUBLIC_BASE_URL: base,
    PENTHERA_TOKEN_KEYS: `v1:${randomBytes(32).toString("base64")}`, CRON_SECRET: `cron_${randomBytes(12).toString("hex")}`,
  };
  const store = memoryStore();
  const app = createApp({ env, store, fetch, now });
  return { app, store, vercel, outside, env, world: w };
}

// A browser's cookie jar, enough for our cookies.
export function jar() {
  const cookies = new Map();
  return {
    take(res) {
      for (const c of res.headers.getSetCookie()) {
        const [pair, ...attrs] = c.split(";");
        const [k, v] = pair.split("=");
        if (attrs.some((a) => /max-age=0/i.test(a.trim())) || v === "") cookies.delete(k);
        else cookies.set(k, v);
      }
      return res;
    },
    header: () => [...cookies].map(([k, v]) => `${k}=${v}`).join("; "),
    has: (k) => cookies.has(k),
  };
}

export const get = (path, browser, headers = {}) => new Request(`${BASE}${path}`, { headers: { cookie: browser.header(), ...headers } });
export const post = (path, body, browser, origin) =>
  new Request(`${BASE}${path}`, { method: "POST", body, headers: { "content-type": "application/x-www-form-urlencoded", cookie: browser.header(), ...(origin === undefined ? {} : { origin }) } });

/** Vercel's signed integration-configuration.removed webhook for this installation. */
export function removedWebhook({ base = BASE, at = T0 + 1000, projects = ["prj_gaiaweb"] } = {}) {
  const raw = JSON.stringify({ id: `evt_${randomBytes(4).toString("hex")}`, type: "integration-configuration.removed", createdAt: at, payload: { configuration: { id: CFG, projects } } });
  return new Request(`${base}/webhook`, { method: "POST", body: raw, headers: { "x-vercel-signature": createHmac("sha1", CLIENT_SECRET).update(raw).digest("hex") } });
}

/**
 * The workflow's last step: POST /report with the run's OIDC token, and the SHA-256 of the host it
 * scanned (`host`), as the workflow sends it. Without `host`, the body of a workflow from before.
 */
export function reportRequest(deploymentId, conclusion, { base = BASE, t = T0, runId, projectId = "prj_gaiaweb", ip = "203.0.113.10", host, reason } = {}) {
  const extra = { ...(host ? { hostSha256: createHash("sha256").update(host).digest("hex") } : {}), ...(reason ? { reason } : {}) };
  return new Request(`${base}/report`, {
    method: "POST", body: JSON.stringify({ deploymentId, projectId, conclusion, ...extra }),
    headers: { authorization: `Bearer ${oidc(deploymentId, t, { base, runId })}`, "content-type": "application/json", "x-real-ip": ip },
  });
}

/** The URL Vercel sends the browser to after an install from the listing link (no state). */
export const listingInstallUrl = (base = BASE) => `${base}/install?code=${CODE}&configurationId=${CFG}&teamId=${TEAM}&next=${encodeURIComponent(NEXT)}&source=external`;
