// Daan's install journey, end to end, through the real app, against a fake Vercel that holds every
// request to Vercel's published API spec (test/vercel-contract.mjs, test/fixtures/vercel-openapi.json).
//
// It walks: /start, /install (from our link and from the Marketplace), Pick, Workflow, Turn on (a
// browser's Origin: null and our own origin), the dispatch's POST /report with a GitHub OIDC token
// from a local test key set, the check run's conclusion, /configure, the signed `removed` webhook,
// and an empty store. Offline: no call reaches Vercel, GitHub or Upstash.
//
// What this cannot prove, because only the live services can: README, "What only a live test proves".
import { execFileSync, spawnSync } from "node:child_process";
import { createHmac, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createApp } from "../lib/app.mjs";
import { GITHUB_ISSUER, GITHUB_JWKS_URL } from "../lib/oidc.mjs";
import { memoryStore } from "../lib/store.mjs";
import { CHECK_TIMEOUT_SECONDS, WORKFLOW_YAML } from "../lib/workflow.mjs";
import { OPERATIONS, trim } from "../scripts/refresh-openapi.mjs";
import { SPEC, checkRequest, contractVercel } from "./vercel-contract.mjs";

const BASE = "https://vercel.penthera.example.test";
const CLIENT_ID = "oac_testclient";
const CLIENT_SECRET = `cs_${randomBytes(18).toString("hex")}`;
const ACCESS_TOKEN = `at_${randomBytes(18).toString("hex")}`;
const CODE = randomBytes(12).toString("hex");
const CFG = "icfg_JourneyConfig1";
const TEAM = "team_JourneyTeam1";
const NEXT = "https://vercel.com/integrations/penthera/new/done?configurationId=icfg_JourneyConfig1";
const T0 = Date.UTC(2026, 10, 7, 12, 0, 0);

const github = generateKeyPairSync("rsa", { modulusLength: 2048 });
const KID = "journey-kid";
const JWKS = { keys: [{ ...github.publicKey.export({ format: "jwk" }), kid: KID, use: "sig", alg: "RS256" }] };
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString("base64url");
function oidc(deploymentId, t = T0) {
  const s = Math.floor(t / 1000);
  const h = b64({ alg: "RS256", typ: "JWT", kid: KID });
  const p = b64({
    iss: GITHUB_ISSUER, aud: `${BASE}/report/${deploymentId}`, repository: "daan/gaia-web", repository_id: "9001",
    repository_owner: "daan", repository_owner_id: "42", event_name: "repository_dispatch", ref: "refs/heads/main",
    workflow_ref: "daan/gaia-web/.github/workflows/penthera-vercel.yml@refs/heads/main", run_id: "123456", iat: s - 5, nbf: s - 5, exp: s + 295,
  });
  return `${h}.${p}.${sign("RSA-SHA256", Buffer.from(`${h}.${p}`), github.privateKey).toString("base64url")}`;
}

/** Daan's Vercel team: one GitHub project, one GitLab one, a production and a preview deployment. */
const world = () => ({
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

function harness({ autoRuns = true, publicView = false } = {}) {
  const w = world();
  // Vercel's reduced public view of a deployment: `project: { id, name }` and no `projectId`.
  if (publicView) for (const d of Object.values(w.deployments)) Object.assign(d, { project: { id: d.projectId, name: "gaia-web" }, projectId: undefined });
  const vercel = contractVercel({ world: w, token: ACCESS_TOKEN, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, code: CODE, redirectUri: `${BASE}/install`, autoRuns });
  const outside = [];
  const fetch = async (input, init) => {
    const href = String(input);
    if (href === GITHUB_JWKS_URL) return new Response(JSON.stringify(JWKS), { status: 200 });
    if (new URL(href).origin !== "https://api.vercel.com") outside.push(href);
    return vercel.fetch(input, init);
  };
  const env = {
    INTEGRATION_CLIENT_ID: CLIENT_ID, INTEGRATION_CLIENT_SECRET: CLIENT_SECRET, PUBLIC_BASE_URL: BASE,
    PENTHERA_TOKEN_KEYS: `v1:${randomBytes(32).toString("base64")}`, CRON_SECRET: `cron_${randomBytes(12).toString("hex")}`,
  };
  const store = memoryStore();
  const app = createApp({ env, store, fetch, now: () => T0 });
  return { app, store, vercel, outside, env };
}

// A browser's cookie jar, enough for our cookies.
function jar() {
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

const get = (path, browser, headers = {}) => new Request(`${BASE}${path}`, { headers: { cookie: browser.header(), ...headers } });
const post = (path, body, browser, origin) =>
  new Request(`${BASE}${path}`, { method: "POST", body, headers: { "content-type": "application/x-www-form-urlencoded", cookie: browser.header(), ...(origin === undefined ? {} : { origin }) } });

/** Asserts a user-facing page is a normal one, with none of the error pages' words. */
async function page(res, status, ...words) {
  expect(res.status, `status for ${words[0]}`).toBe(status);
  const text = await res.text();
  for (const bad of ["Some checks", "Form check failed", "Install check failed", "has expired", "did not answer", "did not accept"]) expect(text).not.toContain(bad);
  for (const w of words) expect(text).toContain(w);
  return text;
}
const csrfOf = (html) => /name="csrf" value="([^"]+)"/.exec(html)[1];

async function journey({ entry, origin, autoRuns = true, publicView = false }) {
  const h = harness({ autoRuns, publicView });
  const browser = jar();
  let installUrl = `/install?code=${CODE}&configurationId=${CFG}&teamId=${TEAM}&next=${encodeURIComponent(NEXT)}`;

  if (entry === "external") {
    // 1. Our own link: /start sets the CSRF state and sends the browser to Vercel.
    const start = browser.take(await h.app.start(get("/start", browser)));
    expect(start.status).toBe(302);
    const to = new URL(start.headers.get("location"));
    expect(to.origin + to.pathname).toBe("https://vercel.com/integrations/penthera/new");
    installUrl += `&state=${to.searchParams.get("state")}&source=external`;
  } else {
    installUrl += "&source=marketplace";
  }

  // 2. Vercel sends the browser back to the Redirect URL.
  const install = browser.take(await h.app.install(get(installUrl, browser)));
  expect(install.status).toBe(303);
  expect(install.headers.get("location")).toBe("/setup");
  expect(browser.has("__Host-pv_session")).toBe(true);

  // 3. Pick.
  const pick = await page(await h.app.setup(get("/setup", browser)), 200, "Pick your projects", "gaia-web", "notes", "Needs a GitHub-connected project", "What Penthera asks for, and why");
  // 4. Workflow (a browser's form post says Origin: null under our Referrer-Policy).
  const wf = await page(await h.app.setup(post("/setup", `csrf=${csrfOf(pick)}&action=workflow&p=prj_gaiaweb`, browser, "null")), 200, "Add the workflow", "Turn on the check", "github.com/daan/gaia-web/new/main");
  // 5. Turn on the check.
  const on = browser.take(await h.app.setup(post("/setup", `csrf=${csrfOf(wf)}&action=enable&p=prj_gaiaweb`, browser, origin)));
  expect(on.status, await on.clone().text()).toBe(303);
  expect(on.headers.get("location")).toBe(NEXT);

  const [check] = h.vercel.checks.prj_gaiaweb;
  expect(check).toMatchObject({
    name: "Penthera", requires: "deployment-url", blocks: "deployment-promotion", targets: ["production"], timeout: CHECK_TIMEOUT_SECONDS,
    source: { kind: "integration", integrationId: "oac_PentheraIntegration", integrationConfigurationId: CFG },
  });

  // 6. A production deploy: Vercel dispatches vercel.deployment.ready, the workflow scans, then reports.
  const report = (deploymentId, conclusion = "succeeded", ip = "203.0.113.10") =>
    h.app.report(new Request(`${BASE}/report`, {
      method: "POST", body: JSON.stringify({ deploymentId, projectId: "prj_gaiaweb", conclusion }),
      headers: { authorization: `Bearer ${oidc(deploymentId)}`, "content-type": "application/json", "x-real-ip": ip },
    }));
  const rep = await report("dpl_prod1");
  expect(rep.status, await rep.clone().text()).toBe(200);
  const run = h.vercel.runs.dpl_prod1.find((r) => r.checkId === check.id);
  expect(run).toMatchObject({ status: "completed", conclusion: "succeeded", externalUrl: "https://github.com/daan/gaia-web/actions/runs/123456" });
  // A preview deploy is never reported by the workflow, and the server refuses it before any write.
  expect((await report("dpl_preview1")).status).toBe(403);
  expect(h.vercel.runs.dpl_preview1 ?? []).toHaveLength(0);

  // 7. Configure, later, from Vercel's button, with no session.
  await page(await h.app.configure(new Request(`${BASE}/configure?configurationId=${CFG}`)), 200, "Penthera on Vercel", "penthera-vercel.yml");

  // 8. Uninstall: Vercel's signed webhook.
  const raw = JSON.stringify({ id: "evt_1", type: "integration-configuration.removed", createdAt: T0 + 1000, payload: { configuration: { id: CFG, projects: ["prj_gaiaweb"] } } });
  const removed = await h.app.webhook(new Request(`${BASE}/webhook`, { method: "POST", body: raw, headers: { "x-vercel-signature": createHmac("sha1", CLIENT_SECRET).update(raw).digest("hex") } }));
  expect(removed.status).toBe(200);
  expect(h.store.dump()).toEqual([]);
  expect(h.store.dumpLinks()).toEqual([]);
  expect(h.vercel.checks.prj_gaiaweb).toEqual([]);
  expect((await h.app.setup(get("/setup", browser))).status).toBe(401);

  return h;
}

describe("Daan's install journey against Vercel's API spec", () => {
  for (const [entry, origin, autoRuns, publicView] of [
    ["marketplace", "null", true, false],
    ["marketplace", BASE, true, false],
    ["external", "null", true, false],
    ["external", BASE, false, false],
    ["marketplace", "null", true, true],
  ]) {
    it(`from the ${entry}, Turn on with Origin ${origin === "null" ? "null" : "set"}, Vercel ${autoRuns ? "making" : "not making"} the run${publicView ? ", deployments in Vercel's public view" : ""}`, async () => {
      const h = await journey({ entry, origin, autoRuns, publicView });
      expect(h.vercel.violations).toEqual([]);
      expect(h.outside).toEqual([]);
      // Every operation the server is meant to call, it called, and each one was checked.
      const called = new Set(h.vercel.calls.map((c) => checkRequest(c.method, c.url, {}).op?.path && `${c.method} ${checkRequest(c.method, c.url, {}).op.path}`).filter(Boolean));
      const expected = OPERATIONS.map(([m, p]) => `${m.toUpperCase()} ${p}`);
      for (const k of expected) {
        if (k === "POST /v2/deployments/{deploymentId}/check-runs" && autoRuns) continue;
        expect(called, k).toContain(k);
      }
    });
  }
});

describe("the contract check catches what live Vercel refused", () => {
  const url = (p, q = "teamId=team_x") => new URL(`https://api.vercel.com${p}?${q}`);
  const json = (body) => ({ headers: { Authorization: "Bearer t", "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const create = (body) => checkRequest("POST", url("/v2/projects/prj_a/checks"), json(body)).problems;
  const good = { name: "Penthera", requires: "deployment-url", blocks: "deployment-promotion", targets: ["production"], isRerequestable: false, timeout: 1200, source: { kind: "integration", integrationId: "oac_x", integrationConfigurationId: "icfg_x" } };

  it("passes the body the server sends", () => {
    expect(create(good)).toEqual([]);
  });

  it("names the field for a wrong enum, a wrong type, a missing field, an unknown source field and an unknown kind", () => {
    expect(create({ ...good, blocks: "deployment-ready" }).join()).toMatch(/\/blocks: must be equal to one of the allowed values/);
    expect(create({ ...good, requires: "url" }).join()).toMatch(/\/requires/);
    expect(create({ ...good, timeout: "1200" }).join()).toMatch(/\/timeout: must be number/);
    const { requires: _r, ...noRequires } = good;
    expect(create(noRequires).join()).toMatch(/must have required property 'requires'/);
    expect(create({ ...good, source: { ...good.source, integrationSlug: "penthera" } }).join()).toMatch(/\/source\/: must NOT have additional properties \(integrationSlug\)/);
    expect(create({ ...good, source: { kind: "marketplace" } }).join()).toMatch(/source\/kind: "marketplace" names no branch/);
    expect(create({ ...good, targets: ["production", "production"] }).join()).toMatch(/\/targets/);
  });

  it("checks query parameters, path parameters and the token", () => {
    expect(checkRequest("GET", url("/v10/projects", "limit=20&teamId=t"), { headers: { Authorization: "Bearer t" } }).problems).toEqual([]);
    expect(checkRequest("GET", url("/v10/projects", "projectId=x"), { headers: { Authorization: "Bearer t" } }).problems.join()).toMatch(/query projectId is not a parameter/);
    expect(checkRequest("GET", url("/v2/projects/prj_a/checks", "blocks=soon"), { headers: { Authorization: "Bearer t" } }).problems.join()).toMatch(/query blocks=soon does not fit/);
    expect(checkRequest("GET", url("/v9/projects/prj_a"), {}).problems.join()).toMatch(/Bearer/);
    expect(checkRequest("GET", url("/v3/projects/prj_a"), {}).problems.join()).toMatch(/no operation/);
  });

  it("checks the check-run update: status and conclusion enums, and the URL pattern", () => {
    const patch = (body) => checkRequest("PATCH", url("/v2/deployments/dpl_a/check-runs/crun_a"), json(body)).problems;
    expect(patch({ status: "completed", conclusion: "succeeded", conclusionText: "ok", externalUrl: "https://github.com/a/b/actions/runs/1" })).toEqual([]);
    expect(patch({ status: "done" }).join()).toMatch(/\/status/);
    expect(patch({ conclusion: "passed" }).join()).toMatch(/\/conclusion/);
    expect(patch({ externalUrl: "javascript:alert(1)" }).join()).toMatch(/\/externalUrl/);
  });
});

describe("the trimmed spec", () => {
  it("names its source and date, holds every operation the server calls, and every field it reads", () => {
    expect(SPEC["x-source"]).toBe("https://vercel.com/openapi.json");
    expect(SPEC["x-fetched"]).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(SPEC["x-not-in-spec"]).toEqual([]);
    for (const [m, p] of OPERATIONS) expect(SPEC.paths[p]?.[m], `${m} ${p}`).toBeTruthy();
  });

  it("the refresh script refuses a spec that lost an operation, and lists a read field it lost", () => {
    const spec = { paths: structuredClone(Object.fromEntries(Object.entries(SPEC.paths).map(([p, ms]) => [p, Object.fromEntries(Object.entries(ms).map(([m, op]) => [m, { ...op, responses: { 200: { content: { "application/json": { schema: op.response } } } }, requestBody: op.requestBody ? { content: { "application/json": { schema: op.requestBody } } } : undefined }]))]))) };
    expect(trim(spec, "2026-11-07")["x-not-in-spec"]).toEqual([]);
    for (const b of spec.paths["/v13/deployments/{idOrUrl}"].get.responses[200].content["application/json"].schema.oneOf) delete b.properties?.projectId;
    expect(trim(spec, "2026-11-07")["x-not-in-spec"]).toEqual(["GET /v13/deployments/{idOrUrl}: projectId"]);
    delete spec.paths["/v2/projects/{projectIdOrName}/checks"].post;
    expect(() => trim(spec, "2026-11-07")).toThrow(/no POST \/v2\/projects\/\{projectIdOrName\}\/checks/);
  });

  it("is small enough for the repo", () => {
    expect(JSON.stringify(SPEC).length).toBeLessThan(100_000);
  });
});

describe("the workflow passes actionlint", () => {
  const bin = process.env.ACTIONLINT || (spawnSync("sh", ["-c", "command -v actionlint"], { encoding: "utf8" }).stdout.trim() || null);
  const file = new URL("../workflow/penthera-vercel.yml", import.meta.url).pathname;

  it.skipIf(!bin && !process.env.CI)("actionlint (with shellcheck when installed) reports nothing", () => {
    // CI installs a pinned actionlint (.github/workflows/ci.yml) and must run this, never skip it.
    expect(bin, "actionlint is not installed; CI must set ACTIONLINT").toBeTruthy();
    expect(existsSync(file)).toBe(true);
    const out = (() => {
      try {
        return execFileSync(bin, ["-no-color", file], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
      } catch (e) {
        return `${e.stdout ?? ""}${e.stderr ?? ""}` || String(e);
      }
    })();
    expect(out).toBe("");
    expect(WORKFLOW_YAML.length).toBeGreaterThan(0);
  });
});
