// POST /report: the GitHub OIDC check, the binding to the Vercel project and deployment, and
// the cleanup of project links. Offline: a local RSA key stands in for GitHub's JWKS, and a mock
// stands in for Vercel. No call reaches GitHub, Vercel or Upstash.
import { createHmac, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createApp } from "../lib/app.mjs";
import { parseKeys, sealToken } from "../lib/crypto.mjs";
import { setLogSink } from "../lib/log.mjs";
import { GITHUB_ISSUER, GITHUB_JWKS_URL, jwksCache, verifyGithubToken } from "../lib/oidc.mjs";
import { REJECT_REASONS, STAT_FIELDS, STAT_TTL_SECONDS, memoryStore, redisStore } from "../lib/store.mjs";
import { WORKFLOW_YAML } from "../lib/workflow.mjs";

const BASE = "https://penthera-vercel.example.test";
const CLIENT_SECRET = `cs_${randomBytes(18).toString("hex")}`;
const ACCESS_TOKEN = `at_${randomBytes(18).toString("hex")}`;
const CODE = randomBytes(12).toString("hex");
const CFG = "icfg_TestConfig123";
const OTHER_CFG = "icfg_OtherConfig456";
const TEAM = "team_TestTeam123";
const T0 = Date.UTC(2026, 10, 7, 12, 0, 0);

// GitHub's signing key, and one that is not GitHub's.
const github = generateKeyPairSync("rsa", { modulusLength: 2048 });
const stranger = generateKeyPairSync("rsa", { modulusLength: 2048 });
const KID = "gh-test-kid";
const JWKS = { keys: [{ ...github.publicKey.export({ format: "jwk" }), kid: KID, use: "sig", alg: "RS256" }] };

const b64 = (v) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url");

function jwt(claims, { header = {}, key = github.privateKey, signature } = {}) {
  const h = b64({ alg: "RS256", typ: "JWT", kid: KID, ...header });
  const p = b64(claims);
  const s = signature ?? sign("RSA-SHA256", Buffer.from(`${h}.${p}`), key).toString("base64url");
  return `${h}.${p}.${s}`;
}

function claims(t = T0, extra = {}) {
  const s = Math.floor(t / 1000);
  return {
    iss: GITHUB_ISSUER,
    aud: `${BASE}/report/dpl_one`,
    repository: "acme/shop",
    repository_id: "4242",
    repository_owner: "acme",
    repository_owner_id: "77",
    event_name: "repository_dispatch",
    ref: "refs/heads/main",
    workflow_ref: "acme/shop/.github/workflows/penthera-vercel.yml@refs/heads/main",
    run_id: "987654",
    iat: s - 5,
    nbf: s - 5,
    exp: s + 295,
    ...extra,
  };
}

const PROJECTS = {
  prj_one: { id: "prj_one", name: "shop", link: { type: "github", org: "acme", repo: "shop", repoId: 4242, repoOwnerId: 77, productionBranch: "main" } },
  prj_two: { id: "prj_two", name: "blog", link: { type: "github", org: "acme", repo: "blog", repoId: 5151, repoOwnerId: 77, productionBranch: "main" } },
};
// Which project each deployment belongs to, and its target, as Vercel knows it.
const DEPLOYMENTS = { dpl_one: "prj_one", dpl_two: "prj_two", dpl_preview: "prj_one" };
const TARGETS = { dpl_one: "production", dpl_two: "production", dpl_preview: null };

function mock({ jwksStatus = 200 } = {}) {
  const calls = [];
  const checks = {};
  const runs = {};
  let n = 1;
  const fetch = async (input, init = {}) => {
    const url = new URL(String(input));
    const method = init.method ?? "GET";
    calls.push({ method, url, body: init.body });
    const reply = (status, body) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.href === GITHUB_JWKS_URL) return jwksStatus === 200 ? reply(200, JWKS) : reply(jwksStatus, {});
    if (url.pathname === "/v2/oauth/access_token") return reply(200, { access_token: ACCESS_TOKEN, installation_id: CFG, team_id: TEAM, user_id: "user_1" });
    if (init.headers?.Authorization !== `Bearer ${ACCESS_TOKEN}`) return reply(401, { error: { code: "unauthorized" } });
    let m;
    if (url.pathname === "/v10/projects") return reply(200, { projects: Object.values(PROJECTS), pagination: { next: null } });
    if ((m = /^\/v9\/projects\/([^/]+)$/.exec(url.pathname))) return PROJECTS[m[1]] ? reply(200, PROJECTS[m[1]]) : reply(404, { error: { code: "not_found" } });
    if ((m = /^\/v2\/projects\/([^/]+)\/checks$/.exec(url.pathname))) {
      checks[m[1]] ??= [];
      if (method === "GET") return reply(200, { checks: checks[m[1]] });
      const body = JSON.parse(init.body);
      const created = { id: `chk_${n++}`, ...body, projectId: m[1] };
      checks[m[1]].push(created);
      return reply(200, created);
    }
    if ((m = /^\/v2\/projects\/([^/]+)\/checks\/([^/]+)$/.exec(url.pathname)) && method === "DELETE") {
      checks[m[1]] = (checks[m[1]] ?? []).filter((c) => c.id !== m[2]);
      return reply(204);
    }
    if ((m = /^\/v13\/deployments\/([^/]+)$/.exec(url.pathname))) {
      return DEPLOYMENTS[m[1]] ? reply(200, { id: m[1], projectId: DEPLOYMENTS[m[1]], target: TARGETS[m[1]], url: "x.vercel.app" }) : reply(404, { error: { code: "not_found" } });
    }
    if ((m = /^\/v2\/deployments\/([^/]+)\/check-runs$/.exec(url.pathname))) {
      if (!DEPLOYMENTS[m[1]]) return reply(404, { error: { code: "not_found" } });
      runs[m[1]] ??= [];
      if (method === "GET") return reply(200, { runs: runs[m[1]] });
      // A lenient Vercel: it starts the run on the deployment's own project, whatever check it names.
      const run = { id: `run_${n++}`, checkId: JSON.parse(init.body).checkId, deploymentId: m[1], projectId: DEPLOYMENTS[m[1]], status: "queued" };
      runs[m[1]].push(run);
      return reply(200, run);
    }
    if ((m = /^\/v2\/deployments\/([^/]+)\/check-runs\/([^/]+)$/.exec(url.pathname)) && method === "PATCH") {
      const run = (runs[m[1]] ?? []).find((r) => r.id === m[2]);
      if (!run) return reply(404, { error: { code: "not_found" } });
      Object.assign(run, JSON.parse(init.body));
      return reply(200, run);
    }
    return reply(404, { error: { code: "no_route" } });
  };
  return { fetch, calls, checks, runs };
}

const cookieJar = (res) => res.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
const get = (path, headers = {}) => new Request(`${BASE}${path}`, { headers });
const form = (path, body, headers = {}) =>
  new Request(`${BASE}${path}`, { method: "POST", body, headers: { "content-type": "application/x-www-form-urlencoded", origin: BASE, ...headers } });
const report = (token, body = { deploymentId: "dpl_one", projectId: "prj_one", conclusion: "succeeded" }, headers = {}) =>
  new Request(`${BASE}/report`, {
    method: "POST",
    body: typeof body === "string" ? body : JSON.stringify(body),
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), "x-real-ip": "198.51.100.7", ...headers },
  });
const signed = (event) => {
  const raw = JSON.stringify(event);
  return new Request(`${BASE}/webhook`, { method: "POST", body: raw, headers: { "x-vercel-signature": createHmac("sha1", CLIENT_SECRET).update(raw).digest("hex") } });
};

/** Installed as CFG, with the check turned on for prj_one, and Vercel's queued run for dpl_one. */
async function enabled({ clock, store = memoryStore(), vercel = mock(), queued = true } = {}) {
  let t = T0;
  const now = clock ?? (() => t);
  const env = {
    INTEGRATION_CLIENT_ID: "oac_testclient",
    INTEGRATION_CLIENT_SECRET: CLIENT_SECRET,
    PENTHERA_TOKEN_KEYS: `v1:${randomBytes(32).toString("base64")}`,
    PUBLIC_BASE_URL: BASE,
    CRON_SECRET: `cron_${randomBytes(16).toString("hex")}`,
  };
  const app = createApp({ env, store, fetch: vercel.fetch, now });
  const res = await app.install(get(`/install?code=${CODE}&configurationId=${CFG}&teamId=${TEAM}&source=marketplace`));
  const cookie = cookieJar(res);
  const csrf = /name="csrf" value="([^"]+)"/.exec(await (await app.setup(get("/setup", { cookie }))).text())[1];
  const done = await app.setup(form("/setup", `csrf=${csrf}&action=enable&p=prj_one`, { cookie }));
  expect(done.status).toBe(200);
  const check = vercel.checks.prj_one[0];
  if (queued) vercel.runs.dpl_one = [{ id: "run_q1", checkId: check.id, deploymentId: "dpl_one", projectId: "prj_one", status: "queued" }];
  return { app, store, vercel, env, cookie, csrf, check, keys: parseKeys(env.PENTHERA_TOKEN_KEYS), tick: (ms) => (t += ms) };
}

const patches = (vercel) => vercel.calls.filter((c) => c.method === "PATCH");

describe("POST /report relays pass or fail to our check run", () => {
  it("sets the run's conclusion with the installation's token, and stores nothing about the scan", async () => {
    const ctx = await enabled();
    const before = { records: ctx.store.dump(), links: ctx.store.dumpLinks() };
    expect(before.links).toEqual([{ projectId: "prj_one", configurationId: CFG }]);

    const res = await ctx.app.report(report(jwt(claims())));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, conclusion: "succeeded" });
    expect(ctx.vercel.runs.dpl_one[0]).toMatchObject({ status: "completed", conclusion: "succeeded", externalUrl: "https://github.com/acme/shop/actions/runs/987654" });
    const patch = patches(ctx.vercel)[0];
    expect(patch.url.pathname).toBe("/v2/deployments/dpl_one/check-runs/run_q1");
    expect(patch.url.searchParams.get("teamId")).toBe(TEAM);
    expect(Object.keys(JSON.parse(patch.body)).sort()).toEqual(["conclusion", "conclusionText", "externalUrl", "status"]);
    expect({ records: ctx.store.dump(), links: ctx.store.dumpLinks() }).toEqual(before);
  });

  it("relays failed, and starts the run itself when Vercel has not", async () => {
    const ctx = await enabled({ queued: false });
    const res = await ctx.app.report(report(jwt(claims()), { deploymentId: "dpl_one", projectId: "prj_one", conclusion: "failed" }));
    expect(res.status).toBe(200);
    expect(ctx.vercel.runs.dpl_one).toHaveLength(1);
    expect(ctx.vercel.runs.dpl_one[0]).toMatchObject({ checkId: ctx.check.id, status: "completed", conclusion: "failed" });
  });

  it("never overwrites a run that already has a result", async () => {
    const ctx = await enabled();
    expect((await ctx.app.report(report(jwt(claims()), { deploymentId: "dpl_one", projectId: "prj_one", conclusion: "failed" }))).status).toBe(200);
    const again = await ctx.app.report(report(jwt(claims())));
    expect(again.status).toBe(409);
    expect(ctx.vercel.runs.dpl_one[0].conclusion).toBe("failed");
  });

  // Each of these must leave the run queued and make no PATCH.
  const refused = [
    ["no token", () => null, 401],
    ["a token for another audience", (t) => jwt(claims(t, { aud: "https://evil.example" })), 401],
    ["an audience list", (t) => jwt(claims(t, { aud: [`${BASE}/report/dpl_one`] })), 401],
    ["the bare origin as audience", (t) => jwt(claims(t, { aud: BASE })), 401],
    ["a token for another deployment", (t) => jwt(claims(t, { aud: `${BASE}/report/dpl_two` })), 401],
    ["a token with no repository_owner_id", (t) => jwt(claims(t, { repository_owner_id: undefined })), 401],
    ["another repository owner id", (t) => jwt(claims(t, { repository_owner_id: "78" })), 403],
    ["another issuer", (t) => jwt(claims(t, { iss: "https://evil.example" })), 401],
    ["an expired token", (t) => jwt(claims(t - 20 * 60_000)), 401],
    ["a token not valid yet", (t) => jwt(claims(t, { nbf: Math.floor(t / 1000) + 600 })), 401],
    ["a token with no nbf", (t) => jwt(claims(t, { nbf: undefined })), 401],
    ["a token issued in the future", (t) => jwt(claims(t, { iat: Math.floor(t / 1000) + 600 })), 401],
    ["a far-future expiry", (t) => jwt(claims(t, { exp: Math.floor(t / 1000) + 10 * 365 * 86400 })), 401],
    ["string times", (t) => jwt(claims(t, { exp: String(Math.floor(t / 1000) + 60) })), 401],
    ["a bad signature (another key, GitHub's kid)", (t) => jwt(claims(t), { key: stranger.privateKey }), 401],
    ["a changed payload under a real signature", (t) => {
      const [h, , s] = jwt(claims(t)).split(".");
      return `${h}.${b64(claims(t, { repository: "acme/shop", run_id: "1" }))}.${s}`;
    }, 401],
    ["alg: none", (t) => jwt(claims(t), { header: { alg: "none" }, signature: "" }).replace(/\.$/, ".AA"), 401],
    ["alg: none with no signature", (t) => `${b64({ alg: "none", kid: KID })}.${b64(claims(t))}.`, 401],
    ["HS256 with the public key as the secret", (t) => {
      const h = b64({ alg: "HS256", typ: "JWT", kid: KID });
      const p = b64(claims(t));
      const pem = github.publicKey.export({ type: "spki", format: "pem" });
      return `${h}.${p}.${createHmac("sha256", pem).update(`${h}.${p}`).digest("base64url")}`;
    }, 401],
    ["an unknown kid", (t) => jwt(claims(t), { header: { kid: "other" } }), 401],
    ["a crit header", (t) => jwt(claims(t), { header: { crit: ["exp"] } }), 401],
    ["another repo", (t) => jwt(claims(t, { repository: "evil/shop", workflow_ref: "evil/shop/.github/workflows/penthera-vercel.yml@refs/heads/main" })), 403],
    ["the same name with another repo id (recreated repo)", (t) => jwt(claims(t, { repository_id: "9999" })), 403],
    ["the repo of another project", (t) => jwt(claims(t, { repository: "acme/blog", repository_id: "5151", workflow_ref: "acme/blog/.github/workflows/penthera-vercel.yml@refs/heads/main" })), 403],
    ["another workflow file in the repo", (t) => jwt(claims(t, { workflow_ref: "acme/shop/.github/workflows/ci.yml@refs/heads/main" })), 403],
    ["a pull_request run", (t) => jwt(claims(t, { event_name: "pull_request", workflow_ref: "acme/shop/.github/workflows/penthera-vercel.yml@refs/pull/1/merge" })), 403],
  ];
  for (const [name, make, status] of refused) {
    it(`refuses ${name}`, async () => {
      const ctx = await enabled();
      const res = await ctx.app.report(report(make(T0)));
      expect(res.status).toBe(status);
      expect(patches(ctx.vercel)).toHaveLength(0);
      expect(ctx.vercel.runs.dpl_one[0].status).toBe("queued");
    });
  }

  it("refuses a body with any other field, id shape or conclusion", async () => {
    const ctx = await enabled();
    const token = jwt(claims());
    for (const body of [
      { deploymentId: "dpl_one", projectId: "prj_one", conclusion: "succeeded", findings: [] },
      { deploymentId: "dpl_one", projectId: "prj_one" },
      { deploymentId: "dpl_one", projectId: "prj_one", conclusion: "neutral" },
      { deploymentId: "dpl_one/../x", projectId: "prj_one", conclusion: "succeeded" },
      { deploymentId: "dpl_one", projectId: ["prj_one"], conclusion: "succeeded" },
      "not json",
      "[]",
    ]) {
      expect((await ctx.app.report(report(token, body))).status).toBe(400);
    }
    expect((await ctx.app.report(report(token, "x".repeat(2048)))).status).toBe(413);
    expect((await ctx.app.report(new Request(`${BASE}/report`, { headers: { authorization: `Bearer ${token}` } }))).status).toBe(405);
    expect(patches(ctx.vercel)).toHaveLength(0);
  });

  it("refuses a deployment of another project, even when Vercel would start a run on it", async () => {
    const ctx = await enabled();
    // The token and project are right; the deployment belongs to prj_two.
    const res = await ctx.app.report(report(jwt(claims(T0, { aud: `${BASE}/report/dpl_two` })), { deploymentId: "dpl_two", projectId: "prj_one", conclusion: "succeeded" }));
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "deployment_mismatch" });
    // The deployment is read before any write: no run is started on it, nothing is set.
    expect(ctx.vercel.calls.filter((c) => c.method !== "GET" && c.url.pathname.startsWith("/v2/deployments/"))).toHaveLength(0);
    expect(ctx.vercel.runs.dpl_two ?? []).toHaveLength(0);
  });

  it("refuses a preview deployment of the right project, before any write", async () => {
    const ctx = await enabled();
    const res = await ctx.app.report(report(jwt(claims(T0, { aud: `${BASE}/report/dpl_preview` })), { deploymentId: "dpl_preview", projectId: "prj_one", conclusion: "succeeded" }));
    expect(res.status).toBe(403);
    expect(ctx.vercel.calls.filter((c) => c.method !== "GET" && c.url.pathname.startsWith("/v2/deployments/"))).toHaveLength(0);
  });

  it("fails closed when Vercel gives no GitHub repository id for the project", async () => {
    const ctx = await enabled();
    const saved = PROJECTS.prj_one.link.repoId;
    delete PROJECTS.prj_one.link.repoId;
    try {
      const res = await ctx.app.report(report(jwt(claims())));
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "repository_mismatch" });
      expect(patches(ctx.vercel)).toHaveLength(0);
    } finally {
      PROJECTS.prj_one.link.repoId = saved;
    }
  });

  it("refuses a project the check is not on, and a project whose link names another installation", async () => {
    const ctx = await enabled();
    // prj_two has no link.
    const blog = jwt(claims(T0, { aud: `${BASE}/report/dpl_two`, repository: "acme/blog", repository_id: "5151", workflow_ref: "acme/blog/.github/workflows/penthera-vercel.yml@refs/heads/main" }));
    expect((await ctx.app.report(report(blog, { deploymentId: "dpl_two", projectId: "prj_two", conclusion: "succeeded" }))).status).toBe(404);

    // Someone with store access points prj_one at another installation that has a working token.
    // That installation's check is not the one on prj_one, so nothing is set.
    await ctx.store.put({ configurationId: OTHER_CFG, ownerId: TEAM, ...sealToken(ACCESS_TOKEN, OTHER_CFG, ctx.keys), createdAt: new Date(T0).toISOString(), sessionNonce: "o".repeat(32) });
    ctx.store.rawLink("prj_one", { projectId: "prj_one", configurationId: OTHER_CFG });
    expect((await ctx.app.report(report(jwt(claims())))).status).toBe(404);

    // A link stored under prj_one that says it is for prj_two, or has no installation, is not used.
    ctx.store.rawLink("prj_one", { projectId: "prj_two", configurationId: CFG });
    expect((await ctx.app.report(report(jwt(claims())))).status).toBe(404);
    ctx.store.rawLink("prj_one", { projectId: "prj_one", configurationId: "icfg_Gone" });
    expect((await ctx.app.report(report(jwt(claims())))).status).toBe(404);
    expect(patches(ctx.vercel)).toHaveLength(0);
    expect(ctx.vercel.runs.dpl_one[0].status).toBe("queued");
  });

  it("a Vercel 403 or 404 while relaying is a 502, so the workflow fails instead of passing", async () => {
    const ctx = await enabled();
    const app = createApp({ env: ctx.env, store: ctx.store, now: () => T0, fetch: async (u, i) => (new URL(String(u)).pathname.endsWith("/check-runs") ? new Response(JSON.stringify({ error: { code: "forbidden" } }), { status: 403 }) : ctx.vercel.fetch(u, i)) });
    expect((await app.report(report(jwt(claims())))).status).toBe(502);
    expect(ctx.vercel.runs.dpl_one[0].status).toBe("queued");
  });

  it("refuses when the install's token was moved onto another record", async () => {
    const ctx = await enabled();
    const mine = ctx.store.dump()[0];
    // OTHER_CFG's record holds CFG's ciphertext; prj_one's link points at OTHER_CFG.
    await ctx.store.put({ ...mine, configurationId: OTHER_CFG });
    ctx.store.rawLink("prj_one", { projectId: "prj_one", configurationId: OTHER_CFG });
    ctx.vercel.calls.length = 0;
    expect((await ctx.app.report(report(jwt(claims())))).status).toBe(404);
    expect(ctx.vercel.calls.filter((c) => c.url.hostname === "api.vercel.com")).toHaveLength(0);
  });

  it("never logs the token, the ids from the body or Vercel's error text", async () => {
    const lines = [];
    const previous = setLogSink((l) => lines.push(l));
    try {
      const vercel = mock();
      const ctx = await enabled({ vercel });
      const good = jwt(claims());
      const bad = jwt(claims(T0, { aud: "https://evil.example" }));
      await ctx.app.report(report(bad));
      // Vercel fails the PATCH: the error path logs.
      const realFetch = vercel.fetch;
      const failing = createApp({ env: ctx.env, store: ctx.store, now: () => T0, fetch: async (u, i) => (i?.method === "PATCH" ? new Response(JSON.stringify({ error: { code: "boom", message: good } }), { status: 500 }) : realFetch(u, i)) });
      expect((await failing.report(report(good))).status).toBe(502);
      const out = lines.join("\n");
      expect(lines.length).toBeGreaterThan(0);
      for (const secret of [good, bad, good.split(".")[2], ACCESS_TOKEN, "dpl_one"]) expect(out).not.toContain(secret);
    } finally {
      setLogSink(previous);
    }
  });

  it("stops reading a chunked body the moment it passes the cap, before the token is looked at", async () => {
    const ctx = await enabled();
    let pulled = 0;
    const chunk = new Uint8Array(256).fill(0x20);
    const body = new ReadableStream({
      pull(controller) {
        pulled += chunk.byteLength;
        controller.enqueue(chunk);
        if (pulled >= 64 * 1024 * 1024) controller.close();
      },
    });
    const req = new Request(`${BASE}/report`, { method: "POST", body, duplex: "half", headers: { authorization: `Bearer ${jwt(claims())}`, "x-real-ip": "198.51.100.9" } });
    expect(req.headers.get("content-length")).toBeNull();
    const res = await ctx.app.report(req);
    expect(res.status).toBe(413);
    // 1 KiB cap: at most a few 256-byte chunks are pulled (plus the stream's own read-ahead), never 64 MiB.
    expect(pulled).toBeLessThan(4 * 1024);
    expect(ctx.vercel.calls.filter((c) => c.url.href === GITHUB_JWKS_URL)).toHaveLength(0);
  });

  it("rate-limits one runner address", async () => {
    const ctx = await enabled({ queued: false });
    let last;
    for (let i = 0; i < 31; i++) last = await ctx.app.report(report("x.y.z"));
    expect(last.status).toBe(429);
    expect((await ctx.app.report(report("x.y.z", undefined, { "x-real-ip": "198.51.100.8" }))).status).toBe(401);
  });
});

describe("GitHub's key set", () => {
  it("is fetched once, kept 10 minutes, refetched after that, and after the clock moves back", async () => {
    const ctx = await enabled();
    const jwksCalls = () => ctx.vercel.calls.filter((c) => c.url.href === GITHUB_JWKS_URL).length;
    const t = (ms) => ctx.tick(ms);
    await ctx.app.report(report(jwt(claims())));
    await ctx.app.report(report(jwt(claims())));
    expect(jwksCalls()).toBe(1);
    t(11 * 60_000);
    await ctx.app.report(report(jwt(claims(T0 + 11 * 60_000))));
    expect(jwksCalls()).toBe(2);
    t(-60 * 60_000);
    await ctx.app.report(report(jwt(claims(T0 - 49 * 60_000))));
    expect(jwksCalls()).toBe(3);
  });

  it("an unknown kid refetches at most once a minute", async () => {
    let t = T0;
    const v = mock();
    const jwks = jwksCache({ fetch: v.fetch, now: () => t });
    expect(await jwks.get(KID)).not.toBeNull();
    expect(await jwks.get("nope")).toBeNull();
    expect(await jwks.get("nope")).toBeNull();
    expect(v.calls).toHaveLength(1);
    t += 61_000;
    expect(await jwks.get("nope")).toBeNull();
    expect(v.calls).toHaveLength(2);
  });

  it("while GitHub's keys fail, refetches at most once a minute, with one fetch for concurrent callers", async () => {
    let t = T0;
    let calls = 0;
    const fetch = async () => {
      calls++;
      await new Promise((r) => setTimeout(r, 5));
      return new Response("{}", { status: 500 });
    };
    const jwks = jwksCache({ fetch, now: () => t });
    const results = await Promise.allSettled(Array.from({ length: 5 }, () => jwks.get(KID)));
    expect(results.every((r) => r.status === "rejected" && /jwks_unavailable/.test(r.reason.message))).toBe(true);
    expect(calls).toBe(1);
    for (let i = 0; i < 20; i++) {
      t += 2_000;
      await expect(jwks.get(KID)).rejects.toThrow(/jwks_unavailable/);
    }
    expect(calls).toBe(1);
    t += 61_000;
    await expect(jwks.get(KID)).rejects.toThrow(/jwks_unavailable/);
    expect(calls).toBe(2);
  });

  it("concurrent callers on a cold cache share one slow fetch, and all get the key", async () => {
    let calls = 0;
    const fetch = async () => {
      calls++;
      await new Promise((r) => setTimeout(r, 10));
      return new Response(JSON.stringify(JWKS), { status: 200 });
    };
    const jwks = jwksCache({ fetch, now: () => T0 });
    const keys = await Promise.all(Array.from({ length: 5 }, () => jwks.get(KID)));
    expect(keys.every((k) => k !== null)).toBe(true);
    expect(calls).toBe(1);
  });

  it("asks for no redirects and reads at most 64 KiB of the key set", async () => {
    const seen = [];
    let pulled = 0;
    const fetch = async (url, init) => {
      seen.push(init);
      const body = new ReadableStream({
        pull(c) {
          pulled += 1024;
          c.enqueue(new Uint8Array(1024).fill(0x20));
          if (pulled > 10 * 1024 * 1024) c.close();
        },
      });
      return new Response(body, { status: 200 });
    };
    await expect(jwksCache({ fetch, now: () => T0 }).get(KID)).rejects.toThrow(/jwks_unavailable/);
    expect(seen[0].redirect).toBe("error");
    expect(pulled).toBeLessThan(80 * 1024);
  });

  it("answers 503 and changes nothing when GitHub's keys cannot be read", async () => {
    const vercel = mock({ jwksStatus: 500 });
    const ctx = await enabled({ vercel });
    expect((await ctx.app.report(report(jwt(claims())))).status).toBe(503);
    expect(patches(vercel)).toHaveLength(0);
  });

  it("verifyGithubToken accepts a good token and returns its claims", async () => {
    const v = mock();
    const out = await verifyGithubToken(jwt(claims()), { audience: `${BASE}/report/dpl_one`, jwks: jwksCache({ fetch: v.fetch, now: () => T0 }), now: () => T0 });
    expect(out.repository).toBe("acme/shop");
    await expect(verifyGithubToken(jwt(claims()), { audience: "", jwks: jwksCache({ fetch: v.fetch, now: () => T0 }), now: () => T0 })).rejects.toThrow(/bad_audience/);
  });

  it("refuses every algorithm but RS256 before it looks up a key", async () => {
    const v = mock();
    const opts = { audience: `${BASE}/report/dpl_one`, jwks: jwksCache({ fetch: v.fetch, now: () => T0 }), now: () => T0 };
    for (const alg of ["none", "HS256", "RS512", "PS256", "ES256", undefined]) {
      await expect(verifyGithubToken(jwt(claims(), { header: { alg } }), opts)).rejects.toThrow(/bad_alg/);
    }
    expect(v.calls).toHaveLength(0);
    const s = Math.floor(T0 / 1000);
    // A lifetime over one hour, even when exp itself is near.
    await expect(verifyGithubToken(jwt(claims(T0, { iat: s - 7200, nbf: s - 7200, exp: s + 60 })), opts)).rejects.toThrow(/too_long/);
  });
});

let enableWithShared;
describe("turning the check on", () => {
  /** enabled(), with Vercel's configuration lookup and the check create answered by `routes`. */
  async function enableWith(routes, env = {}, before = null) {
    const vercel = mock();
    const lines = [];
    const previous = setLogSink((l) => lines.push(l));
    const fetch = async (u, i) => {
      const url = new URL(String(u));
      const key = `${i?.method ?? "GET"} ${url.pathname}`;
      if (routes[key]) {
        const r = routes[key](i);
        if (r) return new Response(JSON.stringify(r.body), { status: r.status });
      }
      return vercel.fetch(u, i);
    };
    try {
      const store = memoryStore();
      const e = { INTEGRATION_CLIENT_ID: "oac_testclient", INTEGRATION_CLIENT_SECRET: CLIENT_SECRET, PENTHERA_TOKEN_KEYS: `v1:${randomBytes(32).toString("base64")}`, PUBLIC_BASE_URL: BASE, ...env };
      const app = createApp({ env: e, store, fetch, now: () => T0 });
      const cookie = cookieJar(await app.install(get(`/install?code=${CODE}&configurationId=${CFG}&teamId=${TEAM}&source=marketplace`)));
      const csrf = /name="csrf" value="([^"]+)"/.exec(await (await app.setup(get("/setup", { cookie }))).text())[1];
      if (before) await before({ vercel, store, keys: parseKeys(e.PENTHERA_TOKEN_KEYS) });
      const res = await app.setup(form("/setup", `csrf=${csrf}&action=enable&p=prj_one`, { cookie }));
      return { res, vercel, store, lines, posts: vercel.calls.filter((c) => c.method === "POST" && c.url.pathname === "/v2/projects/prj_one/checks").map((c) => JSON.parse(c.body)) };
    } finally {
      setLogSink(previous);
    }
  }
  enableWithShared = enableWith;
  const CONFIG = `GET /v1/integrations/configuration/${CFG}`;

  it("uses the integration id from Vercel's record of the installation", async () => {
    const { res, vercel } = await enableWith({ [CONFIG]: () => ({ status: 200, body: { id: CFG, integrationId: "oac_fromvercel" } }) });
    expect(res.status).toBe(200);
    expect(vercel.checks.prj_one[0].source).toEqual({ kind: "integration", integrationId: "oac_fromvercel", integrationConfigurationId: CFG });
    expect(vercel.checks.prj_one[0]).toMatchObject({ name: "Penthera", requires: "deployment-url", blocks: "deployment-promotion", targets: ["production"], isRerequestable: false, timeout: 1200 });
  });

  it("INTEGRATION_ID overrides the lookup, which is then not made", async () => {
    const { vercel } = await enableWith({ [CONFIG]: () => ({ status: 200, body: { id: CFG, integrationId: "oac_fromvercel" } }) }, { INTEGRATION_ID: "oac_override" });
    expect(vercel.checks.prj_one[0].source.integrationId).toBe("oac_override");
    expect(vercel.calls.some((c) => c.url.pathname.startsWith("/v1/integrations/"))).toBe(false);
  });

  it("never sends the client id: a failed or foreign lookup sends the configuration alone, and says why in the log", async () => {
    const failed = await enableWith({ [CONFIG]: () => ({ status: 403, body: { error: { code: "forbidden", message: "Missing scope integration-configuration:read" } } }) });
    expect(failed.vercel.checks.prj_one[0].source).toEqual({ kind: "integration", integrationConfigurationId: CFG });
    expect(failed.lines.join("\n")).toMatch(/"event":"integration_lookup_failed","status":403,"code":"forbidden","message":"Missing scope integration-configuration:read"/);
    const foreign = await enableWith({ [CONFIG]: () => ({ status: 200, body: { id: "icfg_Someone", integrationId: "oac_theirs" } }) });
    expect(foreign.vercel.checks.prj_one[0].source).toEqual({ kind: "integration", integrationConfigurationId: CFG });
    expect(JSON.stringify(foreign.posts)).not.toContain("oac_testclient");
  });

  it("logs Vercel's code and message when the create fails, with no token in it", async () => {
    const { res, lines } = await enableWith({
      "POST /v2/projects/prj_one/checks": () => ({ status: 400, body: { error: { code: "bad_request", message: `Invalid request: source.integrationId is not ours (token ${ACCESS_TOKEN})` } } }),
    });
    expect(res.status).toBe(502);
    const line = lines.find((l) => l.includes('"event":"check_failed"'));
    expect(JSON.parse(line)).toMatchObject({ status: 400, code: "bad_request", configurationId: CFG });
    expect(JSON.parse(line).message).toMatch(/^Invalid request: source\.integrationId is not ours/);
    expect(lines.join("\n")).not.toContain(ACCESS_TOKEN);
  });

  it("when Vercel refuses the timeout, tries once more without it, and only then", async () => {
    let n = 0;
    const timeoutRefused = await enableWith({
      "POST /v2/projects/prj_one/checks": () => (n++ === 0 ? { status: 400, body: { error: { code: "bad_request", message: "timeout must be less than or equal to 600" } } } : null),
    });
    expect(timeoutRefused.res.status).toBe(200);
    expect(timeoutRefused.vercel.checks.prj_one).toHaveLength(1);
    expect(timeoutRefused.vercel.checks.prj_one[0].timeout).toBeUndefined();
    expect(timeoutRefused.lines.some((l) => l.includes("check_timeout_refused"))).toBe(true);

    let m = 0;
    const other = await enableWith({ "POST /v2/projects/prj_one/checks": () => (m++, { status: 400, body: { error: { code: "bad_request", message: "name is required" } } }) });
    expect(other.res.status).toBe(502);
    expect(m).toBe(1);
  });
});

describe("when Turn on meets an old check or a refusal", () => {
  // Same helper as "turning the check on", with Vercel's configuration lookup naming our integration.
  const OURS = "oac_fromvercel";
  const config = { [`GET /v1/integrations/configuration/${CFG}`]: () => ({ status: 200, body: { id: CFG, integrationId: OURS } }) };
  const leftover = (extra = {}) => ({ id: "chk_old", name: "Penthera", projectId: "prj_one", source: { kind: "integration", integrationId: OURS, integrationConfigurationId: "icfg_OldInstall9" }, ...extra });
  const enable = (routes, before) => turnOn({ ...config, ...routes }, before);
  let turnOn;

  it("removes our own integration's check left by an earlier, uninstalled installation, then adds ours", async () => {
    const { res, vercel } = await enable({}, ({ vercel: v }) => (v.checks.prj_one = [leftover()]));
    expect(res.status).toBe(200);
    expect(vercel.checks.prj_one.map((k) => k.id)).not.toContain("chk_old");
    expect(vercel.checks.prj_one).toHaveLength(1);
    expect(vercel.checks.prj_one[0].source).toMatchObject({ kind: "integration", integrationConfigurationId: CFG });
  });

  it("leaves a live installation's check alone, and adds no second one", async () => {
    const { res, vercel } = await enable({}, async ({ vercel: v, store, keys }) => {
      v.checks.prj_one = [leftover()];
      await store.put({ configurationId: "icfg_OldInstall9", ownerId: TEAM, ...sealToken(ACCESS_TOKEN, "icfg_OldInstall9", keys), createdAt: new Date(T0).toISOString(), sessionNonce: "l".repeat(32) });
    });
    expect(res.status).toBe(409);
    expect(vercel.checks.prj_one.map((k) => k.id)).toEqual(["chk_old"]);
  });

  const oldRecord = async (store, keys, token = ACCESS_TOKEN) =>
    store.put({ configurationId: "icfg_OldInstall9", ownerId: TEAM, ...sealToken(token, "icfg_OldInstall9", keys), createdAt: new Date(T0).toISOString(), sessionNonce: "l".repeat(32) });

  it("fails closed when the old installation's record is there but its token does not decrypt", async () => {
    const { res, vercel } = await enable({}, async ({ vercel: v, store }) => {
      v.checks.prj_one = [leftover()];
      // Sealed under a key this server no longer has (a rotation gone wrong, a config error).
      await oldRecord(store, parseKeys(`v1:${randomBytes(32).toString("base64")}`));
    });
    expect(res.status).toBe(409);
    expect(vercel.calls.filter((c) => c.method === "DELETE")).toHaveLength(0);
    expect(vercel.checks.prj_one.map((k) => k.id)).toEqual(["chk_old"]);
  });

  it("a 403 for the old installation counts as taken, as in the sweep: nothing is deleted", async () => {
    const { res, vercel } = await enable(
      { "GET /v2/projects/prj_one/checks": (i) => (i?.headers?.Authorization === "Bearer at_old_install" ? { status: 403, body: { error: { code: "integration_configuration_disabled" } } } : null) },
      async ({ vercel: v, store, keys }) => {
        v.checks.prj_one = [leftover()];
        await oldRecord(store, keys, "at_old_install");
      },
    );
    expect(res.status).toBe(409);
    expect(vercel.calls.filter((c) => c.method === "DELETE")).toHaveLength(0);
    expect(vercel.checks.prj_one.map((k) => k.id)).toEqual(["chk_old"]);
  });

  it("a 401 or 404 for the old installation's token means it is gone: our leftover is removed", async () => {
    for (const status of [401, 404]) {
      const { res, vercel } = await enable(
        { "GET /v2/projects/prj_one/checks": (i) => (i?.headers?.Authorization === "Bearer at_old_install" ? { status, body: { error: { code: "gone" } } } : null) },
        async ({ vercel: v, store, keys }) => {
          v.checks.prj_one = [leftover()];
          await oldRecord(store, keys, "at_old_install");
        },
      );
      expect(res.status, String(status)).toBe(200);
      expect(vercel.checks.prj_one.map((k) => k.id)).not.toContain("chk_old");
    }
  });

  it("never deletes a check that is not ours by source, and says it is there", async () => {
    const theirs = [
      { id: "chk_gh", name: "Penthera", projectId: "prj_one", source: { kind: "git-provider", provider: "github", externalCheckName: "Penthera on Vercel | scan (shop - production)" } },
      { id: "chk_other", name: "Penthera scan", projectId: "prj_one", source: { kind: "integration", integrationId: "oac_someoneelse", integrationConfigurationId: "icfg_Theirs1" } },
    ];
    const { res, vercel } = await enable({}, ({ vercel: v }) => (v.checks.prj_one = [...theirs]));
    expect(vercel.calls.filter((c) => c.method === "DELETE")).toHaveLength(0);
    expect(vercel.checks.prj_one.map((k) => k.id)).toEqual(expect.arrayContaining(["chk_gh", "chk_other"]));
    expect(vercel.checks.prj_one).toHaveLength(3);
    const text = await res.text();
    expect(text).toContain('data-reason="lookalike_check"');
    expect(text).toContain("did not add");
  });

  it("without a known integration id, deletes nothing", async () => {
    const { vercel } = await turnOn({ [`GET /v1/integrations/configuration/${CFG}`]: () => ({ status: 403, body: { error: { code: "forbidden" } } }) }, ({ vercel: v }) => (v.checks.prj_one = [leftover()]));
    expect(vercel.calls.filter((c) => c.method === "DELETE")).toHaveLength(0);
    expect(vercel.checks.prj_one.map((k) => k.id)).toContain("chk_old");
  });

  it("when Vercel refuses to remove the old check, the page says how to remove it, and offers no retry", async () => {
    const { res } = await enable({ "DELETE /v2/projects/prj_one/checks/chk_old": () => ({ status: 403, body: { error: { code: "forbidden", message: "not your check" } } }) }, ({ vercel: v }) => (v.checks.prj_one = [leftover()]));
    const text = await res.text();
    expect(text).toContain('data-reason="leftover"');
    expect(text).toContain("Remove the old Penthera check");
    expect(text).toContain("deployment-checks");
    expect(text).not.toContain('href="/setup">Try again');
  });

  const answers = [
    // [Vercel's answer to the create, reason, try again offered, words, link]
    [403, { code: "forbidden", message: "Missing scope deployment-check" }, "forbidden", false, "accept any pending permission update", "integrations"],
    [403, { code: "integration_configuration_disabled" }, "disabled", false, "disabled this installation", "integrations"],
    [404, { code: "not_found" }, "not_found", false, "cannot find this project", "integrations"],
    [401, { code: "unauthorized" }, "revoked", false, "Install Penthera again", 'href="/start"'],
    [409, { code: "conflict", message: "A check named Penthera already exists" }, "conflict", false, "already has a check like this", "deployment-checks"],
    [400, { code: "bad_request", message: "name already exists on this project" }, "conflict", false, "already has a check like this", "deployment-checks"],
    [400, { code: "bad_request", message: "source.integrationId <script>alert(1)</script> is invalid" }, "rejected", false, "on our side, not yours", "github.com/danoszz/penthera/issues"],
    [429, { code: "rate_limited" }, "rate_limited", true, "Wait a minute", null],
    [503, { code: "unavailable" }, "vercel_down", true, "problem on its side", null],
  ];
  for (const [status, error, reason, retry, words, link] of answers) {
    it(`Vercel ${status} ${error.code}: a page that says ${reason}${retry ? ", with Try again" : ", without a bare retry"}`, async () => {
      const { res } = await enable({ "POST /v2/projects/prj_one/checks": () => ({ status, body: { error } }) });
      const text = await res.text();
      expect(text).toContain(`data-reason="${reason}"`);
      expect(text).toContain(words);
      if (link) expect(text).toContain(link);
      expect(text.includes('href="/setup">Try again')).toBe(retry);
      // The code in small print, so the user can send it to us; Vercel's text escaped.
      expect(text).toContain(`Code: <code>Vercel ${status} ${error.code}`);
      expect(text).not.toContain("<script>alert(1)</script>");
      expect(text).not.toContain("Vercel did not accept the check for");
    });
  }

  it("our own store failing is its own page, with Try again", async () => {
    const { res } = await enable({}, ({ store }) => {
      store.putLink = async () => {
        throw new Error("store down");
      };
    });
    const text = await res.text();
    expect(text).toContain('data-reason="store"');
    expect(text).toContain('href="/setup">Try again');
    expect(text).toContain("Code: <code>penthera store_unavailable</code>");
  });

  it("no page says only Vercel did not accept the check", async () => {
    const { res } = await enable({ "POST /v2/projects/prj_one/checks": () => ({ status: 400, body: { error: { code: "bad_request" } } }) });
    expect(await res.text()).not.toContain("Vercel did not accept the check for");
  });

  // Reuses the helper from "turning the check on".
  turnOn = (routes, before) => enableWithShared(routes, {}, before);
});

describe("project links", () => {
  /** A second installation, OTHER_CFG, in the same team, with a working token. */
  async function second(ctx, { withCheck }) {
    await ctx.store.put({ configurationId: OTHER_CFG, ownerId: TEAM, ...sealToken(ACCESS_TOKEN, OTHER_CFG, ctx.keys), createdAt: new Date(T0).toISOString(), sessionNonce: "o".repeat(32) });
    await ctx.store.putLink({ projectId: "prj_one", configurationId: OTHER_CFG });
    ctx.vercel.checks.prj_one = withCheck ? [{ id: "chk_other", name: "Penthera", projectId: "prj_one", source: { kind: "integration", integrationConfigurationId: OTHER_CFG } }] : [];
  }

  it("a second installation never takes a link from one whose own check is live", async () => {
    const ctx = await enabled();
    await second(ctx, { withCheck: true });
    const res = await ctx.app.setup(form("/setup", `csrf=${ctx.csrf}&action=enable&p=prj_one`, { cookie: ctx.cookie }));
    expect(res.status).toBe(409);
    expect(await res.text()).toContain("Another Penthera installation already runs the check for shop");
    expect(ctx.store.dumpLinks()).toEqual([{ projectId: "prj_one", configurationId: OTHER_CFG }]);
    // No second check was added next to theirs.
    expect(ctx.vercel.checks.prj_one.map((k) => k.id)).toEqual(["chk_other"]);
  });

  it("takes the link over when the other installation's check is gone, or its record is", async () => {
    const ctx = await enabled();
    await second(ctx, { withCheck: false });
    expect((await ctx.app.setup(form("/setup", `csrf=${ctx.csrf}&action=enable&p=prj_one`, { cookie: ctx.cookie }))).status).toBe(200);
    expect(ctx.store.dumpLinks()).toEqual([{ projectId: "prj_one", configurationId: CFG }]);
    expect(ctx.vercel.checks.prj_one.some((k) => k.source.integrationConfigurationId === CFG)).toBe(true);

    await second(ctx, { withCheck: true });
    await ctx.store.delete(OTHER_CFG);
    expect((await ctx.app.setup(form("/setup", `csrf=${ctx.csrf}&action=enable&p=prj_one`, { cookie: ctx.cookie }))).status).toBe(200);
    expect(ctx.store.dumpLinks()).toEqual([{ projectId: "prj_one", configurationId: CFG }]);
  });

  it("keeps the other installation's link when Vercel cannot say (a 5xx), and re-enabling its own link is fine", async () => {
    const ctx = await enabled();
    await second(ctx, { withCheck: true });
    const real = ctx.vercel.fetch;
    const app = createApp({ env: ctx.env, store: ctx.store, now: () => T0, fetch: async (u, i) => (new URL(String(u)).pathname === "/v2/projects/prj_one/checks" && (i?.method ?? "GET") === "GET" ? new Response("{}", { status: 503 }) : real(u, i)) });
    const res = await app.setup(form("/setup", `csrf=${ctx.csrf}&action=enable&p=prj_one`, { cookie: ctx.cookie }));
    expect(res.status).toBe(409);
    expect(ctx.store.dumpLinks()).toEqual([{ projectId: "prj_one", configurationId: OTHER_CFG }]);
    // Its own link: enable again is a no-op success.
    const own = await enabled();
    expect((await own.app.setup(form("/setup", `csrf=${own.csrf}&action=enable&p=prj_one`, { cookie: own.cookie }))).status).toBe(200);
    expect(own.vercel.checks.prj_one).toHaveLength(1);
  });

  it("removing the check deletes the project's link", async () => {
    const ctx = await enabled();
    expect((await ctx.app.setup(form("/setup", `csrf=${ctx.csrf}&remove=prj_one`, { cookie: ctx.cookie }))).status).toBe(303);
    expect(ctx.vercel.checks.prj_one).toHaveLength(0);
    expect(ctx.store.dumpLinks()).toEqual([]);
    expect((await ctx.app.report(report(jwt(claims())))).status).toBe(404);
  });

  it("uninstall deletes this installation's links and keeps other installations' links", async () => {
    const ctx = await enabled();
    await ctx.store.putLink({ projectId: "prj_two", configurationId: OTHER_CFG });
    ctx.store.rawLink("prj_moved", { projectId: "prj_elsewhere", configurationId: CFG });
    const res = await ctx.app.webhook(signed({ type: "integration-configuration.removed", payload: { configuration: { id: CFG, projects: ["prj_one"] } } }));
    expect(res.status).toBe(200);
    expect(ctx.store.dump()).toEqual([]);
    expect(ctx.store.dumpLinks()).toEqual([{ projectId: "prj_two", configurationId: OTHER_CFG }]);
    expect((await ctx.app.report(report(jwt(claims())))).status).toBe(404);
  });

  it("a link cleanup that fails answers 500, and Vercel's retry finishes it", async () => {
    const ctx = await enabled();
    const links = ctx.store.links;
    let failOnce = true;
    ctx.store.links = async () => {
      if (failOnce) {
        failOnce = false;
        throw new Error("store down");
      }
      return links();
    };
    const event = { type: "integration-configuration.removed", payload: { configuration: { id: CFG, projects: [] } } };
    expect((await ctx.app.webhook(signed(event))).status).toBe(500);
    expect(ctx.store.dump()).toEqual([]);
    expect(ctx.store.dumpLinks()).toHaveLength(1);
    expect((await ctx.app.webhook(signed(event))).status).toBe(200);
    expect(ctx.store.dumpLinks()).toEqual([]);
  });

  it("the sweep deletes links whose installation is gone or that do not match their key", async () => {
    const ctx = await enabled();
    await ctx.store.putLink({ projectId: "prj_two", configurationId: "icfg_Gone" });
    ctx.store.rawLink("prj_three", { projectId: "prj_four", configurationId: CFG });
    ctx.store.rawLink("prj_five", "junk");
    ctx.store.rawLink("prj_six", { projectId: "prj_six", configurationId: CFG, repo: "acme/shop" });
    const res = await ctx.app.sweep(get("/sweep", { authorization: `Bearer ${ctx.env.CRON_SECRET}` }));
    expect(await res.json()).toMatchObject({ unlinked: 4 });
    expect(ctx.store.dumpLinks()).toEqual([{ projectId: "prj_one", configurationId: CFG }]);
  });

  it("the store refuses a link with any other field or id shape", async () => {
    const store = memoryStore();
    await store.putLink({ projectId: "prj_one", configurationId: CFG });
    await expect(store.putLink({ projectId: "prj_one", configurationId: CFG, repo: "acme/shop" })).rejects.toThrow(/exactly/);
    await expect(store.putLink({ projectId: "prj_one" })).rejects.toThrow(/exactly/);
    await expect(store.putLink({ projectId: "dpl_one", configurationId: CFG })).rejects.toThrow(/projectId/);
    await expect(store.putLink({ projectId: "prj_one", configurationId: "team_x" })).rejects.toThrow(/configurationId/);
  });

  it("the Redis store keeps links under their own prefix", async () => {
    const sent = [];
    const fetch = async (url, init) => {
      const cmd = JSON.parse(init.body);
      sent.push(cmd);
      const link = JSON.stringify({ projectId: "prj_one", configurationId: CFG });
      const result = cmd[0] === "SCAN" ? ["0", ["pv:prj:prj_one", "pv:prj:prj_gone"]] : cmd[0] === "GET" ? link : cmd[0] === "MGET" ? [link, null] : "OK";
      return new Response(JSON.stringify({ result }), { status: 200 });
    };
    const store = redisStore({ url: "https://kv.example.test", token: "kvtoken", fetch });
    await store.putLink({ projectId: "prj_one", configurationId: CFG });
    expect(await store.getLink("prj_one")).toEqual({ projectId: "prj_one", configurationId: CFG });
    expect(await store.links()).toEqual([{ key: "prj_one", link: { projectId: "prj_one", configurationId: CFG } }]);
    await store.deleteLink("prj_one");
    expect(sent[0]).toEqual(["SET", "pv:prj:prj_one", JSON.stringify({ projectId: "prj_one", configurationId: CFG })]);
    expect(sent.at(-1)).toEqual(["DEL", "pv:prj:prj_one"]);
    expect(sent.find((c) => c[0] === "SCAN")[2]).toBe("MATCH");
    expect(sent.find((c) => c[0] === "SCAN")[3]).toBe("pv:prj:*");
    expect(sent.find((c) => c[0] === "MGET")).toEqual(["MGET", "pv:prj:prj_one", "pv:prj:prj_gone"]);
  });
});

describe("anonymous daily totals", () => {
  const DAY = new Date(T0).toISOString().slice(0, 10);

  it("writes relays that reached Vercel at once, and refusals at most once a minute", async () => {
    const ctx = await enabled();
    expect((await ctx.app.report(report(jwt(claims()), { deploymentId: "dpl_one", projectId: "prj_one", conclusion: "failed" }))).status).toBe(200);
    expect(await ctx.store.stats(DAY)).toEqual({ received: 1, failed: 1 });
    await ctx.app.report(report(jwt(claims()))); // 409, the first refusal: flushed at once
    await ctx.app.report(report(jwt(claims(T0, { aud: "https://evil.example" }))));
    await ctx.app.report(report(null));
    expect(await ctx.store.stats(DAY)).toEqual({ received: 2, failed: 1, rejected_already_completed: 1 });
    ctx.tick(61_000);
    await ctx.app.report(report(null));
    expect(await ctx.store.stats(DAY)).toEqual({ received: 5, failed: 1, rejected_already_completed: 1, rejected_bad_token: 1, rejected_unauthorized: 2 });
    // Nothing but the date and the counter names: no project, deployment, team, configuration or address.
    const dump = JSON.stringify({ days: ctx.store.statDays(), stats: await ctx.store.stats(DAY) });
    for (const id of ["prj_", "dpl_", "team_", "icfg_", "198.51.100", "acme"]) expect(dump).not.toContain(id);
    expect(ctx.store.statDays()).toEqual([DAY]);
  });

  it("every reason /report can answer has a counter, and nothing else does", () => {
    expect([...STAT_FIELDS].sort()).toEqual(["failed", "received", "succeeded", ...REJECT_REASONS.map((r) => `rejected_${r}`)].sort());
  });

  it("a flood of junk, or of valid tokens from a stranger's repo, costs a few store commands a minute", async () => {
    const kv = [];
    const vercel = mock();
    const fetch = async (u, i) => {
      if (new URL(String(u)).origin === "https://kv.example.test") {
        const cmd = JSON.parse(i.body);
        kv.push(cmd);
        const value = cmd[0] === "GET" ? null : cmd[0] === "SCAN" ? ["0", []] : 1;
        return new Response(JSON.stringify({ result: value }), { status: 200 });
      }
      return vercel.fetch(u, i);
    };
    const store = redisStore({ url: "https://kv.example.test", token: "kvtoken", fetch });
    const env = {
      INTEGRATION_CLIENT_ID: "oac_testclient", INTEGRATION_CLIENT_SECRET: CLIENT_SECRET, PUBLIC_BASE_URL: BASE,
      PENTHERA_TOKEN_KEYS: `v1:${randomBytes(32).toString("base64")}`,
    };
    let t = T0;
    const app = createApp({ env, store, fetch, now: () => t });
    // A stranger's own repo mints valid tokens for our audience; the project is not linked.
    const stranger = jwt(claims(T0, { repository: "evil/x", repository_id: "1", repository_owner_id: "2", workflow_ref: "evil/x/.github/workflows/penthera-vercel.yml@refs/heads/main" }));
    for (let i = 0; i < 20; i++) {
      const ip = `203.0.113.${i}`;
      await app.report(report("a.b.c", {}, { "x-real-ip": ip }));
      await app.report(report(stranger, undefined, { "x-real-ip": ip }));
    }
    const writes = () => kv.filter((c) => c[0] === "HINCRBY" || c[0] === "EXPIRE");
    // The first refusal flushes at once (2 counters + 1 EXPIRE); the other 39 wait in memory.
    expect(writes()).toHaveLength(3);
    t += 61_000;
    await app.report(report("a.b.c", {}));
    // One flush: three counter names, and no second EXPIRE for the same day.
    expect(writes()).toHaveLength(6);
    expect(writes().filter((c) => c[0] === "EXPIRE")).toHaveLength(1);
    expect(writes().slice(3).map((c) => [c[2], c[3]]).sort()).toEqual([["received", "40"], ["rejected_bad_body", "20"], ["rejected_not_enabled", "20"]].sort());
  });

  it("does not count rate-limited requests, and a store error while counting changes no answer", async () => {
    const ctx = await enabled();
    for (let i = 0; i < 35; i++) await ctx.app.report(report("x.y.z"));
    ctx.tick(61_000);
    await ctx.app.report(report("x.y.z"));
    expect((await ctx.store.stats(DAY)).received).toBe(31);
    const other = await enabled();
    other.store.countStats = async () => {
      throw new Error("store down");
    };
    expect((await other.app.report(report(jwt(claims())))).status).toBe(200);
    expect(other.vercel.runs.dpl_one[0].conclusion).toBe("succeeded");
  });

  it("a clock out of range counts nothing and still answers", async () => {
    const ctx = await enabled();
    ctx.tick(8.64e15);
    expect((await ctx.app.report(report(null))).status).toBe(401);
    expect(ctx.store.statDays()).toEqual([]);
  });

  it("the store refuses any other counter name, day or count", async () => {
    const store = memoryStore();
    await store.countStats(DAY, { received: 2 });
    await expect(store.countStats(DAY, { rejected_prj_one: 1 })).rejects.toThrow(/documented names/);
    await expect(store.countStats(DAY, { project: 1 })).rejects.toThrow(/documented names/);
    await expect(store.countStats("prj_one", { received: 1 })).rejects.toThrow(/day/);
    await expect(store.countStats(DAY, { received: -1 })).rejects.toThrow(/count/);
    await expect(store.countStats(DAY, { received: 1.5 })).rejects.toThrow(/count/);
    await expect(store.countStats(DAY, {})).rejects.toThrow(/no counts/);
  });

  it("the Redis store keeps one hash per day and sets its 90-day expiry once", async () => {
    const sent = [];
    const fetch = async (url, init) => {
      const cmd = JSON.parse(init.body);
      sent.push(cmd);
      return new Response(JSON.stringify({ result: cmd[0] === "HGETALL" ? ["received", "3", "succeeded", "2"] : 1 }), { status: 200 });
    };
    const store = redisStore({ url: "https://kv.example.test", token: "kvtoken", fetch });
    await store.countStats(DAY, { received: 1 });
    await store.countStats(DAY, { received: 1, succeeded: 1 });
    expect(sent).toEqual([
      ["HINCRBY", `pv:stats:${DAY}`, "received", "1"],
      ["EXPIRE", `pv:stats:${DAY}`, String(STAT_TTL_SECONDS)],
      ["HINCRBY", `pv:stats:${DAY}`, "received", "1"],
      ["HINCRBY", `pv:stats:${DAY}`, "succeeded", "1"],
    ]);
    expect(STAT_TTL_SECONDS).toBe(90 * 86_400);
    expect(await store.stats(DAY)).toEqual({ received: 3, succeeded: 2 });
  });
});

describe("the workflow reports to the relay", () => {
  it("asks for an OIDC token for this server and reports on every outcome, for production only", () => {
    expect(WORKFLOW_YAML).toMatch(/^\s+id-token: write/m);
    expect(WORKFLOW_YAML).toMatch(/^\s+statuses: write/m);
    expect(WORKFLOW_YAML).toContain("vercel/repository-dispatch/actions/status@");
    const step = WORKFLOW_YAML.slice(WORKFLOW_YAML.indexOf("- name: Report pass or fail"));
    expect(step).toMatch(/if: always\(\) && github\.event\.client_payload\.environment == 'production'/);
    expect(step).toContain("audience=https%3A%2F%2Fvercel.penthera.org%2Freport%2F$DEPLOYMENT_ID");
    // The id is checked against its shape before it goes into the token request.
    expect(step.indexOf("grep -Eq '^dpl_")).toBeLessThan(step.indexOf("ACTIONS_ID_TOKEN_REQUEST_URL"));
    expect(step).toContain('if [ "$SCAN_OUTCOME" = "success" ]; then conclusion=succeeded; fi');
    expect(step).toContain("conclusion=failed");
    // Untrusted dispatch values reach the shell only through env.
    expect(step).not.toMatch(/run: \|[\s\S]*\$\{\{/);
    expect(step).toContain("{deploymentId: $d, projectId: $p, conclusion: $c}");
  });
});
