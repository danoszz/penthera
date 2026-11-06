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
    aud: BASE,
    repository: "acme/shop",
    repository_id: "4242",
    repository_owner: "acme",
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
  prj_one: { id: "prj_one", name: "shop", link: { type: "github", org: "acme", repo: "shop", repoId: 4242, productionBranch: "main" } },
  prj_two: { id: "prj_two", name: "blog", link: { type: "github", org: "acme", repo: "blog", repoId: 5151, productionBranch: "main" } },
};
// Which project each deployment belongs to, as Vercel knows it.
const DEPLOYMENTS = { dpl_one: "prj_one", dpl_two: "prj_two" };

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
    ["an audience list", (t) => jwt(claims(t, { aud: [BASE] })), 401],
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
    const res = await ctx.app.report(report(jwt(claims()), { deploymentId: "dpl_two", projectId: "prj_one", conclusion: "succeeded" }));
    expect(res.status).toBe(403);
    expect(patches(ctx.vercel)).toHaveLength(0);
  });

  it("refuses a project the check is not on, and a project whose link names another installation", async () => {
    const ctx = await enabled();
    // prj_two has no link.
    const blog = jwt(claims(T0, { repository: "acme/blog", repository_id: "5151", workflow_ref: "acme/blog/.github/workflows/penthera-vercel.yml@refs/heads/main" }));
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
    const app = createApp({ env: ctx.env, store: ctx.store, now: () => T0, fetch: async (u, i) => (String(u).includes("/check-runs") ? new Response(JSON.stringify({ error: { code: "forbidden" } }), { status: 403 }) : ctx.vercel.fetch(u, i)) });
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

  it("answers 503 and changes nothing when GitHub's keys cannot be read", async () => {
    const vercel = mock({ jwksStatus: 500 });
    const ctx = await enabled({ vercel });
    expect((await ctx.app.report(report(jwt(claims())))).status).toBe(503);
    expect(patches(vercel)).toHaveLength(0);
  });

  it("verifyGithubToken accepts a good token and returns its claims", async () => {
    const v = mock();
    const out = await verifyGithubToken(jwt(claims()), { audience: BASE, jwks: jwksCache({ fetch: v.fetch, now: () => T0 }), now: () => T0 });
    expect(out.repository).toBe("acme/shop");
    await expect(verifyGithubToken(jwt(claims()), { audience: "", jwks: jwksCache({ fetch: v.fetch, now: () => T0 }), now: () => T0 })).rejects.toThrow(/bad_audience/);
  });

  it("refuses every algorithm but RS256 before it looks up a key", async () => {
    const v = mock();
    const opts = { audience: BASE, jwks: jwksCache({ fetch: v.fetch, now: () => T0 }), now: () => T0 };
    for (const alg of ["none", "HS256", "RS512", "PS256", "ES256", undefined]) {
      await expect(verifyGithubToken(jwt(claims(), { header: { alg } }), opts)).rejects.toThrow(/bad_alg/);
    }
    expect(v.calls).toHaveLength(0);
    const s = Math.floor(T0 / 1000);
    // A lifetime over one hour, even when exp itself is near.
    await expect(verifyGithubToken(jwt(claims(T0, { iat: s - 7200, nbf: s - 7200, exp: s + 60 })), opts)).rejects.toThrow(/too_long/);
  });
});

describe("project links", () => {
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

  it("counts received, succeeded, failed and rejected by reason, under the date only", async () => {
    const ctx = await enabled();
    expect((await ctx.app.report(report(jwt(claims()), { deploymentId: "dpl_one", projectId: "prj_one", conclusion: "failed" }))).status).toBe(200);
    await ctx.app.report(report(jwt(claims()))); // already completed
    await ctx.app.report(report(jwt(claims(T0, { aud: "https://evil.example" }))));
    await ctx.app.report(report(null));
    expect(await ctx.store.stats(DAY)).toEqual({ received: 4, failed: 1, rejected_already_completed: 1, rejected_bad_token: 1, rejected_unauthorized: 1 });
    const other = await enabled({ queued: true });
    await other.app.report(report(jwt(claims())));
    expect(await other.store.stats(DAY)).toEqual({ received: 1, succeeded: 1 });
    // Nothing but the date and the counter names: no project, deployment, team, configuration or address.
    const dump = JSON.stringify({ days: ctx.store.statDays(), stats: await ctx.store.stats(DAY) });
    for (const id of ["prj_", "dpl_", "team_", "icfg_", "198.51.100", "acme"]) expect(dump).not.toContain(id);
    expect(ctx.store.statDays()).toEqual([DAY]);
  });

  it("every reason /report can answer has a counter, and nothing else does", () => {
    expect([...STAT_FIELDS].sort()).toEqual(["failed", "received", "succeeded", ...REJECT_REASONS.map((r) => `rejected_${r}`)].sort());
  });

  it("does not count rate-limited requests, and a store error while counting changes no answer", async () => {
    const ctx = await enabled();
    for (let i = 0; i < 35; i++) await ctx.app.report(report("x.y.z"));
    expect((await ctx.store.stats(DAY)).received).toBe(30);
    const other = await enabled();
    other.store.countStat = async () => {
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

  it("the store refuses any other counter name or day", async () => {
    const store = memoryStore();
    await store.countStat(DAY, "received");
    await expect(store.countStat(DAY, "rejected_prj_one")).rejects.toThrow(/documented names/);
    await expect(store.countStat(DAY, "project")).rejects.toThrow(/documented names/);
    await expect(store.countStat("prj_one", "received")).rejects.toThrow(/day/);
  });

  it("the Redis store keeps one hash per day that expires after 90 days", async () => {
    const sent = [];
    const fetch = async (url, init) => {
      const cmd = JSON.parse(init.body);
      sent.push(cmd);
      return new Response(JSON.stringify({ result: cmd[0] === "HGETALL" ? ["received", "3", "succeeded", "2"] : 1 }), { status: 200 });
    };
    const store = redisStore({ url: "https://kv.example.test", token: "kvtoken", fetch });
    await store.countStat(DAY, "received");
    expect(sent).toEqual([["HINCRBY", `pv:stats:${DAY}`, "received", "1"], ["EXPIRE", `pv:stats:${DAY}`, String(STAT_TTL_SECONDS)]]);
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
    expect(step).toContain("audience=https%3A%2F%2Fvercel.penthera.org");
    expect(step).toContain('if [ "$SCAN_OUTCOME" = "success" ]; then conclusion=succeeded; fi');
    expect(step).toContain("conclusion=failed");
    // Untrusted dispatch values reach the shell only through env.
    expect(step).not.toMatch(/run: \|[\s\S]*\$\{\{/);
    expect(step).toContain("{deploymentId: $d, projectId: $p, conclusion: $c}");
  });
});
