/**
 * Offline tests for the Vercel integration server (integrations/vercel).
 * They run under the repo's vitest (`npm test`). No test reaches Vercel,
 * GitHub or Upstash: every fetch is a mock that records its calls.
 */
import { createHmac, randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createApp, readConfig } from "../lib/app.mjs";
import { openToken, parseKeys, sealToken, signValue, unsignValue, verifyWebhookSignature } from "../lib/crypto.mjs";
import { CSP, safeNext } from "../lib/http.mjs";
import { redact, setLogSink } from "../lib/log.mjs";
import { memoryStore, redisStore } from "../lib/store.mjs";
import { WORKFLOW_YAML, checkBody, checkName, githubNewFileUrl } from "../lib/workflow.mjs";

const here = (p) => new URL(p, import.meta.url);
const b64key = () => randomBytes(32).toString("base64");
const BASE = "https://penthera-vercel.example.test";

// Fake credentials, random per run, so a leak check can search for them.
const CLIENT_SECRET = `cs_${randomBytes(18).toString("hex")}`;
const ACCESS_TOKEN = `at_${randomBytes(18).toString("hex")}`;
const CODE = randomBytes(12).toString("hex");
const CFG = "icfg_TestConfig123";
const TEAM = "team_TestTeam123";
const NEXT = "https://vercel.com/integrations/penthera/new/done?x=1";

function env(extra = {}) {
  return {
    VERCEL_CLIENT_ID: "oac_testclient",
    VERCEL_CLIENT_SECRET: CLIENT_SECRET,
    PENTHERA_TOKEN_KEYS: `v1:${b64key()}`,
    PUBLIC_BASE_URL: BASE,
    CRON_SECRET: `cron_${randomBytes(16).toString("hex")}`,
    ...extra,
  };
}

const PROJECTS = [
  { id: "prj_one", name: "shop", link: { type: "github", org: "acme", repo: "shop", productionBranch: "main" } },
  { id: "prj_two", name: "blog", link: { type: "gitlab", org: "acme", repo: "blog" } },
];

/** A mock Vercel API. `checks` maps project id to its checks; `fail` forces a status per path. */
function mockVercel({ checks = {}, fail = {}, token = ACCESS_TOKEN } = {}) {
  const calls = [];
  let nextId = 1;
  const fetch = async (input, init = {}) => {
    const url = new URL(String(input));
    const method = init.method ?? "GET";
    calls.push({ method, url, headers: init.headers ?? {}, body: init.body });
    const reply = (status, body) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const forced = fail[`${method} ${url.pathname}`];
    if (forced) return reply(forced, { error: { code: "forced", message: `echo ${token}` } });
    if (url.pathname === "/v2/oauth/access_token") {
      const form = new URLSearchParams(String(init.body));
      if (form.get("code") !== CODE || form.get("client_secret") !== CLIENT_SECRET) return reply(400, { error: { code: "bad_code" } });
      return reply(200, { token_type: "Bearer", access_token: token, installation_id: CFG, user_id: "user_1", team_id: TEAM });
    }
    if (init.headers?.Authorization !== `Bearer ${token}`) return reply(401, { error: { code: "unauthorized" } });
    let m;
    if (url.pathname === "/v10/projects") return reply(200, { projects: PROJECTS, pagination: { count: 2, next: null } });
    if ((m = /^\/v9\/projects\/([^/]+)$/.exec(url.pathname))) {
      const p = PROJECTS.find((x) => x.id === m[1]);
      return p ? reply(200, p) : reply(404, { error: { code: "not_found" } });
    }
    if ((m = /^\/v2\/projects\/([^/]+)\/checks$/.exec(url.pathname))) {
      checks[m[1]] ??= [];
      if (method === "GET") return reply(200, { availableNativeChecks: [], checks: checks[m[1]] });
      const body = JSON.parse(init.body);
      const created = { id: `chk_${nextId++}`, ...body, sourceKind: "git-provider", projectId: m[1] };
      checks[m[1]].push(created);
      return reply(200, created);
    }
    if ((m = /^\/v2\/projects\/([^/]+)\/checks\/([^/]+)$/.exec(url.pathname)) && method === "DELETE") {
      checks[m[1]] = (checks[m[1]] ?? []).filter((c) => c.id !== m[2]);
      return reply(204);
    }
    return reply(404, { error: { code: "no_route" } });
  };
  return { fetch, calls, checks };
}

const cookieJar = (res) => res.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
const get = (path, headers = {}) => new Request(`${BASE}${path}`, { headers });
const post = (path, body, headers = {}) =>
  new Request(`${BASE}${path}`, { method: "POST", body, headers: { "content-type": "application/x-www-form-urlencoded", ...headers } });
const installUrl = (extra = "") => `/install?code=${CODE}&configurationId=${CFG}&teamId=${TEAM}&next=${encodeURIComponent(NEXT)}&source=marketplace${extra}`;

function setup(opts = {}) {
  const e = env(opts.env);
  const store = opts.store ?? memoryStore();
  const vercel = mockVercel(opts.vercel);
  const app = createApp({ env: e, store, fetch: vercel.fetch, now: opts.now });
  return { app, store, vercel, env: e };
}

async function installed(opts) {
  const ctx = setup(opts);
  const res = await ctx.app.install(get(installUrl()));
  return { ...ctx, res, cookie: cookieJar(res) };
}

const csrfOf = async (res) => /name="csrf" value="([^"]+)"/.exec(await res.text())?.[1];

describe("webhook signature", () => {
  const secret = "integration-secret";
  const body = Buffer.from('{"type":"integration-configuration.removed"}');
  const good = createHmac("sha1", secret).update(body).digest("hex");

  it("accepts the HMAC-SHA1 of the raw body", () => {
    expect(verifyWebhookSignature(body, good, secret)).toBe(true);
    expect(verifyWebhookSignature(body, good.toUpperCase(), secret)).toBe(true);
  });
  it("rejects a bad, short, missing or other-body signature", () => {
    expect(verifyWebhookSignature(body, good.replace(/.$/, (c) => (c === "0" ? "1" : "0")), secret)).toBe(false);
    expect(verifyWebhookSignature(body, good.slice(0, 39), secret)).toBe(false);
    expect(verifyWebhookSignature(body, undefined, secret)).toBe(false);
    expect(verifyWebhookSignature(body, "", secret)).toBe(false);
    expect(verifyWebhookSignature(Buffer.from(`${body} `), good, secret)).toBe(false);
    expect(verifyWebhookSignature(body, good, "")).toBe(false);
  });

  it("the route answers 403 to unsigned and wrongly signed requests, and changes nothing", async () => {
    const { app, store } = await installed();
    const raw = JSON.stringify({ id: "evt_1", type: "integration-configuration.removed", payload: { configuration: { id: CFG } } });
    const unsigned = await app.webhook(new Request(`${BASE}/webhook`, { method: "POST", body: raw }));
    expect(unsigned.status).toBe(403);
    const wrong = await app.webhook(new Request(`${BASE}/webhook`, { method: "POST", body: raw, headers: { "x-vercel-signature": createHmac("sha1", "nope").update(raw).digest("hex") } }));
    expect(wrong.status).toBe(403);
    expect(await store.get(CFG)).not.toBeNull();
  });
});

describe("encryption", () => {
  it("round-trips a token and binds it to its configuration", () => {
    const keys = parseKeys(`v1:${b64key()}`);
    const sealed = sealToken(ACCESS_TOKEN, CFG, keys);
    expect(JSON.stringify(sealed)).not.toContain(ACCESS_TOKEN);
    expect(openToken(sealed, CFG, keys)).toBe(ACCESS_TOKEN);
    expect(() => openToken(sealed, "icfg_other", keys)).toThrow();
    expect(() => openToken({ ...sealed, tag: Buffer.alloc(16).toString("base64") }, CFG, keys)).toThrow();
    expect(sealToken(ACCESS_TOKEN, CFG, keys).iv).not.toBe(sealed.iv);
  });
  it("decrypts with an older key after rotation, and fails with a wrong one", () => {
    const old = `v1:${b64key()}`;
    const sealed = sealToken(ACCESS_TOKEN, CFG, parseKeys(old));
    expect(openToken(sealed, CFG, parseKeys(`v2:${b64key()},${old}`))).toBe(ACCESS_TOKEN);
    expect(() => openToken(sealed, CFG, parseKeys(`v1:${b64key()}`))).toThrow();
  });
  it("refuses malformed keys without echoing them", () => {
    expect(() => parseKeys("")).toThrow(/not set/);
    expect(() => parseKeys("v1:short")).toThrow(/32 bytes/);
    try {
      parseKeys("v1:secretvalue");
    } catch (e) {
      expect(e.message).not.toContain("secretvalue");
    }
  });
  it("signed cookies expire and refuse tampering", () => {
    const key = randomBytes(32);
    const v = signValue({ c: CFG, e: 2_000 }, key);
    expect(unsignValue(v, key, 1_000)?.c).toBe(CFG);
    expect(unsignValue(v, key, 3_000)).toBeNull();
    expect(unsignValue(`${v}x`, key, 1_000)).toBeNull();
    expect(unsignValue(v, randomBytes(32), 1_000)).toBeNull();
  });
});

describe("OAuth install", () => {
  it("exchanges the code once, form-encoded, and stores only the sealed record", async () => {
    const { res, store, vercel, env: e } = await installed();
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("/setup");
    const exchange = vercel.calls.find((c) => c.url.pathname === "/v2/oauth/access_token");
    expect(exchange.method).toBe("POST");
    expect(exchange.headers["Content-Type"]).toBe("application/x-www-form-urlencoded");
    const form = new URLSearchParams(String(exchange.body));
    expect(Object.fromEntries(form)).toEqual({ client_id: "oac_testclient", client_secret: CLIENT_SECRET, code: CODE, redirect_uri: `${BASE}/install` });

    const [record] = store.dump();
    expect(Object.keys(record).sort()).toEqual(["ciphertext", "configurationId", "createdAt", "iv", "keyVersion", "ownerId", "tag"]);
    expect(record).toMatchObject({ configurationId: CFG, ownerId: TEAM, keyVersion: "v1" });
    expect(JSON.stringify(store.dump())).not.toContain(ACCESS_TOKEN);
    expect(openToken(record, CFG, parseKeys(e.PENTHERA_TOKEN_KEYS))).toBe(ACCESS_TOKEN);

    const cookie = res.headers.getSetCookie().find((c) => c.startsWith("__Host-pv_session="));
    expect(cookie).toMatch(/; Secure; HttpOnly; SameSite=Lax; Max-Age=1800$/);
    expect(cookie).not.toContain(ACCESS_TOKEN);
  });

  it("a second install with the same configurationId overwrites, never duplicates", async () => {
    const ctx = await installed();
    const first = ctx.store.dump()[0];
    await ctx.app.install(get(installUrl()));
    expect(ctx.store.dump()).toHaveLength(1);
    expect(ctx.store.dump()[0].createdAt).toBe(first.createdAt);
  });

  it("refuses a rejected code, a bad next URL and missing parameters, storing nothing", async () => {
    const { app, store } = setup();
    expect((await app.install(get(installUrl().replace(CODE, "deadbeefdeadbeef")))).status).toBe(502);
    expect((await app.install(get(`/install?code=${CODE}&configurationId=${CFG}&next=${encodeURIComponent("https://evil.example/x")}`))).status).toBe(400);
    expect((await app.install(get(`/install?configurationId=${CFG}`))).status).toBe(400);
    expect((await app.install(get(`/install?code=${CODE}`))).status).toBe(400);
    expect(store.dump()).toHaveLength(0);
  });

  it("only returns to vercel.com", () => {
    expect(safeNext(NEXT)).toBe(NEXT);
    for (const bad of ["http://vercel.com/x", "https://vercel.com.evil.example/", "https://user@vercel.com/", "javascript:alert(1)", "//vercel.com", ""]) {
      expect(safeNext(bad)).toBeNull();
    }
  });
});

describe("state check (CSRF)", () => {
  it("/start sets a state cookie and sends the user to Vercel with it", async () => {
    const { app } = setup();
    const res = await app.start(get("/start"));
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("location"));
    expect(location.origin + location.pathname).toBe("https://vercel.com/integrations/penthera/new");
    const state = location.searchParams.get("state");
    expect(state.length).toBeGreaterThanOrEqual(32);
    expect(res.headers.getSetCookie()[0]).toContain(`__Host-pv_state=${state};`);
  });

  it("accepts an external install whose state matches the cookie, and clears the cookie", async () => {
    const { app } = setup();
    const startRes = await app.start(get("/start"));
    const state = new URL(startRes.headers.get("location")).searchParams.get("state");
    const res = await app.install(get(installUrl(`&state=${state}`).replace("source=marketplace", "source=external"), { cookie: cookieJar(startRes) }));
    expect(res.status).toBe(303);
    expect(res.headers.getSetCookie().some((c) => c.startsWith("__Host-pv_state=;") && c.includes("Max-Age=0"))).toBe(true);
  });

  it("refuses a missing, wrong or cookie-less state before exchanging the code", async () => {
    const { app, vercel, store } = setup();
    const ext = (s) => installUrl(s).replace("source=marketplace", "source=external");
    expect((await app.install(get(ext("&state=abc"), { cookie: "__Host-pv_state=xyz" }))).status).toBe(403);
    expect((await app.install(get(ext("&state=abc")))).status).toBe(403);
    expect((await app.install(get(ext("")))).status).toBe(403);
    expect(vercel.calls).toHaveLength(0);
    expect(store.dump()).toHaveLength(0);
  });
});

describe("setup", () => {
  it("lists projects, shows the prefilled workflow link, registers the check, then returns to next", async () => {
    const { app, cookie, vercel } = await installed();
    const page = await app.setup(get("/setup", { cookie }));
    expect(page.status).toBe(200);
    const text = await page.text();
    expect(text).toContain("shop");
    expect(text).toContain("Needs a GitHub-connected project");
    const csrf = /name="csrf" value="([^"]+)"/.exec(text)[1];
    expect(vercel.calls.filter((c) => c.url.pathname === "/v10/projects")[0].url.searchParams.get("teamId")).toBe(TEAM);

    const workflow = await app.setup(post("/setup", `csrf=${csrf}&action=workflow&p=prj_one&p=prj_two`, { cookie, origin: BASE }));
    const wtext = await workflow.text();
    const link = /href="(https:\/\/github\.com\/[^"]+)"/.exec(wtext)[1].replaceAll("&amp;", "&");
    const u = new URL(link);
    expect(u.pathname).toBe("/acme/shop/new/main");
    expect(u.searchParams.get("filename")).toBe(".github/workflows/penthera-vercel.yml");
    expect(u.searchParams.get("value")).toBe(WORKFLOW_YAML);
    expect(vercel.calls.some((c) => c.method === "POST" && c.url.pathname.endsWith("/checks"))).toBe(false);

    const done = await app.setup(post("/setup", `csrf=${csrf}&action=enable&p=prj_one`, { cookie, origin: BASE }));
    expect(done.status).toBe(303);
    expect(done.headers.get("location")).toBe(NEXT);
    expect(vercel.checks.prj_one).toHaveLength(1);
    expect(vercel.checks.prj_one[0]).toMatchObject(checkBody("shop"));

    // Enabling again adds no duplicate; remove deletes ours.
    await app.setup(post("/setup", `csrf=${csrf}&action=enable&p=prj_one`, { cookie, origin: BASE }));
    expect(vercel.checks.prj_one).toHaveLength(1);
    expect((await app.setup(post("/setup", `csrf=${csrf}&remove=prj_one`, { cookie, origin: BASE }))).status).toBe(303);
    expect(vercel.checks.prj_one).toHaveLength(0);
  });

  it("refuses posts without the form token, from another origin, or without a session", async () => {
    const { app, cookie, vercel } = await installed();
    const csrf = await csrfOf(await app.setup(get("/setup", { cookie })));
    expect((await app.setup(post("/setup", "action=enable&p=prj_one", { cookie }))).status).toBe(403);
    expect((await app.setup(post("/setup", `csrf=${csrf}&action=enable&p=prj_one`, { cookie, origin: "https://evil.example" }))).status).toBe(403);
    expect((await app.setup(post("/setup", `csrf=${csrf}&action=enable&p=prj_one`))).status).toBe(401);
    expect(vercel.checks.prj_one ?? []).toHaveLength(0);
  });

  it("the session ends after 30 minutes", async () => {
    let t = 1_000_000;
    const ctx = setup({ now: () => t });
    const res = await ctx.app.install(get(installUrl()));
    t += 31 * 60_000;
    expect((await ctx.app.setup(get("/setup", { cookie: cookieJar(res) }))).status).toBe(401);
  });

  it("configure without the install session reveals nothing about the configuration", async () => {
    const { app, cookie } = await installed();
    const anon = await app.configure(get(`/configure?configurationId=${CFG}`));
    const text = await anon.text();
    expect(anon.status).toBe(200);
    expect(text).not.toContain("shop");
    expect(text).not.toContain(TEAM);
    const known = await app.configure(get(`/configure?configurationId=${CFG}`, { cookie }));
    expect(known.headers.get("location")).toBe("/setup");
  });
});

describe("uninstall", () => {
  const signed = (raw, secret = CLIENT_SECRET) =>
    new Request(`${BASE}/webhook`, { method: "POST", body: raw, headers: { "x-vercel-signature": createHmac("sha1", secret).update(raw).digest("hex") } });

  it("integration-configuration.removed deletes the record, after trying to remove our checks", async () => {
    const { app, store, vercel, cookie } = await installed();
    const csrf = await csrfOf(await app.setup(get("/setup", { cookie })));
    await app.setup(post("/setup", `csrf=${csrf}&action=enable&p=prj_one`, { cookie, origin: BASE }));
    expect(vercel.checks.prj_one).toHaveLength(1);

    const raw = JSON.stringify({ id: "evt_1", type: "integration-configuration.removed", payload: { configuration: { id: CFG, projects: ["prj_one"] } } });
    const res = await app.webhook(signed(raw));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ deleted: true });
    expect(store.dump()).toHaveLength(0);
    expect(vercel.checks.prj_one).toHaveLength(0);
    // A retry of the same event is harmless.
    expect((await app.webhook(signed(raw))).status).toBe(200);
  });

  it("deletes the record even when Vercel has already revoked the token", async () => {
    const { app, store } = await installed({ vercel: { fail: { "GET /v9/projects/prj_one": 401 } } });
    const raw = JSON.stringify({ type: "integration-configuration.removed", payload: { configuration: { id: CFG, projects: ["prj_one"] } } });
    expect((await app.webhook(signed(raw))).status).toBe(200);
    expect(store.dump()).toHaveLength(0);
  });

  it("ignores other events and keeps the record", async () => {
    const { app, store } = await installed();
    const raw = JSON.stringify({ type: "deployment.created", payload: { deployment: { url: "x.vercel.app" } } });
    expect(await (await app.webhook(signed(raw))).json()).toMatchObject({ ignored: true });
    expect(store.dump()).toHaveLength(1);
  });

  it("transferred re-keys the owner and nothing else", async () => {
    const { app, store } = await installed();
    const before = store.dump()[0];
    const raw = JSON.stringify({ type: "integration-configuration.transferred", payload: { configuration: { id: CFG }, newTeamId: "team_New1" } });
    await app.webhook(signed(raw));
    expect(store.dump()[0]).toEqual({ ...before, ownerId: "team_New1" });
  });

  it("the weekly sweep deletes records whose token no longer works, and needs the cron secret", async () => {
    const ctx = await installed({ vercel: { fail: { "GET /v10/projects": 403 } } });
    expect((await ctx.app.sweep(get("/sweep"))).status).toBe(401);
    expect(ctx.store.dump()).toHaveLength(1);
    const res = await ctx.app.sweep(get("/sweep", { authorization: `Bearer ${ctx.env.CRON_SECRET}` }));
    expect(await res.json()).toMatchObject({ checked: 1, removed: 1 });
    expect(ctx.store.dump()).toHaveLength(0);
  });
});

describe("no secrets in logs", () => {
  it("an install, setup, failure and uninstall log no token, code or secret", async () => {
    const lines = [];
    const previous = setLogSink((l) => lines.push(l));
    try {
      const failing = await installed({ vercel: { fail: { "GET /v10/projects": 500, "POST /v2/projects/prj_one/checks": 403 } } });
      await failing.app.setup(get("/setup", { cookie: failing.cookie }));
      const csrf = "x";
      await failing.app.setup(post("/setup", `csrf=${csrf}&action=enable&p=prj_one`, { cookie: failing.cookie }));
      const bad = setup();
      await bad.app.install(get(installUrl().replace(CODE, "deadbeefdeadbeef")));
      const broken = createApp({ env: { ...env(), PENTHERA_TOKEN_KEYS: "v1:not-a-key" }, store: memoryStore(), fetch: mockVercel().fetch });
      await broken.install(get(installUrl()));
    } finally {
      setLogSink(previous);
    }
    expect(lines.length).toBeGreaterThan(0);
    const all = lines.join("\n");
    for (const secret of [ACCESS_TOKEN, CLIENT_SECRET, CODE, "deadbeefdeadbeef", "not-a-key"]) expect(all).not.toContain(secret);
  });

  it("redact() masks token shapes and env secrets but keeps ids and error codes", () => {
    const e = { VERCEL_CLIENT_SECRET: CLIENT_SECRET };
    expect(redact(`Bearer ${ACCESS_TOKEN}`, e)).not.toContain(ACCESS_TOKEN);
    expect(redact(`secret ${CLIENT_SECRET} here`, e)).not.toContain(CLIENT_SECRET);
    expect(redact(`${CFG} integration_configuration_disabled`, e)).toBe(`${CFG} integration_configuration_disabled`);
  });
});

describe("headers", () => {
  it("every page and API answer carries a strict CSP and the popup's COOP", async () => {
    const { app, cookie } = await installed();
    for (const res of [await app.setup(get("/setup", { cookie })), await app.configure(get("/configure")), await app.health(get("/health")), await app.webhook(new Request(`${BASE}/webhook`, { method: "POST", body: "{}" }))]) {
      expect(res.headers.get("content-security-policy")).toBe(CSP);
      expect(res.headers.get("cross-origin-opener-policy")).toBe("unsafe-none");
      expect(res.headers.get("x-frame-options")).toBe("DENY");
      expect(res.headers.get("cache-control")).toBe("no-store");
    }
    expect(CSP).toContain("script-src 'none'");
    expect(CSP).not.toContain("unsafe-inline");
  });

  it("pages use no inline style attributes or scripts, which the CSP would block", async () => {
    const { app, cookie } = await installed();
    const page = await (await app.setup(get("/setup", { cookie }))).text();
    expect(page).not.toMatch(/\sstyle="/);
    expect(page).not.toMatch(/<script/i);
  });

  it("an unset env answers 500 not_configured and echoes no value", async () => {
    const app = createApp({ env: {}, store: memoryStore(), fetch: mockVercel().fetch });
    const res = await app.install(get(installUrl()));
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "not_configured" });
    expect(() => readConfig({ ...env(), PUBLIC_BASE_URL: "http://example.test" })).toThrow(/https/);
  });
});

describe("store", () => {
  it("refuses any field beyond the documented record", async () => {
    const store = memoryStore();
    const keys = parseKeys(`v1:${b64key()}`);
    const record = { configurationId: CFG, ownerId: TEAM, ...sealToken("t", CFG, keys), createdAt: "2026-11-05T00:00:00.000Z" };
    await store.put(record);
    await expect(store.put({ ...record, projectName: "shop" })).rejects.toThrow(/exactly/);
    await expect(store.put({ ...record, token: "t" })).rejects.toThrow(/exactly/);
  });

  it("the Redis store speaks the Upstash REST protocol over https only", async () => {
    const sent = [];
    const fetch = async (url, init) => {
      sent.push({ url: String(url), auth: init.headers.Authorization, cmd: JSON.parse(init.body) });
      const cmd = JSON.parse(init.body)[0];
      const result = cmd === "GET" ? null : cmd === "SCAN" ? ["0", ["pv:cfg:icfg_a"]] : "OK";
      return new Response(JSON.stringify({ result }), { status: 200 });
    };
    const store = redisStore({ url: "https://kv.example.test", token: "kvtoken", fetch });
    expect(await store.get(CFG)).toBeNull();
    expect(await store.ids()).toEqual(["icfg_a"]);
    await store.delete(CFG);
    expect(sent.map((s) => s.cmd[0])).toEqual(["GET", "SCAN", "DEL"]);
    expect(sent[0]).toMatchObject({ url: "https://kv.example.test/", auth: "Bearer kvtoken", cmd: ["GET", `pv:cfg:${CFG}`] });
    expect(() => redisStore({ url: "http://kv.example.test", token: "x", fetch })).toThrow(/https/);
  });
});

describe("workflow and repo rules", () => {
  it("matches row 125's example when that file is in the repo", () => {
    const example = here("../../../docs/examples/vercel-deployment-check.yml");
    if (existsSync(example)) expect(WORKFLOW_YAML).toBe(readFileSync(example, "utf8"));
  });

  it("pins every action by full SHA, triggers on deployment.ready, and sets no AI input", () => {
    expect(WORKFLOW_YAML).toMatch(/types:\s*\n\s*- "vercel\.deployment\.ready"/);
    for (const [, ref] of WORKFLOW_YAML.matchAll(/uses:\s*\S+@(\S+)/g)) expect(ref).toMatch(/^[0-9a-f]{40}$/);
    expect(WORKFLOW_YAML).not.toMatch(/^\s*ai:/m);
    expect(WORKFLOW_YAML).not.toMatch(/--ai\b/);
  });

  it("names the Vercel check after the status the workflow reports", () => {
    expect(checkName("shop")).toBe("Penthera on Vercel | scan (shop - production)");
    expect(checkBody("shop")).toMatchObject({ blocks: "deployment-promotion", targets: ["production"], source: { kind: "git-provider", provider: "github" } });
  });

  it("builds the GitHub link only for plain owner/repo names, and keeps it short enough", () => {
    expect(githubNewFileUrl("acme/shop", "main").length).toBeLessThan(8_000);
    expect(githubNewFileUrl("acme/shop", "release/v2")).toContain("/new/release/v2?");
    for (const bad of ["acme", "acme/shop/x", "../x/y", "a b/c", ""]) expect(githubNewFileUrl(bad, "main")).toBeNull();
  });

  it("the server has no dependencies at all, so no SDK and no model", () => {
    const pkg = JSON.parse(readFileSync(here("../package.json"), "utf8"));
    expect(pkg.dependencies ?? {}).toEqual({});
    expect(pkg.devDependencies ?? {}).toEqual({});
  });
});
