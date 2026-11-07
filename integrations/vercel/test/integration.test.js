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
import { PREFILL_YAML, WORKFLOW_YAML, checkBody, checkName, githubNewFileUrl, isOurCheck } from "../lib/workflow.mjs";
// The repo's vendored YAML parser: no package to install, the same one the Action tests use.
import YAML from "../../../lib/vendor/yaml/index.js";
const parseYaml = (text) => YAML.parse(text);

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
    INTEGRATION_CLIENT_ID: "oac_testclient",
    INTEGRATION_CLIENT_SECRET: CLIENT_SECRET,
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
    if (url.pathname === `/v1/integrations/configuration/${CFG}`) return reply(200, { id: CFG, integrationId: "oac_realintegration", slug: "penthera" });
    if ((m = /^\/v9\/projects\/([^/]+)$/.exec(url.pathname))) {
      const p = PROJECTS.find((x) => x.id === m[1]);
      return p ? reply(200, p) : reply(404, { error: { code: "not_found" } });
    }
    if ((m = /^\/v2\/projects\/([^/]+)\/checks$/.exec(url.pathname))) {
      checks[m[1]] ??= [];
      if (method === "GET") return reply(200, { availableNativeChecks: [], checks: checks[m[1]] });
      const body = JSON.parse(init.body);
      const created = { id: `chk_${nextId++}`, ...body, sourceKind: body.source?.kind, projectId: m[1] };
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
    expect(Object.keys(record).sort()).toEqual(["ciphertext", "configurationId", "createdAt", "iv", "keyVersion", "ownerId", "sessionNonce", "tag"]);
    expect(record).toMatchObject({ configurationId: CFG, ownerId: TEAM, keyVersion: "v1" });
    expect(JSON.stringify(store.dump())).not.toContain(ACCESS_TOKEN);
    expect(openToken(record, CFG, parseKeys(e.PENTHERA_TOKEN_KEYS))).toBe(ACCESS_TOKEN);

    const cookie = res.headers.getSetCookie().find((c) => c.startsWith("__Host-pv_session="));
    expect(cookie).toMatch(/; Secure; HttpOnly; SameSite=Lax; Max-Age=1800$/);
    expect(cookie).not.toContain(ACCESS_TOKEN);
  });

  it("a second install with the same configurationId overwrites, never duplicates", async () => {
    let t = 1_000_000;
    const ctx = setup({ now: () => t });
    await ctx.app.install(get(installUrl()));
    t += 60_000;
    await ctx.app.install(get(installUrl()));
    expect(ctx.store.dump()).toHaveLength(1);
    expect(ctx.store.dump()[0].createdAt).toBe(new Date(t).toISOString());
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
    for (const bad of ["http://vercel.com/x", "https://vercel.com.evil.example/", "https://user@vercel.com/", "https://api.vercel.com/x", "https://vercel.com:8443/x", "javascript:alert(1)", "//vercel.com", ""]) {
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

  it("refuses a wrong or cookie-less state before exchanging the code", async () => {
    const { app, vercel, store } = setup();
    const ext = (s) => installUrl(s).replace("source=marketplace", "source=external");
    expect((await app.install(get(ext("&state=abc"), { cookie: "__Host-pv_state=xyz" }))).status).toBe(403);
    expect((await app.install(get(ext("&state=abc")))).status).toBe(403);
    expect(vercel.calls).toHaveLength(0);
    expect(store.dump()).toHaveLength(0);
  });
});

describe("the install window", () => {
  const ext = (extra) => installUrl(extra).replace("source=marketplace", "source=external");
  const reasonOf = async (res) => /<h1 data-reason="([a-z_]+)"/.exec(await res.text())?.[1] ?? null;
  const clearsState = (res) => res.headers.getSetCookie().some((c) => c.startsWith("__Host-pv_state=;") && c.includes("Max-Age=0"));

  it("a Marketplace or Deploy Button install goes through with a leftover state cookie, and clears it", async () => {
    for (const source of ["marketplace", "deploy-button"]) {
      const { app, store } = setup();
      // Daan's retest: an earlier /start left pv_state in the browser, then he installed from Vercel's page.
      const res = await app.install(get(installUrl().replace("source=marketplace", `source=${source}`), { cookie: "__Host-pv_state=left-from-an-earlier-start" }));
      expect(res.status, source).toBe(303);
      expect(res.headers.get("location")).toBe("/setup");
      expect(clearsState(res)).toBe(true);
      expect(res.headers.getSetCookie().some((c) => c.startsWith("__Host-pv_session="))).toBe(true);
      expect(store.dump()).toHaveLength(1);
    }
  });

  it("an install from the listing link (source=external, no state) goes through like a Marketplace one", async () => {
    // Daan's live install on 7 Nov from vercel.com/integrations/penthera/new came back like this.
    for (const cookie of [undefined, "__Host-pv_state=left-from-an-earlier-start"]) {
      const { app, store, vercel } = setup();
      const res = await app.install(get(ext(""), cookie ? { cookie } : {}));
      expect(res.status, String(cookie)).toBe(303);
      expect(res.headers.get("location")).toBe("/setup");
      expect(res.headers.getSetCookie().some((c) => c.startsWith("__Host-pv_session="))).toBe(true);
      expect(clearsState(res)).toBe(!!cookie);
      expect(vercel.calls.some((c) => c.url.pathname === "/v2/oauth/access_token")).toBe(true);
      expect(store.dump()).toHaveLength(1);
    }
  });

  it("a state-less listing install gets the same exchange checks as a Marketplace one", async () => {
    for (const source of ["marketplace", "external"]) {
      const { app, store } = setup();
      const res = await app.install(get(installUrl().replace("source=marketplace", `source=${source}`).replace(`configurationId=${CFG}`, "configurationId=icfg_Other999")));
      expect(res.status, source).toBe(400);
      expect(store.dump()).toHaveLength(0);
      expect(res.headers.getSetCookie().some((c) => c.startsWith("__Host-pv_session="))).toBe(false);
    }
  });

  it("the leftover-cookie path is the no-cookie path: same exchange, same checks, same refusals", async () => {
    // A mismatched exchange is refused the same way with or without the cookie.
    for (const cookie of [undefined, "__Host-pv_state=old"]) {
      const { app, store } = setup({ vercel: { fail: {} } });
      const res = await app.install(get(installUrl().replace(`configurationId=${CFG}`, "configurationId=icfg_Other999"), cookie ? { cookie } : {}));
      expect(res.status).toBe(400);
      expect(store.dump()).toHaveLength(0);
    }
  });

  it("the state cookie lasts 30 minutes, as long as Vercel's install code", async () => {
    const { app } = setup();
    const set = (await app.start(get("/start"))).headers.getSetCookie()[0];
    expect(set).toMatch(/Max-Age=1800(;|$)/);
  });

  it("each failed state check has its own reason, clears the cookie, and stops before the exchange", async () => {
    const cases = [
      ["state_cookie_missing", ext("&state=abc"), {}],
      ["state_mismatch", ext("&state=abc"), { cookie: "__Host-pv_state=xyz" }],
      // A state on a Marketplace link is still checked against the cookie.
      ["state_cookie_missing", installUrl("&state=abc"), {}],
      ["state_mismatch", installUrl("&state=abc"), { cookie: "__Host-pv_state=xyz" }],
    ];
    for (const [reason, url, headers] of cases) {
      const { app, vercel, store } = setup();
      const res = await app.install(get(url, headers));
      expect(res.status, reason).toBe(403);
      expect(clearsState(res), reason).toBe(true);
      expect(await reasonOf(res.clone()), url).toBe(reason);
      expect(await res.text()).toContain('href="/start"');
      expect(vercel.calls, reason).toHaveLength(0);
      expect(store.dump()).toHaveLength(0);
      expect(res.headers.getSetCookie().some((c) => c.startsWith("__Host-pv_session="))).toBe(false);
    }
  });

  it("each refusal page says nothing was added and what to do in Vercel", async () => {
    const { app } = setup();
    for (const url of [ext("&state=abc"), installUrl("&state=abc")]) {
      const text = await (await app.install(get(url))).text();
      expect(text).toContain("added nothing to your projects");
      expect(text).toContain("Settings, Integrations");
      expect(text).toContain('<dl class="left">');
      expect(text).toContain("Why we check this");
      expect(text).not.toContain("timed out");
    }
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
    // What a deploy does comes before the button that ends the install.
    expect(wtext.indexOf("What happens on your next deploy")).toBeGreaterThan(0);
    expect(wtext.indexOf("What happens on your next deploy")).toBeLessThan(wtext.indexOf("Turn on the check and finish"));
    const link = /href="(https:\/\/github\.com\/[^"]+)"/.exec(wtext)[1].replaceAll("&amp;", "&");
    const u = new URL(link);
    expect(u.pathname).toBe("/acme/shop/new/main");
    expect(u.searchParams.get("filename")).toBe(".github/workflows/penthera-vercel.yml");
    expect(u.searchParams.get("value")).toBe(PREFILL_YAML);
    expect(vercel.calls.some((c) => c.method === "POST" && c.url.pathname.endsWith("/checks"))).toBe(false);

    const done = await app.setup(post("/setup", `csrf=${csrf}&action=enable&p=prj_one`, { cookie, origin: BASE }));
    // Turn on ends the install on Vercel's next address, which closes the popup.
    expect(done.status).toBe(303);
    expect(done.headers.get("location")).toBe(NEXT);
    expect(done.headers.getSetCookie().some((c) => c.startsWith("__Host-pv_session=;"))).toBe(true);
    expect(vercel.checks.prj_one).toHaveLength(1);
    expect(vercel.checks.prj_one[0]).toMatchObject(checkBody(CFG, "oac_realintegration"));
    // The integration id comes from Vercel's record of the installation, not the client id.
    expect(vercel.checks.prj_one[0].source).toEqual({ kind: "integration", integrationId: "oac_realintegration", integrationConfigurationId: CFG });
    expect(vercel.calls.some((c) => c.url.pathname === `/v1/integrations/configuration/${CFG}` && c.url.searchParams.get("teamId") === TEAM)).toBe(true);

    // Enabling again adds no duplicate; remove deletes ours.
    await app.setup(post("/setup", `csrf=${csrf}&action=enable&p=prj_one`, { cookie, origin: BASE }));
    expect(vercel.checks.prj_one).toHaveLength(1);
    expect((await app.setup(post("/setup", `csrf=${csrf}&remove=prj_one`, { cookie, origin: BASE }))).status).toBe(303);
    expect(vercel.checks.prj_one).toHaveLength(0);
  });

  it("once a check is on, /setup reports in per project instead of starting the wizard again", async () => {
    const { app, cookie } = await installed();
    const pick = await (await app.setup(get("/setup", { cookie }))).text();
    expect(pick).toContain("<h1>Pick your projects</h1>");
    const csrf = /name="csrf" value="([^"]+)"/.exec(pick)[1];
    await app.setup(post("/setup", `csrf=${csrf}&action=enable&p=prj_one`, { cookie, origin: BASE }));
    const status = await (await app.setup(get("/setup", { cookie }))).text();
    expect(status).toContain("<h1>Penthera checks 1 of 2 projects</h1>");
    expect(status).not.toContain("Pick your projects");
    expect(status).toContain('<span class="on">Check on</span>');
    expect(status).toContain('name="remove" value="prj_one"');
    expect(status).toContain("Needs a GitHub-connected project");
    // No stored result: the row links to the repo's runs, where the workflow and every result are.
    expect(status).toMatch(/href="https:\/\/github\.com\/[^"]+\/actions\/workflows\/penthera-vercel\.yml"/);
    expect(status).toContain('<details class="faq copy">');
    expect(status).not.toMatch(/<script/i);
    // Turn off goes back to the wizard once nothing is on.
    await app.setup(post("/setup", `csrf=${csrf}&remove=prj_one`, { cookie, origin: BASE }));
    expect(await (await app.setup(get("/setup", { cookie }))).text()).toContain("<h1>Pick your projects</h1>");
  });

  it("accepts a browser post that says Origin: null when the form token is right", async () => {
    const { app, cookie } = await installed();
    const page = await (await app.setup(get("/setup", { cookie }))).text();
    const csrf = page.match(/name="csrf" value="([^"]+)"/)[1];
    const res = await app.setup(post("/setup", `csrf=${csrf}&action=workflow&p=prj_one`, { cookie, origin: "null" }));
    expect(res.status).not.toBe(403);
    expect((await app.setup(post("/setup", `csrf=wrong&action=workflow&p=prj_one`, { cookie, origin: "null" }))).status).toBe(403);
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
    const closed = await ctx.app.setup(get("/setup", { cookie: cookieJar(res) }));
    expect(closed.status).toBe(401);
    // The same page follows an uninstall, so it never claims Penthera is still installed.
    const body = await closed.text();
    expect(body).toContain("If you uninstalled it");
    expect(body).not.toContain("stays installed");
    expect(body).toContain('href="/start"');
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
    const after = store.dump()[0];
    expect(after.sessionNonce).not.toBe(before.sessionNonce);
    expect(after).toEqual({ ...before, ownerId: "team_New1", sessionNonce: after.sessionNonce });
  });

  it("the weekly sweep deletes records whose token no longer works, and needs the cron secret", async () => {
    const ctx = await installed({ vercel: { fail: { "GET /v10/projects": 401 } } });
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

  it("redact() masks token shapes, env secrets and every id, and keeps error codes", () => {
    const e = { INTEGRATION_CLIENT_SECRET: CLIENT_SECRET };
    expect(redact(`Bearer ${ACCESS_TOKEN}`, e)).not.toContain(ACCESS_TOKEN);
    expect(redact(`secret ${CLIENT_SECRET} here`, e)).not.toContain(CLIENT_SECRET);
    expect(redact(`${CFG} integration_configuration_disabled`, e)).toBe("[id] integration_configuration_disabled");
    expect(redact("project prj_a1 of team_b2 (user_c3) on dpl_d4, oac_e5, chk_f6, crun_g7", e)).toBe("project [id] of [id] ([id]) on [id], [id], [id], [id]");
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

describe("pages", () => {
  it("load the font and the favicon from this server only, and both files ship in public/", async () => {
    expect(CSP).toContain("font-src 'self'");
    expect(CSP).toContain("img-src 'self'");
    expect(CSP).not.toMatch(/https?:\/\/(?!vercel\.com\b)/);
    const { app, cookie } = await installed();
    const page = await (await app.setup(get("/setup", { cookie }))).text();
    const refs = [...page.matchAll(/(?:url\(|href=")(\/[^)"?]+\.(?:woff2|svg))/g)].map((m) => m[1]);
    expect(refs.sort()).toEqual(["/favicon.svg", "/fonts/DepartureMono-Regular.woff2"]);
    for (const ref of refs) expect(existsSync(here(`../public${ref}`))).toBe(true);
    // One font, two places: the copy here must stay the site's own file.
    const font = (p) => readFileSync(here(p));
    expect(font("../public/fonts/DepartureMono-Regular.woff2").equals(font("../../../src/ui/static/fonts/DepartureMono-Regular.woff2"))).toBe(true);
    expect(existsSync(here("../public/fonts/DepartureMono-LICENSE.txt"))).toBe(true);
    // Vercel serves public/ only, so lib/ and the README are not static files on the domain.
    expect(JSON.parse(readFileSync(here("../vercel.json"), "utf8")).outputDirectory).toBe("public");
  });

  it("every page has the wordmark, one title and at most one blue button", async () => {
    const { app, cookie } = await installed();
    const csrf = await csrfOf(await app.setup(get("/setup", { cookie })));
    const pages = [
      await app.home(get("/")),
      await app.setup(get("/setup", { cookie })),
      await app.setup(post("/setup", `csrf=${csrf}&action=workflow&p=prj_one`, { cookie, origin: BASE })),
      await app.configure(get(`/configure?configurationId=${CFG}`)),
      await app.setup(get("/setup")),
      await app.setup(post("/setup", `csrf=wrong&action=workflow&p=prj_one`, { cookie, origin: BASE })),
    ];
    for (const res of pages) {
      const body = await res.text();
      expect(body).toContain('class="mark"');
      expect(body.match(/<h1>/g) ?? []).toHaveLength(body.includes('class="home"') ? 0 : 1);
      expect((body.match(/class="btn go"/g) ?? []).length).toBeLessThanOrEqual(1);
    }
  });

  it("pick, workflow and configure say what Penthera asks for, and why, without a script", async () => {
    const { app, cookie } = await installed();
    const pick = await (await app.setup(get("/setup", { cookie }))).text();
    const csrf = /name="csrf" value="([^"]+)"/.exec(pick)[1];
    const workflow = await (await app.setup(post("/setup", `csrf=${csrf}&action=workflow&p=prj_one`, { cookie, origin: BASE }))).text();
    const configure = await (await app.configure(get(`/configure?configurationId=${CFG}`))).text();
    for (const page of [pick, workflow, configure]) {
      expect(page).toContain("<summary>What Penthera asks for, and why</summary>");
      expect(page).toContain("Deployment Checks, read and write");
      expect(page).toContain('href="https://github.com/danoszz/penthera/tree/main/integrations/vercel"');
      expect(page).not.toMatch(/<script/i);
    }
    expect(pick).toContain('<details class="faq">');
    expect(configure).not.toContain('<details class="faq" open>');
    // Configure without a session: one way to confirm through Vercel, and the workflow behind a closed toggle.
    expect(configure).toContain('<a class="btn go" href="/start">Show my projects</a>');
    expect(configure).toContain('<details class="faq copy"><summary>Copy the workflow again</summary>');
    expect(configure).not.toContain("<details class=\"faq copy\" open>");
  });

  it("draws no thin left line on any page: no border-left, no blockquote bar", () => {
    const style = readFileSync(here("../lib/http.mjs"), "utf8");
    expect(style).not.toMatch(/border-left|border-inline-start|<blockquote/);
  });

  it("every install error says what to do and offers the way out", async () => {
    const { app } = setup();
    for (const url of ["/install", `/install?code=${CODE}`, `/install?code=${CODE}&configurationId=${CFG}&teamId=bad`, `/install?code=${CODE}&configurationId=${CFG}&state=x`]) {
      const body = await (await app.install(get(url))).text();
      expect(body).toContain('<a class="btn go" href="/start">Restart on Vercel</a>');
    }
  });

  it("a page whose only next step is waiting takes the visitor on by itself, without a script", async () => {
    const { app } = setup();
    let res;
    for (let i = 0; i < 12; i++) res = await app.install(get(installUrl(), { "x-real-ip": "198.51.100.7" }));
    const text = await res.text();
    expect(res.status).toBe(429);
    expect(text).toContain('<meta http-equiv="refresh" content="60;url=/start">');
    expect(text).not.toMatch(/<script/i);
  });

  it("an expired session and a failed form check each offer a way out", async () => {
    const { app, cookie } = await installed();
    expect(await (await app.setup(get("/setup"))).text()).toContain('<a class="btn go" href="/start">Restart on Vercel</a>');
    expect(await (await app.setup(post("/setup", "csrf=wrong&action=workflow&p=prj_one", { cookie, origin: BASE }))).text()).toContain('href="/setup"');
  });
});

describe("store", () => {
  it("refuses any field beyond the documented record", async () => {
    const store = memoryStore();
    const keys = parseKeys(`v1:${b64key()}`);
    const record = { configurationId: CFG, ownerId: TEAM, ...sealToken("t", CFG, keys), createdAt: "2026-11-05T00:00:00.000Z", sessionNonce: "n".repeat(32) };
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
  it("is the same file in docs/examples and in this repo's own workflows", () => {
    for (const copy of ["../../../docs/examples/vercel-deployment-check.yml", "../../../.github/workflows/penthera-vercel.yml"]) {
      expect(existsSync(here(copy)), copy).toBe(true);
      expect(readFileSync(here(copy), "utf8"), copy).toBe(WORKFLOW_YAML);
    }
  });

  it("the prefill link carries the same workflow, without its full-line comments, and says where they are", () => {
    expect(parseYaml(PREFILL_YAML)).toEqual(parseYaml(WORKFLOW_YAML));
    // So stripping comments never touches a script: no run block holds a comment line.
    for (const st of parseYaml(WORKFLOW_YAML).jobs.scan.steps) if (st.run) expect(st.run, st.name).not.toMatch(/^\s*#/m);
    expect(PREFILL_YAML.split("\n")[0]).toMatch(/^# Penthera on Vercel\. The file with its comments: https:\/\/github\.com\/danoszz\/penthera\/blob\/main\/integrations\/vercel\/workflow\/penthera-vercel\.yml$/);
    expect(PREFILL_YAML.split("\n").slice(1).filter((l) => /^\s*#/.test(l))).toEqual([]);
  });

  it("pins every action by full SHA, triggers on deployment.ready, and sets no AI input", () => {
    expect(WORKFLOW_YAML).toMatch(/types:\s*\n\s*- "vercel\.deployment\.ready"/);
    for (const [, ref] of WORKFLOW_YAML.matchAll(/uses:\s*\S+@(\S+)/g)) expect(ref).toMatch(/^[0-9a-f]{40}$/);
    expect(WORKFLOW_YAML).not.toMatch(/^\s*ai:/m);
    expect(WORKFLOW_YAML).not.toMatch(/--ai\b/);
  });

  it("names the Vercel check after the status the workflow reports", () => {
    expect(checkName("shop")).toBe("Penthera on Vercel | scan (shop - production)");
    expect(checkBody(CFG, "oac_x")).toMatchObject({ blocks: "deployment-alias", targets: ["production"], isRerequestable: false, source: { kind: "integration", integrationId: "oac_x", integrationConfigurationId: CFG } });
  });

  it("counts our integration check and the old git-provider check as ours, and nobody else's", () => {
    expect(isOurCheck({ source: { kind: "integration", integrationConfigurationId: CFG } }, "shop", CFG)).toBe(true);
    expect(isOurCheck({ source: { kind: "git-provider", provider: "github", externalCheckName: checkName("shop") } }, "shop", CFG)).toBe(true);
    expect(isOurCheck({ source: { kind: "integration", integrationConfigurationId: "icfg_Other" } }, "shop", CFG)).toBe(false);
    expect(isOurCheck({ source: { kind: "integration" } }, "shop", undefined)).toBe(false);
    expect(isOurCheck({ source: { kind: "git-provider", externalCheckName: "Lint" } }, "shop", CFG)).toBe(false);
  });

  it("builds the GitHub link only for plain owner/repo names, and keeps it short enough", () => {
    expect(githubNewFileUrl("acme/shop", "main").length).toBeLessThan(8_000);
    // The longest names GitHub allows: a 39-character owner and a 100-character repo.
    expect(githubNewFileUrl(`${"o".repeat(39)}/${"r".repeat(100)}`, "main").length).toBeLessThan(8_000);
    expect(githubNewFileUrl("acme/shop", "release/v2")).toContain("/new/release/v2?");
    for (const bad of ["acme", "acme/shop/x", "../x/y", "a b/c", ""]) expect(githubNewFileUrl(bad, "main")).toBeNull();
  });

  it("the server has no dependencies at all, so no SDK and no model", () => {
    const pkg = JSON.parse(readFileSync(here("../package.json"), "utf8"));
    expect(pkg.dependencies ?? {}).toEqual({});
    expect(pkg.devDependencies ?? {}).toEqual({});
  });
});

describe("review fixes", () => {
  const signed = (event, secret = CLIENT_SECRET) => {
    const raw = JSON.stringify(event);
    return new Request(`${BASE}/webhook`, { method: "POST", body: raw, headers: { "x-vercel-signature": createHmac("sha1", secret).update(raw).digest("hex") } });
  };
  const victim = async (store, keys) =>
    store.put({ configurationId: CFG, ownerId: TEAM, ...sealToken("at_victim", CFG, keys), createdAt: "2026-11-01T00:00:00.000Z", sessionNonce: "n".repeat(32) });
  const exchangeOnly = (body) => async (u) =>
    String(u).includes("access_token") ? new Response(JSON.stringify(body), { status: 200 }) : new Response("{}", { status: 200 });

  it("refuses an exchange that does not name the configuration, and leaves the record alone", async () => {
    const e = env();
    const keys = parseKeys(e.PENTHERA_TOKEN_KEYS);
    const store = memoryStore();
    await victim(store, keys);
    const app = createApp({ env: e, store, fetch: exchangeOnly({ access_token: "at_attacker", user_id: "user_att" }) });
    const res = await app.install(get(installUrl().replace(`&teamId=${TEAM}`, "")));
    expect(res.status).toBe(400);
    expect(openToken(await store.get(CFG), CFG, keys)).toBe("at_victim");
  });

  it("never hands an existing record to another owner", async () => {
    const e = env();
    const keys = parseKeys(e.PENTHERA_TOKEN_KEYS);
    const store = memoryStore();
    await victim(store, keys);
    const app = createApp({ env: e, store, fetch: exchangeOnly({ access_token: "at_attacker", installation_id: CFG, user_id: "user_att", team_id: null }) });
    const res = await app.install(get(installUrl().replace(`&teamId=${TEAM}`, "")));
    expect(res.status).toBe(409);
    expect(res.headers.getSetCookie().some((c) => c.startsWith("__Host-pv_session="))).toBe(false);
    expect(openToken(await store.get(CFG), CFG, keys)).toBe("at_victim");
  });

  it("refuses an install with neither state nor a Vercel source, also with a leftover state cookie", async () => {
    const { app, vercel } = setup();
    const bare = await app.install(get(`/install?code=${CODE}&configurationId=${CFG}`));
    expect(bare.status).toBe(403);
    const leftover = await app.install(get(`/install?code=${CODE}&configurationId=${CFG}`, { cookie: "__Host-pv_state=expected" }));
    expect(leftover.status).toBe(403);
    expect(await leftover.text()).toContain('data-reason="no_source"');
    expect(vercel.calls).toHaveLength(0);
  });

  it("limits install exchanges per visitor", async () => {
    const { app, vercel } = setup();
    const statuses = [];
    for (let i = 0; i < 12; i++) statuses.push((await app.install(get(installUrl(), { "x-real-ip": "203.0.113.9" }))).status);
    expect(statuses.slice(0, 10).every((s) => s !== 429)).toBe(true);
    expect(statuses.slice(10)).toEqual([429, 429]);
    expect(vercel.calls.filter((c) => c.url.pathname === "/v2/oauth/access_token")).toHaveLength(10);
  });

  it("uninstall deletes the record before any Vercel call, however slow Vercel is", async () => {
    const e = env();
    const keys = parseKeys(e.PENTHERA_TOKEN_KEYS);
    const order = [];
    const inner = memoryStore();
    await victim(inner, keys);
    const store = { ...inner, delete: async (id) => (order.push("delete"), inner.delete(id)) };
    let t = 0;
    const fetch = async () => {
      order.push("fetch");
      t += 9_900;
      return new Response(JSON.stringify({ error: { code: "slow" } }), { status: 500 });
    };
    const app = createApp({ env: e, store, fetch, now: () => t });
    const res = await app.webhook(signed({ type: "integration-configuration.removed", payload: { configuration: { id: CFG, projects: ["prj_a", "prj_b", "prj_c"] } } }));
    expect(res.status).toBe(200);
    expect(order[0]).toBe("delete");
    expect(t).toBeLessThanOrEqual(25_000);
    expect(inner.dump()).toHaveLength(0);
  });

  it("answers 500 when the store fails, so Vercel retries the uninstall", async () => {
    const store = { ...memoryStore(), get: async () => { throw new Error("down"); } };
    const app = createApp({ env: env(), store, fetch: mockVercel().fetch });
    const res = await app.webhook(signed({ type: "integration-configuration.removed", payload: { configuration: { id: CFG } } }));
    expect(res.status).toBe(500);
  });

  it("ignores a replayed uninstall older than the current install", async () => {
    const { app, store } = await installed({ now: () => Date.parse("2026-11-05T12:00:00.000Z") });
    const old = { createdAt: Date.parse("2026-11-04T12:00:00.000Z"), type: "integration-configuration.removed", payload: { configuration: { id: CFG } } };
    expect(await (await app.webhook(signed(old))).json()).toMatchObject({ ignored: "stale" });
    expect(store.dump()).toHaveLength(1);
    const fresh = { ...old, createdAt: Date.parse("2026-11-06T12:00:00.000Z") };
    expect(await (await app.webhook(signed(fresh))).json()).toMatchObject({ deleted: true });
    expect(store.dump()).toHaveLength(0);
  });

  it("the sweep keeps a record on 403, which can be a missed transfer or a disabled install", async () => {
    const ctx = await installed({ vercel: { fail: { "GET /v10/projects": 403 } } });
    const res = await ctx.app.sweep(get("/sweep", { authorization: `Bearer ${ctx.env.CRON_SECRET}` }));
    expect(await res.json()).toMatchObject({ checked: 1, removed: 0 });
    expect(ctx.store.dump()).toHaveLength(1);
  });

  it("a transfer to a personal account re-keys the owner, and later calls carry no teamId", async () => {
    const { app, store, vercel, env: e } = await installed();
    await app.webhook(signed({ type: "integration-configuration.transferred", payload: { configuration: { id: CFG }, previousTeamId: TEAM, newTeamId: null, newAccountId: "user_New1" } }));
    expect(store.dump()[0].ownerId).toBe("user_New1");
    await app.sweep(get("/sweep", { authorization: `Bearer ${e.CRON_SECRET}` }));
    const list = vercel.calls.filter((c) => c.url.pathname === "/v10/projects").at(-1);
    expect(list.url.searchParams.has("teamId")).toBe(false);
  });

  it("refuses a GCM tag shorter than 16 bytes", () => {
    const keys = parseKeys(`v1:${b64key()}`);
    const sealed = sealToken(ACCESS_TOKEN, CFG, keys);
    for (const n of [4, 8, 12]) {
      expect(() => openToken({ ...sealed, tag: Buffer.from(sealed.tag, "base64").subarray(0, n).toString("base64") }, CFG, keys)).toThrow();
    }
  });
});

describe("sessions end when the record changes", () => {
  const signed = (event) => {
    const raw = JSON.stringify(event);
    return new Request(`${BASE}/webhook`, { method: "POST", body: raw, headers: { "x-vercel-signature": createHmac("sha1", CLIENT_SECRET).update(raw).digest("hex") } });
  };

  it("a transfer ends the former owner's setup session on GET and on the remove path", async () => {
    const { app, cookie, vercel } = await installed();
    const csrf = await csrfOf(await app.setup(get("/setup", { cookie })));
    await app.setup(post("/setup", `csrf=${csrf}&action=enable&p=prj_one`, { cookie, origin: BASE }));
    expect(vercel.checks.prj_one).toHaveLength(1);

    await app.webhook(signed({ type: "integration-configuration.transferred", payload: { configuration: { id: CFG }, previousTeamId: TEAM, newTeamId: "team_New1" } }));

    expect((await app.setup(get("/setup", { cookie }))).status).toBe(401);
    expect((await app.setup(post("/setup", `csrf=${csrf}&remove=prj_one`, { cookie, origin: BASE }))).status).toBe(401);
    expect((await app.setup(post("/setup", `csrf=${csrf}&action=enable&p=prj_one`, { cookie, origin: BASE }))).status).toBe(401);
    expect((await app.configure(get(`/configure?configurationId=${CFG}`, { cookie }))).status).toBe(200);
    expect(vercel.checks.prj_one).toHaveLength(1);
  });

  it("a reinstall ends sessions from the earlier install, and the new one works", async () => {
    let t = 1_000_000;
    const ctx = setup({ now: () => t });
    const first = cookieJar(await ctx.app.install(get(installUrl())));
    t += 60_000;
    const second = cookieJar(await ctx.app.install(get(installUrl())));
    expect((await ctx.app.setup(get("/setup", { cookie: first }))).status).toBe(401);
    expect((await ctx.app.setup(get("/setup", { cookie: second }))).status).toBe(200);
  });

  it("a validly signed cookie without the owner binding is refused", async () => {
    const { app, env: e } = await installed();
    const { cookieKey } = await import("../lib/crypto.mjs");
    const old = signValue({ c: CFG, n: null, e: Date.now() + 60_000 }, cookieKey(parseKeys(e.PENTHERA_TOKEN_KEYS)));
    expect((await app.setup(get("/setup", { cookie: `__Host-pv_session=${old}` }))).status).toBe(401);
  });
});

describe("session nonce", () => {
  const signed = (event) => {
    const raw = JSON.stringify(event);
    return new Request(`${BASE}/webhook`, { method: "POST", body: raw, headers: { "x-vercel-signature": createHmac("sha1", CLIENT_SECRET).update(raw).digest("hex") } });
  };
  const transfer = (payload, createdAt) => signed({ type: "integration-configuration.transferred", ...(createdAt ? { createdAt } : {}), payload: { configuration: { id: CFG }, ...payload } });
  const live = async (app, cookie) => (await app.setup(get("/setup", { cookie }))).status;

  it("a transfer that names no new owner still ends older sessions", async () => {
    const { app, cookie, store } = await installed();
    const before = store.dump()[0].sessionNonce;
    await app.webhook(transfer({ previousTeamId: TEAM }));
    expect(store.dump()[0].ownerId).toBe(TEAM);
    expect(store.dump()[0].sessionNonce).not.toBe(before);
    expect(await live(app, cookie)).toBe(401);
  });

  it("a transfer A to B to A does not bring the old session back", async () => {
    const { app, cookie, store } = await installed();
    await app.webhook(transfer({ previousTeamId: TEAM, newTeamId: "team_B1" }));
    await app.webhook(transfer({ previousTeamId: "team_B1", newTeamId: TEAM }));
    expect(store.dump()[0].ownerId).toBe(TEAM);
    expect(await live(app, cookie)).toBe(401);
    const csrf = "unused";
    expect((await app.setup(post("/setup", `csrf=${csrf}&remove=prj_one`, { cookie, origin: BASE }))).status).toBe(401);
  });

  it("two quick transfers each make a new nonce, and a replay of the older one changes nothing", async () => {
    let t = Date.parse("2026-11-05T12:00:00.000Z");
    const ctx = setup({ now: () => t });
    const cookie = cookieJar(await ctx.app.install(get(installUrl())));
    const first = t + 1_000;
    await ctx.app.webhook(transfer({ newTeamId: "team_B1" }, first));
    await ctx.app.webhook(transfer({ newTeamId: "team_C1" }, first + 1));
    const settled = ctx.store.dump()[0];
    expect(settled.ownerId).toBe("team_C1");
    expect(await (await ctx.app.webhook(transfer({ newTeamId: "team_B1" }, first))).json()).toMatchObject({ ignored: "stale" });
    expect(ctx.store.dump()[0]).toEqual(settled);
    expect(await live(ctx.app, cookie)).toBe(401);
  });

  it("an uninstall and reinstall of the same id does not revive an old setup cookie", async () => {
    let t = Date.parse("2026-11-05T12:00:00.000Z");
    const ctx = setup({ now: () => t });
    const old = cookieJar(await ctx.app.install(get(installUrl())));
    await ctx.app.webhook(signed({ type: "integration-configuration.removed", createdAt: t + 1_000, payload: { configuration: { id: CFG } } }));
    expect(ctx.store.dump()).toHaveLength(0);
    t += 60_000;
    const fresh = cookieJar(await ctx.app.install(get(installUrl())));
    expect(ctx.store.dump()).toHaveLength(1);
    expect(await live(ctx.app, old)).toBe(401);
    expect((await ctx.app.setup(post("/setup", "csrf=x&remove=prj_one", { cookie: old, origin: BASE }))).status).toBe(401);
    expect(await live(ctx.app, fresh)).toBe(200);
  });

  it("the store refuses a record without a long random sessionNonce", async () => {
    const keys = parseKeys(`v1:${b64key()}`);
    const base = { configurationId: CFG, ownerId: TEAM, ...sealToken("t", CFG, keys), createdAt: "2026-11-05T00:00:00.000Z" };
    await expect(memoryStore().put(base)).rejects.toThrow(/exactly/);
    await expect(memoryStore().put({ ...base, sessionNonce: "short" })).rejects.toThrow(/sessionNonce/);
    await expect(memoryStore().put({ ...base, sessionNonce: 1 })).rejects.toThrow(/sessionNonce/);
  });
});

describe("records are bound to the id they were looked up by", () => {
  const VICTIM = "icfg_Victim123";
  const signed = (event) => {
    const raw = JSON.stringify(event);
    return new Request(`${BASE}/webhook`, { method: "POST", body: raw, headers: { "x-vercel-signature": createHmac("sha1", CLIENT_SECRET).update(raw).digest("hex") } });
  };

  // A store an attacker with Redis read/write can shape freely: keys and records need not agree.
  function rawStore() {
    const map = new Map();
    return {
      map,
      get: async (id) => (map.has(id) ? { ...map.get(id) } : null),
      put: async (r) => map.set(r.configurationId, { ...r }),
      delete: async (id) => map.delete(id),
      ids: async () => [...map.keys()],
      getLink: async () => null,
      putLink: async () => {},
      deleteLink: async () => {},
      links: async () => [],
    };
  }

  /**
   * The attacker installs normally as CFG and holds a live cookie. Then, in the store, the victim's
   * sealed token goes under CFG: either the victim's whole record with its own configurationId
   * ("moved"), or only its ciphertext inside the attacker's record ("swapped").
   */
  async function transplanted(shape) {
    const store = rawStore();
    const ctx = setup({ store });
    const cookie = cookieJar(await ctx.app.install(get(installUrl())));
    const keys = parseKeys(ctx.env.PENTHERA_TOKEN_KEYS);
    const victimSeal = sealToken(`at_victim_${randomBytes(8).toString("hex")}`, VICTIM, keys);
    const mine = store.map.get(CFG);
    store.map.set(CFG, shape === "moved" ? { ...mine, ...victimSeal, configurationId: VICTIM } : { ...mine, ...victimSeal });
    ctx.vercel.calls.length = 0;
    return { ...ctx, store, cookie };
  }

  for (const shape of ["moved", "swapped"]) {
    it(`setup refuses a ${shape} ciphertext and calls nothing`, async () => {
      const { app, cookie, vercel } = await transplanted(shape);
      expect((await app.setup(get("/setup", { cookie }))).status).toBe(401);
      expect((await app.setup(post("/setup", "csrf=x&remove=prj_one", { cookie, origin: BASE }))).status).toBe(401);
      expect(vercel.calls).toHaveLength(0);
    });

    it(`the uninstall webhook deletes a ${shape} record without calling Vercel`, async () => {
      const { app, store, vercel } = await transplanted(shape);
      const res = await app.webhook(signed({ type: "integration-configuration.removed", payload: { configuration: { id: CFG, projects: ["prj_one"] } } }));
      expect(res.status).toBe(200);
      expect(store.map.has(CFG)).toBe(false);
      expect(vercel.calls).toHaveLength(0);
    });

    it(`the sweep makes no call with a ${shape} record`, async () => {
      const { app, vercel, env: e } = await transplanted(shape);
      const res = await app.sweep(get("/sweep", { authorization: `Bearer ${e.CRON_SECRET}` }));
      expect(res.status).toBe(200);
      expect(vercel.calls).toHaveLength(0);
    });
  }

  it("a transfer leaves a moved record alone", async () => {
    const { app, store } = await transplanted("moved");
    const before = store.map.get(CFG);
    await app.webhook(signed({ type: "integration-configuration.transferred", payload: { configuration: { id: CFG }, newTeamId: "team_B1" } }));
    expect(store.map.get(CFG)).toEqual(before);
  });
});

describe("store fields are not trusted for the replay check", () => {
  const removed = (createdAt) => {
    const raw = JSON.stringify({ type: "integration-configuration.removed", createdAt, payload: { configuration: { id: CFG } } });
    return new Request(`${BASE}/webhook`, { method: "POST", body: raw, headers: { "x-vercel-signature": createHmac("sha1", CLIENT_SECRET).update(raw).digest("hex") } });
  };

  // The clock moves: install at t0, tamper, then a real uninstall a day later, dated by that clock.
  for (const tampered of ["2099-01-01T00:00:00.000Z", "12345"]) {
    it(`a real uninstall deletes a record whose stored createdAt was set to ${tampered}`, async () => {
      let t = Date.parse("2026-11-06T12:00:00.000Z");
      const store = memoryStore();
      const ctx = setup({ store, now: () => t });
      await ctx.app.install(get(installUrl()));
      await store.put({ ...store.dump()[0], createdAt: tampered });
      t += 24 * 60 * 60_000;
      expect(await (await ctx.app.webhook(removed(t))).json()).toMatchObject({ deleted: true });
      expect(store.dump()).toHaveLength(0);
    });
  }

  it("with a moving clock, a replay older than a reinstall is ignored and a real uninstall 1 s later deletes", async () => {
    let t = Date.parse("2026-11-06T12:00:00.000Z");
    const store = memoryStore();
    const ctx = setup({ store, now: () => t });
    await ctx.app.install(get(installUrl()));
    const oldUninstall = t + 5_000;
    t += 60_000;
    await ctx.app.install(get(installUrl()));
    expect(await (await ctx.app.webhook(removed(oldUninstall))).json()).toMatchObject({ ignored: "stale" });
    expect(store.dump()).toHaveLength(1);
    t += 1_000;
    expect(await (await ctx.app.webhook(removed(t))).json()).toMatchObject({ deleted: true });
    expect(store.dump()).toHaveLength(0);
  });

  it("an unreadable createdAt skips the replay check instead of blocking the uninstall", async () => {
    const store = memoryStore();
    const ctx = setup({ store });
    await ctx.app.install(get(installUrl()));
    await store.put({ ...store.dump()[0], createdAt: "not a date" });
    await ctx.app.webhook(removed(Date.now()));
    expect(store.dump()).toHaveLength(0);
  });
});

describe("home page", () => {
  it("serves a static page with the repo and security links, and no script", async () => {
    const { app } = setup();
    const res = await app.home(new Request(`${BASE}/`));
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("Not much to find here.");
    expect(body).toContain("¯\\_(ツ)_/¯");
    expect(body).toContain("https://github.com/danoszz/penthera");
    expect(body).not.toMatch(/<script/i);
    expect(res.headers.get("content-security-policy")).toContain("script-src 'none'");
  });
});
