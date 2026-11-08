// The whole journey from Penthera's listing page on Vercel, one step at a time, through the real
// server against the strict fake Vercel (test/vercel-allowed.mjs) and a fake GitHub OIDC issuer
// (test/journey-harness.mjs). Each step is asserted on its own, so a failure names the step.
//
// Listing install (source=external, no state) → Pick → Workflow → Turn on → a production
// deployment → the workflow's POST /report, success → a second production deployment → failure
// → a repeated report refused → Configure → uninstall (record, links and our check gone).
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ID_PREFIXES, INFO_EVENTS, logInfo, setLogSink } from "../lib/log.mjs";
import { CHECK_TIMEOUT_SECONDS } from "../lib/workflow.mjs";
import { ALLOWED } from "./vercel-allowed.mjs";
import { ACCESS_TOKEN, BASE, CFG, CLIENT_SECRET, CODE, NEXT, get, harness, jar, listingInstallUrl, post, removedWebhook, reportRequest } from "./journey-harness.mjs";

/** No id of any kind, no repo, run id, install code or token in any log line, error or info. */
function expectNoIds(lines, h, extra = []) {
  const all = lines.map((l) => l.line).join("\n");
  expect(all).not.toMatch(new RegExp(`\\b(${ID_PREFIXES.join("|")})_`));
  for (const secret of [ACCESS_TOKEN, CLIENT_SECRET, CODE, "gaia-web", "daan/", h.env.PENTHERA_TOKEN_KEYS.split(":")[1], ...extra]) {
    expect(all, secret).not.toContain(secret);
  }
}
const csrfOf = (html) => /name="csrf" value="([^"]+)"/.exec(html)[1];
const runOf = (h, deploymentId, checkId) => (h.vercel.runs[deploymentId] ?? []).find((r) => r.checkId === checkId);

describe("the listing journey, step by step, against the strict fake Vercel", () => {
  const h = harness();
  const browser = jar();
  const s = {};
  const lines = [];
  let previousSink;
  beforeAll(() => { previousSink = setLogSink((line, level = "error") => lines.push({ line, level })); });
  afterAll(() => setLogSink(previousSink));

  it("1. Vercel sends the browser back from the listing link with source=external and no state: a session, no refusal", async () => {
    const res = browser.take(await h.app.install(new Request(listingInstallUrl(), { headers: { cookie: browser.header() } })));
    expect(res.status, await res.clone().text()).toBe(303);
    expect(res.headers.get("location")).toBe("/setup");
    expect(browser.has("__Host-pv_session")).toBe(true);
    expect(h.store.dump()).toHaveLength(1);
    expect(h.store.dump()[0]).toMatchObject({ configurationId: CFG, ownerId: "team_JourneyTeam1" });
  });

  it("2. Pick lists the GitHub project and marks the GitLab one", async () => {
    const res = await h.app.setup(get("/setup", browser));
    s.pick = await res.text();
    expect(res.status).toBe(200);
    expect(s.pick).toContain("gaia-web");
    expect(s.pick).toContain("Needs a GitHub-connected project");
  });

  it("3. Workflow shows the file, prefilled for the repo", async () => {
    const res = await h.app.setup(post("/setup", `csrf=${csrfOf(s.pick)}&action=workflow&p=prj_gaiaweb`, browser, "null"));
    s.wf = await res.text();
    expect(res.status).toBe(200);
    expect(s.wf).toContain("github.com/daan/gaia-web/new/main");
    expect(s.wf).toContain("Turn on the check");
    // The check holds a deploy only while automatic production aliasing is on (Vercel, Deployment Checks).
    expect(s.wf).toContain('data-reason="auto_alias"');
  });

  it("4. Turn on adds one integration check that blocks the production alias, and returns to Vercel", async () => {
    const res = browser.take(await h.app.setup(post("/setup", `csrf=${csrfOf(s.wf)}&action=enable&p=prj_gaiaweb`, browser, "null")));
    expect(res.status, await res.clone().text()).toBe(303);
    expect(res.headers.get("location")).toBe(NEXT);
    expect(h.vercel.checks.prj_gaiaweb).toHaveLength(1);
    s.check = h.vercel.checks.prj_gaiaweb[0];
    expect(s.check).toMatchObject({
      name: "Penthera", requires: "deployment-url", blocks: "deployment-alias", targets: ["production"], isRerequestable: false, timeout: CHECK_TIMEOUT_SECONDS,
      source: { kind: "integration", integrationId: "oac_PentheraIntegration", integrationConfigurationId: CFG },
    });
    expect(h.store.dumpLinks()).toEqual([{ projectId: "prj_gaiaweb", configurationId: CFG }]);
  });

  it("5. A production deployment is created: Vercel queues a run of our check on it", async () => {
    h.world.deployments.dpl_prod2 = { projectId: "prj_gaiaweb", target: "production", url: "gaia-web-def.vercel.app" };
    const list = await h.vercel.fetch(new URL("https://api.vercel.com/v2/deployments/dpl_prod2/check-runs?teamId=team_JourneyTeam1"), { headers: { Authorization: `Bearer ${h.vercel.token}` } });
    expect(list.status).toBe(200);
    expect(runOf(h, "dpl_prod2", s.check.id)).toMatchObject({ status: "queued" });
  });

  it("6. The workflow reports a pass with its OIDC token: the run completes as succeeded, linked to the GitHub run", async () => {
    const res = await h.app.report(reportRequest("dpl_prod2", "succeeded", { runId: "700", host: h.world.deployments.dpl_prod2.url }));
    expect(res.status, await res.clone().text()).toBe(200);
    expect(await res.json()).toEqual({ ok: true, conclusion: "succeeded" });
    expect(runOf(h, "dpl_prod2", s.check.id)).toMatchObject({ status: "completed", conclusion: "succeeded", externalUrl: "https://github.com/daan/gaia-web/actions/runs/700" });
    expect(runOf(h, "dpl_prod2", s.check.id).conclusionText).toMatch(/no high or critical issue/);
  });

  it("7. A second production deployment fails the scan: its run completes as failed", async () => {
    h.world.deployments.dpl_prod3 = { projectId: "prj_gaiaweb", target: "production", url: "gaia-web-ghi.vercel.app" };
    const res = await h.app.report(reportRequest("dpl_prod3", "failed", { runId: "701", host: h.world.deployments.dpl_prod3.url }));
    expect(res.status, await res.clone().text()).toBe(200);
    expect(runOf(h, "dpl_prod3", s.check.id)).toMatchObject({ status: "completed", conclusion: "failed", externalUrl: "https://github.com/daan/gaia-web/actions/runs/701" });
    // The first deployment's result is untouched.
    expect(runOf(h, "dpl_prod2", s.check.id).conclusion).toBe("succeeded");
  });

  it("8. A result is set once: reporting the failed deployment again changes nothing", async () => {
    const res = await h.app.report(reportRequest("dpl_prod3", "succeeded", { runId: "702", host: h.world.deployments.dpl_prod3.url }));
    expect(res.status).toBe(409);
    expect(runOf(h, "dpl_prod3", s.check.id).conclusion).toBe("failed");
  });

  it("9. Configure, from Vercel's button, shows the installation", async () => {
    const res = await h.app.configure(new Request(`${BASE}/configure?configurationId=${CFG}`));
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("penthera-vercel.yml");
  });

  it("10. Uninstall: the record, the links and our check are gone, and the session ends", async () => {
    const res = await h.app.webhook(removedWebhook());
    expect(res.status).toBe(200);
    expect(h.store.dump()).toEqual([]);
    expect(h.store.dumpLinks()).toEqual([]);
    expect(h.vercel.checks.prj_gaiaweb).toEqual([]);
    expect((await h.app.setup(get("/setup", browser))).status).toBe(401);
  });

  it("11. Every request fit Vercel's spec and the table of what Vercel accepts, and nothing left the machine", () => {
    expect(h.vercel.violations).toEqual([]);
    expect(h.outside).toEqual([]);
  });

  it("12. The logs name each good event, and no id, repo, code or token reaches any line, error or info", () => {
    // Only good events on this journey: the refused repeat (step 8) is an answer, not an error.
    expect(lines.filter((l) => l.level !== "info")).toEqual([]);
    expect(lines.map((l) => JSON.parse(l.line))).toEqual([
      { level: "info", event: "install_ok", source: "external" },
      { level: "info", event: "check_on", projects: 1 },
      { level: "info", event: "report_ok", conclusion: "succeeded" },
      { level: "info", event: "report_ok", conclusion: "failed" },
      { level: "info", event: "uninstall_ok" },
    ]);
    expectNoIds(lines, h, ["9001", "700", "701"]);
  });
});

describe("error log lines carry no id either, also when Vercel's message is full of them", () => {
  // Vercel's answers here name every kind of id, the way a real error message might.
  const IDS = "prj_gaiaweb of team_JourneyTeam1 for icfg_JourneyConfig1 by user_daan on dpl_prod1 (oac_PentheraIntegration, chk_1, crun_1)";
  const lines = [];
  let previousSink;
  beforeAll(() => { previousSink = setLogSink((line, level = "error") => lines.push({ line, level })); });
  afterAll(() => setLogSink(previousSink));

  it("a refused install, a spent code, a failed lookup, a refused check and a failed report all log without ids", async () => {
    const h = harness();
    const strict = h.vercel.fetch;
    h.vercel.fetch = async (input, init = {}) => {
      const url = new URL(String(input));
      const method = init.method ?? "GET";
      const fail = (status, code) => new Response(JSON.stringify({ error: { code, message: `Cannot do this: ${IDS}` } }), { status, headers: { "content-type": "application/json" } });
      if (url.pathname.startsWith("/v1/integrations/configuration/")) return fail(403, "forbidden");
      if (method === "POST" && url.pathname.endsWith("/checks")) return fail(400, "bad_request");
      if (url.pathname.endsWith("/check-runs")) return fail(500, "internal_server_error");
      return strict(input, init);
    };

    // A state that doesn't match this browser: refused before the exchange.
    await h.app.install(new Request(`${listingInstallUrl()}&state=abc`, { headers: { cookie: "__Host-pv_state=xyz" } }));
    // A code Vercel won't exchange.
    await h.app.install(new Request(listingInstallUrl().replace(CODE, "a1b2c3d4e5f6a7b8")));
    // A real install, then a Turn on that Vercel refuses with a message full of ids.
    const browser = jar();
    browser.take(await h.app.install(new Request(listingInstallUrl(), { headers: { cookie: browser.header() } })));
    const pick = await (await h.app.setup(get("/setup", browser))).text();
    const wf = await (await h.app.setup(post("/setup", `csrf=${csrfOf(pick)}&action=workflow&p=prj_gaiaweb`, browser, "null"))).text();
    const on = await h.app.setup(post("/setup", `csrf=${csrfOf(wf)}&action=enable&p=prj_gaiaweb`, browser, "null"));
    expect(on.status).toBe(502);
    // A report while Vercel is failing. The check is not on, so turn it on behind the server's back.
    h.vercel.checks.prj_gaiaweb = [{ id: "chk_9", name: "Penthera", source: { kind: "integration", integrationId: "oac_PentheraIntegration", integrationConfigurationId: CFG } }];
    await h.store.putLink({ projectId: "prj_gaiaweb", configurationId: CFG });
    expect((await h.app.report(reportRequest("dpl_prod1", "succeeded", { host: h.world.deployments.dpl_prod1.url }))).status).toBe(502);

    const events = lines.filter((l) => l.level === "error").map((l) => JSON.parse(l.line).event);
    for (const e of ["install_refused", "exchange_failed", "integration_lookup_failed", "check_failed", "report_failed"]) expect(events).toContain(e);
    // Vercel's text is kept, its ids are not.
    const failed = lines.map((l) => JSON.parse(l.line)).find((l) => l.event === "check_failed");
    expect(failed).toMatchObject({ status: 400, code: "bad_request", message: "Cannot do this: [id] of [id] for [id] by [id] on [id] ([id], [id], [id])" });
    for (const l of lines) expect(Object.keys(JSON.parse(l.line)).every((k) => ["level", "event", "status", "code", "message", "route", "count", "source", "projects", "conclusion"].includes(k)), l.line).toBe(true);
    expectNoIds(lines, h);
  });
});

describe("the strict fake answers as live Vercel did", () => {
  const send = async (h, path, body, method = "POST") =>
    h.vercel.fetch(new URL(`https://api.vercel.com${path}?teamId=team_JourneyTeam1`), {
      method, headers: { Authorization: `Bearer ${h.vercel.token}`, "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
  const good = { name: "Penthera", requires: "deployment-url", blocks: "deployment-alias", targets: ["production"], isRerequestable: false, timeout: 1200, source: { kind: "integration", integrationId: "oac_PentheraIntegration", integrationConfigurationId: CFG } };

  it("blocks: deployment-promotion gets the 400 not_implemented Daan's Turn on got, word for word", async () => {
    const h = harness();
    const res = await send(h, "/v2/projects/prj_gaiaweb/checks", { ...good, blocks: "deployment-promotion" });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: { code: "not_implemented", message: "Only deployment-alias and none are currently supported for blocks" } });
    expect(h.vercel.checks.prj_gaiaweb ?? []).toEqual([]);
  });

  it("a git-provider source from an integration gets 400 not_implemented", async () => {
    const h = harness();
    const res = await send(h, "/v2/projects/prj_gaiaweb/checks", { ...good, source: { kind: "git-provider", provider: "github", externalCheckName: "Penthera" } });
    expect(res.status).toBe(400);
    expect((await res.json()).error.code).toBe("not_implemented");
  });

  it("a field that is not in the table, or a value outside it, gets a 400 and is recorded", async () => {
    for (const [path, body, method] of [
      ["/v2/projects/prj_gaiaweb/checks", { ...good, rerequestable: true }],
      ["/v2/projects/prj_gaiaweb/checks", { ...good, targets: ["all", "production"] }],
      ["/v2/projects/prj_gaiaweb/checks", { ...good, timeout: 0 }],
      ["/v2/projects/prj_gaiaweb/checks", { ...good, requires: "build-ready", name: "" }],
      ["/v2/deployments/dpl_prod1/check-runs/crun_1", { status: "completed", conclusion: "passed" }, "PATCH"],
      ["/v2/deployments/dpl_prod1/check-runs/crun_1", { status: "completed", conclusionText: "" }, "PATCH"],
      ["/v2/deployments/dpl_prod1/check-runs/crun_1", { externalUrl: "ftp://example.test/run" }, "PATCH"],
    ]) {
      const h = harness();
      const res = await send(h, path, body, method);
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect((await res.json()).error.code).toMatch(/^(bad_request|not_implemented)$/);
      expect(h.vercel.violations.length, JSON.stringify(body)).toBeGreaterThan(0);
    }
  });

  it("the server's Turn on, sending main's old blocks value, shows the failure page with Vercel's code", async () => {
    const h = harness();
    // Rewrite the server's outgoing check body to what main sent before 7 Nov.
    const strict = h.vercel.fetch;
    h.vercel.fetch = async (input, init = {}) => {
      if ((init.method ?? "GET") === "POST" && String(input).includes("/checks?")) init = { ...init, body: JSON.stringify({ ...JSON.parse(init.body), blocks: "deployment-promotion" }) };
      return strict(input, init);
    };
    const browser = jar();
    browser.take(await h.app.install(new Request(listingInstallUrl(), { headers: { cookie: browser.header() } })));
    const pick = await (await h.app.setup(get("/setup", browser))).text();
    const wf = await (await h.app.setup(post("/setup", `csrf=${csrfOf(pick)}&action=workflow&p=prj_gaiaweb`, browser, "null"))).text();
    const res = await h.app.setup(post("/setup", `csrf=${csrfOf(wf)}&action=enable&p=prj_gaiaweb`, browser, "null"));
    const text = await res.text();
    // The done page answers 502 when a project failed: the check is not on.
    expect(res.status).toBe(502);
    expect(text).toContain('data-reason="rejected"');
    expect(text).toContain("Vercel 400 not_implemented: Only deployment-alias and none are currently supported for blocks");
    expect(h.vercel.checks.prj_gaiaweb ?? []).toEqual([]);
  });
});

describe("the README lists every row of the table of what Vercel accepts", () => {
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  for (const row of ALLOWED) {
    it(`${row.op} ${row.in} ${row.field}`, () => {
      const line = readme.split("\n").find((l) => l.startsWith(`| \`${row.op}\` | ${row.in} | \`${row.field}\` |`));
      expect(line, "README, What Vercel accepts").toBeTruthy();
      expect(line).toContain(row.live);
    });
  }
});

describe("logInfo keeps the counters' privacy", () => {
  const capture = (fn) => {
    const out = [];
    const previous = setLogSink((line, level) => out.push({ line, level }));
    try { fn(); } finally { setLogSink(previous); }
    return out;
  };

  it("drops every field that is not allowed for the event, and every value outside its list", () => {
    const out = capture(() => {
      logInfo("install_ok", { source: "external", configurationId: CFG, teamId: "team_x" });
      logInfo("install_ok", { source: "icfg_JourneyConfig1" });
      logInfo("check_on", { projects: 2, projectId: "prj_gaiaweb", name: "gaia-web" });
      logInfo("check_on", { projects: "prj_gaiaweb" });
      logInfo("check_on", { projects: 5000 });
      logInfo("report_ok", { conclusion: "succeeded", deploymentId: "dpl_1", repo: "daan/gaia-web" });
      logInfo("report_ok", { conclusion: "dpl_1" });
      logInfo("uninstall_ok", { configurationId: CFG });
    });
    expect(out.every((l) => l.level === "info")).toBe(true);
    expect(out.map((l) => JSON.parse(l.line))).toEqual([
      { level: "info", event: "install_ok", source: "external" },
      { level: "info", event: "install_ok" },
      { level: "info", event: "check_on", projects: 2 },
      { level: "info", event: "check_on" },
      { level: "info", event: "check_on" },
      { level: "info", event: "report_ok", conclusion: "succeeded" },
      { level: "info", event: "report_ok" },
      { level: "info", event: "uninstall_ok" },
    ]);
  });

  it("logs nothing for an event outside the fixed list, also one named like an id", () => {
    expect(capture(() => { logInfo("icfg_JourneyConfig1"); logInfo("toString"); logInfo("__proto__"); })).toEqual([]);
  });

  it("no allowed field can carry free text: every rule is a fixed list or a count", () => {
    for (const fields of Object.values(INFO_EVENTS)) {
      for (const rule of Object.values(fields)) {
        expect(rule === "count" || (Array.isArray(rule) && rule.every((v) => /^[a-z-]+$/.test(v)))).toBe(true);
      }
    }
  });
});
