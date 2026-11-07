/**
 * Vercel's Protection Bypass for Automation: the secret goes to the target's own origin only,
 * only for an https *.vercel.app target, never into a report, and never on the command line.
 *
 * Offline: global fetch is an in-memory fake, DNS and TLS are mocked.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// The repo's vendored YAML parser: no package to install.
import YAML from "../lib/vendor/yaml/index.js";

vi.mock("node:dns/promises", () => {
  const fail = async () => { throw Object.assign(new Error("dns disabled in tests"), { code: "ENOTFOUND" }); };
  return { resolveTxt: fail, resolveMx: fail, default: { resolveTxt: fail, resolveMx: fail } };
});
vi.mock("node:tls", () => {
  const connect = () => { throw new Error("tls disabled in tests"); };
  return { default: { connect }, connect };
});

const { scanUrl, scrubSecret, vercelBypass, VERCEL_BYPASS_HEADER } = await import("../src/scan-url.js");
const { request, createEgressContext, runWithEgress, egressSummary } = await import("../src/utils/http.js");
const { formatMarkdownReport } = await import("../src/report/markdown.js");

// A secret a person might choose: not shaped like a token, so only its value can find it.
const SECRET = "my.Bypass_Phrase-42~ok";
const SAFE_SECRET = "Vx7kQ2mN9pR4sT6uW8yZ1aB3cD5eF7gH";
const TARGET = "https://shop-abc123.vercel.app";

/** The deployment: 401 without the right header, 200 with it. Its home page echoes the header back. */
function fakeVercel(secret) {
  const calls = [];
  const fn = vi.fn(async (input, init = {}) => {
    const url = new URL(String(input));
    const headers = new Headers(init.headers);
    calls.push({ url: url.toString(), host: url.hostname, bypass: headers.get(VERCEL_BYPASS_HEADER) });
    if (url.hostname !== "shop-abc123.vercel.app") return new Response("unavailable", { status: 503 });
    if (headers.get(VERCEL_BYPASS_HEADER) !== secret) return new Response("<html><body>Authentication Required</body></html>", { status: 401, headers: { "content-type": "text/html" } });
    if (url.pathname === "/") {
      return new Response(`<!doctype html><html><head><title>shop</title></head><body>debug: ${headers.get(VERCEL_BYPASS_HEADER)}</body></html>`, { status: 200, headers: { "content-type": "text/html" } });
    }
    // Every other path fails with an error that repeats the request's header, the way a
    // client library might. Probe errors land in the report, so the secret would too.
    throw new TypeError(`fetch failed: connection reset after sending ${VERCEL_BYPASS_HEADER}: ${headers.get(VERCEL_BYPASS_HEADER)}`);
  });
  return { fn, calls };
}

const opts = (extra = {}) => ({ timeout: 2_000, concurrency: 5, profile: "quick", skipRetireJs: true, skipParamDiscovery: true, offline: true, ...extra });

let saved;
beforeEach(() => { saved = process.env.PENTHERA_VERCEL_BYPASS; delete process.env.PENTHERA_VERCEL_BYPASS; });
afterEach(() => {
  vi.unstubAllGlobals();
  if (saved === undefined) delete process.env.PENTHERA_VERCEL_BYPASS;
  else process.env.PENTHERA_VERCEL_BYPASS = saved;
});

describe("target-only headers in the egress context", () => {
  it("are sent to the target origin, dropped on a hop to another origin, and sent again on the way back", async () => {
    const seen = [];
    vi.stubGlobal("fetch", vi.fn(async (input, init = {}) => {
      const url = new URL(String(input));
      seen.push([url.origin, new Headers(init.headers).get("x-secret")]);
      if (url.origin === "https://a.vercel.app" && url.pathname === "/") return new Response(null, { status: 302, headers: { location: "https://b.vercel.app/x" } });
      if (url.origin === "https://b.vercel.app") return new Response(null, { status: 302, headers: { location: "https://a.vercel.app/back" } });
      return new Response("ok", { status: 200 });
    }));
    const ctx = createEgressContext({ target: "https://a.vercel.app", targetHeaders: { "x-secret": "s3cret-value" } });
    await runWithEgress(ctx, () => request("https://a.vercel.app/", { redirect: "follow" }));
    expect(seen).toEqual([["https://a.vercel.app", "s3cret-value"], ["https://b.vercel.app", null], ["https://a.vercel.app", "s3cret-value"]]);
  });

  it("are never sent to another host, another port or plain http on the same host", async () => {
    const seen = [];
    vi.stubGlobal("fetch", vi.fn(async (input, init = {}) => { seen.push([String(input), new Headers(init.headers).get("x-secret")]); return new Response("ok"); }));
    const ctx = createEgressContext({ target: "https://a.vercel.app", targetHeaders: { "x-secret": "s3cret-value" } });
    await runWithEgress(ctx, async () => {
      for (const u of ["https://raw.githubusercontent.com/x", "https://a.vercel.app:8443/", "http://a.vercel.app/", "https://www.a.vercel.app/"]) await request(u).catch(() => {});
    });
    expect(seen.every(([, v]) => v === null)).toBe(true);
  });

  it("the summary names the header, never its value", () => {
    const ctx = createEgressContext({ target: "https://a.vercel.app", targetHeaders: { "X-Secret": "s3cret-value" } });
    const summary = JSON.stringify(egressSummary(ctx));
    expect(summary).toContain('"targetHeaders":["x-secret"]');
    expect(summary).not.toContain("s3cret-value");
  });
});

describe("vercelBypass()", () => {
  it("comes from PENTHERA_VERCEL_BYPASS and is sent only to an https *.vercel.app target", () => {
    const env = { PENTHERA_VERCEL_BYPASS: SAFE_SECRET };
    expect(vercelBypass(TARGET, {}, env)).toMatchObject({ header: SAFE_SECRET, note: "sent to target only" });
    for (const t of ["http://shop-abc123.vercel.app", "https://shop.example.com", "https://vercel.app", "https://shop.vercel.app.evil.test", "https://127.0.0.1:3000"]) {
      expect(vercelBypass(t, {}, env), t).toMatchObject({ header: "", note: expect.stringMatching(/^not sent/) });
    }
    expect(vercelBypass(TARGET, {}, {})).toEqual({ secret: "", header: "", note: null });
    // The longest value it takes, the same as the workflow's bash check (macOS bash caps {n,m} at 255).
    expect(vercelBypass(TARGET, {}, { PENTHERA_VERCEL_BYPASS: "x".repeat(128) }).header).toBe("x".repeat(128));
  });

  it("refuses a value that could break a header, before anything is scanned", () => {
    // Also every character a page could echo back in another form (&, %, quotes, <, space).
    for (const bad of ["short-value", " leading-space-value", "has space inside it", "line\nbreak-header-x", "cr\rbreak-header-xx", "tab\there-value-xx", "é-not-ascii-value-x", "amp&ersand-value-x", "per%25cent-value-xx", "quote\"value-xxxxxx", "angle<value-xxxxxx", "x".repeat(129)]) {
      expect(() => vercelBypass(TARGET, {}, { PENTHERA_VERCEL_BYPASS: bad }), JSON.stringify(bad)).toThrow(/PENTHERA_VERCEL_BYPASS/);
    }
  });
});

describe("scrubSecret()", () => {
  it("replaces the secret by its value in strings, keys, arrays and nested objects, and leaves the rest", () => {
    const at = new Date(0);
    const value = { a: `x ${SECRET} y`, [SECRET]: 1, list: [SECRET, { deep: `${SECRET}${SECRET}` }], n: 3, ok: true, none: null, at };
    const out = scrubSecret(value, SECRET);
    expect(out).toEqual({ a: "x [redacted] y", "[redacted]": 1, list: ["[redacted]", { deep: "[redacted][redacted]" }], n: 3, ok: true, none: null, at });
    expect(out.at).toBe(at);
    expect(value.a).toContain(SECRET);
    expect(scrubSecret(value, "")).toBe(value);
  });
});

describe("a scan of a protected deployment", () => {
  it("without the secret, the site answers 401 and the report says so", async () => {
    const net = fakeVercel(SAFE_SECRET);
    vi.stubGlobal("fetch", net.fn);
    const result = await scanUrl(TARGET, opts());
    expect(result.httpStatus).toBe(401);
    expect(net.calls.every((c) => c.bypass === null)).toBe(true);
    expect(result.egress.targetHeaders).toBeUndefined();
  });

  it("with the secret, every request to the deployment carries it, nothing else does, and no report holds it", async () => {
    process.env.PENTHERA_VERCEL_BYPASS = SAFE_SECRET;
    const net = fakeVercel(SAFE_SECRET);
    vi.stubGlobal("fetch", net.fn);
    const result = await scanUrl(TARGET, opts({ offline: false }));
    expect(result.httpStatus).toBe(200);
    const own = net.calls.filter((c) => c.host === "shop-abc123.vercel.app");
    expect(own.length).toBeGreaterThan(1);
    expect(own.every((c) => c.bypass === SAFE_SECRET)).toBe(true);
    expect(net.calls.filter((c) => c.host !== "shop-abc123.vercel.app").every((c) => c.bypass === null)).toBe(true);
    expect(result.egress).toMatchObject({ targetHeaders: [VERCEL_BYPASS_HEADER], vercelBypass: "sent to target only" });
    // The deployment's errors repeated the secret; the report keeps them, with the secret replaced.
    const json = JSON.stringify(result);
    expect(json).toContain("[redacted]");
    expect(json).not.toContain(SAFE_SECRET);
    expect(formatMarkdownReport(result)).not.toContain(SAFE_SECRET);
  });

  it("a secret a person chose, with punctuation and in no token shape, is sent and removed by its value (bypass checklist row 8)", async () => {
    const chosen = SECRET;
    expect(vercelBypass(TARGET, {}, { PENTHERA_VERCEL_BYPASS: chosen }).header).toBe(chosen);
    process.env.PENTHERA_VERCEL_BYPASS = chosen;
    const net = fakeVercel(chosen);
    vi.stubGlobal("fetch", net.fn);
    const result = await scanUrl(TARGET, opts());
    expect(result.httpStatus).toBe(200);
    expect(JSON.stringify(result)).not.toContain(chosen);
    expect(formatMarkdownReport(result)).not.toContain(chosen);
  });

  it("an MCP scan never sends it, even to a vercel.app deployment", async () => {
    process.env.PENTHERA_VERCEL_BYPASS = SAFE_SECRET;
    const net = fakeVercel(SAFE_SECRET);
    vi.stubGlobal("fetch", net.fn);
    const result = await scanUrl(TARGET, opts({ scoped: true }));
    expect(net.calls.every((c) => c.bypass === null)).toBe(true);
    expect(result.egress.vercelBypass).toBe("not sent: MCP scan");
    expect(JSON.stringify(result)).not.toContain(SAFE_SECRET);
  });

  it("for a target that is not a vercel.app deployment, the secret is not sent and the report says so by name", async () => {
    process.env.PENTHERA_VERCEL_BYPASS = SAFE_SECRET;
    const seen = [];
    vi.stubGlobal("fetch", vi.fn(async (input, init = {}) => { seen.push(new Headers(init.headers).get(VERCEL_BYPASS_HEADER)); return new Response("<html></html>", { status: 200, headers: { "content-type": "text/html" } }); }));
    const result = await scanUrl("https://shop.example.com", opts());
    expect(seen.every((v) => v === null)).toBe(true);
    expect(result.egress.vercelBypass).toMatch(/^not sent/);
    expect(JSON.stringify(result)).not.toContain(SAFE_SECRET);
  });
});

describe("the Action's vercel-bypass-secret input", () => {
  const action = YAML.parse(readFileSync(new URL("../action.yml", import.meta.url), "utf-8"));
  const run = action.runs.steps.find((s) => s.id === "run").run;

  function runStep(mode, secret) {
    const tmp = mkdtempSync(join(tmpdir(), "penthera-action-bypass-"));
    try {
      const fake = join(tmp, "penthera");
      mkdirSync(join(fake, "bin"), { recursive: true });
      writeFileSync(join(fake, "package.json"), JSON.stringify({ version: "0.0.0-test" }));
      // The stand-in CLI writes what it was given: its argv, and whether the env holds the secret.
      writeFileSync(join(fake, "bin", "penthera.js"), `const fs = require("node:fs"); const a = process.argv; fs.writeFileSync(a[a.indexOf("-o") + 1], JSON.stringify({ argv: a.slice(2), env: process.env.PENTHERA_VERCEL_BYPASS ?? null, input: process.env.INPUT_VERCEL_BYPASS ?? null })); if (a.includes("--pr-comment")) fs.writeFileSync(a[a.indexOf("--pr-comment") + 1], "x"); process.exit(0);\n`);
      const runner = join(tmp, "runner");
      mkdirSync(runner);
      const output = join(runner, "output");
      writeFileSync(output, "");
      const r = spawnSync("bash", ["-c", run], {
        cwd: tmp, encoding: "utf-8",
        env: { PATH: process.env.PATH, PENTHERA_DIR: fake, INPUT_MODE: mode, INPUT_PATH: ".", INPUT_URL: TARGET, INPUT_BASE_REF: "", PR_BASE_SHA: "", INPUT_VERSION: "", INPUT_FOOTER: "true", INPUT_VERCEL_BYPASS: secret, RUNNER_TEMP: runner, GITHUB_OUTPUT: output },
      });
      const report = JSON.parse(readFileSync(join(runner, "penthera", "penthera.json"), "utf-8"));
      return { ...r, report };
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }

  it("is declared with an empty default and a description that says where it goes", () => {
    expect(action.inputs["vercel-bypass-secret"]).toMatchObject({ required: false, default: "" });
    expect(action.inputs["vercel-bypass-secret"].description).toMatch(/x-vercel-protection-bypass/);
  });

  it("is masked first, reaches the CLI only as PENTHERA_VERCEL_BYPASS in scan mode, and never as an argument", () => {
    const scan = runStep("scan", SAFE_SECRET);
    expect(scan.status, scan.stderr).toBe(0);
    expect(scan.stdout.split("\n")[0]).toBe(`::add-mask::${SAFE_SECRET}`);
    expect(scan.report.env).toBe(SAFE_SECRET);
    expect(scan.report.input).toBeNull();
    expect(scan.report.argv.join(" ")).not.toContain(SAFE_SECRET);
    const deps = runStep("deps", SAFE_SECRET);
    expect(deps.status, deps.stderr).toBe(0);
    expect(deps.report.env).toBeNull();
    const none = runStep("scan", "");
    expect(none.stdout).not.toContain("::add-mask::");
    expect(none.report.env).toBeNull();
  });
});
