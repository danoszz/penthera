/**
 * One count everywhere: one fixture app, every surface, the same numbers in
 * the same words. The fixture is tests/fixtures/fix/next, the app the UX audit
 * of 7 Nov walked: a hardcoded secret, wildcard CORS, a cookie with no flags,
 * a login route with no rate limit and no security headers in next.config.mjs.
 *
 * Before this test, the scan, the dashboard and the MCP tool said 2 problems
 * while `fix --plan` found 10 findings and planned 5 fixes: the scan never ran
 * the fix planner's static checks. Now the scan runs them, and every surface
 * counts with src/report/counts.js.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { scanRepo } from "../src/scan-repo.js";
import { buildBrief, formatBrief } from "../src/report/brief.js";
import { problemCounts } from "../src/report/counts.js";
import { buildReportModel } from "../src/report/model.js";
import { TOOLS } from "../src/mcp/tools.js";
import { buildOverview, buildFindings } from "../src/ui/api/summarize.js";
import { runLoop } from "../src/agent/loop.js";

const FIXTURE = resolve("tests/fixtures/fix/next");
const BIN = resolve("bin/penthera.js");
// What the fixture holds, counted by hand: 3 to act on (the secret, the CORS
// wildcard, the cookie), 5 to check first (the login route with no rate limit, a low hint; CSP, X-Frame-Options,
// X-Content-Type-Options and HSTS: read from code, so a host may still add them),
// 1 info (Referrer-Policy). One config change fixes all five headers.
const EXPECTED = { problems: 8, act: 3, check: 5, info: 1, fixes: 5 };

let root;
let app;
const cli = (args) => {
  const home = join(root, "home");
  try {
    return { status: 0, out: execFileSync(process.execPath, [BIN, ...args], { cwd: app, encoding: "utf-8", env: { ...process.env, HOME: home, NO_COLOR: "1", CI: "1" } }) };
  } catch (e) {
    return { status: e.status, out: String(e.stdout) };
  }
};
const git = (...args) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", ...args], { cwd: app, stdio: "pipe" });

beforeAll(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "penthera-one-count-")));
  app = join(root, "app");
  cpSync(FIXTURE, app, { recursive: true });
  git("init", "-q", "-b", "main");
  git("add", "-A");
  git("commit", "-qm", "fixture");
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("one count everywhere (the next fixture)", () => {
  it("the repo scan reads next.config.mjs and finds what the fix planner fixes", async () => {
    const result = await scanRepo(app);
    expect(result.executedProbes).toContain("app-settings");
    const c = problemCounts(result.findings);
    expect(c).toMatchObject({ problems: EXPECTED.problems, act: EXPECTED.act, check: EXPECTED.check, info: EXPECTED.info, noise: 0 });
    // The file the audit saw skipped is read now, so it is not under Not checked.
    const settings = result.coverage.families.find((f) => f.id === "app-settings");
    expect(settings).toMatchObject({ ran: true, skipped: {} });
    expect(settings.examined).toBe(3);
    expect(formatBrief(buildBrief(result))).not.toMatch(/not a route/);
    // One CORS problem, not two: the route scan's finding stands for the file.
    expect(result.findings.filter((f) => /cors/i.test(f.title))).toHaveLength(1);
  });

  it("the CLI brief, the JSON report, the report model and SARIF say 8 problems", () => {
    const sarif = join(root, "out.sarif");
    const report = join(root, "report.json");
    const brief = cli(["--repo", ".", "--brief", "-o", report, "--sarif", sarif]);
    expect(brief.out).toContain("8 problems (3 to act on, 5 to check first)");
    expect(brief.out).toContain("A fix recipe matches 8 of the 8 problems. It shows each diff");
    expect(brief.out).not.toMatch(/may be fixable|also checks cookie flags/);
    const json = JSON.parse(readFileSync(report, "utf-8"));
    expect(json.brief.counts).toMatchObject({ problems: 8, act: 3, check: 5, info: 1 });
    expect(buildReportModel(json).summary.problems).toBe(8);
    expect(JSON.parse(readFileSync(sarif, "utf-8")).runs[0].properties.counts).toMatchObject({ problems: 8, act: 3, check: 5 });
  });

  it("the terminal report says the same", () => {
    const text = cli(["--repo", "."]).out;
    expect(text).toContain("8 problems (3 to act on, 5 to check first)");
    expect(text).toContain("A fix recipe matches 8 of the 8 problems: penthera fix --plan --repo");
  });

  it("the MCP scan_repo brief says 8 problems", async () => {
    const tool = TOOLS.find((t) => t.name === "scan_repo");
    const r = await tool.run({ path: app }, { roots: async () => [root], allowHosts: [], offline: true, version: "test" });
    expect(r.structured.brief.counts.problems).toBe(8);
    expect(r.text).toContain("8 problems (3 to act on, 5 to check first)");
  });

  it("fix --plan plans 5 fixes for the same 8 problems", () => {
    const plan = cli(["fix", "--plan", "--repo", "."]);
    expect(plan.out).toContain("5 fixes planned for 8 problems");
    const json = JSON.parse(cli(["fix", "--plan", "--repo", ".", "--json"]).out);
    expect(json.counts).toEqual({ problems: 8, covered: 8, fixes: EXPECTED.fixes, other: 0, findings: 9 });
  });

  it("the dashboard counts 8 open problems, in its header and in its list", () => {
    const report = JSON.parse(readFileSync(join(root, "report.json"), "utf-8"));
    const scans = [{ name: "report.json", mtime: Date.now(), data: report }];
    const p = buildOverview({ scans }).projects[0];
    expect(p.open).toBe(8);
    expect(p.trend.at(-1).total).toBe(8);
    const rows = buildFindings(scans);
    expect(rows.filter((r) => r.bucket === "act" || r.bucket === "check")).toHaveLength(8);
  });

  it("the fix loop (the dashboard's Fix problems for me) says 8 problems and 5 fixes planned", async () => {
    const lines = [];
    const run = await runLoop({ repo: app, memoryRoot: join(root, "mem"), ask: async () => "n", maxIterations: 1, log: (l) => lines.push(l) });
    expect(run.iterations[0].findings).toMatchObject({ problems: 8, fixable: EXPECTED.fixes });
    expect(lines.join("\n")).toMatch(/scan: 8 problems \(0 suppressed\), 5 fixes planned/);
  });
});

describe("the fix count leaves out noise and what no recipe can change (gaia feedback, 8 Nov)", () => {
  // An agent on a real repo saw "6 may be fixable" stay after it fixed every
  // fixable one: the line counted likely noise, and findings no recipe can
  // change (a secret in a .env file). The scan counts recipe matches without
  // reading the repo; fix --plan counts the fixes it really plans.
  let dir;
  beforeAll(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), "penthera-fixcount-")));
    const files = {
      "package.json": JSON.stringify({ dependencies: { express: "4.0.0" } }),
      // Built at run time, so this file holds no key-shaped string.
      "ext/.env": `STRIPE_SECRET_KEY=${"sk_" + "live_"}${"a1B2c3D4".repeat(3)}\n`,
      // Already fixed.
      "server.js": 'const express = require("express");\nconst app = express();\nres.cookie("session", t, { httpOnly: true, secure: true, sameSite: "lax" });\napp.listen(3000);\n',
      // Likely noise: a fixture.
      "tests/fixtures/app.js": 'res.cookie("sid", v);\n',
    };
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(dirname(join(dir, rel)), { recursive: true });
      writeFileSync(join(dir, rel), text);
    }
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const run = (args) => {
    try {
      return execFileSync(process.execPath, [BIN, ...args], { cwd: dir, encoding: "utf-8", env: { ...process.env, HOME: dir, NO_COLOR: "1", CI: "1" } });
    } catch (e) {
      return String(e.stdout);
    }
  };

  it("the scan counts 4 of the 5 problems as fixable; the .env secret and the fixture are not", () => {
    const out = run(["--repo", ".", "--brief"]);
    expect(out).toContain("5 problems (1 to act on, 4 to check first)");
    expect(out).toContain("A fix recipe matches 4 of the 5 problems. It shows each diff");
    expect(out).not.toMatch(/matches 5 of the 5|may be fixable/);
  });

  it("fix --plan says the same, and names the fix for noise apart", () => {
    const out = run(["fix", "--plan", "--repo", "."]);
    expect(out).toContain("1 fix planned for 4 of 5 problems, and 1 for likely noise or info");
    const json = JSON.parse(run(["fix", "--plan", "--repo", ".", "--json"]));
    expect(json.counts).toMatchObject({ problems: 5, covered: 4, fixes: 1, other: 1 });
  });
});

describe("what an agent reads (gaia feedback, 8 Nov)", () => {
  it("JSON findings keep url and confidence, and add path and exploitability", () => {
    const json = JSON.parse(readFileSync(join(root, "report.json"), "utf-8"));
    const secret = json.findings.find((f) => f.category === "secrets");
    expect(secret).toMatchObject({ path: secret.url, confidence: expect.any(String), exploitability: "not-assessed" });
    expect(secret.url).toMatch(/\.(?:ts|js|mjs)$/);
    // Every repo finding with a file has the alias; the value is always the same as url or file.
    for (const f of json.findings) if (f.path) expect([f.file, f.url]).toContain(f.path);
  });

  it("text says a rule matched, never 'confirmed' as if it were a verdict", () => {
    const out = cli(["--repo", ".", "--brief"]).out;
    expect(out).toMatch(/\[(?:critical|high|medium|low)[^\]]*, (?:pattern matched|likely match|possible match)\]/);
    expect(out).not.toMatch(/, confirmed\]/);
  });

  it("the MCP finding view adds exploitability next to confidence", async () => {
    const tool = TOOLS.find((t) => t.name === "scan_repo");
    const r = await tool.run({ path: app }, { roots: async () => [root], allowHosts: [], offline: true, version: "test" });
    for (const f of r.structured.findings) expect(f.exploitability).toMatch(/^(?:not-assessed|needs-human-review)$/);
  });

  it("the brief says how to set aside a checked problem by fid; only where findings carry a fid", async () => {
    const out = cli(["--repo", ".", "--brief"]).out;
    expect(out).toMatch(/Checked one and it is not a problem\? `(?:npx )?penthera memory suppress <fid> --reason "<why>"`/);
    expect(JSON.parse(readFileSync(join(root, "report.json"), "utf-8")).brief.set_aside.command).toBe('penthera memory suppress <fid> --reason "<why>"');
    expect(out).toContain("penthera.suppress.json");
    const tool = TOOLS.find((t) => t.name === "scan_repo");
    const r = await tool.run({ path: app }, { roots: async () => [root], allowHosts: [], offline: true, version: "test" });
    expect(r.text).not.toContain("memory suppress <fid>");
  });

  it("fix --plan ends with its headline, so tail shows it", () => {
    const lines = cli(["fix", "--plan", "--repo", "."]).out.trimEnd().split("\n");
    expect(lines.slice(-2).join("\n")).toMatch(/5 fixes planned for 8 problems\n\s+Apply one:/);
  });
});

describe("small things from the re-check (9 Nov)", () => {
  it("path is a file, never a route", async () => {
    const { stampProvenance } = await import("../lib/provenance.js");
    const [route, file, addr] = stampProvenance([{ url: "/api/orders", title: "a" }, { url: "src/a.ts", title: "b" }, { url: "https://x.test/", title: "c" }]);
    expect(route.path).toBeUndefined();
    expect(file.path).toBe("src/a.ts");
    expect(addr.path).toBeUndefined();
  });

  it("the dashboard demo prints the fix loop's own scan line", async () => {
    // The parser in runs.js, as it stands there, must read the line the demo prints.
    const runs = readFileSync(resolve("src/ui/api/runs.js"), "utf-8");
    const parser = new RegExp(runs.match(/\/(\^\\s\*scan: [^\n]*?planned)\//)[1]);
    const demo = readFileSync(resolve("src/ui/api/demo.js"), "utf-8");
    const tpl = demo.match(/log\(`( {2}scan: [^`]*)`\)/)[1];
    const line = tpl.replace(/\$\{remaining\}/g, "9").replace(/\$\{fixable\}/g, "3").replace(/\$\{[^}]*\}/g, (m) => (m.includes("es") ? "es" : "s"));
    expect(line).toBe("  scan: 9 problems (1 suppressed), 3 fixes planned");
    expect(parser.test(line)).toBe(true);
  });
});
