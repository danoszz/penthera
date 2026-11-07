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
import { cpSync, mkdtempSync, readFileSync, rmSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
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
// What the fixture holds, counted by hand: 4 to act on (the secret, the CORS
// wildcard, the cookie, the login route), 4 to check first (CSP, X-Frame-Options,
// X-Content-Type-Options and HSTS: read from code, so a host may still add them),
// 1 info (Referrer-Policy). One config change fixes all five headers.
const EXPECTED = { problems: 8, act: 4, check: 4, info: 1, fixes: 5 };

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
    expect(brief.out).toContain("8 problems (4 to act on, 4 to check first)");
    expect(brief.out).toContain("A fix recipe matches 8 of the 8 problems");
    expect(brief.out).not.toMatch(/may be fixable|also checks cookie flags/);
    const json = JSON.parse(readFileSync(report, "utf-8"));
    expect(json.brief.counts).toMatchObject({ problems: 8, act: 4, check: 4, info: 1 });
    expect(buildReportModel(json).summary.problems).toBe(8);
    expect(JSON.parse(readFileSync(sarif, "utf-8")).runs[0].properties.counts).toMatchObject({ problems: 8, act: 4, check: 4 });
  });

  it("the terminal report says the same", () => {
    const text = cli(["--repo", "."]).out;
    expect(text).toContain("8 problems (4 to act on, 4 to check first)");
  });

  it("the MCP scan_repo brief says 8 problems", async () => {
    const tool = TOOLS.find((t) => t.name === "scan_repo");
    const r = await tool.run({ path: app }, { roots: async () => [root], allowHosts: [], offline: true, version: "test" });
    expect(r.structured.brief.counts.problems).toBe(8);
    expect(r.text).toContain("8 problems (4 to act on, 4 to check first)");
  });

  it("fix --plan plans 5 fixes for the same 8 problems", () => {
    const plan = cli(["fix", "--plan", "--repo", "."]);
    expect(plan.out).toContain("5 fixes planned for 8 problems");
    const json = JSON.parse(cli(["fix", "--plan", "--repo", ".", "--json"]).out);
    expect(json.counts).toEqual({ problems: 8, covered: 8, fixes: EXPECTED.fixes, findings: 9 });
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
