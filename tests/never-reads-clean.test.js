/**
 * The last of its kind. Every surface renders every way a run can read nothing, and none may use
 * a success sentence. A new surface or sentence belongs in these lists.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { buildComplianceCoverage } from "../lib/compliance/index.js";
import { countLine, gradeArea, runCheck, summaryJson, summaryMarkdown } from "../src/cli/onboarding.js";
import { formatAudienceReport } from "../src/report/audience.js";
import { buildBrief, formatBrief, VERDICTS } from "../src/report/brief.js";
import { formatMarkdownReport } from "../src/report/markdown.js";
import { notRead, nothingClaim, readNothing } from "../src/report/unread.js";
import { printReport } from "../src/reporter.js";
import { verdict } from "../src/ui/static/js/copy.js";
import { checkResult } from "../src/ui/static/js/format.js";
import { buildOverview, withAudits } from "../src/ui/api/summarize.js";
import { scanAgents } from "../lib/agents/index.js";

const SUCCESS = /no issues|looking good|all clear|clean scan|no problems|no findings|nothing to fix|nothing open|no gaps/i;
const NOTE = { severity: "info", title: "Cloudflare served a bot challenge instead of the site", category: "scan" };
const base = { target: "http://127.0.0.1:5173", timestamp: "2026-11-01T10:00:00Z" };
const CASES = {
  "a firewall's page": { ...base, mode: "url", reachable: true, challenge: { provider: "Cloudflare", action: "challenge" }, findings: [NOTE] },
  "a dead address beside a folder": { ...base, target: `${base.target} + /app`, modes: ["url", "repo"], reachable: false, findings: [] },
  "a server error beside a folder": { ...base, target: `${base.target} + /app`, modes: ["url", "repo"], reachable: false, httpStatus: 503, findings: [] },
  "a deps audit with no code to read": { target: "/app", timestamp: base.timestamp, mode: "deps", deps: { total: 1, scanned: 0, notInstalled: ["a"], direct: [], typosquats: [], capabilityCounts: {} }, findings: [] },
  "a deps audit that read 1 of 4 packages": { target: "/app", timestamp: base.timestamp, mode: "deps", deps: { total: 4, scanned: 1, notInstalled: ["a", "b", "c"], direct: [], typosquats: [], capabilityCounts: {} }, findings: [] },
  "an empty folder": { target: "/app", timestamp: base.timestamp, mode: "repo", coverage: { families: [{ id: "secrets", label: "Secrets", ran: true, examined: 0, skipped: {} }, { id: "routes", label: "Routes", ran: true, examined: 0, skipped: {} }], notRun: [], blindSpots: { count: 0 }, excludedDirs: [] }, findings: [{ severity: "info", title: "Library mode note", category: "scan" }] },
  "a plain 403": { ...base, mode: "url", reachable: true, httpStatus: 403, findings: [] },
  "an AI audit with no config": { target: "/app", timestamp: base.timestamp, mode: "agents", agents: { grade: null, score: null, inventory: {}, notChecked: [] }, executedProbes: ["agent-config-discovery"], findings: [] },
};

function terminal(result) {
  const lines = [];
  const log = vi.spyOn(console, "log").mockImplementation((l = "") => { lines.push(l); });
  const out = vi.spyOn(process.stdout, "write").mockImplementation((l) => { lines.push(String(l)); return true; });
  printReport(result);
  log.mockRestore();
  out.mockRestore();
  return lines.join("\n");
}

const SURFACES = {
  terminal,
  brief: (r) => formatBrief(buildBrief(r)),
  "Markdown report": (r) => formatMarkdownReport(r, { version: "0" }),
  "developer report": (r) => formatAudienceReport(r, "developer", { version: "0" }),
  "owner report": (r) => formatAudienceReport(r, "owner", { version: "0" }),
  "auditor report": (r) => formatAudienceReport(r, "auditor", { version: "0" }),
  "agent report": (r) => formatAudienceReport(r, "agent", { version: "0" }),
  "wizard line": (r) => { const a = { merged: r }; gradeArea(a); return `${a.grade} ${countLine(r.findings, a.unchecked)}`; },
  "dashboard verdict": (r) => { const [p] = buildOverview({ scans: [{ name: "r.json", mtime: 1, data: r }] }).projects; return verdict({ scanned: true, when: "now", counts: p.counts, open: p.open, unread: p.unread, }).text; },
  "dashboard run ending": (r) => checkResult({ counts: {}, total: r.findings.length, claim: nothingClaim(r) }),
  compliance: (r) => buildComplianceCoverage(r, "nis2").measures.map((m) => m.status).join(" ").replace("tested-clean", "no gaps"),
};

describe.each(Object.entries(CASES))("%s", (_name, result) => {
  it.each(Object.keys(SURFACES))("%s never reads as a success", (surface) => {
    expect(SURFACES[surface](result)).not.toMatch(SUCCESS);
  });
});

describe("a config that can't be parsed", () => {
  it("is not a config read, so it has no grade", async () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "penthera-agents-")));
    writeFileSync(join(dir, ".mcp.json"), "{ not json\n");
    const r = await scanAgents(dir, { home: join(dir, "nohome") });
    expect(r.agents.grade).toBeNull();
    expect(r.findings.map((f) => f.templateId)).toContain("agents/config-unparsed");
    expect(nothingClaim(r)).toBeTruthy();
  });
});

describe("a broken config beside one that reads", () => {
  const run = async () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "penthera-agents-")));
    writeFileSync(join(dir, ".mcp.json"), "{ broken\n");
    writeFileSync(join(dir, "CLAUDE.md"), "# Notes\n");
    return scanAgents(dir, { home: join(dir, "nohome") });
  };
  it("has no A, and says so everywhere", async () => {
    const r = await run();
    expect(r.agents.grade).toBeNull();
    expect(r.agents.unparsed).toBe(1);
    expect(readNothing(r)).toBe(false);
    expect(nothingClaim(r)).toContain("1 config file couldn't be read.");
    expect(r.agents.notChecked.join()).toContain(".mcp.json");
    expect(buildBrief(r).verdict).toBe(VERDICTS.review);
    expect(buildBrief(r).exit_code).toBe(0);
    const area = { merged: r };
    gradeArea(area);
    expect(area.grade).toBe("–");
    expect(countLine(r.findings, area.unchecked)).toContain("couldn't be read");
    expect(terminal(r)).not.toMatch(SUCCESS);
    expect(formatMarkdownReport(r)).toContain("a config couldn't be read");
  });
  it("shows in the dashboard, also on a project with a code scan", async () => {
    const r = await run();
    const scan = { name: "s.json", mtime: 2, data: { target: "/app", mode: "repo", timestamp: base.timestamp, findings: [] } };
    const [p] = buildOverview({ scans: withAudits([scan], [{ name: "a.json", mtime: 1, data: { ...r, target: "/app" } }], (d) => d.target) }).projects;
    expect(p.grade).toBe("–");
    expect(p.unread.title).toBe("1 config file couldn't be read.");
  });
  it("keeps a bad grade", async () => {
    const r = await run();
    expect(notRead({ ...r, agents: { ...r.agents, grade: "F" } })).toBeNull();
  });
});

describe("a check of one part", () => {
  const clean = { counts: {}, total: 0 };
  it("says what it checked", () => {
    expect(checkResult({ ...clean, what: "deps" })).toBe("No problems in your dependencies.");
    expect(checkResult({ ...clean, what: "agents" })).toBe("No problems in your AI tools.");
    expect(checkResult({ ...clean, what: "deps", codeUnchecked: true })).toBe("No problems in your dependencies. Your code hasn't been checked.");
    expect(checkResult({ ...clean, what: "deps", counts: { info: 1 }, total: 1, codeUnchecked: true })).toBe("No problems in your dependencies, 1 note. Your code hasn't been checked.");
    expect(checkResult({ counts: { high: 1 }, total: 1, what: "deps", codeUnchecked: true })).toBe("Done. 1 problem found, 1 serious. Your code hasn't been checked.");
  });
  it("a no-code project tells the run so", () => {
    const audit = { name: "r.json", mtime: 1, data: { target: "/app", mode: "deps", timestamp: base.timestamp, deps: { total: 2, scanned: 2, notInstalled: [], direct: [], capabilityCounts: {} }, findings: [] } };
    expect(buildOverview({ scans: withAudits([], [audit], (d) => d.target) }).projects[0].unread.noCode).toBe(true);
  });
});

describe("the counts", () => {
  const f = (n) => ({ templateId: `r${n}`, title: `P${n}`, severity: "high", url: "x", location: "x" });
  const at = (key, findings, t) => ({ name: `${key}${t}.json`, mtime: t, data: { target: key, mode: "repo", timestamp: new Date(t * 1000).toISOString(), findings } });
  it("gives a project the fixes its memory holds, the same as All projects", () => {
    const o = buildOverview({ scans: [at("/app", [f(1), f(2)], 1), at("/app", [f(1)], 2)], memory: [{ label: "/app", verifiedFixes: 2, trend: [] }] });
    expect(o.projects[0].fixed).toBe(2);
    expect(o.fixed).toBe(2);
  });
});

describe("the sweep itself", () => {
  const partial = CASES["a deps audit that read 1 of 4 packages"];
  it("says how much it read, with no A", () => {
    const [p] = buildOverview({ scans: [{ name: "r.json", mtime: 1, data: partial }] }).projects;
    expect(p.grade).toBe("–");
    expect(p.score).toBeNull();
    expect(verdict({ scanned: true, when: "now", counts: p.counts, open: 0, unread: p.unread }).text).toBe("1 of 4 packages read.");
  });
  it("discloses it in the owner report", () => {
    expect(formatAudienceReport(partial, "owner", { version: "0" })).toContain("1 of 4 packages read.");
  });
  it("reads Review in the brief, with no exit change", () => {
    const b = buildBrief(partial);
    expect(b.verdict).toBe(VERDICTS.review);
    expect(b.exit_code).toBe(0);
  });
});

describe("a project with no code scan", () => {
  const audit = (mode, field) => ({ name: "r.json", mtime: 1, data: { target: "/app", mode, timestamp: base.timestamp, ...field, findings: [] } });
  const only = (audits) => buildOverview({ scans: withAudits([], audits, (d) => d.target) }).projects[0];
  it("has no grade after deps alone", () => {
    const p = only([audit("deps", { deps: { total: 2, scanned: 2, notInstalled: [], direct: [], capabilityCounts: {} } })]);
    expect(p.grade).toBe("–");
    expect(verdict({ scanned: true, when: "now", counts: p.counts, open: 0, unread: p.unread }).text).toBe("Only your dependencies were checked.");
  });
  it("has no grade after the AI audit alone", () => {
    const p = only([audit("agents", { agents: { grade: "A", score: 100, inventory: {} } })]);
    expect(p.grade).toBe("–");
    expect(p.unread.title).toBe("Only your AI tools were checked.");
  });
  it("gets its grade once the code is scanned", () => {
    const scan = { name: "s.json", mtime: 2, data: { target: "/app", mode: "repo", timestamp: base.timestamp, findings: [] } };
    const [p] = buildOverview({ scans: withAudits([scan], [audit("deps", { deps: { total: 2, scanned: 2, notInstalled: [], direct: [], capabilityCounts: {} } })], (d) => d.target) }).projects;
    expect(p.grade).toBe("A");
  });
});

describe("the all-projects count of fixes", () => {
  it("ignores memory of a project that isn't here", () => {
    const scans = [{ name: "s.json", mtime: 2, data: { target: "/app", mode: "repo", timestamp: base.timestamp, findings: [] } }];
    expect(buildOverview({ scans, memory: [{ label: "/other", verifiedFixes: 1, trend: [] }] }).fixed).toBe(0);
    expect(buildOverview({ scans, memory: [{ label: "/app", verifiedFixes: 1, trend: [] }] }).fixed).toBe(1);
  });
});

describe("the brief's Scanned line", () => {
  it("doesn't claim a site it couldn't read", () => {
    expect(formatBrief(buildBrief(CASES["a firewall's page"]))).not.toContain("Scanned: live URL");
    expect(formatBrief(buildBrief({ ...base, mode: "url", reachable: true, findings: [] }))).toContain("Scanned: live URL");
  });
});

describe("the sweep itself", () => {
  it("would catch a run that read everything", () => {
    const fine = { target: "/app", timestamp: base.timestamp, mode: "repo", findings: [] };
    expect(terminal(fine)).toMatch(SUCCESS);
    expect(formatBrief(buildBrief(fine))).toMatch(SUCCESS);
    expect(nothingClaim(fine)).toBeNull();
  });
});

describe("the wizards, on a firewall's page", () => {
  let server, cwd;
  afterEach(async () => {
    if (cwd) rmSync(cwd, { recursive: true, force: true });
    cwd = null;
    if (server) await new Promise((r) => server.close(r));
    server = null;
  });
  const firewall = (status) => {
    server = createServer((_q, res) => { res.writeHead(status, { "content-type": "text/html", "cf-mitigated": "challenge" }); res.end("x"); });
    return new Promise((r) => server.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${server.address().port}`)));
  };

  it("the app area grades nothing, in summary.md and summary.json", async () => {
    const url = await firewall(403);
    const r = { id: "app", label: "Running app", command: "penthera" };
    const ctx = { url, offline: true, date: "2026-11-01", version: "0" };
    r.merged = await runCheck("app", ctx);
    gradeArea(r);
    expect(r.grade).toBe("–");
    const md = summaryMarkdown([r], [], ctx);
    expect(md).toContain("We couldn't see your site.");
    expect(md).not.toMatch(SUCCESS);
    const row = summaryJson([r], [], ctx, "0").checks[0];
    expect(row.notRead.site).toContain("Cloudflare answered instead of the site");
    expect(row.grade).toBe("–");
    expect(row.report).toEqual({ json: "app.json", markdown: "app.md" });
  });

  it.each([403, 503])("penthera-scan on a %i: no success line, and exit stays 0", async (status) => {
    const url = await firewall(status);
    cwd = mkdtempSync(join(tmpdir(), "penthera-scan-"));
    const bin = fileURLToPath(new URL("../bin/scan.js", import.meta.url));
    const p = spawn(process.execPath, [bin], { cwd, env: { ...process.env, HOME: cwd, NO_COLOR: "1" } });
    p.stdin.write(`${url}\n1\n`);
    let out = "";
    p.stdout.on("data", (d) => { out += d; });
    p.stderr.on("data", (d) => { out += d; });
    const code = await new Promise((r) => { p.on("close", r); setTimeout(() => p.stdin.end(), 12_000); });
    expect(out).toContain("We couldn't see your site.");
    expect(out).not.toMatch(/looking good|Looks good|No issues found/);
    expect(code).toBe(0);
  }, 40_000);
});
