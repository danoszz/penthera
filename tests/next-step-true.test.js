/**
 * What the CLI promises next has to hold: the dashboard finds the wizard's reports, the hint says
 * what a person will really do there, and explain_finding says something about the rule it names.
 */
import { describe, it, expect, vi } from "vitest";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createDataSource } from "../src/ui/api/data.js";
import { printReport } from "../src/reporter.js";
import { TOOL_BY_NAME } from "../src/mcp/tools.js";

const FINDING = { severity: "high", title: "Wizard finding", category: "secrets", file: "a.js" };
const report = (target) => JSON.stringify({ target, mode: "repo", timestamp: "2026-11-01T10:00:00Z", findings: [FINDING] });

function source(write) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "penthera-ui-")));
  const project = join(root, "app"), reports = join(project, "reports");
  mkdirSync(reports, { recursive: true });
  write(reports, project);
  return createDataSource({ projects: [project], reportsDir: reports, home: join(root, "home"), memoryRoot: join(root, "memory"), settings: { get: () => ({}) } });
}

describe("the dashboard's reports", () => {
  it("finds what the wizard wrote in reports/penthera-<date>/", () => {
    const src = source((reports, project) => {
      mkdirSync(join(reports, "penthera-2026-11-01"));
      writeFileSync(join(reports, "penthera-2026-11-01", "code.json"), report(project));
      writeFileSync(join(reports, "penthera-2026-11-01", "summary.json"), JSON.stringify({ generatedAt: "x", checks: [], fixFirst: [] }));
    });
    expect(src.findings().map((f) => f.title)).toEqual(["Wizard finding"]);
    expect(src.overview().projects).toHaveLength(1);
  });

  it("leaves every other folder alone", () => {
    const src = source((reports, project) => {
      mkdirSync(join(reports, "scratch"));
      writeFileSync(join(reports, "scratch", "old.json"), report(project));
    });
    expect(src.findings()).toEqual([]);
  });
});

describe("the CLI's next step", () => {
  it("says the dashboard needs a check, because a plain scan writes no report", () => {
    const lines = [];
    const log = vi.spyOn(console, "log").mockImplementation((l = "") => { lines.push(l); });
    const out = vi.spyOn(process.stdout, "write").mockImplementation((l) => { lines.push(String(l)); return true; });
    printReport({ target: "/code", mode: "repo", findings: [FINDING] });
    log.mockRestore();
    out.mockRestore();
    expect(lines.join("\n")).toContain("npx penthera ui --open, then Check my app");
    expect(lines.join("\n")).not.toContain("walks you through every problem");
  });
});

describe("explain_finding", () => {
  const explain = (id) => TOOL_BY_NAME.get("explain_finding").run({ id });

  it("gives code-pattern real guidance", async () => {
    const { structured, text } = await explain("code-pattern");
    expect(structured.action).not.toBe("Review and remediate this finding");
    expect(text).toMatch(/eval|shell/i);
    expect(structured.limits).toEqual([]);
  });

  it("says so when a known rule has only general advice", async () => {
    const { structured, text } = await explain("timing");
    expect(structured.known).toBe(true);
    expect(structured.action).toBe("Review and remediate this finding");
    expect(structured.limits[0]).toContain("general advice");
    expect(text).toContain("general advice");
  });

  it("names the parameter it takes", () => {
    const t = TOOL_BY_NAME.get("explain_finding");
    expect(t.description).toContain("as `id`");
    expect(Object.keys(t.inputSchema.properties)).toEqual(["id"]);
  });
});
