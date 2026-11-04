/**
 * PR triage (scripts/ci/pr-triage.mjs): which changed paths need a maintainer
 * before CI runs, and that a changed path can't write outside its folder.
 */
import { describe, it, expect } from "vitest";
import { sensitivePaths, safeRelative } from "../scripts/ci/pr-triage.mjs";

describe("PR triage", () => {
  it("flags files that change what CI, an install or an agent runs", () => {
    const paths = [
      ".github/workflows/ci.yml", "package.json", "package-lock.json", ".npmrc", "scripts/ci/x.mjs",
      "bin/penthera.js", "Dockerfile", "action.yml", ".claude/settings.json", ".mcp.json", "AGENTS.md",
      "vitest.config.js",
    ];
    expect(sensitivePaths(paths)).toEqual(paths);
  });

  it("leaves source, docs, tests and fragments as safe paths", () => {
    expect(sensitivePaths(["src/report/markdown.js", "docs/commands/scan.md", "tests/reports.test.js", "changelog.d/x.md", "lib/rules/a.js"])).toEqual([]);
  });

  it("refuses a path that would leave the output folder", () => {
    expect(safeRelative("src/a.js")).toBe(true);
    expect(safeRelative("../../etc/passwd")).toBe(false);
    expect(safeRelative("/etc/passwd")).toBe(false);
  });
});
