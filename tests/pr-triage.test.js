/**
 * PR triage (scripts/ci/pr-triage.mjs): which changed paths need a maintainer
 * before CI runs, and that a changed path can't write outside its folder.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { sensitivePaths, safeRelative, workflowRunPaths } from "../scripts/ci/pr-triage.mjs";

const workflows = readdirSync(".github/workflows").filter((f) => /\.ya?ml$/.test(f)).map((f) => readFileSync(`.github/workflows/${f}`, "utf-8"));

describe("PR triage", () => {
  it("flags files that change what CI, an install or an agent runs", () => {
    const paths = [
      ".github/workflows/ci.yml", "package.json", "package-lock.json", ".npmrc", "scripts/ci/x.mjs",
      "bin/penthera.js", "Dockerfile", "action.yml", ".claude/settings.json", ".mcp.json", "AGENTS.md",
      "vitest.config.js", "skills/penthera/SKILL.md", "skills/penthera/scripts/preflight.sh",
      "examples/app/package.json", "site/scripts/build.sh",
    ];
    expect(sensitivePaths(paths)).toEqual(paths);
  });

  it("flags every file our workflows run directly, read from the workflows themselves", () => {
    const run = workflowRunPaths(workflows);
    expect(run.has("skills/penthera/scripts/preflight.sh")).toBe(true);
    for (const p of run) expect(sensitivePaths([p], run)).toEqual([p]);
  });

  it("leaves source, docs, tests and fragments as standard paths", () => {
    expect(sensitivePaths(["src/report/markdown.js", "docs/commands/scan.md", "tests/reports.test.js", "changelog.d/x.md", "lib/rules/a.js"])).toEqual([]);
  });

  it("refuses a path that would leave the output folder", () => {
    expect(safeRelative("src/a.js")).toBe(true);
    expect(safeRelative("../../etc/passwd")).toBe(false);
    expect(safeRelative("/etc/passwd")).toBe(false);
  });
});
