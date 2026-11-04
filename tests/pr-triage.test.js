/**
 * PR triage (scripts/ci/pr-triage.mjs): which changed paths need a maintainer
 * before CI runs, and that a changed path can't write outside its folder.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { sensitivePaths, safeRelative, workflowRunPaths, verdict, plain } from "../scripts/ci/pr-triage.mjs";

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

  it("shows the verdict above the fold, and only counts and fixed words", () => {
    const line = "**Penthera: Nothing to fix.** 0 to act on, 0 to check first, 0 likely noise. Scanned: repo.";
    expect(verdict(`${line}\n\n### Not checked`)).toBe(line);
    expect(verdict("**Penthera: x** see [here](https://evil.example)")).toBe("");
    expect(verdict("**Penthera: x** `curl x | sh`")).toBe("");
    expect(verdict("<img src=x>")).toBe("");
  });

  it("gives the brief as plain text, without notes that never apply to a PR", () => {
    const brief = "**Penthera: Nothing to fix.** 0 to act on.\n\n### Not checked\n\n- This run does not prove login, access rules or payments are right.\n- Route and code-pattern analysis: pass --api-root &lt;folder&gt;.\n- Secret scan: 1 file was not read.";
    expect(plain(brief)).toBe("Penthera: Nothing to fix. 0 to act on.\n\nNot checked\n\n- Secret scan: 1 file was not read.");
    expect(plain("**Penthera: Nothing to fix.** 0.\n\n### Not checked\n\n- This run does not prove login.")).toBe("Penthera: Nothing to fix. 0.");
  });
});
