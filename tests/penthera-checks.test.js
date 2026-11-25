/**
 * The two Penthera checks (scripts/ci/penthera-checks.mjs): which job goes
 * where, and how a group's state is decided.
 */
import { describe, it, expect } from "vitest";
import { groupOf, summarize, NAMES } from "../scripts/ci/penthera-checks.mjs";

describe("Penthera checks", () => {
  it("puts triage, self-scan, dependency review and CodeQL under security, the rest of CI under safe build", () => {
    expect(groupOf("PR triage", "scan")).toBe("security");
    expect(groupOf("CI", "scan")).toBe("security");
    expect(groupOf("CodeQL", "analyze")).toBe("security");
    expect(groupOf("Dependency review", "penthera")).toBe("security");
    expect(groupOf("CI", "test (22)")).toBe("build");
    expect(groupOf("Install matrix", "npm pack")).toBe("build");
    expect(groupOf("Penthera checks", "summary")).toBe(null);
    expect(groupOf("News feed", "x")).toBe(null);
  });

  it("never counts its own two checks as jobs, whichever workflow GitHub files them under", () => {
    for (const workflow of ["CodeQL", "CI", "Install matrix", "Dependency review", "PR triage"]) {
      for (const name of Object.values(NAMES)) expect(groupOf(workflow, name), `${workflow} / ${name}`).toBe(null);
    }
    expect(Object.values(NAMES)).toEqual(["Penthera: security", "Penthera: safe build"]);
    // A real job that borrows the name runs on a runner, so it keeps its labels and still counts.
    expect(groupOf("CI", "Penthera: security", ["ubuntu-latest"])).toBe("build");
    expect(groupOf("CodeQL", "Penthera: safe build", ["ubuntu-latest"])).toBe("security");
    // The deadlock: CodeQL is done, and the only "jobs" still running are these checks themselves.
    const jobs = [
      { workflow: "CodeQL", name: "analyze", status: "completed", conclusion: "success" },
      { workflow: "CodeQL", name: "Penthera: security", status: "in_progress", conclusion: null },
      { workflow: "CodeQL", name: "Penthera: safe build", status: "in_progress", conclusion: null },
    ].filter((j) => groupOf(j.workflow, j.name) === "security");
    expect(jobs.map((j) => j.name)).toEqual(["analyze"]);
    expect(summarize(jobs)).toMatchObject({ status: "completed", conclusion: "success" });
  });

  it("is running while any job runs, failed if any failed, and passes otherwise", () => {
    const ok = { status: "completed", conclusion: "success" };
    expect(summarize([ok, { status: "in_progress" }]).status).toBe("in_progress");
    expect(summarize([ok, { status: "completed", conclusion: "failure" }]).conclusion).toBe("failure");
    expect(summarize([ok, { status: "completed", conclusion: "skipped" }]).conclusion).toBe("success");
  });
});
