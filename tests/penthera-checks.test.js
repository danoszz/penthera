/**
 * The two Penthera checks (scripts/ci/penthera-checks.mjs): which job goes
 * where, and how a group's state is decided.
 */
import { describe, it, expect } from "vitest";
import { groupOf, summarize } from "../scripts/ci/penthera-checks.mjs";

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

  it("is running while any job runs, failed if any failed, and passes otherwise", () => {
    const ok = { status: "completed", conclusion: "success" };
    expect(summarize([ok, { status: "in_progress" }]).status).toBe("in_progress");
    expect(summarize([ok, { status: "completed", conclusion: "failure" }]).conclusion).toBe("failure");
    expect(summarize([ok, { status: "completed", conclusion: "skipped" }]).conclusion).toBe("success");
  });
});
