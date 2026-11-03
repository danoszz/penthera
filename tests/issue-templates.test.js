// The issue forms people meet first. A wrong finding is the report we most want,
// and the one most likely to carry a real key if the form doesn't say otherwise.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

const read = (f) => readFileSync(new URL(`../.github/ISSUE_TEMPLATE/${f}`, import.meta.url), "utf8");

describe("issue templates", () => {
  it("have no blank issues, so every report uses a form", () => {
    expect(read("config.yml")).toMatch(/^blank_issues_enabled: false$/m);
  });

  it("ask what a wrong finding needs, and never for a real key", () => {
    const t = read("wrong_finding.md");
    expect(t).toMatch(/^name: Wrong finding$/m);
    expect(t).toMatch(/^about: .+/m);
    for (const field of ["The command", "penthera --version", "The finding's title", "Rule id", "File and line", "Why it's wrong"]) {
      expect(t, field).toContain(field);
    }
    expect(t).toMatch(/never paste a real key/i);
  });
});
