import { describe, it, expect } from "vitest";
import { parseTemplatePaths, BUILT_IN_TEMPLATES, runBuiltInTemplates } from "../lib/plugins.js";

describe("plugins API", () => {
  it("parses comma-separated template paths", () => {
    expect(parseTemplatePaths("./a, ./b")).toEqual(["./a", "./b"]);
    expect(parseTemplatePaths("")).toEqual([]);
  });

  it("exports built-in templates", () => {
    expect(BUILT_IN_TEMPLATES.length).toBeGreaterThan(10);
  });

  it("runs built-in templates against unreachable host without throw", async () => {
    const findings = await runBuiltInTemplates("http://127.0.0.1:1");
    expect(Array.isArray(findings)).toBe(true);
  });
});
