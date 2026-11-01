import { describe, it, expect } from "vitest";
import { reachLines } from "../src/report/reach.js";
import { formatSarif } from "../src/reporter.js";

describe("a site that was not read", () => {
  it("does not report paths found", () => {
    const lines = reachLines([{ mode: "url", reachable: false, httpStatus: 503, endpoints: { discovered: 0 } }]);
    expect(lines.join(" ")).toMatch(/HTTP 503/);
    expect(lines.join(" ")).not.toMatch(/paths found/);
  });

  it("says so in SARIF", () => {
    const sarif = formatSarif({ target: "https://x.example", modes: ["url", "repo"], reachable: false, httpStatus: 503, findings: [] });
    const [invocation] = sarif.runs[0].invocations;
    expect(invocation.executionSuccessful).toBe(false);
    expect(invocation.toolExecutionNotifications[0].message.text).toMatch(/HTTP 503/);
  });
});
