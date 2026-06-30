import { describe, it, expect } from "vitest";
import {
  resolveWstgTags,
  buildWstgCoverage,
  getProbesForScan,
  PROBE_WSTG,
} from "../lib/owasp-wstg.js";

describe("OWASP WSTG mapping", () => {
  it("maps IDOR findings to WSTG-ATHZ-04", () => {
    const tags = resolveWstgTags({
      title: "IDOR: user can access another user's object",
      category: "auth",
      source: "idor-probe",
    });
    expect(tags).toContain("WSTG-ATHZ-04");
  });

  it("maps CORS category to WSTG-CLNT-07", () => {
    const tags = resolveWstgTags({ title: "CORS misconfiguration", category: "cors" });
    expect(tags).toContain("WSTG-CLNT-07");
  });

  it("builds coverage for standard URL scan", () => {
    const coverage = buildWstgCoverage(
      { mode: "url", findings: [{ title: "Missing CSP", category: "exposure" }] },
      "standard",
    );
    expect(coverage.probesRun).toBeGreaterThan(10);
    expect(coverage.wstgExercised.length).toBeGreaterThan(5);
    expect(coverage.wstgTriggered.length).toBeGreaterThan(0);
  });

  it("deep profile includes injection probes", () => {
    const standard = getProbesForScan({ mode: "url" }, "standard").map((p) => p.probe);
    const deep = getProbesForScan({ mode: "url" }, "deep").map((p) => p.probe);
    expect(deep.length).toBeGreaterThan(standard.length);
    expect(deep.some((p) => /SQL injection/i.test(p))).toBe(true);
  });

  it("exports probe catalog", () => {
    expect(PROBE_WSTG.length).toBeGreaterThan(20);
  });
});
