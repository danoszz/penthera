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

  it("coverage reflects the probes that actually ran (executedProbes)", () => {
    const coverage = buildWstgCoverage(
      { mode: "url", executedProbes: ["tls", "security-headers"], findings: [] },
      "deep",
    );
    expect(coverage.probesRun).toBe(2);
    expect(coverage.wstgExercised).toContain("WSTG-CRYP-01");
    // Injection was NOT run — it must not be claimed, even on a deep profile.
    expect(coverage.wstgExercised).not.toContain("WSTG-INPV-05");
  });

  it("does not claim injection when a deep scan found no endpoints to probe", () => {
    const probes = getProbesForScan(
      { mode: "url", executedProbes: ["reachability", "openapi"] },
      "deep",
    ).map((p) => p.id);
    expect(probes).toContain("reachability");
    expect(probes).not.toContain("sqli");
  });

  it("falls back to the profile catalog when no execution record is present", () => {
    const probes = getProbesForScan({ mode: "url" }, "deep").map((p) => p.id);
    expect(probes).toContain("sqli"); // deep profile catalog still advertises it
  });
});
