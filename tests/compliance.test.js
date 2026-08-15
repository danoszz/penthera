/**
 * Compliance mapping (NIS2 Article 21) — coverage reflects the probes that
 * actually ran, and organisational measures never get claimed as "tested".
 */
import { describe, it, expect } from "vitest";
import {
  buildComplianceCoverage,
  listFrameworks,
  formatComplianceMarkdown,
} from "../lib/compliance/index.js";

describe("compliance mapping (NIS2)", () => {
  it("lists nis2 as a supported framework", () => {
    expect(listFrameworks()).toContain("nis2");
  });

  it("returns null for an unknown framework", () => {
    expect(buildComplianceCoverage({ executedProbes: [], findings: [] }, "gdpr")).toBeNull();
  });

  it("marks a measure tested only when its probes actually ran", () => {
    const cov = buildComplianceCoverage(
      { executedProbes: ["tls", "auth-hardening", "idor"], findings: [] },
      "nis2",
    );
    expect(cov.measures.find((m) => m.id === "h").status).toBe("tested-clean"); // cryptography ← tls
    expect(cov.measures.find((m) => m.id === "i").status).toBe("tested-clean"); // access control
    expect(cov.measures.find((m) => m.id === "e").status).toBe("not-run");      // no e-probes ran
  });

  it("reflects findings under a measure", () => {
    const cov = buildComplianceCoverage(
      { executedProbes: ["tls"], findings: [{ severity: "high", category: "tls", title: "Weak TLS" }] },
      "nis2",
    );
    const h = cov.measures.find((m) => m.id === "h");
    expect(h.status).toBe("tested-findings");
    expect(h.findings).toBe(1);
  });

  it("keeps organisational measures out of scope / planned regardless of probes", () => {
    const cov = buildComplianceCoverage({ executedProbes: ["tls"], findings: [] }, "nis2");
    expect(cov.measures.find((m) => m.id === "c").status).toBe("out-of-scope");
    expect(cov.measures.find((m) => m.id === "b").status).toBe("planned");
    expect(cov.measures.find((m) => m.id === "a").status).toBe("evidence");
  });

  it("summarises testable coverage for this scan", () => {
    const cov = buildComplianceCoverage(
      { executedProbes: ["tls", "auth-hardening"], findings: [] },
      "nis2",
    );
    expect(cov.summary.testable).toBeGreaterThan(0);
    expect(cov.summary.coveredThisScan).toBeGreaterThanOrEqual(2);
  });

  it("renders a markdown section with the disclaimer", () => {
    const md = formatComplianceMarkdown(
      buildComplianceCoverage({ executedProbes: ["tls"], findings: [] }, "nis2"),
    );
    expect(md).toContain("Compliance mapping");
    expect(md).toMatch(/not.*certification/i);
    expect(md).toMatch(/Art\. 21/);
  });
});
