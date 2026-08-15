/**
 * Policy-pack generator — proportionate, editable NIS2 policy templates,
 * pre-filled from jurisdiction data and the readiness report.
 */
import { describe, it, expect } from "vitest";
import { buildPolicyPack, policyPackIndex, POLICIES } from "../lib/compliance/policy-pack.js";

const NL = {
  authorities: { csirt: "NCSC-NL", supervisor: "RDI" },
  incidentDeadlines: [{ within: "24 hours", of: "awareness", to: "your CSIRT", content: "early warning" }],
  penalties: "Up to €10M or 2%.",
};

describe("policy pack", () => {
  it("generates a template per core policy, each an editable draft", () => {
    const pack = buildPolicyPack({ org: "Acme BV", date: "2026-08-15", jurisdiction: NL });
    expect(pack.length).toBe(POLICIES.length);
    expect(pack.length).toBeGreaterThanOrEqual(6);
    for (const p of pack) {
      expect(p.content).toContain("Acme BV");
      expect(p.content).toMatch(/not legal advice/i);
      expect(p.filename).toMatch(/\.md$/);
      expect(p.measure).toMatch(/^[a-j]$/);
    }
  });

  it("pre-fills the incident plan with the jurisdiction's deadlines and authority", () => {
    const pack = buildPolicyPack({ org: "Acme BV", date: "2026-08-15", jurisdiction: NL });
    const ir = pack.find((p) => p.id === "incident-response");
    expect(ir.content).toContain("24 hours");
    expect(ir.content).toContain("NCSC-NL");
  });

  it("adds a readiness note when a readiness report is provided", () => {
    const readiness = { measures: [{ id: "a", status: "partial", gaps: [] }] };
    const pack = buildPolicyPack({ org: "Acme BV", date: "2026-08-15", jurisdiction: NL, readiness });
    const infosec = pack.find((p) => p.id === "information-security");
    expect(infosec.content).toMatch(/current readiness for this measure.*partial/i);
  });

  it("falls back to a generic org name and omits readiness notes when absent", () => {
    const pack = buildPolicyPack({});
    expect(pack[0].content).toContain("Your organisation");
    expect(pack[0].content).not.toMatch(/current readiness/i);
  });

  it("builds an index linking every policy", () => {
    const pack = buildPolicyPack({ org: "Acme BV", date: "2026-08-15", jurisdiction: NL });
    const idx = policyPackIndex(pack, { org: "Acme BV" });
    for (const p of pack) expect(idx).toContain(p.filename);
  });
});
