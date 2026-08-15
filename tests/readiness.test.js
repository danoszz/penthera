/**
 * NIS2 readiness report + local self-assessment. Combines scan evidence with
 * offline attestation into a per-measure met/partial/gap/n-a report, with
 * provenance on every evidence item.
 */
import { describe, it, expect } from "vitest";
import { blankAssessment, normalizeAnswers, QUESTIONS } from "../lib/compliance/self-assessment.js";
import { buildReadiness, formatReadinessMarkdown } from "../lib/compliance/readiness.js";

const NL = {
  id: "nl", name: "Netherlands", law: "Cyberbeveiligingswet",
  authorities: { supervisor: "RDI", csirt: "NCSC-NL" },
  incidentDeadlines: [{ within: "24 hours", of: "awareness", content: "early warning" }],
  penalties: "Up to €10M or 2%.", disclaimer: "Readiness tooling only; not legal advice.",
};

describe("self-assessment", () => {
  it("blank template covers every measure question", () => {
    const t = blankAssessment();
    for (const q of QUESTIONS) expect(t.answers[q.id]).toBeDefined();
  });
  it("normalizeAnswers keeps valid answers and drops invalid ones", () => {
    const n = normalizeAnswers({ answers: { a1: { answer: "yes" }, a2: { answer: "maybe" }, zz: { answer: "yes" } } });
    expect(n.a1.answer).toBe("yes");
    expect(n.a2).toBeUndefined(); // invalid value dropped
    expect(n.zz).toBeUndefined(); // unknown id dropped
  });
});

describe("buildReadiness", () => {
  it("marks an unassessed, unscanned measure as a gap (not n/a)", () => {
    const r = buildReadiness({ executedProbes: [], findings: [] }, { jurisdiction: NL });
    // (c) business continuity: no scan signal, no attestation → gap
    expect(r.measures.find((m) => m.id === "c").status).toBe("gap");
  });

  it("lifts an organisational measure to met when attested yes", () => {
    const answers = { answers: { c1: { answer: "yes" }, c2: { answer: "yes" } } };
    const r = buildReadiness({ executedProbes: [], findings: [] }, { answers, jurisdiction: NL });
    expect(r.measures.find((m) => m.id === "c").status).toBe("met");
  });

  it("records n/a only when the user attests na", () => {
    const answers = { answers: { c1: { answer: "na" }, c2: { answer: "na" } } };
    const r = buildReadiness({ executedProbes: [], findings: [] }, { answers, jurisdiction: NL });
    expect(r.measures.find((m) => m.id === "c").status).toBe("n/a");
  });

  it("uses scan evidence for technical measures", () => {
    // e = secure dev / vuln handling: probes ran, no findings → tested-clean → met
    const scan = { executedProbes: ["openapi", "sensitive-files", "cors", "security-headers"], findings: [] };
    const r = buildReadiness(scan, { jurisdiction: NL });
    expect(r.measures.find((m) => m.id === "e").status).toBe("met");
  });

  it("attaches provenance to every evidence item", () => {
    const scan = { executedProbes: ["tls"], findings: [], timestamp: "2026-08-15T00:00:00Z" };
    const answers = { answers: { h1: { answer: "yes", note: "AES-256 at rest" } } };
    const r = buildReadiness(scan, { answers, jurisdiction: NL });
    const h = r.measures.find((m) => m.id === "h");
    const scanEv = h.evidence.find((e) => e.source === "scan");
    const attEv = h.evidence.find((e) => e.source === "self-assessment");
    expect(scanEv).toMatchObject({ source: "scan", confidence: "measured", collected_at: "2026-08-15T00:00:00Z" });
    expect(scanEv.method).toMatch(/^probe:/);
    expect(attEv).toMatchObject({ source: "self-assessment", method: "attestation", confidence: "attested" });
  });

  it("carries jurisdiction incident deadlines and disclaimer", () => {
    const r = buildReadiness({ executedProbes: [], findings: [] }, { jurisdiction: NL });
    expect(r.jurisdiction.incidentDeadlines[0].within).toBe("24 hours");
    expect(r.jurisdiction.disclaimer).toMatch(/not legal advice/i);
  });

  it("renders markdown with the disclaimer, a measures table, and deadlines", () => {
    const md = formatReadinessMarkdown(buildReadiness({ executedProbes: [], findings: [] }, { jurisdiction: NL }));
    expect(md).toContain("# NIS2 readiness report");
    expect(md).toMatch(/not a certification/i);
    expect(md).toContain("Incident-reporting duties");
    expect(md).toContain("| Art. 21(2) |");
  });
});
