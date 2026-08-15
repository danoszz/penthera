/**
 * Provenance + honest-confidence labelling on findings (principles #1 and #3).
 */
import { describe, it, expect } from "vitest";
import { confidenceFor, stampProvenance } from "../lib/provenance.js";

describe("confidence labelling", () => {
  it("labels deterministic probes as confirmed", () => {
    expect(confidenceFor({ source: "header-audit" })).toBe("confirmed");
    expect(confidenceFor({ source: "tls-check" })).toBe("confirmed");
    expect(confidenceFor({ source: "email-dns-probe" })).toBe("confirmed");
  });
  it("labels heuristic probes as needs-human-review or potential", () => {
    expect(confidenceFor({ source: "idor-probe" })).toBe("needs-human-review");
    expect(confidenceFor({ source: "client-auth-probe" })).toBe("needs-human-review");
    expect(confidenceFor({ source: "fuzzer" })).toBe("potential");
    expect(confidenceFor({ source: "adaptive-probe" })).toBe("potential");
  });
  it("falls back to category, then a safe default", () => {
    expect(confidenceFor({ category: "secrets" })).toBe("confirmed");
    expect(confidenceFor({ category: "auth-bypass" })).toBe("needs-human-review");
    expect(confidenceFor({})).toBe("likely");
  });
  it("respects an explicit finding.confidence", () => {
    expect(confidenceFor({ source: "idor-probe", confidence: "confirmed" })).toBe("confirmed");
  });
});

describe("stampProvenance", () => {
  it("stamps every finding with the four provenance fields", () => {
    const [f] = stampProvenance([{ title: "x", source: "tls-check", category: "tls" }], "2026-08-15T00:00:00Z");
    expect(f).toMatchObject({
      source: "tls-check", method: "tls-check",
      collected_at: "2026-08-15T00:00:00Z", confidence: "confirmed",
    });
  });
  it("defaults source and method when absent", () => {
    const [f] = stampProvenance([{ title: "x" }], "2026-08-15T00:00:00Z");
    expect(f.source).toBe("penthera");
    expect(f.method).toBe("penthera");
    expect(f.confidence).toBe("likely");
  });
  it("does not overwrite an existing collected_at", () => {
    const [f] = stampProvenance([{ title: "x", collected_at: "2000-01-01T00:00:00Z" }], "2026-08-15T00:00:00Z");
    expect(f.collected_at).toBe("2000-01-01T00:00:00Z");
  });
});
